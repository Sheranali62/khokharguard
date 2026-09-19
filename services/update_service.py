"""Khokhar & Son's Antivirus - signature update service.

Checks for and installs signature database updates over HTTPS with
integrity verification (spec section 37). Updates are never trusted
blindly:

    - Manifest and every file are fetched over HTTPS only.
    - Each file's SHA-256 must match the manifest.
    - When a signing public key is installed
      (``signatures/update_public_key.pub``), the manifest must carry
      a valid Ed25519 signature over its canonical JSON body - an
      attacker who controls the update URL cannot inject signatures.
    - Manifest paths are confined to the signatures directory; the
      updater never executes downloaded content (signature databases
      are data files: JSON hashes and YARA rules compiled by the
      engine's rule loader).
    - Versioned backups allow rollback to any previous signature set.
    - Offline operation is unaffected - this service is entirely
      optional and fails safe (previous signatures stay active).
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

from utils import get_logger, paths
from utils.ed25519 import verify as ed25519_verify
from utils.settings import get_settings

logger = get_logger("update_service")

MANIFEST_SCHEMA_VERSION = 1

# Safety caps so a hostile manifest cannot exhaust disk/RAM.
MAX_MANIFEST_BYTES = 256 * 1024          # 256 KiB manifest
MAX_UPDATE_FILE_BYTES = 32 * 1024 * 1024  # 32 MiB per signature file
MAX_TOTAL_UPDATE_BYTES = 64 * 1024 * 1024  # 64 MiB per update set
HTTP_TIMEOUT_SECS = 20

_USER_AGENT = "KhokharGuard/1.0 (signature-updater)"


class UpdateError(Exception):
    """Raised when an update cannot be validated or installed."""


def _sha256_of_file(path: Path) -> str:
    """Chunked SHA-256 of a local file."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _https_get(url: str, max_bytes: int, timeout: int = HTTP_TIMEOUT_SECS) -> bytes:
    """Fetch an HTTPS URL with a hard size cap; anything else fails."""
    if not url.lower().startswith("https://"):
        raise UpdateError("Update URLs must use HTTPS (got %r)" %
                          url.split("//", 1)[-1][:40])
    req = urllib.request.Request(  # noqa: S310 - scheme enforced above
        url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:  # noqa: S310
            data = response.read(max_bytes + 1)
    except (urllib.error.URLError, OSError) as exc:
        raise UpdateError(f"Download failed: {exc}") from exc
    if len(data) > max_bytes:
        raise UpdateError(
            f"Download exceeds safety cap ({max_bytes // 1024} KiB)")
    return data


def public_key_path() -> Path:
    """Path of the optional Ed25519 public key for manifest signing."""
    return paths.signatures_dir() / "update_public_key.pub"


def manifest_signing_key_installed() -> bool:
    """True when update manifests must be cryptographically signed."""
    return public_key_path().is_file()


def canonical_manifest_bytes(manifest: Dict[str, object]) -> bytes:
    """Canonical byte form that manifest signatures cover.

    Signatures are computed over the manifest JSON with the ``signature``
    field removed, serialised with sorted keys and compact separators.
    Publishers must sign exactly this form; the verifier re-derives it
    from the received manifest so no separate signed blob is needed.
    """
    body = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _verify_manifest_signature(manifest: Dict[str, object]) -> None:
    """Enforce the Ed25519 manifest signature when a key is installed.

    Raises UpdateError when the key is installed and the signature is
    missing/invalid. No-op when no key is installed (hash-only mode).

    Supported key-file encodings for ``update_public_key.pub``:

        - raw 32 bytes (used exactly, never whitespace-trimmed)
        - 64 hex characters (optionally surrounded by whitespace)
        - standard base64 of the 32 raw bytes
    """
    if not manifest_signing_key_installed():
        return
    signature_hex = ""
    signature = manifest.get("signature")
    if isinstance(signature, dict):
        signature_hex = str(signature.get("ed25519", ""))
    elif isinstance(signature, str):
        signature_hex = signature
    try:
        signature_bytes = bytes.fromhex(signature_hex)
    except ValueError:
        raise UpdateError("Manifest signature is not valid hex")
    # Only trim text framing for textual key encodings; a raw 32-byte
    # key may legitimately start or end with a byte that .strip() would
    # remove (0x20, 0x09-0x0d), silently corrupting the key and failing
    # every verification. Happens for ~4.6% of random raw keys.
    raw = public_key_path().read_bytes()
    if len(raw) == 32:
        public_key = raw
    else:
        key_text = raw.strip().decode("utf-8", errors="strict")
        if len(key_text) == 64 and all(
                c in "0123456789abcdefABCDEF" for c in key_text):
            public_key = bytes.fromhex(key_text)
        else:
            try:
                public_key = base64.b64decode(key_text, validate=True)
            except Exception as exc:  # noqa: BLE001 - invalid key file
                raise UpdateError(
                    f"Manifest signing key is unreadable: {exc}")
    if len(public_key) != 32:
        raise UpdateError(
            f"Manifest signing key must be 32 bytes, got {len(public_key)}")
    message = canonical_manifest_bytes(manifest)
    if not ed25519_verify(public_key, signature_bytes, message):
        raise UpdateError(
            "Manifest signature verification FAILED - update refused")


def compare_versions(version_a: str, version_b: str) -> int:
    """Numeric-aware version compare (-1/0/1).

    Handles dotted numeric versions ("1.2.10" > "1.2.9") and falls
    back to string comparison for exotic schemes. YARA rule packs may
    also use date versions ("2026.09.18") - same dotted-numeric path.
    """
    def parts(v: str) -> List[object]:
        out: List[object] = []
        for piece in str(v).replace("-", ".").split("."):
            out.append(int(piece) if piece.isdigit() else piece)
        return out

    pa, pb = parts(version_a), parts(version_b)
    for a, b in zip(pa, pb):
        if a == b:
            continue
        if isinstance(a, int) and isinstance(b, int):
            return -1 if a < b else 1
        sa, sb = str(a), str(b)
        return -1 if sa < sb else 1
    # Shorter (prefix) version sorts lower: "1.0" < "1.0.1".
    return (len(pa) > len(pb)) - (len(pa) < len(pb))


class UpdateService:
    """Verifies and installs signature updates with rollback support."""

    def __init__(self) -> None:
        self.settings = get_settings()

    # ------------------------------------------------------------------
    # Checking
    # ------------------------------------------------------------------

    def check_for_updates(self) -> Dict[str, object]:
        """Fetch the update manifest (if configured).

        Returns dict with keys: available, version, error. Never
        installs anything by itself. When a signing key is installed
        the manifest signature is verified during the check so a
        bad manifest never even offers an install.
        """
        result: Dict[str, object] = {"available": False, "version": None,
                                     "error": ""}
        url = self.settings.get("updates.update_url", "")
        if not url:
            result["error"] = "No update URL configured (offline mode)."
            return result

        try:
            raw = _https_get(url, MAX_MANIFEST_BYTES)
            manifest = json.loads(raw.decode("utf-8"))
        except (UpdateError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            result["error"] = f"Update check failed: {exc}"
            logger.warning("%s", result["error"])
            return result

        version = manifest.get("version")
        if not version:
            result["error"] = "Manifest missing version field."
            return result

        try:
            _verify_manifest_signature(manifest)
        except UpdateError as exc:
            result["error"] = str(exc)
            logger.error("%s", exc)
            return result

        current = str(self.settings.get("database.signature_db_version", "0"))
        result["version"] = version
        result["available"] = compare_versions(str(version), current) > 0
        result["manifest"] = manifest
        return result

    # ------------------------------------------------------------------
    # Installing
    # ------------------------------------------------------------------

    def install_update(self, manifest: Dict[str, object]) -> bool:
        """Download, verify, and install a verified signature set.

        The manifest signature (when required) must verify, every file
        must match its manifest SHA-256, and the whole set is staged
        before anything is swapped. A versioned backup of the previous
        set is kept for rollback.
        """
        _verify_manifest_signature(manifest)

        entries = manifest.get("files", [])
        if not isinstance(entries, list) or not entries:
            raise UpdateError("Manifest contains no file entries")

        target_dir = paths.signatures_dir()
        version = str(manifest.get("version", "unknown"))
        versioned_backup = self.backup_dir(version)
        downloaded: List[tuple] = []
        total_bytes = 0

        try:
            for entry in entries:
                rel_path = str(entry.get("path", ""))
                expected_hash = str(entry.get("sha256", "")).lower()
                file_url = str(entry.get("url", ""))

                if not rel_path or not expected_hash or not file_url:
                    raise UpdateError(f"Invalid manifest entry: {entry!r}")

                # Path traversal guard: target must stay in signatures/.
                target = (target_dir / rel_path).resolve()
                if target_dir.resolve() not in target.parents:
                    raise UpdateError(
                        f"Manifest path escapes signatures dir: {rel_path}")

                data = _https_get(file_url, MAX_UPDATE_FILE_BYTES, timeout=60)
                total_bytes += len(data)
                if total_bytes > MAX_TOTAL_UPDATE_BYTES:
                    raise UpdateError("Update set exceeds total size cap")

                actual_hash = hashlib.sha256(data).hexdigest()
                if actual_hash != expected_hash:
                    raise UpdateError(
                        f"Integrity check failed for {rel_path}: "
                        f"expected {expected_hash[:16]}..., "
                        f"got {actual_hash[:16]}...")

                staged = target.with_suffix(target.suffix + ".staging")
                staged.parent.mkdir(parents=True, exist_ok=True)
                staged.write_bytes(data)
                downloaded.append((staged, target))

            # All verified: back up current files, then swap in.
            versioned_backup.mkdir(parents=True, exist_ok=True)
            for staged, target in downloaded:
                if target.exists():
                    shutil.copy2(target, versioned_backup / target.name)
                staged.replace(target)
        except UpdateError:
            for staged, _ in downloaded:
                try:
                    staged.unlink(missing_ok=True)
                except OSError:
                    pass
            raise
        except OSError as exc:
            raise UpdateError(f"Update installation I/O error: {exc}") from exc

        if "version" in manifest:
            self.settings.set("database.signature_db_version", version)
            from utils.file_utils import utc_timestamp

            self.settings.set("database.signature_db_updated",
                              utc_timestamp())
            # Invalidate any cached scan verdicts: new signatures must
            # get a chance to re-check previously-clean files.
            try:
                from database.database import get_database

                get_database().setting_set(
                    "scan_cache_invalidate", version)
            except Exception:  # noqa: BLE001 - bookkeeping is best effort
                pass

        # Signature engines reload lazily (hash DB re-read per lookup
        # cycle, YARA hot-reloads by fingerprint), so no restart is
        # needed for the new signatures to take effect.
        logger.info("Signature update installed: version %s (%d file(s))",
                    version, len(downloaded))
        return True

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------

    def backup_dir(self, version: str) -> Path:
        """Versioned backup directory for a signature set version."""
        safe = "".join(c for c in str(version) if c.isalnum() or c in "._-")
        return paths.signatures_dir().parent / "signature_backups" / safe

    def list_backups(self) -> List[str]:
        """Available rollback versions, newest first."""
        base = paths.signatures_dir().parent / "signature_backups"
        if not base.is_dir():
            return []
        versions = [d.name for d in base.iterdir() if d.is_dir()]
        return sorted(versions, key=lambda v: v, reverse=True)

    def rollback(self, version: Optional[str] = None) -> bool:
        """Restore signatures from a versioned backup.

        With no version given, the most recent backup is restored.
        Returns False when no suitable backup exists (fail safe:
        current signatures stay active).
        """
        if version is None:
            versions = self.list_backups()
            if not versions:
                logger.warning("Rollback requested but no backups exist")
                return False
            version = versions[0]
        backup_dir = self.backup_dir(version)
        if not backup_dir.is_dir():
            logger.warning("No backup for version %s", version)
            return False

        target_dir = paths.signatures_dir()
        restored = 0
        for backup_file in backup_dir.rglob("*"):
            if not backup_file.is_file():
                continue
            relative = backup_file.relative_to(backup_dir)
            dest = target_dir / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup_file, dest)
            restored += 1
        if restored:
            self.settings.set("database.signature_db_version", str(version))
            logger.info("Rolled back signatures to %s (%d file(s))",
                        version, restored)
        return restored > 0

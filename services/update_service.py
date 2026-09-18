"""LocalGuard Antivirus - signature update service.

Checks for and installs signature database updates over HTTPS with
integrity verification (spec section 37). Updates are never trusted
blindly: manifest SHA-256 hashes must match before installation, and
the previous database is retained for rollback. Offline operation is
unaffected - this service is entirely optional.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import urllib.request
from pathlib import Path
from typing import Dict, Optional

from utils import get_logger, paths
from utils.settings import get_settings

logger = get_logger("update_service")

MANIFEST_SCHEMA_VERSION = 1


class UpdateError(Exception):
    """Raised when an update cannot be validated or installed."""


def _sha256_of_file(path: Path) -> str:
    """Chunked SHA-256 of a local file."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class UpdateService:
    """Verifies and installs signature updates."""

    def __init__(self) -> None:
        self.settings = get_settings()

    # ------------------------------------------------------------------
    # Checking
    # ------------------------------------------------------------------

    def check_for_updates(self) -> Dict[str, object]:
        """Fetch the update manifest (if configured).

        Returns dict with keys: available, version, error.
        Never executes or installs anything by itself.
        """
        result: Dict[str, object] = {"available": False, "version": None,
                                     "error": ""}
        url = self.settings.get("updates.update_url", "")
        if not url:
            result["error"] = "No update URL configured (offline mode)."
            return result
        if not url.lower().startswith("https://"):
            result["error"] = "Update URL must use HTTPS."
            return result

        try:
            req = urllib.request.Request(  # noqa: S310 - HTTPS enforced above
                url, headers={"User-Agent": "LocalGuard/1.0"}
            )
            with urllib.request.urlopen(req, timeout=20) as response:  # noqa: S310
                manifest = json.loads(response.read().decode("utf-8"))
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            result["error"] = f"Update check failed: {exc}"
            logger.warning("%s", result["error"])
            return result

        version = manifest.get("version")
        if not version:
            result["error"] = "Manifest missing version field."
            return result

        current = str(self.settings.get("database.signature_db_version", "0"))
        result["version"] = version
        result["available"] = str(version) != current
        result["manifest"] = manifest
        return result

    # ------------------------------------------------------------------
    # Installing
    # ------------------------------------------------------------------

    def install_update(self, manifest: Dict[str, object]) -> bool:
        """Download, verify, and install a signed/hashed signature set."""
        entries = manifest.get("files", [])
        if not isinstance(entries, list) or not entries:
            raise UpdateError("Manifest contains no file entries")

        target_dir = paths.signatures_dir()
        backup_dir = paths.signatures_dir().parent / "signatures_backup"
        downloaded: list = []

        try:
            for entry in entries:
                rel_path = str(entry.get("path", ""))
                expected_hash = str(entry.get("sha256", "")).lower()
                file_url = str(entry.get("url", ""))

                if not rel_path or not expected_hash or not file_url.startswith("https://"):
                    raise UpdateError(f"Invalid manifest entry: {entry!r}")

                # Path traversal guard.
                target = (target_dir / rel_path).resolve()
                if not str(target).startswith(str(target_dir.resolve())):
                    raise UpdateError(f"Manifest path escapes signatures dir: {rel_path}")

                req = urllib.request.Request(  # noqa: S310 - HTTPS enforced
                    file_url, headers={"User-Agent": "LocalGuard/1.0"}
                )
                with urllib.request.urlopen(req, timeout=60) as response:  # noqa: S310
                    data = response.read()

                actual_hash = hashlib.sha256(data).hexdigest()
                if actual_hash != expected_hash:
                    raise UpdateError(
                        f"Integrity check failed for {rel_path}: "
                        f"expected {expected_hash[:16]}..., got {actual_hash[:16]}..."
                    )

                staged = target_dir / f"{rel_path}.staging"
                staged.parent.mkdir(parents=True, exist_ok=True)
                staged.write_bytes(data)
                downloaded.append((staged, target))

            # All verified: back up current DB, then swap in.
            backup_dir.mkdir(parents=True, exist_ok=True)
            for staged, target in downloaded:
                if target.exists():
                    shutil.copy2(target, backup_dir / target.name)
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
            self.settings.set("database.signature_db_version",
                              str(manifest["version"]))

        # Reload the signature engine on next use.
        logger.info("Signature update installed: version %s", manifest.get("version"))
        return True

    def rollback(self) -> bool:
        """Restore signatures from the backup directory."""
        backup_dir = paths.signatures_dir().parent / "signatures_backup"
        if not backup_dir.is_dir():
            return False
        restored = 0
        for backup_file in backup_dir.iterdir():
            if backup_file.is_file():
                shutil.copy2(backup_file, paths.signatures_dir() / backup_file.name)
                restored += 1
        logger.info("Rolled back %d signature files", restored)
        return restored > 0

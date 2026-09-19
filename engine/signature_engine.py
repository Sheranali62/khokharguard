"""Khokhar & Son's Antivirus - signature engine.

Loads the local hash signature database (signatures/hashes.json),
syncs it with the SQLite signatures table, supports EICAR testing,
and detects by exact SHA-256 match (spec sections 14-15).

Never fabricates malware signatures: the bundled database contains
only the EICAR test entry. Users and updates can extend it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional

from utils import get_logger, paths
from utils.file_utils import sha256_of_bytes

logger = get_logger("signature_engine")

# The standard EICAR test string (harmless, industry standard - see
# https://www.eicar.org). Used for safe self-testing of detection.
EICAR_STRING = (
    r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
)
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

BUNDLED_SIGNATURE_NAMES = {"EICAR.Test.File"}


class SignatureMatch:
    """Result of a successful signature lookup."""

    def __init__(self, name: str, severity: str, category: str,
                 description: str, sha256: str) -> None:
        self.name = name
        self.severity = severity
        self.category = category
        self.description = description
        self.sha256 = sha256

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<SignatureMatch {self.name} ({self.severity})>"


class SignatureEngine:
    """Exact SHA-256 signature matching with a JSON + SQLite backend."""

    def __init__(self, database=None) -> None:
        self._database = database
        self._signatures: Dict[str, Dict[str, str]] = {}
        self.reload()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def reload(self) -> None:
        """Reload signatures from JSON file and database."""
        self._signatures = {}

        json_path = paths.hashes_signature_path()
        if json_path.is_file():
            try:
                data = json.loads(json_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self._signatures.update(
                        {k.lower(): v for k, v in data.items() if isinstance(v, dict)}
                    )
            except (OSError, json.JSONDecodeError) as exc:
                logger.error("Could not load %s: %s", json_path, exc)
        else:
            logger.warning("Signature file missing: %s", json_path)

        if self._database is not None:
            try:
                self._signatures.update(self._database.all_signatures())
                self._sync_eicar_to_db()
            except Exception as exc:  # noqa: BLE001 - DB optional at this layer
                logger.debug("Signature DB sync skipped: %s", exc)

        logger.info("Signature database loaded: %d entries", len(self._signatures))

    def _sync_eicar_to_db(self) -> None:
        """Ensure the EICAR entry exists in the SQLite signatures table."""
        assert self._database is not None
        try:
            if self._database.signature_count() == 0:
                self._database.upsert_signature(
                    EICAR_SHA256, "EICAR.Test.File", "high", "test",
                    "Standard harmless antivirus test file (eicar.org).",
                    source="local",
                )
                self._signatures[EICAR_SHA256] = {
                    "name": "EICAR.Test.File", "severity": "high",
                    "category": "test",
                    "description": "Standard harmless antivirus test file.",
                }
        except Exception as exc:  # noqa: BLE001
            logger.debug("EICAR DB seed skipped: %s", exc)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @property
    def count(self) -> int:
        """Number of loaded signatures."""
        return len(self._signatures)

    def lookup(self, sha256: str) -> Optional[SignatureMatch]:
        """Return a SignatureMatch if the hash is known."""
        entry = self._signatures.get((sha256 or "").lower())
        if not entry:
            return None
        return SignatureMatch(
            name=entry.get("name", "Unknown.Signature"),
            severity=entry.get("severity", "medium"),
            category=entry.get("category", "malware"),
            description=entry.get("description", ""),
            sha256=sha256.lower(),
        )

    def is_eicar(self, data: bytes) -> bool:
        """True when *data* starts with the EICAR test string."""
        return data[: len(EICAR_STRING)] == EICAR_STRING.encode("ascii")

    def eicar_match(self) -> SignatureMatch:
        """Signature match for the EICAR test string."""
        return SignatureMatch(
            name="EICAR.Test.File", severity="high", category="test",
            description="Standard harmless antivirus test file (eicar.org).",
            sha256=EICAR_SHA256,
        )

    # ------------------------------------------------------------------
    # User signature management
    # ------------------------------------------------------------------

    def add_signature(self, sha256: str, name: str, severity: str = "high",
                      category: str = "malware", description: str = "",
                      persist_json: bool = True) -> bool:
        """Add a user-created signature (used by quarantine 'block hash')."""
        sha256 = (sha256 or "").lower()
        if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
            logger.warning("Rejected invalid signature hash: %r", sha256[:16])
            return False
        self._signatures[sha256] = {
            "name": name, "severity": severity,
            "category": category, "description": description,
        }
        if self._database is not None:
            self._database.upsert_signature(sha256, name, severity, category,
                                            description, source="local")
        if persist_json:
            self._persist_json()
        return True

    def remove_signature(self, sha256: str) -> None:
        """Remove a signature by hash."""
        self._signatures.pop((sha256 or "").lower(), None)
        if self._database is not None:
            self._database.remove_signature(sha256)
        self._persist_json()

    def _persist_json(self) -> None:
        """Write the in-memory signatures back to hashes.json."""
        json_path = paths.hashes_signature_path()
        try:
            json_path.parent.mkdir(parents=True, exist_ok=True)
            json_path.write_text(
                json.dumps(self._signatures, indent=2), encoding="utf-8"
            )
        except OSError as exc:
            logger.error("Could not persist signatures: %s", exc)

    def version_label(self) -> str:
        """Human-readable database version for the dashboard."""
        return f"{len(self._signatures)} signatures"


def sha256_of_text(text: str) -> str:
    """Helper for tests/tools: hash of a text string."""
    return sha256_of_bytes(text.encode("utf-8"))

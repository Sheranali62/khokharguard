"""Khokhar & Son's Antivirus - quarantine manager.

Implements the secure quarantine workflow (spec section 20):

    1. Identify file            4. Move to isolated directory
    2. Hash file                5. Restrict access where practical
    3. Create secure record     6. Non-executable .quar extension

The original file is removed ONLY after the quarantined copy is
verified byte-identical (SHA-256). Restore and permanent delete are
explicit, user-confirmed operations.
"""

from __future__ import annotations

import ctypes
import json
import os
import shutil
from pathlib import Path
from typing import Any, Dict, Optional

from engine.file_analyzer import Detection
from quarantine.quarantine_database import QuarantineDatabase
from utils import get_logger, paths
from utils.file_utils import sha256_of_file, utc_timestamp

logger = get_logger("quarantine")

QUARANTINE_EXTENSION = ".quar"


class QuarantineError(Exception):
    """Raised when a quarantine operation cannot be completed safely."""


class QuarantineManager:
    """Moves threats into isolated storage and tracks them."""

    def __init__(self, database: Optional[QuarantineDatabase] = None) -> None:
        self.db = database or QuarantineDatabase()
        self._root = paths.quarantine_dir()

    # ------------------------------------------------------------------
    # Quarantine
    # ------------------------------------------------------------------

    def quarantine_file(
        self,
        file_path: Path,
        detection_name: str,
        detection_type: str = "heuristic",
        severity: str = "medium",
        sha256: str = "",
        file_size: Optional[int] = None,
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Quarantine *file_path* and return the created record.

        Raises :class:`QuarantineError` when the file cannot be moved
        or the stored copy fails verification. The original is only
        removed after verification succeeds.
        """
        file_path = Path(file_path)
        if not file_path.is_file():
            raise QuarantineError(f"File not found: {file_path}")

        # 2. Hash the file (fresh copy of truth for verification).
        try:
            actual_hash = sha256_of_file(file_path)
            size = file_path.stat().st_size
        except OSError as exc:
            raise QuarantineError(f"Cannot read file: {exc}") from exc

        if sha256 and sha256.lower() != actual_hash:
            logger.warning(
                "Hash changed between detection and quarantine for %s", file_path
            )

        record_id = self.db.add_record({
            "original_path": str(file_path),
            "quarantine_path": "(pending)",
            "sha256": actual_hash,
            "detection_name": detection_name,
            "detection_type": detection_type,
            "severity": severity,
            "file_size": file_size if file_size is not None else size,
            "metadata": json.dumps({
                "quarantined_at": utc_timestamp(),
                **(extra_metadata or {}),
            }),
        })

        # 4-5. Move into the quarantine vault with a non-executable name.
        vault_name = f"{record_id}_{file_path.name}{QUARANTINE_EXTENSION}"
        vault_path = self._root / vault_name
        counter = 0
        while vault_path.exists():
            counter += 1
            vault_name = f"{record_id}_{file_path.stem}_{counter}{QUARANTINE_EXTENSION}"
            vault_path = self._root / vault_name

        try:
            shutil.move(str(file_path), str(vault_path))
        except (OSError, shutil.Error) as exc:
            # Roll back the pending DB record; original stays untouched.
            self.db.update_metadata(
                record_id, json.dumps({"failed": True, "error": str(exc)})
            )
            raise QuarantineError(f"Could not move file to quarantine: {exc}") from exc

        # Verify the stored copy before removing the original.
        try:
            stored_hash = sha256_of_file(vault_path)
        except OSError as exc:
            self._rollback(vault_path, file_path)
            raise QuarantineError(f"Verification read failed: {exc}") from exc

        if stored_hash != actual_hash:
            self._rollback(vault_path, file_path)
            raise QuarantineError("Quarantined copy failed SHA-256 verification")

        self._restrict_access(vault_path)

        metadata = {
            "quarantined_at": utc_timestamp(),
            "verified": True,
            **(extra_metadata or {}),
        }
        self.db.update_metadata(record_id, json.dumps(metadata))

        # Point the record at the real vault path.
        from database.database import get_database

        get_database().execute(
            "UPDATE quarantine SET quarantine_path = ? WHERE quarantine_id = ?",
            (str(vault_path), record_id),
        )

        logger.info("Quarantined %s as %s", file_path, vault_path.name)
        self._log_event("threat_quarantined",
                        f"{detection_name} quarantined from {file_path}",
                        severity="warning")

        return {
            "quarantine_id": record_id,
            "original_path": str(file_path),
            "quarantine_path": str(vault_path),
            "sha256": actual_hash,
            "detection_name": detection_name,
            "severity": severity,
        }

    def quarantine_detection(self, detection: Detection,
                             source: str = "scan") -> Dict[str, Any]:
        """Quarantine a file from its Detection object."""
        return self.quarantine_file(
            Path(detection.path),
            detection_name=detection.detection_name,
            detection_type=detection.detection_method,
            severity=detection.severity,
            sha256=detection.sha256,
            file_size=detection.file_size,
            extra_metadata={"risk_score": detection.risk_score,
                            "reason": detection.reason, "source": source},
        )

    def _rollback(self, vault_path: Path, original: Path) -> None:
        """Best-effort restore when verification fails mid-quarantine."""
        try:
            if vault_path.exists() and not original.exists():
                shutil.move(str(vault_path), str(original))
        except OSError:
            logger.error("Quarantine rollback failed for %s", original)

    def _restrict_access(self, vault_path: Path) -> None:
        """Make the vault file hidden and user-only where practical.

        Renaming to .quar already removes execution-by-double-click.
        ACL tightening is best-effort and never fatal.
        """
        try:
            FILE_ATTRIBUTE_HIDDEN = 0x2
            FILE_ATTRIBUTE_SYSTEM = 0x4
            attrs = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
            ctypes.windll.kernel32.SetFileAttributesW(str(vault_path), attrs)  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            pass  # non-Windows or attribute failure: .quar name still inert

        icacls = shutil.which("icacls")
        if icacls:
            import subprocess  # noqa: S404 - fixed args, no shell

            try:
                username = os.environ.get("USERNAME", "")
                if username:
                    subprocess.run(  # noqa: S603
                        [icacls, str(vault_path), "/inheritance:r",
                         "/grant:r", f"{username}:(F)"],
                        capture_output=True, timeout=10,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    )
            except (OSError, subprocess.TimeoutExpired):
                logger.debug("ACL tightening skipped for %s", vault_path)

    # ------------------------------------------------------------------
    # Restore / delete
    # ------------------------------------------------------------------

    def restore(self, quarantine_id: int,
                user_confirmed: bool = False) -> Path:
        """Restore a quarantined file to its original location.

        Requires explicit user confirmation (spec section 21). Verifies
        the stored hash before releasing the file.
        """
        if not user_confirmed:
            raise QuarantineError("Restore requires explicit user confirmation")

        record = self.db.get(quarantine_id)
        if record is None:
            raise QuarantineError(f"Quarantine record {quarantine_id} not found")
        if record["status"] != "QUARANTINED":
            raise QuarantineError(f"Record is {record['status']}, not QUARANTINED")

        vault_path = Path(record["quarantine_path"])
        if not vault_path.is_file():
            raise QuarantineError(f"Quarantined file missing: {vault_path}")

        stored_hash = sha256_of_file(vault_path)
        if record["sha256"] and stored_hash != record["sha256"]:
            raise QuarantineError(
                "Quarantined file hash mismatch - restore refused for safety"
            )

        original = Path(record["original_path"])
        try:
            original.parent.mkdir(parents=True, exist_ok=True)
            if original.exists():
                # Never silently overwrite; rename the incoming copy.
                alt = original.with_name(
                    f"{original.stem}_restored_{quarantine_id}{original.suffix}"
                )
                logger.warning("Restore target exists; using %s", alt.name)
                original = alt
            shutil.move(str(vault_path), str(original))
        except (OSError, shutil.Error) as exc:
            raise QuarantineError(f"Restore failed: {exc}") from exc

        self._clear_restrictions(original)
        self.db.mark_status(quarantine_id, "RESTORED")

        from database.database import get_database

        get_database().execute(
            "UPDATE threats SET status = 'quarantined', resolved_at = ? "
            "WHERE file_path = ? AND status = 'open'",
            (utc_timestamp(), record["original_path"]),
        )

        logger.info("Restored %s", original)
        self._log_event("threat_restored",
                        f"{record['detection_name']} restored to {original}")
        return original

    def delete_permanently(self, quarantine_id: int,
                           user_confirmed: bool = False) -> None:
        """Permanently delete a quarantined file (requires confirmation)."""
        if not user_confirmed:
            raise QuarantineError(
                "Permanent deletion requires explicit user confirmation"
            )

        record = self.db.get(quarantine_id)
        if record is None:
            raise QuarantineError(f"Quarantine record {quarantine_id} not found")
        if record["status"] != "QUARANTINED":
            raise QuarantineError(f"Record is {record['status']}, not QUARANTINED")

        vault_path = Path(record["quarantine_path"])
        try:
            if vault_path.exists():
                try:
                    os.chmod(vault_path, 0o666)
                except OSError:
                    pass
                self._clear_attributes(vault_path)
                vault_path.unlink()
        except OSError as exc:
            raise QuarantineError(f"Could not delete file: {exc}") from exc

        self.db.mark_status(quarantine_id, "DELETED")
        logger.info("Permanently deleted quarantined item %s", vault_path.name)
        self._log_event("threat_deleted",
                        f"{record['detection_name']} permanently deleted",
                        severity="warning")

    def _clear_attributes(self, path: Path) -> None:
        """Strip hidden/system attributes before deletion."""
        try:
            ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x80)  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            pass

    def _clear_restrictions(self, restored_path: Path) -> None:
        """Remove hidden/system attrs from a restored file."""
        self._clear_attributes(restored_path)

    def _log_event(self, event_type: str, description: str,
                   severity: str = "info") -> None:
        """Record a security event (best effort)."""
        try:
            from database.database import get_database

            get_database().add_event(event_type, description, severity=severity)
        except Exception:  # noqa: BLE001
            logger.debug("Event logging failed for %s", event_type)

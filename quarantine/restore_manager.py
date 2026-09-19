"""Khokhar & Son's Antivirus - restore manager.

Unified restore entry point for quarantined files and cleanup
operations (spec section 47). Every restore creates an audit trail so
users can review what was changed and undo cleanups where possible.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

from quarantine.quarantine_manager import QuarantineError, QuarantineManager
from utils import get_logger

logger = get_logger("restore_manager")


class RestoreManager:
    """Coordinates restore operations with audit logging."""

    def __init__(self, quarantine_manager: Optional[QuarantineManager] = None) -> None:
        self.quarantine = quarantine_manager or QuarantineManager()

    def restore_quarantined(self, quarantine_id: int,
                            user_confirmed: bool = False) -> Path:
        """Restore one quarantined file (delegates with confirmation)."""
        logger.info("User-initiated restore of quarantine item %s", quarantine_id)
        return self.quarantine.restore(quarantine_id, user_confirmed=user_confirmed)

    def restore_cleanup(self, cleanup_id: int,
                        user_confirmed: bool = False) -> bool:
        """Undo a cleanup operation from cleanup_history.

        Returns True when the cleanup was successfully reversed.
        """
        if not user_confirmed:
            raise QuarantineError("Cleanup restore requires explicit user confirmation")

        from database.database import get_database

        db = get_database()
        record = db.query_one(
            "SELECT * FROM cleanup_history WHERE cleanup_id = ?", (cleanup_id,)
        )
        if record is None:
            raise QuarantineError(f"Cleanup record {cleanup_id} not found")
        if record["restored"]:
            logger.info("Cleanup %s already restored", cleanup_id)
            return False

        from cleanup.recovery import undo_cleanup_record

        ok = undo_cleanup_record(record)
        if ok:
            db.mark_cleanup_restored(cleanup_id)
            db.add_event("cleanup_restored",
                         f"Cleanup record {cleanup_id} restored")
        return ok

    def cleanup_history(self) -> List[Dict[str, object]]:
        """Recent cleanup records for the recovery UI."""
        from database.database import get_database

        return get_database().list_cleanup_records(include_restored=True)

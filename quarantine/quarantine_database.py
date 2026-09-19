"""Khokhar & Son's Antivirus - quarantine database access.

Thin, quarantine-specific facade over the shared Database so the
quarantine package has one obvious place for its persistence logic.
All queries remain parameterized.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from database.database import Database
from utils.file_utils import utc_timestamp


class QuarantineDatabase:
    """CRUD helpers for the quarantine table."""

    def __init__(self, database: Optional[Database] = None) -> None:
        self._db = database

    def _database(self) -> Database:
        """Resolve the shared database lazily."""
        if self._db is None:
            from database.database import get_database

            self._db = get_database()
        return self._db

    def add_record(self, record: Dict[str, Any]) -> int:
        """Insert a quarantine record; return its id."""
        return self._database().add_quarantine_record(record)

    def get(self, quarantine_id: int) -> Optional[Dict[str, Any]]:
        """Fetch one quarantine record."""
        return self._database().get_quarantine_record(quarantine_id)

    def list_active(self) -> List[Dict[str, Any]]:
        """All records currently QUARANTINED."""
        return self._database().list_quarantine(active_only=True)

    def list_all(self) -> List[Dict[str, Any]]:
        """All records including restored/deleted."""
        return self._database().list_quarantine(active_only=False)

    def mark_status(self, quarantine_id: int, status: str) -> None:
        """Set QUARANTINED / RESTORED / DELETED with timestamps."""
        self._database().mark_quarantine_status(quarantine_id, status)

    def count_active(self) -> int:
        """Number of active quarantine records."""
        return self._database().quarantine_count()

    def update_metadata(self, quarantine_id: int, metadata_json: str) -> None:
        """Replace the metadata JSON of a record."""
        self._database().execute(
            "UPDATE quarantine SET metadata = ? WHERE quarantine_id = ?",
            (metadata_json, quarantine_id),
        )

    def now(self) -> str:
        """Consistent timestamp helper."""
        return utc_timestamp()

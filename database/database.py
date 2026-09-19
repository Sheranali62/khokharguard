"""LocalGuard Antivirus - SQLite database layer.

Single connection management, schema initialisation from
database/schema.sql, and thin, parameterized helper accessors for the
tables used across the application. All queries are parameterized -
user input is never concatenated into SQL (spec section 33).
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from utils import get_logger, paths
from utils.file_utils import utc_timestamp

logger = get_logger("database")

_SCHEMA_TABLES = (
    "settings", "scan_history", "scan_results", "threats", "quarantine",
    "security_events", "signatures", "exclusions", "usb_devices",
    "cleanup_history",
)


class Database:
    """Thread-safe SQLite wrapper for LocalGuard."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._path = Path(db_path) if db_path else paths.database_path()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        self._open()
        self.initialise_schema()

    # ------------------------------------------------------------------
    # Connection handling
    # ------------------------------------------------------------------

    def _open(self) -> None:
        """Open the SQLite connection with sensible pragmas.

        Corruption is tolerated here: a file that is not a database
        (or fails integrity checks at open time) is moved aside as
        ``<name>.corrupt.bak`` and recreated, so one corrupt file never
        takes the whole application down (spec section 50).
        """
        self._conn = sqlite3.connect(
            str(self._path), check_same_thread=False, timeout=15.0
        )
        self._conn.row_factory = sqlite3.Row
        try:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA foreign_keys=ON;")
        except sqlite3.DatabaseError as exc:
            logger.error("Database corrupt at open (%s); recreating", exc)
            self._conn.close()
            backup = self._path.with_suffix(".corrupt.bak")
            backup.unlink(missing_ok=True)
            self._path.rename(backup)
            self._conn = sqlite3.connect(
                str(self._path), check_same_thread=False, timeout=15.0
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA foreign_keys=ON;")

    def close(self) -> None:
        """Close the connection (safe to call twice)."""
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                except sqlite3.Error:
                    pass
                self._conn = None

    def _execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        """Execute inside the lock; reconnect transparently on I/O error."""
        with self._lock:
            if self._conn is None:
                self._open()
            assert self._conn is not None
            try:
                return self._conn.execute(sql, tuple(params))
            except sqlite3.OperationalError as exc:
                logger.warning("DB reconnect after error: %s", exc)
                try:
                    self._conn.close()
                except sqlite3.Error:
                    pass
                self._open()
                assert self._conn is not None
                return self._conn.execute(sql, tuple(params))

    def commit(self) -> None:
        """Commit the current transaction."""
        with self._lock:
            if self._conn is not None:
                self._conn.commit()

    def initialise_schema(self) -> None:
        """Create tables from schema.sql if the DB is empty."""
        schema_file = paths.schema_path()
        if not schema_file.is_file():
            # PyInstaller fallback: schema ships next to the binary.
            alt = paths.executable_dir() / "database" / "schema.sql"
            if alt.is_file():
                schema_file = alt
            else:
                logger.error("schema.sql not found at %s", schema_file)
                raise FileNotFoundError(f"schema.sql not found: {schema_file}")
        sql_text = schema_file.read_text(encoding="utf-8")
        with self._lock:
            assert self._conn is not None
            try:
                self._conn.executescript(sql_text)
                self._conn.commit()
            except sqlite3.DatabaseError as exc:
                # Corrupt database: move aside and recreate from scratch.
                logger.error("Database corrupt (%s); recreating", exc)
                self._conn.close()
                self._path.with_suffix(".corrupt.bak").unlink(missing_ok=True)
                self._path.rename(self._path.with_suffix(".corrupt.bak"))
                self._open()
                assert self._conn is not None
                self._conn.executescript(sql_text)
                self._conn.commit()
        logger.info("Database ready at %s", self._path)

    # ------------------------------------------------------------------
    # Generic helpers
    # ------------------------------------------------------------------

    def query(self, sql: str, params: Iterable[Any] = ()) -> List[Dict[str, Any]]:
        """Run a SELECT and return rows as dicts."""
        cur = self._execute(sql, params)
        return [dict(row) for row in cur.fetchall()]

    def query_one(self, sql: str, params: Iterable[Any] = ()) -> Optional[Dict[str, Any]]:
        """Run a SELECT returning at most one row as dict."""
        cur = self._execute(sql, params)
        row = cur.fetchone()
        return dict(row) if row else None

    def execute(self, sql: str, params: Iterable[Any] = ()) -> int:
        """Run an INSERT/UPDATE/DELETE and commit; return lastrowid."""
        cur = self._execute(sql, params)
        self.commit()
        return int(cur.lastrowid or 0)

    def execute_many(self, sql: str, rows: Iterable[Iterable[Any]]) -> None:
        """Run executemany and commit."""
        with self._lock:
            assert self._conn is not None
            self._conn.executemany(sql, [tuple(r) for r in rows])
            self._conn.commit()

    # ------------------------------------------------------------------
    # settings
    # ------------------------------------------------------------------

    def setting_get(self, key: str) -> Optional[str]:
        """Read a persisted DB-level setting value."""
        row = self.query_one("SELECT value FROM settings WHERE key = ?", (key,))
        return row["value"] if row else None

    def setting_set(self, key: str, value: str) -> None:
        """Upsert a DB-level setting."""
        self.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
            "updated_at = excluded.updated_at",
            (key, value, utc_timestamp()),
        )

    # ------------------------------------------------------------------
    # scan_history
    # ------------------------------------------------------------------

    def scan_start(self, scan_type: str, targets: List[str]) -> int:
        """Insert a running scan row; return its scan_id."""
        return self.execute(
            "INSERT INTO scan_history (scan_type, start_time, status, scan_targets) "
            "VALUES (?, ?, 'running', ?)",
            (scan_type, utc_timestamp(), json.dumps(targets)),
        )

    def scan_finish(
        self, scan_id: int, status: str, files_scanned: int, threats: int,
        suspicious: int, quarantined: int, skipped: int, errors: int,
        duration_secs: float, directories_scanned: int = 0,
    ) -> None:
        """Finalise a scan row with statistics."""
        self.execute(
            "UPDATE scan_history SET end_time = ?, status = ?, files_scanned = ?, "
            "directories_scanned = ?, threats_found = ?, suspicious_found = ?, "
            "quarantined = ?, skipped = ?, errors = ?, duration_secs = ? "
            "WHERE scan_id = ?",
            (utc_timestamp(), status, files_scanned, directories_scanned, threats,
             suspicious, quarantined, skipped, errors, round(duration_secs, 2), scan_id),
        )

    def last_scan(self) -> Optional[Dict[str, Any]]:
        """Return the most recent completed scan, if any."""
        return self.query_one(
            "SELECT * FROM scan_history WHERE status = 'completed' "
            "ORDER BY scan_id DESC LIMIT 1"
        )

    def list_scans(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Return recent scans, newest first."""
        return self.query(
            "SELECT * FROM scan_history ORDER BY scan_id DESC LIMIT ?", (limit,)
        )

    def delete_scan(self, scan_id: int) -> None:
        """Delete a scan and its per-file results."""
        self.execute("DELETE FROM scan_history WHERE scan_id = ?", (scan_id,))

    def clear_scan_history(self) -> None:
        """Delete all scan history rows."""
        self.execute("DELETE FROM scan_history")

    # ------------------------------------------------------------------
    # scan_results
    # ------------------------------------------------------------------

    def add_scan_result(self, scan_id: int, result: Dict[str, Any]) -> None:
        """Persist one per-file scan result."""
        self.execute(
            "INSERT INTO scan_results (scan_id, file_path, sha256, file_size, "
            "detection_name, detection_type, severity, confidence, risk_score, "
            "reason, recommended_action, action_taken) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id, result.get("path", ""), result.get("sha256"),
                result.get("size"), result.get("detection_name"),
                result.get("detection_type"), result.get("severity"),
                result.get("confidence"), result.get("risk_score"),
                result.get("reason"), result.get("recommended_action"),
                result.get("action_taken", "none"),
            ),
        )

    def results_for_scan(self, scan_id: int) -> List[Dict[str, Any]]:
        """Return all per-file results for a scan."""
        return self.query(
            "SELECT * FROM scan_results WHERE scan_id = ? ORDER BY result_id",
            (scan_id,),
        )

    # ------------------------------------------------------------------
    # threats
    # ------------------------------------------------------------------

    def add_threat(self, threat: Dict[str, Any]) -> int:
        """Insert a threat detection; return threat_id."""
        return self.execute(
            "INSERT INTO threats (file_path, sha256, file_size, detection_name, "
            "detection_type, severity, confidence, risk_score, reason, "
            "recommended_action, source, scan_id, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                threat.get("file_path", ""), threat.get("sha256"),
                threat.get("file_size"), threat.get("detection_name", "Unknown"),
                threat.get("detection_type"), threat.get("severity"),
                threat.get("confidence"), threat.get("risk_score"),
                threat.get("reason"), threat.get("recommended_action"),
                threat.get("source", "scan"), threat.get("scan_id"),
                threat.get("status", "open"),
            ),
        )

    def list_threats(self, status: Optional[str] = None,
                     limit: int = 500) -> List[Dict[str, Any]]:
        """Return threats, optionally filtered by status."""
        if status:
            return self.query(
                "SELECT * FROM threats WHERE status = ? ORDER BY threat_id DESC LIMIT ?",
                (status, limit),
            )
        return self.query(
            "SELECT * FROM threats ORDER BY threat_id DESC LIMIT ?", (limit,)
        )

    def open_threats(self) -> List[Dict[str, Any]]:
        """Threats awaiting user action."""
        return self.list_threats(status="open")

    def set_threat_status(self, threat_id: int, status: str) -> None:
        """Update a threat's status and resolution timestamp."""
        self.execute(
            "UPDATE threats SET status = ?, resolved_at = ? WHERE threat_id = ?",
            (status, utc_timestamp() if status != "open" else None, threat_id),
        )

    def threat_counts(self) -> Dict[str, int]:
        """Aggregate threat counters for the dashboard."""
        rows = self.query(
            "SELECT status, COUNT(*) AS n FROM threats GROUP BY status"
        )
        counts = {row["status"]: row["n"] for row in rows}
        return {
            "open": counts.get("open", 0),
            "quarantined": counts.get("quarantined", 0),
            "allowed": counts.get("allowed", 0),
            "total": sum(counts.values()),
        }

    # ------------------------------------------------------------------
    # quarantine
    # ------------------------------------------------------------------

    def add_quarantine_record(self, record: Dict[str, Any]) -> int:
        """Insert a quarantine record; return quarantine_id."""
        return self.execute(
            "INSERT INTO quarantine (original_path, quarantine_path, sha256, "
            "detection_name, detection_type, severity, file_size, metadata, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'QUARANTINED')",
            (
                record.get("original_path", ""), record.get("quarantine_path", ""),
                record.get("sha256"), record.get("detection_name"),
                record.get("detection_type"), record.get("severity"),
                record.get("file_size"), record.get("metadata"),
            ),
        )

    def list_quarantine(self, active_only: bool = True) -> List[Dict[str, Any]]:
        """Return quarantine records, newest first."""
        if active_only:
            return self.query(
                "SELECT * FROM quarantine WHERE status = 'QUARANTINED' "
                "ORDER BY quarantine_id DESC"
            )
        return self.query(
            "SELECT * FROM quarantine ORDER BY quarantine_id DESC"
        )

    def get_quarantine_record(self, quarantine_id: int) -> Optional[Dict[str, Any]]:
        """Fetch one quarantine record."""
        return self.query_one(
            "SELECT * FROM quarantine WHERE quarantine_id = ?", (quarantine_id,)
        )

    def mark_quarantine_status(self, quarantine_id: int, status: str) -> None:
        """Set status and matching timestamp column for a record."""
        column = {
            "RESTORED": "restored_date", "DELETED": "deleted_date",
        }.get(status)
        if column:
            self.execute(
                f"UPDATE quarantine SET status = ?, {column} = ? WHERE quarantine_id = ?",
                (status, utc_timestamp(), quarantine_id),
            )
        else:
            self.execute(
                "UPDATE quarantine SET status = ? WHERE quarantine_id = ?",
                (status, quarantine_id),
            )

    def quarantine_count(self) -> int:
        """Count of currently quarantined items."""
        row = self.query_one(
            "SELECT COUNT(*) AS n FROM quarantine WHERE status = 'QUARANTINED'"
        )
        return int(row["n"]) if row else 0

    # ------------------------------------------------------------------
    # security_events
    # ------------------------------------------------------------------

    def add_event(self, event_type: str, description: str,
                  severity: str = "info", details: Optional[Dict[str, Any]] = None) -> None:
        """Append a security event to the audit log."""
        self.execute(
            "INSERT INTO security_events (event_type, severity, description, details) "
            "VALUES (?, ?, ?, ?)",
            (event_type, severity, description,
             json.dumps(details) if details else None),
        )

    def list_events(self, limit: int = 300) -> List[Dict[str, Any]]:
        """Return recent security events."""
        return self.query(
            "SELECT * FROM security_events ORDER BY event_id DESC LIMIT ?", (limit,)
        )

    # ------------------------------------------------------------------
    # signatures
    # ------------------------------------------------------------------

    def upsert_signature(self, sha256: str, name: str, severity: str,
                         category: str = "", description: str = "",
                         source: str = "local") -> None:
        """Insert or update one hash signature."""
        self.execute(
            "INSERT INTO signatures (sha256, name, severity, category, description, source) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(sha256) DO UPDATE SET name = excluded.name, "
            "severity = excluded.severity, category = excluded.category, "
            "description = excluded.description, source = excluded.source",
            (sha256.lower(), name, severity, category, description, source),
        )

    def remove_signature(self, sha256: str) -> None:
        """Delete a signature by hash."""
        self.execute("DELETE FROM signatures WHERE sha256 = ?", (sha256.lower(),))

    def all_signatures(self) -> Dict[str, Dict[str, str]]:
        """Return every signature keyed by SHA-256."""
        rows = self.query("SELECT * FROM signatures")
        return {
            row["sha256"]: {
                "name": row["name"],
                "severity": row["severity"],
                "category": row["category"] or "",
                "description": row["description"] or "",
            }
            for row in rows
        }

    def signature_count(self) -> int:
        """Number of stored signatures."""
        row = self.query_one("SELECT COUNT(*) AS n FROM signatures")
        return int(row["n"]) if row else 0

    # ------------------------------------------------------------------
    # exclusions
    # ------------------------------------------------------------------

    def add_exclusion(self, exclusion_type: str, value: str,
                      label: str = "") -> bool:
        """Add an exclusion; returns False when it already exists."""
        existing = self.query_one(
            "SELECT exclusion_id FROM exclusions WHERE exclusion_type = ? AND value = ?",
            (exclusion_type, value),
        )
        if existing:
            return False
        self.execute(
            "INSERT INTO exclusions (exclusion_type, value, label) VALUES (?, ?, ?)",
            (exclusion_type, value, label),
        )
        return True

    def remove_exclusion(self, exclusion_id: int) -> None:
        """Delete an exclusion by id."""
        self.execute("DELETE FROM exclusions WHERE exclusion_id = ?", (exclusion_id,))

    def list_exclusions(self) -> List[Dict[str, Any]]:
        """Return all user-configured exclusions."""
        return self.query("SELECT * FROM exclusions ORDER BY exclusion_id")

    # ------------------------------------------------------------------
    # usb_devices
    # ------------------------------------------------------------------

    def upsert_usb_device(self, drive_letter: str, volume_name: str,
                          serial: str, capacity: Optional[int],
                          free: Optional[int], fstype: str) -> int:
        """Insert/update a seen USB device; return device_id."""
        existing = self.query_one(
            "SELECT device_id FROM usb_devices WHERE drive_letter = ? AND serial = ?",
            (drive_letter, serial),
        )
        now = utc_timestamp()
        if existing:
            device_id = int(existing["device_id"])
            self.execute(
                "UPDATE usb_devices SET volume_name = ?, capacity_bytes = ?, "
                "free_bytes = ?, file_system = ?, last_seen = ? WHERE device_id = ?",
                (volume_name, capacity, free, fstype, now, device_id),
            )
            return device_id
        return self.execute(
            "INSERT INTO usb_devices (drive_letter, volume_name, serial, "
            "capacity_bytes, free_bytes, file_system, last_seen, last_scan_status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'not_scanned')",
            (drive_letter, volume_name, serial, capacity, free, fstype, now),
        )

    def set_usb_scan_result(self, device_id: int, scan_id: int, status: str) -> None:
        """Record the outcome of a USB scan."""
        self.execute(
            "UPDATE usb_devices SET last_scan_id = ?, last_scan_time = ?, "
            "last_scan_status = ? WHERE device_id = ?",
            (scan_id, utc_timestamp(), status, device_id),
        )

    def list_usb_devices(self) -> List[Dict[str, Any]]:
        """Return known USB devices."""
        return self.query("SELECT * FROM usb_devices ORDER BY last_seen DESC")

    # ------------------------------------------------------------------
    # usb_trusted_devices
    # ------------------------------------------------------------------

    def is_usb_trusted(self, serial: str, volume_name: str) -> bool:
        """True when this exact drive (serial + label) is user-trusted."""
        row = self.query_one(
            "SELECT 1 FROM usb_trusted_devices WHERE serial = ? "
            "AND volume_name = ?",
            (serial, volume_name),
        )
        return row is not None

    def trust_usb_device(self, serial: str, volume_name: str,
                         label: str = "") -> bool:
        """Trust a drive for auto-scan skipping; False when invalid.

        A drive without a serial cannot be identified reliably and is
        never trusted.
        """
        serial = (serial or "").strip()
        volume_name = (volume_name or "").strip()
        if not serial or not volume_name:
            return False
        self.execute(
            "INSERT OR IGNORE INTO usb_trusted_devices "
            "(serial, volume_name, label) VALUES (?, ?, ?)",
            (serial, volume_name, label),
        )
        return True

    def untrust_usb_device(self, serial: str, volume_name: str) -> int:
        """Revoke trust; returns rows removed."""
        cur = self._execute(
            "DELETE FROM usb_trusted_devices WHERE serial = ? "
            "AND volume_name = ?",
            (serial, volume_name),
        )
        self.commit()
        return cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0

    def list_trusted_usb_devices(self) -> List[Dict[str, Any]]:
        """All user-trusted drives, newest first."""
        return self.query(
            "SELECT * FROM usb_trusted_devices ORDER BY trusted_at DESC")

    # ------------------------------------------------------------------
    # cleanup_history
    # ------------------------------------------------------------------

    def add_cleanup_record(self, cleanup_type: str, target: str,
                           backup_data: Optional[str], description: str) -> int:
        """Record a cleanup operation with its restore snapshot."""
        return self.execute(
            "INSERT INTO cleanup_history (cleanup_type, target, backup_data, description) "
            "VALUES (?, ?, ?, ?)",
            (cleanup_type, target, backup_data, description),
        )

    def list_cleanup_records(self, include_restored: bool = True) -> List[Dict[str, Any]]:
        """Return cleanup history rows."""
        if include_restored:
            return self.query(
                "SELECT * FROM cleanup_history ORDER BY cleanup_id DESC LIMIT 200"
            )
        return self.query(
            "SELECT * FROM cleanup_history WHERE restored = 0 "
            "ORDER BY cleanup_id DESC LIMIT 200"
        )

    def mark_cleanup_restored(self, cleanup_id: int) -> None:
        """Mark a cleanup record as restored."""
        self.execute(
            "UPDATE cleanup_history SET restored = 1, restored_at = ? WHERE cleanup_id = ?",
            (utc_timestamp(), cleanup_id),
        )

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def vacuum(self) -> None:
        """Compact the database file."""
        with self._lock:
            if self._conn is not None:
                self._conn.execute("VACUUM;")
                self._conn.commit()


_shared_db: Optional[Database] = None
_shared_lock = threading.Lock()


def get_database() -> Database:
    """Return the shared Database instance."""
    global _shared_db
    with _shared_lock:
        if _shared_db is None:
            _shared_db = Database()
        return _shared_db


def reset_shared() -> None:
    """Close and forget the shared instance (tests)."""
    global _shared_db
    with _shared_lock:
        if _shared_db is not None:
            _shared_db.close()
        _shared_db = None

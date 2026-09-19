"""Khokhar & Son's Antivirus - pre-rebrand data migration.

One-time import of user data created by the pre-rebrand build
(brand name ``LocalGuard``) into the current KhokharGuard data
locations:

    - ``%LOCALAPPDATA%\\LocalGuard``  ->  ``%LOCALAPPDATA%\\KhokharGuard``
      (settings, database rows, quarantine vault, reports)
    - ``database/localguard.db``  ->  ``database/khokharguard.db``
      (source-mode development database)

Safety rules:

    - Identifies the legacy layout strictly by known file names under
      the two documented roots - it never invents other paths.
    - Copies (never moves or deletes) every file; the legacy directory
      is left untouched so the user can discard it manually.
    - Never overwrites existing KhokharGuard data: existing targets and
      existing settings keys always win.
    - Imported rows get fresh primary keys (no ID collisions with data
      the new build already created), and quarantine vault files keep
      their file names so imported records keep restoring correctly
      after their stored paths are rewritten to the new vault.
    - Runs at most once: a completion marker records the migrated
      legacy file inventory; a second call with the same legacy state
      is a no-op even if the user re-creates the legacy folder.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from database.database import Database
from utils import paths

logger = logging.getLogger("khokharguard.migration")

LEGACY_APP_NAME = "LocalGuard"

# Marker stored in the KhokharGuard app-data dir after a successful
# migration (JSON: {"completed": true, "legacy_files": [...],
# "summary": {...}, "notified": bool}).
_MIGRATION_MARKER = "legacy_migration.json"

# Legacy database file names, checked in the legacy app-data dir and
# (for source runs) the repository database directory.
_LEGACY_DB_NAMES = ("localguard.db",)

# Legacy user-data tables mirrored into the KhokharGuard database.
# The legacy schema is identical to the current one (the rebrand did
# not change schema.sql); columns are still intersected at runtime so
# an unexpected legacy schema can only ever import fewer columns.
_MIGRATED_TABLES = ("scan_history", "security_events", "quarantine")


def legacy_app_data_dir() -> Optional[Path]:
    """Directory of the legacy per-user data, if it exists.

    Returns ``None`` when ``LOCALAPPDATA`` is unavailable or the legacy
    directory does not exist (fresh machines have nothing to migrate).
    """
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        return None
    legacy = Path(base) / LEGACY_APP_NAME
    return legacy if legacy.is_dir() else None


def _marker_path() -> Path:
    """Path of the once-only completion marker."""
    return paths.app_data_dir() / _MIGRATION_MARKER


def _legacy_inventory(legacy_dir: Path) -> List[str]:
    """Relative paths of every file under the legacy directory."""
    return sorted(str(p.relative_to(legacy_dir))
                  for p in legacy_dir.rglob("*") if p.is_file())


def _already_done(legacy_files: List[str]) -> bool:
    """True when an identical migration already completed."""
    try:
        data = json.loads(
            _marker_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return bool(data.get("completed")) and \
        sorted(data.get("legacy_files", [])) == sorted(legacy_files)


def _write_marker(legacy_files: List[str],
                  summary: Dict[str, Any]) -> None:
    """Record the completed migration for the once-only guarantee."""
    try:
        marker = _marker_path()
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(
            json.dumps({"completed": True, "version": 1,
                        "legacy_files": sorted(legacy_files),
                        "summary": summary, "notified": False},
                       default=str),
            encoding="utf-8")
    except OSError:
        logger.warning("Could not write migration marker")


def pending_notification() -> Optional[Dict[str, Any]]:
    """Return the stored migration summary when the UI has not yet
    acknowledged it.

    The first call returns the summary and flips ``notified`` so the
    dialog shows exactly once; subsequent calls return ``None``. A
    corrupt or missing marker is simply 'nothing to show'.
    """
    try:
        data = json.loads(_marker_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not data.get("completed") or data.get("notified"):
        return None
    try:
        data["notified"] = True
        _marker_path().write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        logger.warning("Could not update migration marker")
        return None
    summary = data.get("summary")
    return summary if isinstance(summary, dict) else None


def _legacy_user_db(legacy_dir: Path) -> Optional[Path]:
    """Find the legacy per-user database file."""
    for name in _LEGACY_DB_NAMES:
        candidate = legacy_dir / name
        if candidate.is_file():
            return candidate
    return None


def _legacy_dev_db() -> Optional[Path]:
    """Legacy source-mode development database, if present.

    Only relevant when the new per-user database does not exist yet
    (a developer running from source with no migrated app data). The
    repository directory itself is never touched when it happens to be
    named like the legacy brand.
    """
    root = paths.project_root()
    if root.name == LEGACY_APP_NAME:
        return None
    for name in _LEGACY_DB_NAMES:
        candidate = root / "database" / name
        if candidate.is_file():
            return candidate
    return None


def _table_columns(conn: sqlite3.Connection, table: str) -> List[str]:
    """Column names of *table*; empty list when the table is absent."""
    try:
        rows = conn.execute(
            f"PRAGMA table_info({table})").fetchall()
    except sqlite3.Error:
        return []
    return [row[1] for row in rows]


def _import_database(source_db: Path, db: Database,
                     summary: Dict[str, Any],
                     new_vault: Optional[Path]) -> None:
    """Mirror user-data rows from the legacy database.

    Rows are inserted without their primary keys so the new database
    assigns fresh IDs (legacy IDs may collide with rows the new build
    already created). Quarantine vault paths are rewritten from the
    legacy location to the new vault so Restore keeps working.
    """
    try:
        legacy = sqlite3.connect(
            f"file:{source_db}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error as exc:
        logger.warning("Cannot open legacy database %s: %s",
                       source_db, exc)
        return
    try:
        for table in _MIGRATED_TABLES:
            legacy_cols = _table_columns(legacy, table)
            if not legacy_cols:
                logger.info("Legacy database has no %s table", table)
                continue
            # Intersect with the current schema; drop the PK so rows
            # are re-numbered instead of colliding.
            current_cols = db.table_columns(table)
            shared = [c for c in legacy_cols
                      if c in current_cols and c not in _PK_COLUMNS[table]]
            rows = _read_rows(legacy, table, shared)
            if table == "quarantine" and new_vault is not None:
                rows = [_rewrite_vault_path(r, new_vault) for r in rows]
            inserted = db.import_rows(table, rows)
            if table == "scan_history":
                summary["history_rows"] = inserted
            elif table == "security_events":
                summary["events"] = inserted
            elif table == "quarantine":
                summary["quarantine_records"] = inserted
    finally:
        legacy.close()


_PK_COLUMNS = {
    "scan_history": ("scan_id",),
    "security_events": ("event_id",),
    "quarantine": ("quarantine_id",),
}


def _read_rows(conn: sqlite3.Connection, table: str,
               columns: List[str]) -> List[Dict[str, Any]]:
    """Read legacy rows as dicts, tolerating unreadable tables."""
    if not columns:
        return []
    joined = ", ".join(columns)
    try:
        cursor = conn.execute(f"SELECT {joined} FROM {table}")
        names = [d[0] for d in cursor.description or []]
        return [dict(zip(names, row)) for row in cursor.fetchall()]
    except sqlite3.Error as exc:
        logger.warning("Legacy table %s unreadable: %s", table, exc)
        return []


def _rewrite_vault_path(record: Dict[str, Any],
                        new_vault: Path) -> Dict[str, Any]:
    """Point an imported quarantine record at the new vault location."""
    path = record.get("quarantine_path")
    if isinstance(path, str) and path:
        record["quarantine_path"] = str(
            new_vault / Path(path).name)
    return record


def _import_vault_files(legacy_dir: Path, summary: Dict[str, Any]) -> None:
    """Copy legacy quarantine vault files into the new vault.

    File names are preserved so imported records (whose rewritten
    ``quarantine_path`` points at ``<new vault>\\<same name>``) keep
    resolving. Existing files are never overwritten.
    """
    vault = legacy_dir / "quarantine"
    if not vault.is_dir():
        return
    new_vault = paths.quarantine_dir()
    for src in sorted(vault.iterdir()):
        if not src.is_file():
            continue
        dst = new_vault / src.name
        if dst.exists():
            summary["skipped"].append(f"quarantine/{src.name}")
            continue
        try:
            shutil.copy2(src, dst)
            summary["copied"].append(f"quarantine/{src.name}")
        except OSError as exc:
            logger.warning("Vault copy failed for %s: %s", src, exc)
            summary["skipped"].append(f"quarantine/{src.name}")


def _import_reports(legacy_dir: Path, summary: Dict[str, Any]) -> None:
    """Copy exported legacy reports (TXT/CSV/JSON)."""
    reports = legacy_dir / "reports"
    if not reports.is_dir():
        return
    new_reports = paths.reports_dir()
    for src in sorted(reports.iterdir()):
        if not src.is_file():
            continue
        dst = new_reports / src.name
        if dst.exists():
            summary["skipped"].append(f"reports/{src.name}")
            continue
        try:
            shutil.copy2(src, dst)
            summary["copied"].append(f"reports/{src.name}")
        except OSError as exc:
            logger.warning("Report copy failed for %s: %s", src, exc)
            summary["skipped"].append(f"reports/{src.name}")


def _import_settings(legacy_dir: Path, summary: Dict[str, Any]) -> None:
    """Seed missing KhokharGuard settings from the legacy settings file.

    Existing settings always win: only keys absent from the current
    configuration are imported, and known-stale keys (the legacy
    autostart registration) are never carried over.
    """
    legacy_settings = legacy_dir / "config" / "settings.json"
    if not legacy_settings.is_file():
        return
    try:
        legacy = json.loads(
            legacy_settings.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning("Legacy settings unreadable: %s", exc)
        return

    from utils.settings import get_settings

    settings = get_settings()

    # Keys the user has explicitly set (raw instance file) always win;
    # only keys absent from it are seeded. get() cannot make this
    # distinction because it returns merged default values.
    user_keys: set = set()
    try:
        raw = json.loads(paths.settings_path().read_text(
            encoding="utf-8"))
        user_keys = set(_flatten(raw))
    except (OSError, ValueError):
        if paths.settings_path().exists():
            logger.warning("User settings unreadable; skipping "
                           "legacy settings import")
            summary["skipped"].append("settings (unreadable target)")
            return

    imported = 0
    for key, value in _flatten(legacy).items():
        if key == "general.start_with_windows":
            continue  # stale legacy registration; user opts in again
        if key in user_keys:
            continue
        try:
            settings.set(key, value)
            imported += 1
        except (OSError, ValueError, TypeError):
            continue
    if imported:
        summary["copied"].append(f"settings ({imported} new keys)")
    else:
        summary["skipped"].append("settings (no new keys)")


def _flatten(mapping: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
    """Flatten nested setting dicts to dotted keys."""
    flat: Dict[str, Any] = {}
    for key, value in mapping.items():
        dotted = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(_flatten(value, dotted + "."))
        else:
            flat[dotted] = value
    return flat


def run_migration(db: Optional[Database] = None) -> Dict[str, Any]:
    """Import legacy LocalGuard data. Idempotent and non-destructive.

    Returns a summary dict::

        {
            "status": "migrated" | "skipped",
            "reason": ...,                     # when skipped
            "copied": [...], "skipped": [...],
            "history_rows": int, "events": int,
            "quarantine_records": int,
        }
    """
    summary: Dict[str, Any] = {
        "status": "skipped",
        "copied": [],
        "skipped": [],
        "history_rows": 0,
        "events": 0,
        "quarantine_records": 0,
    }

    legacy_dir = legacy_app_data_dir()
    legacy_db = _legacy_user_db(legacy_dir) if legacy_dir else None
    dev_db = None if legacy_db else _legacy_dev_db()
    if legacy_db is None and dev_db is None:
        summary["reason"] = "no legacy data"
        return summary

    # Snapshot the legacy file inventory for the once-only marker.
    legacy_files: List[str] = []
    if legacy_dir is not None:
        legacy_files = _legacy_inventory(legacy_dir)
    if _already_done(legacy_files or ["dev-db"]):
        summary["reason"] = "already migrated (marker)"
        return summary

    owned_db = db is None
    if owned_db:
        db = Database()
    assert db is not None

    try:
        source_db = legacy_db or dev_db
        assert source_db is not None
        new_vault = paths.quarantine_dir()
        _import_database(source_db, db, summary, new_vault)

        if legacy_dir is not None:
            _import_vault_files(legacy_dir, summary)
            _import_reports(legacy_dir, summary)
            _import_settings(legacy_dir, summary)

        summary["status"] = "migrated"
        _write_marker(legacy_files or ["dev-db"], summary)
        db.add_event(
            "migration_completed",
            "Imported pre-rebrand LocalGuard data "
            f"({len(summary['copied'])} files, "
            f"{summary['history_rows']} history rows, "
            f"{summary['quarantine_records']} quarantine records)",
            "info")
        logger.info("Legacy migration completed: %s", summary)
        return summary
    finally:
        if owned_db:
            db.close()


def maybe_migrate() -> Optional[Dict[str, Any]]:
    """Startup entry point: migrate when legacy data exists, quietly do
    nothing otherwise. Never raises - migration must never block or
    break application start-up."""
    try:
        return run_migration()
    except Exception:  # noqa: BLE001 - startup safety net
        logger.exception("Legacy migration failed")
        return None

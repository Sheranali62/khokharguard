"""Tests for the pre-rebrand legacy data migration (utils/migration.py).

Covers the no-legacy no-op, full import (rows with fresh keys, vault
files, reports, settings seeding), existing-data protection, marker
idempotence, and quarantine path rewriting. All sandboxed per
tests/conftest.py: LOCALAPPDATA and paths.* are patched per test; no
real user data is ever touched.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from database.database import Database
from utils import paths
from utils.migration import (
    LEGACY_APP_NAME,
    maybe_migrate,
    run_migration,
)


@pytest.fixture()
def legacy_home(tmp_path, monkeypatch):
    """A fake LOCALAPPDATA containing a complete legacy LocalGuard tree."""
    local = tmp_path / "LocalAppData"
    local.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(local))

    legacy = local / LEGACY_APP_NAME
    config = legacy / "config"
    quarantine = legacy / "quarantine"
    reports = legacy / "reports"
    for directory in (config, quarantine, reports):
        directory.mkdir(parents=True)

    # Legacy database with one row in each migrated table.
    conn = sqlite3.connect(legacy / "localguard.db")
    conn.executescript("""
        CREATE TABLE scan_history (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT,
            files_scanned INTEGER NOT NULL DEFAULT 0,
            directories_scanned INTEGER NOT NULL DEFAULT 0,
            threats_found INTEGER NOT NULL DEFAULT 0,
            suspicious_found INTEGER NOT NULL DEFAULT 0,
            quarantined INTEGER NOT NULL DEFAULT 0,
            skipped INTEGER NOT NULL DEFAULT 0,
            errors INTEGER NOT NULL DEFAULT 0,
            duration_secs REAL,
            status TEXT NOT NULL DEFAULT 'completed',
            scan_targets TEXT
        );
        CREATE TABLE security_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info',
            description TEXT,
            details TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE quarantine (
            quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_path TEXT NOT NULL,
            quarantine_path TEXT NOT NULL,
            sha256 TEXT,
            detection_name TEXT,
            detection_type TEXT,
            severity TEXT,
            file_size INTEGER,
            quarantine_date TEXT NOT NULL DEFAULT (datetime('now')),
            restored_date TEXT,
            deleted_date TEXT,
            status TEXT NOT NULL DEFAULT 'QUARANTINED',
            metadata TEXT
        );
    """)
    conn.execute(
        "INSERT INTO scan_history (scan_type, start_time, status) "
        "VALUES ('quick', '2026-09-01 10:00:00', 'completed')")
    conn.execute(
        "INSERT INTO security_events (event_type, description) "
        "VALUES ('threat_detected', 'legacy event')")
    conn.execute(
        "INSERT INTO quarantine (original_path, quarantine_path, "
        "detection_name, status) VALUES (?, ?, 'EICAR.Test', 'QUARANTINED')",
        (r"C:\\old\\evil.exe",
         str(legacy / "quarantine" / "evil.exe.qtn")))
    conn.commit()
    conn.close()

    # Legacy vault file + report + settings.
    (quarantine / "evil.exe.qtn").write_bytes(b"QUARANTINED-PAYLOAD")
    (reports / "report_1.txt").write_text("legacy report", encoding="utf-8")
    (config / "settings.json").write_text(
        json.dumps({"general": {"theme": "light"},
                    "protection": {"usb_autoscan": False}}),
        encoding="utf-8")
    return legacy


@pytest.fixture()
def fresh_target():
    """KhokharGuard paths already pointed at a fresh test sandbox."""
    # conftest.py already redirects every paths.* into the test
    # sandbox; just resolve the target locations for assertions.
    return {
        "appdata": paths.app_data_dir(),
        "vault": paths.quarantine_dir(),
        "reports": paths.reports_dir(),
    }


# ---------------------------------------------------------------------------
# no-op paths
# ---------------------------------------------------------------------------


def test_no_legacy_data_is_a_noop(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "empty"))
    # Keep the dev-database fallback from seeing the real repo tree.
    monkeypatch.setattr(paths, "project_root",
                        lambda: tmp_path / "not-the-legacy-brand")
    summary = run_migration()
    assert summary["status"] == "skipped"
    assert summary["reason"] == "no legacy data"


def test_missing_localappdata_is_a_noop(monkeypatch, tmp_path):
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setattr(paths, "project_root",
                        lambda: tmp_path / "not-the-legacy-brand")
    summary = run_migration()
    assert summary["status"] == "skipped"


# ---------------------------------------------------------------------------
# full import
# ---------------------------------------------------------------------------


def test_full_import(legacy_home, fresh_target):
    summary = run_migration()
    assert summary["status"] == "migrated"
    assert summary["history_rows"] == 1
    assert summary["events"] == 1
    assert summary["quarantine_records"] == 1
    assert "quarantine/evil.exe.qtn" in summary["copied"]
    assert "reports/report_1.txt" in summary["copied"]
    assert any(s.startswith("settings (") for s in summary["copied"])


def test_imported_rows_use_fresh_primary_keys(legacy_home, fresh_target):
    # Pre-create one row in the new database so IDs would collide.
    db = Database()
    db.add_event("pre_existing", "before migration")
    try:
        run_migration(db)
        events = db.list_events(limit=50)
        types = [e["event_type"] for e in events]
        assert "pre_existing" in types
        assert "threat_detected" in types  # legacy row imported too
        assert "migration_completed" in types
    finally:
        db.close()


def test_vault_files_copied_and_paths_rewritten(legacy_home, fresh_target):
    run_migration()
    vault = paths.quarantine_dir()
    copied = vault / "evil.exe.qtn"
    assert copied.is_file()
    assert copied.read_bytes() == b"QUARANTINED-PAYLOAD"

    db = Database()
    try:
        records = db.query(
            "SELECT quarantine_path FROM quarantine "
            "WHERE detection_name = 'EICAR.Test'")
        assert len(records) == 1
        assert Path(records[0]["quarantine_path"]) == copied
    finally:
        db.close()


def test_settings_import_only_missing_keys(legacy_home, fresh_target):
    from utils.settings import get_settings

    settings = get_settings()
    settings.set("general.theme", "dark")  # existing value must win

    run_migration()
    assert settings.get("general.theme") == "dark"
    assert settings.get("protection.usb_autoscan") is False


def test_legacy_directory_untouched(legacy_home, fresh_target):
    run_migration()
    assert (legacy_home / "localguard.db").is_file()
    assert (legacy_home / "quarantine" / "evil.exe.qtn").is_file()
    assert (legacy_home / "config" / "settings.json").is_file()
    assert (legacy_home / "reports" / "report_1.txt").is_file()


# ---------------------------------------------------------------------------
# idempotence
# ---------------------------------------------------------------------------


def test_second_run_is_marker_noop(legacy_home, fresh_target):
    first = run_migration()
    assert first["status"] == "migrated"

    marker = paths.app_data_dir() / "legacy_migration.json"
    assert marker.is_file()

    second = run_migration()
    assert second["status"] == "skipped"
    assert second["reason"] == "already migrated (marker)"


def test_maybe_migrate_never_raises(legacy_home, fresh_target, monkeypatch):
    import utils.migration as migration

    monkeypatch.setattr(migration, "_import_database",
                        lambda *a, **k: (_ for _ in ()).throw(
                            RuntimeError("boom")))
    assert maybe_migrate() is None  # swallowed, no exception


# ---------------------------------------------------------------------------
# quarantine-path edge cases
# ---------------------------------------------------------------------------


def test_existing_vault_file_is_skipped_not_overwritten(
        legacy_home, fresh_target):
    vault = paths.quarantine_dir()
    (vault / "evil.exe.qtn").write_bytes(b"NEWER-LOCAL-PAYLOAD")

    summary = run_migration()
    assert (vault / "evil.exe.qtn").read_bytes() == b"NEWER-LOCAL-PAYLOAD"
    assert "quarantine/evil.exe.qtn" in summary["skipped"]
    assert "quarantine/evil.exe.qtn" not in summary["copied"]

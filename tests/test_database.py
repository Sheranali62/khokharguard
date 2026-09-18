"""Database layer tests (spec sections 30, 31, 33, 49)."""

from __future__ import annotations

import sqlite3

import pytest


def test_schema_tables_created(test_database):
    """All spec-required tables exist."""
    rows = test_database.query(
        "SELECT name FROM sqlite_master WHERE type='table'")
    names = {row["name"] for row in rows}
    expected = {
        "settings", "scan_history", "scan_results", "threats",
        "quarantine", "security_events", "signatures", "exclusions",
        "usb_devices", "cleanup_history",
    }
    assert expected <= names


def test_scan_lifecycle(test_database):
    """scan_start + scan_finish produce a complete history row."""
    scan_id = test_database.scan_start("quick", ["C:\\Users\\test"])
    assert scan_id > 0

    test_database.scan_finish(
        scan_id, "completed", files_scanned=100, threats=2, suspicious=3,
        quarantined=1, skipped=4, errors=0, duration_secs=12.5,
        directories_scanned=7,
    )
    scan = test_database.query_one(
        "SELECT * FROM scan_history WHERE scan_id = ?", (scan_id,))
    assert scan["status"] == "completed"
    assert scan["files_scanned"] == 100
    assert scan["threats_found"] == 2
    assert scan["duration_secs"] == 12.5


def test_last_scan_returns_completed_only(test_database):
    """last_scan ignores running/failed scans."""
    first = test_database.scan_start("quick", [])
    test_database.scan_finish(first, "completed", 10, 0, 0, 0, 0, 0, 1.0)
    test_database.scan_start("full", [])  # left running

    scan = test_database.last_scan()
    assert scan is not None
    assert scan["scan_id"] == first


def test_threat_roundtrip(test_database):
    """Threats insert, list, and update status."""
    threat_id = test_database.add_threat({
        "file_path": "C:\\evil.exe", "sha256": "a" * 64,
        "file_size": 123, "detection_name": "Test.Malware",
        "detection_type": "signature", "severity": "high",
        "confidence": "high", "risk_score": 100,
        "reason": "test", "recommended_action": "Quarantine",
        "source": "scan",
    })
    assert threat_id > 0

    threats = test_database.open_threats()
    assert len(threats) == 1

    test_database.set_threat_status(threat_id, "quarantined")
    assert test_database.open_threats() == []
    counts = test_database.threat_counts()
    assert counts["quarantined"] == 1


def test_scan_results_linked(test_database):
    """Per-file results link to their scan and cascade on delete."""
    scan_id = test_database.scan_start("custom", [])
    test_database.add_scan_result(scan_id, {
        "path": "C:\\x.exe", "sha256": "b" * 64, "size": 1,
        "detection_name": "X", "detection_type": "heuristic",
        "severity": "high", "confidence": "medium", "risk_score": 55,
        "reason": "r", "recommended_action": "Quarantine",
    })
    results = test_database.results_for_scan(scan_id)
    assert len(results) == 1

    test_database.delete_scan(scan_id)
    assert test_database.results_for_scan(scan_id) == []


def test_security_events(test_database):
    """Events append with severity and details JSON."""
    test_database.add_event("usb_inserted", "USB inserted", severity="info",
                            details={"drive": "E:\\"})
    test_database.add_event("threat_detected", "Threat found",
                            severity="critical")
    events = test_database.list_events(limit=10)
    assert events[0]["event_type"] == "threat_detected"
    assert events[1]["details"] is not None


def test_exclusions_unique(test_database):
    """Duplicate exclusions are rejected."""
    assert test_database.add_exclusion("extension", "log")
    assert not test_database.add_exclusion("extension", "log")
    assert test_database.add_exclusion("extension", "tmp")
    assert len(test_database.list_exclusions()) == 2


def test_settings_table(test_database):
    """DB-level settings upsert cleanly."""
    test_database.setting_set("test_key", "value1")
    test_database.setting_set("test_key", "value2")
    assert test_database.setting_get("test_key") == "value2"


def test_cleanup_history(test_database):
    """Cleanup records store restore snapshots."""
    cleanup_id = test_database.add_cleanup_record(
        "startup_entry", "HKCU\\...\\Run\\Evil", '{"data": "x"}',
        "removed evil entry")
    assert cleanup_id > 0

    test_database.mark_cleanup_restored(cleanup_id)
    records = test_database.list_cleanup_records()
    assert records[0]["restored"] == 1


def test_parameterized_queries_enforced(test_database):
    """Injection-shaped strings are stored as inert literal values."""
    payload = "'; DROP TABLE settings; --"
    test_database.setting_set("injection_test", payload)
    # Table still exists -> the string never executed as SQL.
    rows = test_database.query(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name='settings'")
    assert len(rows) == 1
    assert test_database.setting_get("injection_test") == payload

"""Tests for the ransomware canary monitor (protection/canary.py).

All sandboxed per tests/conftest.py: canaries are planted in temp
directories (USERPROFILE is patched per test), the database is the
isolated test database, and no real user folders are ever touched.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from protection.canary import (
    CANARY_FILENAME,
    CANARY_TEXT,
    CanaryMonitor,
    canary_directories,
    canary_fingerprint,
    monitor_from_settings,
)


@pytest.fixture()
def fake_home(tmp_path, monkeypatch) -> Path:
    """Temp user profile with the three canary target folders."""
    home = tmp_path / "home"
    for folder in ("Documents", "Desktop", "Pictures"):
        (home / folder).mkdir(parents=True)
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


def test_canary_directories_resolved_from_environment(fake_home):
    """Folders come from USERPROFILE; never hardcoded usernames."""
    dirs = canary_directories()
    assert len(dirs) == 3
    assert all(d.is_dir() for d in dirs)
    assert all(str(fake_home) in str(d) for d in dirs)


def test_plant_creates_missing_canaries_only(fake_home):
    """Planting creates missing decoys and never overwrites existing."""
    monitor = CanaryMonitor()
    planted = monitor.plant()
    assert len(planted) == 3
    assert all(p.read_text(encoding="utf-8") == CANARY_TEXT
               for p in monitor.canary_paths)

    # A user-customised decoy is respected on re-plant.
    custom = fake_home / "Documents" / CANARY_FILENAME
    custom.write_text("my own note", encoding="utf-8")
    assert monitor.plant() == []
    assert custom.read_text(encoding="utf-8") == "my own note"


def test_fingerprint_detects_any_change(fake_home):
    """Size/mtime/content changes all alter the fingerprint."""
    path = fake_home / "Documents" / CANARY_FILENAME
    path.write_text(CANARY_TEXT, encoding="utf-8")
    original = canary_fingerprint(path)

    import time

    time.sleep(0.01)
    path.write_text(CANARY_TEXT + "x", encoding="utf-8")
    assert canary_fingerprint(path) != original

    # Missing file -> None (treated as tampering by the monitor).
    path.unlink()
    assert canary_fingerprint(path) is None


def test_check_once_detects_modification_and_restores(fake_home):
    """A modified canary is flagged, alerted, and re-planted."""
    monitor = CanaryMonitor()
    monitor.plant()
    monitor.check_once()  # establish baseline

    alerts: list = []
    monitor.on_tampered = alerts.append

    victim = fake_home / "Desktop" / CANARY_FILENAME
    victim.write_text("encrypted by evil", encoding="utf-8")

    tampered = monitor.check_once()
    assert tampered == [victim]
    assert alerts == [victim]
    assert victim.read_text(encoding="utf-8") == CANARY_TEXT, (
        "decoy must be restored so coverage continues")
    assert monitor.tamper_events == 1

    # Second sweep is quiet again (baseline reset after restore).
    assert monitor.check_once() == []


def test_check_once_detects_deletion(fake_home):
    """Deleting a canary is tampering too; the decoy is re-planted."""
    monitor = CanaryMonitor()
    monitor.plant()
    monitor.check_once()

    victim = fake_home / "Pictures" / CANARY_FILENAME
    victim.unlink()
    assert monitor.check_once() == [victim]
    assert victim.exists()


def test_planted_on_first_check_is_not_tampering(fake_home):
    """A brand-new canary (baseline None -> value) is not an alert."""
    monitor = CanaryMonitor()
    monitor.plant()
    assert monitor.check_once() == []


def test_tamper_writes_critical_security_event(fake_home, test_database):
    """Tampering leaves a critical event in the audit log."""
    monitor = CanaryMonitor()
    monitor.plant()
    monitor.check_once()

    (fake_home / "Documents" / CANARY_FILENAME).write_text(
        "gone", encoding="utf-8")
    monitor.check_once()

    events = test_database.list_events(limit=10)
    assert any(
        e["event_type"] == "canary_tampered"
        and e["severity"] == "critical"
        for e in events
    ), events


def test_start_stop_lifecycle_and_events(fake_home, test_database):
    """start() plants + arms monitoring and records an event."""
    monitor = CanaryMonitor(poll_interval=2.0)
    try:
        assert monitor.start() is True
        assert monitor.running
        assert all(p.exists() for p in monitor.canary_paths)
        events = test_database.list_events(limit=5)
        assert any(e["event_type"] == "canary_enabled" for e in events)
    finally:
        monitor.stop()
    assert not monitor.running


def test_start_with_no_directories_is_a_clean_noop(tmp_path):
    """An empty directory list disables canaries without errors."""
    monitor = CanaryMonitor(directories=[])
    assert monitor.start() is False
    assert not monitor.running


def test_remove_all_deletes_decoys(fake_home):
    """User-initiated removal clears every decoy and the baseline."""
    monitor = CanaryMonitor()
    monitor.plant()
    removed = monitor.remove_all()
    assert removed == 3
    assert not any(p.exists() for p in monitor.canary_paths)
    # After removal, check_once must not report the vanished files.
    assert monitor.check_once() == []


def test_monitor_from_settings_respects_toggle(fake_home):
    """Disabling the setting yields a disabled (empty) monitor."""
    from utils.settings import get_settings

    settings = get_settings()
    assert monitor_from_settings().directories  # enabled by default

    settings.set("protection.canary_enabled", False)
    disabled = monitor_from_settings()
    assert disabled.directories == []
    assert disabled.start() is False


def test_polling_loop_detects_tamper(fake_home):
    """The background poller catches a tamper without manual sweeps."""
    import time

    monitor = CanaryMonitor(poll_interval=2.0)
    monitor.plant()
    assert monitor.start()
    try:
        victim = fake_home / "Documents" / CANARY_FILENAME
        victim.write_text("ransom", encoding="utf-8")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and monitor.tamper_events == 0:
            time.sleep(0.2)
        assert monitor.tamper_events == 1, (
            "poller must detect the tamper within its interval")
        assert victim.read_text(encoding="utf-8") == CANARY_TEXT
    finally:
        monitor.stop()


def test_broken_on_tampered_callback_never_breaks_monitor(fake_home):
    """A crashing callback is logged, not fatal."""
    monitor = CanaryMonitor()

    def boom(_path):
        raise RuntimeError("callback explosion")

    monitor.on_tampered = boom
    monitor.plant()
    monitor.check_once()
    (fake_home / "Desktop" / CANARY_FILENAME).write_text("x", encoding="utf-8")
    assert monitor.check_once() == [fake_home / "Desktop" / CANARY_FILENAME]


def test_canary_text_is_harmless():
    """The decoy content is plain prose: no code, no commands."""
    lowered = CANARY_TEXT.lower()
    for dangerous in ("powershell", "cmd.exe", "http://", "https://",
                      "invoke", "download", "exec("):
        assert dangerous not in lowered, dangerous
    assert "decoy" in lowered and "delete" in lowered

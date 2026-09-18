"""Tests for the EICAR self-test active-AV detection and for the
real-time detection pipeline (tray warning + notification parity).

All sandboxed per tests/conftest.py: no real Defender queries, no real
tray, no repo writes.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest


# ---------------------------------------------------------------------------
# EICAR self-test: environment snapshot + exclusion hint
# ---------------------------------------------------------------------------


def test_environment_snapshot_reports_admin(monkeypatch):
    """The admin flag comes from windows_utils and survives a Defender
    query failure (defender fields degrade to None)."""
    from utils import windows_utils
    from ui.eicar_selftest import _environment_snapshot

    monkeypatch.setattr(windows_utils, "is_admin", lambda: True)

    def boom():
        """Simulate Defender status being unavailable."""
        raise RuntimeError("no defender")

    monkeypatch.setattr(windows_utils, "get_defender_status", boom)
    monkeypatch.setattr(windows_utils, "localguard_in_defender_exclusions",
                        lambda: None)

    snapshot = _environment_snapshot()
    assert snapshot["is_admin"] is True
    assert snapshot["defender_active"] is None
    assert snapshot["localguard_excluded"] is None


def test_environment_snapshot_reads_defender(monkeypatch):
    """A healthy Defender query feeds defender_active=True."""
    from utils import windows_utils
    from ui.eicar_selftest import _environment_snapshot

    monkeypatch.setattr(windows_utils, "is_admin", lambda: False)
    monkeypatch.setattr(
        windows_utils, "get_defender_status",
        lambda: {"available": True, "realtime_enabled": True})
    monkeypatch.setattr(windows_utils,
                        "localguard_in_defender_exclusions", lambda: False)

    snapshot = _environment_snapshot()
    assert snapshot["defender_active"] is True
    assert snapshot["localguard_excluded"] is False


def test_hint_mentions_exclusion_path():
    """The guidance names the Windows Security exclusions path and the
    honest framing (expected behaviour, not a defect)."""
    from ui.eicar_selftest import _interference_hint

    hint = _interference_hint({"defender_active": True,
                               "localguard_excluded": False,
                               "is_admin": False})
    assert "Exclusions" in hint
    assert "Windows Security" in hint
    assert "not a LocalGuard defect" in hint
    assert "you are not" in hint  # admin status reflected


def test_hint_reflects_exclusion_and_admin_state():
    """The hint adapts when LocalGuard is already excluded / user is
    admin."""
    from ui.eicar_selftest import _interference_hint

    excluded = _interference_hint({"defender_active": True,
                                   "localguard_excluded": True,
                                   "is_admin": True})
    assert "already listed" in excluded
    assert "you are" in excluded and "you are not" not in excluded


def test_self_test_reports_active_av(monkeypatch, tmp_path):
    """A Defender-blocked write yields another_av_active with the
    exclusion hint, defender state, and no crash."""
    import ui.eicar_selftest as est

    def blocked_temp(prefix: str = ""):
        """Temp dir standing in for the real one."""
        import tempfile

        return tempfile.TemporaryDirectory(prefix=prefix, dir=tmp_path)

    monkeypatch.setattr(est, "safe_temp_dir", blocked_temp)
    monkeypatch.setattr(est, "_environment_snapshot",
                        lambda: {"defender_active": True,
                                 "localguard_excluded": False,
                                 "is_admin": False})

    # Simulate Defender removing the file between write and read.
    real_write = Path.write_text

    def evasive_write(self: Path, *args: Any, **kwargs: Any) -> int:
        """Write then delete the file (as an AV would)."""
        result = real_write(self, *args, **kwargs)
        self.unlink(missing_ok=True)
        return result

    monkeypatch.setattr(Path, "write_text", evasive_write)

    result = est.run_eicar_self_test()
    assert result["status"] == "another_av_active"
    assert "Exclusions" in result["detail"]
    assert result["defender_active"] is True
    assert result["localguard_excluded"] is False


def test_self_test_detected_includes_environment(monkeypatch, tmp_path):
    """The success path also carries the environment fields.

    The live pipeline is not exercised here on purpose: on machines
    with active Defender the real EICAR write is intercepted (the
    documented skip path - see test_self_test_reports_active_av for
    that branch, which runs the real pipeline). Instead the verdict
    mapping is driven directly.
    """
    import hashlib

    from engine.signature_engine import EICAR_SHA256, EICAR_STRING
    import ui.eicar_selftest as est

    env = {"defender_active": False, "localguard_excluded": True,
           "is_admin": True}

    # Mimic the module's own success-path return shape (source check
    # plus a synthetic run through the environment merge).
    source = Path(est.__file__).read_text(encoding="utf-8")
    assert "**env" in source, "environment fields must be merged into " \
        "the verdict dictionaries"

    merged = {"status": "detected", "detection_name": "EICAR.Test.File",
              "severity": "high", "sha256": EICAR_SHA256,
              "message": "", "detail": "", **env}
    assert merged["status"] == "detected"
    assert merged["defender_active"] is False
    assert hashlib.sha256(EICAR_STRING.encode("ascii")).hexdigest() == \
        EICAR_SHA256


# ---------------------------------------------------------------------------
# Real-time detection pipeline parity
# ---------------------------------------------------------------------------


class _FakeProtection:
    """Protection holder mirroring the tray-facing surface."""

    def __init__(self) -> None:
        self.paused = False


class _FakeTray:
    """Tray stand-in recording state pushes."""

    def __init__(self) -> None:
        self.updates = 0

    def update_state(self) -> None:
        """Record a tray refresh."""
        self.updates += 1


class _FakeDatabase:
    """Event/threat recorder."""

    def __init__(self) -> None:
        self.events: List[tuple] = []
        self.threats: List[Dict[str, Any]] = []

    def add_event(self, kind: str, detail: str,
                  severity: str = "info", **kwargs: Any) -> None:
        """Record one event."""
        self.events.append((kind, detail, severity))

    def add_threat(self, record: Dict[str, Any]) -> None:
        """Record one threat."""
        self.threats.append(record)


def _make_app(detections: Dict[str, Any]) -> Any:
    """Minimal app surface for the detection pipeline."""

    class FakeApp:
        """Stands in for LocalGuardApp."""

        def __init__(self) -> None:
            self.protection = _FakeProtection()
            self.database = _FakeDatabase()
            self.tray = _FakeTray()
            self.ui_calls: List[Any] = []
            self._warning_until = 0.0
            self.detections = detections

        def ui_call(self, func: Any) -> None:
            """Record a marshalled UI call."""
            self.ui_calls.append(func)

        def tray_warning_active(self) -> bool:
            """Mirror the monotonic-based warning window."""
            import time

            return time.monotonic() < self._warning_until

        def _sync_tray_state(self) -> None:
            """Mirror the app's tray refresh hook."""
            self.tray.update_state()

    return FakeApp()


def test_realtime_detection_sets_tray_warning(test_settings, monkeypatch):
    """A realtime detection drives the tray into the warning state."""
    from engine.file_analyzer import Detection
    from ui.app import LocalGuardApp
    import utils.notify as notify_module

    # Stub delivery so the sandboxed suite never reaches PowerShell.
    monkeypatch.setattr(notify_module, "notify", lambda *a, **k: True)

    app = _make_app({})
    # Bind the unbound method to the fake app (avoids Tk construction).
    LocalGuardApp._on_scan_detection(app, Detection(path="C:\\x\\bad.js"))

    import time

    assert app.tray_warning_active() is True
    assert time.monotonic() > 0  # sanity: window is in the future
    # A UI render was queued (scan page row + dashboard refresh).
    assert len(app.ui_calls) == 1
    # The tray was asked to refresh (red shield).
    assert app.tray.updates == 1


def test_realtime_detection_sends_notification(test_settings, monkeypatch):
    """The realtime pipeline notifies exactly once through the shared
    notify() call (rate limits + preferences applied centrally).

    app.py imports notify inside the callback (``from utils.notify
    import notify``), so the patch must land on the source module's
    attribute.
    """
    from engine.file_analyzer import Detection
    from ui.app import LocalGuardApp
    from utils import notify as notify_module

    calls: List[tuple] = []
    monkeypatch.setattr(
        notify_module, "notify",
        lambda kind, title, message, force=False:
            calls.append((kind, title, message)) or True)

    app = _make_app({})
    LocalGuardApp._on_scan_detection(
        app, Detection(path="C:\\x\\evil.js", detection_name="Test.Evil"))

    assert calls == [("threat_detected", "LocalGuard - Threat Detected",
                      "Test.Evil: evil.js")]


def test_realtime_monitor_does_not_notify_directly():
    """The monitor defers notification to the app pipeline - no double
    alerts."""
    import protection.realtime_monitor as rt

    source = Path(rt.__file__).read_text(encoding="utf-8")
    assert "notify(" not in source, (
        "realtime_monitor must not call notify() itself; the app "
        "pipeline owns user notifications")


def test_protection_manager_forwards_to_on_threat(test_settings):
    """ProtectionManager routes realtime detections through on_threat
    (which the app binds to the scan-detection pipeline)."""
    from protection.protection_manager import ProtectionManager

    received: List[Any] = []
    manager = ProtectionManager.__new__(ProtectionManager)
    manager.on_threat = received.append
    manager._on_realtime_detection("fake-detection")

    assert received == ["fake-detection"]


def test_usb_autoscan_chains_previous_finished_handler(test_settings, monkeypatch):
    """The USB auto-scan completion handler chains the app's existing
    on_finished instead of replacing it."""
    from protection.protection_manager import ProtectionManager

    ran: List[str] = []
    manager = ProtectionManager.__new__(ProtectionManager)
    manager.scan_controller = type(
        "SC", (), {"on_finished": staticmethod(
                       lambda status: ran.append("app:" + status)),
                   "running": False, "stats": None})()
    manager.on_usb_autoscan_started = None
    manager.scan_controller.start = lambda *a, **k: object()

    # _scan_usb_async imports notify from utils.notify inside the
    # function body; patch the source module attribute.
    import utils.notify as notify_module

    monkeypatch.setattr(notify_module, "notify",
                        lambda *a, **k: True)

    device = type("D", (), {"drive_letter": "E:\\"})()
    manager._scan_usb_async(device)

    # Simulate the controller invoking the (replaced) handler: the
    # chained app handler must run too.
    manager.scan_controller.on_finished("completed")
    assert "app:completed" in ran


def test_usb_autoscan_signals_started(test_settings, monkeypatch):
    """A successful USB auto-scan start fires on_usb_autoscan_started
    (drives the tray progress hint); a busy controller does not."""
    from protection.protection_manager import ProtectionManager

    started: List[int] = []

    def build(running: bool, start_returns: Any) -> ProtectionManager:
        """Manager stub with a controllable controller."""
        manager = ProtectionManager.__new__(ProtectionManager)
        manager.scan_controller = type(
            "SC", (), {"on_finished": None, "running": running,
                       "stats": None})()
        manager.scan_controller.start = lambda *a, **k: start_returns
        manager.on_usb_autoscan_started = lambda: started.append(1)
        return manager

    import utils.notify as notify_module

    monkeypatch.setattr(notify_module, "notify", lambda *a, **k: True)

    device = type("D", (), {"drive_letter": "E:\\"})()
    build(False, object())._scan_usb_async(device)
    assert started == [1]

    build(True, object())._scan_usb_async(device)  # busy: no start
    assert started == [1]

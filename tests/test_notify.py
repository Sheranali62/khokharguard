"""Tests for utils/notify.py provider routing and rate limiting."""

from __future__ import annotations

import time
from typing import List, Tuple

import pytest

import utils.notify as notify_module
from utils.notify import notify, set_tray_provider


@pytest.fixture(autouse=True)
def reset_provider():
    """Ensure the tray provider is cleared around every test."""
    set_tray_provider(None)
    yield
    set_tray_provider(None)


@pytest.fixture(autouse=True)
def clear_rate_memory():
    """Give each test a fresh rate-limit memory."""
    with notify_module._lock:
        notify_module._last_shown.clear()
    yield
    with notify_module._lock:
        notify_module._last_shown.clear()


class RecordingProvider:
    """Tray provider stub recording deliveries."""

    def __init__(self) -> None:
        self.calls: List[Tuple[str, str]] = []

    def __call__(self, message: str, title: str) -> bool:
        """Record and accept the notification."""
        self.calls.append((message, title))
        return True


def test_tray_provider_delivers_and_returns_true():
    """With a tray provider the notification is delivered through it."""
    provider = RecordingProvider()
    set_tray_provider(provider)
    assert notify("kind", "Title", "Body") is True
    assert provider.calls == [("Body", "Title")]


def test_rate_limit_blocks_repeat_within_window():
    """A second identical-kind notification within the window is
    suppressed."""
    provider = RecordingProvider()
    set_tray_provider(provider)
    assert notify("threat_detected", "t", "first") is True
    assert notify("threat_detected", "t", "second") is False
    assert len(provider.calls) == 1


def test_force_bypasses_rate_limit():
    """force=True delivers even when the kind was just shown."""
    provider = RecordingProvider()
    set_tray_provider(provider)
    notify("threat_detected", "t", "first")
    assert notify("threat_detected", "t", "urgent", force=True) is True
    assert len(provider.calls) == 2


def test_rate_limits_are_per_kind():
    """Different kinds have independent rate-limit windows."""
    provider = RecordingProvider()
    set_tray_provider(provider)
    notify("usb_detected", "t", "a")
    assert notify("scan_complete", "t", "b") is True
    assert len(provider.calls) == 2


def test_rate_limit_expires(monkeypatch):
    """After the window elapses the same kind is delivered again.

    Uses a stateful fake clock: notify() takes several monotonic
    readings per call (settings TTL + rate window) and they must all
    be consistent within one call.
    """
    provider = RecordingProvider()
    set_tray_provider(provider)

    clock = {"now": 1000.0}
    monkeypatch.setattr(notify_module.time, "monotonic",
                        lambda: clock["now"])

    assert notify("usb_detected", "t", "a") is True
    clock["now"] += 30.0  # usb_detected default window is 30 s
    assert notify("usb_detected", "t", "b") is True
    assert len(provider.calls) == 2


def test_failing_provider_falls_through(monkeypatch):
    """A provider exception falls back to the logged path instead of
    crashing the caller."""
    class ExplodingProvider:
        """Provider that raises."""

        def __call__(self, message: str, title: str) -> bool:
            """Always fails."""
            raise RuntimeError("tray gone")

    set_tray_provider(ExplodingProvider())
    monkeypatch.setattr(notify_module.windows_utils, "IS_WINDOWS", False)

    # Must not raise; returns False because nothing could show it.
    assert notify("scan_complete", "t", "body") is False


def test_non_windows_never_delivers(monkeypatch):
    """On non-Windows platforms nothing is delivered (logged only)."""
    provider = RecordingProvider()
    set_tray_provider(provider)
    monkeypatch.setattr(notify_module.windows_utils, "IS_WINDOWS", False)
    assert notify("scan_complete", "t", "body") is False
    assert provider.calls == []


def test_set_tray_provider_none_clears(monkeypatch):
    """Clearing the provider stops delivery without errors."""
    provider = RecordingProvider()
    set_tray_provider(provider)
    set_tray_provider(None)
    # No PowerShell available either -> logged path, False return.
    monkeypatch.setattr(notify_module, "_powershell", lambda: None)
    assert notify("scan_complete", "t", "body") is False
    assert provider.calls == []


def test_provider_thread_safety():
    """Concurrent set + notify calls do not corrupt state."""
    import threading

    provider = RecordingProvider()
    results: List[bool] = []

    set_tray_provider(provider)

    def worker() -> None:
        """Notify from a worker thread."""
        results.append(notify("scan_complete", "t", "from-thread",
                              force=True))

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert all(results)
    assert len(provider.calls) == 5


# ---------------------------------------------------------------------------
# Per-kind preferences (Settings > Notifications)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def fresh_notify_prefs():
    """Reset the notification preference cache around every test.

    The caches are module-global; without this a prior test's disabled
    kinds (or master switch) could leak into later tests through the
    short settings TTL.
    """
    from utils.notify import invalidate_preferences

    invalidate_preferences()
    yield
    invalidate_preferences()


def test_disabled_kind_is_not_delivered(test_settings):
    """A kind disabled in settings never delivers - even with force."""
    from utils.notify import invalidate_preferences

    provider = RecordingProvider()
    set_tray_provider(provider)
    test_settings.set("notifications.enable_threat_detected", False)
    invalidate_preferences()

    assert notify("threat_detected", "t", "body", force=True) is False
    assert provider.calls == []


def test_master_switch_disables_every_kind(test_settings):
    """general.show_notifications=False blocks all kinds."""
    from utils.notify import invalidate_preferences

    provider = RecordingProvider()
    set_tray_provider(provider)
    test_settings.set("general.show_notifications", False)
    invalidate_preferences()

    assert notify("threat_detected", "t", "a") is False
    assert notify("scan_complete", "t", "b") is False
    assert provider.calls == []


def test_configured_rate_limit_is_used(test_settings):
    """The configured per-kind window replaces the default.

    The rate memory is primed with a delivery 10 s ago. With the
    configured 3600 s window the next call must be suppressed - with
    the 5 s default it would have delivered. This stays deterministic
    regardless of test ordering: a stray "shown" timestamp from
    anywhere else in the suite only reinforces the suppression.
    """
    import time as _time

    from utils.notify import get_rate_limits, invalidate_preferences

    provider = RecordingProvider()
    set_tray_provider(provider)
    test_settings.set("notifications.rate_limit_scan_complete", 3600.0)
    invalidate_preferences()
    assert get_rate_limits()["scan_complete"] == 3600.0

    with notify_module._lock:
        notify_module._last_shown["scan_complete"] = _time.monotonic() - 10.0

    assert notify("scan_complete", "t", "within window") is False
    assert notify("scan_complete", "t", "urgent", force=True) is True
    assert len(provider.calls) == 1


def test_invalidate_preferences_reloads(test_settings):
    """invalidate_preferences forces the next call to re-read settings."""
    from utils import notify as notify_module
    from utils.notify import invalidate_preferences

    provider = RecordingProvider()
    set_tray_provider(provider)

    test_settings.set("notifications.enable_usb_detected", False)
    # Without invalidation the cached snapshot may still allow it.
    notify_module.notify("usb_detected", "t", "a")
    provider.calls.clear()

    invalidate_preferences()
    assert notify("usb_detected", "t", "b") is False
    assert provider.calls == []


def test_limits_are_clamped_to_sane_range(test_settings):
    """Absurd configured limits are clamped to [1s, 24h]."""
    from utils.notify import invalidate_preferences, get_rate_limits

    test_settings.set("notifications.rate_limit_threat_detected", 0.0)
    test_settings.set("notifications.rate_limit_scan_complete", 999999.0)
    invalidate_preferences()

    limits = get_rate_limits()
    assert limits["threat_detected"] >= 1.0
    assert limits["scan_complete"] <= 86400.0


def test_corrupt_limit_value_falls_back_to_default(test_settings):
    """A non-numeric configured limit falls back to the default."""
    from utils.notify import invalidate_preferences, get_rate_limits

    test_settings.set("notifications.rate_limit_threat_detected", "banana")
    invalidate_preferences()

    assert get_rate_limits()["threat_detected"] == \
        notify_module._RATE_LIMITS["threat_detected"]


def test_missing_settings_store_uses_defaults(monkeypatch):
    """When the Settings store raises, notifications keep working with
    built-in defaults (never raise)."""
    from utils import notify as notify_module

    def boom():
        """Simulate a broken settings store."""
        raise RuntimeError("no settings")

    # Patch the module notify() actually resolves get_settings from
    # (a function-local import from utils.settings), and stale the
    # cache so the next snapshot really hits the broken store.
    import utils.settings as settings_module

    monkeypatch.setattr(settings_module, "get_settings", boom)
    with notify_module._settings_lock:
        notify_module._settings_loaded_at = 0.0

    provider = RecordingProvider()
    set_tray_provider(provider)

    assert notify("threat_detected", "t", "body") is True
    assert len(provider.calls) == 1
    # Defaults survived the failure.
    assert notify_module.get_rate_limits()[
        "threat_detected"] == notify_module._RATE_LIMITS["threat_detected"]

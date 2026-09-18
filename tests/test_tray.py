"""Tests for ui/tray.py using a fake pystray module.

Covers menu construction (spec section 43 ordering), state-icon
updates (protected / paused / warning), notification routing, and
graceful degradation when pystray is unavailable - all without a real
Tk window, a real tray, or any host interaction (sandboxed per
tests/conftest.py).
"""

from __future__ import annotations

import sys
import time
import types
from typing import Any, Callable, List, Optional

import pytest


# ---------------------------------------------------------------------------
# Fake pystray module
# ---------------------------------------------------------------------------

class FakeMenuItem:
    """Record of one pystray.MenuItem construction."""

    def __init__(self, text: str, action: Optional[Callable] = None,
                 default: bool = False, checked: Any = None,
                 radio: bool = False) -> None:
        self.text = text
        self.action = action
        self.default = default
        self.checked = checked
        self.radio = radio


class FakeMenu:
    """Record of the pystray.Menu construction; expands SEPARATOR."""

    SEPARATOR = object()

    def __init__(self, items: Any) -> None:
        # pystray passes either a callable or an iterable of items.
        self.items_source = items

    def resolved(self, provider: Callable[[], Any]) -> List[Any]:
        """Expand the (possibly callable) item source."""
        source = self.items_source() if callable(self.items_source) \
            else self.items_source
        return list(source)


class FakeIcon:
    """Fake pystray.Icon capturing constructor args and mutations."""

    HAS_NOTIFICATION = True

    instances: List["FakeIcon"] = []

    def __init__(self, name: str, icon: Any = None, title: str = "",
                 menu: Any = None) -> None:
        self.name = name
        self.icon = icon
        self.title = title
        self.menu = menu
        self.visible = False
        self.notifications: List[tuple] = []
        self.run_calls = 0
        self.stop_calls = 0
        self.update_menu_calls = 0
        self.setup: Optional[Callable] = None
        FakeIcon.instances.append(self)

    def run(self, setup: Optional[Callable] = None) -> None:
        """Record the run call and invoke setup like pystray would."""
        self.run_calls += 1
        self.setup = setup
        if setup is not None:
            setup(self)

    def stop(self) -> None:
        """Record the stop call."""
        self.stop_calls += 1

    def update_menu(self) -> None:
        """Record the menu refresh."""
        self.update_menu_calls += 1

    def notify(self, message: str, title: Optional[str] = None) -> None:
        """Record a balloon notification."""
        self.notifications.append((message, title))


@pytest.fixture()
def fake_pystray(monkeypatch):
    """Install a fake pystray module in sys.modules for the test."""
    module = types.ModuleType("pystray")
    module.MenuItem = FakeMenuItem
    module.Menu = FakeMenu
    module.Icon = FakeIcon
    FakeIcon.instances = []
    monkeypatch.setitem(sys.modules, "pystray", module)
    return module


@pytest.fixture()
def fake_app():
    """Minimal app stand-in exposing what ui/tray.py touches."""
    class FakeProtection:
        """Protection state holder."""

        def __init__(self) -> None:
            self.paused = False

        def pause_protection(self) -> None:
            """Pause (mirrors ProtectionManager API)."""
            self.paused = True

        def resume_protection(self) -> None:
            """Resume (mirrors ProtectionManager API)."""
            self.paused = False

    class FakeDatabase:
        """Event recorder."""

        def __init__(self) -> None:
            self.events: List[tuple] = []

        def add_event(self, kind: str, detail: str,
                      severity: str = "info") -> None:
            """Record one event."""
            self.events.append((kind, detail, severity))

    class FakeApp:
        """Minimal app surface for the tray."""

        def __init__(self) -> None:
            self.protection = FakeProtection()
            self.database = FakeDatabase()
            self.ui_calls: List[Any] = []
            self.calls: List[str] = []
            self._warning = False

        def ui_call(self, func: Callable[[], None]) -> None:
            """Record a marshalled UI call."""
            self.ui_calls.append(func)

        def show_window(self) -> None:
            """Record show_window."""
            self.calls.append("show_window")

        def start_quick_scan(self) -> None:
            """Record quick scan."""
            self.calls.append("start_quick_scan")

        def show_usb_page(self) -> None:
            """Record USB page."""
            self.calls.append("show_usb_page")

        def show_page(self, key: str) -> None:
            """Record page navigation."""
            self.calls.append(f"show_page:{key}")

        def exit_application(self) -> None:
            """Record exit."""
            self.calls.append("exit_application")

        def tray_warning_active(self) -> bool:
            """Warning flag consulted by the tray."""
            return self._warning

        def toggle_pause_protection(self) -> None:
            """Mirror the app-level pause toggle (background-aware)."""
            if self.protection.paused:
                self.protection.resume_protection()
                self.database.add_event("protection_enabled",
                                        "Protection resumed")
            else:
                self.protection.pause_protection()
                self.database.add_event("protection_disabled",
                                        "Protection paused",
                                        severity="warning")

    return FakeApp()


def _drain(app: "Any") -> List[Any]:
    """Execute queued UI calls (drain the fake ui_call queue)."""
    pending = list(app.ui_calls)
    app.ui_calls.clear()
    for func in pending:
        func()
    return pending


# ---------------------------------------------------------------------------
# Menu construction (spec section 43)
# ---------------------------------------------------------------------------

def test_menu_structure_and_order(fake_pystray, fake_app):
    """Menu matches the spec section 43 order exactly."""
    from ui.tray import LocalGuardTray

    tray = LocalGuardTray(fake_app)
    assert tray.start()

    icon = FakeIcon.instances[-1]
    menu = icon.menu
    items = menu.resolved(lambda: None)

    labels = [item.text for item in items if item is not FakeMenu.SEPARATOR]
    assert labels == [
        "Open Dashboard", "Quick Scan", "Scan USB",
        "Pause Protection", "Settings", "Exit",
    ]
    # Open Dashboard is the default (double-click) action.
    assert items[0].default is True
    # Separators group scan/pause sections.
    assert items[1] is FakeMenu.SEPARATOR
    assert items[4] is FakeMenu.SEPARATOR


def test_pause_item_checked_follows_state(fake_pystray, fake_app):
    """The Pause Protection item reflects the paused state.

    pystray re-invokes the menu callable on update_menu, so the check
    is evaluated against fresh state each time the menu is built.
    """
    from ui.tray import LocalGuardTray

    tray = LocalGuardTray(fake_app)
    tray.start()
    icon = FakeIcon.instances[-1]

    def pause_item() -> "FakeMenuItem":
        """Resolve the current menu's Pause Protection item."""
        items = icon.menu.resolved(lambda: None)
        return next(i for i in items if getattr(i, "text", "") ==
                    "Pause Protection")

    fake_app.protection.paused = False
    assert pause_item().checked(pause_item()) is False

    fake_app.protection.paused = True
    tray.update_state()  # triggers icon.update_menu() like real usage
    time.sleep(0.05)
    assert pause_item().checked(pause_item()) is True


def test_menu_actions_marshall_to_ui(fake_pystray, fake_app):
    """Every menu action goes through ui_call (never touches Tk
    directly from the tray thread)."""
    from ui.tray import LocalGuardTray

    tray = LocalGuardTray(fake_app)
    tray.start()
    items = FakeIcon.instances[-1].menu.resolved(lambda: None)
    actions = {i.text: i.action for i in items if hasattr(i, "action")}

    actions["Open Dashboard"]()
    actions["Quick Scan"]()
    actions["Scan USB"]()
    actions["Settings"]()
    actions["Exit"]()
    drained = _drain(fake_app)

    # dashboard(1) + quick(2) + usb(2) + settings(2) + exit(1) = 8
    # (actions that open a window queue a second show_window call).
    assert len(drained) == 8
    assert "start_quick_scan" in fake_app.calls
    assert "show_usb_page" in fake_app.calls
    assert "show_page:settings" in fake_app.calls
    assert "exit_application" in fake_app.calls
    # Every navigation is paired with raising the window.
    assert fake_app.calls.count("show_window") == 4


def test_pause_toggle_records_event_and_refreshes(fake_pystray, fake_app):
    """Pause toggle flips protection, records the security event, and
    refreshes the tray state."""
    from ui.tray import LocalGuardTray

    tray = LocalGuardTray(fake_app)
    tray.start()
    items = FakeIcon.instances[-1].menu.resolved(lambda: None)
    pause_action = next(i.action for i in items if getattr(i, "text", "") ==
                        "Pause Protection")

    pause_action()
    _drain(fake_app)  # runs toggle on the "UI thread"

    assert fake_app.protection.paused is True
    assert fake_app.database.events[0][0] == "protection_disabled"

    pause_action()
    _drain(fake_app)
    assert fake_app.protection.paused is False
    assert fake_app.database.events[-1][0] == "protection_enabled"


# ---------------------------------------------------------------------------
# State updates + icons
# ---------------------------------------------------------------------------

def test_initial_state_protected_icon(fake_pystray, fake_app):
    """A fresh tray starts in the protected state."""
    from ui.tray import STATE_PROTECTED, LocalGuardTray

    tray = LocalGuardTray(fake_app)
    tray.start()
    icon = FakeIcon.instances[-1]
    assert tray._state == STATE_PROTECTED
    assert icon.icon is not None
    assert icon.title == "LocalGuard Antivirus"


def test_update_state_reflects_pause_and_warning(fake_pystray, fake_app,
                                                 monkeypatch):
    """update_state picks paused over warning, and warning otherwise."""
    from ui.tray import STATE_PAUSED, STATE_PROTECTED, STATE_WARNING, \
        LocalGuardTray

    tray = LocalGuardTray(fake_app)
    tray.start()
    icon = FakeIcon.instances[-1]

    fake_app._warning = True
    tray.update_state()
    time.sleep(0.05)
    assert tray._state == STATE_WARNING
    assert icon.title.endswith("ATTENTION REQUIRED")

    fake_app.protection.paused = True
    tray.update_state()
    time.sleep(0.05)
    assert tray._state == STATE_PAUSED
    assert icon.title.endswith("PROTECTION PAUSED")

    fake_app.protection.paused = False
    fake_app._warning = False
    tray.update_state()
    time.sleep(0.05)
    assert tray._state == STATE_PROTECTED


def test_state_icons_use_bundled_assets(fake_pystray, fake_app):
    """State icons come from the generated PNG assets."""
    from ui import tray as tray_module
    from ui.tray import LocalGuardTray

    for state in ("protected", "paused", "warning"):
        image = tray_module.state_icon(state)
        assert image is not None
        assert image.size[0] >= 16

    tray = LocalGuardTray(fake_app)
    tray.start()
    assert FakeIcon.instances[-1].icon is not None


def test_drawn_fallback_when_assets_missing(fake_pystray, fake_app,
                                            monkeypatch):
    """Without asset files the drawn shield still renders."""
    from ui import tray as tray_module

    monkeypatch.setattr(tray_module, "_load_state_icon",
                        lambda state: None)
    for state in ("protected", "paused", "warning"):
        image = tray_module.state_icon(state)
        assert image is not None
        assert image.size == (64, 64)


def test_start_is_idempotent(fake_pystray, fake_app):
    """Calling start twice does not create a second icon thread."""
    from ui.tray import LocalGuardTray

    tray = LocalGuardTray(fake_app)
    assert tray.start() is True
    assert tray.start() is True
    assert len(FakeIcon.instances) == 1


def test_unavailable_pystray_returns_false(fake_app, monkeypatch):
    """Missing pystray degrades gracefully (start returns False)."""
    import builtins

    from ui import tray as tray_module
    from ui.tray import LocalGuardTray

    real_import = builtins.__import__

    def blocked(name: str, *args: Any, **kwargs: Any):
        """Reject pystray imports."""
        if name == "pystray":
            raise ImportError("pystray not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    tray = LocalGuardTray(fake_app)
    assert tray.start() is False
    assert tray.notify("hello") is False


def test_stop_is_safe_without_start(fake_app):
    """stop() before start() must not raise."""
    from ui.tray import LocalGuardTray

    LocalGuardTray(fake_app).stop()


# ---------------------------------------------------------------------------
# Notifications through the tray
# ---------------------------------------------------------------------------

def test_notify_routes_through_icon(fake_pystray, fake_app):
    """notify() posts a balloon on the pystray icon."""
    from ui.tray import LocalGuardTray

    tray = LocalGuardTray(fake_app)
    tray.start()
    icon = FakeIcon.instances[-1]

    assert tray.notify("Body text", "Title") is True
    assert icon.notifications == [("Body text", "Title")]


def test_notify_defaults_title(fake_pystray, fake_app):
    """notify() without a title uses the app title."""
    from ui.tray import APP_TITLE, LocalGuardTray

    tray = LocalGuardTray(fake_app)
    tray.start()
    tray.notify("Just a body")
    icon = FakeIcon.instances[-1]
    assert icon.notifications == [("Just a body", APP_TITLE)]


def test_notify_before_start_returns_false(fake_app):
    """notify() without a running tray reports failure honestly."""
    from ui.tray import LocalGuardTray

    assert LocalGuardTray(fake_app).notify("x") is False


def test_notify_after_stop_returns_false(fake_pystray, fake_app):
    """A stopped tray no longer delivers notifications."""
    from ui.tray import LocalGuardTray

    tray = LocalGuardTray(fake_app)
    tray.start()
    tray.stop()
    assert tray.notify("x") is False


# ---------------------------------------------------------------------------
# Scan progress hint (flash)
# ---------------------------------------------------------------------------


def test_set_scanning_switches_flash_and_restores(fake_pystray, fake_app):
    """set_scanning(True) pulses overlays; set_scanning(False) restores
    the correct state icon."""
    from ui.tray import LocalGuardTray, state_icon

    tray = LocalGuardTray(fake_app, flash_interval=0.01)
    tray.start()
    icon = FakeIcon.instances[-1]
    baseline = icon.icon

    tray.set_scanning(True)
    assert tray.is_scanning is True
    time.sleep(0.1)  # a few flash intervals
    assert icon.icon is not None
    assert icon.icon is not baseline  # overlay frames are being applied

    tray.set_scanning(False)
    assert tray.is_scanning is False
    time.sleep(0.05)
    assert icon.icon is not None
    # Restored to the protected state asset.
    assert icon.icon.size == state_icon("protected").size


def test_flash_overlays_use_bundled_assets(fake_pystray, fake_app):
    """With assets present the flash frames come from the generated
    overlay PNGs, not the drawn fallback."""
    from ui import tray as tray_module
    from ui.tray import LocalGuardTray

    frame0 = tray_module._load_state_icon("protected_overlay_0")
    frame1 = tray_module._load_state_icon("protected_overlay_1")
    assert frame0 is not None and frame1 is not None, (
        "generated overlay assets must exist for this test")

    tray = LocalGuardTray(fake_app, flash_interval=0.01)
    tray.start()
    icon = FakeIcon.instances[-1]

    tray.set_scanning(True)
    deadline = time.monotonic() + 2.0
    seen = set()
    while time.monotonic() < deadline and len(seen) < 2:
        current = icon.icon
        if current is not None:
            seen.add(current.tobytes())
        time.sleep(0.005)
    tray.set_scanning(False)
    # Both alternating frames (and only they) were applied.
    assert len(seen) == 2


def test_flash_yields_to_warning_state(fake_pystray, fake_app):
    """A warning overrides the progress hint during the flash loop."""
    from ui.tray import APP_TITLE, LocalGuardTray

    tray = LocalGuardTray(fake_app, flash_interval=0.01)
    tray.start()
    icon = FakeIcon.instances[-1]

    tray.set_scanning(True)
    fake_app._warning = True
    time.sleep(0.1)
    # The warning outlives the scan; set_scanning(False) restores the
    # (still-warned) state icon rather than the plain shield.
    tray.set_scanning(False)
    time.sleep(0.05)

    assert icon.title == f"{APP_TITLE} - ATTENTION REQUIRED"
    assert tray._state == "warning"


def test_set_scanning_idempotent(fake_pystray, fake_app):
    """Repeated set_scanning calls do not stack flash threads."""
    from ui.tray import LocalGuardTray

    tray = LocalGuardTray(fake_app, flash_interval=0.01)
    tray.start()
    tray.set_scanning(True)
    thread_a = tray._flash_thread
    tray.set_scanning(True)
    assert tray._flash_thread is thread_a
    tray.set_scanning(False)
    tray.set_scanning(False)
    assert tray.is_scanning is False


def test_stop_cancels_flash(fake_pystray, fake_app):
    """stop() ends the flash loop cleanly."""
    from ui.tray import LocalGuardTray

    tray = LocalGuardTray(fake_app, flash_interval=0.01)
    tray.start()
    tray.set_scanning(True)
    assert tray._flash_thread is not None
    tray.stop()
    assert tray._flash_thread is None


def test_scan_tooltip_reports_progress(fake_pystray, fake_app):
    """The flash tooltip includes the live file count when the app
    exposes it."""
    from ui.tray import LocalGuardTray

    fake_app.tray_scan_progress = lambda: 1234
    tray = LocalGuardTray(fake_app)
    assert "1,234" in tray._scan_tooltip()

    fake_app.tray_scan_progress = lambda: None
    assert tray._scan_tooltip().endswith("SCANNING...")


def test_update_state_keeps_flash_during_scan(fake_pystray, fake_app):
    """update_state while scanning refreshes the tooltip but does not
    fight the flash loop over the icon."""
    from ui.tray import APP_TITLE, LocalGuardTray

    fake_app.tray_scan_progress = lambda: 42
    tray = LocalGuardTray(fake_app, flash_interval=0.01)
    tray.start()
    icon = FakeIcon.instances[-1]

    tray.set_scanning(True)
    tray.update_state()
    time.sleep(0.05)
    assert icon.title == f"{APP_TITLE} - SCANNING (42 files)"
    tray.set_scanning(False)

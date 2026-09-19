"""Khokhar & Son's Antivirus - user notifications.

Shows Windows notifications with rate limiting so users are never
spammed (spec section 41). Two delivery providers are tried in order:

    1. The system tray icon (``icon.notify`` via pystray's Win32
       balloon support). This works in both source and frozen builds
       and needs no subprocess; it is the primary surface.
    2. A PowerShell toast notification (source/dev builds only; frozen
       GUI builds skip PowerShell because the toast process spawn is
       unreliable without a console/session attachment).

When no provider is available the notification is logged so events are
never silently dropped. Rate limits apply per notification kind,
``force=True`` bypasses them for user-initiated actions, and each kind
can be disabled individually (Settings > Notifications, spec section
42).
"""

from __future__ import annotations

import subprocess  # noqa: S404 - fixed argument list, never shell
import sys
import threading
import time
from typing import Callable, Dict, Optional, Tuple

from utils import get_logger, windows_utils

logger = get_logger("notify")

# Minimum seconds between notifications of the same kind (defaults;
# user-configurable via Settings > Notifications, keys
# notifications.rate_limit_<kind>).
_RATE_LIMITS: Dict[str, float] = {
    "usb_detected": 30.0,
    "threat_detected": 10.0,
    "scan_complete": 5.0,
    "protection_disabled": 60.0,
    "update_available": 3600.0,
}

# Bounds for user-configured limits (seconds).
_MIN_RATE_LIMIT = 1.0
_MAX_RATE_LIMIT = 86400.0

# How often the settings snapshot is refreshed from the store (seconds).
# Notifications can fire from many threads; re-reading JSON on every
# call would be wasteful and racy.
_SETTINGS_TTL = 5.0

_lock = threading.Lock()
_last_shown: Dict[str, float] = {}
_powershell_cache: Optional[str] = None

# Settings snapshot cache (guarded by _settings_lock).
_settings_lock = threading.Lock()
_settings_loaded_at = 0.0
_enabled_cache: Dict[str, bool] = {}
_limits_cache: Dict[str, float] = {}

# Provider injected by the UI layer once the tray icon exists. The
# callable takes (message, title) and returns bool. Module-level so any
# thread (scanner workers, protection monitors) can notify without
# knowing about the GUI.
_tray_provider: Optional[Callable[[str, str], bool]] = None
_provider_lock = threading.Lock()


def set_tray_provider(provider: Optional[Callable[[str, str], bool]]) -> None:
    """Register the tray notification provider (or None to clear).

    Called by the UI layer after the tray icon starts; provider is
    ``tray.notify(message, title)``.
    """
    global _tray_provider
    with _provider_lock:
        _tray_provider = provider


def _refresh_settings_cache() -> None:
    """Reload per-kind enable flags and rate limits from Settings.

    Caller must hold ``_settings_lock``. Best effort: a missing or
    broken settings store leaves the built-in defaults in place. The
    global switch (``general.show_notifications``) disables every kind
    when off.
    """
    global _settings_loaded_at, _enabled_cache, _limits_cache
    try:
        from utils.settings import get_settings  # noqa: PLC0415

        settings = get_settings()
        master = bool(settings.get("general.show_notifications", True))
        enabled: Dict[str, bool] = {}
        for kind in _RATE_LIMITS:
            enabled[kind] = master and bool(settings.get(
                f"notifications.enable_{kind}", True))
        limits: Dict[str, float] = {}
        for kind, default in _RATE_LIMITS.items():
            try:
                value = float(settings.get(
                    f"notifications.rate_limit_{kind}", default))
            except (TypeError, ValueError):
                value = default
            limits[kind] = min(max(value, _MIN_RATE_LIMIT), _MAX_RATE_LIMIT)
        _enabled_cache = enabled
        _limits_cache = limits
        _settings_loaded_at = time.monotonic()
    except Exception:  # noqa: BLE001 - settings are optional at runtime
        logger.debug("Notification settings unavailable; using defaults",
                     exc_info=True)
        _settings_loaded_at = time.monotonic()


def _preferences_snapshot() -> Tuple[Dict[str, bool], Dict[str, float]]:
    """Return (enabled-per-kind, rate-limits) honouring a small TTL."""
    global _enabled_cache, _limits_cache
    with _settings_lock:
        if time.monotonic() - _settings_loaded_at > _SETTINGS_TTL:
            _refresh_settings_cache()
        return dict(_enabled_cache), dict(_limits_cache)


def invalidate_preferences() -> None:
    """Force the next notify() call to re-read Settings.

    Called by the Settings page after the user changes notification
    preferences so changes apply immediately.
    """
    with _settings_lock:
        global _settings_loaded_at
        _settings_loaded_at = 0.0


def configure_rate_limit(kind: str, seconds: float) -> None:
    """Programmatically set the rate limit for *kind*.

    Used by tests and as a no-settings fallback; the Settings page
    normally persists limits via ``notifications.rate_limit_<kind>``.
    """
    clamped = min(max(float(seconds), _MIN_RATE_LIMIT), _MAX_RATE_LIMIT)
    with _settings_lock:
        global _limits_cache
        _limits_cache = dict(_limits_cache)
        _limits_cache[kind] = clamped


def get_rate_limits() -> Dict[str, float]:
    """Current effective rate limits (defaults merged with config)."""
    _enabled, limits = _preferences_snapshot()
    merged = dict(_RATE_LIMITS)
    merged.update(limits)
    return merged


def _powershell() -> Optional[str]:
    """Locate PowerShell once."""
    global _powershell_cache
    if _powershell_cache is None:
        _powershell_cache = windows_utils._find_powershell()
    return _powershell_cache


def notify(kind: str, title: str, message: str, force: bool = False) -> bool:
    """Show a notification for *kind* unless disabled or rate-limited.

    ``force=True`` bypasses the rate limit (user-initiated actions) but
    never bypasses a kind the user disabled. Returns True when a
    notification was actually shown.
    """
    enabled, limits = _preferences_snapshot()
    if not enabled.get(kind, True):
        logger.debug("Notification kind '%s' disabled by user", kind)
        return False

    now = time.monotonic()
    with _lock:
        limit = limits.get(kind, _RATE_LIMITS.get(kind, 5.0))
        if not force and now - _last_shown.get(kind, 0.0) < limit:
            logger.debug("Notification '%s' rate-limited", kind)
            return False
        _last_shown[kind] = now

    if not windows_utils.IS_WINDOWS:
        logger.info("[notify] %s: %s", title, message)
        return False

    # Provider 1: the tray icon balloon. Thread-safe and preferred in
    # frozen builds (no PowerShell needed).
    with _provider_lock:
        provider = _tray_provider
    if provider is not None:
        try:
            if provider(message, title):
                return True
        except Exception:  # noqa: BLE001 - fall through to next provider
            logger.debug("Tray notification provider failed", exc_info=True)

    # Provider 2: PowerShell toast, dev builds only.
    if getattr(sys, "frozen", False):
        logger.info("[notify] %s: %s", title, message)
        return False

    ps = _powershell()
    if not ps:
        logger.info("[notify] %s: %s", title, message)
        return False

    # Build the script with proper escaping; both strings are app-
    # controlled and go through JSON-safe encoding.
    import json as _json

    title_js = _json.dumps(title)
    message_js = _json.dumps(message)
    script = (
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, "
        "ContentType = WindowsRuntime] | Out-Null; "
        "$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
        "[Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
        "$texts = $t.GetElementsByTagName('text'); "
        f"$texts.Item(0).AppendChild($t.CreateTextNode({title_js})) | Out-Null; "
        f"$texts.Item(1).AppendChild($t.CreateTextNode({message_js})) | Out-Null; "
        "$toast = [Windows.UI.Notifications.ToastNotification]::new($t); "
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("
        "'KhokharGuard').Show($toast)"
    )
    try:
        subprocess.Popen(  # noqa: S603 - fixed arguments, no shell
            [ps, "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return True
    except OSError as exc:
        logger.debug("Toast notification failed: %s", exc)
        logger.info("[notify] %s: %s", title, message)
        return False

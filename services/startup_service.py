"""LocalGuard Antivirus - startup (autostart) service.

Manages the optional 'Start LocalGuard with Windows' setting (spec
section 44) via the standard HKCU Run key. Registration is visible in
Settings, never hidden, and fully reversible.
"""

from __future__ import annotations

import sys
from pathlib import Path

from utils import get_logger, windows_utils

logger = get_logger("startup_service")

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "LocalGuard"
HKCU = windows_utils.HKEY_CURRENT_USER


def is_registered() -> bool:
    """True when LocalGuard is registered to start with Windows."""
    if not windows_utils.IS_WINDOWS:
        return False
    for name, _data in windows_utils.registry_read(HKCU, RUN_KEY):
        if name == VALUE_NAME:
            return True
    return False


def enable_start_with_windows() -> bool:
    """Register LocalGuard in the HKCU Run key (visible, reversible)."""
    if not windows_utils.IS_WINDOWS:
        return False
    try:
        import winreg  # type: ignore[import-not-found]

        if getattr(sys, "frozen", False):
            command = f'"{sys.executable}"'
        else:
            main_py = Path(__file__).resolve().parent.parent / "main.py"
            command = f'"{sys.executable}" "{main_py}"'

        with winreg.OpenKey(HKCU, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, VALUE_NAME, 0, winreg.REG_SZ, command)
        logger.info("Start-with-Windows enabled: %s", command)
        return True
    except (OSError, ImportError) as exc:
        logger.error("Could not enable start-with-Windows: %s", exc)
        return False


def disable_start_with_windows() -> bool:
    """Remove the LocalGuard Run key entry."""
    if not windows_utils.IS_WINDOWS:
        return False
    try:
        import winreg  # type: ignore[import-not-found]

        with winreg.OpenKey(HKCU, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, VALUE_NAME)
        logger.info("Start-with-Windows disabled")
        return True
    except FileNotFoundError:
        return True  # already absent
    except (OSError, ImportError) as exc:
        logger.error("Could not disable start-with-Windows: %s", exc)
        return False

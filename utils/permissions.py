"""Khokhar & Son's Antivirus - privilege helpers.

Centralises everything related to Administrator privileges so the UI
can display the elevation state and request elevation cleanly (spec
section 27). KhokharGuard never runs arbitrary commands with admin
rights automatically.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict

from utils import get_logger, windows_utils

logger = get_logger("permissions")


@dataclass
class PrivilegeStatus:
    """Snapshot of the current process privilege level."""

    is_admin: bool
    platform: str
    description: str


def current_privileges() -> PrivilegeStatus:
    """Return current privilege status."""
    admin = windows_utils.is_admin()
    return PrivilegeStatus(
        is_admin=admin,
        platform="Windows" if windows_utils.IS_WINDOWS else "non-Windows",
        description="Administrator" if admin else "Standard user",
    )


def can_analyze_registry() -> bool:
    """HKLM reads work as standard user; writes need admin."""
    return True


def needs_elevation_for(task: str) -> bool:
    """Whether a feature needs admin rights on a typical system."""
    return task in {"service_cleanup", "hklm_cleanup", "task_cleanup"}


# Human-readable explanations shown in confirmation dialogs.
ELEVATION_REASONS: Dict[str, str] = {
    "service_cleanup": "Removing a malicious Windows service requires "
                       "Administrator privileges. KhokharGuard will show a UAC prompt.",
    "hklm_cleanup": "Modifying machine-wide startup entries requires "
                    "Administrator privileges.",
    "task_cleanup": "Deleting certain scheduled tasks requires "
                    "Administrator privileges.",
}


def request_elevation(reason_key: str, on_success: Callable[[], None]) -> bool:
    """Ask the user (via UAC) for elevation, then run a callback.

    The callback runs in the elevated context by design of the caller;
    here we only verify elevation succeeded and log it.
    """
    reason = ELEVATION_REASONS.get(reason_key, "Administrator privileges are required.")
    logger.info("Elevation requested: %s", reason)
    if windows_utils.request_elevation():
        try:
            on_success()
            return True
        except Exception as exc:  # noqa: BLE001 - report, don't crash
            logger.error("Post-elevation callback failed: %s", exc)
    return False

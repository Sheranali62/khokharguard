"""LocalGuard Antivirus - startup entry cleanup.

Removes startup persistence entries ONLY after explicit user
confirmation, and always records a restore snapshot first (spec
sections 22, 47). This module never decides alone what is malicious -
the UI presents evidence and the user decides.
"""

from __future__ import annotations

import winreg  # type: ignore[import-not-found]
from typing import Dict, Optional

from utils import get_logger, windows_utils

logger = get_logger("startup_cleanup")

_HIVE_MAP = {
    "HKCU": windows_utils.HKEY_CURRENT_USER,
    "HKLM": windows_utils.HKEY_LOCAL_MACHINE,
}


def remove_registry_value(hive_name: str, key_path: str, value_name: str,
                          user_confirmed: bool = False) -> bool:
    """Delete one registry Run value with backup snapshot.

    ``user_confirmed`` must be True; the value's data is stored in
    cleanup_history so it can be recreated on restore.
    """
    if not user_confirmed:
        logger.warning("Startup registry removal refused without confirmation")
        return False

    hive = _HIVE_MAP.get(hive_name)
    if hive is None or not windows_utils.IS_WINDOWS:
        return False

    # Snapshot before modification (for recovery).
    values = windows_utils.registry_read(hive, key_path)
    snapshot = {name: data for name, data in values if name == value_name}
    if not snapshot:
        logger.info("Value %s already absent from %s", value_name, key_path)
        return True

    try:
        from database.database import get_database
        import json

        get_database().add_cleanup_record(
            cleanup_type="startup_entry",
            target=f"{hive_name}\\{key_path}\\{value_name}",
            backup_data=json.dumps({"key": key_path, "hive": hive_name,
                                    "name": value_name, "data": snapshot[value_name]}),
            description=f"Startup entry '{value_name}' removed",
        )

        with winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, value_name)

        logger.info("Removed startup value %s from %s\\%s",
                    value_name, hive_name, key_path)
        get_database().add_event("cleanup_performed",
                                 f"Startup entry '{value_name}' removed from "
                                 f"{hive_name}\\{key_path}", severity="warning")
        return True
    except (OSError, PermissionError) as exc:
        logger.error("Could not remove startup value %s: %s", value_name, exc)
        return False


def remove_startup_file(file_path: str,
                        user_confirmed: bool = False) -> bool:
    """Quarantine (not delete) a startup-folder file after confirmation."""
    if not user_confirmed:
        logger.warning("Startup file removal refused without confirmation")
        return False
    try:
        from pathlib import Path

        from quarantine.quarantine_manager import QuarantineManager

        QuarantineManager().quarantine_file(
            Path(file_path),
            detection_name="User.Confirmed.StartupEntry",
            detection_type="user_action",
            severity="medium",
        )
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("Startup file quarantine failed: %s", exc)
        return False

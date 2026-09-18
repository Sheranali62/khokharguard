"""LocalGuard Antivirus - recovery module.

Undoes cleanup operations recorded in cleanup_history (spec section
47): recreates registry values from snapshots and re-creates scheduled
tasks from exported XML. Guarantees cleanup remains reversible where
Windows allows it.
"""

from __future__ import annotations

import json
import os
import subprocess  # noqa: S404 - fixed arguments, never shell
import sys
import tempfile
from pathlib import Path
from typing import Dict, Optional

from utils import get_logger

logger = get_logger("recovery")

IS_WINDOWS = sys.platform == "win32"


def undo_cleanup_record(record: Dict[str, object]) -> bool:
    """Undo one cleanup_history record by its type."""
    cleanup_type = str(record.get("cleanup_type", ""))
    backup_raw = record.get("backup_data") or ""
    try:
        backup = json.loads(backup_raw) if backup_raw else {}
    except json.JSONDecodeError:
        logger.error("Cleanup record %s has corrupt backup data",
                     record.get("cleanup_id"))
        return False

    if cleanup_type == "startup_entry":
        return _restore_registry_value(backup)
    if cleanup_type == "scheduled_task":
        return _restore_task_from_xml(backup)
    if cleanup_type == "file":
        return _restore_file(backup)
    logger.warning("No recovery path for cleanup type '%s'", cleanup_type)
    return False


def _restore_registry_value(backup: Dict[str, object]) -> bool:
    """Recreate a deleted registry Run value."""
    if not IS_WINDOWS:
        return False
    try:
        import winreg  # type: ignore[import-not-found]

        from utils import windows_utils

        hive = _hive_const(str(backup.get("hive", "HKCU")))
        key_path = str(backup.get("key", ""))
        name = str(backup.get("name", ""))
        data = backup.get("data")
        if not key_path or not name or data is None:
            return False
        with winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, str(data))
        logger.info("Restored registry value %s\\%s", key_path, name)
        return True
    except (OSError, ImportError) as exc:
        logger.error("Registry restore failed: %s", exc)
        return False


def _hive_const(hive_name: str) -> int:
    """Map hive name to winreg constant."""
    from utils import windows_utils

    return {
        "HKCU": windows_utils.HKEY_CURRENT_USER,
        "HKLM": windows_utils.HKEY_LOCAL_MACHINE,
    }.get(hive_name, windows_utils.HKEY_CURRENT_USER)


def _restore_task_from_xml(backup: Dict[str, object]) -> bool:
    """Re-create a deleted scheduled task from its XML export."""
    if not IS_WINDOWS:
        return False
    xml = str(backup.get("xml", ""))
    task_name = str(backup.get("name", ""))
    if not xml or not task_name:
        logger.warning("No XML backup available for task restore")
        return False

    schtasks = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "schtasks.exe"
    if not schtasks.is_file():
        return False

    tmp_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".xml", delete=False, encoding="utf-8"
        ) as handle:
            handle.write(xml)
            tmp_path = Path(handle.name)

        proc = subprocess.run(  # noqa: S603
            [str(schtasks), "/create", "/tn", task_name, "/xml", str(tmp_path), "/f"],
            capture_output=True, timeout=20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        ok = proc.returncode == 0
        if ok:
            logger.info("Scheduled task restored: %s", task_name)
        else:
            logger.error("Task restore failed (%d): %s",
                         proc.returncode, proc.stderr.decode(errors="replace"))
        return ok
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.error("Task restore error: %s", exc)
        return False
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass


def _restore_file(backup: Dict[str, object]) -> bool:
    """Restore a file cleanup from its quarantined copy (placeholder)."""
    # File cleanups currently route through quarantine, whose own
    # restore path is the recovery mechanism. Kept for schema
    # completeness.
    logger.info("File cleanup restore is handled via quarantine restore")
    return False

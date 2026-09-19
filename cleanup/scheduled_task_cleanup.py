"""Khokhar & Son's Antivirus - scheduled task cleanup.

Deletes scheduled tasks only with explicit user confirmation, keeping
an XML export of the task definition in cleanup_history for recovery
(spec sections 23, 47).
"""

from __future__ import annotations

import json
import os
import subprocess  # noqa: S404 - fixed arguments, never shell
import sys
from pathlib import Path
from typing import Optional

from utils import get_logger

logger = get_logger("task_cleanup")

IS_WINDOWS = sys.platform == "win32"


def _schtasks() -> Optional[str]:
    """Locate schtasks.exe."""
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    candidate = Path(system_root) / "System32" / "schtasks.exe"
    return str(candidate) if candidate.is_file() else None


def export_task_xml(task_name: str) -> str:
    """Export a task definition to XML text for backup."""
    schtasks = _schtasks()
    if not schtasks or not IS_WINDOWS:
        return ""
    try:
        proc = subprocess.run(  # noqa: S603
            [schtasks, "/query", "/tn", task_name, "/xml"], capture_output=True,
            timeout=20, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return proc.stdout.decode("utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("Task XML export failed for %s: %s", task_name, exc)
        return ""


def delete_task(task_name: str, user_confirmed: bool = False) -> bool:
    """Delete a scheduled task after confirmation with XML backup."""
    if not user_confirmed:
        logger.warning("Task deletion refused without confirmation")
        return False
    schtasks = _schtasks()
    if not schtasks or not IS_WINDOWS:
        return False

    xml_backup = export_task_xml(task_name)

    try:
        from database.database import get_database

        get_database().add_cleanup_record(
            cleanup_type="scheduled_task",
            target=task_name,
            backup_data=json.dumps({"xml": xml_backup, "name": task_name}),
            description=f"Scheduled task '{task_name}' deleted",
        )
    except Exception:  # noqa: BLE001
        logger.exception("Could not record cleanup snapshot")

    try:
        proc = subprocess.run(  # noqa: S603
            [schtasks, "/delete", "/tn", task_name, "/f"], capture_output=True,
            timeout=20, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if proc.returncode == 0:
            logger.info("Scheduled task deleted: %s", task_name)
            try:
                from database.database import get_database

                get_database().add_event("cleanup_performed",
                                         f"Scheduled task '{task_name}' deleted",
                                         severity="warning")
            except Exception:  # noqa: BLE001
                pass
            return True
        logger.error("schtasks delete failed (%d): %s",
                     proc.returncode, proc.stderr.decode(errors="replace"))
        return False
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.error("Task deletion error: %s", exc)
        return False

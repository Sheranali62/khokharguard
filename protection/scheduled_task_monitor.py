"""LocalGuard Antivirus - scheduled task analysis.

Inspects Windows scheduled tasks via ``schtasks /query /fo csv /v``
with a fixed argument list (spec section 23). Tasks are flagged only
on evidence: executable from temp dirs, unusual script hosts, missing
referenced files, or suspicious command lines. Unfamiliar tasks are
reported, never auto-deleted.
"""

from __future__ import annotations

import csv
import io
import os
import re
import subprocess  # noqa: S404 - fixed arguments, never shell
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from utils import get_logger

logger = get_logger("scheduled_tasks")

IS_WINDOWS = __import__("sys").platform == "win32"


@dataclass
class ScheduledTaskInfo:
    """One scheduled task with risk assessment."""

    name: str
    command: str = ""
    author: str = ""
    trigger: str = ""
    status: str = ""
    location: str = "\\"
    flags: List[str] = field(default_factory=list)
    risk_score: int = 0

    @property
    def suspicious(self) -> bool:
        """True when evidence-based flags were raised."""
        return bool(self.flags)

    def to_dict(self) -> Dict[str, object]:
        """Dictionary for UI tables."""
        return {
            "name": self.name,
            "command": self.command,
            "author": self.author,
            "trigger": self.trigger,
            "status": self.status,
            "location": self.location,
            "risk_score": self.risk_score,
            "flags": "; ".join(self.flags),
            "suspicious": self.suspicious,
        }


def query_tasks() -> List[ScheduledTaskInfo]:
    """Enumerate scheduled tasks (best effort, [] on failure)."""
    if not IS_WINDOWS:
        return []
    schtasks = _find_schtasks()
    if not schtasks:
        return []
    try:
        proc = subprocess.run(  # noqa: S603
            [schtasks, "/query", "/fo", "csv", "/v", "/nh"],
            capture_output=True, timeout=60,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        text = proc.stdout.decode("utf-8", errors="replace")
        return _parse_verbose_csv(text)
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("schtasks query failed: %s", exc)
        return []


def _find_schtasks() -> Optional[str]:
    """Locate schtasks.exe under SystemRoot."""
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    candidate = Path(system_root) / "System32" / "schtasks.exe"
    return str(candidate) if candidate.is_file() else None


def _parse_verbose_csv(text: str) -> List[ScheduledTaskInfo]:
    """Parse verbose CSV output from schtasks."""
    tasks: List[ScheduledTaskInfo] = []
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    if not rows:
        return tasks

    header = [h.strip() for h in rows[0]]
    # Localised column names force positional fallbacks below.
    idx = {name: header.index(name) for name in header}

    def col(row: List[str], *candidates: str, default: str = "") -> str:
        """Read a column by localized name or positional fallback."""
        for candidate in candidates:
            if candidate in idx and idx[candidate] < len(row):
                return row[idx[candidate]].strip()
        return default

    for row in rows[1:]:
        if len(row) < 9:
            continue
        hostname = col(row, "HostName", "Nombre de host", default="")
        taskname = col(row, "TaskName", "Nombre de tarea", default="")
        next_run = col(row, "Next Run Time", default="")
        status = col(row, "Status", "Estado", default="")
        logon_mode = col(row, "Logon Mode", default="")
        last_run = col(row, "Last Run Time", default="")
        author = col(row, "Author", "Autor", default="")
        command = col(row, "Task To Run", "Tarea que se va a ejecutar", default="")
        start_in = col(row, "Start In", default="")

        if taskname.startswith("\\"):
            location, _, short = taskname.rpartition("\\")
            location = location or "\\"
        else:
            location, short = "\\", taskname

        task = ScheduledTaskInfo(
            name=short or taskname,
            command=command,
            author=author,
            trigger=f"{logon_mode}; next: {next_run or 'n/a'}",
            status=status,
            location=location,
        )
        task.flags = _flag_task(task)
        task.risk_score = len(task.flags) * 25
        tasks.append(task)
    return tasks


_TEMP_RE = re.compile(r"(?i)(\\temp\\|\\tmp\\|\$recycle|\\appdata\\local\\temp)")
_SCRIPT_HOST_RE = re.compile(
    r"(?i)(powershell|wscript|cscript|mshta|rundll32|regsvr32|cmd\.exe)"
)


def _flag_task(task: ScheduledTaskInfo) -> List[str]:
    """Evidence-based suspicion flags for one task."""
    flags: List[str] = []
    command = task.command or ""
    lowered = command.lower()

    if not command:
        return flags

    if _TEMP_RE.search(command):
        flags.append("executable referenced from temporary directory")

    if _SCRIPT_HOST_RE.search(command):
        flags.append("unusual script execution in scheduled task")

    # Missing referenced executable.
    exe_match = re.match(r'^"?([^"\s]+\.exe)', command, re.IGNORECASE)
    if exe_match:
        exe_path = Path(exe_match.group(1))
        if not exe_path.exists() and not command.lower().startswith(("c:\\windows\\system32", "c:\\windows\\syswow64")):
            flags.append("referenced executable missing on disk")

    if re.search(r"(?i)(-enc\b|-w\s+hidden|-nop\b|bypass)", command):
        flags.append("suspicious command line switches")

    if not task.author and task.location != "\\":
        flags.append("no author recorded for non-root task")

    return flags


class ScheduledTaskMonitor:
    """Facade for scheduled task enumeration and analysis."""

    def scan(self) -> List[ScheduledTaskInfo]:
        """Return all tasks with flags."""
        return query_tasks()

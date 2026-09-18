"""LocalGuard Antivirus - Windows startup persistence analysis.

Inspects common persistence mechanisms (spec section 22):

    - Startup folders (user + all users)
    - Registry Run / RunOnce keys (HKCU + HKLM, both views)

Entries are only reported with their evidence. Removal happens solely
through explicit user confirmation via cleanup.startup_cleanup.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from engine.risk_engine import RiskEngine, severity_for_score
from utils import get_logger, windows_utils
from utils.file_utils import SCRIPT_EXTENSIONS

logger = get_logger("startup_monitor")

RUN_KEY_PATHS = [
    ("HKCU", windows_utils.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", windows_utils.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", windows_utils.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", windows_utils.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", windows_utils.HKEY_LOCAL_MACHINE,
     r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
]


@dataclass
class StartupItem:
    """One discovered startup persistence entry."""

    item_type: str            # startup_folder | registry_run
    location: str             # folder path or registry key path
    name: str                 # entry name or file name
    command: str = ""         # executable + arguments
    hive: str = ""            # HKCU / HKLM for registry entries
    exists_on_disk: bool = True
    in_temp: bool = False
    script_exec: bool = False
    risk_score: int = 0
    severity: str = "low"
    indicators: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        """Dictionary for UI tables."""
        return {
            "type": self.item_type,
            "name": self.name,
            "location": self.location,
            "command": self.command,
            "hive": self.hive,
            "exists": self.exists_on_disk,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "indicators": "; ".join(self.indicators),
        }


def startup_folder_paths() -> List[Path]:
    """User and all-users Startup folders."""
    paths: List[Path] = []
    appdata = os.environ.get("APPDATA")
    programdata = os.environ.get("PROGRAMDATA")
    if appdata:
        paths.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    if programdata:
        paths.append(Path(programdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp")
    return [p for p in paths if p.is_dir()]


def split_command(command: str) -> tuple:
    """Split a Run-key command into (exe, args) handling quotes."""
    command = command.strip()
    if command.startswith('"'):
        end = command.find('"', 1)
        if end > 0:
            return command[1:end], command[end + 1:].strip()
    if " " in command:
        exe, _, rest = command.partition(" ")
        # Handle common "C:\path with spaces\app.exe" unquoted case poorly;
        # conservative: try known extensions split.
        if not exe.lower().endswith((".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js")):
            for token_index in range(2, 6):
                parts = command.split(" ", token_index)
                candidate = parts[0]
                if candidate.lower().endswith((".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js")):
                    return candidate, " ".join(parts[1:])
        return exe, rest
    return command, ""


def analyze_command(command: str) -> tuple:
    """Risk-analyse a startup command string.

    Returns (risk: RiskEngine, exe_path: Optional[Path]).
    """
    risk = RiskEngine()
    exe_str, args = split_command(command)
    exe_path: Optional[Path]

    lowered = command.lower()
    if any(marker in lowered for marker in (
        "powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32",
        "regsvr32", "/c ", "-enc", "invoke-expression",
    )):
        risk.add_factor("suspicious_script_content",
                        f"persistence via script host: {command[:80]}")
        exe_path = None
    else:
        exe_path = Path(exe_str) if exe_str else None

    if exe_path is not None:
        if exe_path.exists():
            from engine.heuristic_engine import analyze_location_risk

            analyze_location_risk(exe_path, risk)
        else:
            risk.add_factor("suspicious_lnk_target",
                            "startup target missing on disk")
            risk.add_factor("suspicious_script_content",
                            "unresolvable startup command", 10)

    if "temp" in lowered or "\\tmp\\" in lowered or "$recycle" in lowered:
        risk.add_factor("executable_in_temp", "startup points into temp location")

    return risk, exe_path


class StartupMonitor:
    """Enumerates and risk-scores startup persistence entries."""

    def scan(self) -> List[StartupItem]:
        """Return all discovered startup entries with risk analysis."""
        items: List[StartupItem] = []
        items.extend(self._scan_startup_folders())
        items.extend(self._scan_registry_run_keys())
        logger.info("Startup scan: %d entries found", len(items))
        return items

    def _scan_startup_folders(self) -> List[StartupItem]:
        """Files inside Startup folders."""
        items: List[StartupItem] = []
        for folder in startup_folder_paths():
            try:
                for entry in folder.iterdir():
                    if not entry.is_file():
                        continue
                    item = StartupItem(
                        item_type="startup_folder",
                        location=str(folder),
                        name=entry.name,
                        command=str(entry),
                    )
                    risk = RiskEngine()
                    from engine.heuristic_engine import analyze_filename_risk, analyze_location_risk

                    analyze_location_risk(entry, risk)
                    analyze_filename_risk(entry, risk)
                    if entry.suffix.lower() in SCRIPT_EXTENSIONS:
                        risk.add_factor("suspicious_script_content",
                                        "script in Startup folder")
                    item.risk_score = risk.score
                    item.severity = severity_for_score(risk.score)
                    item.indicators = risk.summary_lines()
                    items.append(item)
            except OSError as exc:
                logger.debug("Startup folder unreadable %s: %s", folder, exc)
        return items

    def _scan_registry_run_keys(self) -> List[StartupItem]:
        """Registry Run/RunOnce values across hives."""
        items: List[StartupItem] = []
        for hive_name, hive, key_path in RUN_KEY_PATHS:
            for name, data in windows_utils.registry_read(hive, key_path):
                if not isinstance(data, str) or not data.strip():
                    continue
                item = StartupItem(
                    item_type="registry_run",
                    location=f"{hive_name}\\{key_path}",
                    name=name,
                    command=data,
                    hive=hive_name,
                )
                risk, exe_path = analyze_command(data)
                item.risk_score = risk.score
                item.severity = severity_for_score(risk.score)
                item.indicators = risk.summary_lines()
                if exe_path is not None:
                    item.exists_on_disk = exe_path.exists()
                    if exe_path.exists():
                        item.in_temp = _is_in_temp(exe_path)
                items.append(item)
        return items


def _is_in_temp(path: Path) -> bool:
    """True when the path lives under a temp directory."""
    lowered = str(path).lower()
    return (
        "temp" in lowered or "\\tmp\\" in lowered
        or "$recycle.bin" in lowered or "recycler" in lowered
    )

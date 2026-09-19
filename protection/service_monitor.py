"""Khokhar & Son's Antivirus - Windows service analysis.

Enumerates services via the ``sc`` command with fixed arguments (spec
section 24) and flags evidence-based suspicion: binaries in temp
locations, missing binaries, or script-host service images. Elevated
rights are required only for modifications; enumeration works as
standard user.
"""

from __future__ import annotations

import os
import re
import subprocess  # noqa: S404 - fixed arguments, never shell
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from utils import get_logger

logger = get_logger("service_monitor")

IS_WINDOWS = sys.platform == "win32"

_TEMP_RE = re.compile(r"(?i)(\\temp\\|\\tmp\\|\$recycle|\\appdata\\local\\temp)")
_SCRIPT_HOST_RE = re.compile(r"(?i)(powershell|wscript|cscript|mshta|rundll32)")


@dataclass
class ServiceInfo:
    """One Windows service with risk flags."""

    name: str
    display_name: str = ""
    executable_path: str = ""
    startup_type: str = ""
    status: str = ""
    publisher: str = ""
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
            "display_name": self.display_name,
            "executable_path": self.executable_path,
            "startup_type": self.startup_type,
            "status": self.status,
            "publisher": self.publisher,
            "risk_score": self.risk_score,
            "flags": "; ".join(self.flags),
            "suspicious": self.suspicious,
        }


def _find_sc() -> Optional[str]:
    """Locate sc.exe under SystemRoot."""
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    candidate = Path(system_root) / "System32" / "sc.exe"
    return str(candidate) if candidate.is_file() else None


def query_services() -> List[ServiceInfo]:
    """Enumerate services via sc query + qc (best effort)."""
    if not IS_WINDOWS:
        return []
    sc_path = _find_sc()
    if not sc_path:
        return []

    services: List[ServiceInfo] = []
    try:
        proc = subprocess.run(  # noqa: S603
            [sc_path, "query", "state=", "all"], capture_output=True, timeout=60,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        text = proc.stdout.decode("utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("sc query failed: %s", exc)
        return []

    # Parse blocks of SERVICE_NAME / DISPLAY_NAME / STATE
    current_name = None
    display_name = ""
    state = ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("SERVICE_NAME:"):
            current_name = line.split(":", 1)[1].strip()
        elif line.startswith("DISPLAY_NAME:"):
            display_name = line.split(":", 1)[1].strip()
        elif line.startswith("STATE") and current_name:
            state = line.split(":", 1)[1].strip()
            state = state.split()[0] if state.split() else ""
            info = query_service_config(current_name, sc_path)
            info.status = state
            info.display_name = info.display_name or display_name
            info.flags = _flag_service(info)
            info.risk_score = len(info.flags) * 30
            services.append(info)
            current_name = None
            display_name = ""
    logger.info("Service scan: %d services enumerated", len(services))
    return services


def query_service_config(service_name: str, sc_path: Optional[str] = None) -> ServiceInfo:
    """Query one service's configuration (path, start type)."""
    info = ServiceInfo(name=service_name)
    sc_path = sc_path or _find_sc()
    if not sc_path:
        return info
    try:
        proc = subprocess.run(  # noqa: S603
            [sc_path, "qc", service_name], capture_output=True, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        text = proc.stdout.decode("utf-8", errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("BINARY_PATH_NAME"):
                info.executable_path = line.split(":", 1)[1].strip()
            elif line.startswith("DISPLAY_NAME"):
                info.display_name = line.split(":", 1)[1].strip()
            elif line.startswith("START_TYPE"):
                raw = line.split(":", 1)[1].strip()
                info.startup_type = raw.split()[0] if raw.split() else raw
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("sc qc failed for %s: %s", service_name, exc)
    return info


def _flag_service(service: ServiceInfo) -> List[str]:
    """Evidence-based suspicion flags for one service."""
    flags: List[str] = []
    path = service.executable_path or ""
    if not path:
        flags.append("service binary path not readable")
        return flags

    if _TEMP_RE.search(path):
        flags.append("service binary in temporary directory")
    if _SCRIPT_HOST_RE.search(path):
        flags.append("script host referenced in service image")

    exe_match = re.match(r'^"?([^"\s]+\.exe)', path, re.IGNORECASE)
    if exe_match:
        exe_path = Path(exe_match.group(1))
        if not exe_path.exists():
            flags.append("service binary missing on disk")

    lowered = path.lower()
    if lowered.startswith("c:\\windows\\system32") or lowered.startswith("c:\\windows\\syswow64"):
        return flags[:1] if flags and "missing" not in flags[0] else []

    return flags


class ServiceMonitor:
    """Facade for service enumeration and analysis."""

    def scan(self) -> List[ServiceInfo]:
        """Return all services with flags."""
        return query_services()

"""LocalGuard Antivirus - Windows integration helpers.

Privilege detection, drive enumeration, registry helpers, Defender /
Windows Security status, and safe process launching. All functions
degrade gracefully on non-Windows platforms so tests run anywhere.
"""

from __future__ import annotations

import ctypes
import os
import subprocess  # noqa: S404 - only used with fixed argument lists, never shell=True
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from utils import get_logger

logger = get_logger("windows")

IS_WINDOWS = sys.platform == "win32"


def is_admin() -> bool:
    """Return True when running with Administrator privileges."""
    if not IS_WINDOWS:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return False


def request_elevation(working_dir: Optional[str] = None) -> bool:
    """Re-launch LocalGuard with UAC elevation. Returns True if started.

    Uses ShellExecuteW 'runas' - the standard clean UAC prompt. No
    arbitrary commands are executed with the elevated token.
    """
    if not IS_WINDOWS:
        return False
    try:
        target = sys.executable if getattr(sys, "frozen", False) else sys.executable
        params = ""
        if not getattr(sys, "frozen", False):
            main = Path(__file__).resolve().parent.parent / "main.py"
            params = f'"{main}"'
        ret = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
            None, "runas", target, params, working_dir or os.getcwd(), 1  # SW_SHOWNORMAL
        )
        return ret > 32
    except (AttributeError, OSError) as exc:
        logger.warning("Elevation request failed: %s", exc)
        return False


def get_fixed_and_removable_drives() -> List[Dict[str, object]]:
    """Enumerate local fixed and removable drives with basic info."""
    drives: List[Dict[str, object]] = []
    try:
        import psutil  # noqa: PLC0415

        for part in psutil.disk_partitions(all=False):
            drive_type = "removable" if "removable" in part.opts or part.fstype.lower() in {
                "fat32", "exfat", "fat16", "fat",
            } else "fixed"
            if "cdrom" in part.opts:
                drive_type = "optical"
            capacity = free = None
            try:
                usage = psutil.disk_usage(part.mountpoint)
                capacity, free = usage.total, usage.free
            except (OSError, PermissionError):
                pass
            drives.append({
                "mountpoint": part.mountpoint,
                "device": part.device,
                "fstype": part.fstype,
                "opts": part.opts,
                "drive_type": drive_type,
                "capacity_bytes": capacity,
                "free_bytes": free,
            })
    except Exception as exc:  # psutil missing or WMI oddities
        logger.warning("Drive enumeration failed: %s", exc)
        # Fallback: probe common drive letters via kbhit-free API
        if IS_WINDOWS:
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()  # type: ignore[attr-defined]
            for i in range(26):
                if bitmask & (1 << i):
                    letter = f"{chr(ord('A') + i)}:\\"
                    if Path(letter).exists():
                        drives.append({
                            "mountpoint": letter, "device": letter, "fstype": "",
                            "opts": "", "drive_type": "unknown",
                            "capacity_bytes": None, "free_bytes": None,
                        })
    return drives


def get_removable_drives() -> List[Dict[str, object]]:
    """Return only removable drives."""
    return [d for d in get_fixed_and_removable_drives() if d.get("drive_type") == "removable"]


def volume_label(drive: Path) -> str:
    """Read a volume label without shelling out."""
    if not IS_WINDOWS:
        return ""
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        name_buf = ctypes.create_unicode_buffer(261)
        fs_buf = ctypes.create_unicode_buffer(261)
        serial = ctypes.c_ulong(0)
        max_len = ctypes.c_ulong(0)
        flags = ctypes.c_ulong(0)
        ok = kernel32.GetVolumeInformationW(
            str(drive), name_buf, len(name_buf), ctypes.byref(serial),
            ctypes.byref(max_len), ctypes.byref(flags), fs_buf, len(fs_buf),
        )
        return name_buf.value if ok else ""
    except (AttributeError, OSError):
        return ""


def drive_serial(drive: Path) -> str:
    """Best-effort volume serial number as hex string."""
    if not IS_WINDOWS:
        return ""
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        serial = ctypes.c_ulong(0)
        name_buf = ctypes.create_unicode_buffer(261)
        fs_buf = ctypes.create_unicode_buffer(261)
        max_len = ctypes.c_ulong(0)
        flags = ctypes.c_ulong(0)
        ok = kernel32.GetVolumeInformationW(
            str(drive), name_buf, len(name_buf), ctypes.byref(serial),
            ctypes.byref(max_len), ctypes.byref(flags), fs_buf, len(fs_buf),
        )
        return f"{serial.value:08X}" if ok else ""
    except (AttributeError, OSError):
        return ""


# ---------------------------------------------------------------------------
# Registry helpers (Run keys, uninstall entries)
# ---------------------------------------------------------------------------

def registry_read(root: int, subkey: str, value_name: Optional[str] = None) -> List[Tuple[str, object]]:
    """Read a registry key's values. Returns list of (name, data)."""
    if not IS_WINDOWS:
        return []
    try:
        import winreg  # noqa: PLC0415

        with winreg.OpenKey(root, subkey) as key:
            results = []
            index = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, index)
                except OSError:
                    break
                results.append((name, data))
                index += 1
            return results
    except (ImportError, OSError, FileNotFoundError):
        return []


def registry_list_subkeys(root: int, subkey: str) -> List[str]:
    """List subkey names under a registry key."""
    if not IS_WINDOWS:
        return []
    try:
        import winreg  # noqa: PLC0415

        with winreg.OpenKey(root, subkey) as key:
            results = []
            index = 0
            while True:
                try:
                    results.append(winreg.EnumKey(key, index))
                except OSError:
                    break
                index += 1
            return results
    except (ImportError, OSError, FileNotFoundError):
        return []


HKEY_CURRENT_USER = 0x80000001 if IS_WINDOWS else 0
HKEY_LOCAL_MACHINE = 0x80000002 if IS_WINDOWS else 0


# ---------------------------------------------------------------------------
# Microsoft Defender / Windows Security status
# ---------------------------------------------------------------------------

def localguard_in_defender_exclusions() -> Optional[bool]:
    """Check whether LocalGuard's process is in Defender's exclusions.

    Reads the read-only preference ``ExclusionProcess`` from
    ``SOFTWARE\\Microsoft\\Windows Defender\\Exclusions`` in HKLM (no
    elevation needed to read). Returns None when Defender's policy is
    not readable (non-Windows, access denied) - never raises.
    """
    if not IS_WINDOWS:
        return None
    try:
        import winreg  # noqa: PLC0415

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows Defender\Exclusions",
        ) as key:
            index = 0
            while True:
                try:
                    name, _value, _vtype = winreg.EnumValue(key, index)
                except OSError:
                    break
                if name.lower().endswith("localguard.exe"):
                    return True
                index += 1
    except (ImportError, OSError, FileNotFoundError):
        return None
    return False


def get_defender_status() -> Dict[str, object]:
    """Query Windows Security / Defender real-time protection state.

    Uses the PowerShell Get-MpComputerStatus cmdlet with a fixed
    argument list (no shell). Never modifies Defender settings.
    Returns a dict; empty on non-Windows or when unavailable.
    """
    result: Dict[str, object] = {
        "available": False,
        "realtime_enabled": None,
        "antivirus_enabled": None,
        "engine_version": "",
        "signature_version": "",
        "signature_age_days": None,
    }
    if not IS_WINDOWS:
        return result
    ps = _find_powershell()
    if not ps:
        return result
    try:
        output = subprocess.run(  # noqa: S603 - fixed arguments, no shell
            [
                ps, "-NoProfile", "-NonInteractive", "-Command",
                "$s = Get-MpComputerStatus; "
                "'{0}|{1}|{2}|{3}|{4}' -f $s.RealTimeProtectionEnabled,"
                "$s.AntivirusEnabled,$s.AMEngineVersion,$s.AntivirusSignatureVersion,"
                "$s.AntivirusSignatureAge",
            ],
            capture_output=True, text=True, timeout=20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        line = (output.stdout or "").strip().splitlines()[-1] if (output.stdout or "").strip() else ""
        if "|" in line and line != "|||":
            parts = line.split("|")
            result["available"] = True
            if len(parts) >= 1 and parts[0]:
                result["realtime_enabled"] = parts[0] == "True"
            if len(parts) >= 2 and parts[1]:
                result["antivirus_enabled"] = parts[1] == "True"
            if len(parts) >= 3:
                result["engine_version"] = parts[2]
            if len(parts) >= 4:
                result["signature_version"] = parts[3]
            if len(parts) >= 5 and parts[4].isdigit():
                result["signature_age_days"] = int(parts[4])
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("Defender status query failed: %s", exc)
    return result


def _find_powershell() -> Optional[str]:
    """Locate powershell.exe without a shell."""
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    candidate = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    return str(candidate) if candidate.is_file() else None


def open_windows_security() -> None:
    """Open the Windows Security app (user-facing convenience)."""
    if not IS_WINDOWS:
        return
    try:
        os.startfile("windowsdefender:")  # noqa: S606 - documented URI launch
    except OSError as exc:
        logger.warning("Could not open Windows Security: %s", exc)


def set_process_priority(priority: str) -> None:
    """Set current process priority (below_normal / normal)."""
    if not IS_WINDOWS:
        return
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetCurrentProcess()
        classes = {
            "idle": 0x00000040,
            "below_normal": 0x00004000,
            "normal": 0x00000020,
            "above_normal": 0x00008000,
            "high": 0x00000080,
        }
        cls = classes.get(priority, 0x00004000)
        kernel32.SetPriorityClass(handle, cls)
    except (AttributeError, OSError):
        pass

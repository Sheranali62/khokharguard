"""LocalGuard Antivirus - heuristic analysis engine.

Produces evidence-based risk factors from filename, location, content,
and shortcut/autorun structure (spec sections 10 & 16). Heuristic
indicators are never treated as proof of malware: uncertain files are
classified as SUSPICIOUS for user review, never auto-deleted.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable, List, Optional, Set

from engine.risk_engine import RiskEngine
from utils import get_logger
from utils.file_utils import (
    EXECUTABLE_EXTENSIONS,
    SCRIPT_EXTENSIONS,
    SHORTCUT_EXTENSIONS,
    is_hidden,
    read_prefix,
)

logger = get_logger("heuristic")

# Commands that suggest malicious script behaviour when combined with
# other evidence. Matched case-insensitively against script text.
_SUSPICIOUS_SCRIPT_PATTERNS: List[tuple] = [
    (re.compile(r"(?i)\bpowershell\b.*(-enc|-encodedcommand|-w\s+hidden|-nop)"), "encoded/hidden PowerShell"),
    (re.compile(r"(?i)\bcmd(\.exe)?\b.*\/c\s+del\b"), "mass file deletion"),
    (re.compile(r"(?i)\bvssadmin\b.*delete\s+shadows"), "shadow copy deletion"),
    (re.compile(r"(?i)\bbcdedit\b"), "boot configuration modification"),
    (re.compile(r"(?i)\breg\s+add\b.*\\Run\b"), "registry persistence"),
    (re.compile(r"(?i)\bschtasks\b.*\/create\b"), "scheduled task creation"),
    (re.compile(r"(?i)\bnet\s+user\b.*\/add\b"), "user account creation"),
    (re.compile(r"(?i)\binvoke-expression\b|\biex\b"), "Invoke-Expression"),
    (re.compile(r"(?i)\bdownloadstring\b|\bdownloadfile\b"), "remote payload download"),
    (re.compile(r"(?i)\bstart-process\b.*-verb\s+runas"), "elevation attempt"),
    (re.compile(r"(?i)\bcertutil\b.*-urlcache\b"), "certutil download"),
    (re.compile(r"(?i)\bmshta\b\b|\brundll32\b.*javascript"), "mshta/rundll32 script exec"),
]

_TEMP_HINTS = {"temp", "tmp", "$recycle.bin", "recycler", "recycle"}
_STARTUP_HINTS = {"startup", "start menu"}
_SUSPICIOUS_DOC_NAMES = {
    "invoice", "receipt", "payment", "dhl", "fedex", "ups", "order",
    "scan", "document", "resume", "cv", "report", "statement", "ticket",
}

_DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|txt|mp3|mp4|avi|zip|rar|7z)\."
    r"(exe|dll|scr|com|pif|bat|cmd|ps1|vbs|js|jar|hta|lnk)$",
    re.IGNORECASE,
)

_MASQUERADE_RE = re.compile(
    r"\.(exe|scr|com|pif|bat|cmd|vbs|js|lnk)$", re.IGNORECASE
)


def _path_hints(path: Path) -> Set[str]:
    """Lowercase hints from all path components."""
    return {part.lower() for part in path.parts}


def is_in_temp(path: Path) -> bool:
    """True when the file lives in a temp/recycle location."""
    hints = _path_hints(path)
    return any(hint in hints for hint in _TEMP_HINTS)


def is_in_startup(path: Path) -> bool:
    """True when the file lives in a Startup folder."""
    hints = _path_hints(path)
    return any(hint in hints for hint in _STARTUP_HINTS)


def analyze_filename_risk(path: Path, risk: RiskEngine) -> None:
    """Filename-based heuristics: double extensions, masquerading."""
    name = path.name

    if _DOUBLE_EXT_RE.search(name):
        risk.add_factor("double_extension", f"double extension in '{name}'")

    if _MASQUERADE_RE.search(name):
        stem = name.rsplit(".", 1)[0].lower()
        if any(doc in stem for doc in _SUSPICIOUS_DOC_NAMES):
            risk.add_factor(
                "masquerading_document",
                f"executable named like a '{stem}' document",
            )

    # Executables disguised with double dots e.g. file.jpg .exe
    if re.search(r"\s+\.(exe|scr|com|pif)$", name, re.IGNORECASE):
        risk.add_factor("masquerading_document", "space-padded executable extension")


def analyze_location_risk(path: Path, risk: RiskEngine) -> None:
    """Location-based heuristics: temp dirs, startup folders."""
    if is_in_temp(path) and path.suffix.lower() in EXECUTABLE_EXTENSIONS:
        risk.add_factor("executable_in_temp", "executable in temporary directory")
    if is_in_startup(path) and path.suffix.lower() in SUSPICIOUS_ALL:
        risk.add_factor("executable_in_startup", "auto-start location entry")


SUSPICIOUS_ALL = EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS | SHORTCUT_EXTENSIONS


def analyze_script_content(path: Path, risk: RiskEngine) -> Optional[str]:
    """Scan script text for suspicious command patterns.

    Reads a bounded prefix only; never executes the script. Returns
    matched reason text for the first hit, if any.
    """
    if path.suffix.lower() not in SCRIPT_EXTENSIONS:
        return None

    try:
        raw = read_prefix(path, 512 * 1024)
        text = raw.decode("utf-8", errors="replace")
    except OSError:
        return None

    matched: List[str] = []
    for pattern, label in _SUSPICIOUS_SCRIPT_PATTERNS:
        if pattern.search(text):
            matched.append(label)
    if matched:
        risk.add_factor(
            "suspicious_script_content", "; ".join(sorted(set(matched))[:3])
        )
        return "; ".join(sorted(set(matched)))
    return None


def analyze_hidden_attribute(path: Path, risk: RiskEngine) -> None:
    """Flag hidden executables (common on infected USB drives)."""
    if path.suffix.lower() in SUSPICIOUS_ALL and is_hidden(path):
        risk.add_factor("hidden_executable", "hidden attribute on executable")


def analyze_lnk_structure(path: Path, risk: RiskEngine) -> None:
    """Inspect .lnk shortcut bytes for script/executable targets.

    Reads raw bytes only - LNK parsing here is deliberately simple:
    we look for embedded command/script references that indicate a
    malicious shortcut structure (spec section 10).
    """
    if path.suffix.lower() != ".lnk":
        return
    try:
        data = read_prefix(path, 64 * 1024)
        text = data.decode("latin-1", errors="replace")
    except OSError:
        return

    lowered = text.lower()
    suspicious_markers = [
        (".bat", "shortcut targeting batch script"),
        (".cmd", "shortcut targeting batch script"),
        (".ps1", "shortcut targeting PowerShell script"),
        (".vbs", "shortcut targeting VBScript"),
        (".js", "shortcut targeting JScript"),
        ("cmd.exe", "shortcut invoking cmd.exe"),
        ("powershell", "shortcut invoking PowerShell"),
        ("wscript", "shortcut invoking wscript"),
        ("cscript", "shortcut invoking cscript"),
        ("mshta", "shortcut invoking mshta"),
        ("rundll32", "shortcut invoking rundll32"),
    ]
    hits = [label for marker, label in suspicious_markers if marker in lowered]
    if hits:
        risk.add_factor("suspicious_lnk_target", "; ".join(sorted(set(hits))[:2]))


def analyze_autorun_inf(path: Path, risk: RiskEngine) -> Optional[str]:
    """Analyse autorun.inf on removable drives (never auto-deleted).

    Returns 'open=' target when the file references an executable.
    """
    if path.name.lower() != "autorun.inf":
        return None

    try:
        text = read_prefix(path, 32 * 1024).decode("utf-8", errors="replace")
    except OSError:
        return None

    open_target: Optional[str] = None
    has_open = has_shellexecute = has_icon = False
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith((";", "#")):
            continue
        lowered = line.lower()
        if lowered.startswith("open") and "=" in line:
            has_open = True
            open_target = line.split("=", 1)[1].strip()
        elif lowered.startswith("shellexecute") and "=" in line:
            has_shellexecute = True
            open_target = line.split("=", 1)[1].strip()
        elif lowered.startswith("icon") and "=" in line:
            has_icon = True

    if has_open or has_shellexecute:
        risk.add_factor(
            "autorun_inf_mechanism",
            f"autorun.inf launches '{open_target}' when drive is opened",
        )
    elif has_icon:
        risk.add_factor("autorun_inf_mechanism", "autorun.inf overrides drive icon", 5)
    return open_target


def recent_modification_check(path: Path, risk: RiskEngine) -> None:
    """Tiny weight when file was modified in the last 24 hours."""
    try:
        import time

        mtime = path.stat().st_mtime
        if time.time() - mtime < 86400:
            risk.add_factor("recent_modification", "modified within 24 hours")
    except OSError:
        pass


class HeuristicEngine:
    """Facade bundling all heuristic checks for one file."""

    def analyze_file(
        self,
        path: Path,
        risk: RiskEngine,
        *,
        on_removable_drive: bool = False,
        skip_content: bool = False,
    ) -> List[str]:
        """Run all filename/location/content heuristics.

        Returns list of human-readable factor details.
        """
        analyze_filename_risk(path, risk)
        analyze_location_risk(path, risk)

        if not skip_content:
            analyze_script_content(path, risk)
            analyze_lnk_structure(path, risk)
            if on_removable_drive:
                analyze_autorun_inf(path, risk)

        analyze_hidden_attribute(path, risk)
        recent_modification_check(path, risk)
        return [str(f["detail"]) for f in risk.factors if f.get("detail")]

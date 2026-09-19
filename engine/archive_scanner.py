"""Khokhar & Son's Antivirus - archive inspection with bomb protection.

Inspects ZIP/TAR/GZ/BZ2/XZ archives natively; 7Z/RAR when 7-Zip is
installed. Enforces strict extraction limits (spec section 19): member
count, total uncompressed size, single-member size, compression ratio,
recursion depth, and wall-clock time. Extracted content is analysed
only as bytes - never executed - inside a private temp directory.
"""

from __future__ import annotations

import os
import shutil
import tarfile
import time
import zipfile
from pathlib import Path
from typing import Callable, List, Optional

from engine.risk_engine import RiskEngine
from utils import get_logger
from utils.security_utils import (
    ArchiveBombError,
    ArchiveLimits,
    Budget,
    safe_temp_dir,
)

logger = get_logger("archive_scanner")

_ARCHIVE_EXTS = {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz"}


def is_archive(path: Path) -> bool:
    """True when the extension suggests an archive we can inspect."""
    return path.suffix.lower() in _ARCHIVE_EXTS


class ArchiveScanResult:
    """Outcome of scanning one archive file."""

    def __init__(self) -> None:
        self.members_seen: int = 0
        self.members_scanned: int = 0
        self.suspicious_members: List[str] = []
        self.skipped_reason: str = ""
        self.bomb_detected: bool = False
        self.error: str = ""

    @property
    def ok(self) -> bool:
        """True when the archive was processed without fatal error."""
        return not self.error and not self.bomb_detected


class ArchiveScanner:
    """Safe, limited archive inspection feeding the risk engine."""

    def __init__(self, limits: Optional[ArchiveLimits] = None) -> None:
        self.limits = limits or ArchiveLimits()
        self._seven_zip: Optional[Path] = self._find_7z()

    # ------------------------------------------------------------------
    # External tool discovery (optional)
    # ------------------------------------------------------------------

    @staticmethod
    def _find_7z() -> Optional[Path]:
        """Locate 7z.exe in common install locations."""
        candidates = [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
            / "7-Zip" / "7z.exe",
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
            / "7-Zip" / "7z.exe",
        ]
        for candidate in candidates:
            try:
                if candidate.is_file():
                    return candidate
            except OSError:
                continue
        return None

    @property
    def seven_zip_available(self) -> bool:
        """True when 7z.exe was found."""
        return self._seven_zip is not None

    # ------------------------------------------------------------------
    # Public entry
    # ------------------------------------------------------------------

    def scan_archive(
        self,
        path: Path,
        risk: RiskEngine,
        analyze_member: Callable[[Path, RiskEngine], None],
        depth: int = 0,
    ) -> ArchiveScanResult:
        """Scan an archive.

        ``analyze_member`` is a callable(Path, RiskEngine) -> None
        supplied by the caller (usually FileAnalyzer) so nested files
        go through the full analysis pipeline.
        """
        result = ArchiveScanResult()
        if depth > self.limits.max_recursion_depth:
            result.error = "archive recursion depth exceeded"
            return result

        ext = path.suffix.lower()
        try:
            if ext == ".zip":
                self._scan_zip(path, risk, analyze_member, depth, result)
            elif ext in {".tar", ".gz", ".bz2", ".xz"}:
                self._scan_tar(path, risk, analyze_member, depth, result)
            elif ext in {".7z", ".rar"} and self._seven_zip:
                self._scan_with_7z(path, risk, analyze_member, depth, result)
            else:
                result.skipped_reason = f"no handler for {ext} archive"
        except ArchiveBombError as exc:
            result.bomb_detected = True
            risk.add_factor("huge_archive_member", str(exc))
            logger.warning("Archive bomb protection triggered for %s: %s",
                           path, exc)
        except (OSError, zipfile.BadZipFile, tarfile.TarError, EOFError,
                ValueError) as exc:
            result.error = f"corrupt or unreadable archive: {exc}"
            risk.add_factor("malformed_archive_member", result.error)
        except Exception as exc:  # noqa: BLE001 - one bad file must not stop a scan
            result.error = f"unexpected archive error: {exc}"
            logger.warning("Archive scan error %s: %s", path, exc, exc_info=True)
        return result

    # ------------------------------------------------------------------
    # ZIP
    # ------------------------------------------------------------------

    def _scan_zip(self, path: Path, risk: RiskEngine, analyze_member,
                  depth: int, result: ArchiveScanResult) -> None:
        """ZIP inspection with per-member budget accounting."""
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            result.members_seen = len(names)
            budget = Budget(self.limits)
            started = time.monotonic()

            with safe_temp_dir() as tmp:
                tmp_dir = Path(tmp)
                for name in names:
                    if time.monotonic() - started > self.limits.max_archive_seconds:
                        result.skipped_reason = "archive time limit reached"
                        break
                    info = zf.getinfo(name)
                    budget.account(info.file_size, info.compress_size)
                    if name.endswith("/"):
                        continue
                    result.members_scanned += 1

                    # Path traversal guard on member names.
                    if ".." in Path(name).parts or Path(name).is_absolute():
                        risk.add_factor(
                            "malformed_archive_member",
                            f"unsafe member path '{name}'",
                        )
                        continue

                    safe_name = name.replace("\\", "/").lstrip("/")
                    target = tmp_dir / safe_name
                    try:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        data = zf.read(name)
                        target.write_bytes(data)
                    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                        result.skipped_reason = f"member unreadable: {name}"
                        logger.debug("ZIP member %s unreadable: %s", name, exc)
                        continue

                    self._dispatch_member(target, risk, analyze_member,
                                          depth, result)
                    target.unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # TAR family
    # ------------------------------------------------------------------

    def _scan_tar(self, path: Path, risk: RiskEngine, analyze_member,
                  depth: int, result: ArchiveScanResult) -> None:
        """TAR/gzip/bzip2/xz inspection with budget accounting."""
        with safe_temp_dir() as tmp:
            tmp_dir = Path(tmp)
            try:
                with tarfile.open(path, "r:*") as tf:
                    members = tf.getmembers()
                    result.members_seen = len(members)
                    budget = Budget(self.limits)
                    started = time.monotonic()

                    for member in members:
                        if time.monotonic() - started > self.limits.max_archive_seconds:
                            result.skipped_reason = "archive time limit reached"
                            break
                        if not member.isfile():
                            continue
                        budget.account(member.size, None)
                        result.members_scanned += 1

                        if (".." in Path(member.name).parts
                                or Path(member.name).is_absolute()):
                            risk.add_factor(
                                "malformed_archive_member",
                                f"unsafe member path '{member.name}'",
                            )
                            continue

                        safe_name = member.name.replace("\\", "/").lstrip("/")
                        target = tmp_dir / safe_name
                        try:
                            target.parent.mkdir(parents=True, exist_ok=True)
                            source = tf.extractfile(member)
                            if source is None:
                                continue
                            with open(target, "wb") as out:
                                shutil.copyfileobj(source, out, length=256 * 1024)
                        except (OSError, tarfile.TarError, EOFError) as exc:
                            result.skipped_reason = \
                                f"member unreadable: {member.name}"
                            logger.debug("TAR member %s unreadable: %s",
                                         member.name, exc)
                            continue

                        self._dispatch_member(target, risk, analyze_member,
                                              depth, result)
                        target.unlink(missing_ok=True)
            except tarfile.ReadError as exc:
                result.error = f"corrupt tar archive: {exc}"
                risk.add_factor("malformed_archive_member", result.error)

    # ------------------------------------------------------------------
    # 7z / RAR via 7z.exe (optional)
    # ------------------------------------------------------------------

    def _scan_with_7z(self, path: Path, risk: RiskEngine, analyze_member,
                      depth: int, result: ArchiveScanResult) -> None:
        """Extract with 7z.exe into a private temp dir and analyse."""
        import subprocess  # noqa: S404 - fixed args, no shell

        with safe_temp_dir() as tmp:
            tmp_dir = Path(tmp)
            try:
                proc = subprocess.run(  # noqa: S603
                    [str(self._seven_zip), "x", "-y", f"-o{tmp_dir}",
                     str(path)],
                    capture_output=True,
                    timeout=int(self.limits.max_archive_seconds),
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                result.error = f"7-Zip extraction failed: {exc}"
                return

            if proc.returncode not in (0, 1):  # 1 = warnings only
                result.error = "7-Zip reported archive errors"
                risk.add_factor("malformed_archive_member", result.error)
                return

            members = [p for p in tmp_dir.rglob("*") if p.is_file()]
            result.members_seen = len(members)
            budget = Budget(self.limits)
            for member in members:
                try:
                    budget.account(member.stat().st_size, None)
                except OSError:
                    continue
                result.members_scanned += 1
                self._dispatch_member(member, risk, analyze_member,
                                      depth, result)

    # ------------------------------------------------------------------
    # Member dispatch
    # ------------------------------------------------------------------

    def _dispatch_member(self, member_path: Path, risk: RiskEngine,
                         analyze_member, depth: int,
                         result: ArchiveScanResult) -> None:
        """Analyse one extracted member, recursing into nested archives."""
        if member_path.suffix.lower() in _ARCHIVE_EXTS:
            nested = self.scan_archive(member_path, risk, analyze_member,
                                       depth + 1)
            if nested.bomb_detected:
                raise ArchiveBombError(
                    str(nested.error or "nested archive bomb"))
            return
        try:
            analyze_member(member_path, risk)
        except Exception as exc:  # noqa: BLE001 - keep scanning other members
            logger.debug("Member analysis failed %s: %s", member_path, exc)

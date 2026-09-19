"""Khokhar & Son's Antivirus - security utilities.

Path validation, safe temporary directories, and archive-bomb guards.
These helpers exist so no module scans, opens, or extracts outside the
paths it was explicitly given.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path, PureWindowsPath
from typing import Iterable, Optional

from utils import get_logger

logger = get_logger("security")

_WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")


def is_valid_windows_path(path: str) -> bool:
    """Return True if *path* looks like a syntactically valid Windows path.

    Rejects empty strings, illegal characters, reserved device names,
    and path-traversal fragments.
    """
    if not path or not path.strip():
        return False
    candidate = path.strip()

    if "\x00" in candidate:
        return False

    try:
        pure = PureWindowsPath(candidate)
    except (ValueError, OSError):
        return False

    # Reject traversal fragments used to escape a scan root.
    if ".." in pure.parts:
        return False

    name = pure.name
    stem = name.split(".")[0].upper()
    if stem in _WINDOWS_RESERVED_NAMES:
        return False

    # UNC and drive paths are fine; relative paths are valid too.
    return True


def resolve_safe_path(root: Path, untrusted: str) -> Optional[Path]:
    """Resolve *untrusted* inside *root*, returning None on traversal.

    Prevents path traversal when an archive member name or similar
    untrusted string is joined onto a trusted base directory.
    """
    try:
        root_resolved = root.resolve()
        candidate = (root_resolved / untrusted).resolve()
    except (OSError, ValueError):
        return None
    try:
        candidate.relative_to(root_resolved)
    except ValueError:
        return None
    return candidate


def is_within(child: Path, parent: Path) -> bool:
    """Return True if *child* is located inside *parent*."""
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except (OSError, ValueError):
        return False


def is_reparse_point(path: Path) -> bool:
    """Return True if path is a symlink/junction/mount point."""
    try:
        st = os.lstat(path)
    except (OSError, ValueError):
        return False
    return bool(st.st_file_attributes & 0x400) if hasattr(st, "st_file_attributes") else path.is_symlink()


def safe_temp_dir(prefix: str = "localguard_") -> tempfile.TemporaryDirectory:
    """Create a private temporary directory with restrictive permissions.

    Used for archive inspection and the EICAR self-test; caller must
    clean up via the context manager. Contents are never executed by
    KhokharGuard.

    Cleanup errors are ignored: antivirus products (including Windows
    Defender) routinely hold handles to freshly written files on
    Windows, which would otherwise raise on cleanup. Stranded temp
    files are inert and removed by Windows temp maintenance.
    """
    tmp = tempfile.TemporaryDirectory(  # noqa: S108 - system temp is per-user on Windows
        prefix=prefix, ignore_cleanup_errors=True,
    )
    try:
        os.chmod(tmp.name, 0o700)
    except OSError:
        pass
    return tmp


class ArchiveLimits:
    """Guard values used by the archive scanner to prevent archive bombs."""

    def __init__(
        self,
        max_file_count: int = 10_000,
        max_total_uncompressed_bytes: int = 2 * 1024 * 1024 * 1024,  # 2 GiB
        max_single_file_bytes: int = 512 * 1024 * 1024,              # 512 MiB
        max_compression_ratio: float = 500.0,
        max_recursion_depth: int = 3,
        max_archive_seconds: float = 120.0,
    ) -> None:
        self.max_file_count = max_file_count
        self.max_total_uncompressed_bytes = max_total_uncompressed_bytes
        self.max_single_file_bytes = max_single_file_bytes
        self.max_compression_ratio = max_compression_ratio
        self.max_recursion_depth = max_recursion_depth
        self.max_archive_seconds = max_archive_seconds


class ArchiveBombError(Exception):
    """Raised when an archive exceeds safe extraction limits."""


class Budget:
    """Mutable accounting object enforcing ArchiveLimits during extraction."""

    def __init__(self, limits: Optional[ArchiveLimits] = None) -> None:
        self.limits = limits or ArchiveLimits()
        self.files_seen = 0
        self.total_bytes = 0

    def account(self, declared_size: int, compressed_size: Optional[int] = None) -> None:
        """Account for one member; raise ArchiveBombError when limits trip."""
        self.files_seen += 1
        if self.files_seen > self.limits.max_file_count:
            raise ArchiveBombError(f"Archive member count exceeded {self.limits.max_file_count}")

        if declared_size > self.limits.max_single_file_bytes:
            raise ArchiveBombError("Single archive member exceeds size limit")

        self.total_bytes += max(0, declared_size)
        if self.total_bytes > self.limits.max_total_uncompressed_bytes:
            raise ArchiveBombError("Total uncompressed size exceeds limit")

        if (
            compressed_size
            and compressed_size > 0
            and declared_size / compressed_size > self.limits.max_compression_ratio
        ):
            raise ArchiveBombError("Compression ratio exceeds limit")


def find_executable_on_path(name: str) -> Optional[str]:
    """Locate an executable on PATH without using a shell."""
    exts = [e.upper() for e in os.environ.get("PATHEXT", ".EXE").split(";") if e]
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        for ext in [""] + exts:
            candidate = Path(directory) / f"{name}{ext}"
            try:
                if candidate.is_file():
                    return str(candidate)
            except OSError:
                continue
    return None


def normalize_exclusion_value(value: str, kind: str) -> str:
    """Normalise an exclusion value for reliable comparison."""
    value = value.strip()
    if kind == "extension":
        return value.lower().lstrip(".")
    if kind == "hash":
        return value.lower()
    if kind == "folder":
        return str(Path(value).resolve()).rstrip("\\/") if Path(value).exists() else value.rstrip("\\/")
    if kind == "file":
        try:
            return str(Path(value).resolve())
        except OSError:
            return value
    return value

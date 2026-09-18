"""LocalGuard Antivirus - filesystem helpers.

Chunked SHA-256 hashing, safe file reads, size/extension helpers, and
human-readable formatting. Hashing is streamed so huge files never
load fully into RAM (spec section 13).
"""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path
from typing import Iterator, Optional, Tuple

CHUNK_SIZE = 1024 * 1024  # 1 MiB

# Executable / script extensions LocalGuard analyses (spec section 12).
EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".msi", ".sys", ".drv", ".ocx",
    ".cpl", ".efi",
}
SCRIPT_EXTENSIONS = {
    ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta",
}
SHORTCUT_EXTENSIONS = {".lnk", ".url"}
DOCUMENT_EXTENSIONS = {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".rtf", ".pdf"}
ARCHIVE_EXTENSIONS = {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz"}
SUSPICIOUS_EXTENSIONS = EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS


def sha256_of_file(path: Path, max_bytes: Optional[int] = None) -> str:
    """Compute SHA-256 of a file with chunked reading.

    ``max_bytes`` caps how much of the file is hashed (for oversize
    files); the cap is noted by the caller in analysis results.
    """
    digest = hashlib.sha256()
    remaining = max_bytes
    with open(path, "rb") as handle:
        while True:
            chunk_size = CHUNK_SIZE
            if remaining is not None:
                if remaining <= 0:
                    break
                chunk_size = min(CHUNK_SIZE, remaining)
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
            if remaining is not None:
                remaining -= len(chunk)
    return digest.hexdigest()


def sha256_of_bytes(data: bytes) -> str:
    """Compute SHA-256 of an in-memory byte string."""
    return hashlib.sha256(data).hexdigest()


def human_size(num_bytes: Optional[int]) -> str:
    """Format a byte count as a human-readable string."""
    if num_bytes is None:
        return "?"
    value = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def format_duration(seconds: float) -> str:
    """Format elapsed seconds as H:MM:SS."""
    seconds = max(0, int(seconds))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def file_stat(path: Path) -> dict:
    """Collect size and timestamp metadata for a file (best effort)."""
    info = {
        "size": None,
        "created": None,
        "modified": None,
        "extension": path.suffix.lower(),
    }
    try:
        stat = path.stat()
        info["size"] = stat.st_size
        info["created"] = stat.st_ctime
        info["modified"] = stat.st_mtime
    except OSError:
        pass
    return info


def mtime_of(path: Path) -> Optional[float]:
    """Return modification time or None."""
    try:
        return path.stat().st_mtime
    except OSError:
        return None


def looks_like_pe(path: Path) -> bool:
    """Return True if the file starts with the 'MZ' DOS header."""
    try:
        with open(path, "rb") as handle:
            return handle.read(2) == b"MZ"
    except OSError:
        return False


def read_prefix(path: Path, byte_count: int = 64 * 1024) -> bytes:
    """Read the first *byte_count* bytes of a file (safe, bounded)."""
    try:
        with open(path, "rb") as handle:
            return handle.read(byte_count)
    except OSError:
        return b""


def is_hidden(path: Path) -> bool:
    """Return True if the file or its name indicates hidden status."""
    if path.name.startswith("."):
        return True
    try:
        import ctypes  # noqa: PLC0415 - Windows only, imported lazily

        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))  # type: ignore[attr-defined]
        if attrs == -1:
            return False
        return bool(attrs & 0x2)  # FILE_ATTRIBUTE_HIDDEN
    except (AttributeError, OSError):
        return False


def iter_directory_files(
    directory: Path,
    skip_hidden_dirs: bool = False,
) -> Iterator[Tuple[Path, Optional[str]]]:
    """Yield (path, error) for files under *directory* recursively.

    Errors (access denied, broken links) are yielded as (path, error)
    so the caller can count skipped files without crashing. Reparse
    points are never followed.
    """
    try:
        entries = list(os.scandir(directory))
    except OSError as exc:
        yield directory, str(exc)
        return

    for entry in entries:
        try:
            if entry.is_symlink():
                yield Path(entry.path), "symlink skipped"
                continue
            if entry.is_dir(follow_symlinks=False):
                if skip_hidden_dirs and entry.name.startswith("."):
                    continue
                yield from iter_directory_files(Path(entry.path), skip_hidden_dirs)
            elif entry.is_file(follow_symlinks=False):
                yield Path(entry.path), None
        except OSError as exc:
            yield Path(entry.path), str(exc)


def remove_file_safe(path: Path) -> bool:
    """Delete a file, clearing read-only attributes first. Returns success."""
    try:
        try:
            os.chmod(path, 0o666)
        except OSError:
            pass
        path.unlink()
        return True
    except OSError:
        return False


def utc_timestamp() -> str:
    """Local timestamp string used consistently across DB rows/reports."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

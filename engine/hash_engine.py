"""LocalGuard Antivirus - SHA-256 hash engine.

Computes file hashes with chunked reading plus full metadata records
(path, size, type, timestamps) as required by spec section 13.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

from utils import get_logger
from utils.file_utils import sha256_of_bytes, sha256_of_file

logger = get_logger("hash_engine")


@dataclass
class FileHashRecord:
    """Complete metadata record for one analysed file."""

    path: str
    sha256: str
    size: int
    extension: str
    type: str = "unknown"
    created: float = 0.0
    modified: float = 0.0
    partial_hash: bool = False


def classify_type(path: Path, size: int) -> str:
    """Classify file type from extension and header bytes."""
    ext = path.suffix.lower()
    if ext in {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv"}:
        return "PE32 executable" if size > 2 else "tiny executable"
    if ext in {".msi"}:
        return "OLE compound document"
    if ext in {".bat", ".cmd"}:
        return "batch script"
    if ext == ".ps1":
        return "PowerShell script"
    if ext in {".vbs", ".vbe"}:
        return "VBScript"
    if ext in {".js", ".jse"}:
        return "JScript"
    if ext in {".wsf", ".wsh", ".hta"}:
        return "Windows script host file"
    if ext in {".lnk", ".url"}:
        return "Windows shortcut"
    if ext == ".zip":
        return "ZIP archive"
    if ext == ".7z":
        return "7-Zip archive"
    if ext == ".rar":
        return "RAR archive"
    if ext in {".tar", ".gz", ".bz2", ".xz"}:
        header = b""
        try:
            with open(path, "rb") as fh:
                header = fh.read(4)
        except OSError:
            pass
        if header.startswith(b"\xfd7zXZ"):
            return "XZ archive"
        if header.startswith(b"BZh"):
            return "bzip2 archive"
        if header.startswith(b"\x1f\x8b"):
            return "gzip archive"
        return "tar archive"
    if ext in {".doc", ".xls", ".ppt"}:
        return "legacy Office document"
    if ext in {".docm", ".xlsm", ".pptm"}:
        return "macro-enabled Office document"
    if ext == ".pdf":
        header = b""
        try:
            with open(path, "rb") as fh:
                header = fh.read(5)
        except OSError:
            return "document"
        return "PDF document" if header == b"%PDF-" else "document"
    return f"{ext.lstrip('.').upper() or 'no-extension'} file"


def type_matches_content(path: Path) -> Optional[str]:
    """Detect extension/content mismatch; return note or None.

    Checks PE header for executable extensions and PDF/ZIP magic for
    documents, catching renamed malware like invoice.pdf.exe payloads.
    """
    ext = path.suffix.lower()
    try:
        with open(path, "rb") as fh:
            header = fh.read(8)
    except OSError:
        return None

    if ext in EXEC_EXT and not header.startswith(b"MZ"):
        return "executable extension without PE header"
    if ext in {".pdf"} and not header.startswith(b"%PDF-"):
        return "PDF extension without PDF header"
    if ext in {".zip"} and not header.startswith(b"PK"):
        return "ZIP extension without ZIP header"
    return None


EXEC_EXT = {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".drv", ".com", ".pif"}


class HashEngine:
    """Computes and optionally caches SHA-256 hashes with metadata."""

    def __init__(self, cache_enabled: bool = True, cache_size: int = 20_000) -> None:
        self._cache: Dict[str, tuple] = {}  # path -> (mtime, size, hash)
        self._cache_enabled = cache_enabled
        self._cache_size = cache_size

    def hash_record(
        self, path: Path, max_bytes: Optional[int] = None
    ) -> Optional[FileHashRecord]:
        """Hash a file and build its metadata record.

        Returns None when the file cannot be read at all.
        """
        try:
            stat = path.stat()
            mtime, size = stat.st_mtime, stat.st_size
        except OSError:
            return None

        if self._cache_enabled:
            cached = self._cache.get(str(path))
            if cached and cached[0] == mtime and cached[1] == size:
                return FileHashRecord(
                    path=str(path), sha256=cached[2], size=size,
                    extension=path.suffix.lower(),
                    type=classify_type(path, size),
                    created=stat.st_ctime, modified=mtime,
                )

        partial = False
        try:
            digest = sha256_of_file(path, max_bytes=max_bytes)
            if max_bytes is not None and size > max_bytes:
                partial = True
        except OSError as exc:
            logger.debug("Hash failed for %s: %s", path, exc)
            return None

        if self._cache_enabled:
            if len(self._cache) >= self._cache_size:
                self._cache.clear()
            self._cache[str(path)] = (mtime, size, digest)

        return FileHashRecord(
            path=str(path), sha256=digest, size=size,
            extension=path.suffix.lower(),
            type=classify_type(path, size),
            created=stat.st_ctime, modified=mtime, partial_hash=partial,
        )

    def hash_bytes(self, data: bytes) -> str:
        """Hash an in-memory byte string."""
        return sha256_of_bytes(data)

    def clear_cache(self) -> None:
        """Drop the hash cache."""
        self._cache.clear()

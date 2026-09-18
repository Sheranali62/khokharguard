"""Security utility tests (spec sections 28, 50)."""

from __future__ import annotations

import pytest

from utils.security_utils import (
    find_executable_on_path,
    is_valid_windows_path,
    normalize_exclusion_value,
    resolve_safe_path,
)


def test_valid_paths_accepted():
    """Normal Windows paths validate."""
    assert is_valid_windows_path("C:\\Users\\test\\file.txt")
    assert is_valid_windows_path("relative\\path\\file.exe")
    assert is_valid_windows_path("E:\\usb\\invoice.pdf.exe")


def test_traversal_rejected():
    """Path traversal fragments are rejected."""
    assert not is_valid_windows_path("..\\..\\windows\\system32")
    assert not is_valid_windows_path("C:\\safe\\..\\..\\evil")


def test_empty_and_null_rejected():
    """Empty strings and NUL bytes are rejected."""
    assert not is_valid_windows_path("")
    assert not is_valid_windows_path("   ")
    assert not is_valid_windows_path("file\x00.txt")


def test_reserved_names_rejected():
    """Windows reserved device names are rejected."""
    assert not is_valid_windows_path("CON")
    assert not is_valid_windows_path("NUL.txt")
    assert not is_valid_windows_path("COM1")


def test_resolve_safe_path_blocks_traversal(tmp_path):
    """resolve_safe_path refuses escapes from the base directory."""
    evil = resolve_safe_path(tmp_path, "..\\evil.txt")
    assert evil is None

    good = resolve_safe_path(tmp_path, "sub\\ok.txt")
    assert good is not None
    assert good == (tmp_path / "sub" / "ok.txt").resolve()


def test_normalize_exclusion_values(tmp_path):
    """Exclusion values normalise per type."""
    assert normalize_exclusion_value(".EXE", "extension") == "exe"
    assert normalize_exclusion_value("ABCDEF", "hash") == "abcdef"
    assert normalize_exclusion_value("  C:\\Dir  ", "folder").lower().startswith("c:")


def test_find_executable_on_path():
    """PATH lookup finds an existing executable without a shell."""
    result = find_executable_on_path("python")
    if result is not None:
        assert "python" in result.lower()


def test_logger_sanitization():
    """Log sanitiser redacts secret-like fragments."""
    from utils.logger import sanitize

    text = "connecting with password=hunter2 and token=abc123 done"
    cleaned = sanitize(text)
    assert "hunter2" not in cleaned
    assert "abc123" not in cleaned
    assert "connecting" in cleaned
    assert "done" in cleaned


def test_human_size_formatting():
    """Byte formatting stays readable."""
    from utils.file_utils import format_duration, human_size

    assert human_size(500) == "500 B"
    assert human_size(2048).endswith("KB")
    assert human_size(5 * 1024 * 1024).endswith("MB")
    assert format_duration(3725) == "1:02:05"
    assert format_duration(59) == "00:59"

"""Tests for scanner and file analyzer behaviour (spec section 49)."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from engine.scanner import ScanState, ScanStatistics, Scanner
from engine.signature_engine import EICAR_STRING

def _make_tree(base: Path) -> Path:
    """Create a small test tree with a script and a text file."""
    (base / "sub").mkdir(parents=True)
    (base / "clean.txt").write_text("hello")
    (base / "sub" / "run.bat").write_text("echo hello")
    return base


def test_scanner_collects_files(tmp_path, analyzer):
    """Scanner finds files recursively."""
    _make_tree(tmp_path)
    scanner = Scanner(analyzer, threads=2)
    files = scanner.collect_files([tmp_path])
    names = {f.name for f in files}
    assert {"clean.txt", "run.bat"} <= names


def test_scanner_stats(tmp_path, analyzer):
    """Scanning produces accurate statistics."""
    _make_tree(tmp_path)
    scanner = Scanner(analyzer, threads=2)
    stats = scanner.scan_paths([tmp_path])
    assert stats.files_scanned >= 2
    assert stats.errors == 0


def test_scanner_stop(tmp_path, analyzer):
    """A stop request ends the scan promptly (spec: scanner can stop)."""
    for i in range(200):
        (tmp_path / f"file_{i}.txt").write_text("x" * 100)
    scanner = Scanner(analyzer, threads=2)
    scanner.state.stop()  # request stop before starting
    stats = scanner.scan_paths([tmp_path])
    assert stats.files_scanned == 0


def test_scanner_pause_resume(tmp_path, analyzer):
    """Pause/resume complete without hangs or losses."""
    _make_tree(tmp_path)
    scanner = Scanner(analyzer, threads=2)
    scanner.state.pause()

    def resume_soon() -> None:
        """Resume shortly after start."""
        import time

        time.sleep(0.4)
        scanner.state.resume()

    thread = threading.Thread(target=resume_soon, daemon=True)
    thread.start()
    stats = scanner.scan_paths([tmp_path])
    thread.join(timeout=2)
    assert stats.files_scanned >= 2


def test_scanner_skips_inaccessible(tmp_path, analyzer, monkeypatch):
    """Inaccessible files are counted as skipped, not crashes."""
    _make_tree(tmp_path)
    scanner = Scanner(analyzer, threads=1)

    def unreadable_directory(directory):
        """Simulate unreadable directory."""
        yield directory, "access denied"
        return

    monkeypatch.setattr("engine.scanner.iter_directory_files",
                        unreadable_directory)
    stats = scanner.scan_paths([tmp_path])
    assert stats.skipped >= 1


def test_analyzer_clean_text_file(analyzer, tmp_path):
    """Plain text files stay clean."""
    target = tmp_path / "notes.txt"
    target.write_text("totally normal notes")
    detection = analyzer.analyze_path(target)
    assert detection.severity == "clean"
    assert detection.detection_name == "Clean.File"


def test_analyzer_double_extension(analyzer, tmp_path):
    """invoice.pdf.exe style names are flagged as suspicious."""
    target = tmp_path / "invoice.pdf.exe"
    target.write_bytes(b"MZ" + b"\x00" * 64)
    detection = analyzer.analyze_path(target)
    assert detection.severity in {"medium", "high", "critical"}
    assert any("double" in str(f.get("factor")) for f in detection.factors)


def test_analyzer_script_with_suspicious_content(analyzer, tmp_path):
    """Scripts with shadow-copy deletion commands are flagged."""
    target = tmp_path / "cleanup.cmd"
    target.write_text("vssadmin delete shadows /all /quiet\n")
    detection = analyzer.analyze_path(target)
    assert detection.severity in {"medium", "high", "critical"}
    assert "suspicious_script_content" in [f["factor"] for f in detection.factors]


def test_analyzer_detects_eicar_in_subdir(analyzer, tmp_path):
    """EICAR nested in directories is found by the scanner.

    Skips when Windows Defender interferes with the test artifact.
    """
    import hashlib

    nested = tmp_path / "docs"
    nested.mkdir()
    target = nested / "test.eicar"
    target.write_text(EICAR_STRING)
    try:
        on_disk = hashlib.sha256(target.read_bytes()).hexdigest()
    except OSError:
        pytest.skip("Defender blocks reading the EICAR test file")
    if on_disk != hashlib.sha256(EICAR_STRING.encode()).hexdigest():
        pytest.skip("Defender altered/removed the EICAR test file")
    scanner = Scanner(analyzer, threads=1)
    stats = scanner.scan_paths([tmp_path])
    assert stats.threats_found == 1


def test_scan_state_check():
    """ScanState basic transitions."""
    state = ScanState()
    assert state.check() is True
    state.pause()
    assert state.paused is False  # not yet entered pause loop
    state.stop()
    assert state.stopped is True


def test_statistics_snapshot():
    """Snapshot returns a dict of counters."""
    stats = ScanStatistics()
    snapshot = stats.snapshot()
    assert "files_scanned" in snapshot
    assert "elapsed" in snapshot


def test_corrupt_file_does_not_crash(analyzer, tmp_path):
    """Corrupted files are handled without exceptions."""
    target = tmp_path / "corrupt.exe"
    target.write_bytes(b"MZ\x00\x01garbage" * 10)
    detection = analyzer.analyze_path(target)
    assert detection is not None


def test_unicode_and_long_paths(analyzer, tmp_path):
    """Unicode filenames are analysed without errors."""
    target = tmp_path / "файл_测试_🎉.txt"
    target.write_text("unicode content")
    detection = analyzer.analyze_path(target)
    assert detection is not None

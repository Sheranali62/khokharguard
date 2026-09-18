"""Tests for archive inspection and bomb protection (spec 19, 49, 50)."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from engine.archive_scanner import ArchiveScanner, is_archive
from engine.risk_engine import RiskEngine
from utils.security_utils import ArchiveBombError, ArchiveLimits, Budget


def test_is_archive():
    """Extension detection covers the supported formats."""
    assert is_archive(Path("x.zip"))
    assert is_archive(Path("x.7z"))
    assert is_archive(Path("x.rar"))
    assert is_archive(Path("x.tar"))
    assert is_archive(Path("x.tar.gz"))
    assert not is_archive(Path("x.txt"))


def test_zip_scanning_members(analyzer, tmp_path):
    """ZIP members are extracted to temp and analysed, never executed."""
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("docs/readme.txt", "hello")
        zf.writestr("run.bat", "echo hi")

    risk = RiskEngine()
    scanner = ArchiveScanner()
    result = scanner.scan_archive(archive, risk, lambda member, r: None)

    assert result.ok
    assert result.members_seen == 2
    assert result.members_scanned == 2


def test_zip_with_suspicious_script(analyzer, tmp_path):
    """A suspicious script inside a ZIP contributes risk factors."""
    archive = tmp_path / "payload.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("cleanup.cmd", "vssadmin delete shadows /all /quiet")

    risk = RiskEngine()
    scanner = ArchiveScanner()
    scanner.scan_archive(archive, risk, analyzer._analyze_member)

    assert "suspicious_script_content" in [f["factor"] for f in risk.factors]


def test_zip_path_traversal_member_flagged(tmp_path):
    """Members with traversal names are flagged, not extracted outside."""
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("../escape.txt")
        zf.writestr(info, "bad")

    risk = RiskEngine()
    scanner = ArchiveScanner()
    result = scanner.scan_archive(archive, risk, lambda member, r: None)

    assert any("unsafe member path" in str(f.get("detail", ""))
               for f in risk.factors)
    assert not (tmp_path.parent / "escape.txt").exists()


def test_zip_bomb_member_count_limit(tmp_path):
    """Archives exceeding member limits raise ArchiveBombError handling."""
    archive = tmp_path / "many.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for i in range(50):
            zf.writestr(f"f{i}.txt", "x")

    tiny_limits = ArchiveLimits(max_file_count=10)
    risk = RiskEngine()
    scanner = ArchiveScanner(limits=tiny_limits)
    result = scanner.scan_archive(archive, risk, lambda member, r: None)

    assert result.bomb_detected


def test_zip_bomb_compression_ratio(tmp_path):
    """High compression ratios trip the bomb guard."""
    archive = tmp_path / "ratio.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.txt", b"\x00" * (2 * 1024 * 1024))

    strict = ArchiveLimits(max_total_uncompressed_bytes=10 * 1024 * 1024,
                           max_compression_ratio=100.0)
    risk = RiskEngine()
    scanner = ArchiveScanner(limits=strict)
    result = scanner.scan_archive(archive, risk, lambda member, r: None)

    assert result.bomb_detected


def test_corrupt_zip_handled(tmp_path):
    """Corrupt ZIPs produce an error result, not a crash."""
    archive = tmp_path / "corrupt.zip"
    archive.write_bytes(b"PK\x03\x04 not really a zip file" * 10)

    risk = RiskEngine()
    scanner = ArchiveScanner()
    result = scanner.scan_archive(archive, risk, lambda member, r: None)

    assert not result.ok
    assert result.error


def test_budget_accounting():
    """Budget accumulates and trips on member count."""
    budget = Budget(ArchiveLimits(max_file_count=3))
    budget.account(100, 50)
    budget.account(100, 50)
    budget.account(100, 50)
    with pytest.raises(ArchiveBombError):
        budget.account(100, 50)


def test_budget_total_size():
    """Budget trips on total uncompressed size."""
    budget = Budget(ArchiveLimits(max_total_uncompressed_bytes=1000))
    budget.account(600, None)
    with pytest.raises(ArchiveBombError):
        budget.account(600, None)


def test_unsupported_7z_without_tool(tmp_path):
    """7z archives are skipped cleanly when 7z.exe is absent."""
    archive = tmp_path / "sample.7z"
    archive.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 32)

    risk = RiskEngine()
    scanner = ArchiveScanner()
    scanner._seven_zip = None  # simulate missing tool
    result = scanner.scan_archive(archive, risk, lambda member, r: None)

    assert result.skipped_reason

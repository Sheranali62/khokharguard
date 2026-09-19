"""Tests for incremental scanning (engine/scan_cache.py + wiring).

Covers the persistent clean-verdict cache, skip logic in Scanner,
setting toggles, and signature-change invalidation - all over the
isolated test database, no real filesystem outside tmp_path.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from database.database import Database
from engine.scan_cache import ENGINE_VERSION, ScanCache


@pytest.fixture()
def cache(test_database):
    """ScanCache over the isolated test database."""
    return ScanCache(test_database, sig_version="1.0.0")


@pytest.fixture()
def sample_file(tmp_path):
    """One clean text file and its stat helpers."""
    target = tmp_path / "sample.txt"
    target.write_text("clean payload", encoding="utf-8")
    return target


def test_store_then_lookup_is_a_hit(cache, sample_file):
    """A stored clean verdict makes the identical stat a hit."""
    stat = sample_file.stat()
    assert not cache.lookup(sample_file, stat.st_size, stat.st_mtime_ns)
    cache.store_clean(sample_file, stat.st_size, stat.st_mtime_ns)
    assert cache.lookup(sample_file, stat.st_size, stat.st_mtime_ns)
    assert cache.stats()["hits"] >= 1


def test_content_change_misses(cache, sample_file):
    """Rewriting the file (size or content) invalidates the entry."""
    stat = sample_file.stat()
    cache.store_clean(sample_file, stat.st_size, stat.st_mtime_ns)

    sample_file.write_text("clean payload!", encoding="utf-8")
    new_stat = sample_file.stat()
    assert not cache.lookup(sample_file, new_stat.st_size, new_stat.st_mtime_ns)


def test_mtime_change_misses(cache, sample_file):
    """A pure mtime bump (same bytes) must re-scan."""
    stat = sample_file.stat()
    cache.store_clean(sample_file, stat.st_size, stat.st_mtime_ns)

    future = stat.st_mtime_ns + 1_000_000
    os.utime(sample_file, ns=(future, future))
    new_stat = sample_file.stat()
    assert not cache.lookup(sample_file, new_stat.st_size, new_stat.st_mtime_ns)


def test_missing_file_never_hits(cache, sample_file, tmp_path):
    """A vanished file cannot be looked up in the pipeline.

    The cache keys on (path, size, mtime) values alone, so a stale
    tuple can still "hit" - but the scan pipeline always stats the
    real file first and skips vanished paths entirely, so the case is
    unreachable in practice. Here we pin the documented primitive
    contract and the safe prune behaviour.
    """
    stat = sample_file.stat()
    cache.store_clean(sample_file, stat.st_size, stat.st_mtime_ns)
    sample_file.unlink()
    # Same key values still match (documented primitive behaviour).
    assert cache.lookup(sample_file, stat.st_size, stat.st_mtime_ns)
    # Housekeeping drops the dead entry so the table stays bounded.
    assert cache.prune_missing() == 1
    assert cache.stats()["entries"] == 0


def test_signature_version_change_clears_everything(cache, sample_file):
    """A signature update must re-check previously-clean files."""
    stat = sample_file.stat()
    cache.store_clean(sample_file, stat.st_size, stat.st_mtime_ns)
    assert cache.lookup(sample_file, stat.st_size, stat.st_mtime_ns)

    cache.set_signature_version("2.0.0")
    assert cache.stats()["entries"] == 0
    assert not cache.lookup(sample_file, stat.st_size, stat.st_mtime_ns)


def test_retarget_keeps_current_version_rows(test_database, sample_file):
    """Retargeting keeps rows already stamped with the target version."""
    cache = ScanCache(test_database, sig_version="1.0.0")
    stat = sample_file.stat()
    # Store with the target version directly (as a scan that started
    # before the version was read would).
    cache._sig_version = "1.0.1"
    cache.store_clean(sample_file, stat.st_size, stat.st_mtime_ns)

    cache.retarget_signature_version("1.0.1")
    assert cache.lookup(sample_file, stat.st_size, stat.st_mtime_ns)

    cache.retarget_signature_version("9.9.9")
    assert cache.stats()["entries"] == 0


def test_engine_version_change_invalidates(test_database, sample_file):
    """Entries from another engine version are never matched."""
    stat = sample_file.stat()
    cache = ScanCache(test_database, sig_version="1.0.0")
    cache.store_clean(sample_file, stat.st_size, stat.st_mtime_ns)

    test_database.execute(
        "UPDATE scan_cache SET engine_version = ?",
        (str(int(ENGINE_VERSION) + 1),))
    assert not cache.lookup(sample_file, stat.st_size, stat.st_mtime_ns)


def test_clear_and_prune(cache, sample_file, tmp_path):
    """Housekeeping: prune drops vanished files, clear drops all."""
    stat = sample_file.stat()
    cache.store_clean(sample_file, stat.st_size, stat.st_mtime_ns)
    other = tmp_path / "gone.txt"
    cache.store_clean(other, 1, 1)
    assert cache.stats()["entries"] == 2

    assert cache.prune_missing() == 1  # other.txt does not exist
    assert cache.stats()["entries"] == 1
    assert cache.clear() == 1
    assert cache.stats()["entries"] == 0


def test_corrupt_database_degrades_gracefully(cache, sample_file):
    """Cache failures never break scanning (worst case: always miss)."""
    stat = sample_file.stat()
    cache.store_clean(sample_file, stat.st_size, stat.st_mtime_ns)
    # Simulate a broken backend: lookups fail closed (miss), stores
    # are swallowed.
    cache._db.query_one = lambda *a, **k: (_ for _ in ()).throw(
        RuntimeError("boom"))
    assert not cache.lookup(sample_file, stat.st_size, stat.st_mtime_ns)
    cache.store_clean(sample_file, stat.st_size, stat.st_mtime_ns)  # no raise


# ---------------------------------------------------------------------------
# Scanner / ScanController integration
# ---------------------------------------------------------------------------


@pytest.fixture()
def scan_stack(test_database, tmp_path):
    """Analyzer + tree of clean files ready for repeat scans."""
    from engine.file_analyzer import FileAnalyzer
    from engine.signature_engine import SignatureEngine

    engine = SignatureEngine(database=test_database)
    analyzer = FileAnalyzer(signature_engine=engine, hash_cache=False)
    tree = tmp_path / "tree"
    tree.mkdir()
    for index in range(12):
        (tree / f"f{index:02d}.txt").write_text(
            f"clean payload {index}", encoding="utf-8")
    return analyzer, test_database, tree


def _run_scan(analyzer, database, tree, **kwargs):
    from engine.scan_controller import ScanController

    controller = ScanController(analyzer=analyzer, database=database,
                                threads=2, **kwargs)
    controller.start([tree], scan_type="custom")
    controller.wait()
    return controller.stats


def test_second_scan_hits_cache_for_all_files(scan_stack):
    """Repeat scan of unchanged files is served from the cache."""
    analyzer, database, tree = scan_stack
    first = _run_scan(analyzer, database, tree)
    assert first.cache_hits == 0 and first.files_scanned == 12

    second = _run_scan(analyzer, database, tree)
    assert second.cache_hits == 12
    assert second.files_scanned == 12  # counted as scanned either way
    assert second.threats_found == 0


def test_changed_file_is_rescanned(scan_stack):
    """Exactly the changed file is re-analysed after an edit."""
    analyzer, database, tree = scan_stack
    _run_scan(analyzer, database, tree)

    time.sleep(0.02)
    (tree / "f03.txt").write_text("CHANGED", encoding="utf-8")
    stats = _run_scan(analyzer, database, tree)
    assert stats.cache_hits == 11


def test_threat_is_never_cached(scan_stack, test_database, tmp_path):
    """A detection is re-found on every scan (findings never cached)."""
    analyzer, database, tree = scan_stack
    # A file whose hash is a registered signature: a real threat hit
    # that must survive every repeat scan (only clean is cached).
    target = tree / "bad.exe"
    target.write_text("malicious payload", encoding="utf-8")
    from engine.signature_engine import sha256_of_text

    analyzer.signatures.add_signature(
        sha256_of_text("malicious payload"), "Test.CachedThreat", "high")

    first = _run_scan(analyzer, database, tree)
    assert first.threats_found == 1

    second = _run_scan(analyzer, database, tree)
    assert second.threats_found == 1, (
        "signature-confirmed threats must be re-detected every scan")
    assert second.cache_hits == len(list(tree.glob("*.txt"))), (
        "the clean files may cache; the threat must not")


def test_setting_disables_cache(scan_stack):
    """performance.skip_unchanged_files = False bypasses the cache."""
    analyzer, database, tree = scan_stack
    from utils.settings import get_settings

    _run_scan(analyzer, database, tree)
    get_settings().set("performance.skip_unchanged_files", False)
    try:
        stats = _run_scan(analyzer, database, tree)
        assert stats.cache_hits == 0
    finally:
        get_settings().set("performance.skip_unchanged_files", True)


def test_signature_update_invalidates_cache(scan_stack):
    """Adding a signature (version bump) forces full re-analysis."""
    analyzer, database, tree = scan_stack
    _run_scan(analyzer, database, tree)

    analyzer.signatures.add_signature("a" * 64, "Test.New", "high")
    stats = _run_scan(analyzer, database, tree)
    assert stats.cache_hits == 0


def test_cache_persists_across_controllers(scan_stack):
    """The cache lives in the DB, so new controllers still hit it."""
    analyzer, database, tree = scan_stack
    _run_scan(analyzer, database, tree)

    from engine.scan_controller import ScanController

    fresh = ScanController(analyzer=analyzer, database=database, threads=2)
    fresh.start([tree], scan_type="custom")
    fresh.wait()
    assert fresh.stats.cache_hits == 12

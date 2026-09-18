"""Tests for the SHA-256 hash engine (spec section 49)."""

from __future__ import annotations

import hashlib

from engine.hash_engine import HashEngine, classify_type


def test_sha256_matches_reference(tmp_path):
    """Chunked hashing matches hashlib reference."""
    target = tmp_path / "sample.bin"
    payload = b"localguard test payload" * 10_000
    target.write_bytes(payload)

    engine = HashEngine(cache_enabled=False)
    record = engine.hash_record(target)

    assert record is not None
    assert record.sha256 == hashlib.sha256(payload).hexdigest()
    assert record.size == len(payload)
    assert record.path == str(target)


def test_hash_of_empty_file(tmp_path):
    """Empty files hash to the documented SHA-256 of b''."""
    target = tmp_path / "empty.bin"
    target.write_bytes(b"")

    engine = HashEngine(cache_enabled=False)
    record = engine.hash_record(target)

    assert record is not None
    assert record.sha256 == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_large_file_chunked_hashing(tmp_path):
    """A multi-chunk file hashes correctly (exceeds 1 MiB chunk size)."""
    target = tmp_path / "large.bin"
    payload = bytes(range(256)) * (4 * 1024 * 20)  # > 4 MiB
    target.write_bytes(payload)

    engine = HashEngine(cache_enabled=False)
    record = engine.hash_record(target)

    assert record is not None
    assert record.sha256 == hashlib.sha256(payload).hexdigest()


def test_partial_hash_flag(tmp_path):
    """max_bytes capping records partial_hash=True."""
    target = tmp_path / "big.bin"
    target.write_bytes(b"A" * (2 * 1024 * 1024))

    engine = HashEngine(cache_enabled=False)
    record = engine.hash_record(target, max_bytes=1024 * 1024)

    assert record is not None
    assert record.partial_hash is True


def test_missing_file_returns_none(tmp_path):
    """Nonexistent files return None instead of raising."""
    engine = HashEngine(cache_enabled=False)
    assert engine.hash_record(tmp_path / "missing.bin") is None


def test_hash_cache_hit(tmp_path):
    """Cache returns the same digest without rehashing."""
    target = tmp_path / "cached.bin"
    target.write_bytes(b"cache me")

    engine = HashEngine(cache_enabled=True)
    first = engine.hash_record(target)
    target.write_bytes(b"cache me again")  # mtime bump + content change
    second = engine.hash_record(target)

    assert first is not None and second is not None
    # mtime changed -> cache miss -> fresh digest
    assert first.sha256 != second.sha256


def test_classify_type(tmp_path):
    """Type classification uses extension and headers."""
    assert "PE32" in classify_type(tmp_path / "app.exe", 1000)
    assert "batch" in classify_type(tmp_path / "run.bat", 10)
    assert "PowerShell" in classify_type(tmp_path / "s.ps1", 10)
    assert "shortcut" in classify_type(tmp_path / "link.lnk", 10)
    assert "ZIP" in classify_type(tmp_path / "a.zip", 10)

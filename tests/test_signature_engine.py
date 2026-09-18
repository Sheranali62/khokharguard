"""Tests for signature matching and EICAR support (spec sections 14-15)."""

from __future__ import annotations

import pytest

from engine.signature_engine import EICAR_SHA256, EICAR_STRING, SignatureEngine


def test_eicar_hash_constant():
    """EICAR constant hash matches the real EICAR string hash."""
    import hashlib

    assert hashlib.sha256(EICAR_STRING.encode("ascii")).hexdigest() == EICAR_SHA256


def test_lookup_eicar(signature_engine):
    """The bundled EICAR signature resolves by hash."""
    match = signature_engine.lookup(EICAR_SHA256)
    assert match is not None
    assert match.name == "EICAR.Test.File"
    assert match.severity == "high"
    assert match.category == "test"


def test_lookup_unknown_hash(signature_engine):
    """Unknown hashes return None."""
    assert signature_engine.lookup("f" * 64) is None


def test_is_eicar_bytes(signature_engine):
    """EICAR byte detection works on the raw string."""
    assert signature_engine.is_eicar(EICAR_STRING.encode("ascii"))
    assert not signature_engine.is_eicar(b"just a text file")


def test_analyzer_flags_eicar_file(analyzer, tmp_path):
    """Full analysis pipeline flags an EICAR test file as a threat.

    Skips when Windows Defender interferes (delete-on-write or
    read blocking) - active Defender doing its job.
    """
    import hashlib

    target = tmp_path / "eicar.com"
    target.write_text(EICAR_STRING, encoding="ascii")
    try:
        on_disk = hashlib.sha256(target.read_bytes()).hexdigest()
    except OSError:
        pytest.skip("Defender blocks reading the EICAR test file")
    if on_disk != EICAR_SHA256:
        pytest.skip("Defender altered/removed the EICAR test file")

    detection = analyzer.analyze_path(target)

    assert detection.detection_method == "signature"
    assert detection.detection_name == "EICAR.Test.File"
    assert detection.is_threat
    assert detection.severity in {"high", "critical"}


def test_add_and_remove_signature(signature_engine, tmp_path):
    """User-created signatures persist and match."""
    import hashlib

    payload = b"user signature test"
    digest = hashlib.sha256(payload).hexdigest()
    target = tmp_path / "user.bin"
    target.write_bytes(payload)

    assert signature_engine.add_signature(
        digest, "User.Test.Signature", severity="medium", category="test")

    match = signature_engine.lookup(digest)
    assert match is not None
    assert match.name == "User.Test.Signature"

    signature_engine.remove_signature(digest)
    assert signature_engine.lookup(digest) is None


def test_reject_invalid_hash(signature_engine):
    """Invalid and malformed hashes are rejected."""
    assert not signature_engine.add_signature("nothex", "Bad")
    # Uppercase hex is lower-cased and accepted (documented behaviour).
    assert signature_engine.add_signature("A" * 64, "Uppercase-accepted")
    assert signature_engine.lookup("a" * 64) is not None

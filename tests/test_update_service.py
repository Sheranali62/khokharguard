"""Tests for signature update verification (spec section 37).

Covers the pure-Python Ed25519 implementation against the RFC 8032
test vectors, then the update service: HTTPS enforcement, manifest
signature verification, per-file integrity, path-traversal refusal,
versioned backups, and rollback - all over sandboxed paths with the
network layer stubbed (no real HTTP in tests).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from utils import ed25519
from utils.ed25519 import public_key_from_secret, sign, verify

# ---------------------------------------------------------------------------
# Ed25519: RFC 8032 section 7.1 test vectors
# ---------------------------------------------------------------------------

# TEST 1: empty message.
_RFC_SK1 = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc4" "4449c5697b326919703bac031cae7f60")
_RFC_PK1 = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a" "0ee172f3daa62325af021a68f707511a")
_RFC_SIG1 = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a" "84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46b" "d25bf5f0595bbe24655141438e7a100b")

# TEST 2: one-byte message 0x72.
_RFC_SK2 = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5" "b8a319f35aba624da8cf6ed4fb8a6fb")
_RFC_MSG2 = bytes([0x72])
_RFC_PK2 = bytes.fromhex(
    "3d4017c3e843895a92b70aa74d1b7ebc" "9c982ccf2ec4968cc0cd55f12af4660c")
_RFC_SIG2 = bytes.fromhex(
    "92a009a9f0d4cab8720e820b5f642540" "a2b27b5416503f8fb3762223ebdb69da"
    "085ac1e43e15996e458f3613d0f11d8c" "387b2eaeb4302aeeb00d291612bb0c00")


def test_rfc8032_vector_1():
    """Key derivation and signing match the RFC byte-for-byte."""
    assert public_key_from_secret(_RFC_SK1) == _RFC_PK1
    pk, sig = sign(_RFC_SK1, b"")
    assert pk == _RFC_PK1 and sig == _RFC_SIG1
    assert verify(_RFC_PK1, _RFC_SIG1, b"")


def test_rfc8032_vector_2():
    """Non-empty message vector also passes."""
    assert public_key_from_secret(_RFC_SK2) == _RFC_PK2
    _pk, sig = sign(_RFC_SK2, _RFC_MSG2)
    assert sig == _RFC_SIG2
    assert verify(_RFC_PK2, _RFC_SIG2, _RFC_MSG2)


def test_verify_rejects_tampering():
    """Any change to message or signature invalidates verification."""
    message = b"KhokharGuard manifest body"
    _pk, sig = sign(_RFC_SK1, message)
    assert verify(_RFC_PK1, sig, message)

    bad_sig = bytearray(sig)
    bad_sig[13] ^= 0x40
    assert not verify(_RFC_PK1, bytes(bad_sig), message)
    assert not verify(_RFC_PK1, sig, message + b"x")

    wrong_key = public_key_from_secret(_RFC_SK2)
    assert not verify(wrong_key, sig, message)


def test_verify_rejects_malformed_inputs():
    """Bad lengths, zero keys, and non-canonical scalars fail safely."""
    assert not verify(b"short", b"x" * 64, b"m")
    assert not verify(b"\x00" * 32, b"x" * 64, b"m")
    assert not verify(_RFC_PK1, b"short", b"m")
    assert not verify(_RFC_PK1, b"\x00" * 64, b"m")
    # s >= L is non-canonical and must be refused (malleability guard).
    signature = bytearray(b"\x01" + b"\x00" * 31 + b"\xff" * 32)
    signature[0] = 0xED  # top bits set -> s >= L
    assert not verify(_RFC_PK1, bytes(signature), b"m")


# ---------------------------------------------------------------------------
# Update service (network stubbed, paths sandboxed)
# ---------------------------------------------------------------------------

PUBKEY_NAME = "update_public_key.pub"


@pytest.fixture()
def sig_sandbox(tmp_path, monkeypatch):
    """Sandboxed signatures dir + signing key pair for the tests."""
    import utils.paths as paths

    sig_dir = tmp_path / "signatures"
    (sig_dir / "yara").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(paths, "signatures_dir", lambda: sig_dir)
    secret = os.urandom(32)
    public = public_key_from_secret(secret)
    return sig_dir, secret, public


@pytest.fixture()
def update_env(sig_sandbox, monkeypatch, test_settings):
    """UpdateService with the fetch layer stubbed to local bytes."""
    from services import update_service as us

    sig_dir, secret, public = sig_sandbox
    payloads: dict = {}

    def fake_get(url, max_bytes, timeout=20):
        if not url.lower().startswith("https://"):
            raise us.UpdateError("Update URLs must use HTTPS")
        for path, blob in payloads.items():
            if url.endswith(path):
                return blob
        raise AssertionError(f"unexpected url {url}")

    monkeypatch.setattr(us, "_https_get", fake_get)
    service = us.UpdateService()
    return service, sig_dir, secret, public, payloads, us


def _make_manifest(payloads, version="2026.09.19"):
    """Manifest dict covering the given path->bytes payloads."""
    return {
        "version": version,
        "schema": 1,
        "files": [
            {"path": path, "url": "https://updates.example/" + path,
             "sha256": hashlib.sha256(blob).hexdigest(),
             "size": len(blob)}
            for path, blob in payloads.items()
        ],
    }


def _signed(manifest, secret):
    """Attach a valid Ed25519 signature to the manifest."""
    from services.update_service import canonical_manifest_bytes

    _pk, sig = ed25519.sign(secret, canonical_manifest_bytes(manifest))
    out = dict(manifest)
    out["signature"] = {"ed25519": sig.hex()}
    return out


def test_signed_update_installs_and_backs_up(update_env):
    """A valid signed update installs, backs up the old set, versions."""
    service, sig_dir, secret, public, payloads, us = update_env
    (sig_dir / PUBKEY_NAME).write_bytes(public)
    old_set = {"old": True}
    (sig_dir / "hashes.json").write_bytes(json.dumps(old_set).encode())

    new_hashes = json.dumps({"a" * 64: {"name": "T.M"}}).encode()
    rule = b"rule X { condition: false }"
    payloads.update({"hashes.json": new_hashes,
                     "yara/new_rules.yar": rule})
    manifest = _signed(_make_manifest(payloads), secret)

    assert service.install_update(manifest) is True
    assert (sig_dir / "hashes.json").read_bytes() == new_hashes
    assert (sig_dir / "yara" / "new_rules.yar").read_bytes() == rule
    assert service.settings.get(
        "database.signature_db_version") == "2026.09.19"

    backup = (sig_dir.parent / "signature_backups" / "2026.09.19")
    assert json.loads((backup / "hashes.json").read_bytes()) == old_set
    assert service.list_backups() == ["2026.09.19"]


def test_tampered_manifest_refused(update_env):
    """A signed-then-edited manifest never installs."""
    service, sig_dir, secret, public, payloads, us = update_env
    (sig_dir / PUBKEY_NAME).write_bytes(public)
    payloads["hashes.json"] = b"content"
    manifest = _signed(_make_manifest(payloads), secret)

    tampered = dict(manifest)
    tampered["files"] = [dict(manifest["files"][0])]
    tampered["files"][0]["sha256"] = "f" * 64
    with pytest.raises(us.UpdateError):
        service.install_update(tampered)


def test_unsigned_manifest_refused_when_key_installed(update_env):
    """With a key installed, missing signature = refused."""
    service, sig_dir, secret, public, payloads, us = update_env
    (sig_dir / PUBKEY_NAME).write_bytes(public)
    payloads["hashes.json"] = b"content"
    manifest = _make_manifest(payloads)  # never signed
    with pytest.raises(us.UpdateError, match="signature"):
        service.install_update(manifest)


def test_wrong_key_signature_refused(update_env):
    """A signature from another key does not validate."""
    service, sig_dir, secret, public, payloads, us = update_env
    (sig_dir / PUBKEY_NAME).write_bytes(public)
    payloads["hashes.json"] = b"content"
    manifest = _signed(_make_manifest(payloads), os.urandom(32))
    with pytest.raises(us.UpdateError):
        service.install_update(manifest)


def test_no_key_installed_allows_hash_only_updates(update_env):
    """Without a key, per-file SHA-256 alone governs (documented mode)."""
    service, sig_dir, secret, public, payloads, us = update_env
    payloads["hashes.json"] = b"plain verified content"
    manifest = _make_manifest(payloads)  # unsigned
    assert service.install_update(manifest) is True
    assert (sig_dir / "hashes.json").read_bytes() == b"plain verified content"


def test_https_enforced(sig_sandbox):
    """http:// and ftp:// URLs are refused before any request."""
    from services import update_service as us

    with pytest.raises(us.UpdateError, match="HTTPS"):
        us._https_get("http://insecure.example/manifest.json", 100)
    with pytest.raises(us.UpdateError):
        us._https_get("ftp://host/file", 100)


def test_path_traversal_refused(update_env):
    """Manifest paths escaping signatures/ are rejected even if signed."""
    service, sig_dir, secret, public, payloads, us = update_env
    (sig_dir / PUBKEY_NAME).write_bytes(public)
    evil = _signed({
        "version": "2",
        "files": [{"path": "../evil.txt", "url": "https://x/e",
                   "sha256": hashlib.sha256(b"e").hexdigest()}],
    }, secret)
    with pytest.raises(us.UpdateError, match="escapes"):
        service.install_update(evil)
    assert not (sig_dir.parent / "evil.txt").exists()


def test_corrupt_download_refused(update_env):
    """A file whose bytes do not match the manifest hash never lands."""
    service, sig_dir, secret, public, payloads, us = update_env
    (sig_dir / PUBKEY_NAME).write_bytes(public)
    payloads["hashes.json"] = b"real bytes"

    manifest = _signed(_make_manifest(payloads), secret)
    # Now swap the served bytes AFTER signing the manifest hash.
    payloads["hashes.json"] = b"tampered bytes"
    with pytest.raises(us.UpdateError, match="Integrity"):
        service.install_update(manifest)
    assert not (sig_dir / "hashes.json.staging").exists()


def test_rollback_restores_previous_set(update_env):
    """Rollback brings back the exact previous signature files."""
    service, sig_dir, secret, public, payloads, us = update_env
    (sig_dir / PUBKEY_NAME).write_bytes(public)
    old = json.dumps({"old": 1}).encode()
    (sig_dir / "hashes.json").write_bytes(old)

    payloads["hashes.json"] = json.dumps({"new": 1}).encode()
    assert service.install_update(_signed(_make_manifest(payloads), secret))
    (sig_dir / "hashes.json").write_bytes(b"broken new set")

    assert service.rollback("2026.09.19") is True
    assert json.loads((sig_dir / "hashes.json").read_bytes()) == {"old": 1}


def test_rollback_with_no_backups_is_safe_noop(update_env):
    """No backups: rollback returns False and changes nothing."""
    service, sig_dir, secret, public, payloads, us = update_env
    (sig_dir / "hashes.json").write_bytes(b"current")
    assert service.rollback() is False
    assert (sig_dir / "hashes.json").read_bytes() == b"current"


def test_check_for_updates_offline_and_https(update_env):
    """check_for_updates fails safe: offline message, HTTPS refusal."""
    service, _sig_dir, _secret, _public, _payloads, us = update_env

    result = service.check_for_updates()
    assert result["available"] is False
    assert "offline" in result["error"].lower()

    service.settings.set("updates.update_url", "http://insecure.example/m.json")
    result = service.check_for_updates()
    assert result["available"] is False
    assert "https" in result["error"].lower()


def test_compare_versions():
    """Numeric-aware comparison used for update availability."""
    from services.update_service import compare_versions

    assert compare_versions("1.2.10", "1.2.9") == 1
    assert compare_versions("2026.09.19", "2026.09.18") == 1
    assert compare_versions("1.0", "1.0.1") == -1
    assert compare_versions("2.0", "2.0") == 0


# ---------------------------------------------------------------------------
# Verifier hardening: backend/fallback cross-check (permanent regression net)
# ---------------------------------------------------------------------------


def test_ed25519_backend_and_fallback_agree():
    """Randomized round-trips through both verification paths.

    The v1.1.0 release line caught an intermittent pure-Python failure
    (~1/2000 keys). This test keeps both verifiers honest: when the
    ``cryptography`` backend is installed the two must agree on every
    case, and signatures must always verify.
    """
    import utils.ed25519 as ed

    cases = 120
    for _ in range(cases):
        secret = os.urandom(32)
        message = os.urandom(64)
        public = ed.public_key_from_secret(secret)
        _pk, signature = ed.sign(secret, message)
        assert ed.verify(public, signature, message), \
            "valid signature refused"
        if ed._HAVE_BACKEND:
            assert ed._verify_pure_python(public, signature, message), \
                "fallback disagrees with backend on a valid signature"

    # Tampered and malformed input refused by whichever path is active.
    _pk, signature = ed.sign(os.urandom(32), b"authentic message")
    assert not ed.verify(ed.public_key_from_secret(os.urandom(32)),
                         signature, b"authentic message")
    assert not ed.verify(ed.public_key_from_secret(os.urandom(32)),
                         signature[:-1] + bytes([signature[-1] ^ 1]),
                         b"authentic message")
    assert not ed.verify(b"short", signature, b"x")
    assert not ed.verify(ed.public_key_from_secret(os.urandom(32)),
                         signature + b"pad", b"x")

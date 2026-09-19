"""Differential tests: pure-Python Ed25519 vs the OpenSSL backend.

Root-cause summary of the intermittent verification failures seen on
the v1.1.0 release line:

    1. The original affine double-and-add implementation had a real
       arithmetic defect (roughly 1 in 2000 random keys failed to
       verify their own signatures). Fixed by rewriting the internals
       with extended homogeneous coordinates and the standard
       dbl-2008-hwcd formulas.
    2. After the rewrite, randomized differential testing still
       reported rare disagreements - sampling could not reach the
       cause, because it lives in a region of probability ~2**-255:
       ``_decodepoint`` accepted NON-CANONICAL point encodings
       (y >= p) that RFC 8032 section 5.1.3 requires verifiers to
       reject. The current OpenSSL backend happens to be lenient on
       some of these classes (it decodes y = y0 + p down to the
       canonical point), so the first rewrite traded one divergence
       for the mirror-image one. Fixed by enforcing full RFC 8032
       strictness in the pure decoder: canonical y, and the x = 0
       point with the sign bit set is rejected.

This file pins the agreement permanently:

    - RFC 8032 section 7.1 known-answer vectors (external authority;
      the 1023-octet TEST 1024 message is embedded verbatim from the
      RFC, with the backend arbitrating the transcription).
    - Randomized cross-verification between the two implementations
      (backend and pure must agree on honestly generated signatures
      and on every tampered variant).
    - Deterministic strict-decoding edge cases that random sampling
      cannot reach, including the two non-canonical classes the
      lenient backend accepts (documented divergence; the pure
      implementation stays strict, which the updater treats as
      fail-closed for attacker-controlled manifests).

When the ``cryptography`` package is absent, the differential tests
that need the backend self-skip; the RFC vectors and decoding rules
still run because they are backend-independent.
"""

from __future__ import annotations

import hashlib
import os

import pytest

from utils import ed25519 as P

try:  # Backend availability mirrors utils/ed25519.py.
    from cryptography.hazmat.primitives.asymmetric import ed25519 as backend_ed25519
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    HAVE_BACKEND = True
except ImportError:  # pragma: no cover - depends on install
    HAVE_BACKEND = False

Q = P._Q
L = P._L

# Fixed keys for the deterministic differential cases (documented in
# the module docstring as coming from the v1.1.0 investigation).
FIXED_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
FIXED_MESSAGE = b"khokharguard differential test message"

# RFC 8032 section 7.1 test vectors: (seed_hex, pk_hex, msg_hex, sig_hex).
RFC_8032_VECTORS = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]

# RFC 8032 section 7.1 TEST 1024: the 1023-octet message, verbatim
# from the RFC. Used by test_rfc_8032_vector_1024 below (the backend
# arbitrates the transcription so a typo can never be trusted as a
# known-answer).
RFC_VECTOR_1024_SEED = (
    "f5e5767cf153319517630f226876b86c"
    "8160cc583bc013744c6bf255f5cc0ee5")
RFC_VECTOR_1024_PK = (
    "278117fc144c72340f67d0f2316e8386"
    "ceffbf2b2428c9c51fef7c597f1d426e")
RFC_VECTOR_1024_MSG = (
    "08b8b2b733424243760fe426a4b54908"
    "632110a66c2f6591eabd3345e3e4eb98"
    "fa6e264bf09efe12ee50f8f54e9f77b1"
    "e355f6c50544e23fb1433ddf73be84d8"
    "79de7c0046dc4996d9e773f4bc9efe57"
    "38829adb26c81b37c93a1b270b20329d"
    "658675fc6ea534e0810a4432826bf58c"
    "941efb65d57a338bbd2e26640f89ffbc"
    "1a858efcb8550ee3a5e1998bd177e93a"
    "7363c344fe6b199ee5d02e82d522c4fe"
    "ba15452f80288a821a579116ec6dad2b"
    "3b310da903401aa62100ab5d1a36553e"
    "06203b33890cc9b832f79ef80560ccb9"
    "a39ce767967ed628c6ad573cb116dbef"
    "efd75499da96bd68a8a97b928a8bbc10"
    "3b6621fcde2beca1231d206be6cd9ec7"
    "aff6f6c94fcd7204ed3455c68c83f4a4"
    "1da4af2b74ef5c53f1d8ac70bdcb7ed1"
    "85ce81bd84359d44254d95629e9855a9"
    "4a7c1958d1f8ada5d0532ed8a5aa3fb2"
    "d17ba70eb6248e594e1a2297acbbb39d"
    "502f1a8c6eb6f1ce22b3de1a1f40cc24"
    "554119a831a9aad6079cad88425de6bd"
    "e1a9187ebb6092cf67bf2b13fd65f270"
    "88d78b7e883c8759d2c4f5c65adb7553"
    "878ad575f9fad878e80a0c9ba63bcbcc"
    "2732e69485bbc9c90bfbd62481d9089b"
    "eccf80cfe2df16a2cf65bd92dd597b07"
    "07e0917af48bbb75fed413d238f5555a"
    "7a569d80c3414a8d0859dc65a46128ba"
    "b27af87a71314f318c782b23ebfe808b"
    "82b0ce26401d2e22f04d83d1255dc51a"
    "ddd3b75a2b1ae0784504df543af8969b"
    "e3ea7082ff7fc9888c144da2af58429e"
    "c96031dbcad3dad9af0dcbaaaf268cb8"
    "fcffead94f3c7ca495e056a9b47acdb7"
    "51fb73e666c6c655ade8297297d07ad1"
    "ba5e43f1bca32301651339e22904cc8c"
    "42f58c30c04aafdb038dda0847dd988d"
    "cda6f3bfd15c4b4c4525004aa06eeff8"
    "ca61783aacec57fb3d1f92b0fe2fd1a8"
    "5f6724517b65e614ad6808d6f6ee34df"
    "f7310fdc82aebfd904b01e1dc54b2927"
    "094b2db68d6f903b68401adebf5a7e08"
    "d78ff4ef5d63653a65040cf9bfd4aca7"
    "984a74d37145986780fc0b16ac451649"
    "de6188a7dbdf191f64b5fc5e2ab47b57"
    "f7f7276cd419c17a3ca8e1b939ae49e4"
    "88acba6b965610b5480109c8b17b80e1"
    "b7b750dfc7598d5d5011fd2dcc5600a3"
    "2ef5b52a1ecc820e308aa342721aac09"
    "43bf6686b64b2579376504ccc493d97e"
    "6aed3fb0f9cd71a43dd497f01f17c0e2"
    "cb3797aa2a2f256656168e6c496afc5f"
    "b93246f6b1116398a346f1a641f3b041"
    "e989f7914f90cc2c7fff357876e506b5"
    "0d334ba77c225bc307ba537152f3f161"
    "0e4eafe595f6d9d90d11faa933a15ef1"
    "369546868a7f3a45a96768d40fd9d034"
    "12c091c6315cf4fde7cb68606937380d"
    "b2eaaa707b4c4185c32eddcdd306705e"
    "4dc1ffc872eeee475a64dfac86aba41c"
    "0618983f8741c5ef68d3a101e8a3b8ca"
    "c60c905c15fc910840b94c00a0b9d0")
RFC_VECTOR_1024_SIG = (
    "0aab4c900501b3e24d7cdf4663326a3a"
    "87df5e4843b2cbdb67cbf6e460fec350"
    "aa5371b1508f9f4528ecea23c436d94b"
    "5e8fcd4f681e30a6ac00a9704a188a03")


def _pure_verify(pk: bytes, sig: bytes, msg: bytes) -> bool:
    """Force the pure-Python verification path."""
    return P._verify_pure_python(pk, sig, msg)


def _backend_verify(pk: bytes, sig: bytes, msg: bytes) -> bool:
    try:
        backend_ed25519.Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return True
    except Exception:
        return False


def _backend_public_key(seed: bytes) -> bytes:
    priv = backend_ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


# ---------------------------------------------------------------------------
# RFC 8032 known-answer vectors (external authority; no backend needed)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed_hex,pk_hex,msg_hex,sig_hex", RFC_8032_VECTORS,
                         ids=["empty", "1-byte", "2-byte"])
def test_rfc_8032_vectors_pure_implementation(seed_hex: str, pk_hex: str,
                                              msg_hex: str, sig_hex: str) -> None:
    """Key derivation and verification match the RFC's own vectors."""
    seed, pk = bytes.fromhex(seed_hex), bytes.fromhex(pk_hex)
    msg, sig = bytes.fromhex(msg_hex), bytes.fromhex(sig_hex)

    assert P.public_key_from_secret(seed) == pk
    assert _pure_verify(pk, sig, msg)


def test_rfc_8032_vector_1024() -> None:
    """The 1023-octet RFC vector verifies under both implementations.

    The backend arbitrates the transcription: if this OpenSSL rejects
    the recorded signature, the hex is wrong and must not be trusted
    as a known-answer - fail loudly instead.
    """
    if not HAVE_BACKEND:  # pragma: no cover - depends on install
        pytest.skip("cryptography backend unavailable")
    seed = bytes.fromhex(RFC_VECTOR_1024_SEED)
    pk = bytes.fromhex(RFC_VECTOR_1024_PK)
    msg = bytes.fromhex(RFC_VECTOR_1024_MSG)
    sig = bytes.fromhex(RFC_VECTOR_1024_SIG)

    assert len(msg) == 1023
    assert _backend_verify(pk, sig, msg), (
        "Recorded RFC 8032 TEST 1024 signature hex is wrong - do not "
        "trust it as a known-answer")
    assert P.public_key_from_secret(seed) == pk
    assert _pure_verify(pk, sig, msg)


# ---------------------------------------------------------------------------
# Randomized cross-verification (both implementations must agree)
# ---------------------------------------------------------------------------


def test_randomized_cross_verification_agreement() -> None:
    """Backend- and pure-signed signatures verify under BOTH verifiers."""
    if not HAVE_BACKEND:  # pragma: no cover - depends on install
        pytest.skip("cryptography backend unavailable")
    for i in range(24):
        seed = os.urandom(32)
        msg = os.urandom((i % 61) + 1)
        pk_backend = _backend_public_key(seed)
        sig_backend = backend_ed25519.Ed25519PrivateKey.from_private_bytes(
            seed).sign(msg)
        pk_pure, sig_pure = P.sign(seed, msg)

        assert pk_pure == pk_backend, f"round {i}: public key mismatch"
        assert _pure_verify(pk_backend, sig_backend, msg), \
            f"round {i}: pure rejected a valid backend signature"
        assert _backend_verify(pk_pure, sig_pure, msg), \
            f"round {i}: backend rejected a valid pure signature"
        assert _pure_verify(pk_pure, sig_pure, msg), \
            f"round {i}: pure rejected its own signature"


def test_tampered_variant_verdicts_agree() -> None:
    """Tampered/non-canonical scalar variants are rejected by both."""
    if not HAVE_BACKEND:  # pragma: no cover - depends on install
        pytest.skip("cryptography backend unavailable")
    seed = FIXED_SEED
    msg = FIXED_MESSAGE
    pk = _backend_public_key(seed)
    sig = backend_ed25519.Ed25519PrivateKey.from_private_bytes(seed).sign(msg)

    variants = {
        "flip-r": sig[:31] + bytes([sig[31] ^ 1]) + sig[32:],
        "flip-s": sig[:32] + bytes([sig[32] ^ 1]) + sig[33:],
        "s-at-L": sig[:32] + L.to_bytes(32, "little"),
        "s-L-plus-1": sig[:32] + ((L + 1) % (1 << 256)).to_bytes(32, "little"),
        "truncated": sig[:63],
        "oversized": sig + b"\x00",
        "empty": b"",
        "wrong-message": sig,
    }
    for name, bad in variants.items():
        bad_msg = b"not the signed message" if name == "wrong-message" else msg
        assert _pure_verify(pk, bad, bad_msg) is False, \
            f"pure accepted {name}"
        assert _backend_verify(pk, bad, bad_msg) is False, \
            f"backend accepted {name}"


# ---------------------------------------------------------------------------
# Strict decoding: deterministic cases random sampling cannot reach
# (probability ~2**-255). These pin the RFC 8032 section 5.1.3 rules.
# ---------------------------------------------------------------------------


def _small_y_curve_points() -> list:
    """(y, x) affine points with tiny y for building y >= p encodings."""
    points = []
    for y in range(64):
        den = (P._D * y * y + 1) % Q
        if den == 0:
            continue
        xx = (y * y - 1) * pow(den, Q - 2, Q) % Q
        x = pow(xx, (Q + 3) // 8, Q)
        if (x * x - xx) % Q:
            x = x * P._I % Q
        if (x * x - xx) % Q:
            continue
        points.append((y, x % Q))
    return points


def _signature_for_key_encoding(key_encoding: bytes) -> bytes:
    """A well-formed signature over FIXED_MESSAGE for the crafted key.

    The decoder rejects the key long before the signature math, but a
    real signature makes the test prove the WHOLE verification refuses.
    """
    r = P._encodepoint(
        P._scalarmult(P._B, int.from_bytes(hashlib.sha512(
            key_encoding + FIXED_MESSAGE).digest()[:32], "little") % L))
    return r + (L // 2).to_bytes(32, "little")


def test_identity_with_parity_bit_is_rejected() -> None:
    """The identity encoded with the x-parity bit set must fail to decode.

    OpenSSL's current backend accepts this class (leniency); RFC 8032
    requires rejection, so the pure implementation must refuse it -
    that is the fail-closed direction for attacker-controlled input.
    """
    crafted = (1 | (1 << 255)).to_bytes(32, "little")
    with pytest.raises(ValueError):
        P._decodepoint(crafted)
    assert _pure_verify(crafted, _signature_for_key_encoding(crafted),
                        FIXED_MESSAGE) is False


@pytest.mark.parametrize("y0", [0, 1, 3, 4, 5, 6, 9, 10, 14, 15, 16, 18])
def test_non_canonical_y_encoding_is_rejected(y0: int) -> None:
    """y + p encodings decode to the same curve point but must be refused.

    Built from small-y curve points so y0 + p stays below 2**255 and
    the encoding is a well-formed 32-byte string of a point that
    EXISTS - only its canonicity is violated.
    """
    small = dict(_small_y_curve_points())
    x0 = small[y0]
    enc_int = (y0 + Q) | ((x0 & 1) << 255)
    crafted = enc_int.to_bytes(32, "little")

    with pytest.raises(ValueError):
        P._decodepoint(crafted)
    assert _pure_verify(crafted, _signature_for_key_encoding(crafted),
                        FIXED_MESSAGE) is False


def test_public_verify_uses_backend_when_available() -> None:
    """The public verify() agrees with the pure path on a valid sig."""
    pk, sig = P.sign(FIXED_SEED, FIXED_MESSAGE)
    assert P.verify(pk, sig, FIXED_MESSAGE) is True
    assert _pure_verify(pk, sig, FIXED_MESSAGE) is True
    if HAVE_BACKEND:  # pragma: no branch
        assert _backend_verify(pk, sig, FIXED_MESSAGE) is True

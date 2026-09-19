"""Khokhar & Son's Antivirus - Ed25519 signing and verification (RFC 8032).

Pure-Python Ed25519 used to authenticate signature-update manifests
when a signing public key is installed in
``signatures/update_public_key.pub`` (spec section 37: updates must be
"preferably cryptographically signed").

Scope and safety:

    - Verification is the security-critical path: when a public key is
      installed, update manifests are refused unless their signature
      validates. The implementation follows the RFC 8032 reference
      shape (twisted Edwards curve, extended homogeneous coordinates,
      standard add/double formulas) and is validated in the test suite
      against the RFC's own test vectors.
    - ``sign``/``public_key_from_secret`` exist for maintainers
      preparing update manifests (and for the test suite); the
      application itself never signs anything at runtime.
    - Deliberately small, auditable, and dependency-free. Used only
      for update authentication - never on the scanning hot path.

Verification never raises: malformed inputs (wrong lengths, points not
on the curve, malformed encodings, non-canonical scalars) return
``False`` rather than raising, so a malformed manifest can never crash
the update check.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

try:  # Optional hardened backend (OpenSSL via the cryptography package)
    from cryptography.hazmat.primitives.asymmetric import (
        ed25519 as _backend_ed25519,
    )

    _HAVE_BACKEND = True
except ImportError:  # pragma: no cover - depends on install
    _HAVE_BACKEND = False

# Curve25519 field and group constants (RFC 8032 section 5.1).
_Q = 2 ** 255 - 19                     # field prime
_L = 2 ** 252 + 27742317777372353535851937790883648493   # group order
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q            # curve constant
_2D = (2 * _D) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)                           # sqrt(-1) mod q

# Points are (X, Y, Z, T) in extended coordinates:
# x = X/Z, y = Y/Z, T = XY/Z. The neutral element is (0, 1, 1, 0).
_Point = Tuple[int, int, int, int]


def _sha512(data: bytes) -> bytes:
    """SHA-512 digest."""
    return hashlib.sha512(data).digest()


def _inv(x: int) -> int:
    """Modular inverse in Z_q (Fermat)."""
    return pow(x, _Q - 2, _Q)


def _xrecover(y: int) -> int:
    """Recover x from y on the twisted Edwards curve (a = -1, d)."""
    xx = (y * y - 1) * _inv(_D * y * y + 1) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


def _point_add(p: _Point, q: _Point) -> _Point:
    """Unified addition for a = -1 twisted Edwards (add-2008-hwcd-3)."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _Q
    b = (y1 + x1) * (y2 + x2) % _Q
    c = t1 * _2D * t2 % _Q
    d = z1 * z2 % _Q
    d = (d + d) % _Q
    e = (b - a) % _Q
    f = (d - c) % _Q
    g = (d + c) % _Q
    h = (b + a) % _Q
    return (e * f % _Q, g * h % _Q, f * g % _Q, e * h % _Q)


def _point_double(p: _Point) -> _Point:
    """Doubling for a = -1 twisted Edwards (dbl-2008-hwcd)."""
    x1, y1, z1, _t1 = p
    a = x1 * x1 % _Q
    b = y1 * y1 % _Q
    c = 2 * z1 * z1 % _Q
    e = ((x1 + y1) * (x1 + y1) - a - b) % _Q
    g = (b - a) % _Q
    f = (g - c) % _Q
    h = (-a - b) % _Q
    return (e * f % _Q, g * h % _Q, f * g % _Q, e * h % _Q)


def _scalarmult(point: _Point, scalar: int) -> _Point:
    """Double-and-add scalar multiplication (MSB first)."""
    result = (0, 1, 1, 0)  # neutral element
    if scalar <= 0:
        return result
    bits = bin(scalar)[2:]
    for bit in bits:
        result = _point_double(result)
        if bit == "1":
            result = _point_add(result, point)
    return result


def _is_on_curve(point: Tuple[int, int]) -> bool:
    """True when the affine point satisfies -x^2 + y^2 = 1 + dx^2y^2."""
    x, y = point
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _Q == 0


def _decodeint(data: bytes) -> int:
    """Little-endian integer decoding (RFC 8032 convention)."""
    return int.from_bytes(data, "little")


def _encodeint(value: int) -> bytes:
    """Little-endian 32-byte encoding."""
    return value.to_bytes(32, "little")


def _decodepoint(data: bytes) -> _Point:
    """Decode a 32-byte point encoding; raises ValueError when invalid.

    Enforces the RFC 8032 section 5.1.3 decoding rules: the y integer
    must be canonical (y < p), and the recovered point must lie on the
    curve. Non-canonical encodings are rejected exactly like the
    OpenSSL backend so both verifiers agree on attacker-controlled
    input (differential-tested in tests/test_ed25519_differential.py).
    """
    y = _decodeint(data) & ((1 << 255) - 1)
    if y >= _Q:
        raise ValueError("non-canonical y (y >= p)")
    x = _xrecover(y)
    if x == 0 and (data[31] >> 7) & 1:
        raise ValueError("non-canonical encoding (x = 0 with sign bit)")
    if x & 1 != (data[31] >> 7) & 1:
        x = _Q - x
    if not _is_on_curve((x, y)):
        raise ValueError("point not on curve")
    return (x, y, 1, x * y % _Q)


def _encodepoint(point: _Point) -> bytes:
    """Encode an extended point as 32 bytes (y with the x parity bit)."""
    x, y, z, _t = point
    z_inv = _inv(z)
    x_affine = x * z_inv % _Q
    y_affine = y * z_inv % _Q
    return _encodeint(y_affine | ((x_affine & 1) << 255))


def _points_equal(p: _Point, q: _Point) -> bool:
    """Affine equality of two points in extended coordinates."""
    x1, y1, z1, _t1 = p
    x2, y2, z2, _t2 = q
    return (x1 * z2 - x2 * z1) % _Q == 0 and \
        (y1 * z2 - y2 * z1) % _Q == 0


# Base point B: the unique point with y = 4/5 and even x.
_BY = (4 * pow(5, _Q - 2, _Q)) % _Q
_BX = _xrecover(_BY)
_B = (_BX % _Q, _BY, 1, _BX * _BY % _Q)


def _clamp(secret_key: bytes) -> int:
    """Clamped scalar derived from the first half of SHA-512(secret)."""
    digest = _sha512(secret_key)
    clamped = bytearray(digest[:32])
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    return _decodeint(bytes(clamped))


def public_key_from_secret(secret_key: bytes) -> bytes:
    """Derive the 32-byte public key for a 32-byte secret key."""
    if len(secret_key) != 32:
        raise ValueError("Ed25519 secret keys are 32 bytes")
    return _encodepoint(_scalarmult(_B, _clamp(secret_key)))


def _verify_pure_python(public_key: bytes, signature: bytes,
                        message: bytes) -> bool:
    """RFC 8032 verification without optional dependencies (fallback)."""
    try:
        if len(public_key) != 32 or len(signature) != 64:
            return False  # malformed sizes are never valid signatures
        r_point = _decodepoint(signature[:32])
        a_point = _decodepoint(public_key)
        s_value = _decodeint(signature[32:])
        if s_value >= _L:
            return False  # non-canonical scalar (malleability guard)
        challenge = _decodeint(
            _sha512(signature[:32] + public_key + message))
        return _points_equal(
            _scalarmult(_B, s_value),
            _point_add(r_point, _scalarmult(a_point, challenge)))
    except Exception:  # noqa: BLE001 - malformed input is just invalid
        return False


def sign(secret_key: bytes, message: bytes) -> Tuple[bytes, bytes]:
    """Sign *message*; returns ``(public_key, signature)``.

    Maintainer tool for preparing signed update manifests; the
    application never calls this at runtime.
    """
    if len(secret_key) != 32:
        raise ValueError("Ed25519 secret keys are 32 bytes")
    public_key = public_key_from_secret(secret_key)
    scalar = _clamp(secret_key)

    digest = _sha512(secret_key)
    nonce = _decodeint(_sha512(digest[32:64] + message)) % _L
    r_encoded = _encodepoint(_scalarmult(_B, nonce))
    challenge = _decodeint(_sha512(r_encoded + public_key + message)) % _L
    s_value = (nonce + challenge * scalar) % _L
    return public_key, r_encoded + _encodeint(s_value)


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """True when *signature* verifies over *message* for *public_key*.

    Never raises: malformed inputs (wrong lengths, points not on the
    curve, non-canonical scalars) simply return False. When the
    ``cryptography`` package is available its audited OpenSSL-backed
    implementation performs the verification; the pure-Python path is
    the fallback for installs without that dependency.
    """
    if len(public_key) != 32 or len(signature) != 64:
        return False
    if _HAVE_BACKEND:
        try:
            key = _backend_ed25519.Ed25519PublicKey.from_public_bytes(
                public_key)
            key.verify(signature, message)
            return True
        except Exception:  # noqa: BLE001 - any backend rejection is invalid
            return False
    return _verify_pure_python(public_key, signature, message)

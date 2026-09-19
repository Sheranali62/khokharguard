"""LocalGuard Antivirus - Ed25519 signing and verification (RFC 8032).

Pure-Python Ed25519 used to authenticate signature-update manifests
when a signing public key is installed in
``signatures/update_public_key.pub`` (spec section 37: updates must be
"preferably cryptographically signed").

Scope and safety:

    - Verification is the security-critical path: when a public key is
      installed, update manifests are refused unless their signature
      validates. The implementation follows the RFC 8032 reference
      shape and is validated in the test suite against the RFC's own
      test vectors.
    - ``sign``/``public_key_from_secret`` exist for maintainers
      preparing update manifests (and for the test suite); the
      application itself never signs anything at runtime.
    - Deliberately small, auditable, and dependency-free. Used only
      for update authentication - never on the scanning hot path.

Verification only on the runtime path; errors (wrong lengths, points
not on the curve, malformed encodings) return ``False`` rather than
raising, so a malformed manifest can never crash the update check.
"""

from __future__ import annotations

import hashlib
from typing import Tuple

# Curve25519 field and group constants (RFC 8032 section 5.1).
_Q = 2 ** 255 - 19                     # field prime
_L = 2 ** 252 + 27742317777372353535851937790883648493   # group order
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q            # curve constant
_I = pow(2, (_Q - 1) // 4, _Q)                           # sqrt(-1) mod q


def _sha512(data: bytes) -> bytes:
    """SHA-512 digest."""
    return hashlib.sha512(data).digest()


def _inv(x: int) -> int:
    """Modular inverse in Z_q (Fermat)."""
    return pow(x, _Q - 2, _Q)


def _xrecover(y: int) -> int:
    """Recover x from y on the twisted Edwards curve."""
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


def _edwards_add(p: Tuple[int, int], q: Tuple[int, int]) -> Tuple[int, int]:
    """Point addition on the Edwards curve (affine, RFC 8032 formulas)."""
    x1, y1 = p
    x2, y2 = q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _D * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _D * x1 * x2 * y1 * y2)
    return (x3 % _Q, y3 % _Q)


def _scalarmult(point: Tuple[int, int], scalar: int) -> Tuple[int, int]:
    """Double-and-add scalar multiplication (iterative)."""
    result = (0, 1)  # neutral element
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _edwards_add(result, addend)
        addend = _edwards_add(addend, addend)
        scalar >>= 1
    return result


def _is_on_curve(point: Tuple[int, int]) -> bool:
    """True when the point satisfies the curve equation."""
    x, y = point
    return (-x * x + y * y - 1 - _D * x * x * y * y) % _Q == 0


def _decodeint(data: bytes) -> int:
    """Little-endian integer decoding (RFC 8032 convention)."""
    return int.from_bytes(data, "little")


def _encodeint(value: int) -> bytes:
    """Little-endian 32-byte encoding."""
    return value.to_bytes(32, "little")


def _decodepoint(data: bytes) -> Tuple[int, int]:
    """Decode a 32-byte point encoding; raises ValueError when invalid."""
    y = _decodeint(data) & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != (data[31] >> 7) & 1:
        x = _Q - x
    point = (x, y)
    if not _is_on_curve(point):
        raise ValueError("point not on curve")
    return point


def _encodepoint(point: Tuple[int, int]) -> bytes:
    """Encode a point as 32 bytes (y with the x parity bit on top)."""
    x, y = point
    return _encodeint(y | ((x & 1) << 255))


# Base point B, computed after the helpers above are defined.
_BY = (4 * pow(5, _Q - 2, _Q)) % _Q
_BX = _xrecover(_BY) % _Q
_B = (_BX, _BY)


def public_key_from_secret(secret_key: bytes) -> bytes:
    """Derive the 32-byte public key for a 32-byte secret key."""
    if len(secret_key) != 32:
        raise ValueError("Ed25519 secret keys are 32 bytes")
    digest = _sha512(secret_key)
    clamped = bytearray(digest[:32])
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    scalar = _decodeint(bytes(clamped))
    return _encodepoint(_scalarmult(_B, scalar))


def sign(secret_key: bytes, message: bytes) -> Tuple[bytes, bytes]:
    """Sign *message*; returns ``(public_key, signature)``.

    Maintainer tool for preparing signed update manifests; the
    application never calls this at runtime.
    """
    if len(secret_key) != 32:
        raise ValueError("Ed25519 secret keys are 32 bytes")
    public_key = public_key_from_secret(secret_key)

    digest = _sha512(secret_key)
    clamped = bytearray(digest[:32])
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    scalar = _decodeint(bytes(clamped))

    nonce = _decodeint(_sha512(digest[32:64] + message)) % _L
    r_encoded = _encodepoint(_scalarmult(_B, nonce))
    challenge = _decodeint(_sha512(r_encoded + public_key + message)) % _L
    s_value = (nonce + challenge * scalar) % _L
    return public_key, r_encoded + _encodeint(s_value)


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """True when *signature* verifies over *message* for *public_key*.

    Never raises: malformed inputs (wrong lengths, off-curve points,
    non-canonical scalars) simply return False.
    """
    try:
        if len(public_key) != 32 or len(signature) != 64:
            return False
        r_point = _decodepoint(signature[:32])
        a_point = _decodepoint(public_key)
        s_value = _decodeint(signature[32:])
        if s_value >= _L:
            return False  # non-canonical scalar (malleability guard)
        challenge = _decodeint(
            _sha512(signature[:32] + public_key + message))
        return _scalarmult(_B, s_value) == _edwards_add(
            r_point, _scalarmult(a_point, challenge))
    except Exception:  # noqa: BLE001 - malformed input is just invalid
        return False

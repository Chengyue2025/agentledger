"""NIST P-256 (secp256r1) ECDSA — pure Python, zero dependencies.

Implements:
  * point arithmetic on the short Weierstrass curve y^2 = x^3 - 3x + b;
  * RFC 6979 deterministic nonces (HMAC-SHA256);
  * sign with low-s normalisation and verify;
  * JWK import/export with the exact member sets draft -13 Section 4.2
    requires for ``signerPublicKey`` (kty, crv, x, y — never "d").

Signatures are the raw (r, s) pair; the JWS profile (RFC 7518 Section 3.4)
uses the fixed-length R || S concatenation — assembled in jws.py.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Any

__all__ = [
    "P256_P", "P256_N", "P256_GX", "P256_GY",
    "Point", "is_on_curve", "scalar_mult", "pubkey_from_private",
    "sign", "verify", "jwk_public", "jwk_private", "jwk_to_point",
    "int_to_b64u", "b64u_to_int",
]

P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = P256_P - 3
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

# Affine point: (x, y) or None for the point at infinity.
Point = tuple[int, int] | None

_G: Point = (P256_GX, P256_GY)


def _inv(x: int, m: int) -> int:
    return pow(x, m - 2, m)


def is_on_curve(pt: Point) -> bool:
    if pt is None:
        return True
    x, y = pt
    if not (0 <= x < P256_P and 0 <= y < P256_P):
        return False
    lhs = (y * y) % P256_P
    rhs = (x * x * x + P256_A * x + P256_B) % P256_P
    return lhs == rhs


def _add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P256_P == 0:
            return None
        # doubling
        lam = (3 * x1 * x1 + P256_A) * _inv(2 * y1, P256_P) % P256_P
    else:
        lam = (y2 - y1) * _inv((x2 - x1) % P256_P, P256_P) % P256_P
    x3 = (lam * lam - x1 - x2) % P256_P
    y3 = (lam * (x1 - x3) - y1) % P256_P
    return (x3, y3)


def scalar_mult(k: int, pt: Point) -> Point:
    if pt is None or k % P256_N == 0:
        return None
    k %= P256_N
    result: Point = None
    addend = pt
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def b64u_to_int(text: str) -> int:
    import base64
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    return int.from_bytes(raw, "big")


def int_to_b64u(value: int) -> str:
    import base64
    raw = value.to_bytes(32, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def pubkey_from_private(d: int) -> Point:
    if not (1 <= d < P256_N):
        raise ValueError("private scalar out of range")
    return scalar_mult(d, _G)


def _rfc6979_nonces(x_bytes: bytes, h1_bytes: bytes):
    """Yield deterministic nonces k per RFC 6979 (HMAC-SHA256)."""
    import hmac as _hmac

    def hm(key: bytes, data: bytes) -> bytes:
        return _hmac.new(key, data, hashlib.sha256).digest()

    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hm(k, v + b"\x00" + x_bytes + h1_bytes)
    v = hm(k, v)
    k = hm(k, v + b"\x01" + x_bytes + h1_bytes)
    v = hm(k, v)
    while True:
        v = hm(k, v)
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < P256_N:
            yield candidate
        k = hm(k, v + b"\x00")
        v = hm(k, v)


def sign(digest32: bytes, d: int) -> tuple[int, int]:
    """ECDSA sign a32-byte digest; RFC 6979 nonce; low-s normalised."""
    if len(digest32) != 32:
        raise ValueError("digest must be32 bytes")
    if not (1 <= d < P256_N):
        raise ValueError("private scalar out of range")
    z = int.from_bytes(digest32, "big") % P256_N
    x_bytes = d.to_bytes(32, "big")
    for k in _rfc6979_nonces(x_bytes, digest32):
        big_r = scalar_mult(k, _G)
        assert big_r is not None
        r = big_r[0] % P256_N
        if r == 0:
            continue
        s = _inv(k, P256_N) * (z + r * d) % P256_N
        if s == 0:
            continue
        if s > P256_N // 2:  # low-s (EIP-2 style malleability guard)
            s = P256_N - s
        return (r, s)
    raise RuntimeError("unreachable")  # pragma: no cover


def verify(digest32: bytes, r: int, s: int, pub: Point) -> bool:
    """Verify ECDSA (r, s) over a32-byte digest against an affine point."""
    if len(digest32) != 32:
        return False
    if not (1 <= r < P256_N and 1 <= s < P256_N):
        return False
    if not is_on_curve(pub) or pub is None:
        return False
    z = int.from_bytes(digest32, "big") % P256_N
    w = _inv(s, P256_N)
    u1 = z * w % P256_N
    u2 = r * w % P256_N
    pt = _add(scalar_mult(u1, _G), scalar_mult(u2, pub))
    if pt is None:
        return False
    return pt[0] % P256_N == r


def jwk_public(pub: Point) -> dict[str, Any]:
    if pub is None or not is_on_curve(pub):
        raise ValueError("not a valid P-256 public point")
    x, y = pub
    return {"kty": "EC", "crv": "P-256",
            "x": int_to_b64u(x), "y": int_to_b64u(y)}


def jwk_private(d: int, pub: Point | None = None) -> dict[str, Any]:
    jwk = jwk_public(pub if pub is not None else pubkey_from_private(d))
    jwk["d"] = int_to_b64u(d)
    return jwk


def jwk_to_point(jwk: dict[str, Any]) -> Point:
    """Import a public JWK; enforce draft -13 Section 4.2 member rules."""
    if set(jwk.keys()) != {"kty", "crv", "x", "y"}:
        raise ValueError("signerPublicKey must contain exactly kty, crv, x, y")
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("unsupported key type: %s/%s" % (
            jwk.get("kty"), jwk.get("crv")))
    x = b64u_to_int(jwk["x"])
    y = b64u_to_int(jwk["y"])
    pt = (x, y)
    if not is_on_curve(pt):
        raise ValueError("public key not on P-256")
    return pt

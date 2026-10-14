"""JWS Compact Serialization — draft -13 Section 6 profiles.

  * ES256 (REQUIRED): ECDSA P-256 over SHA-256, signature is the raw
    fixed-length R || S concatenation (64 bytes, RFC 7518 Section 3.4).
    DER-encoded signatures are rejected by construction.
  * EdDSA (OPTIONAL): Ed25519 per RFC 8037 (reuses agentledger.ed25519).
  * "none" is PROHIBITED (Section 6.5).
  * Detached payload support (RFC 7797, Section 6.4): protected header with
    "b64": false and "crit": ["b64"], signing input ASCII(header || '.' ||
    raw payload), compact form header..signature.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from . import ed25519, p256

__all__ = [
    "SUPPORTED_ALGS", "b64u_encode", "b64u_decode",
    "sign_compact", "verify_compact", "signing_input",
]

SUPPORTED_ALGS = ("ES256", "EdDSA")


def b64u_encode(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    import base64
    if text and not all(c.isalnum() or c in "-_" for c in text):
        raise ValueError("invalid base64url character")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def signing_input(header_b64: str, payload_b64: str) -> bytes:
    return (header_b64 + "." + payload_b64).encode("ascii")


def _header_json(header: dict[str, Any]) -> bytes:
    # Deterministic issuance order: keys as given (alg first by convention).
    return json.dumps(header, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sign_compact(payload: bytes, header: dict[str, Any],
                 key: Any) -> str:
    """Sign *payload* under *header*.

    key: for ES256 the private scalar (int); for EdDSA the32-byte seed.
    """
    alg = header.get("alg")
    if alg not in SUPPORTED_ALGS:
        raise ValueError("unsupported alg: %r" % (alg,))
    if "b64" in header:  # detached profile
        if header.get("b64") is not False or header.get("crit") != ["b64"]:
            raise ValueError("malformed detached header")
        h_b64 = b64u_encode(_header_json(header))
        inp = h_b64.encode("ascii") + b"." + payload
        p_b64 = ""
    else:
        h_b64 = b64u_encode(_header_json(header))
        p_b64 = b64u_encode(payload)
        inp = signing_input(h_b64, p_b64)
    if alg == "ES256":
        digest = hashlib.sha256(inp).digest()
        r, s = p256.sign(digest, key)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:  # EdDSA
        sig = ed25519.sign(key, inp)
    return h_b64 + "." + p_b64 + "." + b64u_encode(sig)


def verify_compact(jws: str, allowed: tuple[str, ...] = SUPPORTED_ALGS,
                   payload_override: bytes | None = None,
                   pub: Any = None
                   ) -> tuple[dict[str, Any], bytes]:
    """Verify a compact JWS; return (protected header, payload bytes).

    ``pub`` is the verification key (P-256 point for ES256, raw32-byte key
    for EdDSA). When omitted, the key is resolved from the payload's
    ``signerPublicKey`` — correct for receipt JWS bodies, but callers that
    verify an attached orchestratorSignature (whose payload is the binding
    string) MUST pass the sub-receipt's key explicitly (Section 4.4).

    ``payload_override`` supplies out-of-band payload bytes for the detached
    form (RFC 7797); the supplied bytes MUST be byte-identical to the
    canonical payload (checked by the caller via the DRP field validation).
    """
    segments = jws.split(".")
    if len(segments) != 3:
        raise ValueError("malformed JWS: expected3 segments")
    h_b64, p_b64, s_b64 = segments
    try:
        header = json.loads(b64u_decode(h_b64))
    except Exception as exc:
        raise ValueError("malformed JWS header") from exc
    if not isinstance(header, dict):
        raise ValueError("JWS header must be an object")
    alg = header.get("alg")
    if alg == "none" or alg is None:
        raise ValueError("unsecured JWS is prohibited")
    if alg not in allowed:
        raise ValueError("alg not allowed: %r" % (alg,))
    payload = b64u_decode(p_b64) if p_b64 else b""
    if header.get("b64") is False:
        if header.get("crit") != ["b64"]:
            raise ValueError("detached JWS requires crit [b64]")
        if payload_override is None:
            raise ValueError("detached JWS requires out-of-band payload")
        payload = payload_override
        inp = h_b64.encode("ascii") + b"." + payload
    else:
        if payload_override is not None:
            raise ValueError("payload override only valid for detached JWS")
        inp = signing_input(h_b64, p_b64)
        payload = b64u_decode(p_b64)
    sig = b64u_decode(s_b64)
    key = _resolve_pub(alg, payload, pub)
    if alg == "ES256":
        if len(sig) != 64:
            raise ValueError(
                "ES256 signature must be raw R||S (64 bytes); DER rejected")
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        if not p256.verify(hashlib.sha256(inp).digest(), r, s, key):
            raise ValueError("ES256 signature verification failed")
    else:
        if not ed25519.verify(key, inp, sig):
            raise ValueError("EdDSA signature verification failed")
    return header, payload


def _resolve_pub(alg: str, payload: bytes, pub: Any) -> Any:
    if pub is not None:
        if alg == "ES256":
            if not p256.is_on_curve(pub) or pub is None:
                raise ValueError("invalid P-256 verification point")
        elif len(pub) != 32:
            raise ValueError("invalid Ed25519 public key length")
        return pub
    # Receipt-body resolution: signerPublicKey is carried in the body
    # (draft -13 Section 4.2), not in the JWS header.
    try:
        body = json.loads(payload)
    except Exception as exc:
        raise ValueError("payload is not JSON") from exc
    if not isinstance(body, dict):
        raise ValueError("payload must be a JSON object")
    jwk = body.get("signerPublicKey")
    if not isinstance(jwk, dict):
        raise ValueError("missing signerPublicKey in receipt body")
    if alg == "ES256":
        return p256.jwk_to_point(jwk)
    import base64
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("EdDSA requires an OKP Ed25519 signerPublicKey")
    raw = base64.urlsafe_b64decode(
        jwk["x"] + "=" * (-len(jwk["x"]) % 4))
    if len(raw) != 32:
        raise ValueError("bad Ed25519 public key length")
    return raw

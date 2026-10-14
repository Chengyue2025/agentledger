"""Agent Delegation Receipt — draft-nelson-agent-delegation-receipts-13.

Implements the normative semantics of Sections 4-10:

  * closed top-level body field set (Section 4.1) with UNKNOWN_BODY_FIELD;
  * lossy instruction normalization (Section 4.2) — verified empirically
    against the draft's own vectors and the published interop corpus;
  * JCS signing input (Section 5), JWS compact profile (Section 6),
    four-step issuance order (Section 6.6), receiptId (Section 6.6);
  * sub-receipt issuance sequence (Section 8.7), attenuation on literal
    operation::resource keys (Section 8.5), depth limit (Section 8.6),
    orchestrator binding signed by the sub-receipt key (Section 4.4);
  * revocation records + registry, cascade and offline fail-closed
    behaviour (Section 9);
  * the pre-execution gate checks relevant to receipts (Section 10);
  * the published interop corpus runner (7 cases; expected.valid is the
    normative comparison — see receipt-commons/receipt-interop README).
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from . import ed25519, jcs, jws, p256

__all__ = [
    "REQUIRED_FIELDS", "OPTIONAL_FIELDS", "BODY_FIELDS",
    "Normalize", "instructions_hash", "normalize_instructions",
    "receipt_id", "issue", "issue_sub_receipt",
    "verify_receipt", "verify_chain", "VerifyResult",
    "check_action", "action_allowed",
    "issue_revocation_record", "verify_revocation_record",
    "RevocationRegistry", "run_corpus",
]

# ---------------------------------------------------------------- fields

REQUIRED_FIELDS = frozenset({
    "delegationId", "issuedAt", "scope", "boundaries", "timeWindow",
    "operatorInstructions", "instructionsHash", "signerPublicKey",
})
OPTIONAL_FIELDS = frozenset({
    "agentId", "metadata", "toolSchemaHash", "trustedSources",
    "toolOutputHash", "revocationRequired", "oneTimeUse",
    "parentReceiptId", "authorityStateCommitment", "reauthPolicy",
    "scopeSchema", "nonce",
})
BODY_FIELDS = REQUIRED_FIELDS | OPTIONAL_FIELDS
ATTACHED_FIELDS = frozenset({
    "orchestratorSignature", "receiptId", "revoked", "signature",
})

ALGS_REQUIRED = ("ES256",)
ALGS_KNOWN = ("ES256", "EdDSA")

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

# ------------------------------------------------------------- utilities


def _now_ms() -> int:
    return int(time.time() * 1000)


def parse_time(value: Any) -> int:
    """Parse an ISO-8601 timestamp (Z-suffixed or offset) to epoch ms."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value)
    if not isinstance(value, str):
        raise ValueError("time must be ISO-8601 string or epoch ms")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (ms % 1000)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------- instruction hashing


def normalize_instructions(text: str) -> str:
    """Lossy normalization, Section 4.2 (pinned against draft vectors).

    trim -> lowercase -> sort detected key-value line groups by key ->
    collapse whitespace runs -> remove commas -> remove sentence-final
    periods -> remove straight/curly quotes.

    The draft lists the steps as a set; key-value detection only survives
    if it runs on line structure before whitespace collapse (the corpus
    and draft vectors carry single-sentence instructions, so either order
    reproduces them byte-for-byte).
    """
    if not isinstance(text, str):
        raise TypeError("operatorInstructions must be a string")
    s = text.strip().lower()
    # Sort detected key-value pairs (consecutive "key: value" or
    # "key=value" lines) alphabetically by key.
    lines = s.split("\n")
    kv = re.compile(r"^([a-z0-9_.\-]+)\s*[:=]\s*(.+)$")
    out: list[str] = []
    i = 0
    while i < len(lines):
        match = kv.match(lines[i])
        if not match:
            out.append(lines[i])
            i += 1
            continue
        group = [lines[i]]
        i += 1
        while i < len(lines) and kv.match(lines[i]):
            group.append(lines[i])
            i += 1
        group.sort(key=lambda ln: kv.match(ln).group(1))
        out.extend(group)
    s = "\n".join(out)
    s = re.sub(r"\s+", " ", s)
    s = s.replace(",", "")
    # Sentence-final periods: a period not immediately followed by a digit
    # (keeps numeric decimals like "2.5" intact).
    s = re.sub(r"\.(?!\d)", "", s)
    for quote in ("'", '"', "\u2018", "\u2019", "\u201c", "\u201d"):
        s = s.replace(quote, "")
    return s


def instructions_hash(text: str) -> str:
    return sha256_hex(normalize_instructions(text).encode("utf-8"))


# ------------------------------------------------------------ results


@dataclass
class VerifyResult:
    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    body: dict[str, Any] | None = None
    receipt_id: str | None = None
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "errors": list(self.errors),
                "warnings": list(self.warnings),
                "receiptId": self.receipt_id}


def _fail(code: str, body: dict[str, Any] | None = None,
          rid: str | None = None, detail: str = "",
          warnings: Iterable[str] = ()) -> VerifyResult:
    return VerifyResult(False, [code], list(warnings), body, rid, detail)


# ------------------------------------------------------- body validation


def validate_body(body: Any) -> list[str]:
    """Return a list of field-validation error codes (empty == valid)."""
    if not isinstance(body, dict):
        return ["PAYLOAD_NOT_OBJECT"]
    unknown = sorted(set(body) - BODY_FIELDS)
    if unknown:
        return ["UNKNOWN_BODY_FIELD:" + ",".join(unknown)]
    missing = sorted(REQUIRED_FIELDS - set(body))
    if missing:
        return ["FIELD_MISSING:" + ",".join(missing)]
    errors: list[str] = []
    for name in ("delegationId", "scope", "boundaries",
                 "operatorInstructions"):
        if not isinstance(body[name], str):
            errors.append("FIELD_INVALID:%s" % name)
    if not _HEX64.match(str(body.get("instructionsHash", ""))):
        errors.append("FIELD_INVALID:instructionsHash")
    try:
        parse_time(body["issuedAt"])
    except Exception:
        errors.append("FIELD_INVALID:issuedAt")
    win = body["timeWindow"]
    if not isinstance(win, dict) or "start" not in win or "end" not in win:
        errors.append("FIELD_INVALID:timeWindow")
    else:
        try:
            start, end = parse_time(win["start"]), parse_time(win["end"])
            if start > end:
                errors.append("FIELD_INVALID:timeWindow.order")
        except Exception:
            errors.append("FIELD_INVALID:timeWindow")
    if not isinstance(body["signerPublicKey"], dict):
        errors.append("FIELD_INVALID:signerPublicKey")
    for name in ("agentId", "trustedSources", "toolSchemaHash",
                 "toolOutputHash", "oneTimeUse", "revocationRequired",
                 "parentReceiptId", "nonce", "reauthPolicy",
                 "authorityStateCommitment", "metadata"):
        if name in body and body[name] is None:
            errors.append("FIELD_INVALID:%s" % name)
    for name, kind in (("agentId", str), ("metadata", dict),
                       ("trustedSources", list), ("toolSchemaHash", str),
                       ("toolOutputHash", str), ("oneTimeUse", bool),
                       ("revocationRequired", bool),
                       ("parentReceiptId", str), ("nonce", str)):
        if name in body and not isinstance(body[name], kind):
            errors.append("FIELD_INVALID:%s" % name)
    for name in ("toolSchemaHash", "toolOutputHash", "parentReceiptId"):
        if name in body and isinstance(body[name], str) \
                and not _HEX64.match(body[name]):
            errors.append("FIELD_INVALID:%s" % name)
    if "trustedSources" in body and isinstance(body["trustedSources"], list) \
            and not all(isinstance(x, str) for x in body["trustedSources"]):
        errors.append("FIELD_INVALID:trustedSources")
    if "scopeSchema" in body:
        errors.extend(_validate_schema(body["scopeSchema"]))
    # ES256 conformance: signerPublicKey must be exactly kty/crv/x/y and a
    # valid P-256 point (also rejects any private material, Section 4.2).
    if isinstance(body.get("signerPublicKey"), dict):
        jwk = body["signerPublicKey"]
        if jwk.get("kty") == "EC":
            try:
                p256.jwk_to_point(jwk)
            except ValueError as exc:
                errors.append("FIELD_INVALID:signerPublicKey:%s" % exc)
        elif not (jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519"
                  and isinstance(jwk.get("x"), str)):
            errors.append("FIELD_INVALID:signerPublicKey")
    return errors


def _validate_schema(schema: Any) -> list[str]:
    if not isinstance(schema, dict):
        return ["FIELD_INVALID:scopeSchema"]
    errors: list[str] = []
    allowed = schema.get("allowedActions")
    if not isinstance(allowed, list):
        errors.append("FIELD_INVALID:scopeSchema.allowedActions")
        return errors
    for entry in allowed + schema.get("deniedActions", []):
        if not isinstance(entry, dict) \
                or not isinstance(entry.get("operation"), str) \
                or not isinstance(entry.get("resource"), str):
            errors.append("FIELD_INVALID:scopeSchema.entry")
            break
    denied = schema.get("deniedActions", [])
    if not isinstance(denied, list):
        errors.append("FIELD_INVALID:scopeSchema.deniedActions")
    return errors


# -------------------------------------------------------------- issuance


def _jwk_for(key: Any, alg: str) -> dict[str, Any]:
    if alg == "ES256":
        if isinstance(key, dict) and "d" in key:
            d = p256.b64u_to_int(key["d"])
            return p256.jwk_public(p256.pubkey_from_private(d))
        return p256.jwk_public(p256.pubkey_from_private(key))
    if alg == "EdDSA":
        import base64
        return {"kty": "OKP", "crv": "Ed25519",
                "x": base64.urlsafe_b64encode(
                    ed25519.public_key(key)).rstrip(b"=").decode()}
    raise ValueError("unsupported alg %r" % alg)


def _prepare_body(body: dict[str, Any]) -> bytes:
    if not isinstance(body, dict):
        raise TypeError("receipt body must be a dict")
    bad = sorted(set(body) & ATTACHED_FIELDS)
    if bad:
        raise ValueError("attached values must not be signed: %s"
                         % ",".join(bad))
    unknown = sorted(set(body) - BODY_FIELDS)
    if unknown:
        raise ValueError("issuers MUST NOT emit unknown top-level fields: "
                         + ",".join(unknown))
    return jcs.canonicalize(body)


def issue(body: dict[str, Any], key: Any, alg: str = "ES256",
          typ: str = "drp-receipt") -> tuple[str, str]:
    """Issue a receipt: Section 6.6 order (body -> canonical -> sign ->
    serialize -> hash). Returns (jws, receiptId)."""
    payload = _prepare_body(body)
    if alg not in ALGS_KNOWN:
        raise ValueError("unsupported alg %r" % alg)
    header = {"alg": alg}
    if typ:
        header["typ"] = typ
    signed = jws.sign_compact(payload, header, key)
    return signed, receipt_id(signed)


def receipt_id(jws_text: str) -> str:
    """Lowercase hex SHA-256 of the ASCII bytes of the compact JWS."""
    return sha256_hex(jws_text.encode("ascii"))


def _schema_keys(actions: Any) -> list[str]:
    return ["%s::%s" % (a.get("operation"), a.get("resource"))
            for a in actions]


def check_attenuation(parent_body: dict[str, Any],
                      child_body: dict[str, Any]) -> str | None:
    """Section 8.5: literal-key strict proper subset. Returns an error
    detail string on violation, else None."""
    child = child_body.get("scopeSchema")
    parent = parent_body.get("scopeSchema")
    if child is None:
        return None  # text-only child: nothing machine-checkable
    if parent is None:
        return "parent lacks scopeSchema (structured scope required)"
    pa, ca = parent.get("allowedActions", []), child.get("allowedActions", [])
    pd = parent.get("deniedActions", [])
    cd = child.get("deniedActions", [])
    pkeys, ckeys = set(_schema_keys(pa)), set(_schema_keys(ca))
    if not set(ckeys) <= pkeys:
        extra = sorted(set(ckeys) - pkeys)
        return "child grants what parent does not: " + ",".join(extra)
    if len(ca) >= len(pa):
        return ("child allowedActions must be strictly fewer than parent "
                "(%d >= %d)" % (len(ca), len(pa)))
    if not set(_schema_keys(pd)) <= set(_schema_keys(cd)):
        missing = sorted(set(_schema_keys(pd)) - set(_schema_keys(cd)))
        return "child drops parent denials: " + ",".join(missing)
    return None


def check_window_contained(parent_body: dict[str, Any],
                           child_body: dict[str, Any]) -> bool:
    pw, cw = parent_body["timeWindow"], child_body["timeWindow"]
    return (parse_time(cw["start"]) >= parse_time(pw["start"])
            and parse_time(cw["end"]) <= parse_time(pw["end"]))


def issue_sub_receipt(child_body: dict[str, Any], key: Any,
                      parent_jws: str, alg: str = "ES256",
                      typ: str = "drp-receipt",
                      orch_key: Any = None,
                      ) -> tuple[str, str, str]:
    """Section 8.7 issuance sequence. Returns (child jws, receiptId,
    orchestratorSignature JWS).

    The Orchestrator's key signs both the sub-receipt and the binding
    string (Section 4.4 pinning: verifier checks the binding against the
    sub-receipt's signerPublicKey).
    """
    parent_body, parent_rid = _load(parent_jws, verify=True)
    child = dict(child_body)
    if "parentReceiptId" in child:
        raise ValueError("parentReceiptId is derived, not supplied")
    violation = check_attenuation(parent_body, child)
    if violation is not None:
        raise ValueError("scope attenuation violated: " + violation)
    if not check_window_contained(parent_body, child):
        raise ValueError("child timeWindow not contained in parent window")
    child["parentReceiptId"] = parent_rid
    signed, rid = issue(child, key, alg=alg, typ=typ)
    binding = ("orchestrator-delegation:%s:%s" % (parent_rid, rid)
               ).encode("ascii")
    orch_jws = jws.sign_compact(binding, {"alg": alg}, orch_key or key)
    return signed, rid, orch_jws


def _load(jws_text: str, verify: bool = True
          ) -> tuple[dict[str, Any], str]:
    try:
        header, payload = jws.verify_compact(jws_text, allowed=ALGS_KNOWN)
    except ValueError as exc:
        raise ValueError("parent JWS invalid: %s" % exc) from exc
    try:
        body = json.loads(payload)
    except Exception as exc:
        raise ValueError("parent payload is not JSON") from exc
    if not isinstance(body, dict):
        raise ValueError("parent payload must be an object")
    if verify:
        errs = validate_body(body)
        if errs:
            raise ValueError("parent body invalid: " + errs[0])
    return body, receipt_id(jws_text)


# ----------------------------------------------------------- verification


def _element_parts(element: Any) -> tuple[str, str | None]:
    if isinstance(element, str):
        return element, None
    if isinstance(element, dict):
        compact = element.get("compact")
        orch = element.get("orchestratorSignature")
        if not isinstance(compact, str):
            raise ValueError("chain element missing compact JWS")
        if orch is not None and not isinstance(orch, str):
            raise ValueError("orchestratorSignature must be a JWS string")
        return compact, orch
    raise ValueError("chain element must be JWS string or object")


def _check_one_time(body: dict[str, Any],
                    consumed: set[str] | None,
                    rid: str) -> str | None:
    if body.get("oneTimeUse") is not True:
        return None
    if consumed is None:
        return "CONSUMPTION_STORE_REQUIRED"
    key = rid if not isinstance(body.get("nonce"), str) \
        else "%s:%s" % (rid, body["nonce"])
    if key in consumed:
        return "RECEIPT_ALREADY_CONSUMED"
    return None


def verify_receipt(jws_text: str, at: Any = None, *,
                   registry: "RevocationRegistry | None" = None,
                   action: dict[str, Any] | None = None,
                   claimed_instructions: str | None = None,
                   require_instructions: bool = False,
                   instruction_source: str | None = None,
                   consumed: set[str] | None = None,
                   require_parent: bool = False,
                   ) -> VerifyResult:
    """Run the pre-execution gate (Section 10) over a single receipt.

    Checks run in order and stop at the first failure (fail closed).
    """
    at_ms = _now_ms() if at is None else parse_time(at)
    try:
        rid = receipt_id(jws_text)
    except Exception:
        return _fail("JWS_MALFORMED", detail="non-ASCII JWS")
    try:
        header, payload = jws.verify_compact(jws_text, allowed=ALGS_KNOWN)
    except ValueError as exc:
        return _fail("JWS_INVALID", detail=str(exc))
    try:
        body = json.loads(payload)
    except Exception as exc:
        return _fail("PAYLOAD_NOT_OBJECT", detail=str(exc))
    errors = validate_body(body)
    if errors:
        return _fail(errors[0], body, rid)
    # Check 2: revocation (Section 9.4 offline fail-closed).
    if body.get("revocationRequired") is True and registry is None:
        return _fail("REVOCATION_CHECK_REQUIRED", body, rid)
    if registry is not None:
        rec = registry.check(rid)
        if rec.get("revoked"):
            return _fail("REVOKED", body, rid, detail=str(rec.get("reason")))
    # Check 3: time window.
    try:
        win = body["timeWindow"]
        if not (parse_time(win["start"]) <= at_ms <= parse_time(win["end"])):
            return _fail("TIME_WINDOW", body, rid)
    except Exception as exc:
        return _fail("FIELD_INVALID:timeWindow", body, rid, detail=str(exc))
    # Check 4: action within structured scope.
    if action is not None:
        allowed, why = action_allowed(body.get("scopeSchema"), action)
        if not allowed:
            return _fail(why or "SCOPE_ACTION_DENIED", body, rid)
    # Check 5: operator instructions.
    if claimed_instructions is not None:
        if instructions_hash(claimed_instructions) != body["instructionsHash"]:
            return _fail("INSTRUCTIONS_MISMATCH", body, rid)
    elif require_instructions:
        return _fail("INSTRUCTIONS_REQUIRED", body, rid)
    # Check: instruction provenance (trustedSources).
    if instruction_source is not None:
        sources = body.get("trustedSources")
        if isinstance(sources, list) and instruction_source not in sources:
            return _fail("UNTRUSTED_INSTRUCTION_SOURCE", body, rid)
    # One-time-use consumption (Section 9.5) runs last.
    ot = _check_one_time(body, consumed, rid)
    if ot is not None:
        return _fail(ot, body, rid)
    if require_parent and isinstance(body.get("parentReceiptId"), str):
        return _fail("PARENT_CONTEXT_REQUIRED", body, rid)
    warnings: list[str] = []
    if "scopeSchema" not in body:
        warnings.append("TEXT_SCOPE_ADVISORY")
    return VerifyResult(True, [], warnings, body, rid)


def _verify_orchestrator(orch_jws: str, binding: str,
                         child_body: dict[str, Any]) -> str | None:
    """Section 4.4: verify binding payload against the SUB-receipt key."""
    try:
        seg = orch_jws.split(".")
        if len(seg) != 3:
            return "malformed"
        header = json.loads(jws.b64u_decode(seg[0]))
        if not isinstance(header, dict):
            return "malformed header"
        alg = header.get("alg")
        if alg not in ALGS_KNOWN:
            return "alg not allowed"
        jwk = child_body["signerPublicKey"]
        if alg == "ES256":
            pub: Any = p256.jwk_to_point(jwk)
        else:
            import base64
            pub = base64.urlsafe_b64decode(
                jwk["x"] + "=" * (-len(jwk["x"]) % 4))
        _, payload = jws.verify_compact(orch_jws, allowed=ALGS_KNOWN, pub=pub)
    except ValueError as exc:
        return str(exc)
    if payload != binding.encode("ascii"):
        return "binding mismatch"
    return None


def verify_chain(elements: Iterable[Any], at: Any = None, *,
                 registry: "RevocationRegistry | None" = None,
                 max_depth: int = 3,
                 consumed: set[str] | None = None,
                 ) -> VerifyResult:
    """Walk a delegation chain root-first (Sections 8.6-8.7, 9.3).

    ``elements`` items are either compact JWS strings (root) or dicts
    ``{"compact": jws, "orchestratorSignature": jws}`` (sub-receipts),
    exactly the interop corpus shape.
    """
    at_ms = _now_ms() if at is None else parse_time(at)
    try:
        items = [_element_parts(e) for e in elements]
    except ValueError as exc:
        return _fail("CHAIN_MALFORMED", detail=str(exc))
    if not items:
        return _fail("EMPTY_CHAIN")
    depth = len(items) - 1
    if depth >= max_depth:
        return _fail("CHAIN_DEPTH_EXCEEDED",
                     detail="depth %d >= max %d" % (depth, max_depth))
    bodies: list[dict[str, Any]] = []
    rids: list[str] = []
    for compact, _ in items:
        res = verify_receipt(compact, at_ms, registry=registry,
                             consumed=consumed)
        if not res.valid:
            res.errors = ["CHAIN_HOP_%d_%s" % (len(bodies), res.errors[0])]
            return res
        bodies.append(res.body or {})
        rids.append(res.receipt_id or "")
    orch_ok = True
    for i in range(1, len(items)):
        parent_body, child_body = bodies[i - 1], bodies[i]
        parent_rid, child_rid = rids[i - 1], rids[i]
        child = child_body
        expect_parent = child.get("parentReceiptId")
        if expect_parent != parent_rid:
            return _fail("CHAIN_HOP_%d_PARENT_RECEIPT_MISMATCH" % i,
                         child, child_rid)
        _, orch_jws = items[i]
        if orch_jws is None:
            return _fail("CHAIN_HOP_%d_ORCHESTRATOR_SIG_MISSING" % i,
                         child, child_rid)
        binding = "orchestrator-delegation:%s:%s" % (parent_rid, child_rid)
        problem = _verify_orchestrator(orch_jws, binding, child)
        if problem is not None:
            return _fail("CHAIN_HOP_%d_ORCHESTRATOR_SIG_INVALID" % i,
                         child, child_rid, detail=problem)
        if not check_window_contained(parent_body, child_body):
            return _fail("CHAIN_HOP_%d_WINDOW_NOT_CONTAINED" % i,
                         child, child_rid)
        violation = check_attenuation(parent_body, child_body)
        if violation is not None:
            return _fail("CHAIN_HOP_%d_SCOPE_ATTENUATION_VIOLATED" % i,
                         child, child_rid, detail=violation)
        # Ancestor revocation walk (Section 9.3 / offline 9.4).
        if child.get("revocationRequired") is True and registry is None:
            return _fail("ANCESTOR_REVOCATION_CHECK_REQUIRED", child,
                         child_rid)
        if registry is not None:
            rec = registry.check(parent_rid)
            if rec.get("revoked"):
                return _fail("ANCESTOR_REVOKED", child, child_rid)
        del parent_body
    warnings = ["CHAIN_OK"]
    if orch_ok and len(items) > 1:
        warnings.append("ORCHESTRATOR_SIG_OK")
    leaf = VerifyResult(True, [], warnings, bodies[-1], rids[-1])
    return leaf


# -------------------------------------------------------------- actions


def _pattern_match(pattern: str, value: str) -> bool:
    if pattern == "*":
        return True
    if "*" not in pattern:
        return pattern == value
    rx = "^" + ".*".join(re.escape(part)
                         for part in pattern.split("*")) + "$"
    return re.match(rx, value) is not None


def _entry_matches(entry: dict[str, Any], action: dict[str, Any]) -> bool:
    return (_pattern_match(str(entry.get("operation")),
                           str(action.get("operation", "")))
            and _pattern_match(str(entry.get("resource")),
                               str(action.get("resource", ""))))


def _constraints_ok(entry: dict[str, Any], action: dict[str, Any]) -> bool:
    constraints = entry.get("constraints")
    if not isinstance(constraints, dict):
        return True
    params = action.get("params")
    params = params if isinstance(params, dict) else {}
    for name, limit in constraints.items():
        if name not in params:
            continue  # absent parameters are skipped
        value = params[name]
        if isinstance(limit, (int, float)) and not isinstance(limit, bool):
            if not isinstance(value, (int, float)) \
                    or isinstance(value, bool) or value > limit:
                return False
        elif isinstance(limit, str):
            if not isinstance(value, str) \
                    or not _pattern_match(limit, value):
                return False
        else:
            return False
    return True


def action_allowed(schema: Any, action: dict[str, Any]
                   ) -> tuple[bool, str | None]:
    """Section 8.1: denied first, then allowed, default deny."""
    if schema is None:
        return False, "SCOPE_ACTION_NO_SCHEMA"
    if not isinstance(schema, dict):
        return False, "FIELD_INVALID:scopeSchema"
    for entry in schema.get("deniedActions", []) or []:
        if _entry_matches(entry, action):
            return False, "SCOPE_ACTION_DENIED"
    for entry in schema.get("allowedActions", []) or []:
        if _entry_matches(entry, action) and _constraints_ok(entry, action):
            return True, None
    return False, "SCOPE_ACTION_DENIED"


def check_action(body: dict[str, Any], action: dict[str, Any]) -> bool:
    allowed, _ = action_allowed(body.get("scopeSchema"), action)
    return allowed


# ------------------------------------------------------------ revocation


def issue_revocation_record(receipt_hash: str, reason: str, key: Any,
                            alg: str = "ES256",
                            revoked_at: int | None = None) -> dict[str, Any]:
    """Section 9.2: {receiptHash, reason, revokedAt, revokedBy, signature}."""
    if not _HEX64.match(receipt_hash):
        raise ValueError("receiptHash must be hex64")
    record = {
        "receiptHash": receipt_hash,
        "reason": str(reason),
        "revokedAt": int(revoked_at if revoked_at is not None
                         else _now_ms()),
        "revokedBy": _jwk_for(key, alg),
    }
    payload = jcs.canonicalize(record)
    record["signature"] = jws.sign_compact(payload, {"alg": alg}, key)
    return record


def verify_revocation_record(record: dict[str, Any]) -> bool:
    """Records MUST be signature-verified before import (Section 9.2)."""
    if not isinstance(record, dict):
        return False
    sig = record.get("signature")
    if not isinstance(sig, str):
        return False
    body = {k: v for k, v in record.items() if k != "signature"}
    expected = jcs.canonicalize(body)
    revoked_by = body.get("revokedBy")
    if not isinstance(revoked_by, dict):
        return False
    try:
        if revoked_by.get("kty") == "EC":
            pub: Any = p256.jwk_to_point(revoked_by)
        else:
            return False
        _, payload = jws.verify_compact(sig, allowed=ALGS_KNOWN, pub=pub)
    except (ValueError, KeyError, AttributeError, TypeError):
        return False
    return payload == expected


class RevocationRegistry:
    """Append-only mapping receiptId -> signed record (Section 9.1)."""

    def __init__(self) -> None:
        self._records: dict[str, dict[str, Any]] = {}

    def add(self, record: dict[str, Any]) -> bool:
        """Import a signed record; invalid signatures are skipped."""
        if not verify_revocation_record(record):
            return False
        rid = record.get("receiptHash")
        if not isinstance(rid, str) or rid in self._records:
            return False  # revocation is permanent; no overwrites
        self._records[rid] = record
        return True

    def revoke(self, receipt_hash: str, reason: str, key: Any,
               alg: str = "ES256") -> dict[str, Any]:
        record = issue_revocation_record(receipt_hash, reason, key,
                                         alg=alg)
        if not self.add(record):
            raise ValueError("cannot revoke: record rejected or already "
                             "revoked")
        return record

    def check(self, receipt_hash: str) -> dict[str, Any]:
        record = self._records.get(receipt_hash)
        if record is None:
            return {"revoked": False}
        return {"revoked": True, "reason": record.get("reason"),
                "revokedAt": record.get("revokedAt")}


# ---------------------------------------------------------- corpus runner


def run_corpus(corpus: dict[str, Any],
               registry: "RevocationRegistry | None" = None
               ) -> list[dict[str, Any]]:
    """Run the published interop corpus; ``expected.valid`` is normative
    (interop README), errors/warnings are informative diagnostics."""
    rows: list[dict[str, Any]] = []
    for case in corpus.get("cases", []):
        options = case.get("options") or {}
        at = options.get("at")
        if case.get("mode") == "chain":
            result = verify_chain(case.get("chain") or [], at,
                                  registry=registry)
        else:
            result = verify_receipt(case.get("input", ""), at,
                                    registry=registry)
        expected = case.get("expected") or {}
        rows.append({
            "id": case.get("id"),
            "expected_valid": bool(expected.get("valid")),
            "valid": result.valid,
            "pass": result.valid == bool(expected.get("valid")),
            "expected_errors": list(expected.get("errors") or []),
            "errors": list(result.errors),
            "expected_warnings": list(expected.get("warnings") or []),
            "warnings": list(result.warnings),
            "detail": result.detail,
        })
    return rows

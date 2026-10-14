"""aledger receipt — draft -13 Agent Delegation Receipt CLI.

Command surface (v0.3.0, ES256/JCS/JWS per draft -13):

  keygen       generate an ES256 (default) or Ed25519 signing key
  issue        issue a root receipt (Section 6.6 computation order)
  sub-issue    issue a sub-receipt with Section 8.7 sequence (attenuation
               and window containment enforced BEFORE signing)
  verify       run the pre-execution gate over one receipt
  chain        verify a delegation chain root-first (Sections 8.6-8.7)
  revoke       mint a signed revocation record (Section 9.2)
  record-verify  verify a revocation record's signature
  show         decode a JWS, or look up an entry in a receipt log
  corpus       run the published7-case interop corpus
               (expected.valid is the normative comparison)

Keys are stored as JSON files holding the raw scalar/seed in hex — the
operator's own disk is the physical layer; never commit key files.
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
import time
from pathlib import Path
from typing import Any

from . import drp, jws
from .drp import (
    RevocationRegistry, instructions_hash, issue, issue_sub_receipt,
    iso, receipt_id, run_corpus, verify_chain, verify_receipt,
)

__all__ = ["register"]


# ------------------------------------------------------------------ keys

def _load_key(path: str) -> tuple[str, Any]:
    raw = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    alg = raw.get("alg", "ES256")
    secret = raw.get("private")
    if not isinstance(secret, str):
        raise ValueError("key file missing 'private'")
    value = bytes.fromhex(secret)
    if alg == "ES256":
        d = int.from_bytes(value, "big")
        if not (1 <= d < drp.p256.P256_N):
            raise ValueError("private scalar out of range")
        return alg, d
    if alg == "EdDSA":
        if len(value) != 32:
            raise ValueError("Ed25519 seed must be32 bytes")
        return alg, value
    raise ValueError("unsupported alg %r" % alg)


def _public_jwk(alg: str, key: Any) -> dict[str, Any]:
    return drp._jwk_for(key, alg)


def cmd_keygen(args: argparse.Namespace) -> int:
    alg = "ES256" if args.alg.lower() in ("es256", "ecdsa", "p-256") \
        else "EdDSA"
    if alg == "ES256":
        d = 0
        while not (1 <= d < drp.p256.P256_N):
            d = int.from_bytes(secrets.token_bytes(32), "big")
        secret, key = d.to_bytes(32, "big"), d
    else:
        from . import ed25519
        seed = ed25519.generate_seed()
        secret, key = seed, seed
    doc = {"alg": alg, "private": secret.hex(),
           "public": _public_jwk(alg, key)}
    out = Path(args.out)
    out.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({"created": str(out), "alg": alg,
                      "public": doc["public"]}, indent=1))
    print("WARNING: plaintext key file — keep it out of any repository "
          "and store an offline backup.", file=sys.stderr)
    return 0


# ----------------------------------------------------------------- issue

def _build_body(args: argparse.Namespace, alg: str,
                key: Any) -> dict[str, Any]:
    now_ms = int(time.time() * 1000)
    if not args.scope or not args.boundaries or not args.instructions:
        raise ValueError("--scope, --boundaries and --instructions are "
                         "required")
    if not args.start or not args.end:
        raise ValueError("--start and --end (ISO-8601) are required")
    body: dict[str, Any] = {
        "delegationId": args.delegation_id
        or "auth-%d-%s" % (now_ms, secrets.token_hex(2)[:5]),
        "issuedAt": iso(now_ms),
        "scope": args.scope,
        "boundaries": args.boundaries,
        "timeWindow": {"start": args.start, "end": args.end},
        "operatorInstructions": args.instructions,
        "instructionsHash": instructions_hash(args.instructions),
        "signerPublicKey": _public_jwk(alg, key),
    }
    if args.agent_id:
        body["agentId"] = args.agent_id
    if args.metadata:
        body["metadata"] = json.loads(Path(args.metadata).read_text(
            encoding="utf-8-sig"))
    if args.schema:
        body["scopeSchema"] = json.loads(Path(args.schema).read_text(
            encoding="utf-8-sig"))
    if args.trusted_sources:
        body["trustedSources"] = [s for s in
                                  args.trusted_sources.split(",") if s]
    if args.revocation_required:
        body["revocationRequired"] = True
    if args.one_time_use:
        body["oneTimeUse"] = True
    if args.nonce:
        body["nonce"] = args.nonce
    return body


def _append_log(path: str | None, entry: dict[str, Any]) -> None:
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def cmd_issue(args: argparse.Namespace) -> int:
    alg, key = _load_key(args.key)
    body = _build_body(args, alg, key)
    jws_text, rid = issue(body, key, alg=alg)
    result = {"receiptId": rid, "jws": jws_text}
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=1) + "\n",
                                  encoding="utf-8")
        print(json.dumps({"receiptId": rid, "out": args.out}))
    else:
        print(json.dumps(result, indent=1))
    _append_log(args.log, {"kind": "receipt-issue", "receiptId": rid,
                           "delegationId": body["delegationId"],
                           "jws": jws_text, "at": int(time.time() * 1000)})
    return 0


def cmd_sub_issue(args: argparse.Namespace) -> int:
    alg, key = _load_key(args.key)
    body = _build_body(args, alg, key)
    parent_jws = _read_jws(args.parent)
    try:
        child, rid, orch = issue_sub_receipt(body, key, parent_jws,
                                             alg=alg)
    except ValueError as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 1
    result = {"receiptId": rid, "jws": child,
              "orchestratorSignature": orch}
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=1) + "\n",
                                  encoding="utf-8")
        print(json.dumps({"receiptId": rid, "out": args.out}))
    else:
        print(json.dumps(result, indent=1))
    _append_log(args.log, {"kind": "receipt-issue", "receiptId": rid,
                           "delegationId": body["delegationId"],
                           "jws": child, "parent": args.parent,
                           "at": int(time.time() * 1000)})
    return 0


def _read_jws(value: str) -> str:
    if value == "-":
        return sys.stdin.read().strip()
    if value.startswith("@"):
        text = Path(value[1:]).read_text(encoding="utf-8-sig").strip()
        if text.startswith("{"):  # {"jws": ...} envelope
            return json.loads(text)["jws"]
        return text
    if value.startswith("{"):
        return json.loads(value)["jws"]
    return value


def _load_registry(path: str | None) -> RevocationRegistry | None:
    if not path:
        return None
    registry = RevocationRegistry()
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line:
            continue
        if not registry.add(json.loads(line)):
            print("warning: skipped invalid revocation record",
                  file=sys.stderr)
    return registry


def _action_from(value: str | None,
                 params: str | None) -> dict[str, Any] | None:
    if not value:
        return None
    if "::" in value:
        op, resource = value.split("::", 1)
    elif "," in value:
        op, resource = value.split(",", 1)
    else:
        raise ValueError("action must be 'operation::resource'")
    action: dict[str, Any] = {"operation": op, "resource": resource}
    if params:
        action["params"] = json.loads(params)
    return action


def cmd_verify(args: argparse.Namespace) -> int:
    jws_text = _read_jws(args.jws)
    registry = _load_registry(args.registry)
    action = _action_from(args.action, args.params)
    claimed = args.instructions
    if claimed and claimed.startswith("@"):
        claimed = Path(claimed[1:]).read_text(encoding="utf-8-sig")
    result = verify_receipt(
        jws_text, args.at, registry=registry, action=action,
        claimed_instructions=claimed,
        require_instructions=args.require_instructions,
        instruction_source=args.source)
    print(json.dumps(result.as_dict(), indent=1))
    return 0 if result.valid else 1


def cmd_chain(args: argparse.Namespace) -> int:
    data = json.loads(Path(args.file).read_text(encoding="utf-8-sig"))
    elements = data["chain"] if isinstance(data, dict) else data
    registry = _load_registry(args.registry)
    result = verify_chain(elements, args.at, registry=registry,
                          max_depth=args.max_depth)
    print(json.dumps(result.as_dict(), indent=1))
    return 0 if result.valid else 1


def cmd_revoke(args: argparse.Namespace) -> int:
    alg, key = _load_key(args.key)
    record = drp.issue_revocation_record(args.id, args.reason, key,
                                         alg=alg)
    text = json.dumps(record, indent=1) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(json.dumps({"receiptHash": args.id, "out": args.out}))
    else:
        print(text, end="")
    _append_log(args.log, {"kind": "receipt-revoke",
                           "receiptId": args.id,
                           "reason": args.reason,
                           "at": record["revokedAt"]})
    return 0


def cmd_record_verify(args: argparse.Namespace) -> int:
    record = json.loads(Path(args.file).read_text(encoding="utf-8-sig"))
    ok = drp.verify_revocation_record(record)
    print(json.dumps({"valid": ok}))
    return 0 if ok else 1


def cmd_show(args: argparse.Namespace) -> int:
    if args.jws:
        jws_text = _read_jws(args.jws)
        header, payload = jws.verify_compact(jws_text,
                                             allowed=drp.ALGS_KNOWN)
        body = json.loads(payload)
        print(json.dumps({"receiptId": receipt_id(jws_text),
                          "header": header, "body": body}, indent=1))
        return 0
    if args.id:
        for line in Path(args.log).read_text(encoding="utf-8-sig") \
                .splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            if entry.get("receiptId") == args.id:
                print(json.dumps(entry, indent=1))
                return 0
        print("not found in %s" % args.log, file=sys.stderr)
        return 1
    raise ValueError("provide --jws or --id")


def cmd_corpus(args: argparse.Namespace) -> int:
    if args.file:
        corpus = json.loads(Path(args.file).read_text(encoding="utf-8-sig"))
    else:
        from importlib import resources
        corpus = json.loads(
            resources.files("agentledger")
            .joinpath("data/interop-corpus.json").read_text(
                encoding="utf-8-sig"))
    rows = run_corpus(corpus)
    for row in rows:
        flag = "PASS" if row["pass"] else "FAIL"
        print("[%s] %-34s valid exp=%-5s got=%-5s errors=%s"
              % (flag, row["id"], row["expected_valid"], row["valid"],
                 row["errors"]))
    passed = sum(1 for r in rows if r["pass"])
    print("conformance: %d/%d (expected.valid is normative)" %
          (passed, len(rows)))
    if args.json:
        print(json.dumps(rows, indent=1))
    return 0 if passed == len(rows) else 1


# --------------------------------------------------------------- parser

def register(sub: Any) -> None:
    ap = sub.add_parser("receipt", help="IETF DRP delegation receipts "
                        "(draft -13, ES256/JCS/JWS)")
    subs = ap.add_subparsers(dest="receipt_cmd", required=True)

    p = subs.add_parser("keygen", help="generate a signing key file")
    p.add_argument("--alg", default="ES256",
                   help="ES256 (default) or Ed25519")
    p.add_argument("--out", required=True, help="key file to create")
    p.set_defaults(func=cmd_keygen)

    def body_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--key", required=True, help="signer key file")
        p.add_argument("--scope", help="human-readable scope text")
        p.add_argument("--boundaries", help="hard boundary text")
        p.add_argument("--instructions", required=True,
                       help="operator instructions (plaintext)")
        p.add_argument("--start", help="window start (ISO-8601)")
        p.add_argument("--end", help="window end (ISO-8601)")
        p.add_argument("--delegation-id", help="default: auth-<ms>-<hex>")
        p.add_argument("--agent-id")
        p.add_argument("--metadata", help="JSON file")
        p.add_argument("--schema", help="scopeSchema JSON file")
        p.add_argument("--trusted-sources", help="comma-separated")
        p.add_argument("--revocation-required", action="store_true")
        p.add_argument("--one-time-use", action="store_true")
        p.add_argument("--nonce")
        p.add_argument("--out", help="write {receiptId, jws} here")
        p.add_argument("--log", help="append to this receipt log")

    p = subs.add_parser("issue", help="issue a root receipt")
    body_args(p)
    p.set_defaults(func=cmd_issue)

    p = subs.add_parser("sub-issue", help="issue a sub-receipt "
                        "(Section 8.7; attenuation enforced)")
    body_args(p)
    p.add_argument("--parent", required=True, help="parent receipt JWS "
                   "(string, @file, or @out.json)")
    p.set_defaults(func=cmd_sub_issue)

    p = subs.add_parser("verify", help="verify one receipt (gate checks)")
    p.add_argument("--jws", required=True,
                   help="JWS string, @file, '{\"jws\":...}' or '-'")
    p.add_argument("--at", help="verification time (ISO-8601); default now")
    p.add_argument("--action", help="operation::resource to test")
    p.add_argument("--params", help="action params JSON")
    p.add_argument("--instructions", help="claimed instructions "
                   "(or @file) for drift check")
    p.add_argument("--require-instructions", action="store_true")
    p.add_argument("--source", help="instruction source provenance check")
    p.add_argument("--registry", help="revocation records JSONL")
    p.set_defaults(func=cmd_verify)

    p = subs.add_parser("chain", help="verify a delegation chain")
    p.add_argument("--file", required=True,
                   help="JSON array (or {chain: [...]}) root-first")
    p.add_argument("--at", help="verification time (ISO-8601)")
    p.add_argument("--registry", help="revocation records JSONL")
    p.add_argument("--max-depth", type=int, default=3)
    p.set_defaults(func=cmd_chain)

    p = subs.add_parser("revoke", help="mint a signed revocation record")
    p.add_argument("--key", required=True, help="revoker key file")
    p.add_argument("--id", required=True, help="receiptId to revoke")
    p.add_argument("--reason", required=True)
    p.add_argument("--out", help="write record JSON here")
    p.add_argument("--log", help="append to this receipt log")
    p.set_defaults(func=cmd_revoke)

    p = subs.add_parser("record-verify",
                        help="verify a revocation record signature")
    p.add_argument("--file", required=True)
    p.set_defaults(func=cmd_record_verify)

    p = subs.add_parser("show", help="decode a receipt JWS or look up "
                        "a receipt log entry")
    p.add_argument("--jws", help="JWS string, @file or '{\"jws\":...}'")
    p.add_argument("--id", help="receiptId to look up in the log")
    p.add_argument("--log", default="receipts.jsonl")
    p.set_defaults(func=cmd_show)

    p = subs.add_parser("corpus", help="run the published interop corpus")
    p.add_argument("--file", help="corpus.json path (default: bundled)")
    p.add_argument("--json", action="store_true",
                   help="also print machine-readable rows")
    p.set_defaults(func=cmd_corpus)

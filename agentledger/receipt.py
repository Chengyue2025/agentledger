"""委托收据（Delegation Receipt）—— 对齐 IETF DRP 草案的离线实现。

对齐目标：draft-nelson-agent-delegation-receipts（截至 2026-10-13 最新 -12）。
该草案实施状态中已知的唯一实现是作者自家的 authproof-sdk / authproof-cloud
（prototype 级、托管服务形态）。本模块是它的**第一个独立实现**，差异化定位：

  - 零依赖、纯标准库（含 Ed25519 签名，见 ed25519.py）；
  - 离线优先：空气间隙环境可签发/验证，不依赖任何云服务；
  - 账本原生：收据/撤销/动作记录锚定在哈希链式账本
    （receipts.jsonl，草案 §5 的 append-only log 本地形态）；
  - 与 AI BOM 扫描同仓：授权时证据（收据）与事后证据（扫描账本）
    在同一工具、同一信任根下。

实现的验证检查（编号对齐草案 §6.4）：
  1  撤销           → RECEIPT_REVOKED / REVOCATION_CHECK_REQUIRED
  2  签名           → INVALID_SIGNATURE
  3  时间窗         → RECEIPT_EXPIRED / RECEIPT_NOT_YET_VALID
  4  范围(默认拒绝) → ACTION_NOT_IN_SCOPE / ACTION_EXPLICITLY_DENIED
  5  边界           → ACTION_EXPLICITLY_DENIED
  7  指令哈希       → OPERATOR_INSTRUCTIONS_MISMATCH
  11 工具模式哈希   → TOOL_SCHEMA_DRIFT
  13 指令来源       → UNTRUSTED_INSTRUCTION_SOURCE
  14 父收据包含     → PARENT_SCOPE_VIOLATION / SCOPE_NOT_STRICT_SUBSET

有意不实现（属于运行时门控范畴，不属于离线 CLI 边界，见
docs/DRP-ALIGNMENT.md）：6 执行图哈希 / 8 TEE 模型状态 / 9 会话风险 /
10 重放 / 12 工具输出哈希 / 15 权威状态漂移。
"""

from __future__ import annotations

import base64
import json
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from . import __version__, ed25519
from .ledger import LEDGER_DIRNAME, canonical, sha256_hex

SCHEMA_VERSION = "1.0"
RECEIPTS_FILENAME = "receipts.jsonl"
SKEW_TOLERANCE_SECONDS = 300          # 草案 §5.3 推荐的最大时钟容差
MAX_CHAIN_DEPTH = 3                   # 草案 §10.3 maxChainDepth 保守取 3
GENESIS = "0" * 64

# 草案 §4.1 边界字段的保守默认。注意：若收据本身允许了某类操作，
# 再默认拒绝该类操作会自相矛盾 —— issue() 会智能排除。
_DENY_TEMPLATES = ("write", "delete", "execute")


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64url(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _nfc(obj: Any) -> Any:
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, list):
        return [_nfc(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _nfc(v) for k, v in obj.items()}
    return obj


def canonical_bytes(obj: Any) -> bytes:
    """草案 §4.2 规范序列化：键排序、无空白、NFC、UTF-8。"""
    return json.dumps(
        _nfc(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_iso(text: str) -> datetime:
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def sha256_prefixed(text: str) -> str:
    return "sha256:" + sha256_hex(unicodedata.normalize("NFC", text))


# --------------------------------------------------------------------------
# 密钥
# --------------------------------------------------------------------------
@dataclass
class KeyPair:
    seed: bytes

    @property
    def public(self) -> bytes:
        return ed25519.public_key(self.seed)

    @property
    def public_jwk(self) -> dict[str, str]:
        return {"kty": "OKP", "crv": "Ed25519", "x": b64url(self.public)}

    def sign(self, msg: bytes) -> bytes:
        return ed25519.sign(self.seed, msg)

    # -- 文件存取（私钥 = 32 字节种子的 hex；公钥 = JWK）------------------
    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.seed.hex() + "\n", encoding="ascii")
        try:
            import os

            os.chmod(p, 0o600)
        except OSError:
            pass  # Windows 无 POSIX 权限位
        jwk_path = p.with_suffix(p.suffix + ".pub.jwk")
        jwk_path.write_text(
            json.dumps(self.public_jwk, indent=2) + "\n", encoding="utf-8"
        )
        return p

    @classmethod
    def load(cls, path: str | Path) -> "KeyPair":
        seed = bytes.fromhex(Path(path).read_text(encoding="ascii").strip())
        return cls(seed=seed)

    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(seed=ed25519.generate_seed())


def jwk_public_key(jwk: dict[str, Any]) -> bytes | None:
    """从 JWK 取出 32 字节公钥；不支持的格式返回 None。"""
    try:
        if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
            key = unb64url(jwk["x"])
            return key if len(key) == 32 else None
    except (KeyError, ValueError):
        return None
    return None


# --------------------------------------------------------------------------
# 动作描述
# --------------------------------------------------------------------------
def action(op_resource: str | dict[str, str]) -> dict[str, str]:
    """'read:foo/bar' 或 {'operation':..,'resource':..} → 统一形态。"""
    if isinstance(op_resource, dict):
        op = str(op_resource.get("operation", "")).strip().lower()
        res = str(op_resource.get("resource", "")).strip()
    else:
        op, _, res = str(op_resource).partition(":")
        op = op.strip().lower()
        res = res.strip()
    if not op or not res:
        raise ValueError(f"动作格式应为 'operation:resource'，收到 {op_resource!r}")
    return {"operation": op, "resource": res}


def _resource_covered(outer: str, inner: str) -> bool:
    """outer 资源模式是否覆盖 inner（支持 * 与 /* 通配）。"""
    if outer == "*" or outer == inner:
        return True
    if outer.endswith("/*"):
        prefix = outer[:-1]  # 保留斜杠
        if inner.startswith(prefix):
            return True
        if inner.endswith("/*") and inner[:-2].startswith(outer[:-2]):
            return True
        return False
    if outer.endswith("*"):
        return inner.startswith(outer[:-1])
    return False


def _descriptor_covered(outer: dict[str, str], inner: dict[str, str]) -> bool:
    return (
        outer["operation"] == inner["operation"]
        and _resource_covered(outer["resource"], inner["resource"])
    )


def _matches_any(a: dict[str, str], descs: Iterable[dict[str, str]]) -> bool:
    return any(_descriptor_covered(d, a) for d in descs)


def _boundary_hit(a: dict[str, str], boundaries: Iterable[str]) -> bool:
    """边界串形如 'deny:write:prod/*'，命中即硬禁止。"""
    for raw in boundaries:
        parts = str(raw).split(":")
        if len(parts) < 3 or parts[0].strip().lower() != "deny":
            continue
        op = parts[1].strip().lower()
        res = ":".join(parts[2:]).strip()
        if op == a["operation"] and _resource_covered(res, a["resource"]):
            return True
    return False


# --------------------------------------------------------------------------
# 签发
# --------------------------------------------------------------------------
def _default_boundaries(allowed: list[dict[str, str]]) -> list[str]:
    """保守默认边界：仅拒绝收据未显式允许的操作类别。"""
    allowed_ops = {d["operation"] for d in allowed}
    return [f"deny:{op}:*" for op in _DENY_TEMPLATES if op not in allowed_ops]


def issue(
    *,
    allowed: Iterable[str | dict[str, str]],
    key: KeyPair,
    denied: Iterable[str | dict[str, str]] = (),
    boundaries: Iterable[str] | None = None,
    not_before: datetime | None = None,
    minutes: int = 60,
    operator_instructions: str = "",
    metadata: dict[str, Any] | None = None,
    tool_schema: Any = None,
    trusted_sources: Iterable[str] | None = None,
    revocation_required: bool = False,
    parent: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """签发一份委托收据（草案 §4 结构 + §4.3 顺序）。

    parent 非空时签发子收据：签名密钥即编排者密钥，附编排者绑定
    签名（草案 §10.1），范围须为父收据的真子集（§10.2 收窄规则）。
    """
    allowed_list = [action(a) for a in allowed]
    denied_list = [action(d) for d in denied]
    boundaries_list = (
        list(boundaries) if boundaries is not None else _default_boundaries(allowed_list)
    )
    if not boundaries_list:
        boundaries_list = ["deny:delete:*"]  # 草案：边界数组不得为空

    nb = not_before or utcnow()
    na = nb + timedelta(minutes=minutes)

    body: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "scope": {"allowedActions": allowed_list, "deniedActions": denied_list},
        "boundaries": boundaries_list,
        "timeWindow": {"notBefore": iso(nb), "notAfter": iso(na)},
        "operatorInstructions": operator_instructions,
        "operatorInstructionsHash": sha256_prefixed(operator_instructions),
        "publicKey": key.public_jwk,
        "metadata": {
            # 诚实标注：离线签发没有 RFC3161 TSA 时间戳（草案 §5.3 的
            # UNVERIFIED_TIMESTAMP 语义），验证方应按本地时钟 + 容差处理。
            "x-time-source": "local-unverified",
            "x-implementation": f"agentledger/{__version__} drp-offline-profile",
        },
    }
    if metadata:
        body["metadata"].update(_nfc(metadata))
    if tool_schema is not None:
        body["toolSchemaHash"] = "sha256:" + sha256_hex(canonical_bytes(tool_schema))
    if trusted_sources is not None:
        body["trustedSources"] = [str(s) for s in trusted_sources]
    if revocation_required:
        body["revocationRequired"] = True

    if parent is not None:
        parent_id = parent.get("receiptId", "")
        if not parent_id:
            raise ValueError("父收据缺少 receiptId")
        body["parentReceiptId"] = parent_id

    receipt_id = "rec_" + sha256_hex(canonical_bytes(body))
    body["receiptId"] = receipt_id
    # 规范字节只算一次：签名覆盖「含 receiptId、不含 canonicalPayload/signature」的体
    signed = canonical_bytes(body)
    body["canonicalPayload"] = b64url(signed)
    body["signature"] = b64url(key.sign(signed))

    if parent is not None:
        binding = f"orchestrator-delegation:{parent_id}:{receipt_id}".encode("utf-8")
        body["orchestratorSignature"] = b64url(key.sign(binding))
    return body


# --------------------------------------------------------------------------
# 撤销（草案 §10.6：撤销记录 = receiptId + 时间 + 撤销方公钥 + 签名）
# --------------------------------------------------------------------------
def revocation_record(receipt_id: str, key: KeyPair,
                      at: datetime | None = None) -> dict[str, str]:
    ts = iso(at or utcnow())
    msg = f"revocation:{receipt_id}:{ts}".encode("utf-8")
    return {
        "kind": "receipt-revocation",
        "receiptId": receipt_id,
        "revokedAt": ts,
        "publicKey": key.public_jwk,
        "signature": b64url(key.sign(msg)),
    }


def verify_revocation(record: dict[str, Any]) -> bool:
    pub = jwk_public_key(record.get("publicKey") or {})
    if pub is None:
        return False
    msg = f"revocation:{record['receiptId']}:{record['revokedAt']}".encode("utf-8")
    try:
        return ed25519.verify(pub, msg, unb64url(record["signature"]))
    except (KeyError, ValueError):
        return False


# --------------------------------------------------------------------------
# 收据账本 —— 草案 §5 append-only log 的本地哈希链形态
# --------------------------------------------------------------------------
@dataclass
class LogEntry:
    seq: int
    ts: str
    kind: str
    body: dict[str, Any]
    prev: str
    hash: str

    def payload(self) -> dict[str, Any]:
        return {"seq": self.seq, "ts": self.ts, "kind": self.kind,
                "body": self.body, "prev": self.prev}

    def to_dict(self) -> dict[str, Any]:
        d = self.payload()
        d["hash"] = self.hash
        return d

    @staticmethod
    def compute_hash(payload: dict[str, Any]) -> str:
        return sha256_hex(canonical(payload))

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "LogEntry":
        return LogEntry(seq=d["seq"], ts=d["ts"], kind=d["kind"],
                        body=d["body"], prev=d["prev"], hash=d["hash"])


class ReceiptLog:
    """追加式收据账本：<root>/.agentledger/receipts.jsonl"""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    @classmethod
    def for_root(cls, root: str | Path) -> "ReceiptLog":
        return cls(Path(root) / LEDGER_DIRNAME / RECEIPTS_FILENAME)

    # ------------------------------------------------------------------
    def entries(self) -> list[LogEntry]:
        if not self.path.exists():
            return []
        out: list[LogEntry] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(LogEntry.from_dict(json.loads(line)))
            except (json.JSONDecodeError, KeyError, TypeError):
                out.append(LogEntry(seq=-1, ts="", kind="<unparsable>", body={},
                                    prev="", hash=""))
        return out

    def verify(self) -> tuple[bool, list[str]]:
        problems: list[str] = []
        expected_prev = GENESIS
        for i, e in enumerate(self.entries()):
            if e.kind == "<unparsable>":
                problems.append(f"[{i}] 收据账本行无法解析")
                continue
            if e.prev != expected_prev:
                problems.append(f"[{i}] 收据账本链断裂")
            if LogEntry.compute_hash(e.payload()) != e.hash:
                problems.append(f"[{i}] 收据账本条目哈希不匹配")
            expected_prev = e.hash
        return not problems, problems

    def _append(self, kind: str, body: dict[str, Any]) -> LogEntry:
        ents = self.entries()
        prev = ents[-1].hash if ents else GENESIS
        seq = (ents[-1].seq + 1) if ents and ents[-1].seq >= 0 else 0
        entry = LogEntry(
            seq=seq, ts=iso(utcnow()), kind=kind, body=body, prev=prev,
            hash="",  # 下面按 payload 计算
        )
        entry.hash = LogEntry.compute_hash(entry.payload())
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(canonical(entry.to_dict()) + "\n")
        return entry

    def append_receipt(self, receipt: dict[str, Any]) -> LogEntry:
        return self._append("receipt-issue", receipt)

    def append_revocation(self, record: dict[str, Any]) -> LogEntry:
        return self._append("receipt-revocation", record)

    def append_action(self, receipt_id: str, a: dict[str, str],
                      decision: str) -> LogEntry:
        """动作决策留痕（草案 §5.4：DENY 也要记）。"""
        return self._append("action-decision", {
            "receiptId": receipt_id,
            "operation": a["operation"], "resource": a["resource"],
            "decision": decision,
        })

    # ------------------------------------------------------------------
    def revoked_ids(self) -> set[str]:
        out: set[str] = set()
        for e in self.entries():
            if e.kind == "receipt-revocation" and verify_revocation(e.body):
                out.add(e.body.get("receiptId", ""))
        return out

    def find_receipt(self, receipt_id: str) -> dict[str, Any] | None:
        for e in self.entries():
            if e.kind == "receipt-issue" and e.body.get("receiptId") == receipt_id:
                return e.body
        return None

    def chain_depth(self, receipt: dict[str, Any]) -> int:
        """沿 parentReceiptId 上溯计委派跳数（根收据 = 0 跳）。

        对齐草案 §10.3 maxChainDepth：限制的是"根以下的委派层数"，
        根收据本身是锚点不计数。
        """
        depth = 0
        seen = {receipt.get("receiptId")}
        cur = receipt
        while cur.get("parentReceiptId"):
            parent = self.find_receipt(cur["parentReceiptId"])
            if parent is None or parent.get("receiptId") in seen:
                break
            seen.add(parent["receiptId"])
            depth += 1
            cur = parent
        return depth


# --------------------------------------------------------------------------
# 验证（草案 §6.1 顺序；返回草案 §6.3 的结构化结果 + 安全回退动作）
# --------------------------------------------------------------------------
def verify(
    receipt: dict[str, Any],
    *,
    a: str | dict[str, str] | None = None,
    operator_instructions: str | None = None,
    tool_schema: Any = None,
    instruction_source: str | None = None,
    log: ReceiptLog | None = None,
    now: datetime | None = None,
    skew: int = SKEW_TOLERANCE_SECONDS,
) -> dict[str, Any]:
    """执行离线可验证子集。返回：

    {"decision": "PERMIT"|"DENY", "reason": <码或 None>,
     "safeAlternative": "NO_OP_WITH_LOG"（DENY 时）, ...}
    """
    def deny(reason: str) -> dict[str, Any]:
        return {"decision": "DENY", "reason": reason,
                "safeAlternative": "NO_OP_WITH_LOG"}

    rid = receipt.get("receiptId", "")

    # ---- 前置：revocationRequired + 无账本 → 草案 §6.6 硬拒 ----
    if receipt.get("revocationRequired") and log is None:
        return deny("REVOCATION_CHECK_REQUIRED")

    # ---- 1 撤销 ----
    if log is not None:
        ok, problems = log.verify()
        if not ok:
            return deny("LEDGER_INTEGRITY_FAILURE")  # 本实现扩展码，见对齐文档
        if rid in log.revoked_ids():
            return deny("RECEIPT_REVOKED")

    # ---- 2 签名（只信任签名载荷；外层字段可能被剥改）----
    try:
        payload_bytes = unb64url(receipt["canonicalPayload"])
        sig = unb64url(receipt["signature"])
    except (KeyError, ValueError):
        return deny("INVALID_SIGNATURE")
    try:
        body: dict[str, Any] = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return deny("INVALID_SIGNATURE")
    # 外层字段可能被剥改 —— 签名体才是事实。§6.6 硬拒在解码后再判一次。
    if body.get("revocationRequired") and log is None:
        return deny("REVOCATION_CHECK_REQUIRED")
    # receiptId 自洽：去掉 receiptId 重算哈希，且外层与载荷一致
    body_no_id = {k: v for k, v in body.items() if k != "receiptId"}
    if (
        body.get("receiptId") != rid
        or "rec_" + sha256_hex(canonical_bytes(body_no_id)) != rid
    ):
        return deny("INVALID_SIGNATURE")
    pub = jwk_public_key(body.get("publicKey") or {})
    if pub is None or not ed25519.verify(pub, payload_bytes, sig):
        return deny("INVALID_SIGNATURE")

    # ---- 3 时间窗（本地时钟 + 容差；TSA 缺席语义见对齐文档）----
    moment = now or utcnow()
    try:
        nb = parse_iso(body["timeWindow"]["notBefore"])
        na = parse_iso(body["timeWindow"]["notAfter"])
    except (KeyError, ValueError):
        return deny("RECEIPT_EXPIRED")
    if moment + timedelta(seconds=skew) < nb:
        return deny("RECEIPT_NOT_YET_VALID")
    if moment - timedelta(seconds=skew) > na:
        return deny("RECEIPT_EXPIRED")

    # ---- 4 范围（默认拒绝；deniedActions 优先）----
    if a is not None:
        act = action(a)
        scope = body.get("scope", {})
        if _matches_any(act, scope.get("deniedActions", [])):
            return deny("ACTION_EXPLICITLY_DENIED")
        if not _matches_any(act, scope.get("allowedActions", [])):
            return deny("ACTION_NOT_IN_SCOPE")

        # ---- 5 边界 ----
        if _boundary_hit(act, body.get("boundaries", [])):
            return deny("ACTION_EXPLICITLY_DENIED")

        # ---- 13 指令来源 ----
        trusted = body.get("trustedSources")
        if trusted and instruction_source and instruction_source not in trusted:
            return deny("UNTRUSTED_INSTRUCTION_SOURCE")

    # ---- 7 指令哈希 ----
    if operator_instructions is not None:
        if sha256_prefixed(operator_instructions) != body.get(
            "operatorInstructionsHash"
        ):
            return deny("OPERATOR_INSTRUCTIONS_MISMATCH")

    # ---- 11 工具模式哈希 ----
    if tool_schema is not None and body.get("toolSchemaHash"):
        if "sha256:" + sha256_hex(canonical_bytes(tool_schema)) != body[
            "toolSchemaHash"
        ]:
            return deny("TOOL_SCHEMA_DRIFT")

    # ---- 14 父收据包含（收窄规则）----
    parent_id = body.get("parentReceiptId")
    if parent_id:
        if log is None:
            return deny("PARENT_SCOPE_VIOLATION")
        parent = log.find_receipt(parent_id)
        if parent is None:
            return deny("PARENT_SCOPE_VIOLATION")
        if log.chain_depth(body) > MAX_CHAIN_DEPTH:
            return deny("PARENT_SCOPE_VIOLATION")
        # 时间窗包含
        try:
            if not (
                parse_iso(parent["timeWindow"]["notBefore"])
                <= parse_iso(body["timeWindow"]["notBefore"])
                and parse_iso(body["timeWindow"]["notAfter"])
                <= parse_iso(parent["timeWindow"]["notAfter"])
            ):
                return deny("PARENT_SCOPE_VIOLATION")
        except (KeyError, ValueError):
            return deny("PARENT_SCOPE_VIOLATION")
        # 编排者绑定签名：以子收据自己的公钥验绑定串
        # （orchestratorSignature 不在签名体内，只能取外层字段）
        try:
            binding = f"orchestrator-delegation:{parent_id}:{rid}".encode("utf-8")
            sub_pub = jwk_public_key(body.get("publicKey") or {})
            if sub_pub is None or not ed25519.verify(
                sub_pub, binding, unb64url(receipt["orchestratorSignature"])
            ):
                return deny("PARENT_SCOPE_VIOLATION")
        except (KeyError, ValueError):
            return deny("PARENT_SCOPE_VIOLATION")
        # 收窄：子 allowedActions 必须被父覆盖，且不得与父完全相同
        p_scope = parent.get("scope", {})
        c_scope = body.get("scope", {})
        for cd in c_scope.get("allowedActions", []):
            if _matches_any(cd, p_scope.get("deniedActions", [])):
                return deny("PARENT_SCOPE_VIOLATION")
            if not any(
                _descriptor_covered(pd, cd)
                for pd in p_scope.get("allowedActions", [])
            ):
                return deny("SCOPE_NOT_STRICT_SUBSET")
        if canonical(c_scope.get("allowedActions", [])) == canonical(
            p_scope.get("allowedActions", [])
        ):
            return deny("SCOPE_NOT_STRICT_SUBSET")
        # 父边界对子仍然生效
        if _any_boundary_overruled(c_scope.get("allowedActions", []),
                                   parent.get("boundaries", [])):
            return deny("PARENT_SCOPE_VIOLATION")

    return {"decision": "PERMIT", "reason": None}


def _any_boundary_overruled(descs: Iterable[dict[str, str]],
                            boundaries: Iterable[str]) -> bool:
    return any(_boundary_hit(d, boundaries) for d in descs)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def register(sub: Any) -> None:
    r = sub.add_parser("receipt", help="委托收据：签发/验证/撤销（对齐 IETF DRP 草案）")
    r.set_defaults(func=cmd_receipt)
    rs = r.add_subparsers(dest="receipt_cmd", required=True)

    k = rs.add_parser("keygen", help="生成收据签名密钥（Ed25519）")
    k.add_argument("--out", default="receipt-key", help="私钥种子文件前缀")
    k.add_argument("--force", action="store_true")

    i = rs.add_parser("issue", help="签发委托收据")
    i.add_argument("--key", required=True, help="私钥种子文件（keygen 产物）")
    i.add_argument("--allow", action="append", default=[],
                   help="允许动作 operation:resource，可多次")
    i.add_argument("--deny", action="append", default=[],
                   help="拒绝动作，可多次")
    i.add_argument("--boundary", action="append", default=None,
                   help="硬边界 deny:operation:resource（缺省按范围智能生成）")
    i.add_argument("--minutes", type=int, default=60, help="有效窗口（分钟）")
    i.add_argument("--instructions", default="", help="运营方指令原文")
    i.add_argument("--instructions-file", help="从文件读取运营方指令")
    i.add_argument("--trusted-source", action="append", default=None,
                   help="可信指令来源，如 user / system_prompt / verified_tool")
    i.add_argument("--tool-schema", help="工具模式 JSON 文件（签入哈希）")
    i.add_argument("--revocation-required", action="store_true",
                   help="要求验证方必须查撤销表（草案 revocationRequired）")
    i.add_argument("--parent", help="父收据文件（签发子收据）")
    i.add_argument("--ledger", default=".", help="账本根目录")
    i.add_argument("--out", default="receipt.json", help="收据输出路径")

    v = rs.add_parser("verify", help="验证收据并（可选）裁决一个动作")
    v.add_argument("receipt", help="收据 JSON 文件")
    v.add_argument("--action", help="待裁决动作 operation:resource")
    v.add_argument("--instructions", help="当前运营方指令原文（查漂移）")
    v.add_argument("--tool-schema", help="当前工具模式 JSON 文件（查漂移）")
    v.add_argument("--source", help="动作的指令来源（查可信来源）")
    v.add_argument("--ledger", default=".", help="账本根目录（撤销表/父收据）")
    v.add_argument("--no-log", action="store_true", help="离线模式：不查账本")
    v.add_argument("--json", action="store_true", help="输出 JSON")

    x = rs.add_parser("revoke", help="撤销一份收据（写入撤销表）")
    x.add_argument("receipt", help="收据 JSON 文件")
    x.add_argument("--key", required=True, help="撤销方私钥种子文件")
    x.add_argument("--ledger", default=".", help="账本根目录")

    s = rs.add_parser("show", help="查看收据摘要")
    s.add_argument("receipt", help="收据 JSON 文件")
    s.add_argument("--json", action="store_true")


def _load_receipt(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def cmd_receipt(args: Any) -> int:
    if args.receipt_cmd == "keygen":
        out = Path(args.out)
        key_file = out if out.suffix == ".key" else Path(str(out) + ".key")
        if key_file.exists() and not args.force:
            print(f"  ✘ 密钥文件已存在：{key_file}（用 --force 覆盖）")
            return 1
        KeyPair.generate().save(key_file)
        print(f"  ✔ Ed25519 密钥已生成")
        print(f"  私钥  {key_file}（保密！等同你的签署身份）")
        print(f"  公钥  {key_file}.pub.jwk（可公开分发）")
        return 0

    if args.receipt_cmd == "issue":
        key = KeyPair.load(args.key)
        instructions = args.instructions
        if args.instructions_file:
            instructions = Path(args.instructions_file).read_text(encoding="utf-8")
        tool_schema = None
        if args.tool_schema:
            tool_schema = json.loads(Path(args.tool_schema).read_text("utf-8"))
        parent = _load_receipt(args.parent) if args.parent else None
        if not args.allow:
            print("  ✘ 至少需要一个 --allow")
            return 1
        receipt = issue(
            allowed=args.allow, denied=args.deny, boundaries=args.boundary,
            minutes=args.minutes, operator_instructions=instructions,
            key=key, trusted_sources=args.trusted_source,
            tool_schema=tool_schema, revocation_required=args.revocation_required,
            parent=parent,
        )
        out = Path(args.out)
        out.write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + "\n",
                       encoding="utf-8")
        log = ReceiptLog.for_root(args.ledger)
        log.append_receipt(receipt)
        print(f"  ✔ 收据已签发并锚定账本")
        print(f"  收据  {receipt['receiptId']}")
        print(f"  窗口  {receipt['timeWindow']['notBefore']} → "
              f"{receipt['timeWindow']['notAfter']}")
        print(f"  允许  {', '.join(a['operation'] + ':' + a['resource'] for a in receipt['scope']['allowedActions'])}")
        print(f"  边界  {', '.join(receipt['boundaries'])}")
        print(f"  文件  {out}")
        return 0

    if args.receipt_cmd == "verify":
        receipt = _load_receipt(args.receipt)
        tool_schema = None
        if args.tool_schema:
            tool_schema = json.loads(Path(args.tool_schema).read_text("utf-8"))
        log = None if args.no_log else ReceiptLog.for_root(args.ledger)
        result = verify(
            receipt,
            a=args.action,
            operator_instructions=args.instructions,
            tool_schema=tool_schema,
            instruction_source=args.source,
            log=log,
        )
        # 草案 §5.4：裁决（含 DENY）一律留痕
        if args.action and log is not None and log.path.parent.exists():
            log.append_action(receipt.get("receiptId", "?"),
                              action(args.action), result["decision"])
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            mark = "PERMIT ✓" if result["decision"] == "PERMIT" else "DENY ✗"
            print(f"  收据  {receipt.get('receiptId', '?')}")
            print(f"  裁决  {mark}")
            if result["reason"]:
                print(f"  原因  {result['reason']}")
                print(f"  回退  {result['safeAlternative']}（草案 §6.3：无操作并留痕）")
        return 0 if result["decision"] == "PERMIT" else 1

    if args.receipt_cmd == "revoke":
        receipt = _load_receipt(args.receipt)
        key = KeyPair.load(args.key)
        log = ReceiptLog.for_root(args.ledger)
        record = revocation_record(receipt["receiptId"], key)
        log.append_revocation(record)
        print(f"  ✔ 已撤销并写入撤销表")
        print(f"  收据  {receipt['receiptId']}")
        print(f"  时间  {record['revokedAt']}")
        print("  注意  子收据不会级联失效 —— 请逐份撤销（草案 §10.4）")
        return 0

    if args.receipt_cmd == "show":
        receipt = _load_receipt(args.receipt)
        if args.json:
            print(json.dumps(receipt, ensure_ascii=False, indent=2))
            return 0
        scope = receipt.get("scope", {})
        print(f"  收据  {receipt.get('receiptId', '?')}")
        print(f"  版本  {receipt.get('schemaVersion')}  "
              f"（DRP 离线子集实现：agentledger {__version__}）")
        print(f"  允许  {', '.join(a['operation'] + ':' + a['resource'] for a in scope.get('allowedActions', [])) or '—'}")
        print(f"  拒绝  {', '.join(a['operation'] + ':' + a['resource'] for a in scope.get('deniedActions', [])) or '—'}")
        print(f"  边界  {', '.join(receipt.get('boundaries', []))}")
        print(f"  窗口  {receipt.get('timeWindow', {}).get('notBefore')} → "
              f"{receipt.get('timeWindow', {}).get('notAfter')}")
        print(f"  指令  {receipt.get('operatorInstructionsHash', '')[:39]}…")
        if receipt.get("parentReceiptId"):
            print(f"  父收据  {receipt['parentReceiptId']}")
        return 0

    return 1

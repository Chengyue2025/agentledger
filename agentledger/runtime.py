"""运行时行为留痕 —— 让"可追溯"从口号变成可验证的记录。

为什么这是分界线
----------------
静态扫描回答的是「**可能会**出问题」，
运行时记录回答的是「**实际**发生了什么」。

《实施意见》第 6 条要求"确保用户对智能体自主决策享有**知情权**"；
GB/Z 185—2026 要求智能体互联"**可追溯**"；
EU AI Act Art.12 要求高风险系统"automatically record events over their lifetime"。

三者指向同一件事：**行为记录**。而目前行业没有实现手段。
SBOM 解决的是"我用了什么"，解决不了"它到底做了什么、谁批的"。

本模块补的就是这一段，并且：
- 同样哈希链式、同样可验伪（与静态账本同一套信任模型）
- 默认**只存摘要不存明文**（PIPL 视角：记录行为不应等于新建一份个人信息副本）
- 每条记录**回指权限判定**，形成"谁批的→做了什么"的完整闭环

对齐 GB/Z 185—2026 第 7 部分（外部工具调用的架构、流程和数据格式）
的要素：身份标识、能力声明、调用参数、返回结果、时间戳。
字段级完全符合需以标准正式文本为准，本模块按工信部科技司 2026-07-06
解读中公开的结构实现。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

from .ledger import canonical, sha256_hex

SCHEMA = "agentledger/runtime-trace/v1"

# 敏感字段：记录行为不等于复制个人信息。
# 默认脱敏，符合 PIPL「最小必要」与《实施意见》对个人信息保护的要求。
SENSITIVE_KEY_RE = re.compile(
    r"(?i)^(.*_)?(id_?card|ssn|passport|bank_?account|card_?no|"
    r"手机号|phone|mobile|email|address|身份证|银行卡|住址|姓名|name|"
    r"password|passwd|secret|token|api_?key|credential|"
    r"medical|health|健康|病历|biometric)($|_)"
)


def digest(obj: Any) -> str:
    """稳定摘要。用于证明"内容是这一份"，而不必保存内容本身。"""
    return sha256_hex(canonical(obj))


def redact_args(obj: Any, keep_digest: bool = True) -> tuple[Any, list[str]]:
    """脱敏。返回 (脱敏后的对象, 被脱敏的键路径)。

    刻意保留结构与键名 —— 否则记录就失去了可审计价值
    （"调用了 refund 工具，参数含身份证号"本身就是有用证据）。
    """
    hit: list[str] = []

    def walk(node: Any, path: str = "") -> Any:
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                p = f"{path}.{k}" if path else str(k)
                if SENSITIVE_KEY_RE.match(str(k)):
                    hit.append(p)
                    out[k] = "[redacted]"
                else:
                    out[k] = walk(v, p)
            return out
        if isinstance(node, list):
            return [walk(v, f"{path}[{i}]") for i, v in enumerate(node)]
        if isinstance(node, str) and len(node) > 512:
            hit.append(path)
            return f"[truncated:{len(node)}]"
        return node

    safe = walk(obj)
    if keep_digest and not hit:
        pass
    return safe, hit


@dataclass
class TraceRecord:
    """一次工具调用的运行时记录。

    字段按 GB/Z 185 第 7 部分所需的要素组织：
    身份标识 / 能力声明 / 调用参数 / 返回结果 / 时间戳
    """

    seq: int = 0
    trace_id: str = ""
    agent_id: str = ""
    tool: str = ""
    agent_version: str = ""
    actor: str = "agent"             # agent | user | system
    granted_authority: str = ""      # 依据哪条授权
    grant_id: str = ""               # 授权凭据 ID —— 闭环的关键字段
    args_digest: str = ""            # 参数摘要（不存明文）
    args_safe: Any = None            # 脱敏后的参数（可关闭）
    result_digest: str = ""
    result_summary: str = ""         # 结果摘要（可关闭）
    redactions: list[str] = field(default_factory=list)
    outcome: str = "ok"              # ok | blocked | error | denied
    error: str = ""
    latency_ms: float = 0.0
    latency_us: int = 0
    at: str = ""
    prev: str = ""
    hash: str = ""

    def __post_init__(self) -> None:
        if not self.at:
            self.at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def payload(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if k != "hash"}

    def to_dict(self) -> dict[str, Any]:
        d = self.payload()
        d["hash"] = self.hash
        return d

    @staticmethod
    def compute_hash(payload: dict[str, Any]) -> str:
        return sha256_hex(canonical(payload))

    def statement(self) -> str:
        """一句可贴进合规文档的话。"""
        base = (f"[{self.at}] 智能体 {self.agent_id} 调用工具「{self.tool}」，"
                f"结果 {self.outcome}")
        if self.grant_id:
            base += f"，依据授权凭据 {self.grant_id}"
        if self.redactions:
            base += f"（参数含 {len(self.redactions)} 处敏感字段，已脱敏）"
        if self.outcome != "ok":
            base += f"；{self.error or self.outcome}"
        return base + "。"


class RuntimeRecorder:
    """运行时行为账本。

    用法（推荐 contextmanager 形式，自动计时与异常捕获）::

        rec = RuntimeRecorder(ledger_path="var/agent-trace.jsonl",
                              agent_id="acme-support-triage", version="0.4.0")

        with rec.trace("issue_refund", args={"order": "A-1", "id_card": "..."},
                       authority=d.authority.value, grant_id=d.grant_id) as span:
            span.result = do_refund(...)

    也可以包住任意可调用对象，包括 MCP 客户端与 HTTP 客户端::

        rec.wrap("crm.lookup_order", client.call)

    设计约束：
      - **默认不存明文**。args/result 只留摘要与脱敏副本。
        需要留存原文时必须显式 ``store_plaintext=True``，
        且该事实本身会被记录（否则"我们记录了原文"这件事就不可见）。
      - **链式哈希**，与静态账本同一信任模型：改一条、删一条都能检出。
      - 记录永不抛异常。审计设施不能因为审计失败而中断业务。
    """

    def __init__(self, ledger_path: str | None = None,
                 agent_id: str = "unknown-agent",
                 version: str = "",
                 store_plaintext: bool = False,
                 keep_args: bool = True,
                 agent_name: str = ""):
        self.ledger_path = ledger_path
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.version = version
        self.store_plaintext = store_plaintext
        self.keep_args = keep_args
        self._records: list[TraceRecord] = []
        self._pending: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    def _head(self) -> str:
        if self._records:
            return self._records[-1].hash
        if self.ledger_path and os.path.exists(self.ledger_path):
            try:
                with open(self.ledger_path, "r", encoding="utf-8") as fh:
                    lines = [l for l in fh.read().splitlines() if l.strip()]
                if lines:
                    return json.loads(lines[-1]).get("hash", "")
            except (OSError, json.JSONDecodeError):
                return ""
        return ""

    def _seq(self) -> int:
        return len(self._records)

    # ------------------------------------------------------------------
    def record(self, tool: str, args: Any = None, result: Any = None,
               outcome: str = "ok", error: str = "",
               actor: str = "agent", authority: str = "",
               grant_id: str = "", latency_ms: float = 0.0) -> TraceRecord:
        """写入一条运行记录。永不抛异常。"""
        try:
            args_safe, redactions = redact_args(args) if self.keep_args else (None, [])
            result_summary = ""
            if self.keep_args and isinstance(result, str):
                result_summary = result[:256]

            rec = TraceRecord(
                seq=self._seq(),
                trace_id=str(uuid.uuid4()),
                agent_id=self.agent_id,
                agent_version=self.version,
                tool=tool,
                actor=actor,
                granted_authority=authority,
                grant_id=grant_id,
                args_digest=digest(args),
                args_safe=args_safe if self.keep_args else None,
                result_digest=digest(result) if result is not None else "",
                result_summary=result_summary,
                redactions=redactions,
                outcome=outcome,
                error=error[:500],
                # 同时留微秒：本地调用常常 < 0.01ms，只留毫秒会记录成 0.0，
                # 那在合规记录里看起来像"没测"，而实际是"很快"。
                latency_ms=round(latency_ms, 4),
                latency_us=int(latency_ms * 1000),
                prev=self._head(),
            )
            rec.hash = TraceRecord.compute_hash(rec.payload())
            self._records.append(rec)
            self._append(rec)
            return rec
        except Exception as exc:  # 审计设施不得中断业务
            self._pending.append({"error": repr(exc), "tool": tool, "at": rec_now()})
            return TraceRecord(seq=self._seq(), trace_id="", agent_id=self.agent_id,
                               tool=tool, outcome="audit_error", error=repr(exc))

    # ------------------------------------------------------------------
    @contextmanager
    def trace(self, tool: str, args: Any = None, actor: str = "agent",
              authority: str = "", grant_id: str = "") -> Iterator["_Span"]:
        span = _Span(recorder=self, tool=tool, actor=actor,
                     authority=authority, grant_id=grant_id)
        span._args = args
        t0 = time.perf_counter()
        try:
            yield span
        except Exception as exc:
            span.outcome = "error"
            span.error = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            span.recorder.record(
                tool=tool, args=args, result=span.result,
                outcome=span.outcome, error=span.error, actor=actor,
                authority=authority, grant_id=grant_id,
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )

    # ------------------------------------------------------------------
    def wrap(self, tool: str, fn: Callable, *a, **kw) -> Callable:
        """把任意可调用对象包成留痕的。适合 MCP/HTTP 客户端。"""
        def wrapper(*args, **kwargs):
            call_args = {"args": args, "kwargs": kwargs} if (args or kwargs) else None
            with self.trace(tool, args=call_args):
                return fn(*args, **kwargs)
        wrapper.__name__ = getattr(fn, "__name__", tool)
        wrapper.__doc__ = getattr(fn, "__doc__", None)
        return wrapper

    # ------------------------------------------------------------------
    def _append(self, rec: TraceRecord) -> None:
        if not self.ledger_path:
            return
        try:
            d = os.path.dirname(self.ledger_path)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(self.ledger_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec.to_dict(), ensure_ascii=False) + "\n")
        except OSError:
            pass

    # ------------------------------------------------------------------
    def verify(self) -> tuple[bool, list[str]]:
        """校验运行记录的哈希链。"""
        problems: list[str] = []
        expected_prev = ""
        for i, r in enumerate(self._records):
            if r.prev != expected_prev:
                problems.append(f"[{i}] 链断裂：prev 不匹配")
            if TraceRecord.compute_hash(r.payload()) != r.hash:
                problems.append(f"[{i}] 哈希不匹配：记录被修改")
            expected_prev = r.hash
        return not problems, problems

    def merkle_root(self) -> str:
        from .ledger import merkle_root
        return merkle_root(r.hash for r in self._records)

    # ------------------------------------------------------------------
    def evidence(self) -> dict[str, Any]:
        """导出运行时证据包。可与静态扫描证据包合并归档。"""
        by_outcome: dict[str, int] = {}
        by_tool: dict[str, int] = {}
        redaction_total = 0
        for r in self._records:
            by_outcome[r.outcome] = by_outcome.get(r.outcome, 0) + 1
            by_tool[r.tool] = by_tool.get(r.tool, 0) + 1
            redaction_total += len(r.redactions)

        chain_ok, chain_problems = self.verify()
        return {
            "schema": SCHEMA,
            "standard_alignment": {
                "note": "按 GB/Z 185—2026 第 7 部分（外部工具调用的架构、流程和"
                        "数据格式）所要求的要素组织；字段级完全符合需以标准正式文本为准。",
                "elements": {
                    "身份标识": "agent_id / actor / agent_version",
                    "能力声明": "tool",
                    "调用参数": "args_digest / args_safe（脱敏）",
                    "返回结果": "result_digest / result_summary",
                    "时间戳": "at",
                    "授权凭据": "grant_id / granted_authority",
                },
                "policy_refs": [
                    "《智能体规范应用与创新发展实施意见》第 6 条（知情权 / 最终决策权）",
                    "《智能体规范应用与创新发展实施意见》第 7 条（行为可验证、可追溯）",
                    "GB/Z 185—2026 第 7 部分（工具调用数据格式）",
                    "EU AI Act Art.12（记录留存）",
                ],
            },
            "agent": {
                "id": self.agent_id,
                "name": self.agent_name,
                "version": self.version,
            },
            "integrity": {
                "record_count": len(self._records),
                "merkle_root": self.merkle_root(),
                "chain_verified": chain_ok,
                "chain_problems": chain_problems,
                "audit_write_failures": self._pending,
            },
            "privacy": {
                "store_plaintext": self.store_plaintext,
                "args_kept_redacted": self.keep_args,
                "redacted_field_count": redaction_total,
                "basis": "最小必要原则：记录行为不等于复制个人信息",
            },
            "summary": {
                "by_outcome": by_outcome,
                "by_tool": dict(sorted(by_tool.items(), key=lambda kv: -kv[1])),
            },
            "records": [r.to_dict() for r in self._records],
            "statements": [r.statement() for r in self._records],
        }

    def to_json(self) -> str:
        return json.dumps(self.evidence(), ensure_ascii=False, indent=2)


def rec_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class _Span:
    """contextmanager 句柄。调用方给 span.result 赋值即可。"""

    def __init__(self, recorder: RuntimeRecorder, tool: str, actor: str,
                 authority: str, grant_id: str):
        self.recorder = recorder
        self.tool = tool
        self.actor = actor
        self.authority = authority
        self.grant_id = grant_id
        self.result: Any = None
        self.outcome = "ok"
        self.error = ""
        self._args: Any = None

    def deny(self, reason: str) -> None:
        """标记为被权限闸门阻断。"""
        self.outcome = "denied"
        self.error = reason

    def block(self, reason: str) -> None:
        self.outcome = "blocked"
        self.error = reason


__all__ = ["RuntimeRecorder", "TraceRecord", "redact_args", "digest", "SCHEMA"]
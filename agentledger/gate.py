"""审批闸门 —— 把 AGT002「高风险动作缺少审批闸门」从发现项变成已交付的修复。

为什么这是整个产品里最值钱的一环
--------------------------------
发现问题的人不会为"发现问题"付最多钱，付钱的是**问题被修掉**。
本模块让诊断与修复同源：agentledger 报出「你有退款能力却没有闸门」，
同时这个闸门已经装好了、离线运行、零边际成本。

为什么不能有 API 调用成本
------------------------
审批一旦有边际成本，客户的最优解就是**绕过它**。
审批必须是本地推理。当前 33ms 量级（见 research/2026-10_开源前沿扫描与熔炼方案.md）。

双后端设计
----------
1. `HeuristicBackend` —— 零依赖、纯规则、确定性、可审计。**默认。**
   这不是降级方案：对"要不要人工签字"这类问题，可解释的规则往往比
   小模型更可靠，而且监管场景里"为什么必须人工"必须能一句话说清。
2. `LayaBackend` —— 可选。当装了 `laya` 时启用，用其 typed decision
   （`noul` = 否/未知/可能）做语义判断，处理规则覆盖不到的措辞变体。

两者接口一致，可互换；启用 Laya 不会改变任何调用方代码。

安全边界（重要）
--------------
本模块是**拦截器**，不是放行器。默认拒绝。
`GateDecision.requires_approval=False` 不会自动放行 —— 放行必须由
调用方显式处理，且本模块永远记录留痕。
审批闸门不是安全边界，它是**责任边界**：它保证的是"这件事有人签字"，
不是"这件事是安全的"。
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Protocol


# ==========================================================================
# 风险分类
# ==========================================================================
class Risk(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# 动作 → 风险等级。
# 注意：这里的分级是**责任**分级，不是"危害"分级。
# 一条只读查询即使无害，只要它进入对外通道，也需要留痕。
RISK_TABLE: dict[str, Risk] = {
    # --- 资金 ---
    "payment": Risk.CRITICAL,
    "transfer_funds": Risk.CRITICAL,
    "wire": Risk.CRITICAL,
    "issue_refund": Risk.HIGH,
    "refund": Risk.HIGH,
    "charge": Risk.HIGH,
    "purchase": Risk.HIGH,
    "subscription_change": Risk.HIGH,
    "order_cancel": Risk.MEDIUM,
    # --- 不可逆数据 ---
    "delete_account": Risk.CRITICAL,
    "delete": Risk.HIGH,
    "drop_table": Risk.CRITICAL,
    "truncate": Risk.CRITICAL,
    "bulk_update": Risk.HIGH,
    # --- 对外通道 ---
    "send_email": Risk.HIGH,
    "send_email_bulk": Risk.CRITICAL,
    "send_message": Risk.HIGH,
    "post_social": Risk.HIGH,
    "publish": Risk.HIGH,
    "webhook": Risk.MEDIUM,
    "api_call_external": Risk.MEDIUM,
    # --- 权限 ---
    "grant_permission": Risk.HIGH,
    "rotate_secret": Risk.HIGH,
    "deploy": Risk.MEDIUM,
    "escalate": Risk.LOW,
    # --- 只读 ---
    "read": Risk.NONE,
    "lookup": Risk.NONE,
    "search": Risk.NONE,
    "answer_faq": Risk.NONE,
    "summarize": Risk.LOW,
}

_ORDER = {
    Risk.NONE: 0, Risk.LOW: 1, Risk.MEDIUM: 2, Risk.HIGH: 3, Risk.CRITICAL: 4,
}

# 与资金相关的动作 —— 金额阈值只对这些生效。
# 理由见 HeuristicBackend.evaluate 的说明：审批闸门过度触发 = 客户绕过它。
MONEY_ACTIONS = frozenset({
    "payment", "transfer_funds", "wire", "issue_refund", "refund",
    "charge", "purchase", "subscription_change", "order_cancel",
})

# 明显只读的动作前缀/后缀。
# 为什么需要：白名单模型下，未登记的 `lookup_order` 会被判 high。
# 但拦截一个查订单的工具，客户第一天就会绕过闸门 —— 过度触发的闸门等于没有闸门。
# 因此：只读语义自动归为 low，同时标记 should_register=True，
# 让它在证据包/AI BOM 里显式出现，推动项目补全声明。
READONLY_PATTERNS = re.compile(
    r"""(?ix)
    ^ ( get | list | read | query | lookup | find | search | fetch | view
      | show | count | check | describe | inspect | fetch_ | resolve_ )
    | _ ( get | list | read | query | lookup | find | search | fetch | view
        | count | check | describe | inspect ) $
    | ^ (status|info|details|summary|ping|health|echo)
    | _ (info|details|status|list_all|search)
    """
)
# 这些前缀即使是"读"，也要小心（读的是凭据/权限）
_READONLY_BUT_SENSITIVE = re.compile(r"(?i)(secret|credential|token|password|key|acl|permission|role)")

# 高风险语义，即使长得像读操作也要拦
_WRITEISH = re.compile(
    r"(?i)(create|insert|update|delete|remove|write|set|add|put|post|send|"
    r"issue|approve|execute|run|trigger|apply|submit|publish|issue_)"
)


# ==========================================================================
# 决策结果
# ==========================================================================
@dataclass
class GateDecision:
    action: str
    risk: Risk
    requires_approval: bool
    backend: str
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0
    at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "risk": self.risk.value,
            "requires_approval": self.requires_approval,
            "backend": self.backend,
            "reason": self.reason,
            "evidence": self.evidence,
            "latency_ms": round(self.latency_ms, 2),
            "at": self.at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


# 阈值：达到 MEDIUM 即需人工签字。
# 留成可配，因为不同行业的授权额度差异极大 ——
# 客服改地址和银行转账不该用同一个阈值。
DEFAULT_THRESHOLD = Risk.MEDIUM


# ==========================================================================
# 后端接口
# ==========================================================================
class Backend(Protocol):
    name: str

    def evaluate(self, action: str, context: dict[str, Any]) -> tuple[Risk, str, dict]:
        ...


# ==========================================================================
# 后端 1：零依赖启发式（默认）
# ==========================================================================
_ACTION_SYNONYMS = (
    (r"退款|refund", "issue_refund"),
    (r"付款|扣款|支付|pay(ment)?|charge", "payment"),
    (r"转账|汇款|transfer|wire", "transfer_funds"),
    (r"删除|delete|drop|truncate|purge", "delete"),
    (r"发(送)?(邮件|短信)|send[_\s]?(email|mail|message)|群发", "send_email"),
    (r"发布|publish|post_", "publish"),
    (r"部署|deploy|release", "deploy"),
    (r"密钥|secret|credential|token|rotate", "rotate_secret"),
    (r"授权|grant|permission|acl|role", "grant_permission"),
    (r"退款审批|approve_refund", "approve_refund"),
)


class HeuristicBackend:
    """确定性规则后端。零依赖、离线、可审计。

    设计取舍：**宁可多拦，不可漏拦**，但"多拦"要有边界。
    纯粹的白名单模型会把 `lookup_order` 这类显然只读的动作也拦下，
    而一个频繁误拦的闸门会被客户绕过 —— 那等于没有闸门。
    因此分三档：

      1. 已登记 → 按登记表定级
      2. 未登记但只读语义 → 自动归low，并标记 ``should_register``
         （在证据包/AI BOM 里显式出现，推动项目补全声明）
      3. 未登记且非只读 → 默认 high（白名单模型）

    项目可用 ``register()`` 或从 ``agent_manifest.json`` 加载自己的动作表，
    把第 2、3 档收敛掉。
    """

    name = "heuristic"

    def __init__(self, amount: float | None = None,
                 currency: str = "CNY",
                 high_risk_threshold: Risk = Risk.HIGH,
                 extra_table: dict[str, Risk] | None = None):
        self.amount = amount
        self.currency = currency
        self.high_risk_threshold = high_risk_threshold
        # 项目自定义动作表，优先级高于内置表
        self.table: dict[str, Risk] = dict(RISK_TABLE)
        if extra_table:
            self.table.update(extra_table)

    def register(self, action: str, risk: Risk) -> None:
        """登记一个项目自定义动作。"""
        self.table[(action or "").strip().lower().replace("-", "_")] = risk

    @classmethod
    def from_manifest(cls, manifest: dict, **kw) -> "HeuristicBackend":
        """从 agent_manifest.json 构建动作表。

        这样闸门用的就是项目自己声明的动作，而不是一张和项目无关的通用表。
        闭环：agentledger 报 AGT002（缺声明）→ 项目补声明 → 闸门自动获得定级。
        """
        extra: dict[str, Risk] = {}
        for key in ("capabilities", "tools", "actions", "allowed_actions"):
            for name in (manifest.get(key) or []):
                if isinstance(name, str):
                    extra[name.strip().lower().replace("-", "_")] = Risk.MEDIUM
        boundary = manifest.get("action_boundary") or {}
        for name in (boundary.get("allowed_actions") or []):
            if isinstance(name, str):
                extra[name.strip().lower().replace("-", "_")] = Risk.LOW
        for name in (boundary.get("denied_actions") or []):
            if isinstance(name, str):
                extra[name.strip().lower().replace("-", "_")] = Risk.CRITICAL
        gate_cfg = manifest.get("approval_gate") or {}
        for name in (gate_cfg.get("requires_approval") or []):
            if isinstance(name, str):
                extra[name.strip().lower().replace("-", "_")] = Risk.HIGH
        return cls(extra_table=extra, **kw)

    # -- 动作归一化 ---------------------------------------------------
    def normalize(self, action: str) -> tuple[str, bool]:
        """返回 (归一化动作, 是否发生模糊匹配)。"""
        key = (action or "").strip().lower().replace("-", "_").replace(" ", "_")
        if key in self.table:
            return key, False
        for pattern, canon in _ACTION_SYNONYMS:
            if re.search(pattern, key):
                return canon, True
        return key, False

    @staticmethod
    def _classify_unregistered(canon: str) -> tuple[Risk, bool, str]:
        """对未登记动作做只读语义判定。

        返回 (风险, 是否仅只读, 理由)。宁可保守，但不能让只读查询被拦。
        """
        if not canon:
            return Risk.HIGH, False, "空动作名"
        # 长得像写操作的一律按写操作处理，优先级高于只读前缀
        if _WRITEISH.search(canon):
            return Risk.HIGH, False, f"名称含写操作语义 ({canon})"
        if _READONLY_BUT_SENSITIVE.search(canon):
            return Risk.HIGH, False, f"名称含敏感资源语义 ({canon})"
        if READONLY_PATTERNS.search(canon):
            return Risk.LOW, True, f"只读语义 ({canon})"
        return Risk.HIGH, False, f"无法判定 ({canon})"

    # -- 金额评估 -----------------------------------------------------
    def _amount_risk(self, context: dict) -> tuple[Risk, str] | None:
        amt = context.get("amount")
        if amt is None:
            return None
        try:
            amt = float(amt)
        except (TypeError, ValueError):
            return Risk.MEDIUM, f"金额字段不可解析: {amt!r}，保守升级"
        if amt <= 0:
            return Risk.LOW, f"金额 {amt}，非正数"
        # 每万元一个等级；无行业知识时这是最保守的线性近似
        tier = Risk.MEDIUM
        for threshold, sev in ((1_000, Risk.MEDIUM), (10_000, Risk.HIGH),
                               (100_000, Risk.CRITICAL), (1_000_000, Risk.CRITICAL)):
            if amt >= threshold:
                tier = sev
        return tier, f"金额 {amt} {self.currency} → {tier.value}"

    # -- 主评估 -------------------------------------------------------
    def evaluate(self, action: str, context: dict) -> tuple[Risk, str, dict]:
        canon, fuzzy = self.normalize(action)
        risk = self.table.get(canon)
        evidence: dict[str, Any] = {
            "canonical_action": canon,
            "fuzzy_match": fuzzy,
        }

        if risk is None:
            # 未登记：先做只读语义判定，避免误拦查询类动作
            risk, readonly, why = self._classify_unregistered(canon)
            evidence["reason_code"] = "UNREGISTERED_READONLY" if readonly else "UNREGISTERED"
            evidence["registered"] = False
            evidence["should_register"] = True
            evidence["classification"] = why

        notes: list[str] = []
        if not evidence.get("registered", True):
            notes.append(f"未登记动作 '{canon}' → {why} → {risk.value}")

        # 金额只在"与钱有关"的动作上生效。
        # 否则 read(order_total=99999) 会被无意义地拦下 ——
        # 审批闸门一旦过度触发，客户的第一反应就是绕过它。
        amt = self._amount_risk(context) if (risk is None
                                            or canon in MONEY_ACTIONS) else None
        if amt:
            arisk, areason = amt
            evidence["amount_assessment"] = areason
            if _ORDER[arisk] > _ORDER[risk]:
                risk = arisk
            notes.append(areason)

        # 批量放大
        count = context.get("count") or context.get("batch_size")
        if isinstance(count, int) and count > 1:
            if _ORDER[risk] < _ORDER[Risk.HIGH]:
                risk = Risk.HIGH
            notes.append(f"批量操作 x{count} → 升级为 high")
            evidence["batch"] = count

        # 数据敏感度放大
        data = context.get("data") or context.get("fields") or []
        if isinstance(data, (list, tuple)) and data:
            sensitive = [d for d in data if re.search(
                r"id_?card|ssn|身份证|银行卡|bank_?account|手机号|phone|password|"
                r"健康|medical|生物|biometric", str(d), re.I)]
            if sensitive:
                if _ORDER[risk] < _ORDER[Risk.HIGH]:
                    risk = Risk.HIGH
                notes.append(f"涉及敏感字段 {sorted(set(sensitive))} → 至少 high")
                evidence["sensitive_fields"] = sorted(set(sensitive))

        # 外发通道放大
        if context.get("external") and _ORDER[risk] < _ORDER[Risk.MEDIUM]:
            risk = Risk.MEDIUM
            notes.append("对外通道 → 至少 medium")

        evidence["notes"] = notes
        reason = f"动作 '{canon}' 基础风险 {risk.value}"
        if notes:
            reason += "；" + "；".join(notes)
        return risk, reason, evidence


# ==========================================================================
# 后端 2：Laya（可选）
# ==========================================================================
class LayaBackend:
    """基于 Laya 的语义后端（Apache-2.0）。

    用于处理启发式覆盖不到的**自然语言措辞变体**，例如：
        "把这个订单的钱退到客户卡里"  → issue_refund
        "帮忙把老王那条记录清掉"      → delete

    Laya 的 typed decision 里 `noul`（No/Unknown/Likely）天然对应
    "是否需要人工签字"这个三值问题。

    未安装 laya 时 `available()` 返回 False，闸门自动回落到启发式后端。
    """

    name = "laya"

    def __init__(self, router=None, fallback: Backend | None = None):
        self._router = router
        self.fallback = fallback or HeuristicBackend()
        self._probed = False

    @staticmethod
    def available() -> bool:
        try:
            import laya  # noqa: F401
            return True
        except Exception:
            return False

    def _get_router(self):
        if not self._probed:
            self._probed = True
            if self._router is None:
                try:
                    from laya import Router
                    self._router = Router()
                except Exception:
                    self._router = None
        return self._router

    def evaluate(self, action: str, context: dict) -> tuple[Risk, str, dict]:
        router = self._get_router()
        if router is None:
            risk, reason, ev = self.fallback.evaluate(action, context)
            ev["laya_fallback"] = True
            return risk, reason, ev

        text = context.get("text") or context.get("description") or action
        questions = {
            "involves_money": {
                "type": "noul",
                "instructions": "Does this action involve moving money, "
                                "charging, refunding, or any financial transaction?",
            },
            "irreversible": {
                "type": "noul",
                "instructions": "Is this action irreversible or permanently "
                                "destroys data or permissions?",
            },
            "external_side_effect": {
                "type": "noul",
                "instructions": "Does this action have an externally visible "
                                "side effect (sending, publishing, notifying third parties)?",
            },
        }
        try:
            res = router.predict(f"{action}\n{text}", questions)
            answers = {k: _extract(res, k) for k in questions}
        except Exception as exc:
            risk, reason, ev = self.fallback.evaluate(action, context)
            ev["laya_error"] = repr(exc)[:200]
            return risk, reason, ev

        # 三票决策：任一为肯定即升级
        votes = list(answers.values())
        if "yes" in votes:
            risk = Risk.CRITICAL
        elif "likely" in votes:
            risk = Risk.HIGH
        elif "unknown" in votes:
            risk = self.fallback.evaluate(action, context)[0]
            if _ORDER[risk] < _ORDER[Risk.MEDIUM]:
                risk = Risk.MEDIUM
        else:
            risk, _, _ = self.fallback.evaluate(action, context)

        ev = {"laya_answers": answers, "canonical_action":
              self.fallback.normalize(action)[0]}
        return risk, f"语义裁决 {answers}，综合 {risk.value}", ev


def _extract(res: Any, key: str) -> str:
    """从 Laya 的返回结构里取出某个问题的答案，尽最大努力兼容。"""
    for attr in ("answers", "predictions", "results"):
        d = getattr(res, attr, None) if not isinstance(res, dict) else res.get(attr)
        if isinstance(d, dict) and key in d:
            v = d[key]
            return (v if isinstance(v, str)
                    else str(getattr(v, "label", getattr(v, "value", v)))).lower()
    if isinstance(res, dict) and key in res:
        v = res[key]
        return (v if isinstance(v, str)
                else str(getattr(v, "label", getattr(v, "value", v)))).lower()
    return "unknown"


# ==========================================================================
# 闸门
# ==========================================================================
class ApprovalGate:
    """智能体高风险动作的人工审批闸门。

    用法::

        gate = ApprovalGate(threshold=Risk.MEDIUM)
        d = gate.check("issue_refund", {"amount": 50000, "order": "A-123"})
        if d.requires_approval:
            ... # 请人签字；签字结果写回 gate.record_approval

    设计约束（不可更改）：
      - 默认拒绝。任何"不需要审批"的判定都必须由调用方显式处理，
        本类不做自动放行。
      - 全量留痕。每一次 check 都产出一条可归档的记录。
      - 阈值可配。不同行业的授权额度差异极大。
    """

    def __init__(self, threshold: Risk = DEFAULT_THRESHOLD,
                 backend: Backend | None = None,
                 ledger_path: str | None = None,
                 amount: float | None = None):
        self.threshold = threshold
        self.backend = backend or self._default_backend()
        self.ledger_path = ledger_path
        self.amount = amount

    @staticmethod
    def _default_backend() -> Backend:
        if os.environ.get("ALEDGER_GATE_BACKEND") == "laya" and LayaBackend.available():
            return LayaBackend()
        return HeuristicBackend()

    # ------------------------------------------------------------------
    def check(self, action: str, context: dict | None = None) -> GateDecision:
        context = context or {}
        if self.amount is not None and "amount" not in context:
            context["amount"] = self.amount

        t0 = time.perf_counter()
        risk, reason, evidence = self.backend.evaluate(action, context)
        elapsed = (time.perf_counter() - t0) * 1000.0

        requires = _ORDER[risk] >= _ORDER[self.threshold]

        decision = GateDecision(
            action=action,
            risk=risk,
            requires_approval=requires,
            backend=getattr(self.backend, "name", type(self.backend).__name__),
            reason=reason,
            evidence=evidence,
            latency_ms=elapsed,
        )
        self._append(decision)
        return decision

    # ------------------------------------------------------------------
    def record_approval(self, decision: GateDecision, approver: str,
                        approved: bool, note: str = "") -> dict[str, Any]:
        """记录人工审批结果。这是责任链上唯一由人写入的一环。"""
        record = {
            **decision.to_dict(),
            "approval": {
                "approver": approver,
                "approved": approved,
                "note": note,
                "decided_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
        }
        self._append_raw(record)
        return record

    # ------------------------------------------------------------------
    def _append(self, decision: GateDecision) -> None:
        self._append_raw({"type": "check", **decision.to_dict()})

    def _append_raw(self, record: dict[str, Any]) -> None:
        if not self.ledger_path:
            return
        d = os.path.dirname(self.ledger_path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(self.ledger_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    # ------------------------------------------------------------------
    def policy(self) -> dict[str, Any]:
        """导出可公示的闸门策略 —— 可直接进 AI BOM 与证据包。"""
        return {
            "threshold": self.threshold.value,
            "backend": getattr(self.backend, "name", "?"),
            "amount_trigger": self.amount,
            "risk_table": {k: v.value for k, v in sorted(RISK_TABLE.items())},
            "default_deny": True,
            "note": "审批闸门是责任边界，不是安全边界。它保证'有人签字'，"
                    "不保证'这件事是安全的'。",
        }


__all__ = [
    "ApprovalGate", "GateDecision", "Risk", "HeuristicBackend",
    "LayaBackend", "RISK_TABLE",
]
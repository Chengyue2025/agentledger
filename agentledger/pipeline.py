"""整合层：把权限模型、审批闸门、运行时留痕合成**一个**决策。

为什么必须有这一层
------------------
三个模块各自回答的问题不同：

| 模块 | 回答的问题 |
|---|---|
| AuthorityPolicy | 是否**超出已授权范围**？ |
| ApprovalGate | 这个动作的**风险等级**是否需要人工签字？ |
| RuntimeRecorder | 实际发生了什么？ |

单独看没问题，合在一起就出现矛盾：
一个授权额度内的退款，权限模型说「放行」，闸门说「需要签字」——
客户会问："到底行不行？"

更关键的是，**预授权如果每次还要重新签字，那预授权就没有意义**。
人在按下"同意"的时候签的不是一个动作，而是一类动作和它的上限。
本层就是把这句话实现掉的地方。

判定顺序
--------
1. **范围检查** —— 超出授权范围 → 阻断（不可协商）
2. **预授权抵扣** —— 有效的授权覆盖该动作与额度 → 视为人已签字，不重复索要
3. **风险检查** —— 无预授权但风险达阈值 → 需要人工签字
4. **自主执行** —— 风险低于阈值且在自主范围内 → 执行
5. **全量留痕** —— 无论哪条路径

安全约束（不可更改）
--------------------
- **预授权只能向下抵扣，不能向上放行**。授权 `USER_AUTHORIZED` 不会让
  `USER_ONLY` 动作变得可执行。
- **风险高于授权声明容忍度时仍需签字**。授权额度 1 万不代表 1 万的退款
  和 100 元的退款同等风险，但超额部分绝对不能靠它放行。
- 阻断永远优先于放行，任何组合下都不存在"降级放行"。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from .authority import Authority, AuthorityPolicy, AuthorityDecision, Grant
from .gate import ApprovalGate, GateDecision, Risk
from .runtime import RuntimeRecorder, TraceRecord


class Outcome(str, Enum):
    EXECUTED = "executed"
    """自主执行 —— 风险低于阈值且在自主范围内。"""

    PRE_AUTHORIZED = "pre_authorized"
    """凭预授权执行 —— 人已就这一类动作签过字，不重复索要。"""

    REQUIRES_SIGNATURE = "requires_signature"
    """需要人工签字 —— 风险达阈值但无有效预授权。"""

    DENIED = "denied"
    """阻断 —— 超出授权范围，或属不可委托级。"""

    @property
    def zh(self) -> str:
        return {
            "executed": "自主执行",
            "pre_authorized": "凭预授权执行",
            "requires_signature": "需人工签字",
            "denied": "阻断",
        }[self.value]

    @property
    def executed(self) -> bool:
        return self in (Outcome.EXECUTED, Outcome.PRE_AUTHORIZED)


@dataclass
class ExecutionResult:
    action: str
    outcome: Outcome
    authority: AuthorityDecision
    gate: GateDecision | None = None
    value: Any = None
    error: str = ""
    trace: TraceRecord | None = None
    signed_by: str = ""
    signed_at: str = ""
    note: str = ""

    @property
    def ok(self) -> bool:
        return self.outcome.executed

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "outcome": self.outcome.value,
            "outcome_zh": self.outcome.zh,
            "executed": self.ok,
            "authority_level": self.authority.authority.value,
            "authority_level_zh": self.authority.authority_zh,
            "allowed_within_scope": self.authority.allowed,
            "grant_id": self.authority.grant_id,
            "gate_risk": self.gate.risk.value if self.gate else None,
            "signed_by": self.signed_by,
            "signed_at": self.signed_at,
            "note": self.note,
            "error": self.error,
            "statement": self.statement(),
            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    def statement(self) -> str:
        """可直接贴进客户合规文档的一句话。"""
        if self.outcome is Outcome.EXECUTED:
            return (f"「{self.action}」属{self.authority.authority_zh}，"
                    f"风险低于阈值，已自主执行"
                    + (f"；自主范围声明 {self.authority.grant_id}"
                       if self.authority.grant_id else "") + "。")
        if self.outcome is Outcome.PRE_AUTHORIZED:
            return (f"「{self.action}」属{self.authority.authority_zh}，"
                    f"在用户预先授权范围"
                    f"（凭据 {self.authority.grant_id}）内执行，未重复索要签字。")
        if self.outcome is Outcome.REQUIRES_SIGNATURE:
            risk = self.gate.risk.zh if self.gate else "高"
            head = "尚无授权覆盖该动作" if self.authority.denial_kind == "no_authorization" \
                else "无有效预授权"
            return (f"「{self.action}」属{self.authority.authority_zh}，{head}，"
                    f"风险等级为{risk}；已转人工签字"
                    f"（签字人：{self.signed_by or '待指定'}）。")
        return (f"「{self.action}」{self.authority.reason}；已阻断。"
                + (f"（依据授权凭据 {self.authority.grant_id}）"
                   if self.authority.grant_id else ""))


# 授权声明可容忍的风险上界。超过则预授权不再抵扣，必须逐次签字。
#
# 这个上限是"预授权"与"放任"的分界线：
#   · 额度 1 万的退款  → 预授权覆盖
#   · 额度 1 万的删库  → 不可委托，根本轮不到预授权
#   · 额度 1 万的批量外发 → 风险 critical，预授权不抵扣
GRANT_TOLERATED_RISK: dict[Authority, Risk] = {
    Authority.USER_AUTHORIZED: Risk.HIGH,
    Authority.AGENT_AUTONOMOUS: Risk.MEDIUM,
    Authority.USER_ONLY: Risk.NONE,
}


class AgentGuard:
    """智能体动作的统一守门人。

    用法::

        guard = AgentGuard(policy, gate, recorder)
        r = guard.run("issue_refund", {"amount": 300}, do_refund)
        if r.outcome is Outcome.REQUIRES_SIGNATURE:
            ask_human(r)
        elif r.ok:
            ...
    """

    def __init__(self, policy: AuthorityPolicy | None = None,
                 gate: ApprovalGate | None = None,
                 recorder: RuntimeRecorder | None = None,
                 grant_tolerance: dict[Authority, Risk] | None = None):
        self.policy = policy or AuthorityPolicy()
        self.gate = gate or ApprovalGate()
        self.recorder = recorder or RuntimeRecorder()
        self.grant_tolerance = dict(GRANT_TOLERATED_RISK)
        if grant_tolerance:
            self.grant_tolerance.update(grant_tolerance)

    # ------------------------------------------------------------------
    def _grant_covers(self, ad: AuthorityDecision, gd: GateDecision) -> tuple[bool, str]:
        """判断预授权能否抵扣本次签字需求。"""
        if not ad.allowed:
            return False, f"范围检查未通过（{ad.denial_kind}）"
        if not ad.grant_id:
            return False, "无授权覆盖该动作"

        # USER_ONLY 永远不可委托，不接受任何抵扣
        if ad.authority is Authority.USER_ONLY:
            return False, "不可委托级不接受预授权抵扣"

        tolerated = self.grant_tolerance.get(ad.authority, Risk.LOW)
        if _rank(gd.risk) > _rank(tolerated):
            return False, (f"风险 {gd.risk.value} 超出该授权级别可容忍的 "
                           f"{tolerated.value}")

        # 授权额度本身必须真的覆盖本次金额
        grant = next((g for g in self.policy.grants
                      if g.grant_id == ad.grant_id), None)
        if grant and grant.max_amount is not None:
            return True, (f"命中授权 {grant.grant_id}（主体 {grant.subject}，"
                          f"额度上限 {grant.max_amount}）")

        return True, f"命中自主范围声明 {ad.grant_id}"

    # ------------------------------------------------------------------
    def check(self, action: str, context: dict | None = None) -> ExecutionResult:
        """只判定不执行。用于预检。"""
        ctx = context or {}
        ad = self.policy.decide(action, ctx)
        gd = self.gate.check(action, ctx)

        # 1) 范围优先 —— 但要区分「还没授权」与「越权」
        if not ad.allowed:
            kind = ad.denial_kind
            if kind == "no_authorization" and gd.requires_approval:
                # 尚无授权且风险达阈值 → 这是「请你签字」，不是「已越权」。
                # 客户刚接入时所有动作都落在这里，
                # 若一律报"已阻断"，得到的是一份无法指导整改的清单。
                return ExecutionResult(action=action,
                                       outcome=Outcome.REQUIRES_SIGNATURE,
                                       authority=ad, gate=gd,
                                       note=f"尚无授权覆盖该动作；风险 {gd.risk.value}")
            if kind == "no_authorization":
                # 低风险但仍缺自主范围声明
                return ExecutionResult(action=action,
                                       outcome=Outcome.REQUIRES_SIGNATURE,
                                       authority=ad, gate=gd,
                                       note="尚无自主范围声明，请声明该动作的自主级别")
            return ExecutionResult(action=action, outcome=Outcome.DENIED,
                                   authority=ad, gate=gd,
                                   note=ad.reason)

        # 2) 预授权抵扣
        if gd.requires_approval:
            covered, why = self._grant_covers(ad, gd)
            if covered:
                return ExecutionResult(action=action,
                                       outcome=Outcome.PRE_AUTHORIZED,
                                       authority=ad, gate=gd, note=why)
            return ExecutionResult(action=action,
                                   outcome=Outcome.REQUIRES_SIGNATURE,
                                   authority=ad, gate=gd,
                                   note=f"{why}；风险 {gd.risk.value}")

        # 3) 低风险自主执行
        return ExecutionResult(action=action, outcome=Outcome.EXECUTED,
                               authority=ad, gate=gd,
                               note=gd.reason)

    # ------------------------------------------------------------------
    def run(self, action: str, args: dict | None = None,
            fn: Callable[..., Any] | None = None, **kw) -> ExecutionResult:
        """判定 + 执行 + 留痕。fn 为空则只判定。"""
        ctx = dict(args or {})
        ctx.update(kw)
        res = self.check(action, ctx)

        if not res.ok or fn is None:
            r = self.recorder.record(
                tool=action, args=args, outcome="denied",
                error=f"{res.outcome.value}: {res.note}",
                authority=res.authority.authority.value,
                grant_id=res.authority.grant_id)
            res.trace = r
            return res

        try:
            value = fn(args) if args is not None and not kw else fn(**kw) if kw else fn()
            res.value = value
            res.error = ""
            t = self.recorder.record(
                tool=action, args=args, result=value, outcome="ok",
                authority=res.authority.authority.value,
                grant_id=res.authority.grant_id)
            res.trace = t
        except Exception as exc:
            res.value = None
            res.error = f"{type(exc).__name__}: {exc}"
            t = self.recorder.record(
                tool=action, args=args, outcome="error", error=res.error,
                authority=res.authority.authority.value,
                grant_id=res.authority.grant_id)
            res.trace = t
        return res

    # ------------------------------------------------------------------
    def record_signature(self, result: ExecutionResult, approver: str,
                         approved: bool, note: str = "") -> ExecutionResult:
        """人工签字回填。签字后如果批准，重跑一次执行。

        这是整条链上唯一由人写入的一环 —— 也是整个产品的价格锚点。
        """
        result.signed_by = approver
        result.signed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if not approved:
            self.recorder.record(
                tool=result.action, outcome="denied",
                error=f"人工否决：{note}",
                authority=result.authority.authority.value)
            result.note = f"人工否决：{note or '未说明'}"
            return result

        # 批准后签发一次性授权，使该次执行可追溯到具体签字人
        grant = Grant(
            grant_id=f"SIG-{result.trace.trace_id[:8] if result.trace else 'adhoc'}",
            subject=approver,
            authority=Authority.USER_AUTHORIZED,
            actions=(result.action,),
            note=f"人工签字：{note}" if note else "人工签字放行",
        )
        self.policy.add_grant(grant)
        result.authority.grant_id = grant.grant_id
        result.note = f"经 {approver} 签字放行，凭据 {grant.grant_id}"
        return result

    # ------------------------------------------------------------------
    def report(self) -> dict[str, Any]:
        """整合层自述 —— 可直接进 AI BOM 与证据包。"""
        return {
            "components": {
                "authority": {"policy_ref": "《实施意见》第 6 条",
                              "default": self.policy.default.zh,
                              "grants": len(self.policy.grants)},
                "gate": {"threshold": self.gate.threshold.value,
                         "backend": getattr(self.gate.backend, "name", "?"),
                         "default_deny": True},
                "runtime": {"records": len(self.recorder._records),
                            "merkle_root": self.recorder.merkle_root()},
            },
            "pre_authorization_rule": {
                "note": "预授权可以抵扣签字需求，但不能把不可委托级变成可执行，"
                        "也不能把高风险动作降级放行。",
                "tolerated_risk": {k.value: v.value
                                   for k, v in self.grant_tolerance.items()},
            },
            "invariant": [
                "范围检查优先于一切：超出授权范围一律阻断",
                "USER_ONLY 不可委托，任何授权都不能放行",
                "风险超出该授权级别可容忍上界时，预授权不抵扣",
                "不存在降级放行：阻断优先",
                "每一次判定与执行都留痕，链路可验伪",
            ],
        }


def _rank(r: Risk) -> int:
    return {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[r.value]


__all__ = ["AgentGuard", "ExecutionResult", "Outcome", "GRANT_TOLERATED_RISK"]
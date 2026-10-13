"""三级决策权限模型 —— 对齐《智能体规范应用与创新发展实施意见》第 6 条原文。

政策原文
--------
> 厘清仅限用户本人决策、需由用户授权决策和智能体自主决策等各种决策方式的
> 合理边界及所需权限。确保用户对智能体自主决策享有知情权和最终决策权，
> 智能体执行操作不得超出用户授权范围。

这段话给了三样可以直接工程化的东西：

1. **三级权限模型** —— 不再是"拦 / 不拦"的二元判定
2. **签字人** —— 每种权限对应不同的责任主体
3. **授权范围（scope）** —— "不得超出用户授权范围"意味着需要一个可校验的边界，
   超出即阻断，而不是"事后追究"

为什么值得单独做一个模块
----------------------
二进制闸门（要审批 / 不要审批）能回答"能不能做"，但回答不了客户合规文档里
必问的三句话：

- 这个动作属于哪一级权限？
- 谁批准的？授权范围多大？
- 这次执行是否超出了上次的授权？

本模块把这三句话变成可机读、可留痕、可审计的字段。
客户可以直接把输出贴进自己的合规文档，不需要做术语转换。

**这是个转换成本问题，不是营销问题。** 省掉客户的一次翻译，
往往比多加十条检测规则更能推进成交。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Authority(str, Enum):
    """三级决策权限。命名刻意与政策原文一致，便于客户复用。"""

    USER_ONLY = "user_only"
    """仅限用户本人决策 —— 智能体不得自主执行，必须由用户本人操作或明示授权。"""

    USER_AUTHORIZED = "user_authorized"
    """需由用户授权决策 —— 智能体可在授权范围内自主执行，授权可预先授予。"""

    AGENT_AUTONOMOUS = "agent_autonomous"
    """智能体自主决策 —— 在已声明的自主范围内自行决策，受授权范围上界约束。"""

    @property
    def zh(self) -> str:
        return {
            "user_only": "仅限用户本人决策",
            "user_authorized": "需由用户授权决策",
            "agent_autonomous": "智能体自主决策",
        }[self.value]

    @property
    def rank(self) -> int:
        """自主程度由低到高。排序用于"超权"判定。"""
        return {"user_only": 0, "user_authorized": 1, "agent_autonomous": 2}[self.value]


class ScopeViolation(str, Enum):
    """超出授权范围的类型。对应"不得超出用户授权范围"。"""

    NONE = "none"
    AMOUNT_EXCEEDED = "amount_exceeded"
    ACTION_NOT_GRANTED = "action_not_granted"
    FIELD_NOT_ALLOWED = "field_not_allowed"
    CHANNEL_NOT_ALLOWED = "channel_not_allowed"
    TIME_WINDOW_EXCEEDED = "time_window_exceeded"
    AUTONOMY_LEVEL_EXCEEDED = "autonomy_level_exceeded"


# 阻断级别：超权一律阻断，不给"降级放行"的余地。
# 理由：授权范围的语义就是上界，"稍微超一点"在合规上没有意义。
BLOCKING_VIOLATIONS = frozenset(v for v in ScopeViolation if v is not ScopeViolation.NONE)


# ==========================================================================
@dataclass
class Grant:
    """一次授权。授权是可以被审计的独立对象，不是散落在代码里的布尔值。"""

    grant_id: str
    subject: str                       # 被授权的主体（用户 / 角色 / 部门）
    authority: Authority
    actions: tuple[str, ...] = ()      # 允许的动作；空 = 该级别下全部
    max_amount: float | None = None
    allowed_fields: tuple[str, ...] = ()
    allowed_channels: tuple[str, ...] = ()   # email / sms / api / internal
    valid_from: str = ""
    valid_until: str = ""
    note: str = ""
    granted_at: str = ""

    def __post_init__(self) -> None:
        if not self.granted_at:
            self.granted_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def to_dict(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        d["actions"] = list(self.actions)
        d["allowed_fields"] = list(self.allowed_fields)
        d["allowed_channels"] = list(self.allowed_channels)
        return d


@dataclass
class AuthorityDecision:
    """权限判定结果。这就是要进证据包和合规文档的东西。"""

    action: str
    authority: Authority
    allowed: bool
    signer_role: str                  # 谁必须签字 / 已经签了
    reason: str
    violations: list[str] = field(default_factory=list)
    grant_id: str = ""
    matched_scope: dict[str, Any] = field(default_factory=dict)
    policy_ref: str = "《实施意见》第 6 条"
    decided_at: str = ""

    def __post_init__(self) -> None:
        if not self.decided_at:
            self.decided_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    @property
    def authority_zh(self) -> str:
        return self.authority.zh

    # ------------------------------------------------------------------
    @property
    def denial_kind(self) -> str:
        """阻断原因分类。

        这两类必须分开，产品上的含义完全不同：

        - ``no_authorization`` —— **根本还没有授权**。
          客户刚接入智能体时，每个动作都落在这里。
          正确的产品行为是「请你签字」，不是「已越权」。
        - ``scope_violation`` —— 授权存在，但本次执行超出了范围
          （金额/字段/通道/级别）。
          这是真正的越权，必须阻断。

        把两者混为一谈，会让新客户一接入就看到「全部阻断」，
        既不准确也无法指导整改。
        """
        if self.allowed:
            return ""
        if self.authority is Authority.USER_ONLY:
            return "non_delegable"
        if set(self.violations) <= {ScopeViolation.ACTION_NOT_GRANTED.value}:
            return "no_authorization"
        return "scope_violation"

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "authority": self.authority.value,
            "authority_zh": self.authority_zh,
            "allowed": self.allowed,
            "signer_role": self.signer_role,
            "reason": self.reason,
            "violations": self.violations,
            "grant_id": self.grant_id,
            "matched_scope": self.matched_scope,
            "policy_ref": self.policy_ref,
            "decided_at": self.decided_at,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    def to_statement(self) -> str:
        """一句可直接贴进合规文档的话。

        要求：只出现政策原文里的说法，不出现内部机器码。
        客户拿到这句话不需要做术语转换。
        """
        if self.allowed:
            scope = self.matched_scope or {}
            limit = []
            if scope.get("max_amount") is not None:
                limit.append(f"金额上限 {scope['max_amount']}")
            if scope.get("allowed_fields") and scope["allowed_fields"] != ["*"]:
                limit.append(f"字段 {scope['allowed_fields']}")
            if scope.get("allowed_channels") and scope["allowed_channels"] != ["*"]:
                limit.append(f"通道 {scope['allowed_channels']}")
            if scope.get("valid_until"):
                limit.append(f"有效至 {scope['valid_until']}")
            tail = f"，授权范围：{'；'.join(limit)}" if limit else ""
            return (f"「{self.action}」属{self.authority_zh}，由{self.signer_role}负责；"
                    f"已匹配授权凭据 {self.grant_id}{tail}。")

        if self.authority is Authority.USER_ONLY:
            return (f"「{self.action}」属{self.authority_zh}，属不可委托级，"
                    f"须由用户本人执行（{self.signer_role}）；已阻断智能体自主执行。")

        if self.violations and set(self.violations) == {ScopeViolation.AUTONOMY_LEVEL_EXCEEDED.value}:
            return (f"「{self.action}」属{self.authority_zh}，但当前缺少覆盖该动作的"
                    f"{'自主范围声明' if self.authority is Authority.AGENT_AUTONOMOUS else '有效授权'}，"
                    f"已阻断；依据{self.policy_ref}「智能体执行操作不得超出用户授权范围」。")

        human = {
            ScopeViolation.AMOUNT_EXCEEDED.value: "金额超出授权上界",
            ScopeViolation.ACTION_NOT_GRANTED.value: "未获授权的动作",
            ScopeViolation.FIELD_NOT_ALLOWED.value: "涉及授权范围外的字段",
            ScopeViolation.CHANNEL_NOT_ALLOWED.value: "使用授权范围外的通道",
            ScopeViolation.TIME_WINDOW_EXCEEDED.value: "授权已过期",
        }
        why = "、".join(human.get(v, v) for v in self.violations) or "未获授权"
        return (f"「{self.action}」属{self.authority_zh}，{why}，已阻断；"
                f"依据{self.policy_ref}「智能体执行操作不得超出用户授权范围」。")


# ==========================================================================
# 默认权限策略
# ==========================================================================
# 没有显式声明时采用的分级。刻意保守：默认 USER_ONLY。
#
# 这一档的选择是整个模块里最重要的一个决定。
# 取 USER_ONLY 的代价是审批变多；取 AGENT_AUTONOMOUS 的代价是
# 一旦出现提示注入，客户资金直接损失且无人签字。
# 后者不可逆，前者可逆 —— 所以选前者。
DEFAULT_AUTHORITY: dict[str, Authority] = {
    # 不可逆 / 资金 —— 必须用户本人
    "payment": Authority.USER_ONLY,
    "transfer_funds": Authority.USER_ONLY,
    "wire": Authority.USER_ONLY,
    "delete_account": Authority.USER_ONLY,
    "drop_table": Authority.USER_ONLY,
    "issue_refund": Authority.USER_AUTHORIZED,
    "charge": Authority.USER_AUTHORIZED,
    "rotate_secret": Authority.USER_AUTHORIZED,
    "grant_permission": Authority.USER_AUTHORIZED,
    # 对外通道 —— 可预授权
    "send_email": Authority.USER_AUTHORIZED,
    "send_email_bulk": Authority.USER_ONLY,
    "send_message": Authority.USER_AUTHORIZED,
    "publish": Authority.USER_AUTHORIZED,
    "deploy": Authority.USER_AUTHORIZED,
    # 常规写操作
    "modify_address": Authority.USER_AUTHORIZED,
    "order_cancel": Authority.USER_AUTHORIZED,
    "delete": Authority.USER_AUTHORIZED,
    # 只读 —— 自主
    "read": Authority.AGENT_AUTONOMOUS,
    "lookup": Authority.AGENT_AUTONOMOUS,
    "search": Authority.AGENT_AUTONOMOUS,
    "summarize": Authority.AGENT_AUTONOMOUS,
    "answer_faq": Authority.AGENT_AUTONOMOUS,
}

SIGNER_ROLE: dict[Authority, str] = {
    Authority.USER_ONLY: "用户本人（不可代签）",
    Authority.USER_AUTHORIZED: "授权人（可预授权，到期自动失效）",
    Authority.AGENT_AUTONOMOUS: "无需签字（受自主范围声明约束，用户保留知情权）",
}


# ==========================================================================
class AuthorityPolicy:
    """决策权限判定器。

    用法::

        pol = AuthorityPolicy()
        d = pol.decide("issue_refund", {"amount": 80000})
        if not d.allowed:
            request_human_approval(d)
        else:
            pol.execute_with_grant(d, grants)

    核心约束：
      - **没有匹配到授权 = 阻断**，不存在"默认可执行"
      - **USER_ONLY 永远阻断**，无论是否匹配到授权 ——
        政策说的就是"仅限用户本人决策"，含义是不可委托
      - 每次判定都产出可贴进合规文档的结论
    """

    VERSION = "1.0"

    def __init__(self, table: dict[str, Authority] | None = None,
                 default: Authority = Authority.USER_ONLY,
                 grants: list[Grant] | None = None):
        self.table: dict[str, Authority] = dict(DEFAULT_AUTHORITY)
        if table:
            self.table.update(table)
        self.default = default
        self.grants: list[Grant] = list(grants or [])

    # ------------------------------------------------------------------
    def add_grant(self, grant: Grant) -> Grant:
        self.grants.append(grant)
        return grant

    def revoke_grant(self, grant_id: str) -> bool:
        before = len(self.grants)
        self.grants = [g for g in self.grants if g.grant_id != grant_id]
        return len(self.grants) < before

    # ------------------------------------------------------------------
    def authority_for(self, action: str) -> Authority:
        key = (action or "").strip().lower().replace("-", "_")
        return self.table.get(key, self.default)

    # ------------------------------------------------------------------
    def _declared_authority(self, action: str) -> Authority:
        """判定该动作所属的权限级别。

        关键设计：**授权本身��是自主范围声明**。

        《实施意见》第 6 条要求"厘清……各种决策方式的合理边界及所需权限"。
        客户在自己的清单里声明 `lookup_order` 属于自主范围，这件事本身就是
        一次声明 —— 不应该因为内置词表里没有 `lookup_order` 就退回最严的一档，
        否则内置表会变成事实上的强制口径，客户无法自定义。

        因此分类顺序：
          1. 内置表命中 → 用内置值
          2. 未命中但有授权覆盖该动作 → 取这些授权里**最高**的权限级别
             （授权是显式声明，不能被更低级别的授权降级）
          3. 都没有 → 默认级别（USER_ONLY，最保守）
        """
        key = (action or "").strip().lower().replace("-", "_")
        declared = self.table.get(key)
        if declared is not None:
            return declared

        covered = [g.authority for g in self.grants
                   if not g.actions or key in [a.lower() for a in g.actions]]
        if covered:
            return max(covered, key=lambda a: a.rank)
        return self.default

    # ------------------------------------------------------------------
    def _time_ok(self, grant: Grant, now: float) -> bool:
        if grant.valid_from:
            try:
                if now < time.mktime(time.strptime(grant.valid_from, "%Y-%m-%dT%H:%M:%SZ")) - time.timezone:
                    return False
            except (ValueError, OverflowError):
                pass
        if grant.valid_until:
            try:
                if now > time.mktime(time.strptime(grant.valid_until, "%Y-%m-%dT%H:%M:%SZ")) - time.timezone:
                    return False
            except (ValueError, OverflowError):
                pass
        return True

    # ------------------------------------------------------------------
    def decide(self, action: str, context: dict | None = None) -> AuthorityDecision:
        """判定一个动作应归哪一级权限，以及当前是否被授权执行。"""
        context = context or {}
        key = (action or "").strip().lower().replace("-", "_")
        authority = self._declared_authority(key)
        violations: list[str] = []
        notes: list[str] = [f"动作 '{key}' 归类为{authority.zh}"]

        # --- USER_ONLY：不可委托，直接阻断 ---
        if authority is Authority.USER_ONLY:
            return AuthorityDecision(
                action=action, authority=authority, allowed=False,
                signer_role=SIGNER_ROLE[Authority.USER_ONLY],
                reason="；".join(notes) + "；该级为不可委托级，必须由用户本人执行",
                violations=[ScopeViolation.ACTION_NOT_GRANTED.value],
            )

        # --- 找可用授权 ---
        now = time.time()
        amount = context.get("amount")
        fields = context.get("data") or context.get("fields") or []
        channel = context.get("channel")
        channel = str(channel).lower() if channel else None

        for grant in self.grants:
            if grant.authority.rank < authority.rank:
                continue
            if grant.actions and key not in [a.lower() for a in grant.actions]:
                continue
            if not self._time_ok(grant, now):
                continue

            # 金额上界
            if grant.max_amount is not None and isinstance(amount, (int, float)):
                if amount > grant.max_amount:
                    violations.append(ScopeViolation.AMOUNT_EXCEEDED.value)
                    notes.append(f"金额 {amount} 超出授权上界 {grant.max_amount}")
                    continue

            # 字段白名单
            if grant.allowed_fields:
                extra = [f for f in fields
                         if str(f) not in grant.allowed_fields]
                if extra:
                    violations.append(ScopeViolation.FIELD_NOT_ALLOWED.value)
                    notes.append(f"字段 {extra} 不在授权白名单 {list(grant.allowed_fields)}")
                    continue

            # 通道白名单
            if grant.allowed_channels and channel:
                if channel not in [c.lower() for c in grant.allowed_channels]:
                    violations.append(ScopeViolation.CHANNEL_NOT_ALLOWED.value)
                    notes.append(f"通道 '{channel}' 不在授权范围 {list(grant.allowed_channels)}")
                    continue

            # 自主级别上界：USER_AUTHORIZED 授权不能放行 AGENT_AUTONOMOUS
            if grant.authority is Authority.USER_AUTHORIZED and \
                    authority is Authority.AGENT_AUTONOMOUS:
                violations.append(ScopeViolation.AUTONOMY_LEVEL_EXCEEDED.value)
                notes.append("授权级别低于该动作要求的自主级别")
                continue

            return AuthorityDecision(
                action=action, authority=authority, allowed=True,
                signer_role=SIGNER_ROLE[authority],
                reason="；".join(notes) + f"；命中授权 {grant.grant_id}（{grant.subject}）",
                grant_id=grant.grant_id,
                matched_scope={
                    "actions": list(grant.actions) or ["*"],
                    "max_amount": grant.max_amount,
                    "allowed_fields": list(grant.allowed_fields) or ["*"],
                    "allowed_channels": list(grant.allowed_channels) or ["*"],
                    "valid_until": grant.valid_until or None,
                },
            )

        # --- 无可用授权 ---
        if authority is Authority.AGENT_AUTONOMOUS:
            # 自主决策级：默认允许，但必须有显式的自主范围声明
            violations.append(ScopeViolation.AUTONOMY_LEVEL_EXCEEDED.value)
            notes.append("未找到覆盖该动作的自主范围声明，按需补充")
            return AuthorityDecision(
                action=action, authority=authority, allowed=False,
                signer_role=SIGNER_ROLE[Authority.AGENT_AUTONOMOUS],
                reason="；".join(notes),
                violations=violations,
            )

        return AuthorityDecision(
            action=action, authority=authority, allowed=False,
            signer_role=SIGNER_ROLE[authority],
            reason="；".join(notes) + "；未找到覆盖该动作的有效授权",
            violations=violations or [ScopeViolation.ACTION_NOT_GRANTED.value],
        )

    # ------------------------------------------------------------------
    def explain(self) -> dict[str, Any]:
        """导出权限矩阵 —— 可直接进 AI BOM 与证据包。"""
        return {
            "version": self.VERSION,
            "policy_ref": "《智能体规范应用与创新发展实施意见》第 6 条",
            "policy_quote": "厘清仅限用户本人决策、需由用户授权决策和智能体自主决策"
                            "等各种决策方式的合理边界及所需权限……"
                            "智能体执行操作不得超出用户授权范围。",
            "default_authority": self.default.value,
            "default_authority_zh": self.default.zh,
            "levels": [
                {"level": a.value, "zh": a.zh, "signer_role": SIGNER_ROLE[a]}
                for a in Authority
            ],
            "authority_table": {k: v.value for k, v in sorted(self.table.items())},
            "active_grants": [g.to_dict() for g in self.grants],
            "notes": [
                "USER_ONLY 为不可委托级：无论是否匹配到授权都必须由用户本人执行。",
                "无匹配授权一律阻断，不存在默认可执行。",
                "授权是可审计对象（grant_id / 主体 / 范围 / 有效期），不是布尔值。",
            ],
        }


__all__ = [
    "AuthorityPolicy", "AuthorityDecision", "Authority",
    "Grant", "ScopeViolation",
]
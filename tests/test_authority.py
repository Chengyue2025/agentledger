"""三级决策权限模型测试。

锁定的核心行为：
  1. USER_ONLY 永远不可委托 —— 政策说"仅限用户本人决策"
  2. 无授权 = 阻断，不存在默认可执行
  3. 授权是对象（可审计），不是布尔值
  4. 每条判定都能产出一句可直接贴进合规文档的话
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentledger.authority import (  # noqa: E402
    Authority, AuthorityPolicy, Grant, ScopeViolation,
)


class TestUserOnlyIsNonDelegable(unittest.TestCase):
    """政策原文："仅限用户本人决策"。含义是不可委托。"""

    def test_user_only_blocked_even_with_matching_grant(self):
        pol = AuthorityPolicy(grants=[Grant(
            grant_id="G-1", subject="运营部", authority=Authority.USER_ONLY,
            actions=("payment",),
        )])
        d = pol.decide("payment", {})
        self.assertFalse(d.allowed, "USER_ONLY 竟被一笔 USER_ONLY 授权放行")
        self.assertEqual(d.authority, Authority.USER_ONLY)

    def test_user_only_cannot_be_upgraded_by_grant(self):
        """更宽松的授权也不能把 USER_ONLY 提上去。"""
        pol = AuthorityPolicy(grants=[Grant(
            grant_id="G-2", subject="CTO", authority=Authority.AGENT_AUTONOMOUS,
            actions=("payment",), max_amount=10_000_000,
        )])
        self.assertFalse(pol.decide("payment", {}).allowed,
                         "高自主级别授权不得绕过 USER_ONLY")

    def test_signature_role_says_not_delegable(self):
        d = AuthorityPolicy().decide("delete_account", {})
        self.assertIn("不可代签", d.signer_role)


class TestNoDefaultAllow(unittest.TestCase):
    def test_ungranted_action_is_blocked(self):
        d = AuthorityPolicy().decide("issue_refund", {})
        self.assertFalse(d.allowed)
        self.assertIn("未找到覆盖该动作的有效授权", d.reason)

    def test_unknown_action_defaults_to_user_only(self):
        d = AuthorityPolicy().decide("frobnicate_thing", {})
        self.assertEqual(d.authority, Authority.USER_ONLY)
        self.assertFalse(d.allowed)


class TestGrantScopeEnforcement(unittest.TestCase):
    """「不得超出用户授权范围」必须可校验，而不是事后追究。"""

    def setUp(self):
        self.pol = AuthorityPolicy(grants=[Grant(
            grant_id="G-CS", subject="客服主管 张三", authority=Authority.USER_AUTHORIZED,
            actions=("issue_refund",),
            max_amount=10_000,
            allowed_fields=("order_no", "amount"),
            allowed_channels=("email",),
        )])

    def test_within_scope_is_allowed(self):
        d = self.pol.decide("issue_refund", {
            "amount": 5000, "data": ["order_no"], "channel": "email"})
        self.assertTrue(d.allowed)
        self.assertEqual(d.grant_id, "G-CS")

    def test_amount_over_limit_is_blocked(self):
        d = self.pol.decide("issue_refund", {"amount": 50_000})
        self.assertFalse(d.allowed)
        self.assertIn(ScopeViolation.AMOUNT_EXCEEDED.value, d.violations)

    def test_field_outside_whitelist_is_blocked(self):
        d = self.pol.decide("issue_refund", {
            "amount": 100, "data": ["order_no", "id_card"]})
        self.assertFalse(d.allowed)
        self.assertIn(ScopeViolation.FIELD_NOT_ALLOWED.value, d.violations)

    def test_channel_outside_whitelist_is_blocked(self):
        d = self.pol.decide("issue_refund", {"amount": 100, "channel": "sms"})
        self.assertFalse(d.allowed)
        self.assertIn(ScopeViolation.CHANNEL_NOT_ALLOWED.value, d.violations)

    def test_expired_grant_is_ignored(self):
        pol = AuthorityPolicy(grants=[Grant(
            grant_id="G-OLD", subject="前任", authority=Authority.USER_AUTHORIZED,
            actions=("issue_refund",), valid_until="2020-01-01T00:00:00Z")])
        self.assertFalse(pol.decide("issue_refund", {}).allowed)

    def test_grant_covering_other_action_does_not_apply(self):
        pol = AuthorityPolicy(grants=[Grant(
            grant_id="G-X", subject="X", authority=Authority.USER_AUTHORIZED,
            actions=("deploy",))])
        self.assertFalse(pol.decide("issue_refund", {}).allowed)


class TestAutonomyLevels(unittest.TestCase):
    def test_readonly_needs_explicit_autonomy_declaration(self):
        """自主决策级也必须有声明，否则用户"知情权"无从谈起。"""
        d = AuthorityPolicy().decide("read", {})
        self.assertEqual(d.authority, Authority.AGENT_AUTONOMOUS)
        self.assertFalse(d.allowed)
        self.assertIn(ScopeViolation.AUTONOMY_LEVEL_EXCEEDED.value, d.violations)

    def test_autonomy_grant_unlocks_readonly(self):
        pol = AuthorityPolicy(grants=[Grant(
            grant_id="G-AUTO", subject="系统", authority=Authority.AGENT_AUTONOMOUS,
            actions=("read", "lookup", "search"))])
        d = pol.decide("read", {})
        self.assertTrue(d.allowed)
        self.assertEqual(d.authority, Authority.AGENT_AUTONOMOUS)

    def test_authorized_grant_cannot_unlock_autonomous_action(self):
        pol = AuthorityPolicy(grants=[Grant(
            grant_id="G-AUTH", subject="X", authority=Authority.USER_AUTHORIZED,
            actions=("read",))])
        d = pol.decide("read", {})
        self.assertFalse(d.allowed, "USER_AUTHORIZED 授权越级放行了自主决策动作")
        self.assertIn(ScopeViolation.AUTONOMY_LEVEL_EXCEEDED.value, d.violations)


class TestGrantLifecycle(unittest.TestCase):
    def test_revoke_removes_authorization(self):
        pol = AuthorityPolicy()
        pol.add_grant(Grant(grant_id="G1", subject="A",
                            authority=Authority.USER_AUTHORIZED, actions=("issue_refund",)))
        self.assertTrue(pol.decide("issue_refund", {}).allowed)
        self.assertTrue(pol.revoke_grant("G1"))
        self.assertFalse(pol.decide("issue_refund", {}).allowed)

    def test_revoke_unknown_id_returns_false(self):
        self.assertFalse(AuthorityPolicy().revoke_grant("nope"))

    def test_grant_is_a_first_class_audit_object(self):
        g = Grant(grant_id="G1", subject="财务 李四",
                  authority=Authority.USER_AUTHORIZED, actions=("wire",),
                  max_amount=500_000, note="Q3 专项")
        d = g.to_dict()
        for key in ("grant_id", "subject", "authority", "actions",
                    "max_amount", "granted_at", "note"):
            self.assertIn(key, d, f"授权记录缺字段 {key}")
        self.assertTrue(d["granted_at"], "授权必须有授予时间，否则无法追责")


class TestGrantIsAValidDeclaration(unittest.TestCase):
    """授权本身就是一次显式声明，内置词表不得凌驾于客户声明之上。

    否则内置表会变成事实上的强制口径：客户声明了 lookup_order 在自主范围内，
    却因为词表里没这个词而被判最严级 —— 这是不可接受的。
    """

    def test_grant_declares_level_for_unknown_action(self):
        pol = AuthorityPolicy(grants=[Grant(
            grant_id="G", subject="ops", authority=Authority.AGENT_AUTONOMOUS,
            actions=("lookup_order", "weird_internal_tool"))])
        d = pol.decide("lookup_order", {})
        self.assertEqual(d.authority, Authority.AGENT_AUTONOMOUS)
        self.assertTrue(d.allowed, "已显式声明自主范围的动作被误判")

    def test_builtin_table_still_wins_over_grants_for_known_actions(self):
        """内置表对已知动作仍然优先 —— payment 不该因为一笔授权就变成自主级。"""
        pol = AuthorityPolicy(grants=[Grant(
            grant_id="G", subject="x", authority=Authority.AGENT_AUTONOMOUS,
            actions=("payment",))])
        self.assertEqual(pol.decide("payment", {}).authority, Authority.USER_ONLY)

    def test_highest_level_among_grants_is_used(self):
        pol = AuthorityPolicy(grants=[
            Grant(grant_id="G1", subject="a", authority=Authority.USER_AUTHORIZED,
                  actions=("custom_action",)),
            Grant(grant_id="G2", subject="b", authority=Authority.AGENT_AUTONOMOUS,
                  actions=("custom_action",)),
        ])
        self.assertEqual(pol.decide("custom_action", {}).authority,
                         Authority.AGENT_AUTONOMOUS)

    def test_grant_with_open_action_list_covers_everything(self):
        """空 actions = 该级别下全部动作，是一种合法的宽授权。"""
        pol = AuthorityPolicy(grants=[Grant(
            grant_id="G-WIDE", subject="readall", authority=Authority.AGENT_AUTONOMOUS)])
        self.assertTrue(pol.decide("anything_at_all", {}).allowed)


class TestComplianceOutput(unittest.TestCase):
    def test_statement_is_paste_ready(self):
        """产出的句子要能直接贴进客户合规文档，不需要术语转换。"""
        blocked = AuthorityPolicy().decide("payment", {})
        self.assertIn("仅限用户本人决策", blocked.to_statement())
        self.assertIn("不可委托", blocked.to_statement())
        # 不得出现内部机器码
        for code in (v.value for v in ScopeViolation):
            self.assertNotIn(code, blocked.to_statement())

        ungranted = AuthorityPolicy().decide("issue_refund", {})
        self.assertIn("需由用户授权决策", ungranted.to_statement())
        self.assertIn("未获授权的动作", ungranted.to_statement())
        self.assertIn("第 6 条", ungranted.to_statement())

        allowed = AuthorityPolicy(grants=[Grant(
            grant_id="G9", subject="客服主管", authority=Authority.USER_AUTHORIZED,
            actions=("issue_refund",), max_amount=5000)]).decide(
                "issue_refund", {"amount": 100})
        self.assertIn("需由用户授权决策", allowed.to_statement())
        self.assertIn("G9", allowed.to_statement())
        self.assertIn("金额上限 5000", allowed.to_statement())

    def test_explain_carries_policy_quote(self):
        e = AuthorityPolicy().explain()
        self.assertEqual(len(e["levels"]), 3)
        self.assertIn("不得超出用户授权范围", e["policy_quote"])
        self.assertEqual(e["default_authority"], "user_only")

    def test_decision_is_json_serializable(self):
        import json
        d = AuthorityPolicy().decide("issue_refund", {})
        json.loads(d.to_json())


class TestBoundaryConsistency(unittest.TestCase):
    def test_action_outside_grant_amount_still_blocked(self):
        """上界是上界：金额超了就该阻断。"""
        pol = AuthorityPolicy(grants=[Grant(
            grant_id="G", subject="X", authority=Authority.USER_AUTHORIZED,
            actions=("issue_refund",), max_amount=100)])
        self.assertTrue(pol.decide("issue_refund", {"amount": 100}).allowed)
        self.assertFalse(pol.decide("issue_refund", {"amount": 101}).allowed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
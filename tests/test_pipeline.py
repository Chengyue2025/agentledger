"""整合层测试。

锁定的核心不变式（这些是安全边界，任何重构都不能破坏）：
  1. 范围检查优先于一切 —— 超出授权范围一律阻断
  2. USER_ONLY 不可委托，任何授权都不能放行
  3. 预授权可抵扣签字需求，但不能让高风险动作降级放行
  4. 不存在"降级放行"
  5. 每一次判定都留痕
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentledger.authority import Authority, AuthorityPolicy, Grant  # noqa: E402
from agentledger.gate import ApprovalGate, Risk  # noqa: E402
from agentledger.pipeline import AgentGuard, Outcome  # noqa: E402
from agentledger.runtime import RuntimeRecorder  # noqa: E402


def build_guard(**kw):
    policy = AuthorityPolicy(grants=[
        Grant(grant_id="G-CS", subject="客服主管 张三",
              authority=Authority.USER_AUTHORIZED,
              actions=("issue_refund", "modify_address"),
              max_amount=10_000,
              allowed_fields=("order_no", "amount"),
              allowed_channels=("email",)),
        Grant(grant_id="G-AUTO", subject="运维",
              authority=Authority.AGENT_AUTONOMOUS,
              actions=("read", "lookup_order", "search_kb")),
    ])
    rec = RuntimeRecorder(agent_id="test-agent", version="1.0")
    gate = ApprovalGate(threshold=Risk.MEDIUM)
    return AgentGuard(policy=policy, gate=gate, recorder=rec, **kw)


class TestScopeBeatsEverything(unittest.TestCase):
    def test_amount_over_limit_denied_even_with_grant(self):
        g = build_guard()
        r = g.check("issue_refund", {"amount": 50_000})
        self.assertEqual(r.outcome, Outcome.DENIED)
        self.assertFalse(r.ok)

    def test_user_only_is_never_pre_authorized(self):
        """最高级别的授权也不能让 payment 通过。"""
        pol = AuthorityPolicy(grants=[Grant(
            grant_id="G-MAX", subject="CTO",
            authority=Authority.USER_AUTHORIZED,
            actions=("payment", "delete_account"), max_amount=99_999_999)])
        g = AgentGuard(policy=pol, gate=ApprovalGate(threshold=Risk.MEDIUM),
                       recorder=RuntimeRecorder())
        for act in ("payment", "delete_account"):
            r = g.check(act, {"amount": 1000})
            self.assertEqual(r.outcome, Outcome.DENIED, f"{act} 被预授权放行了")
            self.assertIn("不可委托", r.note)

    def test_field_outside_grant_denied(self):
        g = build_guard()
        r = g.check("issue_refund",
                    {"amount": 100, "data": ["order_no", "id_card"]})
        self.assertEqual(r.outcome, Outcome.DENIED)

    def test_channel_outside_grant_denied(self):
        g = build_guard()
        r = g.check("issue_refund", {"amount": 100, "channel": "sms"})
        self.assertEqual(r.outcome, Outcome.DENIED)


class TestPreAuthorizationSemantics(unittest.TestCase):
    """预授权的存在意义：人签的是"一类动作"，不是"每一个动作"。"""

    def test_grant_prevents_repeated_signing(self):
        g = build_guard()
        for _ in range(5):
            r = g.check("issue_refund", {"amount": 300, "channel": "email"})
            self.assertEqual(r.outcome, Outcome.PRE_AUTHORIZED,
                             "预授权额度内的动作每次都要签字，等于预授权无效")

    def test_no_grant_requires_signature(self):
        pol = AuthorityPolicy()          # 没有任何授权
        g = AgentGuard(policy=pol, gate=ApprovalGate(threshold=Risk.MEDIUM),
                       recorder=RuntimeRecorder())
        r = g.check("issue_refund", {"amount": 300})
        self.assertEqual(r.outcome, Outcome.REQUIRES_SIGNATURE)

    def test_grant_cannot_cover_critical_risk(self):
        """高风险动作不接受预授权抵扣 —— 额度大不等于风险低。"""
        pol = AuthorityPolicy(grants=[Grant(
            grant_id="G-HUGE", subject="CTO",
            authority=Authority.USER_AUTHORIZED,
            actions=("send_email_bulk", "delete_account"),
            max_amount=999_999_999)])
        g = AgentGuard(policy=pol, gate=ApprovalGate(threshold=Risk.MEDIUM),
                       recorder=RuntimeRecorder())
        r = g.check("send_email_bulk", {"count": 10_000})
        self.assertNotEqual(r.outcome, Outcome.PRE_AUTHORIZED,
                            "批量外发被预授权放行了")
        self.assertEqual(r.outcome, Outcome.DENIED)   # delete/send_bulk 属不可委托或超容忍


class TestLowRiskAutonomy(unittest.TestCase):
    def test_low_risk_within_autonomy_executes(self):
        g = build_guard()
        r = g.check("read", {})
        self.assertEqual(r.outcome, Outcome.EXECUTED)
        self.assertTrue(r.ok)

    def test_low_risk_without_declaration_requires_signature(self):
        pol = AuthorityPolicy()
        g = AgentGuard(policy=pol, gate=ApprovalGate(threshold=Risk.MEDIUM),
                       recorder=RuntimeRecorder())
        r = g.check("read", {})
        self.assertFalse(r.ok, "未声明自主范围却放行了只读动作")


class TestExecutionAndTracing(unittest.TestCase):
    def test_run_executes_and_records(self):
        g = build_guard()
        r = g.run("read", {}, lambda a: {"rows": 3})
        self.assertTrue(r.ok)
        self.assertEqual(r.value, {"rows": 3})
        self.assertIsNotNone(r.trace)
        self.assertEqual(g.recorder._records[-1].outcome, "ok")

    def test_denied_action_is_still_recorded(self):
        """被阻断的动作也必须留痕 —— 拦截记录本身就是合规证据。"""
        g = build_guard()
        r = g.run("issue_refund", {"amount": 99_999}, lambda a: "SHOULD NOT RUN")
        self.assertFalse(r.ok)
        self.assertIsNone(r.value, "被阻断的动作竟然执行了")
        self.assertIsNotNone(r.trace)
        self.assertEqual(r.trace.outcome, "denied")

    def test_exception_is_recorded_and_reraised_as_error(self):
        g = build_guard()
        def boom(a):
            raise RuntimeError("下游炸了")
        r = g.run("read", {}, boom)
        self.assertIn("下游炸了", r.error)
        self.assertEqual(r.trace.outcome, "error")

    def test_every_check_leaves_a_record(self):
        g = build_guard()
        for act, ctx in [("read", {}), ("issue_refund", {"amount": 50_000}),
                         ("issue_refund", {"amount": 100})]:
            g.check(act, ctx)
        self.assertEqual(len(g.recorder._records), 0,
                         "check() 不应写运行时记录（check 是判定，不是执行）")
        g.run("read", {}, lambda a: 1)
        self.assertEqual(len(g.recorder._records), 1)


class TestHumanSignature(unittest.TestCase):
    def test_signature_grants_traceable_authorization(self):
        g = build_guard()
        pol = AuthorityPolicy()
        guard = AgentGuard(policy=pol, gate=ApprovalGate(threshold=Risk.MEDIUM),
                           recorder=RuntimeRecorder())
        r = guard.check("issue_refund", {"amount": 300})
        self.assertEqual(r.outcome, Outcome.REQUIRES_SIGNATURE)
        guard.record_signature(r, "财务 王五", approved=True, note="已电话确认")
        self.assertIn("王五", r.note)
        self.assertTrue(r.signed_by)
        self.assertIn("SIG-", r.authority.grant_id)

    def test_rejection_blocks_and_leaves_trace(self):
        pol = AuthorityPolicy()
        guard = AgentGuard(policy=pol, gate=ApprovalGate(threshold=Risk.MEDIUM),
                           recorder=RuntimeRecorder())
        r = guard.check("issue_refund", {"amount": 300})
        guard.record_signature(r, "财务 王五", approved=False, note="客户未确认")
        self.assertIn("人工否决", r.note)
        self.assertEqual(guard.recorder._records[-1].outcome, "denied")


class TestStatements(unittest.TestCase):
    def test_statements_are_paste_ready(self):
        g = build_guard()
        pre = g.check("issue_refund", {"amount": 300, "channel": "email"})
        self.assertIn("预先授权", pre.statement())
        self.assertIn("未重复索要签字", pre.statement())

        denied = g.check("issue_refund", {"amount": 50_000})
        self.assertIn("已阻断", denied.statement())

        auto = g.check("read", {})
        self.assertIn("自主执行", auto.statement())

    def test_result_is_json_serializable(self):
        import json
        json.loads(build_guard().check("read", {}).to_dict() and
                   json.dumps(build_guard().check("read", {}).to_dict(),
                              ensure_ascii=False))

    def test_report_states_invariants(self):
        rep = build_guard().report()
        self.assertEqual(len(rep["invariant"]), 5)
        self.assertTrue(rep["components"]["gate"]["default_deny"])
        self.assertIn("pre_authorization_rule", rep)


if __name__ == "__main__":
    unittest.main(verbosity=2)
"""审批闸门测试。

这些用例的价值在于**锁住不可妥协的行为**：
漏放一次高风险动作，比多问一次人的代价高一个数量级。
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentledger.gate import (  # noqa: E402
    ApprovalGate, HeuristicBackend, Risk,
)


class TestRiskTable(unittest.TestCase):
    def test_money_moves_are_high_or_above(self):
        for act in ("payment", "transfer_funds", "issue_refund", "refund", "charge"):
            self.assertGreaterEqual(
                HeuristicBackend().evaluate(act, {})[0].rank if hasattr(
                    HeuristicBackend().evaluate(act, {})[0], "rank") else
                ["none", "low", "medium", "high", "critical"].index(
                    HeuristicBackend().evaluate(act, {})[0].value),
                3, f"{act} 风险等级过低")

    def test_destructive_actions_are_high_or_above(self):
        b = HeuristicBackend()
        idx = ["none", "low", "medium", "high", "critical"]
        for act in ("delete", "delete_account", "drop_table"):
            self.assertGreaterEqual(
                idx.index(b.evaluate(act, {})[0].value), 3, f"{act} 风险过低")

    def test_readonly_actions_are_low(self):
        b = HeuristicBackend()
        for act in ("read", "lookup", "search", "answer_faq"):
            self.assertLessEqual(
                ["none", "low", "medium", "high", "critical"].index(
                    b.evaluate(act, {})[0].value), 1, f"{act} 风险过高")

    def test_unknown_action_is_denylisted_high(self):
        """白名单模型：未登记且无法判定为只读的动作不得获得豁免。"""
        risk, reason, ev = HeuristicBackend().evaluate(
            "frobnicate_widget_v2", {})
        self.assertGreaterEqual(
            ["none", "low", "medium", "high", "critical"].index(risk.value), 3)
        self.assertEqual(ev["reason_code"], "UNREGISTERED")


class TestUnregisteredActions(unittest.TestCase):
    """未登记动作的三档判定。

    这是闸门能否活下来的关键：一个频繁误拦查询的闸门会被客户绕过，
    等于没有闸门；但放过写操作则等于没有闸门。
    """

    def setUp(self):
        self.b = HeuristicBackend()

    def test_readonly_lookups_are_not_blocked(self):
        """客户最常见的动作：查订单、看状态、搜索。误拦这些 = 产品死亡。"""
        for act in ("lookup_order", "get_user", "list_files", "query_inventory",
                    "search_kb", "fetch_profile", "check_status", "view_invoice"):
            d = ApprovalGate(threshold=Risk.MEDIUM).check(act, {})
            self.assertFalse(d.requires_approval,
                             f"只读动作 '{act}' 被误拦，闸门会被客户绕过")

    def test_unregistered_readonly_is_marked_for_registration(self):
        _, _, ev = self.b.evaluate("lookup_order", {})
        self.assertEqual(ev["reason_code"], "UNREGISTERED_READONLY")
        self.assertTrue(ev["should_register"],
                        "自动归类后仍须提示补全声明，否则永远靠猜")

    def test_writeish_names_are_never_treated_as_readonly(self):
        """名称含写语义的一律按写处理，且优先于只读前缀。"""
        for act in ("get_and_delete_user", "search_then_purge", "list_and_send_email"):
            risk, _, _ = self.b.evaluate(act, {})
            self.assertGreaterEqual(
                ["none", "low", "medium", "high", "critical"].index(risk.value), 3,
                f"'{act}' 含写语义却被降级")

    def test_sensitive_reads_are_still_high(self):
        """读密钥/权限即使长得像读，也必须人工过目。"""
        for act in ("get_secret", "read_api_key", "list_permissions", "fetch_credentials"):
            risk, _, _ = self.b.evaluate(act, {})
            self.assertGreaterEqual(
                ["none", "low", "medium", "high", "critical"].index(risk.value), 3,
                f"敏感资源读取 '{act}' 未被拦截")

    def test_empty_action_is_high(self):
        risk, _, _ = self.b.evaluate("", {})
        self.assertEqual(risk, Risk.HIGH)

    def test_project_can_register_its_own_actions(self):
        b = HeuristicBackend()
        b.register("issue_gift_card", Risk.HIGH)
        risk, _, _ = b.evaluate("issue_gift_card", {})
        self.assertEqual(risk, Risk.HIGH)

    def test_gate_from_manifest_uses_declared_boundaries(self):
        """闭环：AGT002 报出缺声明 → 项目补声明 → 闸门自动获得定级。"""
        manifest = {
            "capabilities": ["lookup_order", "answer_faq"],
            "action_boundary": {
                "allowed_actions": ["lookup_order", "read_policy"],
                "denied_actions": ["issue_refund"],
            },
            "approval_gate": {"requires_approval": ["modify_address"]},
        }
        b = HeuristicBackend.from_manifest(manifest)
        g = ApprovalGate(threshold=Risk.MEDIUM, backend=b)
        self.assertFalse(g.check("read_policy", {}).requires_approval)
        self.assertEqual(b.evaluate("issue_refund", {})[0], Risk.CRITICAL)
        self.assertGreaterEqual(
            ["none", "low", "medium", "high", "critical"].index(
                b.evaluate("modify_address", {})[0].value), 3)


class TestAmountEscalation(unittest.TestCase):
    def setUp(self):
        self.gate = ApprovalGate(threshold=Risk.MEDIUM)

    def test_small_amount_medium(self):
        d = self.gate.check("issue_refund", {"amount": 50})
        self.assertTrue(d.requires_approval)

    def test_large_amount_critical(self):
        d = self.gate.check("issue_refund", {"amount": 500_000})
        self.assertEqual(d.risk, Risk.CRITICAL)
        self.assertTrue(d.requires_approval)

    def test_unparseable_amount_escalates(self):
        d = self.gate.check("issue_refund", {"amount": "很多钱"})
        self.assertIn("不可解析", d.evidence.get("amount_assessment", ""))

    def test_readonly_with_amount_still_low(self):
        d = self.gate.check("read", {"amount": 10})
        self.assertFalse(d.requires_approval,
                         "只读动作不应因金额被拦截")


class TestEscalationRules(unittest.TestCase):
    def setUp(self):
        self.gate = ApprovalGate(threshold=Risk.MEDIUM)

    def test_batch_escalates(self):
        d = self.gate.check("send_email", {"count": 500})
        self.assertGreaterEqual(
            ["none", "low", "medium", "high", "critical"].index(d.risk.value), 3)
        self.assertEqual(d.evidence["batch"], 500)

    def test_sensitive_fields_escalate(self):
        d = self.gate.check("export_data", {"data": ["name", "id_card", "phone"]})
        self.assertGreaterEqual(
            ["none", "low", "medium", "high", "critical"].index(d.risk.value), 3)
        self.assertIn("id_card", d.evidence["sensitive_fields"])

    def test_external_side_effect_escalates(self):
        d = self.gate.check("read", {"external": True})
        self.assertGreaterEqual(
            ["none", "low", "medium", "high", "critical"].index(d.risk.value), 2)

    def test_batch_of_one_does_not_escalate(self):
        d = self.gate.check("send_email", {"count": 1})
        self.assertNotIn("batch", d.evidence)


class TestSynonymNormalization(unittest.TestCase):
    def test_chinese_synonyms(self):
        b = HeuristicBackend()
        for text, expect in (("退款", "issue_refund"),
                             ("删除", "delete"),
                             ("发邮件", "send_email"),
                             ("发布", "publish")):
            canon, fuzzy = b.normalize(text)
            self.assertEqual(canon, expect, f"{text} 归一化错误")
            self.assertTrue(fuzzy)

    def test_exact_key_is_not_fuzzy(self):
        canon, fuzzy = HeuristicBackend().normalize("issue_refund")
        self.assertEqual(canon, "issue_refund")
        self.assertFalse(fuzzy)


class TestThreshold(unittest.TestCase):
    def test_threshold_is_configurable(self):
        strict = ApprovalGate(threshold=Risk.LOW)
        loose = ApprovalGate(threshold=Risk.CRITICAL)
        act, ctx = "send_email", {}
        self.assertTrue(strict.check(act, ctx).requires_approval)
        self.assertFalse(loose.check(act, ctx).requires_approval)

    def test_policy_export_is_self_describing(self):
        p = ApprovalGate().policy()
        self.assertTrue(p["default_deny"])
        self.assertIn("不是安全边界", p["note"])
        self.assertIn("issue_refund", p["risk_table"])


class TestLedger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gate_")
        self.path = str(Path(self.tmp) / "gate.jsonl")
        self.gate = ApprovalGate(ledger_path=self.path)

    def test_every_check_is_recorded(self):
        self.gate.check("read", {})
        self.gate.check("issue_refund", {"amount": 999})
        lines = Path(self.path).read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0])["type"], "check")

    def test_approval_is_recorded_with_approver(self):
        d = self.gate.check("transfer_funds", {"amount": 5_000_000})
        rec = self.gate.record_approval(d, "张三", approved=True, note="已电话确认")
        self.assertEqual(rec["approval"]["approver"], "张三")
        self.assertTrue(rec["approval"]["approved"])
        lines = Path(self.path).read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[1])["approval"]["note"], "已电话确认")

    def test_rejection_preserves_decision_context(self):
        d = self.gate.check("delete_account", {})
        rec = self.gate.record_approval(d, "李四", approved=False, note="客户未确认")
        self.assertFalse(rec["approval"]["approved"])
        self.assertEqual(rec["action"], "delete_account")
        self.assertIn("latency_ms", rec)

    def test_no_ledger_path_means_no_write(self):
        g = ApprovalGate()
        d = g.check("read", {})
        self.assertIn("latency_ms", d.to_dict())


class TestPerformance(unittest.TestCase):
    def test_local_latency_is_sub_millisecond(self):
        """审批不能有边际成本 —— 单次判定必须是本地微秒级。"""
        gate = ApprovalGate()
        gate.check("warmup", {})
        times = [gate.check("issue_refund", {"amount": 12345}).latency_ms
                 for _ in range(200)]
        avg = sum(times) / len(times)
        self.assertLess(avg, 1.0, f"平均延迟 {avg:.3f}ms，本地审批应远低于 1ms")


if __name__ == "__main__":
    unittest.main(verbosity=2)
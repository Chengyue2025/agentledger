"""行为围栏测试。

锁定的核心命题：**拆单攻击下，单点闸门全部放行，围栏必须拦住。**
这是围栏存在的唯一理由，其他用例都是它的推论。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentledger.fence import BehaviorFence, Verdict  # noqa: E402


class TestSplitPayment(unittest.TestCase):
    """拆单：把一次 10 万退款拆成 10 次 1 万，单点闸门每次都合规。"""

    def setUp(self):
        # 放宽 burst，避免它先于累计额度命中 —— 本用例要验的是拆单规则本身
        self.fence = BehaviorFence(total_amount_limit={"issue_refund": 50_000},
                                   window_s=3600, burst_limit=10_000,
                                   call_rate_limit=10_000)

    def test_individual_amounts_pass_but_total_blocks(self):
        """累计到上限时先 WARN，越界才 BLOCK —— 不给误判留激进空间。"""
        verdicts = [self.fence.observe("issue_refund", amount=10_000)
                    for _ in range(6)]
        for v in verdicts[:4]:
            self.assertTrue(v.allowed, "未触及额度不应被拦")
        self.assertEqual(verdicts[4].verdict, Verdict.WARN,
                         "累计正好等于额度时应告警而非阻断")
        self.assertFalse(verdicts[5].allowed, "拆单未被累计额度拦住")
        self.assertEqual(verdicts[5].pattern, "total_amount")
        self.assertIn("累计", verdicts[5].reason)

    def test_amount_is_not_double_counted(self):
        """回归：observe 已把本次计入窗口，判定不能再加一次 amount。

        否则额度会提前一半触发，把合法业务误判为拆单。
        """
        fence = BehaviorFence(total_amount_limit={"pay": 1000},
                              burst_limit=10_000, call_rate_limit=10_000)
        for _ in range(3):
            fence.observe("pay", amount=300)      # 累计 900，未越界
        v = fence.observe("pay", amount=300)       # 累计 1200，越界
        self.assertFalse(v.allowed)
        self.assertEqual(v.observed["prior"], 900)
        self.assertEqual(v.observed["total"], 1200)

    def test_blocked_event_is_recorded(self):
        fence = BehaviorFence(total_amount_limit={"issue_refund": 10_000},
                              burst_limit=10_000, call_rate_limit=10_000)
        for _ in range(3):
            fence.observe("issue_refund", amount=5_000)
        ev = fence.evidence()
        self.assertGreaterEqual(ev["blocked_events"], 1)
        self.assertEqual(ev["blocked_by_pattern"].get("total_amount"), 1)


class TestRateAndBurst(unittest.TestCase):
    def setUp(self):
        self.fence = BehaviorFence(call_rate_limit=10, burst_limit=10_000)

    def test_rate_limit_blocks(self):
        v = None
        for _ in range(11):
            v = self.fence.observe("read")
        self.assertFalse(v.allowed)
        self.assertEqual(v.pattern, "call_rate")

    def test_rate_warns_before_blocking(self):
        """接近上限时应先告警，不要突然阻断。"""
        v = None
        for _ in range(9):
            v = self.fence.observe("read")
        self.assertEqual(v.verdict, Verdict.WARN)
        self.assertTrue(v.allowed)

    def test_burst_limit_blocks_retry_storm(self):
        """重试风暴：Agent 反复重试直到绕过限制。"""
        fence = BehaviorFence(burst_limit=5, burst_window_s=60,
                              call_rate_limit=100_000, repeated_read_limit=100_000)
        v = None
        for _ in range(7):
            v = fence.observe("retry")
        self.assertFalse(v.allowed)
        self.assertEqual(v.pattern, "burst")

    def test_normal_high_frequency_is_not_a_burst(self):
        """正常批量查询不能被当成风暴 —— 误判会让围栏被直接关掉。"""
        fence = BehaviorFence(burst_limit=30, burst_window_s=1,
                              call_rate_limit=10_000, repeated_read_limit=10_000)
        v = None
        for _ in range(20):
            v = fence.observe("read")
        self.assertTrue(v.allowed, "20 次/内的常规批量查询被误判为风暴")


class TestDataExfiltration(unittest.TestCase):
    def setUp(self):
        self.fence = BehaviorFence(repeated_read_limit=20,
                                   burst_limit=10_000, call_rate_limit=10_000)

    def test_repeated_read_blocks(self):
        """渐进试探：单次都不超阈值，累计构成爬取。"""
        v = None
        for _ in range(21):
            v = self.fence.observe("read")
        self.assertFalse(v.allowed)
        self.assertEqual(v.pattern, "repeated_read")

    def test_sensitive_field_access_blocks(self):
        """连续访问敏感字段，每次只取一条 —— 典型的数据外泄脚本形态。"""
        fence = BehaviorFence(sensitive_read_limit=5, repeated_read_limit=100,
                              burst_limit=10_000, call_rate_limit=10_000)
        v = None
        for _ in range(6):
            v = fence.observe("read", fields=("id_card",))
        self.assertFalse(v.allowed)
        self.assertEqual(v.pattern, "sensitive_read")

    def test_non_sensitive_reads_not_flagged(self):
        fence = BehaviorFence(sensitive_read_limit=5, repeated_read_limit=100,
                              burst_limit=10_000, call_rate_limit=10_000)
        v = None
        for _ in range(10):
            v = fence.observe("read", fields=("order_no", "status"))
        self.assertTrue(v.allowed)


class TestFenceNeverWidens(unittest.TestCase):
    """围栏只收紧不放宽 —— 这是它作为安全组件的基本性质。"""

    def setUp(self):
        self.fence = BehaviorFence(call_rate_limit=10_000,
                                   burst_limit=10_000,
                                   repeated_read_limit=10_000)

    def test_allow_stays_allow(self):
        for _ in range(50):
            self.assertTrue(self.fence.observe("read").allowed)

    def test_warn_does_not_block(self):
        """额度未越界、但接近上限时应只告警。"""
        fence = BehaviorFence(total_amount_limit={"pay": 1000},
                              call_rate_limit=10_000, burst_limit=10_000)
        fence.observe("pay", amount=700)
        v = fence.observe("pay", amount=150)      # 累计 850，越过 80% 告警线
        self.assertEqual(v.verdict, Verdict.WARN)
        self.assertTrue(v.allowed, "WARN 不应阻止执行")

    def test_exactly_at_threshold_is_not_warn(self):
        """边界：累计正好等于 80% 不告警（> 而非 >=），避免无意义的噪声。"""
        fence = BehaviorFence(total_amount_limit={"pay": 1000},
                              call_rate_limit=10_000, burst_limit=10_000)
        fence.observe("pay", amount=700)
        v = fence.observe("pay", amount=100)      # 累计 800 == 80%
        self.assertEqual(v.verdict, Verdict.ALLOW)

    def test_first_block_wins_no_later_allow(self):
        fence = BehaviorFence(total_amount_limit={"pay": 100},
                              call_rate_limit=10_000, burst_limit=10_000)
        results = [fence.observe("pay", amount=60) for _ in range(4)]
        blocked_idx = next(i for i, v in enumerate(results) if not v.allowed)
        for v in results[blocked_idx:]:
            self.assertFalse(v.allowed, "已阻断后出现了放行")


class TestEvidence(unittest.TestCase):
    def setUp(self):
        self.fence = BehaviorFence(total_amount_limit={"issue_refund": 1000},
                                   window_s=3600, burst_limit=3)

    def test_evidence_declares_policy_ref(self):
        ev = self.fence.evidence()
        self.assertIn("第 7 条", ev["policy_ref"])
        self.assertIn("围栏", ev["policy_ref"])

    def test_evidence_lists_what_it_detects(self):
        ev = self.fence.evidence()
        self.assertTrue(any("拆单" in d for d in ev["detects"]),
                        "证据里必须写明它能抓什么，不能只报结果")

    def test_trajectory_digest_is_stable_and_sensitive(self):
        a = BehaviorFence()
        a.observe("read"); a.observe("write")
        b = BehaviorFence()
        b.observe("read"); b.observe("write")
        self.assertEqual(a.digest(), b.digest())
        c = BehaviorFence()
        c.observe("read"); c.observe("delete")
        self.assertNotEqual(a.digest(), c.digest())

    def test_limits_are_recorded(self):
        ev = self.fence.evidence()
        self.assertEqual(ev["limits"]["total_amount_limit"]["issue_refund"], 1000)
        self.assertEqual(ev["window_s"], 3600)


class TestNoActionLimit(unittest.TestCase):
    def test_action_without_limit_is_unconstrained_by_amount(self):
        fence = BehaviorFence(total_amount_limit={"issue_refund": 1})
        v = fence.observe("other_action", amount=99_999_999)
        self.assertTrue(v.allowed, "未配置额度的动作不应被额度规则拦截")

    def test_none_amount_skips_amount_check(self):
        fence = BehaviorFence(total_amount_limit={"read": 1})
        v = fence.observe("read", amount=None)
        self.assertTrue(v.allowed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
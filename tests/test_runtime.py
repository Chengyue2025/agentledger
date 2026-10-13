"""运行时留痕测试。

锁定的核心行为：
  1. 记录默认**不存明文** —— 记录行为不等于复制个人信息
  2. 哈希链可检出篡改与删除
  3. 每条记录回指授权凭据，形成"谁批的→做了什么"闭环
  4. 审计设施永不中断业务
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentledger.runtime import (  # noqa: E402
    RuntimeRecorder, TraceRecord, redact_args,
)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rt_")
        self.path = str(Path(self.tmp) / "trace.jsonl")
        self.rec = RuntimeRecorder(ledger_path=self.path,
                                   agent_id="acme-support-triage",
                                   version="0.4.0")


class TestRedaction(unittest.TestCase):
    def test_sensitive_keys_are_redacted(self):
        safe, hit = redact_args({"order": "A-1", "id_card": "110101199001011234",
                                 "phone": "13800000000"})
        self.assertEqual(safe["id_card"], "[redacted]")
        self.assertEqual(safe["phone"], "[redacted]")
        self.assertEqual(safe["order"], "A-1", "非敏感字段必须保留，否则记录失去审计价值")
        self.assertEqual(len(hit), 2)

    def test_chinese_field_names(self):
        safe, hit = redact_args({"身份证": "x", "姓名": "y", "金额": 100})
        self.assertEqual(safe["身份证"], "[redacted]")
        self.assertEqual(safe["姓名"], "[redacted]")
        self.assertEqual(safe["金额"], 100, "金额不是个人信息，应保留")
        self.assertEqual(len(hit), 2)

    def test_nested_structures(self):
        safe, hit = redact_args({"user": {"profile": {"phone": "1"}}, "items": [
            {"api_key": "sk-x"}, {"name": "ok"}]})
        self.assertEqual(safe["user"]["profile"]["phone"], "[redacted]")
        self.assertEqual(safe["items"][0]["api_key"], "[redacted]")
        self.assertEqual(safe["items"][1]["name"], "[redacted]")
        # 3 处：phone / api_key / name（name 归入个人信息，脱敏偏保守是安全方向）
        self.assertEqual(len(hit), 3)

    def test_long_strings_truncated(self):
        safe, hit = redact_args({"blob": "x" * 900})
        self.assertTrue(str(safe["blob"]).startswith("[truncated:"))
        self.assertIn("blob", hit)


class TestRecordBasics(Base):
    def test_record_has_required_elements(self):
        """GB/Z 185 第 7 部分所需要素必须齐备。"""
        r = self.rec.record("crm.lookup_order", args={"order": "A-1"},
                            result={"status": "shipped"}, grant_id="G-1",
                            authority="user_authorized")
        for field in ("agent_id", "tool", "args_digest", "result_digest",
                      "at", "grant_id", "granted_authority", "hash"):
            self.assertTrue(hasattr(r, field) and getattr(r, field) != "",
                            f"缺 GB/Z 185 要素 {field}")

    def test_digest_is_stable(self):
        a = self.rec.record("t", args={"x": 1})
        b = self.rec.record("t", args={"x": 1})
        self.assertEqual(a.args_digest, b.args_digest)
        c = self.rec.record("t", args={"x": 2})
        self.assertNotEqual(a.args_digest, c.args_digest)

    def test_plaintext_is_not_stored_by_default(self):
        secret = "110101199001011234"
        r = self.rec.record("crm.lookup", args={"id_card": secret})
        blob = self.rec.to_json()
        self.assertNotIn(secret, blob, "证据包里出现了明文身份证号")
        self.assertIn("[redacted]", blob)

    def test_chain_links_records(self):
        a = self.rec.record("t1")
        b = self.rec.record("t2")
        self.assertEqual(b.prev, a.hash)

    def test_ledger_file_is_appended(self):
        self.rec.record("t1")
        self.rec.record("t2")
        lines = Path(self.path).read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0])["seq"], 0)


class TestChainIntegrity(Base):
    def test_clean_chain_verifies(self):
        for i in range(5):
            self.rec.record(f"tool_{i}")
        ok, problems = self.rec.verify()
        self.assertTrue(ok, problems)

    def test_detects_tampered_record(self):
        for i in range(4):
            self.rec.record(f"tool_{i}", args={"i": i})
        self.rec._records[1].outcome = "denied"   # 篡改但未重算哈希
        self.rec._records[1].error = "事后补写"
        ok, problems = self.rec.verify()
        self.assertFalse(ok, "篡改未被检出")
        self.assertTrue(any("哈希不匹配" in p for p in problems))

    def test_detects_rewritten_grant_reference(self):
        """篡改最危险的字段：把授权凭据换掉，让记录看起来是有授权的。"""
        for i in range(3):
            self.rec.record("refund", grant_id="G-REAL")
        self.rec._records[0].grant_id = "G-FAKE"
        ok, problems = self.rec.verify()
        self.assertFalse(ok, "改写授权凭据未被检出")

    def test_detects_deleted_record(self):
        for i in range(4):
            self.rec.record(f"tool_{i}")
        del self.rec._records[1]
        ok, problems = self.rec.verify()
        self.assertFalse(ok, "删除记录未被检出")


class TestContextManager(Base):
    def test_trace_captures_result_and_latency(self):
        with self.rec.trace("crm.get", args={"id": 1}) as span:
            span.result = {"ok": True}
        r = self.rec._records[-1]
        self.assertEqual(r.outcome, "ok")
        self.assertTrue(r.result_digest, "结果必须有摘要，否则记录无法证明执行内容")
        # 本地调用常 < 0.01ms，只留毫秒会记录成 0.0 —— 看起来像"没测"
        self.assertGreaterEqual(r.latency_us, 0)
        self.assertIsInstance(r.latency_us, int)

    def test_exception_is_recorded_then_reraised(self):
        with self.assertRaises(ValueError):
            with self.rec.trace("risky.op"):
                raise ValueError("boom")
        r = self.rec._records[-1]
        self.assertEqual(r.outcome, "error")
        self.assertIn("ValueError", r.error)

    def test_denied_outcome(self):
        with self.rec.trace("payment") as span:
            span.deny("超出用户授权范围")
        self.assertEqual(self.rec._records[-1].outcome, "denied")

    def test_wrap_records_calls(self):
        def fake(a, b):
            return a + b
        wrapped = self.rec.wrap("calc", fake)
        self.assertEqual(wrapped(1, 2), 3)
        self.assertEqual(self.rec._records[-1].tool, "calc")


class TestAuthorityClosure(Base):
    def test_record_references_grant(self):
        """「谁批的 → 做了什么」的闭环。"""
        r = self.rec.record("issue_refund", args={"amount": 100},
                            grant_id="G-CS-001", authority="user_authorized")
        s = r.statement()
        self.assertIn("G-CS-001", s)
        self.assertIn("issue_refund", s)

    def test_statement_mentions_redaction(self):
        r = self.rec.record("export", args={"phone": "13800000000"})
        self.assertIn("敏感字段", r.statement())


class TestEvidence(Base):
    def test_evidence_has_integrity_and_privacy_blocks(self):
        self.rec.record("t", args={"id_card": "x"})
        ev = self.rec.evidence()
        self.assertEqual(ev["schema"], "agentledger/runtime-trace/v1")
        self.assertTrue(ev["integrity"]["chain_verified"])
        self.assertIn("merkle_root", ev["integrity"])
        self.assertIn("GB/Z 185", json.dumps(ev["standard_alignment"],
                                             ensure_ascii=False))
        self.assertFalse(ev["privacy"]["store_plaintext"])
        self.assertGreaterEqual(ev["privacy"]["redacted_field_count"], 1)

    def test_outcome_summary(self):
        self.rec.record("a")
        with self.rec.trace("b"):
            pass
        with self.assertRaises(RuntimeError):
            with self.rec.trace("c"):
                raise RuntimeError("x")
        ev = self.rec.evidence()
        self.assertEqual(ev["summary"]["by_outcome"].get("ok"), 2)
        self.assertEqual(ev["summary"]["by_outcome"].get("error"), 1)


class TestResilience(Base):
    def test_recorder_never_raises_on_bad_payload(self):
        class Boom:
            def __repr__(self):
                raise RuntimeError("不能序列化")

        r = self.rec.record("weird", args=Boom())
        self.assertIsNotNone(r)
        self.assertEqual(r.outcome, "audit_error")

    def test_unwritable_path_does_not_break_business(self):
        rec = RuntimeRecorder(ledger_path="/definitely/not/writable/x.jsonl")
        r = rec.record("t")  # 不应抛异常
        self.assertEqual(r.outcome, "ok")


if __name__ == "__main__":
    unittest.main(verbosity=2)
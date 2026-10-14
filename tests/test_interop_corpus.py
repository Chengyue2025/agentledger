"""互操作语料库一致性测试（receipt-commons/receipt-interop，7 案例）。

对照关系（interop README）：
  * ``expected.valid`` 是规范性比较 —— 必须逐一命中；
  * ``expected.errors/warnings`` 是参考实现的诊断输出（信息性），
    本实现使用自有的等价错误码；三个负例的错误码恰好同名，一并钉住。
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentledger import drp  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CORPUS = json.loads((FIXTURES / "interop-corpus.json").read_text(
    encoding="utf-8"))
ROWS = {r["id"]: r for r in drp.run_corpus(CORPUS)}

NEGATIVE_ERRORS = {
    "interop-03-expired": ["TIME_WINDOW"],
    "interop-04-scope-violation":
        ["CHAIN_HOP_1_SCOPE_ATTENUATION_VIOLATED"],
    "interop-05-revocation-required": ["REVOCATION_CHECK_REQUIRED"],
}


class TestInteropCorpus(unittest.TestCase):
    def test_corpus_shape(self):
        self.assertEqual(CORPUS["format"],
                         "agent-delegation-receipt-interop-corpus/1")
        self.assertEqual(len(CORPUS["cases"]), 7)

    def test_all_cases_match_expected_valid(self):
        """规范性比较：7/7 案例 valid 结果与语料库预期一致。"""
        for case in CORPUS["cases"]:
            row = ROWS[case["id"]]
            with self.subTest(case=case["id"]):
                self.assertEqual(row["valid"],
                                 case["expected"]["valid"])
                self.assertTrue(row["pass"])

    def test_negative_cases_error_codes(self):
        """信息性钉住：三个负例错误码与参考实现逐字一致。"""
        for cid, expected in NEGATIVE_ERRORS.items():
            with self.subTest(case=cid):
                self.assertEqual(ROWS[cid]["errors"], expected)
                self.assertFalse(ROWS[cid]["valid"])

    def test_valid_cases_no_errors(self):
        for cid in ("interop-01-basic-valid",
                    "interop-02-structured-scope-valid",
                    "interop-06-chain-valid-2hop",
                    "interop-07-chain-valid-3hop"):
            with self.subTest(case=cid):
                self.assertEqual(ROWS[cid]["errors"], [])
                self.assertTrue(ROWS[cid]["valid"])

    def test_chain_warnings(self):
        """链案例产出 CHAIN_OK；2 案例同时确认编排者签名。"""
        self.assertIn("CHAIN_OK", ROWS["interop-06-chain-valid-2hop"]
                      ["warnings"])
        self.assertIn("CHAIN_OK", ROWS["interop-07-chain-valid-3hop"]
                      ["warnings"])
        self.assertIn("ORCHESTRATOR_SIG_OK",
                      ROWS["interop-06-chain-valid-2hop"]["warnings"])

    def test_bundle_matches_fixture(self):
        from importlib import resources
        bundled = json.loads(resources.files("agentledger").joinpath(
            "data/interop-corpus.json").read_text(encoding="utf-8"))
        self.assertEqual(
            [c["id"] for c in bundled["cases"]],
            [c["id"] for c in CORPUS["cases"]])


if __name__ == "__main__":
    unittest.main()

"""RFC 8785 JCS 规范化测试 —— 附录 A.2 金标准字节串 + 边界。"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentledger import jcs  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
GOLDEN = json.loads((FIXTURES / "draft13-golden.json").read_text(
    encoding="utf-8"))


class TestJCS(unittest.TestCase):
    def test_draft_appendix_a2_byte_exact(self):
        """草案附录 A.1 演示 JSON 规范化后必须逐字节等于 A.2 字节串。"""
        body = json.loads(GOLDEN["presentation_json"])
        self.assertEqual(jcs.canonicalize(body),
                         GOLDEN["jcs_bytes"].encode("utf-8"))

    def test_no_whitespace_and_key_order(self):
        out = jcs.canonicalize({"b": 1, "a": {"z": True, "y": None}}).decode()
        self.assertEqual(out, '{"a":{"y":null,"z":true},"b":1}')

    def test_utf16_code_unit_sorting(self):
        """排序按 UTF-16 码元：星平面（代理对 0xD8..）先于 U+E000。"""
        astral = "\U00010000"      # surrogate pair D800 DC00
        private_use = "\ue000"     # code point E000 (> DFFF but < astral cp)
        out = jcs.canonicalize({private_use: 1, astral: 2, "a": 3}).decode()
        # UTF-16 码元序: 'a'(0x61) < D800.. < E000
        self.assertEqual(out, '{"a":3,"\U00010000":2,"\ue000":1}')
        # 码点序会把 \ue000 排在星平面之前 —— JCS 要求的恰是前者
        self.assertNotEqual(out, '{"a":3,"\ue000":1,"\U00010000":2}')

    def test_string_escaping(self):
        out = jcs.canonicalize({"a": 'q"\\ \b\f\n\r\t\x00\x1f\u2028'})
        self.assertEqual(
            out, b'{"a":"q\\"\\\\ \\b\\f\\n\\r\\t\\u0000\\u001f\\u2028"}')

    def test_numbers_shortest_roundtrip(self):
        self.assertEqual(jcs.canonicalize({"a": 100.0}), b'{"a":100}')
        self.assertEqual(jcs.canonicalize({"a": -0.0}), b'{"a":0}')
        self.assertEqual(jcs.canonicalize({"a": 1e-7}), b'{"a":1e-7}')
        self.assertEqual(jcs.canonicalize({"a": 1.5}), b'{"a":1.5}')
        self.assertEqual(jcs.canonicalize({"a": 12345678901234567890}),
                         b'{"a":12345678901234567890}')

    def test_nan_infinity_rejected(self):
        with self.assertRaises(ValueError):
            jcs.canonicalize({"a": float("nan")})
        with self.assertRaises(ValueError):
            jcs.canonicalize({"a": float("inf")})

    def test_bool_before_int(self):
        self.assertEqual(jcs.canonicalize({"a": True}), b'{"a":true}')
        self.assertEqual(jcs.canonicalize({"a": False}), b'{"a":false}')


if __name__ == "__main__":
    unittest.main()

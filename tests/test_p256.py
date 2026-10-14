"""P-256 ECDSA（纯 Python）测试 —— 草案示例密钥金标准 + 往返/篡改。"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentledger import p256  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
GOLDEN = json.loads((FIXTURES / "draft13-golden.json").read_text(
    encoding="utf-8"))


class TestP256(unittest.TestCase):
    def test_draft_example_key_derivation(self):
        """草案附录 A.5 私钥 d 必须导出 A.5 公开 JWK 的 x/y。"""
        d = p256.b64u_to_int(GOLDEN["private_d"])
        jwk = p256.jwk_public(p256.pubkey_from_private(d))
        self.assertEqual(jwk["x"], GOLDEN["public_jwk"]["x"])
        self.assertEqual(jwk["y"], GOLDEN["public_jwk"]["y"])
        self.assertEqual(jwk["kty"], "EC")
        self.assertEqual(jwk["crv"], "P-256")

    def test_sign_verify_roundtrip(self):
        d = p256.b64u_to_int(GOLDEN["private_d"])
        pub = p256.pubkey_from_private(d)
        import hashlib
        digest = hashlib.sha256(b"agentledger test message").digest()
        r, s = p256.sign(digest, d)
        self.assertTrue(p256.verify(digest, r, s, pub))
        # 篡改摘要 / 篡改签名 / 错误密钥全部失败
        bad = hashlib.sha256(b"agentledger test messagf").digest()
        self.assertFalse(p256.verify(bad, r, s, pub))
        self.assertFalse(p256.verify(digest, (r + 1) % p256.P256_N, s, pub))
        other = p256.pubkey_from_private((d + 1) % p256.P256_N)
        self.assertFalse(p256.verify(digest, r, s, other))

    def test_low_s_normalised(self):
        d = p256.b64u_to_int(GOLDEN["private_d"])
        import hashlib
        digest = hashlib.sha256(b"low-s check").digest()
        _, s = p256.sign(digest, d)
        self.assertLessEqual(s, p256.P256_N // 2)

    def test_rfc6979_deterministic(self):
        d = p256.b64u_to_int(GOLDEN["private_d"])
        import hashlib
        digest = hashlib.sha256(b"deterministic").digest()
        self.assertEqual(p256.sign(digest, d), p256.sign(digest, d))

    def test_jwk_member_rules(self):
        """§4.2：signerPublicKey 必须恰含 kty/crv/x/y，且不得含私料。"""
        jwk = dict(GOLDEN["public_jwk"])
        self.assertEqual(p256.jwk_to_point(jwk)[0], p256.b64u_to_int(
            jwk["x"]))
        with_d = dict(jwk)
        with_d["d"] = GOLDEN["private_d"]
        with self.assertRaises(ValueError):
            p256.jwk_to_point(with_d)
        wrong_curve = dict(jwk)
        wrong_curve["crv"] = "P-384"
        with self.assertRaises(ValueError):
            p256.jwk_to_point(wrong_curve)

    def test_off_curve_point_rejected(self):
        x = p256.b64u_to_int(GOLDEN["public_jwk"]["x"])
        y = (p256.b64u_to_int(GOLDEN["public_jwk"]["y"]) + 1) % p256.P256_P
        self.assertFalse(p256.is_on_curve((x, y)))
        with self.assertRaises(ValueError):
            p256.jwk_public((x, y))


if __name__ == "__main__":
    unittest.main()

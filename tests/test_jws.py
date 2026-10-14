"""JWS Compact（§6）测试 —— 草案金标准 JWS、alg 注册表、分离形式。

Ed25519 段保留 RFC 8032 §7.1 官方向量（EdDSA 为 §6.5 OPTIONAL 算法）。
"""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentledger import ed25519, jws  # noqa: E402
from agentledger import p256  # noqa: E402
from agentledger import drp  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
GOLDEN = json.loads((FIXTURES / "draft13-golden.json").read_text(
    encoding="utf-8"))


class TestJWSGolden(unittest.TestCase):
    def test_draft_golden_jws_verifies(self):
        """草案附录 A.3 的 JWS：验签通过、载荷 == A.2 JCS 字节、
        receiptId == 文档给出的 SHA-256。"""
        header, payload = jws.verify_compact(GOLDEN["jws"])
        self.assertEqual(header.get("alg"), "ES256")
        self.assertEqual(header.get("typ"), "drp-receipt")
        self.assertEqual(payload, GOLDEN["jcs_bytes"].encode("utf-8"))
        self.assertEqual(drp.receipt_id(GOLDEN["jws"]),
                         GOLDEN["receiptId"])

    def test_payload_tamper_rejected(self):
        segs = GOLDEN["jws"].split(".")
        body = json.loads(GOLDEN["jcs_bytes"])
        body["scope"] = "read everything"
        forged = segs[0] + "." + jws.b64u_encode(
            drp.jcs.canonicalize(body)) + "." + segs[2]
        with self.assertRaises(ValueError):
            jws.verify_compact(forged)

    def test_unsecured_jws_prohibited(self):
        header = jws.b64u_encode(b'{"alg":"none"}')
        payload = jws.b64u_encode(b"{}")
        with self.assertRaises(ValueError):
            jws.verify_compact(header + "." + payload + ".")

    def test_der_signature_rejected(self):
        """§6.3：ES256 必须是 raw R||S64 字节，DER 必须被拒。"""
        der_sig = bytes.fromhex("30440220") + b"\x11" * 60  # DER-ish
        header = jws.b64u_encode(b'{"alg":"ES256","typ":"drp-receipt"}')
        payload = jws.b64u_encode(GOLDEN["jcs_bytes"].encode())
        bad = header + "." + payload + "." + jws.b64u_encode(der_sig)
        with self.assertRaises(ValueError):
            jws.verify_compact(bad)

    def test_sign_roundtrip_es256(self):
        d = p256.b64u_to_int(GOLDEN["private_d"])
        signed = jws.sign_compact(b'{"hello":"world"}',
                                  {"alg": "ES256", "typ": "drp-receipt"}, d)
        header, payload = jws.verify_compact(signed,
                                             pub=p256.pubkey_from_private(d))
        self.assertEqual(payload, b'{"hello":"world"}')
        self.assertEqual(header["alg"], "ES256")

    def test_detached_roundtrip(self):
        """§6.4 RFC7797 分离形式：b64:false + crit，载荷带外提供。"""
        d = p256.b64u_to_int(GOLDEN["private_d"])
        body = drp.jcs.canonicalize(json.loads(GOLDEN["jcs_bytes"]))
        signed = jws.sign_compact(body,
                                  {"alg": "ES256", "b64": False,
                                   "crit": ["b64"]}, d)
        head, mid, sig = signed.split(".")
        self.assertEqual(mid, "")  # empty payload segment
        pub = p256.pubkey_from_private(d)
        _, payload = jws.verify_compact(signed, pub=pub,
                                        payload_override=body)
        self.assertEqual(payload, body)
        with self.assertRaises(ValueError):
            jws.verify_compact(signed, pub=pub)  # override required


class TestEd25519Vectors(unittest.TestCase):
    """RFC 8032 §7.1 官方向量（EdDSA = §6.5 OPTIONAL）。"""

    SEED = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    PUB = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    SIG = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")

    def test_vector_1_empty_message(self):
        self.assertEqual(ed25519.public_key(self.SEED), self.PUB)
        self.assertEqual(ed25519.sign(self.SEED, b""), self.SIG)
        self.assertTrue(ed25519.verify(self.PUB, b"", self.SIG))

    def test_eddsa_jws_roundtrip(self):
        import base64
        body = {
            "delegationId": "ed-test",
            "issuedAt": "2026-10-09T12:00:00.000Z",
            "scope": "test",
            "boundaries": "none",
            "timeWindow": {"start": "2026-10-09T12:00:00.000Z",
                           "end": "2026-10-09T13:00:00.000Z"},
            "operatorInstructions": "do it",
            "instructionsHash": hashlib.sha256(
                drp.normalize_instructions("do it").encode()).hexdigest(),
            "signerPublicKey": {
                "kty": "OKP", "crv": "Ed25519",
                "x": base64.urlsafe_b64encode(
                    self.PUB).rstrip(b"=").decode()},
        }
        signed, rid = drp.issue(body, self.SEED, alg="EdDSA")
        res = drp.verify_receipt(signed, "2026-10-09T12:30:00.000Z")
        self.assertTrue(res.valid, res.errors)
        self.assertEqual(res.receipt_id, rid)


if __name__ == "__main__":
    unittest.main()

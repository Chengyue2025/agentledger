"""收据（IETF DRP draft -13）测试 —— v0.3.0 引擎全覆盖。

覆盖：指令规范化（对齐草案向量与语料库）、签发/验证往返、封闭字段集、
时间窗、结构化作用域与约束、指令漂移、来源检查、一次性消费、
子收据签发序列（§8.7 衰减/窗口包含在签名前强制）、链验证与深度上限、
撤销记录/注册表/级联/离线失败关闭、字节级篡改防护。
金标准与互操作语料库见 test_interop_corpus.py。
"""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentledger import drp, jws, p256  # noqa: E402
from agentledger.drp import (  # noqa: E402
    RevocationRegistry, instructions_hash, issue, issue_sub_receipt,
    normalize_instructions, receipt_id, validate_body, verify_chain,
    verify_receipt,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
GOLDEN = json.loads((FIXTURES / "draft13-golden.json").read_text(
    encoding="utf-8"))
D = p256.b64u_to_int(GOLDEN["private_d"])
NOW = "2026-10-09T12:30:00.000Z"


def base_body(**over):
    body = {
        "delegationId": "auth-1790000000000-a1b2c",
        "issuedAt": "2026-10-09T12:00:00.000Z",
        "scope": "read calendar events and draft meeting summaries",
        "boundaries": "never send email without explicit confirmation",
        "timeWindow": {"start": "2026-10-09T12:00:00.000Z",
                       "end": "2026-10-09T13:00:00.000Z"},
        "operatorInstructions": ("Read today's calendar events and draft "
                                 "a summary for the 2pm standup."),
        "signerPublicKey": p256.jwk_public(p256.pubkey_from_private(D)),
    }
    body["instructionsHash"] = instructions_hash(
        body["operatorInstructions"])
    body.update(over)
    return body


SCHEMA = {
    "version": "1.0",
    "allowedActions": [
        {"operation": "read", "resource": "calendar/events"},
        {"operation": "write", "resource": "calendar/drafts",
         "constraints": {"maxEvents": 10}},
    ],
    "deniedActions": [
        {"operation": "delete", "resource": "calendar/events"},
    ],
}


class TestNormalization(unittest.TestCase):
    def test_draft_vector(self):
        """草案/语料库双命中向量（实证钉死的有损规范化）。"""
        text = ("Read today's calendar events and draft a summary for the "
                "2pm standup.")
        self.assertEqual(
            instructions_hash(text),
            "c730de758e586e19a81098fa1cd40721162da9817fa7f7e651524a27c93ee4fb")

    def test_steps(self):
        self.assertEqual(normalize_instructions("  A,  B.  "), "a b")
        self.assertEqual(normalize_instructions('"quoted" x'), "quoted x")
        self.assertEqual(normalize_instructions("price:9.99"),
                         "price:9.99")  # 数字中的句点保留
        self.assertEqual(
            normalize_instructions("send: mail\nagent: claude\n"),
            "agent: claude send: mail")  # 键值对按行检测、按键排序后折叠


class TestIssueVerify(unittest.TestCase):
    def test_roundtrip(self):
        signed, rid = issue(base_body(), D)
        self.assertEqual(rid, receipt_id(signed))
        res = verify_receipt(signed, NOW)
        self.assertTrue(res.valid, res.errors)
        self.assertEqual(res.receipt_id, rid)
        self.assertIn("TEXT_SCOPE_ADVISORY", res.warnings)

    def test_closed_field_set_rejects_unknown(self):
        """模拟“签名合法但发行方违规”的收据：字段集封闭必须拒绝。

        （发行器本身拒绝铸造未知字段 —— 见下一测试 —— 这里手工签名。）
        """
        body = base_body()
        body["sneakyConstraint"] = "allow everything"
        payload = drp.jcs.canonicalize(body)
        forged = jws.sign_compact(
            payload, {"alg": "ES256", "typ": "drp-receipt"}, D)
        res = verify_receipt(forged, NOW)
        self.assertFalse(res.valid)
        self.assertTrue(res.errors[0].startswith("UNKNOWN_BODY_FIELD"),
                        res.errors)

    def test_missing_required_field(self):
        body = base_body()
        del body["boundaries"]
        forged = _reforge(body)
        res = verify_receipt(forged, NOW)
        self.assertFalse(res.valid)
        self.assertTrue(res.errors[0].startswith("FIELD_MISSING"),
                        res.errors)

    def test_time_window_expired(self):
        signed, _ = issue(
            base_body(timeWindow={"start": "2026-10-09T10:00:00.000Z",
                                  "end": "2026-10-09T12:00:00.000Z"}), D)
        res = verify_receipt(signed, NOW)
        self.assertFalse(res.valid)
        self.assertEqual(res.errors, ["TIME_WINDOW"])

    def test_signature_covers_bytes(self):
        signed, _ = issue(base_body(), D)
        head, payload, sig = signed.split(".")
        import base64
        raw = json.loads(base64.urlsafe_b64decode(payload + "=="))
        raw["boundaries"] = "none"
        tampered = head + "." + jws_b64(raw) + "." + sig
        res = verify_receipt(tampered, NOW)
        self.assertFalse(res.valid)
        self.assertIn("JWS_INVALID", res.errors[0])

    def test_issuance_refuses_unknown_fields(self):
        with self.assertRaises(ValueError):
            issue(base_body(unknownTopLevel=1), D)


class TestActionScope(unittest.TestCase):
    def test_denied_first(self):
        signed, _ = issue(base_body(scopeSchema=SCHEMA), D)
        res = verify_receipt(signed, NOW, action={
            "operation": "delete", "resource": "calendar/events"})
        self.assertFalse(res.valid)
        self.assertEqual(res.errors, ["SCOPE_ACTION_DENIED"])

    def test_allowed_and_wildcard_and_constraints(self):
        signed, _ = issue(base_body(scopeSchema=SCHEMA), D)
        ok = verify_receipt(signed, NOW, action={
            "operation": "read", "resource": "calendar/events"})
        self.assertTrue(ok.valid, ok.errors)
        # 约束参数超出上限 → 拒绝
        over = verify_receipt(signed, NOW, action={
            "operation": "write", "resource": "calendar/drafts",
            "params": {"maxEvents": 11}})
        self.assertFalse(over.valid)
        # 未列入 → 默认拒绝
        unknown = verify_receipt(signed, NOW, action={
            "operation": "read", "resource": "mail/inbox"})
        self.assertFalse(unknown.valid)

    def test_text_scope_advisory_no_schema(self):
        signed, _ = issue(base_body(), D)
        res = verify_receipt(signed, NOW, action={
            "operation": "read", "resource": "anything"})
        self.assertFalse(res.valid)
        self.assertEqual(res.errors, ["SCOPE_ACTION_NO_SCHEMA"])

    def test_pattern_matching(self):
        schema = {"allowedActions": [
            {"operation": "*", "resource": "files/*"}]}
        self.assertTrue(drp.action_allowed(schema, {
            "operation": "write", "resource": "files/report.pdf"})[0])
        self.assertFalse(drp.action_allowed(schema, {
            "operation": "write", "resource": "files"})[0])


class TestInstructionsAndProvenance(unittest.TestCase):
    def test_drift_detected(self):
        signed, _ = issue(base_body(), D)
        bad = verify_receipt(signed, NOW,
                             claimed_instructions="read everything")
        self.assertFalse(bad.valid)
        self.assertEqual(bad.errors, ["INSTRUCTIONS_MISMATCH"])
        good = verify_receipt(
            signed, NOW,
            claimed_instructions=base_body()["operatorInstructions"])
        self.assertTrue(good.valid, good.errors)

    def test_trusted_sources(self):
        signed, _ = issue(base_body(trustedSources=["user"]), D)
        bad = verify_receipt(signed, NOW, instruction_source="tool_output")
        self.assertEqual(bad.errors, ["UNTRUSTED_INSTRUCTION_SOURCE"])
        good = verify_receipt(signed, NOW, instruction_source="user")
        self.assertTrue(good.valid)


class TestOneTimeUse(unittest.TestCase):
    def test_fail_closed_without_store(self):
        signed, rid = issue(base_body(oneTimeUse=True), D)
        res = verify_receipt(signed, NOW)
        self.assertFalse(res.valid)
        self.assertEqual(res.errors, ["CONSUMPTION_STORE_REQUIRED"])

    def test_consume_once(self):
        signed, rid = issue(base_body(oneTimeUse=True), D)
        store: set[str] = set()
        first = verify_receipt(signed, NOW, consumed=store)
        self.assertTrue(first.valid, first.errors)
        store.add(rid)
        second = verify_receipt(signed, NOW, consumed=store)
        self.assertEqual(second.errors, ["RECEIPT_ALREADY_CONSUMED"])


class TestSubReceiptChain(unittest.TestCase):
    def _root(self, **over):
        body = base_body(scopeSchema=SCHEMA)
        body["timeWindow"] = {"start": "2026-10-09T12:00:00.000Z",
                              "end": "2026-10-09T13:00:00.000Z"}
        body.update(over)
        signed, rid = issue(body, D)
        return signed, rid

    def _child(self, **over):
        body = base_body(scopeSchema={
            "allowedActions": [{"operation": "read",
                                "resource": "calendar/events"}],
            "deniedActions": [{"operation": "delete",
                               "resource": "calendar/events"}],
        })
        body["timeWindow"] = {"start": "2026-10-09T12:15:00.000Z",
                              "end": "2026-10-09T12:45:00.000Z"}
        body.update(over)
        return body

    def test_issue_and_chain_verify(self):
        parent, _ = self._root()
        child, rid, orch = issue_sub_receipt(self._child(), D, parent)
        res = verify_chain(
            [{"compact": child, "orchestratorSignature": orch}],
            NOW)
        # 单独子收据链（缺 root）—— 需要 root-first 全链
        parent_body = json.loads(_payload(parent))
        full = verify_chain(
            [parent, {"compact": child, "orchestratorSignature": orch}],
            NOW)
        self.assertTrue(full.valid, full.errors)
        self.assertIn("CHAIN_OK", full.warnings)
        self.assertIn("ORCHESTRATOR_SIG_OK", full.warnings)
        del parent_body, res, rid

    def test_wide_child_refused_at_issuance(self):
        parent, _ = self._root()
        wide = self._child(scopeSchema={
            "allowedActions": [
                {"operation": "read", "resource": "calendar/events"},
                {"operation": "write", "resource": "calendar/drafts"},
                {"operation": "delete", "resource": "calendar/events"},
            ],
            "deniedActions": [],
        })
        with self.assertRaises(ValueError):
            issue_sub_receipt(wide, D, parent)

    def test_child_window_must_be_contained(self):
        parent, _ = self._root()
        stray = self._child(timeWindow={
            "start": "2026-10-09T11:00:00.000Z",
            "end": "2026-10-09T12:45:00.000Z"})
        with self.assertRaises(ValueError):
            issue_sub_receipt(stray, D, parent)

    def test_attenuation_violation_detected_at_verify(self):
        """手动构造违规子收据（绕过签发检查，模拟恶意编排者）。"""
        parent, parent_rid = self._root()
        wide_body = self._child(scopeSchema={
            "allowedActions": [
                {"operation": "read", "resource": "calendar/events"},
                {"operation": "delete", "resource": "calendar/events"},
            ],
            "deniedActions": [],
        })
        wide_body["parentReceiptId"] = parent_rid
        child, rid = issue(wide_body, D)
        orch = drp.jws.sign_compact(
            ("orchestrator-delegation:%s:%s" % (parent_rid, rid)
             ).encode(), {"alg": "ES256"}, D)
        res = verify_chain(
            [parent, {"compact": child, "orchestratorSignature": orch}],
            NOW)
        self.assertFalse(res.valid)
        self.assertEqual(
            res.errors,
            ["CHAIN_HOP_1_SCOPE_ATTENUATION_VIOLATED"])

    def test_depth_limit(self):
        """默认 maxDepth=3：root + 两级委派（深度2）合法，深度3 拒绝。

        逐级作用域严格收窄（5→3→2→1），窗口逐级内嵌，确保每一跳都能
        通过 §8.5/窗口检查 —— 拒绝仅由深度上限触发。
        """
        actions = [
            {"operation": "read", "resource": "calendar/events"},
            {"operation": "write", "resource": "calendar/drafts"},
            {"operation": "delete", "resource": "calendar/archive"},
            {"operation": "read", "resource": "contacts/list"},
            {"operation": "write", "resource": "notes/draft"},
        ]
        denied = [{"operation": "delete",
                   "resource": "calendar/events"}]
        windows = [
            {"start": "2026-10-09T12:00:00.000Z",
             "end": "2026-10-09T13:00:00.000Z"},
            {"start": "2026-10-09T12:10:00.000Z",
             "end": "2026-10-09T12:55:00.000Z"},
            {"start": "2026-10-09T12:15:00.000Z",
             "end": "2026-10-09T12:50:00.000Z"},
            {"start": "2026-10-09T12:20:00.000Z",
             "end": "2026-10-09T12:45:00.000Z"},
        ]
        widths = [5, 3, 2, 1]
        compact: str | None = None
        elements: list = []
        for i, width in enumerate(widths):
            body = base_body(
                scopeSchema={"allowedActions": actions[:width],
                             "deniedActions": denied},
                timeWindow=windows[i])
            if compact is None:
                compact, _ = issue(body, D)
                elements.append(compact)
            else:
                child, _, orch = issue_sub_receipt(body, D, compact)
                compact = child
                elements.append({"compact": child,
                                 "orchestratorSignature": orch})
        res = verify_chain(elements, NOW)
        self.assertFalse(res.valid)
        self.assertEqual(res.errors, ["CHAIN_DEPTH_EXCEEDED"])
        # 深度2（root+2 跳）在默认上限内
        ok = verify_chain(elements[:3], NOW)
        self.assertTrue(ok.valid, ok.errors)

    def test_wrong_orchestrator_key_fails(self):
        """§4.4：绑定串必须用子收据 signerPublicKey 验证 —— 换钥即失效。"""
        other_d = (D + 7) % p256.P256_N
        parent, parent_rid = self._root()
        child_body = self._child(
            signerPublicKey=p256.jwk_public(
                p256.pubkey_from_private(other_d)))
        child, rid = issue({**child_body, "parentReceiptId": parent_rid},
                           other_d)
        # 绑定串由 D（非子密钥）签名 → 必须被拒
        orch = drp.jws.sign_compact(
            ("orchestrator-delegation:%s:%s" % (parent_rid, rid)
             ).encode(), {"alg": "ES256"}, D)
        res = verify_chain(
            [parent, {"compact": child, "orchestratorSignature": orch}],
            NOW)
        self.assertFalse(res.valid)
        self.assertIn("ORCHESTRATOR_SIG_INVALID", res.errors[0])


class TestRevocation(unittest.TestCase):
    def test_record_roundtrip(self):
        signed, rid = issue(base_body(), D)
        record = drp.issue_revocation_record(
            rid, "key compromised", D)
        self.assertTrue(drp.verify_revocation_record(record))
        # 篡改记录 → 拷贝签名失效
        tampered = dict(record)
        tampered["reason"] = "nothing"
        self.assertFalse(drp.verify_revocation_record(tampered))

    def test_registry_and_revoked_receipt(self):
        signed, rid = issue(base_body(), D)
        registry = RevocationRegistry()
        self.assertTrue(registry.revoke(rid, "misuse", D))
        res = verify_receipt(signed, NOW, registry=registry)
        self.assertFalse(res.valid)
        self.assertEqual(res.errors, ["REVOKED"])
        # 重复撤销必须失败（§9.1 永久性）
        with self.assertRaises(ValueError):
            registry.revoke(rid, "again", D)

    def test_offline_fail_closed(self):
        signed, _ = issue(base_body(revocationRequired=True), D)
        res = verify_receipt(signed, NOW)
        self.assertEqual(res.errors, ["REVOCATION_CHECK_REQUIRED"])
        registry = RevocationRegistry()
        ok = verify_receipt(signed, NOW, registry=registry)
        self.assertTrue(ok.valid, ok.errors)

    def test_ancestor_revoked_denies_child(self):
        parent, rid = issue(base_body(scopeSchema=SCHEMA), D)
        child, _, orch = issue_sub_receipt(_child_body(), D, parent)
        registry = RevocationRegistry()
        registry.revoke(rid, "parent misbehaved", D)
        res = verify_chain(
            [{"compact": parent},
             {"compact": child, "orchestratorSignature": orch}],
            NOW, registry=registry)
        self.assertFalse(res.valid)
        # 叶子先被注册表拒绝（REVOKE 命中自身?叶子未撤销——祖先走查）
        self.assertTrue(
            res.errors[0] in ("CHAIN_HOP_0_REVOKED",
                              "ANCESTOR_REVOKED"),
            res.errors)


class TestBundledCorpus(unittest.TestCase):
    def test_bundled_corpus_resource_present(self):
        from importlib import resources
        text = resources.files("agentledger").joinpath(
            "data/interop-corpus.json").read_text(encoding="utf-8")
        corpus = json.loads(text)
        self.assertEqual(len(corpus["cases"]), 7)


# ------------------------------------------------------------- helpers

def _child_body(**over):
    """子收据体：单动作收窄 + 内嵌时间窗。"""
    body = base_body(scopeSchema={
        "allowedActions": [{"operation": "read",
                            "resource": "calendar/events"}],
        "deniedActions": [{"operation": "delete",
                           "resource": "calendar/events"}],
    })
    body["timeWindow"] = {"start": "2026-10-09T12:15:00.000Z",
                          "end": "2026-10-09T12:45:00.000Z"}
    body.update(over)
    return body


def jws_b64(obj) -> str:
    import base64
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False) \
        .encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _payload(jws_text: str) -> str:
    import base64
    return base64.urlsafe_b64decode(jws_text.split(".")[1] + "==") \
        .decode("utf-8")


def _reforge(body: dict) -> str:
    """用测试密钥重新签发（模拟“合法签名但字段违规”的发行方）。"""
    signed, _ = issue(body, D)
    return signed


if __name__ == "__main__":
    unittest.main()

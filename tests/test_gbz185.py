"""GB/Z 185—2026 对接层测试。

最核心的一条不是格式，而是**诚实性**：
   不得把工程推断当作「已符合 GB/Z 185—2026」对外声明。
这是这类交付最容易、也最致命的失分点，必须由测试锁死。
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentledger.gbz185 import (  # noqa: E402
    ELEMENTS, STANDARD, AgentIdentity, CapabilityDescription,
    ConformanceLevel, RegistrationPayload, conformance_report,
)
from agentledger.inventory import discover  # noqa: E402
from agentledger.rules import run  # noqa: E402


class TestIdentityCodeStability(unittest.TestCase):
    """国标原文：一个身份码仅对应一个智能体。

    这条要求直接排除 Python 内置 hash() —— 字符串哈希带随机种子，
    每个进程都不同，会让同一智能体每次运行得到不同身份码。
    """

    def test_code_is_stable_across_processes(self):
        codes = set()
        for _ in range(3):
            out = subprocess.run(
                [sys.executable, "-c",
                 "import sys;sys.path.insert(0,r'%s')\n"
                 "from agentledger.gbz185 import AgentIdentity\n"
                 "print(AgentIdentity(name='Acme 客服', operator='Acme').ensure_code())"
                 % str(Path(__file__).resolve().parents[1])],
                capture_output=True, text=True, check=True)
            codes.add(out.stdout.strip())
        self.assertEqual(len(codes), 1, f"身份码不稳定：{codes}")

    def test_code_is_deterministic_in_process(self):
        a = AgentIdentity(name="x", operator="y").ensure_code()
        b = AgentIdentity(name="x", operator="y").ensure_code()
        self.assertEqual(a, b)

    def test_different_agents_get_different_codes(self):
        a = AgentIdentity(name="agent-a", operator="op").ensure_code()
        b = AgentIdentity(name="agent-b", operator="op").ensure_code()
        self.assertNotEqual(a, b)

    def test_code_preserves_existing_assignment(self):
        i = AgentIdentity(name="x", identity_code="OFFICIAL.CODE.001")
        self.assertEqual(i.ensure_code(), "OFFICIAL.CODE.001")

    def test_local_code_is_marked_as_inferred(self):
        i = AgentIdentity(name="x")
        i.ensure_code()
        d = i.to_dict()
        self.assertEqual(d["identity_code_source"], "local_inferred")
        self.assertIn("注册服务方", d["identity_code_warning"],
                      "本地推断的身份码必须明确警示，不得静默提交")

    def test_official_code_is_marked_as_assigned(self):
        i = AgentIdentity(name="x", identity_code="A.B.C.D")
        i.ensure_code()
        self.assertEqual(i.to_dict()["identity_code_source"], "assigned")


class TestConformanceHonesty(unittest.TestCase):
    """整个模块最重要的一组测试。"""

    def test_every_element_is_labelled(self):
        for key, meta in ELEMENTS.items():
            self.assertIn("part", meta, f"{key} 缺部分号")
            self.assertIn("part_name", meta)
            self.assertIsInstance(meta["level"], ConformanceLevel)
            self.assertTrue(meta["note"], f"{key} 缺依据说明")

    def test_elements_are_mapped_to_real_parts(self):
        parts = {m["part"] for m in ELEMENTS.values()}
        self.assertTrue(parts <= {2, 3, 4, 5, 6, 7}, "引用了不存在的部分号")
        self.assertEqual(len(parts) >= 4, True)

    def test_payload_states_the_blocking_rule(self):
        p = RegistrationPayload(AgentIdentity(name="x"))
        rep = conformance_report(p.to_dict())
        self.assertIn("不得对外声明", rep["blocking_rule"])

    def test_identity_code_part_is_not_claimed_verified(self):
        """身份码编码规则未公开 —— 必须标记为推定，不能说已符合。"""
        self.assertNotEqual(ELEMENTS["identity_code"]["level"],
                            ConformanceLevel.VERIFIED)

    def test_unverified_elements_are_listed_with_action(self):
        p = RegistrationPayload(AgentIdentity(name="x"))
        rep = conformance_report(p.to_dict())
        self.assertGreater(rep["unverified_count"], 0,
                           "若真按解读核过，这里不该为 0")
        for g in rep["not_yet_verified"]:
            self.assertIn("正式文本", g["action"])

    def test_conformance_report_flags_non_official_code(self):
        p = RegistrationPayload(AgentIdentity(name="x"))
        rep = conformance_report(p.to_dict())
        self.assertFalse(rep["identity_code_is_official"])


class TestPayload(unittest.TestCase):
    def test_payload_covers_four_policy_required_items(self):
        """《实施意见》第 4 条：开发者、部署方式、接口协议、合规认证。"""
        p = RegistrationPayload(AgentIdentity(
            name="x", operator="Acme", deployment_mode="saas"))
        p.add_attestation("static_scan", "abc123", "agentledger/0.1.0")
        d = p.to_dict()
        self.assertTrue(d["identity"]["operator"], "缺开发者")
        self.assertTrue(d["deployment_mode"], "缺部署方式")
        self.assertTrue(d["interface_protocols"], "缺接口协议")
        self.assertTrue(d["compliance_attestations"], "缺合规认证")

    def test_payload_is_json_serializable_and_finite(self):
        """digest 不得依赖时间戳，否则无法用于比对。"""
        p = RegistrationPayload(AgentIdentity(name="x"))
        d1 = p.digest()
        import time as _t
        _t.sleep(1.1)
        d2 = p.digest()
        self.assertEqual(d1, d2, "摘要随时间变化，无法用于跨次比对")
        json.loads(p.to_json())

    def test_digest_changes_with_content(self):
        a = RegistrationPayload(AgentIdentity(name="x")).digest()
        b = RegistrationPayload(AgentIdentity(name="y")).digest()
        self.assertNotEqual(a, b)

    def test_attestations_carry_verification_method(self):
        p = RegistrationPayload(AgentIdentity(name="x"))
        a = p.add_attestation("runtime_audit", "d", "i")
        self.assertIn("复算", a["verify"])
        b = p.add_attestation("human_attestation", "d", "i")
        self.assertIn("不可抵赖", b["verify"],
                      "必须提示 HMAC 对称、不构成不可抵赖签名")

    def test_concept_domins_five(self):
        p = RegistrationPayload(AgentIdentity(name="x"))
        d = p.to_dict()
        self.assertEqual(len(d["concept_domains"]), 5,
                         "解读明确给出五个概念域")


class TestProjection(unittest.TestCase):
    """从扫描结果与运行时记录投影为标准要素。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gbz_")
        Path(self.tmp, ".mcp.json").write_text(json.dumps({"mcpServers": {
            "crm": {"command": "npx", "args": ["-y", "@acme/crm"],
                    "integrity": "sha256:ab"}}}))
        Path(self.tmp, "agent.json").write_text(json.dumps(
            {"name": "a", "capabilities": ["refund"]}))
        Path(self.tmp, "config.py").write_text(
            'OPENAI_BASE_URL = "https://api.openai.com/v1"\n'
            'MODEL = "gpt-4o-latest"\n')
        self.cov = discover(self.tmp)
        self.findings = run(self.cov)

    def test_capability_projection_finds_mcp_servers(self):
        from agentledger.gbz185 import capability_from_scan
        cap = capability_from_scan(self.cov, self.findings)
        names = [s["name"] for s in cap.mcp_servers]
        self.assertIn("crm", names)
        self.assertTrue(cap.mcp_servers[0]["integrity"])

    def test_capability_projection_finds_model_endpoints(self):
        from agentledger.gbz185 import capability_from_scan
        cap = capability_from_scan(self.cov, self.findings)
        self.assertTrue(cap.model_endpoints, "未从发现项投影出模型接入点")

    def test_tool_invocation_projection(self):
        from agentledger.gbz185 import tool_invocations_from_recorder
        from agentledger.runtime import RuntimeRecorder
        rec = RuntimeRecorder(agent_id="a", version="1")
        rec.record("tool_x", args={"a": 1}, result={"ok": True}, grant_id="G1")
        rows = tool_invocations_from_recorder(rec)
        self.assertEqual(len(rows), 1)
        d = rows[0].to_dict()
        # 第 7 部分所需要素
        for k in ("tool", "actor", "args_digest", "result_digest",
                  "at", "grant_id", "record_hash"):
            self.assertIn(k, d)
        self.assertTrue(d["record_hash"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
"""GB/Z 185—2026《人工智能 智能体互联》证据格式对接层。

为什么做这个
------------
《实施意见》第 4 条原文：

> 探索建立**智能体注册平台**，提供智能体数字身份管理、检索发现、能力声明等服务，
> 支持开发者、部署方式、接口协议、**合规认证**等信息查询和管理。

也就是说，未来每个上线的智能体，都会有一个"这个智能体合不合规"的查询入口，
而那个入口展示的字段格式由谁先定义，谁就握住了整个生态的咽喉。
这有先例：Microsoft 定义 SARIF，全生态都输出 SARIF，Code Scanning
因此成为事实上的分发中心。

GB/Z 185—2026（工信部指导，中国电子技术标准化研究院组织 70 余家企业制定）
共 7 部分，其中 3 部分直接落在我们的能力范围：

| 部分 | 名称 | 我们的对应物 |
|---|---|---|
| 第 2 部分 | 智能体身份码编码、分配与管理 | `AgentIdentity.identity_code` |
| 第 3 部分 | 智能体身份注册、账户、凭证和鉴别 | 凭证绑定 + 哈希链账本 |
| 第 4 部分 | 智能体能力描述及其注册、发布和变更 | `CapabilityDescription`（= AI BOM） |
| 第 7 部分 | 外部工具调用的架构、流程和数据格式 | `ToolInvocationRecord`（= 运行时留痕） |

**诚实前提（重要）**
--------------------
GB 国家标准正式文本需付费购买，本模块依据的是
**工业和信息化部科技司 2026-07-06 官方解读**（见 cernet.edu.cn 转载）中
公开的结构，以及该解读明确表述的要素。

因此每一个字段都带 `ConformanceLevel` 标注：

- ``VERIFIED``   —— 解读中明确写出，字段名与语义可直接引用
- ``INTERPRETED``—— 解读给出了概念与要素，但字段命名/编码规则未公开
- ``INFERRED``   —— 我们的工程推断，用于让流程跑通，**必须以正式文本为准**

对外交付时必须带上这些标注。把推定当成符合，是这类交付最危险的失分点。
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .ledger import canonical, sha256_hex

SCHEMA = "agentledger/gbz185-registration/v1"
STANDARD = "GB/Z 185—2026《人工智能 智能体互联》"


class ConformanceLevel(str, Enum):
    VERIFIED = "verified"
    """解读中明确写出，可直接引用。"""

    INTERPRETED = "interpreted"
    """解读给出了概念与要素，字段命名或编码规则未公开。"""

    INFERRED = "inferred"
    """工程推断，用于跑通流程。必须以标准正式文本为准。"""

    @property
    def zh(self) -> str:
        return {
            "verified": "解读已明确",
            "interpreted": "依解读推定",
            "inferred": "工程推断（待正式文本核验）",
        }[self.value]


# --------------------------------------------------------------------------
# 标准要素登记表
# --------------------------------------------------------------------------
ELEMENTS: dict[str, dict[str, Any]] = {
    "identity_code": {
        "part": 2,
        "part_name": "智能体身份码编码、分配与管理",
        "level": ConformanceLevel.INTERPRETED,
        "note": "解读明确：身份码由注册服务方统一分配、采用分层标识体系、"
                "一个身份码仅对应一个智能体。但编码规则未公开。",
    },
    "identity_account": {
        "part": 3,
        "part_name": "智能体身份注册、账户、凭证和鉴别",
        "level": ConformanceLevel.VERIFIED,
        "note": "解读明确列出：身份注册与核验、账户管理、凭证管理、身份鉴别，"
                "并要求支持更新、锁定、解锁、注销。",
    },
    "credential": {
        "part": 3,
        "part_name": "智能体身份注册、账户、凭证和鉴别",
        "level": ConformanceLevel.VERIFIED,
        "note": "解读明确：核验通过后由注册服务方创建账户、分配身份码并发行凭证。",
    },
    "capability_description": {
        "part": 4,
        "part_name": "智能体能力描述及其注册、发布和变更",
        "level": ConformanceLevel.VERIFIED,
        "note": "解读明确：能力描述需支持注册、发布和变更。",
    },
    "discovery": {
        "part": 5,
        "part_name": "智能体发现流程",
        "level": ConformanceLevel.VERIFIED,
        "note": "解读明确：解决「具备什么能力、如何被找到」。",
    },
    "interaction": {
        "part": 6,
        "part_name": "智能体点对点、群组、混合等交互模式",
        "level": ConformanceLevel.VERIFIED,
        "note": "解读明确三种交互模式。",
    },
    "tool_invocation": {
        "part": 7,
        "part_name": "外部工具调用的架构、流程和数据格式",
        "level": ConformanceLevel.VERIFIED,
        "note": "解读明确：解决「如何协同完成任务、如何访问外部资源」。"
                "本模块的字段集合按此要素组织。",
    },
    "authenticator": {
        "part": 3,
        "part_name": "智能体身份注册、账户、凭证和鉴别",
        "level": ConformanceLevel.VERIFIED,
        "note": "解读明确：请求方与服务方完成双向身份鉴别后方可交互。",
    },
}

# 五个概念域（解读第二节明确给出）
CONCEPT_DOMAINS = {
    "user": "用户域 —— 负责任务发起和结果接收",
    "agent": "智能体域 —— 承担身份维护、描述维护、互联鉴权、交互和工具访问",
    "management_service": "管理服务域 —— 提供身份、凭证和鉴别服务",
    "interconnection_service": "互联服务域 —— 提供描述管理、智能体发现和消息分发",
    "resource_access": "资源访问域 —— 提供工具及外部资源支持",
}


# --------------------------------------------------------------------------
@dataclass
class AgentIdentity:
    """智能体身份（第 2、3 部分）。"""

    name: str
    identity_code: str = ""
    operator: str = ""              # 开发者 / 部署单位
    jurisdiction: str = "CN"
    version: str = ""
    account_id: str = ""
    credential_id: str = ""
    credential_digest: str = ""
    deployment_mode: str = ""       # 私有化 / SaaS / 混合
    contact: str = ""
    code_source: str = ""           # assigned | local_inferred

    def ensure_code(self, prefix: str = "CN") -> str:
        """生成本地身份码。

        ⚠️ INFERRED：解读只说明「分层标识体系」，未公开具体编码规则。
        本实现采用 `<域>.<主体类型>.<辖区>.<序号>.<校验位>` 的可读分层，
        目的是让流程跑通并在本地唯一。

        **注册前必须以标准正式文本的分配规则替换本方法**，不能直接提交。

        稳定性说明：序号由 sha256(名称+运营方) 派生，
        刻意**不用**内置 hash() —— Python 的字符串哈希带随机种子，
        每个进程都不同，会导致同一智能体每次运行得到不同身份码，
        直接违反「一个身份码仅对应一个智能体」。
        """
        if self.identity_code:
            # 已有身份码 —— 视为注册服务方分配的正式码
            if not self.code_source:
                self.code_source = "assigned"
            return self.identity_code
        seed = f"{self.jurisdiction}|{self.name}|{self.operator}".encode("utf-8")
        serial = int(hashlib.sha256(seed).hexdigest()[:12], 16) % 10**8
        body = f"{prefix}.AGENT.{self.jurisdiction}.{serial:08d}"
        chk = hashlib.sha256(body.encode("utf-8")).hexdigest()[:4].upper()
        self.identity_code = f"{body}.{chk}"
        self.code_source = "local_inferred"
        return self.identity_code

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "identity_code": self.identity_code,
            "identity_code_source": self.code_source,
            "identity_code_warning":
                "本码为本地推断生成，未使用标准规定的分配服务。"
                "提交登记前必须替换为由注册服务方分配的正式身份码。"
                if self.code_source == "local_inferred" else "",
            "operator": self.operator,
            "jurisdiction": self.jurisdiction,
            "version": self.version,
            "account_id": self.account_id,
            "credential_id": self.credential_id,
            "credential_digest": self.credential_digest,
            "deployment_mode": self.deployment_mode,
            "contact": self.contact,
        }


@dataclass
class CapabilityDescription:
    """智能体能力描述（第 4 部分）= AI BOM。"""

    model_endpoints: list[dict] = field(default_factory=list)
    mcp_servers: list[dict] = field(default_factory=list)
    prompts: list[dict] = field(default_factory=list)
    tools: list[dict] = field(default_factory=list)
    governance: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_endpoints": self.model_endpoints,
            "mcp_servers": self.mcp_servers,
            "prompts": self.prompts,
            "tools": self.tools,
            "governance": self.governance,
            "counts": {
                "model_endpoints": len(self.model_endpoints),
                "mcp_servers": len(self.mcp_servers),
                "prompts": len(self.prompts),
                "tools": len(self.tools),
            },
        }


@dataclass
class ToolInvocationRecord:
    """外部工具调用记录（第 7 部分）。

    与 `agentledger.runtime.TraceRecord` 同构，这里只做标准字段投影。
    """

    tool: str
    actor: str
    args_digest: str
    result_digest: str
    at: str
    grant_id: str = ""
    outcome: str = "ok"
    record_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "actor": self.actor,
            "args_digest": self.args_digest,
            "result_digest": self.result_digest,
            "at": self.at,
            "grant_id": self.grant_id,
            "outcome": self.outcome,
            "record_hash": self.record_hash,
        }


# --------------------------------------------------------------------------
class RegistrationPayload:
    """智能体注册平台登记载荷。

    《实施意见》第 4 条要求平台支持查询管理：
      开发者 · 部署方式 · 接口协议 · 合规认证
    本载荷按这四项组织。
    """

    def __init__(self, identity: AgentIdentity,
                 capability: CapabilityDescription | None = None,
                 attestations: list[dict] | None = None):
        self.identity = identity
        self.identity.ensure_code()
        self.capability = capability or CapabilityDescription()
        self.attestations = attestations or []

    # ------------------------------------------------------------------
    def add_attestation(self, kind: str, digest: str, issuer: str,
                        issued_at: str = "", scope: str = "") -> dict:
        """登记一项合规认证。

        对应《实施意见》第 12 条"推动认证与检测结果互通互认"——
        我们登记的是**可被互认的检测结果**，不是自己发证。
        """
        item = {
            "kind": kind,                 # static_scan / runtime_audit / human_attestation
            "digest": digest,
            "issuer": issuer,
            "issued_at": issued_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "scope": scope,
            "verify": self.verification_hint(kind, digest),
        }
        self.attestations.append(item)
        return item

    @staticmethod
    def verification_hint(kind: str, digest: str) -> str:
        hints = {
            "static_scan": "以 ledger 链头 + 发现项 Merkle 根复算比对",
            "runtime_audit": "以运行时哈希链逐条复算",
            "human_attestation": "签名方须提供可独立验签的凭证（HMAC 为对称，不构成不可抵赖）",
        }
        return hints.get(kind, "由登记方自行定义验证方式")

    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        d = {
            "schema": SCHEMA,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "standard": {
                "id": STANDARD,
                "source": "工业和信息化部科技司 2026-07-06 官方解读"
                          "（GB 国家标准正式文本需付费购买，本载荷按解读公开结构实现）",
                "conformance_warning":
                    "字段级符合性必须以标准正式文本核验。本文件对每个要素标注了"
                    "符合度，不得将「工程推断」当作「已符合」对外提交。",
            },
            "identity": self.identity.to_dict(),
            "deployment_mode": self.identity.deployment_mode,
            "interface_protocols": ["MCP", "GB/Z 185—2026 AIP"],
            "capability_description": self.capability.to_dict(),
            "compliance_attestations": self.attestations,
            "concept_domains": CONCEPT_DOMAINS,
            "elements": {
                k: {"part": v["part"], "part_name": v["part_name"],
                    "conformance": v["level"].value, "conformance_zh": v["level"].zh,
                    "note": v["note"]}
                for k, v in ELEMENTS.items()
            },
        }
        d["integrity"] = self.integrity()
        return d

    # ------------------------------------------------------------------
    def _digest_body(self) -> dict[str, Any]:
        """参与摘要计算的字段。

        注意：generated_at 与 integrity 自身必须排除在外，
        否则摘要会因为时间戳每次变化而无法用于比对，
        且会造成 to_dict ↔ integrity 的递归调用。
        """
        return {
            "identity": self.identity.to_dict(),
            "capability": self.capability.to_dict(),
            "attestations": self.attestations,
        }

    def integrity(self) -> dict[str, Any]:
        return {"payload_digest": sha256_hex(canonical(self._digest_body()))}

    def digest(self) -> str:
        """对外可比对的稳定摘要。"""
        return self.integrity()["payload_digest"]

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------
# 从扫描结果 / 运行时记录构建
# --------------------------------------------------------------------------
def capability_from_scan(coverage, findings) -> CapabilityDescription:
    """把 agentledger 的扫描结果投影为第 4 部分的能力描述。"""
    cap = CapabilityDescription()

    for art in coverage.artifacts:
        if art.data is not None and isinstance(art.data, dict):
            servers = art.data.get("mcpServers") or art.data.get("mcp_servers")
            if isinstance(servers, dict):
                for name, spec in servers.items():
                    if not isinstance(spec, dict):
                        continue
                    cap.mcp_servers.append({
                        "name": name,
                        "transport": spec.get("url") and "remote" or "stdio",
                        "endpoint": spec.get("url", ""),
                        "command": spec.get("command", ""),
                        "declared_version": spec.get("version", ""),
                        "integrity": spec.get("integrity") or spec.get("sha256", ""),
                        "source_file": art.path,
                    })

    for f in findings:
        if f.surface.value == "model":
            cap.model_endpoints.append({
                "detail": f.evidence[:120],
                "source_file": f.path,
            })

    for art in coverage.artifacts:
        if art.kind == "markdown":
            cap.prompts.append({"source_file": art.path, "size": art.size})

    cap.governance = {
        "authority_levels": ["user_only", "user_authorized", "agent_autonomous"],
        "policy_ref": "《智能体规范应用与创新发展实施意见》第 6 条",
    }
    return cap


def tool_invocations_from_recorder(recorder) -> list[ToolInvocationRecord]:
    """把运行时留痕投影为第 7 部分的工具调用记录。"""
    return [
        ToolInvocationRecord(
            tool=r.tool, actor=r.agent_id,
            args_digest=r.args_digest, result_digest=r.result_digest,
            at=r.at, grant_id=r.grant_id, outcome=r.outcome,
            record_hash=r.hash,
        )
        for r in recorder._records
    ]


# --------------------------------------------------------------------------
def conformance_report(payload: dict) -> dict[str, Any]:
    """汇总符合度，供交付前自查。

    用途：交付方在把载荷交给客户或登记平台之前，
    必须能一眼看到哪些部分是"解读已明确"、哪些是"我们推定的"。
    """
    counts: dict[str, int] = {}
    gaps: list[dict[str, str]] = []
    for key, meta in payload.get("elements", {}).items():
        lv = meta["conformance"]
        counts[lv] = counts.get(lv, 0) + 1
        if lv != ConformanceLevel.VERIFIED.value:
            gaps.append({
                "element": key,
                "part": meta["part"],
                "part_name": meta["part_name"],
                "conformance": lv,
                "conformance_zh": lv,
                "action": "提交前须以 GB/Z 185—2026 正式文本核验该要素的字段与编码规则",
            })

    return {
        "standard": STANDARD,
        "element_count": len(payload.get("elements", {})),
        "by_conformance": counts,
        "not_yet_verified": gaps,
        "unverified_count": len(gaps),
        "blocking_rule": "存在非 verified 级要素时，不得对外声明「符合 GB/Z 185—2026」，"
                         "只能声明「依据工信部解读实现，待正式文本核验」。",
        "identity_code_is_official": (
            payload.get("identity", {}).get("identity_code_source") == "assigned"
        ),
    }


__all__ = [
    "AgentIdentity", "CapabilityDescription", "ToolInvocationRecord",
    "RegistrationPayload", "ConformanceLevel", "ELEMENTS", "CONCEPT_DOMAINS",
    "capability_from_scan", "tool_invocations_from_recorder", "conformance_report",
    "STANDARD", "SCHEMA",
]
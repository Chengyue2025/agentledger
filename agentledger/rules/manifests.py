"""智能体治理声明规则。

这一组规则不查漏洞，查的是**治理完备性** —— 对应
《智能体规范应用与创新发展实施意见》第 10-12 条（人机协同审核、
分类分级治理、第三方评测与合规服务供给）与 EU AI Act Article 14/12。

价值在于：把"这个智能体可不可以上线"从主观判断变成可核查的清单。
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterator

from ..model import Artifact, Coverage, Finding, Severity, Surface
from .common import GOVERNANCE_KEYWORDS, HIGH_RISK_ACTIONS

# 识别智能体清单的文件
AGENT_FILE_RE = re.compile(
    r"(?i)(^|/)(agents?\.json|agents?\.ya?ml|agent\.toml|agents\.md|"
    r"openclaw\.json|swarm\.ya?ml|subagents?\.json|agent\.md)"
)
AGENT_DIR_RE = re.compile(r"(?i)(^|/)(agents?|multi[_\-]?agent|orchestrator)/")

REQUIRED_DECLARATIONS = (
    ("human_in_the_loop", Severity.HIGH, "人工介入机制",
     "《实施意见》第 10 条要求强化人机协同审核、拦截阻断能力。"
     "没有可核查的人工介入声明，无法证明该智能体具备有效监督。"),
    ("action_boundary", Severity.HIGH, "行动边界",
     "《实施意见》要求明确智能体的身份、功能范围、行动边界与数据访问。"
     "缺边界声明意味着责任范围不可界定。"),
    ("data_processing", Severity.MEDIUM, "数据处理与留存",
     "须说明个人信息处理、留存期限与数据出境安排，否则无法完成"
     "个人信息保护影响评估与数据出境评估。"),
    ("audit_log", Severity.MEDIUM, "责任留痕",
     "EU AI Act Art.12 与国内责任留痕要求均需要可导出的操作日志；"
     "缺此项则事故与问询均无法闭环。"),
)

_REQUIRED_RULES = {key: (sev, name, why) for key, sev, name, why in REQUIRED_DECLARATIONS}


def _iter_kv(node: Any, out: dict, depth: int = 0) -> None:
    """把 JSON/YAML 结构里的所有 key 收集到扁平集合（值也一并保留用于取证）。"""
    if depth > 12:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            out.setdefault(str(k).lower(), v)
            _iter_kv(v, out, depth + 1)
    elif isinstance(node, list):
        for v in node:
            _iter_kv(v, out, depth + 1)
    elif isinstance(node, str):
        out.setdefault("__text__", "")
        out["__text__"] = (out.get("__text__", "") + " " + node.lower())


def _blob(node: Any) -> str:
    flat: dict[str, Any] = {}
    _iter_kv(node, flat)
    return " ".join(f"{k} {v}" for k, v in flat.items() if k != "__text__").lower() + " " + \
           str(flat.get("__text__", "")).lower()


def _declared(blob: str, group: str) -> bool:
    return any(kw in blob for kw in GOVERNANCE_KEYWORDS[group])


def scan(art: Artifact) -> Iterator[Finding]:
    if not art.text:
        return
    is_agent_file = bool(AGENT_FILE_RE.search(art.path) or AGENT_DIR_RE.search(art.path))
    if not is_agent_file:
        return

    parsed = art.data if art.kind in ("json", "toml") else None
    if parsed is None and art.kind in ("json", "yaml", "toml"):
        # 未解析成功：退回文本扫描，但强度降低
        low = art.text.lower()
    blob = _blob(parsed) if parsed is not None else art.text.lower()

    # ---- 1. 必备治理声明缺失 ----
    for group, (sev, label, why) in _REQUIRED_RULES.items():
        if not _declared(blob, group):
            yield Finding(
                rule_id="AGT001",
                title=f"智能体清单缺少「{label}」声明",
                severity=sev,
                surface=Surface.AGENT,
                path=art.path,
                evidence=f"未发现任一关键字: {', '.join(GOVERNANCE_KEYWORDS[group][:4])} ...",
                rationale=why,
                remedy=f"在智能体清单中补充结构化字段以声明「{label}」，"
                       f"并使其可被机器校验（本工具下次扫描即应通过）。",
                tags=("governance", "regulatory"),
            )

    # ---- 2. 高风险自主动作缺少审批闸门 ----
    risk = [a for a in HIGH_RISK_ACTIONS if a in blob]
    if risk and not _declared(blob, "approval_gate"):
        yield Finding(
            rule_id="AGT002",
            title="存在高风险自主动作但未设置审批闸门",
            severity=Severity.CRITICAL,
            surface=Surface.AGENT,
            path=art.path,
            evidence="高风险动作: " + ", ".join(sorted(set(risk))[:8]),
            rationale="支付/转账/删除/对外发送等动作若可被智能体自主执行，"
                      "一旦提示注入成立即造成不可逆的实际损失，且无人工拦截点。",
            remedy="为每类高风险动作设置显式人工审批闸门；设置单次/周期额度上限；"
                   "提供可验证的 dry-run 与紧急熔断开关。",
            tags=("governance", "financial-risk"),
        )

    # ---- 3. 沙箱/隔离声明 ----
    sandbox_kw = ("sandbox", "isolation", "container", "seccomp", "jail", "sandboxed",
                  "沙箱", "隔离", "容器")
    if not any(k in blob for k in sandbox_kw) and ("executor" in blob or "tools" in blob):
        yield Finding(
            rule_id="AGT003",
            title="未声明工具执行的隔离/沙箱措施",
            severity=Severity.MEDIUM,
            surface=Surface.AGENT,
            path=art.path,
            evidence="未发现 sandbox / isolation / container 相关声明",
            rationale="工具执行未经隔离时，提示注入可直接升级为主机级代码执行。",
            remedy="声明执行隔离方式（容器/受限 syscall/只读挂载）；"
                   "对需要网络的工具使用出口白名单。",
            tags=("governance", "isolation"),
        )


# --------------------------------------------------------------------------
def scan_root_absence(coverage: "Coverage") -> Iterator[Finding]:
    """全局检查：整个项目里是否存在任何智能体治理声明文档。

    这一条面向"我到底有没有做治理"而非"某处写错"，
    在监管问询里往往是第一个被问到的问题。
    """
    blob_parts: list[str] = []
    scanned = 0
    for a in coverage.artifacts:
        if not a.text:
            continue
        if (AGENT_FILE_RE.search(a.path) or AGENT_DIR_RE.search(a.path)
                or a.path.lower().endswith((".md", ".markdown"))):
            blob_parts.append(a.text.lower())
            scanned += 1
    if not blob_parts:
        return
    blob = " ".join(blob_parts)
    if not blob:
        return

    for group, (sev, label, why) in _REQUIRED_RULES.items():
        if not _declared(blob, group):
            yield Finding(
                rule_id="AGT004",
                title=f"项目中未发现「{label}」的成文声明",
                severity=Severity.MEDIUM,
                surface=Surface.PROCESS,
                path="<project>",
                evidence=f"已在 {scanned} 个候选文档中检索，均未命中",
                rationale=why,
                remedy=f"产出一份《{label}》声明并纳入版本管理，"
                       f"使其可被本工具自动核验。",
                tags=("governance", "process"),
            )
"""SARIF 2.1.0 输出。

为什么重要：
  SARIF 是静态分析结果的事实标准交换格式。输出 SARIF 意味着
  agentledger 的结果可以零成本进入已有的消费管道：
    - GitHub Code Scanning（仓库设置里开一个开关即可）
    - GitLab / Azure DevOps / Jenkins 的 SAST 面板
    - 企业内部的缺陷跟踪（Jira/飞书/钉钉的代码质量插件）
  等于用别人的分发渠道，不自建。

参考：OASIS Static Analysis Results Interchange Format (SARIF) v2.1.0
      OASIS-IS-1.1，§3.27 为result 的required 属性集合。
"""

from __future__ import annotations

from typing import Any

from . import TOOL_ID, __version__
from .mapping import obligations_for
from .rules import RULE_CATALOG
from .model import SEVERITY_ORDER, Finding, Severity

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# SARIF level 与本工具严重度的映射
# 注意：SARIF 的 level 只有三档，无法表达 5 级。映射遵循"宁可报高不报低"，
# 因为漏报在合规场景的代价远高于误报。
LEVEL_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

HELP_URI_BASE = "https://github.com/agentledger/agentledger/blob/main/docs/rules"


def _rule_descriptor(f: Finding) -> dict[str, Any]:
    """规则描述符：不含具体实例信息，用于跨多次扫描复用。"""
    return {
        "id": f.rule_id,
        "name": RULE_CATALOG.get(f.rule_id, (f.title, ""))[0],
        "shortDescription": {"text": f.title},
        "fullDescription": {"text": f.rationale},
        "help": {
            "text": f.remedy,
            "markdown": f"**整改动作**\n\n{f.remedy}",
        },
        "helpUri": f"{HELP_URI_BASE}/{f.rule_id}.md",
        "defaultConfiguration": {"level": LEVEL_MAP[f.severity]},
        "properties": {
            "tags": list(f.tags),
            "surface": f.surface.value,
            "security-severity": _security_severity(f.severity),
            "precision": "high",
            "problem.severity": _problem_severity(f.severity),
        },
    }


def _security_severity(sev: Severity) -> str:
    """映射到 GitHub code scanning 使用的 0.0-10.0 分值。"""
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.5",
        Severity.LOW: "3.0",
        Severity.INFO: "1.0",
    }[sev]


def _problem_severity(sev: Severity) -> str:
    return {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }[sev]


def _fingerprint(f: Finding) -> str:
    """跨版本稳定的主位置指纹 —— 让重复告警在面板里正确合并。"""
    import hashlib
    raw = f"{f.rule_id}|{f.path}|{f.component or ''}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def _result(f: Finding) -> dict[str, Any]:
    loc: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": f.path.replace("\\", "/")},
        }
    }
    if f.line:
        loc["physicalLocation"]["region"] = {"startLine": max(1, f.line)}

    msg_parts = [f.title]
    if f.component:
        msg_parts.append(f"[{f.component}]")
    msg_parts.append(f.evidence)

    return {
        "ruleId": f.rule_id,
        "level": LEVEL_MAP[f.severity],
        "message": {"text": " ".join(msg_parts)[:2000]},
        "locations": [loc],
        "partialFingerprints": {"agentledgerLocationHash/v1": _fingerprint(f)},
        "properties": {
            "severity": f.severity.value,
            "tags": list(f.tags),
            "attackSurface": f.surface.value,
            "evidence": f.evidence[:1000],
            "rationale": f.rationale[:2000],
            "remediation": f.remedy[:2000],
            "obligations": [o["id"] for o in obligations_for(f.rule_id)],
        },
    }


def build_sarif(findings: list[Finding], repo_root: str = "",
                info_uri: str = "") -> dict[str, Any]:
    """生成完整的 SARIF 文档。"""
    used = []
    seen = set()
    for f in findings:
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            used.append(_rule_descriptor(f))
    # 把目录里所有规则都带上：规则未被触发时面板上也能看到规则集，
    # 这对"合规基线公示"有实际意义。
    have = {d["id"] for d in used}
    for rid, (title, tag) in RULE_CATALOG.items():
        if rid not in have:
            used.append({
                "id": rid,
                "name": title,
                "shortDescription": {"text": title},
                "helpUri": f"{HELP_URI_BASE}/{rid}.md",
                "defaultConfiguration": {"level": "warning"},
                "properties": {"tags": [tag], "precision": "medium"},
            })

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "agentledger",
                    "semanticVersion": __version__,
                    "version": TOOL_ID,
                    "informationUri": info_uri or
                    "https://github.com/agentledger/agentledger",
                    "rules": used,
                }
            },
            "automationDetails": {
                "id": "agentledger/compliance-scan/v1",
            },
            "invocations": [{
                "executionSuccessful": True,
                "toolExecutionNotifications": [],
            }],
            "results": [_result(f) for f in findings],
            "properties": {
                "findingsTotal": len(findings),
                "rulesDefined": len(RULE_CATALOG),
                "coverage": "静态分析结果；排除项见证据包 coverage_exclusions",
            },
        }],
    }


def pack_to_sarif(pack: dict[str, Any]) -> str:
    import json
    findings = [
        Finding(
            rule_id=f["rule_id"], title=f["title"], severity=Severity(f["severity"]),
            surface=_surface(f["surface"]), path=f["path"], line=f.get("line"),
            evidence=f.get("evidence", ""), rationale=f.get("rationale", ""),
            remedy=f.get("remedy", ""), component=f.get("component", ""),
            tags=tuple(f.get("tags", ())),
        )
        for f in pack.get("findings", [])
    ]
    return json.dumps(build_sarif(findings), ensure_ascii=False, indent=2)


def _surface(value: str):
    from .model import Surface
    try:
        return Surface(value)
    except ValueError:
        return Surface.PROCESS
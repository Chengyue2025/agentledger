"""证据包生成：JSON（机器可读/归档用）+ Markdown（人可读/送审用）。"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from . import TOOL_ID, __version__
from .mapping import OBLIGATIONS, OBLIGATION_PRIORITY, obligations_for, readiness_gap
from .model import SEVERITY_ORDER, Coverage, Finding, Severity

SEV_MARK = {
    Severity.CRITICAL: "■",
    Severity.HIGH: "▲",
    Severity.MEDIUM: "◆",
    Severity.LOW: "○",
    Severity.INFO: "·",
}

SEV_ZH = {s: s.zh for s in SEVERITY_ORDER}


def build_pack(result_findings: list[Finding], coverage: Coverage,
               ledger_head: str = "", merkle: str = "",
               attestation: str = "", attester: str = "") -> dict[str, Any]:
    counts = {s.value: 0 for s in SEVERITY_ORDER}
    for f in result_findings:
        counts[f.severity.value] += 1

    surface_counts: dict[str, int] = {}
    tag_counts: dict[str, int] = {}
    rule_counts: dict[str, int] = {}
    for f in result_findings:
        surface_counts[f.surface.value] = surface_counts.get(f.surface.value, 0) + 1
        rule_counts[f.rule_id] = rule_counts.get(f.rule_id, 0) + 1
        for t in f.tags:
            tag_counts[t] = tag_counts.get(t, 0) + 1

    return {
        "pack_version": "1.0",
        "tool": TOOL_ID,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "integrity": {
            "findings_merkle_root": merkle,
            "ledger_head": ledger_head,
            "attestation_hmac_sha256": attestation,
            "attester": attester,
        },
        "summary": {
            "total_findings": len(result_findings),
            "by_severity": counts,
            "by_surface": dict(sorted(surface_counts.items())),
            "by_tag": dict(sorted(tag_counts.items(), key=lambda kv: -kv[1])),
            "by_rule": dict(sorted(rule_counts.items())),
        },
        "coverage": coverage.summary() if coverage else {},
        "coverage_exclusions": (
            [
                {"path": e.path, "reason": e.reason, "bytes": e.size}
                for e in coverage.exclusions
            ] if coverage else []
        ),
        "findings": [
            {
                **f.to_dict(),
                "location": f.location(),
                "obligations": obligations_for(f.rule_id),
            }
            for f in result_findings
        ],
        "compliance": {
            "obligations_touched": sorted(
                readiness_gap(result_findings).keys(),
                key=lambda o: OBLIGATION_PRIORITY.index(o)
                if o in OBLIGATION_PRIORITY else 999,
            ),
            "gaps": readiness_gap(result_findings),
            "obligation_catalog": {
                k: OBLIGATIONS[k] for k in OBLIGATION_PRIORITY if k in OBLIGATIONS
            },
        },
    }


def pack_to_json(pack: dict[str, Any]) -> str:
    return json.dumps(pack, ensure_ascii=False, indent=2, sort_keys=False)


def pack_to_markdown(pack: dict[str, Any]) -> str:
    s = pack["summary"]
    cov = pack.get("coverage", {})
    integ = pack["integrity"]
    L: list[str] = []
    A = L.append

    A("# 智能体合规证据包 / AI Agent Assurance Evidence Pack")
    A("")
    A(f"> 由 `{pack['tool']}` 生成于 `{pack['generated_at']}`  "
      "(UTC)")
    A(">")
    A("> **本文件是技术证据，不构成法律意见。** 法律结论须由具备资质的"
      "专业人员结合具体业务作出并签署。")
    A("")
    A("---")
    A("")

    # ---- 0. 完整性 ----
    A("## 0. 完整性锚点")
    A("")
    A("| 项 | 值 |")
    A("|---|---|")
    A(f"| 发现项 Merkle 根 | `{integ['findings_merkle_root'] or '—'}` |")
    A(f"| 账本链头 | `{integ['ledger_head'] or '—'}` |")
    A(f"| 人工签署 (HMAC-SHA256) | `{integ['attestation_hmac_sha256'] or '未签署'}` |")
    A(f"| 签署人 | {integ['attester'] or '**未签署**'} |")
    A("")
    A("> 机器产出上述证据根；**签署必须由人完成**——这是本证据链中"
      "唯一无法自动化的环节。")
    A("")

    # ---- 1. 覆盖度 ----
    A("## 1. 扫描覆盖度（我看了什么 / 我没看什么）")
    A("")
    A("| 项 | 值 |")
    A("|---|---|")
    A(f"| 扫描根 | `{cov.get('root', '—')}` |")
    A(f"| 起 / 止 | `{cov.get('started_at', '—')}` → `{cov.get('finished_at', '—')}` |")
    A(f"| 已扫描文件 | {cov.get('scanned_files', 0)} |")
    A(f"| 已扫描字节 | {cov.get('scanned_bytes', 0):,} |")
    A(f"| AI 攻击面文件 | {cov.get('ai_surface_files', 0)} |")
    A(f"| **未扫描 / 排除** | **{cov.get('excluded_count', 0)} 个文件 "
      f"({cov.get('excluded_bytes', 0):,} 字节)** |")
    A("")
    excl = pack.get("coverage_exclusions", [])
    if excl:
        A("<details><summary>排除明细（点击展开）</summary>")
        A("")
        A("| 文件 | 排除原因 | 字节 |")
        A("|---|---|---|")
        for e in excl[:200]:
            A(f"| `{e['path']}` | {e['reason']} | {e['bytes']:,} |")
        if len(excl) > 200:
            A(f"| … | 其余 {len(excl) - 200} 条见 JSON 证据包 | |")
        A("")
        A("</details>")
        A("")
        A("> 排除项同样重要：它界定了本次结论的**适用边界**。")
    A("")

    # ---- 2. 结论摘要 ----
    A("## 2. 结论摘要")
    A("")
    A("| 严重度 | 数量 |")
    A("|---|---:|")
    for sev in SEVERITY_ORDER:
        A(f"| {SEV_MARK[sev]} {sev.value} / {SEV_ZH[sev]} | {s['by_severity'][sev.value]} |")
    A(f"| **合计** | **{s['total_findings']}** |")
    A("")
    if s["by_surface"]:
        A("按攻击面分布：")
        A("")
        A("| 攻击面 | 发现数 |")
        A("|---|---:|")
        for k, v in s["by_surface"].items():
            A(f"| `{k}` | {v} |")
        A("")
    if s["by_tag"]:
        A("按风险类别 Top：" + "、".join(
            f"`{k}`×{v}" for k, v in list(s["by_tag"].items())[:8]))
        A("")

    # ---- 3. 监管义务映射 ----
    touched = pack["compliance"]["obligations_touched"]
    A("## 3. 触及的监管义务")
    A("")
    if not touched:
        A("本次扫描未触及已知义务条款。")
    else:
        A("| 义务 | 标题 | 未满足项 |")
        A("|---|---|---:|")
        gaps = pack["compliance"]["gaps"]
        for oid in touched:
            meta = OBLIGATIONS.get(oid, {})
            A(f"| `{oid}` | {meta.get('title', '')} | {len(gaps.get(oid, []))} |")
    A("")

    # ---- 4. 发现项明细 ----
    A("## 4. 发现项明细")
    A("")
    if not pack["findings"]:
        A("**未发现符合阈值的问题。**")
    for sev in SEVERITY_ORDER:
        group = [f for f in pack["findings"] if f["severity"] == sev.value]
        if not group:
            continue
        A(f"### {SEV_MARK[sev]} {sev.value} / {SEV_ZH[sev]} — {len(group)} 项")
        A("")
        for f in group:
            A(f"#### `{f['rule_id']}` {f['title']}")
            A("")
            A(f"- **位置**：`{f['location']}`")
            if f.get("component"):
                A(f"- **组件**：`{f['component']}`")
            A(f"- **证据**：{f['evidence']}")
            A(f"- **为何是问题**：{f['rationale']}")
            A(f"- **整改动作**：{f['remedy']}")
            obs = f.get("obligations") or []
            if obs:
                A("- **对应义务**：" + "、".join(f"`{o['id']}` {o['title']}" for o in obs))
            if f.get("tags"):
                A("- **标签**：" + " ".join(f"`{t}`" for t in f["tags"]))
            A("")
    A("")

    # ---- 5. 签署 ----
    A("---")
    A("")
    A("## 5. 复核与签署")
    A("")
    A("| | 姓名 | 日期 | 签名 |")
    A("|---|---|---|---|")
    A("| 技术复核 | | | |")
    A("| 合规复核 | | | |")
    A("| **批准（具责人）** | | | |")
    A("")
    A("> 本证据包在技术层面完整，但**责任归属于签署人**。"
      "机器不能承担法律责任，这正是该环节必须由人完成的原因。")
    A("")
    return "\n".join(L)
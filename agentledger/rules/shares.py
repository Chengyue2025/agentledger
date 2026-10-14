"""分享包 / marketplace bot 规则（SHR 族）。

攻击面：**share link 即授权**。2026-10 实调确认：

  · Grok Bot（xAI，闭源）：share link 一键复制 bot 的 identity/描述/
    Skills/Routines——不含电脑/登录/历史，但**包含其可执行的技能与例程**；
    awesome-grok-bot 索引了 3954 个 live share；grokport 等第三方工具正在
    帮用户把这些 share 批量搬进 Claude/Codex/Cursor/OpenCode 等 agent；
  · OpenClaw ClawHub：44K+ skills，820+ 被标记恶意（7.6%）；
  · 共同点：**导入前没有任何验证**。用户点"Add to Grok Bot"的那一刻，
    该 share 的全部 skills/routines 就成了自己 agent 的指令。

本族回答的问题：**这个分享包，在导入之前能不能证明它没藏东西？**
与 PRM 族的分工：PRM 扫"仓库里的提示词文件"，SHR 扫"外来分享包的
结构化清单"（secret / 注入 / 高风险 routine / 来源证明 / 共享计算机访问）。

设计原则：只对**分享包形态**的制品开火（share/bot/marketplace 清单），
避免与 PRM/MCP 族重复误报。
"""

from __future__ import annotations

import re
from typing import Any, Iterator

from ..model import Artifact, Finding, Severity, Surface
from .common import (
    ASSIGNED_SECRET_RE,
    GOVERNANCE_KEYWORDS,
    HIGH_RISK_ACTIONS,
    INJECTION_PATTERNS,
    SECRET_PATTERNS,
    find_hidden_injection,
    first_match,
    is_placeholder,
    line_of,
    line_of_regex,
    redact,
)

# --------------------------------------------------------------------------
# 分享包识别：bot/share/marketplace/routine 的结构化清单
# --------------------------------------------------------------------------
SHARE_PATH_RE = re.compile(
    r"""(?ix)
    (?: ^ | / )
    (?: [\w.\-]* share [\w.\-]*          # share.json / grok-share-xxx.json
      | bot \. (?:json|jsonc|ya?ml|toml)
      | [\w.\-]* marketplace [\w.\-]
      | [\w.\-]* routine [\w.\-]
      | team [\w.\-]* bot [\w.\-]
      )
    (?: \. (?:json|jsonc|yaml|yml|toml) )? $
    | (?: ^ | / ) (?: shares? | bots | marketplace | routines ) / [\w.\-]+ $
    """
)
SHARE_DIR_RE = re.compile(r"(?i)(^|/)(shares?/|bots/|marketplace/|routines/)")

# 结构强信号：Grok share 导出惯例（bot profile + skills + routines）
_SHARE_KEYS = ("skills", "routines", "bot", "profile", "identity",
               "instructions", "persona", "memory", "workflows")

# 判定用词表
_APPROVAL_DECLARED = GOVERNANCE_KEYWORDS["approval_gate"] + (
    "approval", "approve", "confirm", "human", "审批", "签字", "确认",
)
_PROVENANCE_DECLARED = (
    "source", "publisher", "author", "signature", "signed", "digest",
    "sha256", "checksum", "provenance", "attestation", "hash",
    "来源", "发布者", "签名", "校验", "摘要",
)
_ISOLATION_DECLARED = (
    "isolation", "isolated", "sandbox", "separate", "scoped",
    "隔离", "沙箱", "独立", "分域",
)
_SHARED_COMPUTER_MARKERS = (
    "shared_computer", "computer_use", "computer", "browser", "browser_session",
    "session", "login", "credentials", "keychain", "desktop", "file_system",
    "计算机", "浏览器", "登录", "会话", "凭据",
)


def _blob(node: Any) -> str:
    parts: list[str] = []

    def walk(n: Any, depth: int) -> None:
        if depth > 14:
            return
        if isinstance(n, dict):
            for k, v in n.items():
                parts.append(str(k).lower())
                walk(v, depth + 1)
        elif isinstance(n, list):
            for v in n:
                walk(v, depth + 1)
        elif isinstance(n, str):
            parts.append(n.lower())

    walk(node, 0)
    return " ".join(parts)


def _any(blob: str, markers: tuple[str, ...]) -> bool:
    return any(m in blob for m in markers)


def _is_share_package(art: Artifact) -> bool:
    if art.kind not in ("json", "toml", "yaml"):
        return False
    path = art.path.lower()
    if SHARE_DIR_RE.search(path) or SHARE_PATH_RE.search(path):
        return True
    data = art.data
    if isinstance(data, dict):
        hits = sum(1 for k in _SHARE_KEYS if k in data)
        # bot/skills/routines 至少两类同现，才认定为分享包
        return hits >= 2
    return False


def _finding(art, rid, title, sev, surface, line, evidence, rationale,
             remedy, tags) -> Finding:
    return Finding(
        rule_id=rid, title=title, severity=sev, surface=surface,
        path=art.path, line=line, evidence=evidence[:200],
        rationale=rationale, remedy=remedy, tags=tags,
    )


# --------------------------------------------------------------------------
def scan(art: Artifact) -> Iterator[Finding]:
    if not _is_share_package(art):
        return
    blob = _blob(art.data) if art.data is not None else (art.text or "").lower()
    text = art.text or ""

    yield from _secrets(art, text)
    yield from _injection(art, text)
    yield from _risky_routine(art, blob)
    yield from _provenance(art, blob)
    yield from _shared_computer(art, blob)


# --------------------------------------------------------------------------
def _secrets(art: Artifact, text: str) -> Iterator[Finding]:
    """分享包里出现明文凭据 = 最高级别警报。

    share link 传播的是 bot 配方；配方里不该有任何密钥。
    出现即说明：要么发布者把环境塞进了配方，要么这是钓鱼包。
    """
    for pattern, desc in SECRET_PATTERNS:
        m = re.search(pattern, text)
        if m:
            yield _finding(
                art, "SHR001", "分享包内含明文凭据", Severity.CRITICAL,
                Surface.PROMPT, text.count("\n", 0, m.start()) + 1,
                evidence=f"{desc}: {redact(m.group(0), 4)}",
                rationale="分享包会被他人原样导入。其中的凭据即已泄露——"
                          "任何 Add 过该 share 的 agent 都能读到。"
                          "此类包同时是钓鱼包的高发形态。",
                remedy="立即轮换该凭据；清除包内密钥；发布方改用环境变量引用；"
                       "为分享包建立签名与扫描。",
                tags=("share", "secret", "critical"),
            )
            return
    for m in ASSIGNED_SECRET_RE.finditer(text):
        if is_placeholder(m.group("val")):
            continue
        yield _finding(
            art, "SHR001", "分享包内含疑似明文凭据", Severity.HIGH,
            Surface.PROMPT, text.count("\n", 0, m.start()) + 1,
            evidence=f"赋值型凭据: {m.group('name')}={redact(m.group('val'), 4)}",
            rationale="分享包中出现带变量名的长字符串赋值，通常是发布者"
                      "误将环境配置打进配方。",
            remedy="清除该字段；确认该值未与 share 一同分发；轮换以防万一。",
            tags=("share", "secret"),
        )
        return


def _injection(art: Artifact, text: str) -> Iterator[Finding]:
    """skills/routines 文本里的注入指令 —— 导入即成持久后门。"""
    hidden = find_hidden_injection(text)
    if hidden:
        frag, ln = hidden
        yield _finding(
            art, "SHR002", "分享包技能/例程中藏有注入指令（隐蔽容器）",
            Severity.CRITICAL, Surface.PROMPT, ln,
            evidence=redact(frag[:80], 8),
            rationale="指令藏在注释/script 容器里：人眼审查不可见，"
                      "但导入后会被 agent 纳入上下文执行。这是对分享生态的"
                      "定向攻击——攻击者发布有用分享，导入即中招。",
            remedy="拒绝导入该分享；清除隐藏内容；对社区分享建立"
                   "导入前行为扫描（本工具 SHR 族即为此设计）。",
            tags=("share", "prompt-injection", "covert-channel", "critical"),
        )
        return
    hit = first_match(text, INJECTION_PATTERNS)
    if hit:
        yield _finding(
            art, "SHR002", "分享包技能/例程中存在注入指令",
            Severity.CRITICAL, Surface.PROMPT,
            line=text.count("\n", 0, text.find(hit[2])) + 1 if hit[2] in text else None,
            evidence=redact(hit[2][:80], 8) + f"（命中 {hit[1]}）",
            rationale="分享包的 skills/routines 会被导入方 agent 当作指令执行。"
                      "覆盖式/隐瞒式指令可劫持导入方 agent 去调用任意工具。",
            remedy="拒绝导入；对分享生态的来源与内容建立双向核验。",
            tags=("share", "prompt-injection", "critical"),
        )
        return


def _risky_routine(art: Artifact, blob: str) -> Iterator[Finding]:
    """routine 里带高风险动作（支付/删除/外发）但无审批闸门。"""
    risk = [a for a in HIGH_RISK_ACTIONS if a in blob]
    if not risk or _any(blob, _APPROVAL_DECLARED):
        return
    yield _finding(
        art, "SHR003", "分享包含高风险自主动作但无审批闸门",
        Severity.HIGH, Surface.AGENT,
        line=line_of(art.text or "", risk[0]),
        evidence="高风险动作: " + ", ".join(sorted(set(risk))[:8]),
        rationale="Grok Bot 的 routine 可定时执行。导入一个带支付/外发/删除"
                  "动作且无人审的 routine，等于给攻击者一个可周期触发的杠杆。",
        remedy="导入前确认每个 routine 的动作边界与额度；为支付/外发类动作"
               "配置人工审批；对定时任务设执行白名单。",
        tags=("share", "financial-risk", "governance"),
    )


def _provenance(art: Artifact, blob: str) -> Iterator[Finding]:
    """无来源证明：无法回答"这是谁发布的、和发布时一样吗"。"""
    if _any(blob, _PROVENANCE_DECLARED):
        return
    yield _finding(
        art, "SHR004", "分享包缺少来源证明（发布者/签名/摘要）",
        Severity.MEDIUM, Surface.AGENT,
        line=1,
        evidence="未发现 source / publisher / signature / digest 类字段",
        rationale="没有来源证明的分享包不可复现也不可追责：同一个 share link "
                  "今天和明天导入的可能不是同一份内容（走红后投毒），"
                  "出事后找不到发布者。这正是 ClawHub 被批量绕过验证的形态。",
        remedy="为分享包引入签名链与内容摘要；发布者身份可核验；"
               "导入时记录包哈希供事后比对。",
        tags=("share", "provenance", "supply-chain"),
    )


def _shared_computer(art: Artifact, blob: str) -> Iterator[Finding]:
    """要求访问共享计算机/浏览器会话/登录态，但未声明隔离。

    DataCamp 2026-10 实测：Grok Bot 各 bot 名字分开，但共享同一台 computer，
    凭据并不隔离。一个索取 computer/browser 访问的 share 因此天然高危。
    """
    hits = [m for m in _SHARED_COMPUTER_MARKERS if m in blob]
    if not hits or _any(blob, _ISOLATION_DECLARED):
        return
    yield _finding(
        art, "SHR005", "分享包索取共享计算机/会话访问但无隔离声明",
        Severity.HIGH, Surface.AGENT,
        line=line_of(art.text or "", hits[0]),
        evidence=f"访问类声明: {', '.join(hits[:5])}；未见隔离/分域声明",
        rationale="在「一个 bot 班子共用一台计算机、凭据不隔离」的架构里，"
                  "索取 computer/browser/session 访问的分享包能触达该计算机上"
                  "所有登录态。导入它等于把全部 bot 的凭据交出去。",
        remedy="导入前确认其工具访问面；为不同 bot 配置独立运行环境与"
               "凭据命名空间；计算机/浏览器类工具默认 deny。",
        tags=("share", "access-control", "isolation"),
    )


__all__ = ["scan"]

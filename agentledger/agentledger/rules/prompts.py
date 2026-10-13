"""提示词 / 技能 / 指令模板规则。

攻击面：这些文件会被模型当作**高优先级指令**读取。
一次成功的隐藏注入，等价于给智能体装了一个不可见的持久后门。
"""

from __future__ import annotations

import re
from typing import Iterator

from ..model import Artifact, Finding, Severity, Surface
from .common import (
    ANTHROPOMORPHIC_MARKERS,
    BASE64_BLOB_RE,
    BIDI_RE,
    HIDDEN_CONTAINER_RE,
    INJECTION_PATTERNS,
    ZERO_WIDTH_RE,
    first_match,
    redact,
    shannon_entropy,
)


def scan(art: Artifact) -> Iterator[Finding]:
    if art.kind != "markdown" or not art.text:
        return
    text = art.text
    yield from _visible_injection(art)
    yield from _hidden_injection(art)
    yield from _invisible_chars(art)
    yield from _opaque_blob(art)
    yield from _anthropomorphic(art)


def _visible_injection(art: Artifact) -> Iterator[Finding]:
    hit = first_match(art.text, INJECTION_PATTERNS)
    if hit:
        line = art.text.count("\n", 0, art.text.find(hit[2])) + 1 if hit[2] in art.text else None
        yield Finding(
            rule_id="PRM001",
            title="提示词/指令模板中存在注入指令",
            severity=Severity.HIGH,
            surface=Surface.PROMPT,
            path=art.path,
            line=line,
            evidence=redact(hit[2], 36),
            rationale=f"命中 {hit[1]}。该文件会被智能体当作指令读取，"
                      f"攻击者可借此覆盖系统提示、强制调用特定工具或绕过人工确认。",
            remedy="移除该指令；核验该文件的提交者与审批记录；"
                   "对技能/提示词目录建立签名与评审流程。",
            tags=("prompt-injection", "supply-chain"),
        )


def _hidden_injection(art: Artifact) -> Iterator[Finding]:
    """注入藏在注释 / script / style 里 —— 人眼看不见，模型看得见。"""
    for m in HIDDEN_CONTAINER_RE.finditer(art.text):
        block = m.group(0)
        # 去掉容器标记后再找注入
        inner = block[4:-3] if block.startswith("<!--") else block
        hit = first_match(inner, INJECTION_PATTERNS)
        if hit:
            yield Finding(
                rule_id="PRM002",
                title="隐藏注入：指令被藏在注释/不可见容器中",
                severity=Severity.CRITICAL,
                surface=Surface.PROMPT,
                path=art.path,
                line=art.text.count("\n", 0, m.start()) + 1,
                evidence=redact(f"{block[:4]}...{hit[2][:80]}", 20),
                rationale="代码审查与人工阅读看不到 HTML/块注释内部内容，"
                          "但模型会将其纳入上下文。这是典型的隐蔽持久化注入手法。",
                remedy="删除隐藏内容；建立 CI 检查，禁止指令文件中出现带指令语义的注释；"
                       "将该文件的哈希纳入 AI BOM。",
                tags=("prompt-injection", "covert-channel", "critical"),
            )
            return


def _invisible_chars(art: Artifact) -> Iterator[Finding]:
    """零宽 / 双向控制字符 —— 可隐藏任意指令而不改变视觉长度。"""
    zw = ZERO_WIDTH_RE.search(art.text)
    if not zw:
        return
    line = art.text.count("\n", 0, zw.start()) + 1

    # 分别统计两类，并如实报告首个命中的码位
    zero_width = [c for c in ZERO_WIDTH_RE.findall(art.text) if c not in "‪‫‬‭‮"]
    bidi = BIDI_RE.findall(art.text)
    detail = [f"首个码位 U+{ord(zw.group(0)):04X}"]
    if zero_width:
        detail.append(f"零宽字符 x{len(zero_width)}")
    if bidi:
        detail.append(f"双向控制 x{len(bidi)} (U+{ord(bidi[0]):04X})")

    yield Finding(
        rule_id="PRM003",
        title="提示词中存在零宽/双向控制字符",
        severity=Severity.HIGH,
        surface=Surface.PROMPT,
        path=art.path,
        line=line,
        evidence="; ".join(detail),
        rationale="零宽字符不占位、不显示，却会被模型解码为指令内容；"
                  "双向控制符可让指令在视觉上顺序错乱，人工审核几乎不可能发现。",
        remedy="清除全部不可见控制字符；在 CI 中加入 Unicode 类别白名单校验。",
        tags=("covert-channel", "prompt-injection"),
    )


def _opaque_blob(art: Artifact) -> Iterator[Finding]:
    """长 base64 块 —— 审查者无法判断其真实内容。"""
    for m in BASE64_BLOB_RE.finditer(art.text):
        blob = m.group(0)
        try:
            import base64
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            printable = sum(1 for b in decoded if 32 <= b < 127 or b in (9, 10, 13))
        except Exception:
            printable = 0
        if len(decoded) < 16 or printable / max(len(decoded), 1) < 0.8:
            continue
        text = decoded.decode("utf-8", "ignore")
        hit = first_match(text, INJECTION_PATTERNS)
        if hit:
            yield Finding(
                rule_id="PRM004",
                title="base64 载荷中藏有注入指令",
                severity=Severity.CRITICAL,
                surface=Surface.PROMPT,
                path=art.path,
                line=art.text.count("\n", 0, m.start()) + 1,
                evidence=f"base64({len(blob)}) -> {redact(hit[2], 28)}",
                rationale=f"base64 载荷解码后命中 {hit[1]}。载荷对人工审查不可读，"
                          f"但在模型上下文中会被正常解码执行。",
                remedy="移除该载荷；禁止指令文件内出现可解码为文本的长 base64 块。",
                tags=("covert-channel", "prompt-injection", "critical"),
            )
            return


def _anthropomorphic(art: Artifact) -> Iterator[Finding]:
    low = art.text.lower()
    hit = next((m for m in ANTHROPOMORPHIC_MARKERS if m in low), None)
    if not hit:
        return
    # 已有披露声明就不报
    if any(k in art.text for k in ("拟人化互动服务", "AI 生成", "人工智能生成", "非真人", "AI 助手")):
        return
    line = art.text.lower().find(hit)
    yield Finding(
        rule_id="PRM005",
        title="拟人化/情感陪伴类智能体未见必要披露声明",
        severity=Severity.MEDIUM,
        surface=Surface.PROMPT,
        path=art.path,
        line=art.text.count("\n", 0, line) + 1 if line >= 0 else None,
        evidence=f"marker: {hit}",
        rationale="《人工智能拟人化互动服务管理暂行办法》已于 2026-07-15 生效，"
                  "要求向用户明确提示其与 AI 交互的性质，并采取防止情感依赖的措施。",
        remedy="在交互界面显著位置声明 AI 身份；评估并落实防情感依赖措施；留存告知记录。",
        tags=("regulatory", "cn", "anthropomorphic"),
    )
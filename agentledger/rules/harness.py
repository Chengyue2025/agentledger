"""Harness 插件 / 运行时配置规则（HRN 族）。

攻击面：**插件即权限**。2026-10 实调确认的三个生态都在开这个口子——

  · DeepSeek Harness（dsh，MIT）："一切皆插件"（模型/工具/Skills/会话/
    沙箱/存储/主循环/UI 全是插件），1000+ 插件，社区共识是"给 Agent 装插件
    本质上是在给本机放权限"——而它**没有任何安全审核机制**；
  · dsh-im 类 IM 桥：扫码即建机器人，默认全员放行可执行命令；
  · grok-build（Apache-2.0）：扩展系统里跑 shell/工具。

本族回答的问题：**这个插件清单，能不能在导入前就证明它要的权限是必要的、
可审计的、有人把关的？** 与 AGT 族的区别：AGT 查"智能体治理声明"，
HRN 查"第三方插件清单的最小权限与留痕"——攻击者不需要攻破你的Agent，
只需要你装一个插件。

设计原则（继承 common.py）：宁可漏报不要乱报。只对**插件清单形态**的
制品开火（文件名 + 解析后的键结构双重判定），普通 package.json /
requirements.txt 不会命中。
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterator

from ..model import Artifact, Finding, Severity, Surface
from .common import (
    CODE_EXEC_PATTERNS,
    GOVERNANCE_KEYWORDS,
    SECRET_PATTERNS,
    first_match,
    line_of,
    line_of_regex,
    redact,
)
from .shares import SHARE_DIR_RE, SHARE_PATH_RE  # 分享包归 SHR 族，不重复开火

# --------------------------------------------------------------------------
# 插件清单识别
# --------------------------------------------------------------------------
# 文件名/路径Hint：dsh (Cordis) 插件、IM bot 配置、例程、marketplace 包
PLUGIN_PATH_RE = re.compile(
    r"""(?ix)
    (?: ^ | / )
    (?: [\w.\-]* plugin [\w.\-]*        # plugin.json / acme.plugin.yaml
      | [\w.\-]* cordis [\w.\-]
      | [\w.\-]* dsh [\w.\-]
      | [\w.\-]* harness [\w.\-]
      | bot \. (?:json|jsonc|ya?ml|toml)
      | [\w.\-]* share [\w.\-]* \. (?:json|jsonc|ya?ml|toml)
      | [\w.\-]* routine [\w.\-]* \. (?:json|jsonc|ya?ml|toml)
      | [\w.\-]* marketplace [\w.\-]* \. (?:json|jsonc|ya?ml|toml)
      )
    (?: \. (?:json|jsonc|yaml|yml|toml) )? $
    | (?: ^ | / ) (?: plugins? | plugins? \.d | bots | routines | shares | harness ) / [\w.\-]+ $
    """
)
PLUGIN_DIR_RE = re.compile(
    r"(?i)(^|/)(plugins?/|plugins?\.d/|plugin\.d/|\.dsh/|harness/)")

# 解析后结构里的"这是插件清单"强信号
_MANIFEST_STRONG_KEYS = (
    "entry", "main", "provides", "permissions", "capabilities",
    "routines", "skills", "commands", "tools", "cordis",
)
# 声明了插件类型（dsh/Cordis plugin.json 惯例：{"type": "plugin"}）
_PLUGIN_TYPE_VALUES = ("plugin", "cordis-plugin", "dsh-plugin", "harness-plugin")

# --------------------------------------------------------------------------
# 判定用词表
# --------------------------------------------------------------------------
_PERMISSION_DECLARED = (
    "permission", "scope", "capability", "capabilities", "allowlist",
    "whitelist", "permitted", "allowed_actions", "action_boundary",
    "权限", "范围", "能力声明", "调用范围",
)
_EGRESS_CONTROLLED = (
    "egress", "allowlist", "whitelist", "domain_whitelist", "url_allowlist",
    "network_policy", "出口", "白名单", "域名清单", "网络策略",
)
_SANDBOX_DECLARED = (
    "sandbox", "isolation", "isolated", "container", "seccomp", "jail",
    "沙箱", "隔离", "容器",
)
_APPROVAL_DECLARED = GOVERNANCE_KEYWORDS["approval_gate"] + (
    "approval", "approve", "confirm", "human", "审批", "签字", "确认",
)
_TRAJECTORY_DECLARED = (
    "trajectory", "trace", "audit_log", "audit", "logging", "log_retention",
    "轨迹", "留痕", "审计日志", "操作日志",
)
_OPEN_ACCESS_MARKERS = (
    "allow_all", "allowall", "open_access", "permission_all",
    "chat_permission_all", "all_users", "anyone_can", "public_access",
    "allow all", "全体可用", "全员", "所有人", "任意用户", "所有用户",
)
_OPEN_ACCESS_VALUES = ("all", "open", "public", "anyone", "everyone",
                       "all_users", "unrestricted", "default")
_WHITELIST_MARKERS = ("whitelist", "allowlist", "白名单", "许可名单")
_CREDENTIAL_ACCESS_MARKERS = (
    "credential", "secrets", "api_key", "apikey", "private_key",
    "token_store", "keychain", "keyring", "凭据", "密钥", "凭证",
)
_EXEC_TOOL_NAMES = (
    "bash", "shell", "sh", "exec", "execute", "terminal", "python",
    "node", "child_process", "subprocess", "powershell",
)
_NETWORK_MARKERS = (
    "network", "fetch", "http", "https", "url", "endpoint", "web_search",
    "browser", "download", "upload", "request", "api_call",
    "网络", "外联", "上传", "下载",
)
_UNPINNED_INSTALL_RE = re.compile(
    r"""(?ix)
    (?: npx \s+ (?:-y\s+)? | uvx \s+ | pip \s+ install \s+ | npm \s+ i(?:nstall)? \s+
      | go \s+ install \s+ | cargo \s+ install \s+ )
    [^\n&|;]{0,120}
    (?: (?<! =)(?<! = " ) @ (?:latest|next) \b | -y \b )
    """
)
_FLOATING_VERSION_RE = re.compile(
    r"""(?ix) " (?: version | tag | ref | rev ) " \s* : \s* "
    (?: \* | latest | next | main | master | dev | unstable ) " """)


def _blob(node: Any) -> str:
    """扁平化 dict/list 为小写检索串（键与字符串值都纳入）。"""
    parts: list[str] = []

    def walk(n: Any, depth: int) -> None:
        if depth > 12:
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


def _matched(blob: str, markers: tuple[str, ...]) -> list[str]:
    return [m for m in markers if m in blob]


def _is_plugin_manifest(art: Artifact) -> bool:
    """双重判定：路径形态 + 解析结构。普通配置文件不得命中。

    注意：分享包（share.json / bots/ / marketplace/）归 SHR 族管辖，
    此处显式排除，避免两族对同一制品重复开火。
    """
    if art.kind not in ("json", "toml", "yaml"):
        return False
    path = art.path.lower()
    if SHARE_DIR_RE.search(path) or SHARE_PATH_RE.search(path):
        return False
    if PLUGIN_DIR_RE.search(path):
        return True
    if PLUGIN_PATH_RE.search(path):
        return True
    data = art.data
    if isinstance(data, dict):
        t = str(data.get("type", "")).lower()
        if t in _PLUGIN_TYPE_VALUES:
            return True
        strong = sum(1 for k in _MANIFEST_STRONG_KEYS if k in data)
        if strong >= 2 and any(
                k in data for k in ("entry", "main", "provides", "permissions",
                                    "capabilities", "routines")):
            return True
    return False


def _finding(art: Artifact, rid: str, title: str, sev: Severity, surface: Surface,
             line: int | None, evidence: str, rationale: str, remedy: str,
             tags: tuple[str, ...]) -> Finding:
    return Finding(
        rule_id=rid, title=title, severity=sev, surface=surface,
        path=art.path, line=line, evidence=evidence[:200],
        rationale=rationale, remedy=remedy, tags=tags,
    )


# --------------------------------------------------------------------------
def scan(art: Artifact) -> Iterator[Finding]:
    if not _is_plugin_manifest(art):
        return
    blob = _blob(art.data) if art.data is not None else (art.text or "").lower()
    text = art.text or ""

    yield from _permissions_declared(art, blob)
    yield from _pinning(art, blob, text)
    yield from _credential_access(art, blob)
    yield from _egress(art, blob)
    yield from _sandbox(art, blob, text)
    yield from _trajectory(art, blob)
    yield from _im_open_access(art, blob, art.data)


# --------------------------------------------------------------------------
def _permissions_declared(art: Artifact, blob: str) -> Iterator[Finding]:
    if _any(blob, _PERMISSION_DECLARED):
        return
    yield _finding(
        art, "HRN001", "插件清单未声明权限范围", Severity.HIGH, Surface.AGENT,
        line=1,
        evidence="未发现 permissions / capabilities / scope / action_boundary 类字段",
        rationale="插件导入即授予其清单所列能力。没有权限范围声明，就无法证明"
                  "该插件遵循最小权限原则，也无法在事后界定责任边界——"
                  "dsh 生态目前对插件的安全审核为零，导入前的清单是唯一闸门。",
        remedy="在插件清单中声明 permissions/capabilities（含网络、文件、"
               "凭据、工具四类的最小集），并使其可被机器校验。",
        tags=("harness", "least-privilege", "supply-chain"),
    )


def _pinning(art: Artifact, blob: str, text: str) -> Iterator[Finding]:
    m = _UNPINNED_INSTALL_RE.search(text) or _FLOATING_VERSION_RE.search(text)
    if not m:
        return
    yield _finding(
        art, "HRN002", "插件版本未固定（运行时安装或浮动标签）",
        Severity.HIGH, Surface.DEPS,
        line=text.count("\n", 0, m.start()) + 1,
        evidence=redact(m.group(0).strip()[:80], 8),
        rationale="运行时自动安装或 @latest 浮动标签意味着同一份清单在不同时间"
                  "拉到的可能不是同一份代码——构建不可复现，投毒窗口常开。"
                  "这与 MCP002（运行时自动安装）是同一攻击面的 harness 形态。",
        remedy="锁定精确版本 + 记录来源哈希；禁止在清单中使用 npx -y / "
               "@latest 等运行时安装写法。",
        tags=("harness", "supply-chain"),
    )


def _credential_access(art: Artifact, blob: str) -> Iterator[Finding]:
    hits = _matched(blob, _CREDENTIAL_ACCESS_MARKERS)
    if not hits:
        return
    if _any(blob, _APPROVAL_DECLARED):
        return
    line = line_of(art.text or "", hits[0])
    yield _finding(
        art, "HRN003", "插件可访问凭据但无审批闸门声明",
        Severity.CRITICAL, Surface.AGENT,
        line=line,
        evidence=f"凭据访问声明: {', '.join(hits[:4])}；未见审批/人工确认字段",
        rationale="能接触凭据存储（keychain/keyring/token_store/环境变量）的插件，"
                  "一旦被污染即可横向取走该计算机上的全部登录态。xAI 的 grok-build"
                  " 曾被实测上传用户整个 git 仓库与 SSH keys——凭据接触面必须"
                  "有人工闸门与额度声明。",
        remedy="为凭据访问类能力增加显式审批闸门；按凭据类型分级授权；"
               "所有凭据读取动作接入运行时留痕。",
        tags=("harness", "secret", "governance", "critical"),
    )


def _egress(art: Artifact, blob: str) -> Iterator[Finding]:
    if not _any(blob, _NETWORK_MARKERS):
        return
    if _any(blob, _EGRESS_CONTROLLED):
        return
    yield _finding(
        art, "HRN004", "插件具有网络能力但无出口白名单控制",
        Severity.HIGH, Surface.AGENT,
        line=1,
        evidence="检出网络/外联语义；未见 egress / allowlist / 网络策略声明",
        rationale="无出口控制的网络能力 = 静默外传通道。被污染插件可以把"
                  "代码库、会话内容、凭据发往任意端点，且不触发任何工具调用记录。",
        remedy="声明出口白名单（域名/协议/端口）；默认 deny-all，"
               "按需放行；出口决策纳入留痕。",
        tags=("harness", "exfiltration", "least-privilege"),
    )


def _sandbox(art: Artifact, blob: str, text: str) -> Iterator[Finding]:
    exec_names = [t for t in _EXEC_TOOL_NAMES if f'"{t}"' in text or f"'{t}'" in text
                  or t in blob.split()]
    has_sink = bool(first_match(text, CODE_EXEC_PATTERNS))
    if not (exec_names or has_sink):
        return
    if _any(blob, _SANDBOX_DECLARED):
        return
    hit = first_match(text, CODE_EXEC_PATTERNS)
    yield _finding(
        art, "HRN005", "插件具备代码执行能力但未声明沙箱/隔离",
        Severity.HIGH, Surface.DEPS,
        line=line_of_regex(text, hit[0]) if hit else 1,
        evidence=(f"执行类工具: {', '.join(exec_names[:5])}" if exec_names
                  else f"危险汇: {hit[1]}"),
        rationale="执行类能力没有隔离声明时，一次成功的提示词注入即可升级为"
                  "主机级代码执行。dsh/grok-build 的 harness 生态里，工具执行"
                  "普遍跑在宿主进程。",
        remedy="声明执行隔离方式（容器/seccomp/只读挂载/出口白名单）；"
               "对执行工具设置需审批的高风险动作标记。",
        tags=("harness", "isolation", "code-exec"),
    )


def _trajectory(art: Artifact, blob: str) -> Iterator[Finding]:
    if _any(blob, _TRAJECTORY_DECLARED):
        return
    yield _finding(
        art, "HRN006", "harness 运行时未声明轨迹/留痕能力",
        Severity.MEDIUM, Surface.PROCESS,
        line=1,
        evidence="未发现 trajectory / audit / trace / 留痕 类声明",
        rationale="EU AI Act Art.12/26 与国内责任留痕要求都假定运行时可导出"
                  "操作日志。dsh 的 Trajectory 证明这是可实现的；不声明即不可审计，"
                  "事故复盘无从谈起。",
        remedy="启用追加式轨迹日志（系统提示/推理/工具调用/子代理调度全量记录），"
               "并保证其可导出、可验真。",
        tags=("harness", "audit-trail", "regulatory"),
    )


def _im_open_access(art: Artifact, blob: str, data: Any = None) -> Iterator[Finding]:
    """IM 机器人权限档位全员放行。

    结构化检测优先：{"permission"/"access"/"chat_permission"/"scope": "all"}
    或 allow_all=true 这类配置；文本标记兜底。
    """
    hit = ""
    if isinstance(data, dict):
        for k, v in data.items():
            kl = str(k).lower()
            vl = str(v).strip().lower()
            if (any(w in kl for w in ("permission", "access", "chat", "scope"))
                    and vl in _OPEN_ACCESS_VALUES):
                hit = f"{k}={v}"
                break
            if kl in ("allow_all", "allowall", "open_access",
                      "allow_all_users", "allowanyone") and v is True:
                hit = f"{k}=true"
                break
    if not hit:
        marks = _matched(blob, _OPEN_ACCESS_MARKERS)
        hit = f"标记: {marks[0]}" if marks else ""
    if not hit:
        return
    if _any(blob, _WHITELIST_MARKERS):
        return
    yield _finding(
        art, "HRN007", "IM 机器人权限档位为全员放行且无白名单",
        Severity.HIGH, Surface.AGENT,
        line=line_of(art.text or "", hit.split("=", 1)[-1].strip()) or 1,
        evidence=f"全员放行配置（{hit}）",
        rationale="dsh-im 类扫码接入的 IM 机器人默认允许所有用户在私聊与群聊中"
                  "执行内置命令。这意味着任意能加到该机器人的外部账号都能驱动"
                  "其工具——群聊里的陌生人即是攻击者。",
        remedy="默认白名单模式（仅授权账号可执行命令）；命令按权限分级；"
               "在群聊中仅响应显式 @ 且经鉴权的来源。",
        tags=("harness", "access-control", "im"),
    )


__all__ = ["scan"]

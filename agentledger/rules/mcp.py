"""MCP 服务器规则 —— 智能体供应链风险的主要入口。

参考依据：
  - MCP 服务器一旦被投毒，等价于给智能体装了后门（工具投毒 / tool poisoning）
  - 《智能体规范应用与创新发展实施意见》将"模型、插件、工具、提示词模板、
    MCP 服务、Agent 注册表、数据集、第三方 Agent、更新渠道"明确列为供应链风险面
"""

from __future__ import annotations

import re
from typing import Any, Iterator

from ..model import Artifact, Finding, Severity, Surface
from .common import (
    ASSIGNED_SECRET_RE,
    INJECTION_PATTERNS,
    first_match,
    is_placeholder,
    redact,
)

SERVER_CONTAINER_KEYS = {"mcpservers", "mcp_servers", "mcpServers", "servers"}

# 运行时自动拉取并执行 —— 无完整性校验的供应链入口
AUTO_INSTALL_RE = re.compile(
    r"(?i)\b(npx\s+(?:-y|--yes)|uvx|pip\s+install|pipx\s+run|"
    r"pnpm\s+dlx|bunx|go\s+run|npm\s+install|docker\s+run)\b"
)

# 包名 + 精确版本（npm/pypi 的 pin）
PINNED_NPM_RE = re.compile(r"(@[a-z0-9\-_]+/)?[a-z0-9\-_]+@\d+\.\d+\.\d+")
PINNED_PYPI_RE = re.compile(r"==\s*\d")

# 完整性校验字段
INTEGRITY_KEYS = ("integrity", "sha256", "sha512", "hash", "checksum",
                  "digest", "signature", "attestation", "sbom")

BROAD_SCOPE_MARKERS = (
    "c:\\", "c:/", "$home", "~", "%userprofile%",
    "\\*", ":*", "d:\\", "e:\\", "a:\\", "/etc", "/var", "/root",
)

_URL_RE = re.compile(r"(?i)\b(?:https?|wss?|file)://[^\s\"']+")

# 判断一个参数字符串是否为「外部包引用」（相对于「本地路径引用」）
_PKG_RE = re.compile(r"^(?:@[a-z0-9\-_]+/)?[a-z0-9][a-z0-9\-_.]*(?:@[\w.\-+]+)?$")


def _is_local_ref(s: str) -> bool:
    s = s.strip().strip('"').strip("'")
    if not s:
        return True
    if s[0] in "./\\~":
        return True
    if len(s) > 2 and s[1] == ":" and s[2] in "\\/":   # Windows 盘符
        return True
    return False


def _has_package_ref(args: list) -> bool:
    """args 里是否存在「需要从注册表拉取」的包引用。

    若全部是本地路径（./vendor/x.js、C:\\tools\\y.exe），
    就不存在「版本未固定」的供应链问题，不应报MCP001。
    """
    for a in args:
        if not isinstance(a, str):
            continue
        t = a.strip()
        if t.startswith("-"):          # npx -y / uv 的开关
            continue
        if _is_local_ref(t):
            continue
        if _PKG_RE.match(t):
            return True
    return False


def _bare_root_value(values: list[str]) -> bool:
    """是否存在裸的文件系统根路径参数（值为 '/' 或 '//' 或盘符根）。"""
    for v in values:
        t = v.strip().strip('"').strip("'")
        if t in ("/", "//", "\\", "\\\\", "///"):
            return True
        if len(t) == 3 and t[1] == ":" and t[2] in "\\/" and t[0].isalpha():
            return True
    return False


def _iter_server_maps(node: Any, path: str = "$") -> Iterator[tuple[str, dict]]:
    """递归找出所有 MCP 服务器定义。"""
    if isinstance(node, dict):
        for key, val in node.items():
            if isinstance(key, str) and key.lower() in {k.lower() for k in SERVER_CONTAINER_KEYS}:
                if isinstance(val, dict):
                    for name, spec in val.items():
                        if isinstance(spec, dict):
                            yield f"{path}.{key}.{name}", {**spec, "_name": name}
            yield from _iter_server_maps(val, f"{path}.{key}")
    elif isinstance(node, list):
        for i, val in enumerate(node):
            yield from _iter_server_maps(val, f"{path}[{i}]")


def _flatten_strings(spec: dict) -> Iterator[tuple[str, str]]:
    for k, v in spec.items():
        if k.startswith("_"):
            continue
        if isinstance(v, str):
            yield k, v
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    yield k, item


def scan(art: Artifact) -> Iterator[Finding]:
    if art.data is None or art.kind not in ("json", "toml"):
        return
    found_any = False
    for loc, spec in _iter_server_maps(art.data):
        # TOML 里的 [mcp.servers.NAME] 会被识别成 servers 容器，这里保证确实是 server 形态
        if not any(k in spec for k in ("command", "url", "args", "type", "transport")):
            continue
        found_any = True
        yield from _scan_server(art, loc, spec)

    if not found_any:
        return


def _scan_server(art: Artifact, loc: str, spec: dict) -> Iterator[Finding]:
    name = spec.get("_name", "?")
    name_l = loc.split(".")[-1]
    line = art.line_of(f'"{name}"') or art.line_of(name_l) or art.line_of(spec.get("command", "###"))

    fields = list(_flatten_strings(spec))
    blob = " ".join(v for _, v in fields)

    # ---- MCP003：工具投毒 —— 配置字段里直接埋注入指令 ----
    hit = first_match(blob, INJECTION_PATTERNS)
    if hit:
        yield Finding(
            rule_id="MCP003",
            title="MCP 配置中存在提示词注入指令",
            severity=Severity.CRITICAL,
            surface=Surface.MCP,
            path=art.path,
            line=art.line_of(hit[2]) or line,
            evidence=redact(hit[2], 24),
            rationale=f"命中 {hit[1]}。MCP 服务器参数会被模型当作上下文读取，"
                      f"攻击者可在工具参数中植入指令劫持智能体行为。",
            remedy="从可信源重新获取该 MCP 服务器配置；接入前对 command/args/env 做签名校验；"
                   "在网关侧过滤工具参数中的指令性文本。",
            component=name,
            tags=("supply-chain", "tool-poisoning"),
        )

    # ---- MCP002：运行时自动拉包执行，无完整性校验 ----
    auto = AUTO_INSTALL_RE.search(blob)
    if auto:
        pinned = bool(PINNED_NPM_RE.search(blob) or PINNED_PYPI_RE.search(blob))
        has_integrity = any(k.lower() in INTEGRITY_KEYS for k in spec)
        sev = Severity.HIGH if not (pinned and has_integrity) else Severity.MEDIUM
        yield Finding(
            rule_id="MCP002",
            title="MCP 服务器通过运行时自动安装拉取代码",
            severity=sev,
            surface=Surface.MCP,
            path=art.path,
            line=art.line_of(auto.group(0)) or line,
            evidence=f"{auto.group(0)} (pinned={pinned}, integrity={has_integrity})",
            rationale="智能体启动时才会解析包版本，上游被投毒或版本劫持即等于本地代码执行。",
            remedy="改为预构建镜像或本地锁定依赖；记录包名+版本+sha256；"
                   "启用私有制品代理并做签名校验。",
            component=name,
            tags=("supply-chain", "code-exec"),
        )

    # ---- MCP001：外部包依赖未固定版本 ----
    # 本地脚本（./vendor/x.js）不存在"版本未固定"问题，只对包引用报。
    args = spec.get("args") if isinstance(spec.get("args"), list) else []
    pinned = bool(PINNED_NPM_RE.search(blob) or PINNED_PYPI_RE.search(blob))
    if "command" in spec and _has_package_ref(args) and not pinned:
        yield Finding(
            rule_id="MCP001",
            title="MCP 服务器依赖未固定版本",
            severity=Severity.HIGH,
            surface=Surface.MCP,
            path=art.path,
            line=line,
            evidence=(spec.get("command", "") + " " + " ".join(spec.get("args", []) if isinstance(spec.get("args"), list) else []))[:160],
            rationale="未固定版本意味着每次启动可能执行不同的上游代码，行为不可复现、责任不可追溯。",
            remedy="锁定到确切版本并记录 sha256/sha512；变更走人工评审。",
            component=name,
            tags=("supply-chain", "reproducibility"),
        )

    # ---- MCP004：明文凭据 ----
    env = spec.get("env") or spec.get("headers") or {}
    if isinstance(env, dict):
        for k, v in env.items():
            if isinstance(v, str) and len(v) >= 12 and not is_placeholder(v):
                if re.search(r"(?i)key|token|secret|password|credential", str(k)) or ASSIGNED_SECRET_RE.search(f'{k}="{v}"'):
                    yield Finding(
                        rule_id="MCP004",
                        title="MCP 配置中硬编码明文凭据",
                        severity=Severity.CRITICAL,
                        surface=Surface.MCP,
                        path=art.path,
                        line=art.line_of(str(k)) or line,
                        evidence=f"{k} = {redact(v)}",
                        rationale="凭据随配置进入仓库/镜像，任何有读权限的智能体或日志系统都可获取。",
                        remedy="改用密钥管理服务或环境变量注入；立即轮换已泄露凭据；清理版本历史。",
                        component=name,
                        tags=("secret",),
                    )

    # ---- MCP005：权限范围过宽 ----
    # 先把 URL 摘掉，避免 "https://..." 里的 "//" 被当成根路径
    values = [v for _, v in fields]
    scope_text = _URL_RE.sub(" ", blob)
    broad = [m for m in BROAD_SCOPE_MARKERS if m in scope_text]
    if _bare_root_value(values):
        broad.append("文件系统根")
    if broad:
        yield Finding(
            rule_id="MCP005",
            title="MCP 服务器声明了过宽的文件系统权限",
            severity=Severity.HIGH,
            surface=Surface.MCP,
            path=art.path,
            line=line,
            evidence="scope markers: " + ", ".join(sorted(set(broad))),
            rationale="文件系统根/家目录级权限意味着该工具可读取凭据、密钥与业务数据，超出最小必要原则。",
            remedy="收敛到具体工作目录；使用只读挂载；对写操作要求人工确认。",
            component=name,
            tags=("least-privilege",),
        )

    # ---- MCP006：远程 MCP 端点安全 ----
    url = spec.get("url") or spec.get("endpoint") or ""
    if isinstance(url, str) and url:
        if not url.startswith("https://"):
            yield Finding(
                rule_id="MCP006",
                title="远程 MCP 端点未使用 HTTPS",
                severity=Severity.HIGH,
                surface=Surface.MCP,
                path=art.path,
                line=art.line_of(url) or line,
                evidence=redact(url, 30),
                rationale="明文传输可被中间人替换工具响应，直接构成工具投毒路径。",
                remedy="强制 HTTPS；对服务器证书做固定或 CA 校验。",
                component=name,
                tags=("transport",),
            )

    # ---- MCP007：缺少完整性/来源证明 ----
    if not any(k.lower() in INTEGRITY_KEYS for k in spec):
        sev = Severity.MEDIUM
        yield Finding(
            rule_id="MCP007",
            title="MCP 服务器缺少完整性证明与来源记录",
            severity=sev,
            surface=Surface.MCP,
            path=art.path,
            line=line,
            evidence=f"缺少字段: {', '.join(INTEGRITY_KEYS[:4])} ...",
            rationale="无法回答'这个 MCP 服务器是哪一版、由谁提供、是否被篡改'，"
                      "该问题在监管问询与事故追溯中必然无法闭环。",
            remedy="在配置中补充 integrity/sha256/attestation/source_url 字段并纳入 AI BOM。",
            component=name,
            tags=("provenance", "evidence"),
        )


# --------------------------------------------------------------------------
# YAML / TOML 中非结构化的兜底扫描
# --------------------------------------------------------------------------
def scan_text(art: Artifact) -> Iterator[Finding]:
    """对 yaml / toml / text 等未解析成功的制品做粗粒度 MCP 关键字扫描。"""
    if not art.text:
        return
    if "mcpServers:" not in art.text and "mcp_servers" not in art.text:
        return
    for i, line in enumerate(art.text.splitlines(), 1):
        if AUTO_INSTALL_RE.search(line):
            yield Finding(
                rule_id="MCP002",
                title="MCP 配置中出现运行时自动安装命令",
                severity=Severity.HIGH,
                surface=Surface.MCP,
                path=art.path,
                line=i,
                evidence=line.strip()[:160],
                rationale="运行时拉取未固定版本的第三方代码执行路径。",
                remedy="锁定版本并记录完整性摘要。",
                tags=("supply-chain", "code-exec"),
            )
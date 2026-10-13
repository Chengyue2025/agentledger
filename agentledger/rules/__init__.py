"""规则注册表。

新增规则只需在这里登记 —— 上层的扫描、报告、账本会自动带上。
"""

from __future__ import annotations

from typing import Callable, Iterator

from ..model import Artifact, Coverage, Finding, Severity, Surface
from . import deps, manifests, mcp, models, prompts

# (名称, 对制品执行的扫描器)
ARTIFACT_RULES: list[tuple[str, Callable[[Artifact], Iterator[Finding]]]] = [
    ("mcp", mcp.scan),
    ("mcp_text", mcp.scan_text),
    ("models", models.scan),
    ("prompts", prompts.scan),
    ("deps", deps.scan),
    ("manifests", manifests.scan),
]

# 依赖清单类规则：只对少数文件执行，放在最后以便前面已处理过
DEPENDENCY_RULES: list[tuple[str, Callable[[Artifact], Iterator[Finding]]]] = [
    ("deps_pins", deps.scan_dependencies),
]

# 项目级规则：需要全量上下文
PROJECT_RULES: list[tuple[str, Callable[[Coverage], Iterator[Finding]]]] = [
    ("manifests_global", manifests.scan_root_absence),
]


RULE_CATALOG: dict[str, tuple[str, str]] = {
    "MCP001": ("MCP 服务器依赖未固定版本", "supply-chain"),
    "MCP002": ("MCP 服务器通过运行时自动安装拉取代码", "supply-chain"),
    "MCP003": ("MCP 配置中存在提示词注入指令", "tool-poisoning"),
    "MCP004": ("MCP 配置中硬编码明文凭据", "secret"),
    "MCP005": ("MCP 服务器声明了过宽的文件系统权限", "least-privilege"),
    "MCP006": ("远程 MCP 端点未使用 HTTPS", "transport"),
    "MCP007": ("MCP 服务器缺少完整性证明与来源记录", "provenance"),
    "MDL001": ("模型接入点备案状态需核验", "regulatory"),
    "MDL002": ("疑似硬编码的模型 API 密钥", "secret"),
    "MDL003": ("模型版本使用浮动别名", "reproducibility"),
    "MDL004": ("模型系统提示词中存在注入指令", "prompt-injection"),
    "PRM001": ("提示词/指令模板中存在注入指令", "prompt-injection"),
    "PRM002": ("隐藏注入：指令藏在注释中", "covert-channel"),
    "PRM003": ("提示词中存在零宽/双向控制字符", "covert-channel"),
    "PRM004": ("base64 载荷中藏有注入指令", "covert-channel"),
    "PRM005": ("拟人化类智能体未见必要披露声明", "regulatory"),
    "DEP001": ("检出硬编码凭据", "secret"),
    "DEP002": ("危险执行汇", "code-exec"),
    "DEP003": ("模型/工具输出未经净化进入危险汇", "injection"),
    "DEP004": ("依赖未固定版本", "supply-chain"),
    "AGT001": ("智能体清单缺少必备治理声明", "governance"),
    "AGT002": ("高风险动作缺少审批闸门", "financial-risk"),
    "AGT003": ("未声明执行隔离措施", "isolation"),
    "AGT004": ("项目缺少成文治理声明", "process"),
}


def run(coverage: Coverage, enabled: set[str] | None = None,
        disabled: set[str] | None = None) -> list[Finding]:
    """执行全部规则，返回去重后的发现项。"""
    enabled = enabled or set()
    disabled = disabled or set()
    out: list[Finding] = []

    for _, fn in ARTIFACT_RULES:
        for art in coverage.artifacts:
            if disabled.intersection(disabled_tags(art)):
                pass
            try:
                out.extend(fn(art))
            except Exception as exc:  # 单条规则出错不应中断整次扫描
                out.append(_rule_error(_name_of(fn), art, exc))

    for _, fn in DEPENDENCY_RULES:
        for art in coverage.artifacts:
            try:
                out.extend(fn(art))
            except Exception as exc:
                out.append(_rule_error(_name_of(fn), art, exc))

    for _, fn in PROJECT_RULES:
        try:
            out.extend(fn(coverage))
        except Exception as exc:
            out.append(Finding(
                rule_id="SYS001",
                title="规则执行异常",
                severity=Severity.INFO,
                surface=Surface.PROCESS,
                path="<project>",
                evidence=f"{_name_of(fn)}: {exc!r}",
                rationale="该规则本次未能完成，覆盖度因此不完整。",
                remedy="检查输入制品是否超出规则预期格式。",
                tags=("system",),
            ))

    out = _filter(out, enabled, disabled)
    out.sort(key=lambda f: f.sort_key())
    return out


def _filter(findings: list[Finding], enabled: set[str], disabled: set[str]) -> list[Finding]:
    if not enabled and not disabled:
        return _dedupe(findings)
    kept = []
    for f in findings:
        if enabled and f.rule_id not in enabled and not (set(f.tags) & enabled):
            continue
        if disabled and (f.rule_id in disabled or (set(f.tags) & disabled)):
            continue
        kept.append(f)
    return _dedupe(kept)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out = []
    for f in findings:
        key = (f.rule_id, f.path, f.line, f.component)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def disabled_tags(art: Artifact) -> set[str]:  # pragma: no cover - 占位，便于扩展
    return set()


def _rule_error(rule: str, art: Artifact, exc: Exception) -> Finding:
    return Finding(
        rule_id="SYS002",
        title=f"规则 {rule} 在制品上执行异常",
        severity=Severity.INFO,
        surface=Surface.PROCESS,
        path=art.path,
        evidence=f"{exc!r}",
        rationale="该制品未被完整检查，可能存在漏报。",
        remedy="记录该制品并人工复核。",
        tags=("system",),
    )


def _name_of(fn: Callable) -> str:
    return getattr(fn, "__module__", "?").rsplit(".", 1)[-1]
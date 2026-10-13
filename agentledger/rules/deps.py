"""代码执行路径与依赖规则。

关注点：智能体把**模型输出**直接接到执行汇（eval/shell/SQL/文件路径）时，
提示注入就会直接升级为远程代码执行。这是智能体最常见的失陷路径。
"""

from __future__ import annotations

import re
from typing import Iterator

from ..model import Artifact, Finding, Severity, Surface
from .common import (
    ASSIGNED_SECRET_RE,
    CODE_EXEC_PATTERNS,
    SECRET_PATTERNS,
    UNSANITIZED_SINK_RE,
    first_match,
    is_placeholder,
    redact,
    shannon_entropy,
)

# 看起来在处理模型/工具/智能体输出的变量名
MODEL_OUTPUT_VAR_RE = re.compile(
    r"""(?ix)
    \b (?:
        (?:llm|model|gpt|claude|agent|mcp|tool|ai)[_\-]?(?:output|response|result|reply|
           answer|completion|content|text|message|msg|generated) [A-Za-z0-9_]*
      | (?:output|response|result|reply|answer|completion|content) (?:_of)? [A-Za-z0-9_]*
    ) \b
    """
)

# 工具调用结果变量
TOOL_OUTPUT_RE = re.compile(
    r"(?ix)\b(?:tool|mcp|function|plugin)[_\-]?(?:output|result|response|return|data)\b"
)

DANGEROUS_FILE_EXTS = {".md", ".json", ".yaml", ".yml", ".toml", ".txt"}


def scan(art: Artifact) -> Iterator[Finding]:
    if not art.text:
        return
    if art.kind in ("markdown",):
        return  # 提示词文件由 prompts.py 负责
    yield from _secrets(art)
    yield from _exec_sinks(art)
    yield from _unsanitized(art)


# --------------------------------------------------------------------------
def _secrets(art: Artifact) -> Iterator[Finding]:
    # 1) 已知厂商格式的密钥 —— 高置信度
    for pattern, desc in SECRET_PATTERNS:
        m = re.search(pattern, art.text)
        if m:
            yield Finding(
                rule_id="DEP001",
                title=f"检出{desc}",
                severity=Severity.CRITICAL,
                surface=Surface.DEPS,
                path=art.path,
                line=art.text.count("\n", 0, m.start()) + 1,
                evidence=redact(m.group(0)),
                rationale="有效格式的凭据硬编码在代码/配置中，等同于凭据泄露。",
                remedy="立即吊销轮换；迁移至密钥管理服务或环境变量注入；清理版本历史。",
                tags=("secret",),
            )
            return  # 同一文件多处同类不再刷屏

    # 2) 赋值型密钥 —— 需熵值过滤以降低误报
    for m in ASSIGNED_SECRET_RE.finditer(art.text):
        val = m.group("val")
        if len(val) < 16 or is_placeholder(val):
            continue
        if shannon_entropy(val) < 3.2:
            continue
        yield Finding(
            rule_id="DEP001",
            title="检出疑似硬编码凭据",
            severity=Severity.HIGH,
            surface=Surface.DEPS,
            path=art.path,
            line=art.text.count("\n", 0, m.start()) + 1,
            evidence=f"{m.group('name')} = {redact(val)}",
            rationale="硬编码凭据随代码分发，智能体、日志、镜像层均可读取。",
            remedy="迁移至环境变量/密钥管理服务并轮换现有凭据。",
            tags=("secret",),
        )
        return


# --------------------------------------------------------------------------
def _exec_sinks(art: Artifact) -> Iterator[Finding]:
    """危险执行汇。只有当附近存在模型/工具输出变量时才升级为高危。"""
    for pattern, name in CODE_EXEC_PATTERNS:
        for m in re.finditer(pattern, art.text):
            window = art.text[max(0, m.start() - 600):m.end() + 600]
            near_output = bool(MODEL_OUTPUT_VAR_RE.search(window) or TOOL_OUTPUT_RE.search(window))
            sev = Severity.HIGH if near_output else Severity.MEDIUM
            if not near_output and name in ("eval(", "exec(", "pickle.loads()", "new Function()", "__import__()"):
                sev = Severity.MEDIUM
            yield Finding(
                rule_id="DEP002",
                title=f"危险执行汇 {name}"
                      + ("（上下文中存在模型/工具输出）" if near_output else ""),
                severity=sev,
                surface=Surface.DEPS,
                path=art.path,
                line=art.text.count("\n", 0, m.start()) + 1,
                evidence=art.text[m.start():m.end()].strip()[:120],
                rationale=(
                    "模型输出即攻击者可控输入。提示注入一旦命中该路径即升级为远程代码执行。"
                    if near_output
                    else "该汇本身危险；一旦上游数据来自模型或外部内容，风险立即成立。"
                ),
                remedy="禁止对模型/工具输出使用该汇；改用结构化解析 + 严格白名单校验"
                       "（如 ast.literal_eval、受限 subprocess 数组形式）。",
                tags=("code-exec", "prompt-injection") if near_output else ("code-exec",),
            )
            break  # 每种汇在单文件只报一次


# --------------------------------------------------------------------------
def _unsanitized(art: Artifact) -> Iterator[Finding]:
    """模板拼接直接进入 SQL / shell / 文件路径。"""
    if art.kind not in ("code", "text", "json", "yaml", "toml"):
        return
    for m in UNSANITIZED_SINK_RE.finditer(art.text):
        window = art.text[max(0, m.start() - 500):m.end() + 500]
        if not (MODEL_OUTPUT_VAR_RE.search(window) or TOOL_OUTPUT_RE.search(window)):
            continue
        yield Finding(
            rule_id="DEP003",
            title="模型/工具输出未经净化直接进入危险汇",
            severity=Severity.HIGH,
            surface=Surface.DEPS,
            path=art.path,
            line=art.text.count("\n", 0, m.start()) + 1,
            evidence=m.group(0).strip()[:140],
            rationale="SQL 注入 / 命令注入 / 任意文件写入均由此产生；"
                      "模型输出的不可预测性使传统转义假设失效。",
            remedy="使用参数化查询；shell 调用改为数组形式且不经 shell；"
                   "文件路径必须 resolve 后校验是否在允许根目录内。",
            tags=("injection", "code-exec"),
        )
        break


# --------------------------------------------------------------------------
def scan_dependencies(art: Artifact) -> Iterator[Finding]:
    """依赖未固定版本 —— 只对依赖清单文件生效。"""
    if art.kind not in ("json", "toml", "text"):
        return
    name = art.path.rsplit("/", 1)[-1].lower()

    # package.json
    if art.kind == "json" and isinstance(art.data, dict) and "dependencies" in art.data:
        deps = art.data.get("dependencies") or {}
        if isinstance(deps, dict):
            unpinned = {k: v for k, v in deps.items()
                        if isinstance(v, str) and not re.match(r"^\d+\.\d+\.\d+", v)}
            if unpinned:
                yield Finding(
                    rule_id="DEP004",
                    title="npm 依赖使用范围/浮动版本",
                    severity=Severity.MEDIUM,
                    surface=Surface.DEPS,
                    path=art.path,
                    evidence=", ".join(f"{k}@{v}" for k, v in list(unpinned.items())[:8])
                             + (f" (+{len(unpinned) - 8} more)" if len(unpinned) > 8 else ""),
                    rationale="浮动版本会在不同时间安装到不同代码，"
                              "智能体供应链来源不可追溯，无法回答某次行为由哪个版本造成。",
                    remedy="提交 lockfile 并在 CI 执行 npm ci；关键依赖锁定精确版本并记录 sha512。",
                    tags=("supply-chain", "reproducibility"),
                )

    # requirements.txt
    elif name in ("requirements.txt",) and art.text:
        bad = []
        for i, line in enumerate(art.text.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith(("#", "-")):
                continue
            if "==" not in s and not re.search(r"@\s*[\w.]+\s*==", s):
                bad.append((i, s))
        if bad:
            yield Finding(
                rule_id="DEP004",
                title="Python 依赖未固定版本",
                severity=Severity.MEDIUM,
                surface=Surface.DEPS,
                path=art.path,
                line=bad[0][0],
                evidence="; ".join(f"{s[:60]}" for _, s in bad[:6])
                         + (f" (+{len(bad) - 6} more)" if len(bad) > 6 else ""),
                rationale="未固定版本的依赖不可复现，供应链投毒难以定位与举证。",
                remedy="使用 == 固定版本或 uv.lock/pip-tools 生成带哈希的锁定文件。",
                tags=("supply-chain", "reproducibility"),
            )
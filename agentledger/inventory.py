"""制品发现：把一个代码目录切成"AI 攻击面"清单。

这是整个工具的证据基础。审计意义上最重要的一点：
**不仅要记录"看了什么"，更要记录"没看什么"**（Coverage.exclusions），
否则证据包在监管面前是不完整的。
"""

from __future__ import annotations

import json
import os
import tomllib
from datetime import datetime, timezone
from pathlib import Path

from .model import Artifact, Coverage

# --- 明确排除的目录：与 AI 供应链无关，且噪音极大 -------------------------
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build",
    "target", "vendor", ".next", ".nuxt", ".cache", ".idea", ".vscode-test",
    "site-packages", ".eggs", "htmlcov", ".gradle", "Pods", ".terraform",
    # 本工具自己的输出目录：证据包里含有问题原文片段（脱敏后仍是注入特征），
    # 若回灌进扫描会造成"自我污染"—— 每扫一次发现项就多几项，且不可复现。
    ".agentledger",
}

# --- 只读文本类后缀 --------------------------------------------------------
TEXT_EXT = {
    ".json", ".jsonc", ".toml", ".yaml", ".yml", ".md", ".mdc", ".txt",
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rs",
    ".rb", ".php", ".java", ".kt", ".cs", ".sh", ".bash", ".ps1", ".ini",
    ".cfg", ".conf", ".env", ".properties", ".gradle", ".sql", ".html",
    ".prompt", ".mcp", ".yaml.template",
}

# --- 高价值文件名（无条件纳入，作为 AI 攻击面候选） -------------------------
AI_FILENAMES = {
    # MCP 配置
    "mcp.json", ".mcp.json", "mcp_servers.json", "mcp-settings.json",
    "claude_desktop_config.json", "cline_mcp_settings.json",
    # 智能体清单
    "agent.json", "agents.json", "agent.yaml", "agents.yaml",
    "agent.toml", "agent.md", "openclaw.json", "swarm.yaml",
    "mcp-agents.json", "subagents.json",
    # harness 插件清单（dsh/Cordis、grok-build 扩展、IM bot 桥）
    "plugin.json", "plugin.yaml", "plugin.toml", "cordis.json",
    "dsh.json", "harness.json", "dsh.yaml",
    # 分享包 / marketplace bot / routine（Grok share 等）
    "share.json", "bot.json", "bot.yaml", "marketplace.json",
    "routine.json", "routines.json", "skills.json",
    # 指令 / 提示词
    "agents.md", "claude.md", "gemini.md", "copilot-instructions.md",
    ".cursorrules", ".windsurfrules",
    # 依赖清单
    "package.json", "requirements.txt", "pyproject.toml", "cargo.toml",
    "go.mod", "gemfile", "pom.xml", "build.gradle",
    # 模型/供应商配置
    "litellm_config.yaml", "openai.yaml", "models.yaml", "llm_config.json",
}

# --- AI 语义目录名（目录下内容整体视为 AI 攻击面） --------------------------
AI_DIR_HINTS = {
    "skills", "prompts", "agents", "agent", "mcp", "mcp_servers", "mcps",
    "instructions", "rules", ".cursor", ".claude", ".github",
    "chains", "workflows", "pipelines", "tools", "skills.d",
    # harness 插件与分享包生态（2026-10 新增）
    "plugins", "plugins.d", "plugin.d", "shares", "bots", "routines",
    "marketplace", "harness", ".dsh",
}

MAX_FILE_BYTES = 2_000_000   # 超大文件跳过并记录（避免把数据仓库当代码扫）
MAX_YAML_BYTES = 512_000


def _looks_binary(path: Path) -> bool:
    """判断是否二进制。

    注意：不能用「可打印 ASCII 占比」当唯一判据 —— 中文等 UTF-8 多字节文本
    会被误判成二进制，导致中文提示词文件被整个跳过（漏报）。
    正确顺序：NUL 字节 → UTF-8 可解码 → 退回比例判据。
    """
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(4096)
    except OSError:
        return True
    if not chunk:
        return False
    # NUL 字节是二进制最可靠的标志
    if b"\x00" in chunk:
        return True
    # UTF-16/UTF-32 BOM
    if chunk[:4] in (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"):
        return True
    if chunk[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return True
    # 截断的多字节序列不算失败（文件可能大于 4096 字节）
    try:
        chunk.decode("utf-8")
        return False
    except UnicodeDecodeError:
        pass
    except Exception:
        return True
    # 确实是 UTF-8 之外的数据 —— 用可打印比例兜底
    printable = sum(1 for b in chunk if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(chunk) < 0.70


def _read_text(path: Path) -> str | None:
    for enc in ("utf-8", "utf-8-sig", "gb18030", "latin-1"):
        try:
            with open(path, "r", encoding=enc) as fh:
                return fh.read()
        except (UnicodeDecodeError, LookupError):
            continue
        except OSError:
            return None
    return None


def _classify(path: Path, root: Path) -> str:
    name = path.name.lower()
    ext = path.suffix.lower()
    if name in AI_FILENAMES:
        if ext in (".json", ".jsonc"):
            return "json"
        if ext == ".toml":
            return "toml"
        if ext in (".yaml", ".yml"):
            return "yaml"
        if ext in (".md", ".mdc"):
            return "markdown"
        return "text"
    if ext in (".json", ".jsonc"):
        return "json"
    if ext == ".toml":
        return "toml"
    if ext in (".yaml", ".yml"):
        return "yaml"
    if ext in (".md", ".mdc"):
        return "markdown"
    if ext in (".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go",
               ".rs", ".rb", ".php", ".java", ".kt", ".cs", ".sh", ".bash",
               ".ps1", ".sql"):
        return "code"
    return "text"


def _is_ai_path(path: Path, root: Path) -> bool:
    """路径是否落在 AI 语义范围内。"""
    rel_parts = [p.lower() for p in path.relative_to(root).parts]
    name = path.name.lower()
    if name in AI_FILENAMES:
        return True
    for part in rel_parts[:-1]:
        if part in AI_DIR_HINTS:
            return True
    # 指令类文件扩展
    if path.suffix.lower() in (".mdc", ".prompt", ".mcp"):
        return True
    if path.suffix.lower() == ".md" and name.startswith(("agents.", "claude.", "gemini.")):
        return True
    return False


def discover(root: str | Path, max_files: int = 20000) -> Coverage:
    """遍历目录，产出制品清单 + 覆盖度记录。"""
    root = Path(root).resolve()
    cov = Coverage(root=str(root),
                   started_at=datetime.now(timezone.utc).isoformat())

    if root.is_file():
        candidates = [root]
        base = root.parent
    else:
        base = root
        candidates = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".egg")]
            for fn in filenames:
                candidates.append(Path(dirpath) / fn)

    for path in candidates:
        if len(cov.artifacts) >= max_files:
            cov.exclude(str(path), "file cap reached")
            break
        try:
            rel = path.relative_to(base)
        except ValueError:
            rel = Path(path.name)
        rel_posix = rel.as_posix()

        try:
            size = path.stat().st_size
        except OSError:
            continue

        if size > MAX_FILE_BYTES:
            cov.exclude(rel_posix, f"too large ({size} bytes)", size)
            continue
        if _looks_binary(path):
            cov.exclude(rel_posix, "binary content", size)
            continue

        ext = path.suffix.lower()
        name = path.name.lower()
        # 非文本后缀且不在白名单里 —— 跳过但记账
        if ext and ext not in TEXT_EXT and name not in AI_FILENAMES:
            cov.exclude(rel_posix, f"non-text extension '{ext}'", size)
            continue

        text = _read_text(path)
        if text is None:
            cov.exclude(rel_posix, "unreadable", size)
            continue
        if ext in (".yaml", ".yml") and len(text) > MAX_YAML_BYTES:
            cov.exclude(rel_posix, "yaml too large", size)
            continue

        kind = _classify(path, base)
        data = None
        if kind == "json":
            raw = re_strip_jsonc(text)
            try:
                data = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                data = None
        elif kind == "toml":
            try:
                data = tomllib.loads(text)
            except Exception:
                data = None

        art = Artifact(path=rel_posix, kind=kind, text=text, data=data, size=size)
        cov.artifacts.append(art)
        cov.scanned_files += 1
        cov.scanned_bytes += size
        if _is_ai_path(path, base):
            cov.ai_surface_files += 1
            cov.components[kind] = cov.components.get(kind, 0) + 1

    cov.finished_at = datetime.now(timezone.utc).isoformat()
    return cov


def re_strip_jsonc(text: str) -> str:
    """去掉 JSONC 的注释与尾逗号（mcp.json 常见写法）。"""
    out = []
    i, n = 0, len(text)
    in_str = False
    esc = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(c)
        i += 1
    cleaned = "".join(out)
    # 去尾逗号
    result = []
    in_str = False
    esc = False
    for idx, c in enumerate(cleaned):
        if in_str:
            result.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
            result.append(c)
            continue
        if c == ",":
            rest = cleaned[idx + 1:].lstrip()
            if rest[:1] in ("}", "]"):
                continue
        result.append(c)
    return "".join(result)
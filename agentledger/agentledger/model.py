"""核心数据模型：严重度、发现项、制品、覆盖率、扫描记录。"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterator


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[self.value]

    @property
    def zh(self) -> str:
        return {
            "CRITICAL": "严重",
            "HIGH": "高危",
            "MEDIUM": "中危",
            "LOW": "低危",
            "INFO": "提示",
        }[self.value]


class Surface(str, Enum):
    """AI 攻击面分类 —— 对应 AIBOM 的组件层。"""

    MCP = "mcp"          # MCP 服务器 / 工具
    MODEL = "model"      # 模型接入点
    PROMPT = "prompt"    # 提示词 / 技能 / 指令模板
    AGENT = "agent"      # 智能体清单与治理声明
    DEPS = "deps"        # 依赖与执行路径
    PROCESS = "process"  # 流程性缺口（无法定位到行）


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


@dataclass(frozen=True)
class Finding:
    """一条可辩护的发现项。

    audit-grade 要求：每条发现都必须能回答"谁、在哪一行、看到什么、为什么是问题、怎么修"。
    """

    rule_id: str
    title: str
    severity: Severity
    surface: Surface
    path: str
    line: int | None = None
    evidence: str = ""
    rationale: str = ""
    remedy: str = ""
    component: str = ""      # 命中的具体组件名（MCP server 名 / 模型 id 等）
    tags: tuple[str, ...] = ()

    def sort_key(self) -> tuple:
        return (self.severity.rank, self.path, self.line or 0, self.rule_id)

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["severity"] = self.severity.value
        d["surface"] = self.surface.value
        d["tags"] = list(self.tags)
        return d

    def location(self) -> str:
        return f"{self.path}:{self.line}" if self.line else self.path


@dataclass
class Artifact:
    """被扫描到的一个制品。"""

    path: str                      # 相对路径（posix 风格）
    kind: str                      # json | jsonc | toml | yaml | markdown | text | other
    text: str | None = None
    data: Any = None               # 解析后的结构（仅 json/toml）
    size: int = 0

    # --- 文本定位辅助 ---------------------------------------------------
    def line_of(self, needle: str, occurrence: int = 0) -> int | None:
        """在原文中定位 needle 的第 occurrence 次出现所在的行号。"""
        if not self.text or not needle:
            return None
        idx = -1
        for _ in range(occurrence + 1):
            idx = self.text.find(needle, idx + 1)
            if idx < 0:
                return None
        return self.text.count("\n", 0, idx) + 1

    def line_of_regex(self, pattern: str, group: int = 0) -> int | None:
        import re
        if not self.text:
            return None
        m = re.search(pattern, self.text)
        if not m:
            return None
        start = m.start(group) if m.start(group) >= 0 else m.start()
        return self.text.count("\n", 0, start) + 1


@dataclass
class Exclusion:
    """被跳过的东西 —— 审计时必须披露，否则证据包不完整。"""

    path: str
    reason: str
    size: int = 0


@dataclass
class Coverage:
    """扫描覆盖度。'我没看什么' 和 '我看了什么' 一样重要。"""

    root: str
    started_at: str
    finished_at: str = ""
    scanned_files: int = 0
    scanned_bytes: int = 0
    artifacts: list[Artifact] = field(default_factory=list)
    exclusions: list[Exclusion] = field(default_factory=list)
    ai_surface_files: int = 0
    components: dict[str, int] = field(default_factory=dict)

    def exclude(self, path: str, reason: str, size: int = 0) -> None:
        self.exclusions.append(Exclusion(path=path, reason=reason, size=size))

    def summary(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "scanned_files": self.scanned_files,
            "scanned_bytes": self.scanned_bytes,
            "ai_surface_files": self.ai_surface_files,
            "component_counts": dict(sorted(self.components.items())),
            "excluded_count": len(self.exclusions),
            "excluded_bytes": sum(e.size for e in self.exclusions),
        }

    def iter(self, kind: str | None = None) -> Iterator[Artifact]:
        for a in self.artifacts:
            if kind is None or a.kind == kind:
                yield a


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    coverage: Coverage | None = None

    def by_severity(self, sev: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity is sev]

    def counts(self) -> dict[str, int]:
        c = {s.value: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            c[f.severity.value] += 1
        return c

    def exit_code(self, fail_on: Severity = Severity.HIGH) -> int:
        for s in SEVERITY_ORDER:
            if s.rank > fail_on.rank:
                break
            if self.by_severity(s):
                return 1
        return 0
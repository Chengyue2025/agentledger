"""模型接入点规则。

对境内业务最关键的一条：调用大模型 API 的应用是否需要履行
**大模型备案 / 应用登记**（《生成式人工智能服务管理暂行办法》
+网信办「清朗·整治AI应用乱象」专项行动 2026-04 起将"应备未备、应登未登"
列为第一阶段重点整治对象）。
"""

from __future__ import annotations

import re
from typing import Iterator

from ..model import Artifact, Finding, Severity, Surface
from .common import (
    ASSIGNED_SECRET_RE,
    FILED_MODEL_HOST_HINTS,
    FLOATING_MODEL_ALIASES,
    INJECTION_PATTERNS,
    KNOWN_MODEL_HOSTS,
    MODEL_ENDPOINT_KEYS,
    MODEL_ID_RE,
    first_match,
    is_placeholder,
    redact,
    shannon_entropy,
)

SECRET_LIKE_KEY_RE = re.compile(
    r"(?i)(api[_\-]?key|apikey|token|secret|access[_\-]?key|credential|authorization)"
)

URL_RE = re.compile(r"https?://[A-Za-z0-9._\-]+(?::\d+)?")


def _host_of(url: str) -> str:
    m = re.match(r"https?://([^/:]+)", url.strip(), re.I)
    return m.group(1).lower() if m else ""


def _looks_filed(host: str) -> bool:
    return any(h in host for h in FILED_MODEL_HOST_HINTS)


def _provider_of(host: str) -> str:
    for h, name in KNOWN_MODEL_HOSTS.items():
        if h in host:
            return name
    return ""


def scan(art: Artifact) -> Iterator[Finding]:
    if not art.text:
        return

    # ---------------- 1. 明文密钥 ----------------
    for m in SECRET_LIKE_KEY_RE.finditer(art.text):
        seg_start = max(0, m.start() - 20)
        window = art.text[seg_start:m.end() + 120]
        a = ASSIGNED_SECRET_RE.search(window)
        if a:
            val = a.group("val")
            if len(val) >= 16 and not is_placeholder(val) and shannon_entropy(val) > 3.0:
                yield Finding(
                    rule_id="MDL002",
                    title="疑似硬编码的模型 API 密钥",
                    severity=Severity.CRITICAL,
                    surface=Surface.MODEL,
                    path=art.path,
                    line=art.text.count("\n", 0, m.start()) + 1,
                    evidence=f"{a.group('name')} = {redact(val)}",
                    rationale="模型 API 密钥一旦入库即视为泄露，可被用于计费盗用与数据外传。",
                    remedy="立即吊销并轮换；改用密钥管理服务注入；清理 Git 历史。",
                    tags=("secret",),
                )

    # ---------------- 2. 模型端点主机 ----------------
    for m in URL_RE.finditer(art.text):
        url = m.group(0)
        host = _host_of(url)
        if not host:
            continue
        # 只有明显是模型服务的才查备案问题
        provider = _provider_of(host)
        model_here = MODEL_ID_RE.search(art.text[max(0, m.start() - 400):m.end() + 400])
        if not provider and not model_here:
            continue

        line = art.text.count("\n", 0, m.start()) + 1
        if provider and not _looks_filed(host):
            yield Finding(
                rule_id="MDL001",
                title=f"接入境外/未备案模型服务（{provider}）",
                severity=Severity.HIGH,
                surface=Surface.MODEL,
                path=art.path,
                line=line,
                evidence=f"endpoint = {host}",
                rationale="面向境内公众提供服务时，调用未完成备案的境外模型 API 会触发"
                          "大模型调用登记/出境数据评估义务；清朗专项行动已将"
                          "「应备未备、应登未登」列为重点整治对象。",
                remedy="核验该端点是否具备境内备案；如无，改为接入已备案模型或完成登记；"
                       "涉及个人信息与重要数据的，另行评估数据出境合规。",
                component=provider,
                tags=("filing", "regulatory", "cn"),
            )
        elif not provider and model_here and not _looks_filed(host):
            yield Finding(
                rule_id="MDL001",
                title="模型端点所属厂商备案状态需核验",
                severity=Severity.MEDIUM,
                surface=Surface.MODEL,
                path=art.path,
                line=line,
                evidence=f"endpoint = {host}",
                rationale="该地址未出现在已知已备案厂商清单中，无法自动确认备案状态；"
                          "AI 接入方需承担核验责任。",
                remedy="在国家网信办已备案信息公告中核对该模型厂商状态，并留档。",
                component=host,
                tags=("filing", "regulatory", "cn"),
            )

    # ---------------- 3. 浮动模型别名 ----------------
    for m in re.finditer(
        r"""(?ix) ["']? \b (?:model|model[_\-]?name|model[_\-]?id|engine) ["']? \s* [:=] \s* ["'] ([\w.\-/:]+) ["']""",
        art.text,
    ):
        val = m.group(1)
        tail = val.split("/")[-1].split(":")[-1].lower()
        if tail in FLOATING_MODEL_ALIASES or any(
            tail.endswith(suffix) for suffix in ("-latest", "-preview", "-auto", "-default")
        ):
            yield Finding(
                rule_id="MDL003",
                title="模型版本使用浮动别名，行为不可复现",
                severity=Severity.MEDIUM,
                surface=Surface.MODEL,
                path=art.path,
                line=art.text.count("\n", 0, m.start()) + 1,
                evidence=f'model = "{val}"',
                rationale="`latest`/`preview` 类别名会随上游静默变更，导致同一请求在不同时间"
                          "产生不同结果，事故复盘与监管问询都无法定位到具体权重版本。",
                remedy="固定到完整版本号或权重哈希；把版本写入 AI BOM 并随运行日志留痕。",
                tags=("reproducibility", "provenance"),
            )

    # ---------------- 4. 提示注入（模型系统提示词） ----------------
    hit = first_match(art.text, INJECTION_PATTERNS)
    if hit:
        yield Finding(
            rule_id="MDL004",
            title="模型系统提示词/模板中存在注入指令",
            severity=Severity.HIGH,
            surface=Surface.MODEL,
            path=art.path,
            line=art.text.count("\n", 0, art.text.find(hit[2])) + 1 if hit[2] in art.text else None,
            evidence=redact(hit[2], 32),
            rationale=f"命中 {hit[1]}。",
            remedy="清理该指令并复核该提示词的来源与审批记录。",
            tags=("prompt-injection",),
        )
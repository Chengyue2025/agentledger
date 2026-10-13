"""规则共用的模式与工具函数。

设计原则：宁可漏报也不要乱报。
每条规则都必须能指向**具体文件 + 具体行**，否则在监管场景里没有价值。
"""

from __future__ import annotations

import math
import re
from collections import Counter

# --------------------------------------------------------------------------
# 1. 密钥 / 凭据
# --------------------------------------------------------------------------
SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI/Anthropic 风格 API Key"),
    (r"sk-ant-[A-Za-z0-9_\-]{24,}", "Anthropic API Key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token"),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token"),
    (r"github_pat_[A-Za-z0-9_]{50,}", "GitHub Fine-grained PAT"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"AIza[0-9A-Za-z_\-]{35}", "Google API Key"),
    (r"xoxb-[0-9A-Za-z\-]{10,}", "Slack Bot Token"),
    (r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "JWT"),
    (r"DAS[0-9A-Za-z]{20,}", "阿里云 AccessKey"),
    (r"LTAI[A-Za-z0-9]{16,}", "阿里云 AccessKey ID"),
]

# 赋值型密钥（带变量名的，注意排除占位符）
ASSIGNED_SECRET_RE = re.compile(
    r"""(?ix)
    \b(?P<name>[A-Za-z0-9_\-]*(?:api[_\-]?key|secret|token|password|passwd|credential|access[_\-]?key|private[_\-]?key)[A-Za-z0-9_\-]*)
    \s*[:=]\s*
    (?P<quote>['"])
    (?P<val>[^'"\n]{12,})
    (?P=quote)
    """
)

# 占位符 —— 命中这些就不算真实凭据
PLACEHOLDER_MARKERS = (
    "your", "xxx", "todo", "changeme", "example", "placeholder", "dummy",
    "redacted", "<", ">", "${", "{{", "none", "null", "test", "fake",
    "sample", "demo", "abcdef", "123456", "insert", "replace",
)

# --------------------------------------------------------------------------
# 2. 提示词注入 / 工具投毒
# --------------------------------------------------------------------------
INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+"
     r"(?:instruction|prompt|direction|rule|message)",
     "覆盖式指令：ignore previous instructions"),
    (r"(?i)disregard\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier|system)",
     "覆盖式指令：disregard the above"),
    (r"(?i)forget\s+(?:everything|all\s+previous|your\s+instructions)",
     "覆盖式指令：forget everything"),
    (r"(?i)do\s+not\s+(?:tell|inform|mention|reveal|disclose|show)\s+(?:this\s+)?"
     r"(?:to\s+)?(?:the\s+)?(?:user|human|operator|anyone)",
     "隐瞒指令：do not tell the user"),
    (r"(?i)without\s+(?:asking|informing|telling|notifying)\s+(?:the\s+)?(?:user|human|operator)",
     "绕过确认：without asking the user"),
    (r"(?i)(?:silently|quietly|covertly|secretly)\s+(?:send|upload|exfiltrate|forward|post|execute)",
     "隐蔽外传动作"),
    (r"(?i)you\s+must\s+always\s+(?:call|invoke|use|execute|run)\s+",
     "强制工具调用：you must always call"),
    (r"(?i)(?:before|prior\s+to)\s+(?:any\s+)?(?:other\s+)?(?:tool|action|step|response)"
     r"[^.\n]{0,40}(?:always\s+)?(?:invoke|call|use|first)\b",
     "工具优先级劫持"),
    (r"(?i)<\s*IMPORTANT\s*>", "伪装标记 <IMPORTANT>"),
    (r"(?i)\[\s*(?:SYSTEM|ADMIN|ROOT|OVERRIDE)\s*(?:PROMPT|MODE)?\s*\]",
     "伪装角色标记 [SYSTEM]/[ADMIN]"),
    (r"(?i)new\s+system\s+(?:prompt|instruction|role)\s*[:：]",
     "系统提示词重定义"),
    (r"(?i)developer\s+mode\s+(?:enabled|on|:)",
     "越权模式声明 developer mode"),
    (r"(?i)exfiltrat|数据回传|外传|窃取",
     "数据外传语义"),
    # 中文注入
    (r"(?:不要|无需|禁止)(?:告知|告诉|通知|向)(?:用户|人类|操作者)",
     "中文隐瞒指令"),
    (r"(?:忽略|无视)(?:之前|上述|以上|前面)(?:的)?(?:所有)?(?:指令|提示|规则)",
     "中文覆盖式指令"),
    (r"(?:绕过|跳过)(?:用户)?(?:确认|审批|授权|人工审核)",
     "中文绕过确认"),
]

# 零宽 / 双向控制字符（可用于隐藏指令）
ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u061c]")
BIDI_RE = re.compile(r"[\u202a-\u202e\u2066-\u2069]")

# 隐藏指令容器
HIDDEN_CONTAINER_RE = re.compile(
    r"(?s)<!--.{0,4000}?-->"          # HTML 注释
    r"|/\*.*?\*/"                    # 块注释
    r"|<script[^>]*>.*?</script>"     # script 块
)

# --------------------------------------------------------------------------
# 3. 模型接入点
# --------------------------------------------------------------------------
# 已知完成大模型备案的境内厂商域名片段（白名单，降低误报）
FILED_MODEL_HOST_HINTS = (
    "dashscope.aliyuncs.com", "aliyuncs.com", "volces.com", "volcengine.com",
    "api.deepseek.com", "deepseek.com", "moonshot.cn", "moonshot.ai",
    "open.bigmodel.cn", "bigmodel.cn", "baidubce.com", "baidu.com",
    "tencentcloudapi.com", "hunyuan.tencentcloudapi.com", "xunfei.cn",
    "minimax.cn", "minimaxi.com", "siliconflow.cn", "modelscope.cn",
    "baai.ac.cn", "infinigence.cn", "stepfun.com", "xingzhi.cn", "tencent.com",
)

# 常见的境外/未备案接入点
KNOWN_MODEL_HOSTS = {
    "api.openai.com": "OpenAI",
    "api.anthropic.com": "Anthropic",
    "generativelanguage.googleapis.com": "Google Gemini",
    "api.cohere.com": "Cohere",
    "api.mistral.ai": "Mistral",
    "api.groq.com": "Groq",
    "openrouter.ai": "OpenRouter",
    "api.deepinfra.com": "DeepInfra",
    "api.together.xyz": "Together AI",
    "huggingface.co": "HuggingFace",
    "api.fireworks.ai": "Fireworks",
}

MODEL_ENDPOINT_KEYS = (
    "base_url", "baseurl", "base_uri", "api_base", "apibase", "endpoint",
    "openai_base_url", "openai_api_base", "llm_base_url", "model_endpoint",
)

MODEL_ID_RE = re.compile(
    r"(?i)\b(?:gpt-[0-9][\w.\-]*|o[134](?:-mini|\-preview)?|claude-[\w.\-]+|"
    r"gemini-[\w.\-]+|llama-?[\w.\-]*|qwen[\w.\-]*|glm-[\w.\-]*|deepseek-[\w.\-]*|"
    r"ernie-[\w.\-]*|moonshot-[\w.\-]*|abab[\w.\-]*|hunyuan-[\w.\-]*|"
    r"mistral-[\w.\-]*|yi-[\w.\-]*|minimax-[\w.\-]*|spark-[\w.\-]+)\b"
)

# 浮动别名 —— 无法复现，责任不可追溯
FLOATING_MODEL_ALIASES = {
    "latest", "default", "auto", "current", "stable", "prod", "production",
}

# --------------------------------------------------------------------------
# 4. 执行路径风险（模型输出 -> 代码执行）
# --------------------------------------------------------------------------
CODE_EXEC_PATTERNS: list[tuple[str, str]] = [
    (r"\beval\s*\(", "eval()"),
    (r"\bexec\s*\(", "exec()"),
    (r"\bnew\s+Function\s*\(", "new Function()"),
    (r"\bpickle\.loads?\s*\(", "pickle.loads()"),
    (r"\byaml\.load\s*\((?![^)]*Safe)", "yaml.load() 非 Safe 模式"),
    (r"\bmarshal\.loads\s*\(", "marshal.loads()"),
    (r"__import__\s*\(", "__import__()"),
    (r"subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True", "subprocess shell=True"),
    (r"os\.system\s*\(", "os.system()"),
    (r"child_process\.exec\s*\(", "child_process.exec()"),
    (r"shell_exec\s*\(", "shell_exec()"),
]

# 明显是把模型输出接到危险汇的写法
UNSANITIZED_SINK_RE = re.compile(
    r"""(?ix)
    (?:
        (?:execute|executescript|query|executemany|cursor\.execute)
            \s*\(\s* f? ['"] [^)\n]{0,300}? \{[^{}\n]{1,200}\}
      | (?:os\.system|subprocess\.(?:run|call|Popen|check_output)|exec|eval)
            \s*\(\s*[a-z_]
      | open\s*\(\s* f? ['"] [^)\n]{0,300}? \{[^{}\n]{1,200}\}
    )
    """
)

# --------------------------------------------------------------------------
# 5. 智能体治理声明（对齐《智能体规范应用与创新发展实施意见》）
# --------------------------------------------------------------------------
GOVERNANCE_KEYWORDS = {
    "human_in_the_loop": (
        "human_in_the_loop", "human-in-the-loop", "humaninloop",
        "人工介入", "人工审核", "人工确认", "人工复核", "人在回路", "人机协同审核",
        "human_oversight", "human_review", "approval_required", "require_approval",
        "manual_approval", "escalat", "确认后执行",
    ),
    "action_boundary": (
        "action_boundary", "action_boundary_declared", "action_boundaries",
        "allowed_actions", "denied_actions", "tool_whitelist", "tool_allowlist",
        "allowlist", "whitelist", "permission_scope", "scope",
        "行动边界", "权限边界", "允许动作", "禁止动作", "工具白名单", "调用范围",
        "边界声明",
    ),
    "data_processing": (
        "data_processing", "data_handling", "data_retention", "retention_policy",
        "pipl", "personal_data", "personal_information", "data_processing_declaration",
        "数据处理", "留存", "个人信息", "隐私保护", "数据出境",
    ),
    "approval_gate": (
        "approval_gate", "requires_approval", "require_approval", "payment_limit",
        "transaction_limit", "spending_limit", "dry_run", "confirm_before",
        "审批", "二次确认", "限额", "额度", "支付限制",
    ),
    "audit_log": (
        "audit_log", "audit_trail", "logging", "log_retention", "trace",
        "审计日志", "责任留痕", "留痕", "操作日志", "可追溯", "追溯",
    ),
}

# 高风险自主动作关键词
HIGH_RISK_ACTIONS = (
    "payment", "transfer", "purchase", "refund", "delete", "drop_table",
    "send_email", "send_mail", "publish", "deploy", "post_to", "webhook",
    "outbound", "transfer_funds", "wire",
    "支付", "转账", "下单", "付款", "退款", "删除", "发邮件", "发送邮件",
    "发布", "部署", "对外发送", "群发", "扣款",
)

# 拟人化互动特征（《人工智能拟人化互动服务管理暂行办法》2026-07-15 生效）
ANTHROPOMORPHIC_MARKERS = (
    "companion", "girlfriend", "boyfriend", "virtual friend", "roleplay",
    "role-play", "emotional", "emotion support", "anthropomorphic", "ai human",
    "情感陪伴", "拟人化", "虚拟恋人", "陪伴", "人格", "情绪价值",
)


# --------------------------------------------------------------------------
# 工具函数
# --------------------------------------------------------------------------
def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(value: str, keep: int = 4) -> str:
    """脱敏：只保留首尾若干字符，中间打码。审计报告里绝不能出现明文凭据。"""
    v = value.strip()
    if len(v) <= keep * 2:
        return "*" * len(v)
    return f"{v[:keep]}{'*' * (len(v) - keep * 2)}{v[-keep:]}"


def is_placeholder(value: str) -> bool:
    low = value.lower()
    return any(m in low for m in PLACEHOLDER_MARKERS)


def first_match(text: str, patterns: list[tuple[str, str]]) -> tuple[str, str, str] | None:
    """返回 (命中的正则, 人类可读描述, 实际匹配文本)；无命中返回 None。"""
    if not text:
        return None
    for pattern, desc in patterns:
        m = re.search(pattern, text, re.S)
        if m:
            return pattern, desc, m.group(0)
    return None


def line_of(text: str, needle: str) -> int | None:
    if not text or not needle:
        return None
    idx = text.find(needle)
    if idx < 0:
        idx = text.lower().find(needle.lower())
    if idx < 0:
        return None
    return text.count("\n", 0, idx) + 1


def line_of_regex(text: str, pattern: str) -> int | None:
    if not text:
        return None
    m = re.search(pattern, text, re.S)
    if not m:
        return None
    return text.count("\n", 0, m.start()) + 1


def find_hidden_injection(text: str) -> tuple[str, int] | None:
    """在隐藏容器（注释/script）里找注入。返回 (片段, 行号)。"""
    if not text:
        return None
    for m in HIDDEN_CONTAINER_RE.finditer(text):
        block = m.group(0)
        hit = first_match(block, INJECTION_PATTERNS)
        if hit:
            return hit[2], text.count("\n", 0, m.start()) + 1
    return None


BASE64_BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
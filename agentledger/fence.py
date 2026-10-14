"""行为围栏 —— 管住一次会话的整体轨迹，而不是单个动作。

围栏与闸门的区别
----------------
闸门（gate）回答「这个动作能不能做」——单点判定。
围栏（fence）回答「这个智能体**整场行为**是否越界」——轨迹判定。

两者的差别决定了几类闸门抓不到的风险：

1. **拆单**：把一次 10 万的退款拆成 10 次 1 万的退款，每次都合规。
   单点闸门全部放行，围栏在总量上越界。
2. **渐进试探**：连续 20 次查询敏感接口，每次都低于阈值。
   单点无异常，累计行为本身是攻击。
3. **序列依赖**：单独看每一步都合理，组合起来是完整的数据外传。
4. **静默降级**：Agent 反复重试直到绕过限制。

这些是真实的智能体攻击模式，而单点闸门对它们结构性无效。

政策依据
--------
《实施意见》第 7 条（加强行为管控）原文：

> 发展**规则内嵌、行为围栏**等技术，确保智能体在公共场所、隐私场所、
> 专门场所等的行为合法合规。探索利用区块链等技术，
> 建立重要应用场景智能体行为**可验证、可追溯**机制，
> 防范智能体不当行为引发重大风险。

第 2 条的四步链条中，围栏属于"阻断"，但它是**轨迹级**的阻断，
与闸门的**动作级**阻断互补，缺一不可。

设计约束
--------
- **零依赖、内存内、单进程**。围栏必须能在边缘/私有化环境跑，
  不能引入外部协调服务。
- **计数器即证据**。围栏自身产生可哈希的轨迹摘要，
  与 `agentledger.runtime` 的调用记录一起构成可验证的行为证据。
- **只收紧不放宽**。围栏只会让判定更严，不会更松。
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from .ledger import canonical, sha256_hex


class Verdict:
    """围栏判定。只有 BLOCK 会阻止执行；WARN 仅提示。"""

    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


@dataclass
class FenceEvent:
    action: str
    at: str = ""
    amount: float | None = None
    outcome: str = "ok"
    fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.at:
            self.at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "at": self.at,
            "amount": self.amount,
            "outcome": self.outcome,
            "fields": list(self.fields),
        }


@dataclass
class FenceVerdict:
    verdict: str
    pattern: str = ""
    reason: str = ""
    observed: dict[str, Any] = field(default_factory=dict)
    limit: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.verdict != Verdict.BLOCK

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "pattern": self.pattern,
            "reason": self.reason,
            "observed": self.observed,
            "limit": self.limit,
        }


class BehaviorFence:
    """单智能体、单会话的行为围栏。

    用法::

        fence = BehaviorFence(total_refund_limit=50_000, window_s=3600)
        for each_tool_call:
            v = fence.observe(action, amount, fields)
            if not v.allowed:
                escalate(v)
    """

    def __init__(self,
                 total_amount_limit: dict[str, float] | None = None,
                 window_s: int = 3600,
                 call_rate_limit: int = 120,
                 repeated_read_limit: int = 40,
                 burst_limit: int = 30,
                 burst_window_s: int = 1,
                 sensitive_read_limit: int = 10):
        # 每类动作在窗口内的累计额度上限，如 {"issue_refund": 50_000}
        self.total_amount_limit = dict(total_amount_limit or {})
        self.window_s = window_s
        self.call_rate_limit = call_rate_limit
        self.repeated_read_limit = repeated_read_limit
        self.burst_limit = burst_limit
        self.burst_window_s = burst_window_s
        self.sensitive_read_limit = sensitive_read_limit

        self._events: list[FenceEvent] = []
        self._blocked: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    def _window(self) -> list[FenceEvent]:
        cutoff = time.time() - self.window_s
        return [e for e in self._events
                if self._ts(e) >= cutoff]

    @staticmethod
    def _ts(e: FenceEvent) -> float:
        try:
            return time.mktime(time.strptime(e.at, "%Y-%m-%dT%H:%M:%SZ")) - time.timezone
        except (ValueError, OverflowError):
            return time.time()

    # ------------------------------------------------------------------
    def observe(self, action: str, amount: float | None = None,
                fields: tuple[str, ...] = (),
                outcome: str = "ok") -> FenceVerdict:
        """观察一次行为，返回围栏判定。BLOCK 时该行为**不应执行**。

        顺序有意义：先查便宜的计数类规则（O(1)），最后查累计额度（O(n)）。
        任一规则 BLOCK 立即返回 —— 围栏只收紧不放宽。
        """
        self._events.append(FenceEvent(action=action, amount=amount,
                                       outcome=outcome, fields=fields))
        win = self._window()

        warn = FenceVerdict(Verdict.ALLOW)
        for check in (self._check_rate, self._check_burst,
                      self._check_repeated_read, self._check_sensitive_read,
                      self._check_total_amount):
            v = check(win, action, amount)
            if v.verdict == Verdict.BLOCK:
                self._blocked.append({
                    **v.to_dict(),
                    "action": action,
                    "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                })
                return v
            if v.verdict == Verdict.WARN:
                warn = v          # 保留最早触发的那条告警

        return warn

    # ---- 单项检查 ---------------------------------------------------
    def _check_rate(self, win, action, amount) -> FenceVerdict:
        n = len(win)
        if self.call_rate_limit and n > self.call_rate_limit:
            return FenceVerdict(Verdict.BLOCK, "call_rate",
                                 f"窗口内调用 {n} 次，超出速率上限 {self.call_rate_limit}",
                                 {"calls": n}, {"limit": self.call_rate_limit})
        if self.call_rate_limit and n > self.call_rate_limit * 0.8:
            return FenceVerdict(Verdict.WARN, "call_rate",
                                 f"接近速率上限（{n}/{self.call_rate_limit}）",
                                 {"calls": n}, {"limit": self.call_rate_limit})
        return FenceVerdict(Verdict.ALLOW)

    def _check_burst(self, win, action, amount) -> FenceVerdict:
        """重试风暴检测。

        窗口取 1 秒而非 10 秒：10 秒窗口会把正常的高频会话
        （批量查询、报表生成）全部误判为风暴。1 秒内出现
        远超人类/常规业务节奏的调用数，才是真正的重试异常。
        """
        recent = [e for e in win if self._ts(e) > time.time() - self.burst_window_s]
        if self.burst_limit and len(recent) > self.burst_limit:
            return FenceVerdict(Verdict.BLOCK, "burst",
                                 f"{self.burst_window_s} 秒内 {len(recent)} 次调用，"
                                 f"疑似重试风暴",
                                 {"calls": len(recent), "window_s": self.burst_window_s},
                                 {"limit": self.burst_limit})
        return FenceVerdict(Verdict.ALLOW)

    def _check_repeated_read(self, win, action, amount) -> FenceVerdict:
        reads = [e for e in win if e.action in ("read", "lookup", "search", "lookup_order")]
        if self.repeated_read_limit and len(reads) > self.repeated_read_limit:
            return FenceVerdict(Verdict.BLOCK, "repeated_read",
                                 f"窗口内只读操作 {len(reads)} 次，超出上限 "
                                 f"{self.repeated_read_limit}，疑似数据爬取",
                                 {"reads": len(reads)}, {"limit": self.repeated_read_limit})
        return FenceVerdict(Verdict.ALLOW)

    def _check_sensitive_read(self, win, action, amount) -> FenceVerdict:
        from .runtime import SENSITIVE_KEY_RE
        hits = sum(1 for e in win for f in e.fields if SENSITIVE_KEY_RE.match(f))
        if self.sensitive_read_limit and hits > self.sensitive_read_limit:
            return FenceVerdict(Verdict.BLOCK, "sensitive_read",
                                 f"窗口内访问敏感字段 {hits} 次，超出上限 "
                                 f"{self.sensitive_read_limit}",
                                 {"sensitive_hits": hits}, {"limit": self.sensitive_read_limit})
        return FenceVerdict(Verdict.ALLOW)

    def _check_total_amount(self, win, action, amount) -> FenceVerdict:
        if amount is None:
            return FenceVerdict(Verdict.ALLOW)
        limit = self.total_amount_limit.get(action)
        if limit is None:
            return FenceVerdict(Verdict.ALLOW)

        # 注意：observe() 已把本次事件 append 进 _events，
        # 所以 win 里**已经包含本次**。累计值就是 spent 本身，
        # 不能再加一次 amount —— 否则每笔都被算两遍，
        # 额度会提前一半触发，把合法业务误判为拆单。
        total = sum(e.amount or 0.0 for e in win if e.action == action)
        # 这是拆单攻击的核心防线：单笔合规，累计越界即阻断。
        if total > limit:
            return FenceVerdict(Verdict.BLOCK, "total_amount",
                                 f"{action} 窗口累计 {total} 超出额度 {limit}"
                                 f"（单笔 {amount} 合规，但累计越界）",
                                 {"prior": total - amount, "attempt": amount,
                                  "total": total},
                                 {"limit": limit})
        if total > limit * 0.8:
            return FenceVerdict(Verdict.WARN, "total_amount",
                                 f"{action} 累计 {total}/{limit}，接近额度上限",
                                 {"prior": total - amount, "total": total},
                                 {"limit": limit})
        return FenceVerdict(Verdict.ALLOW)

    # ------------------------------------------------------------------
    def digest(self) -> str:
        """轨迹摘要。可与运行时记录一起哈希，作为行为证据。"""
        return sha256_hex(canonical([e.to_dict() for e in self._events]))

    def evidence(self) -> dict[str, Any]:
        """围栏证据。说明"哪些行为模式被识别并阻断"。"""
        patterns: dict[str, int] = defaultdict(int)
        for b in self._blocked:
            patterns[b["pattern"]] += 1
        return {
            "kind": "behavior_fence",
            "policy_ref": "《实施意见》第 7 条（规则内嵌、行为围栏、可验证可追溯）",
            "window_s": self.window_s,
            "limits": {
                "total_amount_limit": self.total_amount_limit,
                "call_rate_limit": self.call_rate_limit,
                "burst_limit": self.burst_limit,
                "burst_window_s": self.burst_window_s,
                "repeated_read_limit": self.repeated_read_limit,
                "sensitive_read_limit": self.sensitive_read_limit,
            },
            "observed_events": len(self._events),
            "blocked_events": len(self._blocked),
            "blocked_by_pattern": dict(patterns),
            "trajectory_digest": self.digest(),
            "detects": [
                "拆单：单笔合规但窗口内累计越界",
                "渐进试探：低频但持续的数据读取",
                "重试风暴：短时间大量调用",
            ],
            "blocked_detail": self._blocked[:50],
        }


__all__ = ["BehaviorFence", "Verdict", "FenceVerdict", "FenceEvent"]
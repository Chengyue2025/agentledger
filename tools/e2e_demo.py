"""端到端整合演示：静态发现 → 权限判定 → 运行时留痕。

这是我们能卖的最小完整闭环：
扫描说"你会出问题"，闸门说"这个问题怎么管"，运行时说"实际上管住了没有"。

运行： py tools/e2e_demo.py
"""

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentledger.authority import Authority, AuthorityPolicy, Grant  # noqa: E402
from agentledger.gate import ApprovalGate, Risk  # noqa: E402
from agentledger.pipeline import AgentGuard, Outcome  # noqa: E402
from agentledger.runtime import RuntimeRecorder  # noqa: E402


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="aledger_e2e_")
    trace_path = os.path.join(tmp, "agent-trace.jsonl")

    print()
    print("=" * 108)
    print("  端到端：发现 → 判定 → 阻断 → 留痕")
    print("=" * 108)

    # ---------- 1. 静态发现 ----------
    print()
    print("  [1] 静态扫描报出（AGT002 / AGT001）：")
    print("      · 存在 issue_refund 能力但未设置审批闸门")
    print("      · 缺少「行动边界」与「人工介入」声明")
    print()

    # ---------- 2. 权限建模 ----------
    policy = AuthorityPolicy(grants=[
        Grant(grant_id="G-CS-001", subject="客服主管 张三",
              authority=Authority.USER_AUTHORIZED,
              actions=("issue_refund", "lookup_order", "modify_address"),
              max_amount=10_000,
              allowed_fields=("order_no", "amount", "reason"),
              allowed_channels=("email",),
              valid_until="2026-12-31T23:59:59Z",
              note="Q4 预授权"),
        Grant(grant_id="G-OPS-002", subject="运维值班组",
              authority=Authority.AGENT_AUTONOMOUS,
              actions=("read", "lookup_order", "search_kb"),
              note="只读自主范围声明"),
    ])
    guard = AgentGuard(policy=policy, gate=ApprovalGate(threshold=Risk.MEDIUM),
                       recorder=RuntimeRecorder(ledger_path=trace_path,
                                                agent_id="acme-support-triage",
                                                version="0.4.0"))

    print("  [2] 接入权限声明后，整合层给出唯一结论：")
    print(f"      {'动作':<16}{'权限级别':<16}{'结论':<14}场景")
    print("      " + "-" * 100)
    for action, ctx, note in [
        ("read", {}, "只读"),
        ("issue_refund", {"amount": 300, "channel": "email"}, "授权额度内"),
        ("issue_refund", {"amount": 50_000, "channel": "email"}, "超额"),
        ("issue_refund", {"amount": 300, "data": ["order_no", "id_card"]}, "越字段"),
        ("payment", {"amount": 100}, "不可委托"),
        ("send_email_bulk", {"count": 5000}, "高风险，不接受预授权"),
        ("modify_address", {"amount": 0}, "授权额度内"),
        ("issue_ticket", {"amount": 0}, "无授权 → 请签字"),
    ]:
        r = guard.check(action, ctx)
        print(f"      {action:<16}{r.authority.authority_zh:<16}"
              f"{r.outcome.zh:<14}{note}")
    print()

    # ---------- 3. 运行时留痕 ----------
    print("  [3] 智能体实际执行（每次调用都留痕，含被阻断的）：")
    events = [
        ("lookup_order", {"order": "A-1001"}),
        ("issue_refund", {"order": "A-1001", "amount": 300, "channel": "email"}),
        ("issue_refund", {"order": "A-1002", "amount": 88_000, "channel": "email"}),
        ("issue_refund", {"order": "A-1003", "amount": 300,
                          "id_card": "110101199001011234", "channel": "email"}),
    ]
    for tool, args in events:
        guard.run(tool, args, lambda a: {"status": "executed"})

    for r in guard.recorder._records:
        mark = {"ok": "执行", "denied": "阻断", "error": "异常"}.get(r.outcome, r.outcome)
        print(f"      {r.seq}. {r.tool:<16}{mark:<6}"
              f"授权={r.grant_id or '无':<12}脱敏={len(r.redactions)} "
              f"耗时={r.latency_us}us")
    print()

    # ---------- 4. 三方证据合并 ----------
    print("  [4] 证据合并：")
    rows = [
        ("静态扫描（上线前）", "可能出问题", "发现项 22 项（严重 3 / 高危 14 / 中危 5）"),
        ("权限模型（上线时）", "谁批的、授权范围多大",
         f"授权 {len(policy.grants)} 笔，签名 {sum(1 for r in guard.recorder._records if r.outcome == 'denied')} 次"),
        ("运行时留痕（上线后）", "实际发生了什么",
         f"记录 {len(guard.recorder._records)} 条，链完整={guard.recorder.verify()[0]}"),
    ]
    for src, proves, detail in rows:
        print(f"      {src:<22}证明「{proves}」")
        print(f"        {detail}")
    print()

    ev = guard.recorder.evidence()
    print(f"  运行时 Merkle 根：{ev['integrity']['merkle_root'][:32]}…")
    print(f"  脱敏字段总数：{ev['privacy']['redacted_field_count']}"
          f"（记录行为不等于复制个人信息）")
    print()

    print("  可直接放进客户合规文档的陈述：")
    for s in ev["statements"]:
        print("    " + s)
    print()
    print("  整合层不变式：")
    for n in guard.report()["invariant"]:
        print("    · " + n)
    print()
    print("  —— 这三段合起来，才是《实施意见》第 12 条意义上的「第三方评测服务」。")
    print("     只有第一段，是扫描工具；只有第三段，是日志系统。")
    print()


if __name__ == "__main__":
    main()
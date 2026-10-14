"""围栏 vs 闸门：拆单攻击对照演示。

这是围栏存在的唯一理由 —— 证明单点闸门在拆单攻击下结构性失效。

运行： py tools/fence_demo.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentledger.fence import BehaviorFence  # noqa: E402
from agentledger.gate import ApprovalGate, Risk  # noqa: E402


def scenario_split(title: str, amounts: list[float], limit: float,
                   note: str) -> None:
    """对照演示。

    关键：闸门阈值设为 HIGH，`issue_refund`（基础风险 HIGH）单笔即合规，
    全部放行 —— 这样才能干净地展示围栏补上了什么。

    若把阈值设为 MEDIUM，每笔都要签字，那是闸门在工作，
    围栏的价值就体现不出来了。两者是叠加关系，不是替代。
    """
    gate = ApprovalGate(threshold=Risk.HIGH)
    fence = BehaviorFence(total_amount_limit={"issue_refund": limit},
                          burst_limit=100_000, call_rate_limit=100_000)
    print()
    print(f"  {title}")
    print(f"  {note}")
    print()
    print(f"  闸门阈值 = HIGH（单笔合规即放行）")
    print()
    print(f"  {'笔':<5}{'金额':>10}  {'单点闸门':<12}{'行为围栏':<10}围栏判定")
    print("  " + "-" * 86)
    gate_pass = 0
    fence_block = 0
    shown = 0
    for i, amt in enumerate(amounts, 1):
        g = gate.check("issue_refund", {"amount": amt})
        f = fence.observe("issue_refund", amount=amt)
        gmark = "需签字" if g.requires_approval else "放行"
        fmark = "放行" if f.allowed else "阻断"
        if gmark == "放行":
            gate_pass += 1
        if fmark == "阻断":
            fence_block += 1
        # 100 笔的场景只显示首次阻断前后几行，避免刷屏
        interesting = (fmark == "阻断") or shown < 3
        if interesting and len(amounts) > 12:
            print(f"  {i:<5}{amt:>10,.0f}  {gmark:<12}{fmark:<10}{f.reason[:36]}")
        elif interesting:
            print(f"  {i:<5}{amt:>10,.0f}  {gmark:<12}{fmark:<10}{f.reason[:36]}")
        if interesting:
            shown += 1
    if len(amounts) > 12:
        print(f"  …（省略中间 {len(amounts) - shown} 笔）")
    print()
    print(f"  单点闸门放行 {gate_pass}/{len(amounts)} 笔    "
          f"行为围栏拦截 {fence_block}/{len(amounts)} 笔")
    if gate_pass == len(amounts) and fence_block > 0:
        print("  → 单点闸门全程未察觉，围栏在累计越界时拦住了")


def main() -> None:
    print()
    print("=" * 92)
    print("  行为围栏 vs 单点闸门：为什么只有单点管控不够")
    print("=" * 92)

    scenario_split(
        "场景一：拆单 —— 把一次 60,000 退款拆成 6 笔 10,000",
        [10000] * 6, 50_000,
        "  单点闸门每次都答「这一笔合规」，6 笔全部放行，总额却已超授权额度。",
    )

    scenario_split(
        "场景二：小额高频 —— 100 笔 900，绕过单笔 1000 的上限",
        [900] * 100, 50_000,
        "  每笔都远低于单笔阈值，任何单点规则都看不出异常。",
    )

    print()
    print("=" * 92)
    print("  结论")
    print("=" * 92)
    print("""
  闸门（gate）   回答「这个动作能不能做」  —— 单点判定，管的是一次调用
  围栏（fence）  回答「这轮会话总共做了多少」—— 轨迹判定，管的是一段行为

  两者的关系不是替代而是叠加：
    · 单笔合规不代表累计合规（拆单）
    · 单次无害不代表轨迹无害（渐进试探）
    · 步骤都合理不代表组合无害（序列依赖）

  《实施意见》第 7 条要求「规则内嵌、行为围栏」，
  第 2 条要求「发现、干预、阻断、恢复」——
  单点闸门只能覆盖「阻断」中的一个切面，围栏才补上轨迹维度。

  证据说明：围栏产出可哈希的轨迹摘要（trajectory_digest），
  与运行时调用记录一起构成「行为可验证、可追溯」的证据链。
""")

    fence = BehaviorFence(total_amount_limit={"issue_refund": 50000})
    for _ in range(6):
        fence.observe("issue_refund", amount=10000)
    ev = fence.evidence()
    print("  围栏证据摘要：")
    print(f"    观察行为 {ev['observed_events']} 次，阻断 {ev['blocked_events']} 次")
    print(f"    命中模式 {ev['blocked_by_pattern']}")
    print(f"    轨迹摘要 {ev['trajectory_digest'][:32]}…")
    print()


if __name__ == "__main__":
    main()
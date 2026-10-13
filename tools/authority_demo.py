"""三级决策权限实战演示 —— 对齐《实施意见》第 6 条原文措辞。

运行： py tools/authority_demo.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentledger.authority import Authority, AuthorityPolicy, Grant  # noqa: E402


def build_policy() -> AuthorityPolicy:
    """一个典型的客服智能体配置：预授权额度内自动退款，超出必须人工。"""
    return AuthorityPolicy(grants=[
        Grant(grant_id="G-CS-001", subject="客服主管 张三",
              authority=Authority.USER_AUTHORIZED,
              actions=("issue_refund", "modify_address"),
              max_amount=10_000,
              allowed_fields=("order_no", "amount", "reason"),
              allowed_channels=("email",),
              valid_until="2026-12-31T23:59:59Z",
              note="Q4 客服自动处理额度授权"),
        Grant(grant_id="G-OPS-002", subject="运维值班组",
              authority=Authority.AGENT_AUTONOMOUS,
              actions=("read", "lookup_order", "search_kb", "summarize"),
              note="只读自主范围声明"),
    ])


CASES = [
    ("payment", {}, "跨境支付：不可委托级"),
    ("delete_account", {}, "注销账户：不可委托级"),
    ("issue_refund", {"amount": 300, "channel": "email"}, "小额退款：在授权内"),
    ("issue_refund", {"amount": 50_000, "channel": "email"}, "超额退款：超上界"),
    ("issue_refund", {"amount": 300, "data": ["order_no", "id_card"]}, "带身份证号：超字段"),
    ("issue_refund", {"amount": 300, "channel": "sms"}, "走短信：超通道"),
    ("issue_refund", {"amount": 300, "channel": "email"}, "找不在名单的工具：未授权"),
    ("read", {}, "只读查询：自主范围已声明"),
    ("lookup_order", {}, "订单查询：自主范围已声明"),
    ("deploy", {}, "生产部署：未授权"),
]


def main() -> None:
    pol = build_policy()

    print()
    print("  三级决策权限判定 —— 《实施意见》第 6 条")
    print()
    print(f"  {'动作':<18}{'权限级别':<16}{'结果':<8}场景")
    print("  " + "-" * 104)
    for action, ctx, note in CASES:
        d = pol.decide(action, ctx)
        mark = "放行" if d.allowed else "阻断"
        print(f"  {action:<18}{d.authority_zh:<16}{mark:<8}{note}")
    print()

    print("  可直接贴进客户合规文档的结论：")
    print()
    for action, ctx, _ in CASES:
        d = pol.decide(action, ctx)
        print("    " + d.to_statement())
    print()

    print("  权限矩阵摘要（可进 AI BOM）：")
    ex = pol.explain()
    print(f"    依据      {ex['policy_ref']}")
    print(f"    默认级别  {ex['default_authority_zh']}")
    for lv in ex["levels"]:
        print(f"      - {lv['zh']:<16}{lv['signer_role']}")
    print(f"    生效授权  {len(ex['active_grants'])} 条：")
    for g in ex["active_grants"]:
        print(f"      {g['grant_id']:<12}{g['subject']:<18}"
              f"{g['authority']:<20}金额上限={g['max_amount']}")
    print()
    print("  纪律说明：")
    for n in ex["notes"]:
        print("    - " + n)
    print()

    # 超权断言语句必须是可读的，而不是机器码
    d = pol.decide("issue_refund", {"amount": 50_000})
    print("  阻断结果的 JSON 形态（供系统消费）：")
    print("    " + json.dumps(d.to_dict(), ensure_ascii=False)[:260] + " …")
    print()


if __name__ == "__main__":
    main()
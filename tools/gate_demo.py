"""审批闸门实战演示 —— 展示 AGT002 报出的缺口如何被真正堵上。

运行： py tools/gate_demo.py
"""

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentledger.gate import ApprovalGate, Risk  # noqa: E402

CASES = [
    ("read", {"order": "A-123"}, "只读"),
    ("lookup_order", {"order": "A-123"}, "只读"),
    ("summarize", {"doc": "ticket-9"}, "只读"),
    ("issue_refund", {"amount": 50}, "小额退款"),
    ("issue_refund", {"amount": 50000}, "大额退款"),
    ("delete_account", {"customer": "u-9"}, "不可逆删除"),
    ("send_email", {"count": 500, "data": ["name", "id_card"]}, "批量外发+敏感字段"),
    ("export_data", {"data": ["id_card", "phone"]}, "未登记动作+敏感字段"),
    ("退款", {"text": "把这个订单的钱退到客户卡里", "amount": 8888}, "中文自然语言"),
    ("frobnicate_widget_v2", {}, "完全未登记的动作"),
]


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="gate_demo_")
    ledger = os.path.join(tmp, "gate.jsonl")
    gate = ApprovalGate(threshold=Risk.MEDIUM, ledger_path=ledger)

    header = f"{'动作':<22}{'风险':<10}{'需审批':<8}{'延迟':>9}  场景"
    print()
    print("  审批闸门实战（阈值 = MEDIUM）")
    print()
    print("  " + header)
    print("  " + "-" * 104)
    for action, ctx, note in CASES:
        d = gate.check(action, ctx)
        need = "是" if d.requires_approval else "否"
        print(f"  {action:<22}{d.risk.value:<10}{need:<8}{d.latency_ms:>7.2f}ms  {note}")
    print()

    print("  逐条判定理由：")
    for action, ctx, _ in CASES:
        d = gate.check(action, ctx)
        print(f"    {action:<22}{d.reason[:76]}")
    print()

    print("  闸门策略（可直接进 AI BOM / 证据包）：")
    print()
    for line in json.dumps(gate.policy(), ensure_ascii=False, indent=2).splitlines()[:9]:
        print("    " + line)
    print()

    # 人工审批留痕
    d = gate.check("transfer_funds", {"amount": 5_000_000})
    rec = gate.record_approval(d, "张三（财务）", approved=True, note="已电话确认，工单 OPS-4821")
    print("  人工审批留痕：")
    print(f"    动作={rec['action']}  风险={rec['risk']}  审批人={rec['approval']['approver']}")
    print(f"    判定={rec['approval']['approved']}  依据={rec['approval']['note']}")
    print()

    lines = Path(ledger).read_text(encoding="utf-8").strip().splitlines()
    print(f"  留痕记录数：{len(lines)}（每条含判定依据 + 延迟 + 时间戳）")
    print(f"  闸门策略默认拒绝：{gate.policy()['default_deny']}")
    print()
    print("  注意：审批闸门是责任边界，不是安全边界。")
    print("  它保证「这件事有人签字」，不保证「这件事是安全的」。")
    print()


if __name__ == "__main__":
    main()
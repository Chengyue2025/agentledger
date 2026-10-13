"""开发辅助：把证据包里的发现项打印成表格，便于人工核对规则是否打准。"""

import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as fh:
    d = json.load(fh)

s = d["summary"]
print(f"工具 {d['tool']}   生成于 {d['generated_at']}")
print(f"覆盖 扫描 {d['coverage']['scanned_files']} / 攻击面 "
      f"{d['coverage']['ai_surface_files']} / 排除 {d['coverage']['excluded_count']}")
print(f"Merkle {d['integrity']['findings_merkle_root'][:24]}…   "
      f"链头 {d['integrity']['ledger_head'][:24]}…")
print()
print(f"{'严重度':<9} {'规则':<8} {'位置':<32} 标题")
print("-" * 108)
for f in d["findings"]:
    print(f"{f['severity']:<9} {f['rule_id']:<8} {f['location'][:31]:<32} {f['title']}")
print()
print(f"合计 {s['total_findings']}   " + "  ".join(
    f"{k}={v}" for k, v in s["by_severity"].items() if v))
print()
print("按攻击面: " + "  ".join(f"{k}={v}" for k, v in s["by_surface"].items()))
print("按类别  : " + "  ".join(f"{k}={v}" for k, v in list(s["by_tag"].items())[:8]))
print()
print("触及义务:")
for oid in d["compliance"]["obligations_touched"]:
    meta = d["compliance"]["obligation_catalog"][oid]
    print(f"  {oid:<16}{meta['title']}  ({len(d['compliance']['gaps'][oid])} 项未满足)")
"""开发辅助：抽查 SARIF 输出里的 obligations 字段是否真的带上了法条映射。"""

import glob
import json
import sys

files = sorted(glob.glob(sys.argv[1]))
if not files:
    print("no sarif found")
    sys.exit(1)

d = json.load(open(files[-1], encoding="utf-8"))
results = d["runs"][0]["results"]
print(f"SARIF {d['version']}  results={len(results)}")

shown = 0
for r in results:
    obl = r["properties"].get("obligations") or []
    if obl and shown < 5:
        print(f"  {r['ruleId']:<8} {r['level']:<8} -> {obl}")
        shown += 1

with_obl = sum(1 for r in results if r["properties"].get("obligations"))
print(f"\n带法条映射的结果: {with_obl}/{len(results)}")
assert with_obl == len(results), "存在未映射法条的结果"
print("OK")
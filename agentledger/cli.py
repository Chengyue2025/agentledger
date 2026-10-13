"""aledger 命令行入口。

    aledger scan <path>          扫描并生成证据包
    aledger verify               校验账本链完整性
    aledger history              查看留痕历史
    aledger rules                列出规则目录与义务映射
    aledger init-key             生成签署密钥
    aledger receipt ...          委托收据：签发/验证/撤销（IETF DRP 对齐）

设计原则：默认零依赖、可离线、可复现。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import TOOL_ID, __version__, receipt
from .inventory import discover
from .ledger import Ledger, attest, findings_merkle, generate_key, write_key
from .mapping import OBLIGATIONS, RULE_OBLIGATIONS
from .model import SEVERITY_ORDER, Severity
from .report import build_pack, pack_to_json, pack_to_markdown
from .rules import RULE_CATALOG, run
from .sarif import pack_to_sarif

# 让中文在 Windows 控制台正常显示
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


def _unicode_ok(stream=None) -> bool:
    """当前输出流能否表示制表符号。

    Windows 中文控制台默认 GBK，直接打印 ─│█■ 会变成乱码。
    这里做能力探测，不支持就降级为 ASCII，保证任何环境下输出都可读。
    """
    stream = stream or sys.stdout
    enc = (getattr(stream, "encoding", None) or "").lower()
    if not enc:
        return False
    try:
        "─│█■▲◆○·√×".encode(enc)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


_U = _unicode_ok()
SEV_MARK = ({"CRITICAL": "■", "HIGH": "▲", "MEDIUM": "◆",
             "LOW": "○", "INFO": "·"} if _U else
            {"CRITICAL": "#", "HIGH": "!", "MEDIUM": "+", "LOW": "-", "INFO": "."})
BOX = ({"h": "─", "tl": "┌", "tr": "┐", "bl": "└", "br": "┘", "v": "│", "bar": "█"}
       if _U else
       {"h": "-", "tl": "+", "tr": "+", "bl": "+", "br": "+", "v": "|", "bar": "#"})
OK_MARK = "√" if _U else "OK"
BAD_MARK = "×" if _U else "X"
SEV_ZH = {
    "CRITICAL": "严重", "HIGH": "高危", "MEDIUM": "中危", "LOW": "低危", "INFO": "提示",
}


# --------------------------------------------------------------------------
def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.path).resolve()
    if not target.exists():
        print(f"[x] 路径不存在: {target}", file=sys.stderr)
        return 2

    cov = discover(target, max_files=args.max_files)
    findings = run(cov, enabled=set(args.only or []), disabled=set(args.skip or []))
    merkle = findings_merkle(findings)

    # ---- 写账本 ----
    ledger_head = ""
    if not args.no_ledger:
        led = Ledger.for_root(target if target.is_dir() else target.parent)
        entry = led.append(target.name or str(target), findings)
        ledger_head = entry.hash

    # ---- 签署 ----
    attestation, attester = "", args.attester or ""
    if args.key:
        key_path = Path(args.key)
        if not key_path.exists():
            print(f"[x] 密钥文件不存在: {key_path}", file=sys.stderr)
            return 2
        attestation = attest(merkle + "|" + ledger_head, key_path.read_text(encoding="ascii").strip())

    pack = build_pack(findings, cov, ledger_head=ledger_head, merkle=merkle,
                      attestation=attestation, attester=attester)

    outdir = Path(args.out) if args.out else (target if target.is_dir() else target.parent) / ".agentledger"
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = pack["generated_at"].replace(":", "").replace("-", "").replace("+0000", "Z")
    jpath = outdir / f"pack-{stamp}.json"
    mpath = outdir / f"pack-{stamp}.md"
    jpath.write_text(pack_to_json(pack), encoding="utf-8")
    mpath.write_text(pack_to_markdown(pack), encoding="utf-8")

    spath = None
    if args.sarif:
        spath = outdir / f"scan-{stamp}.sarif"
        spath.write_text(pack_to_sarif(pack), encoding="utf-8")

    # ---- 控制台摘要 ----
    _print_summary(pack, findings, jpath, mpath, ledger_head, merkle, attestation, spath)

    fail_sev = Severity[args.fail_on.upper()]
    return 1 if any(f.severity.rank <= fail_sev.rank for f in findings) else 0


def _print_summary(pack, findings, jpath, mpath, head, merkle, att, spath=None) -> None:
    s = pack["summary"]
    cov = pack["coverage"]
    print()
    print(f"  {TOOL_ID}")
    print(f"  目标  {cov.get('root')}")
    print(f"  覆盖  扫描 {cov.get('scanned_files', 0)} 文件 / AI 攻击面 "
          f"{cov.get('ai_surface_files', 0)} 个 / 排除 {cov.get('excluded_count', 0)} 个")
    print()
    print("  " + BOX["tl"] + "─ 发现项 " + BOX["h"] * 50)
    for sev in SEVERITY_ORDER:
        n = s["by_severity"][sev.value]
        bar = BOX["bar"] * min(n, 40)
        print(f"  │ {SEV_MARK[sev.value]} {sev.value:<8}{SEV_ZH[sev.value]:<4}"
              f"{n:>4}  {bar}")
    print(f"  └{BOX['h'] * 56}")
    print()

    top = [f for f in findings if f.severity.rank <= Severity.MEDIUM.rank][:8]
    if top:
        print("  主要问题：")
        for f in top:
            print(f"    {SEV_MARK[f.severity.value]} [{f.rule_id}] {f.title}")
            print(f"        {f.location()}")
        print()

    if merkle:
        print(f"  Merkle 根  {merkle[:32]}…")
    if head:
        print(f"  账本链头   {head[:32]}…")
    print(f"  人工签署   {att[:32] + '…' if att else '未签署（机器不能承担责任）'}")
    print()
    print(f"  证据包     {mpath}")
    print(f"             {jpath}")
    if spath:
        print(f"  SARIF      {spath}")
    print()


def cmd_verify(args: argparse.Namespace) -> int:
    target = Path(args.path).resolve()
    led = Ledger.for_root(target if target.is_dir() else target.parent)
    ok, problems = led.verify()
    ents = led.entries()
    if not ents:
        print(f"[i] 账本为空或不存在: {led.path}")
        return 0
    print(f"  账本  {led.path}")
    print(f"  条目  {len(ents)}")
    print(f"  链头  {led.head()}")
    if ok:
        print(f"  状态  {OK_MARK} 链完整，未检测到篡改")
        return 0
    print(f"  状态  {BAD_MARK} 链已断裂")
    for p in problems:
        print(f"    - {p}")
    return 1


def cmd_history(args: argparse.Namespace) -> int:
    target = Path(args.path).resolve()
    led = Ledger.for_root(target if target.is_dir() else target.parent)
    ents = led.entries()
    if not ents:
        print(f"[i] 账本为空或不存在: {led.path}")
        return 0
    print(f"  {'#':>4}  {'时间':<21}{'目标':<24}{'发现':>5}  链头")
    for e in ents:
        if e.hash == "<unparsable>":
            print(f"  {e.seq:>4}  <无法解析>")
            continue
        print(f"  {e.seq:>4}  {e.ts:<21}{e.target[:23]:<24}{e.findings:>5}  {e.hash[:16]}…")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    if args.json:
        print(json.dumps(
            {"catalog": RULE_CATALOG, "obligations": OBLIGATIONS,
             "mapping": RULE_OBLIGATIONS},
            ensure_ascii=False, indent=2))
        return 0
    print()
    print(f"  规则目录 — {TOOL_ID}")
    print()
    groups = {"MCP": "MCP 服务器供应链", "MDL": "模型接入",
              "PRM": "提示词 / 技能", "DEP": "依赖与执行", "AGT": "智能体治理"}
    for prefix, label in groups.items():
        print(f"  {label}")
        for rid, (title, tag) in RULE_CATALOG.items():
            if not rid.startswith(prefix):
                continue
            obs = ", ".join(RULE_OBLIGATIONS.get(rid, []))
            print(f"    {rid}  {title}")
            print(f"          类别={tag}  义务={obs}")
        print()
    print(f"  义务登记表（{len(OBLIGATIONS)} 项）")
    for oid, meta in OBLIGATIONS.items():
        print(f"    {oid:<18}{meta['title']}")
    print()
    return 0


def cmd_init_key(args: argparse.Namespace) -> int:
    p = write_key(args.path)
    print(f"  签署密钥已生成: {p}")
    print("  该密钥用于 HMAC-SHA256 分离式签名。")
    print("  注意：HMAC 为对称算法，能证明证据未被改动，但不能证明'是谁签的'。")
    print("  若需不可抵赖的非对称签名，请用外部 KMS/CA 签发后附加到证据包。")
    return 0


# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aledger",
        description="agentledger —— 智能体 AI BOM、供应链溯源与防篡改责任留痕",
    )
    p.add_argument("--version", action="version", version=TOOL_ID)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="扫描目标并生成证据包")
    s.add_argument("path", help="要扫描的目录或文件")
    s.add_argument("-o", "--out", help="证据包输出目录（默认 <target>/.agentledger）")
    s.add_argument("--json", action="store_true", help="以 JSON 输出到 stdout")
    s.add_argument("--no-ledger", action="store_true", help="不写入账本")
    s.add_argument("--key", help="签署密钥文件路径（用于 HMAC 背书）")
    s.add_argument("--attester", default="", help="签署人姓名/机构")
    s.add_argument("--only", nargs="*", help="仅运行指定规则 ID 或标签")
    s.add_argument("--skip", nargs="*", help="跳过指定规则 ID 或标签")
    s.add_argument("--fail-on", default="HIGH",
                   choices=[s.value for s in SEVERITY_ORDER],
                   help="达到该严重度即以退出码 1 结束（默认 HIGH）")
    s.add_argument("--sarif", action="store_true",
                   help="额外输出 SARIF 2.1.0（可接入 GitHub Code Scanning）")
    s.add_argument("--max-files", type=int, default=20000)
    s.set_defaults(func=cmd_scan)

    v = sub.add_parser("verify", help="校验账本链完整性")
    v.add_argument("path", nargs="?", default=".")
    v.set_defaults(func=cmd_verify)

    h = sub.add_parser("history", help="查看留痕历史")
    h.add_argument("path", nargs="?", default=".")
    h.set_defaults(func=cmd_history)

    r = sub.add_parser("rules", help="列出规则与义务映射")
    r.add_argument("--json", action="store_true")
    r.set_defaults(func=cmd_rules)

    k = sub.add_parser("init-key", help="生成签署密钥")
    k.add_argument("path", nargs="?", default="./.agentledger/attestation.key")
    k.set_defaults(func=cmd_init_key)

    g = sub.add_parser(
        "gbz185",
        help="导出 GB/Z 185—2026 智能体注册载荷（含符合度自查）")
    g.add_argument("path", help="智能体项目目录")
    g.add_argument("--name", required=True, help="智能体名称")
    g.add_argument("--operator", default="", help="开发者/部署单位")
    g.add_argument("--version", default="", help="智能体版本")
    g.add_argument("--deployment-mode", default="",
                   help="部署方式：private / saas / hybrid")
    g.add_argument("--jurisdiction", default="CN")
    g.add_argument("-o", "--out", default="", help="输出目录（默认 <path>/.agentledger）")
    g.add_argument("--strict", action="store_true",
                   help="存在 inferred 级要素时以退出码 1 结束")
    g.set_defaults(func=cmd_gbz185)

    receipt.register(sub)

    return p


def cmd_gbz185(args: argparse.Namespace) -> int:
    """导出 GB/Z 185—2026 注册载荷。

    对应《实施意见》第 4 条：智能体注册平台需支持查询管理
    「开发者、部署方式、接口协议、合规认证」等信息。
    """
    from .gbz185 import (
        AgentIdentity, RegistrationPayload, capability_from_scan,
        conformance_report,
    )
    from .inventory import discover
    from .ledger import findings_merkle

    target = Path(args.path).resolve()
    if not target.exists():
        print(f"[x] 路径不存在: {target}", file=sys.stderr)
        return 2

    cov = discover(target)
    findings = run(cov)
    merkle = findings_merkle(findings)

    ident = AgentIdentity(
        name=args.name, operator=args.operator, version=args.version,
        jurisdiction=args.jurisdiction, deployment_mode=args.deployment_mode,
    )
    payload = RegistrationPayload(ident, capability_from_scan(cov, findings))
    payload.add_attestation(
        kind="static_scan", digest=merkle, issuer=TOOL_ID,
        scope="AI BOM + 供应链溯源 + 治理完备性",
    )

    doc = payload.to_dict()
    report = conformance_report(doc)
    doc["conformance_self_check"] = report

    outdir = Path(args.out) if args.out else (
        target if target.is_dir() else target.parent) / ".agentledger"
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = doc["generated_at"].replace(":", "").replace("-", "").replace("+0000", "Z")
    outpath = outdir / f"gbz185-registration-{stamp}.json"
    outpath.write_text(json.dumps(doc, ensure_ascii=False, indent=2),
                       encoding="utf-8")

    print()
    print("  GB/Z 185—2026 智能体注册载荷")
    print(f"  智能体  {args.name}")
    print(f"  身份码  {ident.identity_code}")
    print(f"  要素    {report['element_count']} 项  " +
          "  ".join(f"{k}={v}" for k, v in sorted(report["by_conformance"].items())))
    print()
    print("  能力描述（第 4 部分）：")
    cd = doc["capability_description"]["counts"]
    print(f"    模型接入点 {cd['model_endpoints']}   MCP 服务器 {cd['mcp_servers']}"
          f"   提示词 {cd['prompts']}   工具 {cd['tools']}")
    print()
    print("  合规认证登记：")
    for a in doc["compliance_attestations"]:
        print(f"    {a['kind']:<12}{a['digest'][:24]}…")
        print(f"    {'':<12}验证方式：{a['verify']}")
    print()
    if not report["identity_code_is_official"]:
        print("  [!] 身份码为本地推断生成，未使用标准规定的注册分配服务。")
        print("      提交登记前必须替换为由注册服务方分配的正式身份码。")
        print()
    if report["not_yet_verified"]:
        print(f"  [!] {len(report['not_yet_verified'])} 项要素未达「解读已明确」级：")
        for gp in report["not_yet_verified"]:
            print(f"      第{gp['part']}部分  {gp['part_name']:<26}{gp['conformance_zh']}")
        print()
        print(f"  {report['blocking_rule']}")
    else:
        print("  OK 全部要素均已在官方解读中明确")
    print()
    print(f"  输出  {outpath}")
    print()
    if args.strict and report["not_yet_verified"]:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "scan" and args.json:
        # JSON 模式下把证据包打到 stdout
        target = Path(args.path).resolve()
        cov = discover(target, max_files=args.max_files)
        findings = run(cov, enabled=set(args.only or []), disabled=set(args.skip or []))
        merkle = findings_merkle(findings)
        head = ""
        if not args.no_ledger:
            led = Ledger.for_root(target if target.is_dir() else target.parent)
            head = led.append(target.name or str(target), findings).hash
        pack = build_pack(findings, cov, ledger_head=head, merkle=merkle)
        print(pack_to_json(pack))
        return ScanResultCode(findings, args.fail_on)
    return args.func(args)


def ScanResultCode(findings, fail_on: str) -> int:
    sev = Severity[fail_on.upper()]
    return 1 if any(f.severity.rank <= sev.rank for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
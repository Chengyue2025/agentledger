# agentledger

**AI BOM · agent supply-chain provenance · tamper-evident accountability ledger for AI agents.**

> 智能体的"证据层"：机器出证据，人签字。零依赖、可离线、可出示给审计。

AI agents are moving from demos into production — but somebody has to answer the auditor's
question: *which agent did what, with which tools, trained on what, approved by whom?*

Today 79% of companies use agents, yet only ~2% run them at scale (PwC, 2026). The blocker is
not model quality — it is governance, audit trails and supply-chain provenance. agentledger is a
scanner that turns an agent repository into a **verifiable evidence pack**.

- **24 detection rules across 5 attack surfaces**: MCP server supply chain · model integration ·
  prompts & skills · dependencies & execution · governance completeness
- **15 regulatory obligations mapped** (CN ×7, EU ×5, ISO ×2, NIST ×1), each with clause quotes
  and a rule → obligation traceability table
- **Tamper-evident ledger**: append-only JSONL chain + Merkle root over findings + HMAC
  attestation — a modified report is detectable
- **Evidence pack**: JSON (machine) + Markdown (human/signature), designed for auditors
- **Zero third-party dependencies**: a compliance tool must not have a supply chain of its own
- **Offline & reproducible**: same input → same findings → same Merkle root

---

## Quick start

```console
$ pip install .            # or: git clone && pip install .
$ aledger scan ./my-agent
$ aledger verify           # check ledger chain integrity
$ aledger rules            # rule catalog + obligation mapping
```

Requires Python ≥ 3.11. Nothing else — no network access needed at runtime.

Example (against the deliberately-vulnerable fixture):

```text
  agentledger/0.1.0
  目标  .\fixtures\vulnerable
  覆盖  扫描 4 文件 / AI 攻击面 3 个 / 排除 0 个

  ┌─ 发现项 ─────────────────────────────────
  │ ■ CRITICAL严重    6  ■■■■■■
  │ ▲ HIGH    高危   15  ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲
  │ ◆ MEDIUM  中危    4  ◆◆◆◆
  │ ○ LOW     低危    0
  │ · INFO    提示    0
  └──────────────────────────────────────────

  主要问题：
    ■ [MCP002] 运行时自动安装未固定的软件包
        .mcp.json:4
    ...

  Merkle 根  4f53cda18e7ac3f13b18ad4a09f03d75…
  账本链头   9a10cc7d31d1d8a0e447e4f2b4104…
  人工签署   未签署（机器不能承担责任）

  证据包     .agentledger\pack-20261013T….md
             .agentledger\pack-20261013T….json
```

Exit code is CI-friendly: `0` clean, `1` findings at/above `--fail-on` (default `HIGH`),
`2` usage error. Use it as a merge gate:

```yaml
- run: aledger scan . --fail-on HIGH   # fails the build on critical agent-supply-chain issues
```

## Commands

| Command | Purpose |
|---|---|
| `aledger scan <path>` | Scan a directory/file, write evidence pack, append to ledger |
| `aledger verify [path]` | Verify the ledger hash chain & detect tampering |
| `aledger history [path]` | Show scan history (sequence, time, findings, chain head) |
| `aledger rules [--json]` | Rule catalog with obligation mapping (24 rules, 15 obligations) |
| `aledger init-key [path]` | Generate an HMAC attestation key for sign-off |

Key scan options: `--only/--skip` (rule filter), `--fail-on` (severity gate), `--key/--attester`
(HMAC sign-off), `--no-ledger`, `--json`, `-o/--out` (evidence pack directory).

## Rule catalog (summary)

| Family | ID prefix | Count | Examples |
|---|---|---|---|
| MCP server supply chain | `MCP` | 7 | unpinned versions, runtime auto-install (`npx -y`), tool poisoning, plaintext credentials, over-broad permissions, non-HTTPS transports, missing integrity/provenance |
| Model integration | `MDL` | 4 | filing/registration checks, hardcoded API keys, floating aliases (`*-latest`), system-prompt injection |
| Prompts & skills | `PRM` | 5 | explicit injection, injection hidden in comments, zero-width characters, base64 payloads, missing anthropomorphism disclosure |
| Dependencies & execution | `DEP` | 4 | hardcoded secrets, `eval`/`shell=True` sinks, unescaped SQL/path construction, unpinned deps |
| Governance | `AGT` | 4 | missing governance declaration, high-risk actions without approval gates, no sandbox declaration, missing project-level governance docs |

Every rule maps to one or more regulatory obligations; `aledger rules --json` exports the full
traceability table (machine-readable, for your GRC tooling).

## Why an evidence pack, not another dashboard

Auditors, procurement and regulators do not want a dashboard — they want a **reproducible
artifact**: what was scanned, what was found, which obligation each finding triggers, a Merkle
root so the report cannot be quietly edited, and a human signature line. agentledger produces
exactly that, in JSON for machines and Markdown for people.

The ledger principle: **machines produce evidence, humans take responsibility.**

## Development

```console
$ py -m unittest discover -s tests     # or: python -m unittest discover -s tests
$ aledger scan fixtures/clean       # regression corpus: expect 0 findings
$ aledger scan fixtures/vulnerable  # regression corpus: expect 25 findings, exit 1
```

`fixtures/` is a curated regression corpus (a governance-clean baseline and a
systematically-vulnerable agent project). Rule changes must keep clean = 0 and must not
lose known findings in vulnerable.

## 中文

**agentledger：智能体的 AI BOM、供应链溯源与防篡改责任留痕。**

- 24 条规则覆盖 5 大攻击面（MCP 供应链 / 模型接入 / 提示词技能 / 依赖执行 / 治理完备性），24/24 全部真实实现；
- 15 项监管义务映射（中国 7 / 欧盟 5 / ISO 2 / NIST 1），附条文引文与规则追溯表；
- 链式账本 + Merkle 根 + HMAC 签署：证据可验真、可追责、可直接出示给审计；
- 零第三方依赖、完全离线可复现——合规工具自己不能有供应链尾巴；
- 退出码即门禁：`--fail-on HIGH` 直接当 CI 合并条件用。

设计原则：**可审计优先于智能；机器出证据，人签字。**

## License

Apache-2.0 — see [LICENSE](LICENSE).

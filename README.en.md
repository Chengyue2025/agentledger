# agentledger

**AI BOM · Agent supply-chain provenance · Tamper-evident accountability ledger**

> Machines produce the **evidence**. Humans **sign it and answer for it**.
> That is the end of the automation road — and the one link in a compliance
> chain that cannot be removed.

Zero runtime dependencies · Single-file runnable · Fully offline ·
Reproducible results · Falsifiable evidence

---

## The problem

Since April 2026, China's "清朗·整治AI应用乱象" campaign has made
*應備未備 / 應登未登* (registered-but-should-be-filed, and vice-versa) its
first-phase priority target — **14,000+ non-compliant AI products were
removed** in the opening stage alone.

In May 2026, CAC, NDRC and MIIT jointly issued
《智能体规范应用与创新发展实施意见》, Article 11–12:

> …strengthen the supply of professional services for agent risk monitoring,
> evaluation, consulting and **certification**… conduct **third-party assessment
> of agent functionality, performance, quality and compliance**…

**Lawyers can answer "is this legal." They cannot answer:**

> Which models does your agent call? Which MCP servers? Which plugins?
> Has the supply chain been poisoned? **Who approved it sending that email?**

Those are precisely the questions that filing, campaign self-inspection, and
**EU AI Act Article 12** require you to answer.

agentledger produces that layer of **technical evidence**.

## What it does

| Capability | Description |
|---|---|
| **AI BOM** | Enumerates model endpoints, MCP servers, prompts/skills, agent manifests, dependency execution paths |
| **Supply-chain provenance** | Detects tool poisoning, runtime package fetch, version float, missing integrity attestation |
| **Covert-channel detection** | Injection hidden in HTML comments, base64 payloads, zero-width / bidi control characters |
| **Execution-path analysis** | Model/tool output flowing into `eval` / shell / SQL / file paths |
| **Governance completeness** | Human oversight, action boundaries, data processing, approval gates, audit logging |
| **Regulatory mapping** | Every finding maps to a specific statute/clause → produces a remediation backlog |
| **Tamper-evident ledger** | Hash-chained records; modifying or deleting one entry is detected |
| **Coverage disclosure** | Records what was **not** scanned — bounding the applicability of the conclusion |

## Install & run

Zero dependencies. Python 3.11+:

```bash
git clone <this-repo> && cd agentledger

# run directly — no install needed
python -m agentledger scan /path/to/your/project

# or install as a command
python -m pip install -e .
aledger scan /path/to/your/project
```

## Commands

```bash
aledger scan <path>     Scan and emit an evidence pack (JSON + Markdown)
aledger verify          Verify ledger chain integrity
aledger history         Show the accountability trail
aledger rules           List rules and their regulatory mapping
aledger init-key        Generate an attestation key
```

Options worth knowing:

```bash
aledger scan . --fail-on CRITICAL      # gate CI on critical findings only
aledger scan . --only MCP PRM          # run a subset of rules
aledger scan . --skip INFO             # drop noise
aledger scan . --sarif                 # emit SARIF 2.1.0 for Code Scanning
aledger scan . --json                  # machine-readable to stdout
aledger scan . --key ./key --attester "Jane Doe (CTO)"
```

### Drop-in Code Scanning

```yaml
# .github/workflows/agent-scan.yml
- uses: actions/checkout@v5
- run: pipx run agentledger scan . --sarif -o .agentledger
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: .agentledger/scan-*.sarif
```

SARIF is an OASIS standard, so the same file feeds GitLab, Azure DevOps,
Jenkins SAST panels, and internal Jira/Feishu/DingTalk code-quality plugins.

## Rule catalogue

| Prefix | Surface | Representative rules |
|---|---|---|
| `MCP` | MCP server supply chain | `MCP002` runtime package fetch · `MCP003` tool poisoning · `MCP005` over-broad scope |
| `MDL` | Model endpoints | `MDL001` filing status · `MDL003` floating alias · `MDL002` plaintext key |
| `PRM` | Prompts & skills | `PRM002` injection in comments · `PRM003` zero-width chars · `PRM004` base64 payload |
| `DEP` | Dependencies & execution | `DEP002` dangerous sink · `DEP003` unsanitized output · `DEP004` unpinned versions |
| `AGT` | Agent governance | `AGT002` high-risk action without gate · `AGT001` missing declarations |

Run `aledger rules` for the full catalogue and obligation mapping.

## Regulatory mapping

| ID | Basis |
|---|---|
| `CN-IMPL-08/10/11/12` | 《智能体规范应用与创新发展实施意见》 (CAC/NDRC/MIIT, 2026-05-08) |
| `CN-FILING` | GenAI filing & registration regime + 清朗 enforcement practice |
| `CN-ANTHRO` | 《人工智能拟人化互动服务管理暂行办法》 (effective 2026-07-15) |
| `CN-DATA` | PIPL impact assessment / cross-border data assessment |
| `EU-ART12/14/15/17/26` | EU AI Act (Reg. 2024/1689) |
| `ISO42001-A8/A9` | ISO/IEC 42001:2023 |
| `NIST-MEASURE` | NIST AI RMF 1.0 |

## Evidence pack structure

1. **Integrity anchors** — Merkle root, ledger head, attestation
2. **Scan coverage** — what was scanned / **what was excluded** (bounds the conclusion)
3. **Summary** — by severity, attack surface, risk category
4. **Regulatory obligations touched** — statute → unsatisfied-item backlog
5. **Findings** — evidence, rationale, remediation, mapped obligations
6. **Review & sign-off** — technical / compliance / **accountable approver**

## On human attestation

The tool computes Merkle roots and ledger heads. Those prove
**"the evidence was not altered."** They do **not** prove **"who reviewed it."**

`aledger attest` uses HMAC-SHA256 detached signatures. Note this is a
**symmetric** algorithm: it guarantees integrity, but anyone holding the same
key produces the same signature — so it is **not** a non-repudiable
electronic signature.

Where a regulator needs *"organisation X confirmed this evidence at time T"*,
issue an asymmetric signature via an external CA/KMS and attach it to the pack.

That gap is deliberate. It marks exactly where automation stops and
accountability begins.

## Tests

```bash
python -m unittest discover -s tests -v
```

39 cases across six classes:

- **Detection** — every known injection point must be caught
- **No false positives** — a compliant baseline must stay silent
- **Ledger tamper** — modified or deleted entries must be detected
- **Reproducibility** — repeated scans must yield identical results
- **Encoding** — CJK files must not be misclassified as binary and skipped

## Known limits

- Static analysis; does not execute code. Dynamically loaded deps are invisible
- YAML is parsed shallowly (a consequence of the zero-dependency constraint)
- Model filing status is inferred from a public vendor list — **must be
  verified by hand** against the CAC's published filings
- Rules are deterministic heuristics, not ML. Chosen for explainability and
  reproducibility, at the cost of not catching novel injection styles
- **This produces technical evidence. It is not legal advice.**

## Design principles

1. **Zero runtime dependencies** — a compliance tool cannot itself carry a supply chain
2. **Auditability over cleverness** — a rule may be dumb, but it must explain *why* it fired
3. **Never hide the boundary** — exclusions must be disclosed or the evidence is void
4. **Reproducible** — same target, same version ⇒ same conclusion

## License

Apache-2.0

---

中文文档见 [README.md](README.md)。
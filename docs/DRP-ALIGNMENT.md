# IETF DRP 对齐说明（agentledger 0.2.0）

**对齐目标**：`draft-nelson-agent-delegation-receipts`（Delegation Receipt Protocol for AI Agent Authorization）
**草案快照**：修订 -12，读取于 2026-10-13（草案持续演进，字段以 IETF Datatracker 最新版为准）
**本实现定位**：该草案的**第一个独立实现** —— 草案 §12 实施状态中已知的唯一实现是作者自家的
authproof-sdk / authproof-cloud（prototype 级、托管服务形态）。

[草案原文](https://datatracker.ietf.org/doc/draft-nelson-agent-delegation-receipts/) ·
[本仓库收据模块](../agentledger/receipt.py) ·
[配套 JSON Schema](../schemas/drp-receipt.schema.json)

---

## 1. 为什么是一个"离线子集"

草案的完整验证链包含 15 项检查，其中多项依赖**运行时环境**（TEE 远程证明、会话信任分、
RFC 3161 时间戳源、执行图哈希）。这些属于在线网关/策略引擎的职责，不属于一个
可离线执行、可放进 CI 的命令行工具。

我们把可离线独立完成的检查定义为 **Agentledger DRP Profile**：

| # | 草案检查 | 状态 | 拒绝码（草案 §6.5 对齐） |
|---|---|---|---|
| 1 | 撤销 | ✅ 本地撤销表 | `RECEIPT_REVOKED` / `REVOCATION_CHECK_REQUIRED` |
| 2 | 签名 | ✅ Ed25519（纯标准库实现） | `INVALID_SIGNATURE` |
| 3 | 时间窗 | ✅ 本地时钟 + 300s 容差 | `RECEIPT_EXPIRED` / `RECEIPT_NOT_YET_VALID` |
| 4 | 范围（默认拒绝） | ✅ deniedActions 优先 | `ACTION_NOT_IN_SCOPE` / `ACTION_EXPLICITLY_DENIED` |
| 5 | 边界硬限制 | ✅ 含智能默认 | `ACTION_EXPLICITLY_DENIED` |
| 6 | 执行图哈希 | ⏭ 运行时职责 | — |
| 7 | 运营方指令哈希 | ✅ | `OPERATOR_INSTRUCTIONS_MISMATCH` |
| 8 | TEE 模型状态 | ⏭ 运行时职责 | — |
| 9 | 会话信任分 | ⏭ 运行时职责 | — |
| 10 | 重放 | ⏭ 时间窗 + 撤销表覆盖主要场景 | — |
| 11 | 工具模式哈希 | ✅ | `TOOL_SCHEMA_DRIFT` |
| 12 | 工具输出哈希 | ⏭ 运行时职责 | — |
| 13 | 可信指令来源 | ✅ | `UNTRUSTED_INSTRUCTION_SOURCE` |
| 14 | 父收据包含/收窄 | ✅ 含编排者绑定签名 | `PARENT_SCOPE_VIOLATION` / `SCOPE_NOT_STRICT_SUBSET` |
| 15 | 权威状态漂移 | ⏭ 运行时职责 | — |

> "⏭" 不是忽略，而是**职责边界声明**：草案把重放/会话/执行图检查留给在线决策点；
> 本实现把这些动作留痕（`action-decision` 日志）供事后审计，检查本身交给运行时门控。

**扩展码**：`LEDGER_INTEGRITY_FAILURE` —— 本地收据账本链校验失败时使用。
草案拒绝码注册表策略为 Specification Required，扩展码在本文档登记；语义为
"证据根不可信，一切裁决按 DENY 处理"，安全回退仍为 `NO_OP_WITH_LOG`。

---

## 2. 字段映射

| 草案字段 | 本实现 | 说明 |
|---|---|---|
| `schemaVersion` | `"1.0"` | 与草案附录 A 一致 |
| `scope.allowedActions` / `deniedActions` | ✅ | `{operation, resource}` 描述符，资源支持 `*` / `/*` 通配 |
| `boundaries` | ✅ 智能默认 | 草案要求非空；若收据显式允许了 write/delete/execute，自动省略对应默认边界（否则自相矛盾）——这是对草案 §4.1 推荐默认的**实现层细化** |
| `timeWindow.notBefore/notAfter` | ✅ | ISO 8601 UTC |
| `operatorInstructions` + `operatorInstructionsHash` | ✅ | `sha256:` 前缀，NFC 归一后哈希 |
| `receiptId` | ✅ | `rec_` + sha256hex(规范体)，签发时先算 ID 再签名 |
| `canonicalPayload` | ✅ | RFC 8785 风格：键排序、无空白、NFC、UTF-8 |
| `publicKey` | ✅ JWK `OKP/Ed25519` | 草案允许 ECDSA P-256；本 Profile 仅收 Ed25519（零依赖红线的取舍） |
| `signature` | ✅ | 覆盖「含 receiptId、不含 canonicalPayload 与 signature」的规范体 |
| `trustedSources` / `toolSchemaHash` / `revocationRequired` | ✅ | 全部在签名体内，外层剥改无效 |
| `parentReceiptId` + `orchestratorSignature` | ✅ | 绑定串 `orchestrator-delegation:{parent}:{child}`，**以子收据公钥验证** |
| `metadata.x-time-source` | `local-unverified` | 草案 §5.3：无 TSA 时以本地时间戳并标记"未验证"——离线签名的诚实标注 |
| 撤销记录 | ✅ | `{receiptId, revokedAt, publicKey, signature}`，追加进收据账本（草案 §10.6） |
| 追加式日志 | ✅ `receipts.jsonl` | 草案 §5 append-only log 的本地哈希链形态：`seq/ts/kind/body/prev/hash` |

## 3. 撤销语义（与草案的差异点）

草案假设有在线撤销服务；本实现把**本地账本当作撤销表**：

- `revocationRequired: true` 且未提供账本 → 按草案 §6.6 硬拒 `REVOCATION_CHECK_REQUIRED`；
- 提供账本 → 撤销记录离线可查（账本链自身校验失败则 `LEDGER_INTEGRITY_FAILURE`）；
- **子收据不级联失效**（草案 §10.4 同样要求逐份撤销），CLI 在 revoke 时显式提示。

## 4. 对草案的互操作观察（可反馈 IETF 的 review comment 素材）

读取 -12 版时发现的两处规格歧义，本实现的解释已记录在代码注释中，拟整理为
对 draft-nelson 的 review comment（草案为个人提交，欢迎实现者反馈）：

1. **编排者绑定签名的验证密钥**：§10.1 只说"orchestrator's key"，未指明验证方从哪取该
   公钥（父收据的 `publicKey`？子收据的？还是独立注册表？）。本实现取**子收据自身公钥**
   （即签发子收据的编排者就是子收据签名方），并同时校验父收据存在于受信账本。
2. **`receiptId` 与 `canonicalPayload` 的计算顺序**：§4.2 同时定义两者各自覆盖"除自身
   外的字段"，存在循环引用；实现层必须规定顺序（本实现：ID → 规范字节 → payload → 签名）。

## 5. 与既有实现的差异

| | authproof-cloud（草案作者） | agentledger 本实现 |
|---|---|---|
| 形态 | 托管 SaaS + SDK | 离线 CLI，纯标准库（零依赖） |
| 签名 | Ed25519 / ECDSA P-256 | Ed25519（纯 Python，含 RFC 8032 官方向量测试） |
| 撤销 | 云服务撤销表 | 本地哈希链账本（可离线验证） |
| 时间戳 | RFC 3161 TSA | 本地时钟 + 容差，诚实标记 `local-unverified` |
| 证据整合 | 单一职责 | 与 AI BOM 扫描共用同一信任根：授权时证据（收据）+ 事后证据（扫描账本） |
| CI | — | Linux/macOS/Windows × Python 3.11–3.13 全绿 |

## 6. 草案版本策略

- 本实现锁定的字段/拒绝码以 **-12 版**为基准（2026-10-13 读取）；
- 草案每次修订后运行 `tests/test_receipt.py` 回归，字段漂移在 release notes 中标注；
- 若字段更名/语义变化，`schemaVersion` 不变时以本对齐文档的映射表为准。

---

*agentledger 是合规证据工具：本对齐文档描述的是实现范围，不构成对草案未来演进的承诺。*

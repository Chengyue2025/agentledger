# IETF DRP 对齐说明（agentledger 0.3.0）

**对齐目标**：`draft-nelson-agent-delegation-receipts`（Agent Delegation Receipt）
**草案快照**：修订 **-13**，读取于 2026-10-14（草案持续演进，字段以 IETF Datatracker 最新版为准）
**本实现定位**：该草案的**第一个独立实现**，且已被写入草案正文——

> *"-13 (October 2026) incorporates feedback from an independent Python implementation
> of the draft (agentledger, [AGENTLEDGER]), filed as [INTEROP-15]."*
> —— 草案附录 B（-12→-13 变更记录）

三处实现反馈全部被采纳并落进 -13 规范：编排者验证密钥钉定到子收据签名公钥（§4.4）、
签发计算顺序编号化（§6.6）、默认边界与显式允许的取舍指引（§4.5）。

[草案原文](https://datatracker.ietf.org/doc/draft-nelson-agent-delegation-receipts/) ·
[反馈线程（authproof-sdk#15）](https://github.com/Commonguy25/authproof-sdk/issues/15) ·
[互操作语料库](https://github.com/receipt-commons/receipt-interop) ·
[引擎源码](../agentledger/drp.py)

---

## 1. 一致性状态（-13）

| 草案章节 | 要求 | 状态 | 备注 |
|---|---|---|---|
| §4.1 | 顶层字段集**封闭**，未知字段拒绝 | ✅ | `UNKNOWN_BODY_FIELD`（含字段名） |
| §4.2 | 必填8字段 + 类型校验 | ✅ | `FIELD_MISSING` / `FIELD_INVALID` |
| §4.2 | `instructionsHash` 有损规范化 | ✅ | 规则逐步实现，并以草案/语料库**双命中向量**钉死 |
| §4.2 | `signerPublicKey` 恰含 kty/crv/x/y、无私料、曲线校验 | ✅ | 拒绝带 `d` 的 JWK |
| §4.4 | `orchestratorSignature` 以**子收据 signerPublicKey** 验证 | ✅ | 绑定串 `orchestrator-delegation:<parent>:<child>` 逐字节比对 |
| §5 | JCS（RFC 8785）规范化 | ✅ | UTF-16 码元排序、最短往返数字、RFC 8785 转义 |
| §6.1-6.3 | JWS Compact；ES256 为 raw R\|\|S 64字节，**DER 拒绝** | ✅ | 按构造拒绝（长度不符即拒） |
| §6.4 | 分离形式（RFC 7797，`b64:false` + `crit`） | ✅ | 载荷带外提供且必须逐字节一致 |
| §6.5 | **ES256 REQUIRED**；EdDSA OPTIONAL；`none` PROHIBITED | ✅ | ES256/P-256 纯 Python 实现（RFC 6979 随机数） |
| §6.6 | 签发四步顺序 + `receiptId` = sha256hex(ASCII JWS) | ✅ | 无循环依赖 |
| §8.1-8.3 | 结构化作用域：denied 优先、通配、约束、默认拒绝 | ✅ | |
| §8.5 | 衰减 = 字面 `operation::resource` 严格真子集 | ✅ | 签发前强制，验证时复检（不展开通配） |
| §8.6 | 深度上限（默认3，root=0），超限 `CHAIN_DEPTH_EXCEEDED` | ✅ | |
| §8.7 | 子收据签发序列（解析父作用域→校验→签名→绑定） | ✅ | 违规**在签名前**拒绝 |
| §9.1-9.3 | 撤销记录（签名先验后入库）、永久性、级联 | ✅ | `REVOKED` / `ANCESTOR_REVOKED` |
| §9.4 | 离线失败关闭 | ✅ | `REVOCATION_CHECK_REQUIRED` / `ANCESTOR_REVOCATION_CHECK_REQUIRED` |
| §9.5 | 一次性收据无持久消费存储则拒绝 | ✅ | `CONSUMPTION_STORE_REQUIRED` / `RECEIPT_ALREADY_CONSUMED` |
| §10 | 预执行门检查序列（签名→撤销→时间窗→作用域→指令→…→父收据包含） | ✅* | 按序短路、失败即停；依赖运行时环境的检查（TEE/会话分/执行图/权威状态）属于运行时门控职责，见 §4 |
| §7 | COSE_Sign1 profile | ⏭ | 未实现（JWS 为首选 profile；受约束环境可用时再补） |
| §6.5 | ES384/ES512/RS256/PS256（OPTIONAL） | ⏭ | 未实现，按需补充 |

### 互操作语料库（规范性结果）

`tests/fixtures/interop-corpus.json`（同款随包分发于 `agentledger/data/`，命令
`aledger receipt corpus` 可直接复跑）来自
[receipt-commons/receipt-interop](https://github.com/receipt-commons/receipt-interop)——
该语料库即作者为本实现（issue #15 线程）发布的7案例交换语料：

```
[PASS] interop-01-basic-valid             valid exp=True  got=True
[PASS] interop-02-structured-scope-valid  valid exp=True  got=True
[PASS] interop-03-expired                 valid exp=False got=False errors=['TIME_WINDOW']
[PASS] interop-04-scope-violation         valid exp=False got=False errors=['CHAIN_HOP_1_SCOPE_ATTENUATION_VIOLATED']
[PASS] interop-05-revocation-required     valid exp=False got=False errors=['REVOCATION_CHECK_REQUIRED']
[PASS] interop-06-chain-valid-2hop        valid exp=True  got=True
[PASS] interop-07-chain-valid-3hop        valid exp=True  got=True
conformance: 7/7 (expected.valid is normative)
```

对照口径（语料库 README 原文）：`expected.valid` 为**规范性**比较，`errors/warnings`
是参考实现的诊断输出（信息性，"use your own codes"）。本实现的错误码在三个负例上与
参考实现**逐字一致**，并被测试钉住。

### 金标准向量（草案附录 A）

字节级往返全部通过（`tests/test_jcs.py`、`test_p256.py`、`test_jws.py`）：

- 示例私钥 `d` → 公开 JWK `x/y` 派生一致；
- A.1 演示 JSON → JCS 规范化 = **A.2 字节串逐字节相等**；
- A.3 金标准 JWS 验签通过，载荷 = A.2 字节串；
- `receiptId =061cef91d98ef21ad9ba2550f1d71b8e16717c97e008282d6a10523a7a838199` 复算一致；
- 附录 A 指令哈希 `c730de75…4fb` 复算一致（有损规范化实证钉死）。

---

## 2. Profile 边界（离线 CLI 的职责声明）

草案 §10 是"实现档位"而非第二标准：语义必须实现，检查管线可以有差异。
依赖运行时环境的检查（执行图哈希、TEE 模型状态、会话信任分、工具输出绑定、
权威状态漂移）由运行时门控承担；本实现把动作留痕到追加式账本供事后审计。
时间源为本地时钟（`options.at` / `--at` 可指定，语料库验证即以案例自带时间为准）。

## 3. 错误码登记（本实现）

核心码：`UNKNOWN_BODY_FIELD`、`FIELD_MISSING`、`FIELD_INVALID`、`JWS_INVALID`、
`TIME_WINDOW`、`REVOKED`、`REVOCATION_CHECK_REQUIRED`、`ANCESTOR_REVOKED`、
`ANCESTOR_REVOCATION_CHECK_REQUIRED`、`SCOPE_ACTION_DENIED`、
`SCOPE_ACTION_NO_SCHEMA`、`INSTRUCTIONS_MISMATCH`、
`UNTRUSTED_INSTRUCTION_SOURCE`、`CONSUMPTION_STORE_REQUIRED`、
`RECEIPT_ALREADY_CONSUMED`、`CHAIN_DEPTH_EXCEEDED`、
`CHAIN_HOP_<n>_PARENT_RECEIPT_MISMATCH`、
`CHAIN_HOP_<n>_ORCHESTRATOR_SIG_INVALID`、
`CHAIN_HOP_<n>_WINDOW_NOT_CONTAINED`、
`CHAIN_HOP_<n>_SCOPE_ATTENUATION_VIOLATED`。

## 4. 与草案官方实现的差异

| | authproof（草案作者） | agentledger 本实现 |
|---|---|---|
| 形态 | 托管 SaaS + SDK | 离线 CLI，纯标准库（零依赖） |
| 算法 | ES256 | ES256（必需）+ EdDSA（可选），均为纯 Python |
| 撤销 | 云撤销表 | 本地签名记录注册表（JSONL，先验签名后入库） |
| 语料库 | 生成方 | 消费方：7/7 有效性命中，测试钉住 |
| 时间戳 | RFC 3161 TSA | 本地时钟，可显式指定 `--at` |
| 证据整合 | 单一职责 | 与 AI BOM 扫描共用同一信任根（授权时证据 + 事后扫描证据） |

## 5. 草案版本策略

- 基线：**-13**（2026-10-14 读取）；金标准与语料库 fixture 随仓库固化，
  草案修订后重跑 `tests/test_jcs.py`、`tests/test_interop_corpus.py` 回归；
- 字段集变化会使旧收据无法通过封闭字段校验——这是草案语义（拒绝优于忽略），
  版本迁移在 release notes 中标注；
- 对草案的观察与反馈走作者仓库 issue（authproof-sdk#15），历史已归档于
  `deliverables/ietf-drp-review-comment.md`。

---

*agentledger 是合规证据工具：本对齐文档描述的是实现范围，不构成对草案未来演进的承诺。*

# IETF 评论稿：AAT + 委托收据 + 审计记录三草案（P-02 更新版）

> 用途：发给 IETF 邮件列表 + datatracker comment 的成稿。
> 更新（2026-10-14）：修正草案名——"agent-audit-trail" 实为
> **`draft-sharif-agent-audit-trail-06`**（v06，2027-04-02 到期）；
> 新增该草案评论（我们的 DSH 插件即其参考实现）；补 `draft-gilda-wimse-agent-audit-record`。
> 发送身份 = 人类物理层（你）。本文由 AI 起草，事实全部可核。

---

## 一、致 draft-sharif-agent-audit-trail（新增，最重要）

**发件人**：AgentOS（DSH 审计插件实现方）
**主题**：Implementation feedback — DSH 插件参考实现 + 三条提案

### 1. 参考实现正在构建

我们正在 DeepSeek Harness（MIT，事件溯源架构）上构建
`dsh-agent-audit-trail` 插件，作为本草案的开放参考实现：

- 挂 `session/event` + `tools/pre-execute` + `agent/pre-step`（DSH 事件流，已验证可接）
- 每条 `tool_call`/`tool_response`/`decision` 序列化为 AAT 记录，
  **逐条 SHA-256 哈希并链到前一条**（JCS/RFC 8785）
- 暴露 `attest(sessionId)` → 完整审计轨迹 + 根哈希
- 一致性测试套件（字段约束 + 哈希链不变量 + pre_execution 强制 + 尾部完整性）

选择 DSH 的原因：它是事件溯源架构（"model-visible means logged"），
`session/event` 流天然就是审计原料——插件只做序列化与链式哈希，
不需要特权核心访问，回放一致（可审计）。

### 2. 三条提案

**提案 A：`cost_estimate` 字段应规范化（§3.2）**
AAT 的 `cost_estimate` 是自由 object。我们实测（DSH 成本归因插件，
DeepSeek 费率卡）：缓存命中/未命中/写入的 **50 倍价差**使 cost 成为
审计的核心维度。建议 `cost_estimate` 增加可选结构化子字段：
`{amount, currency, cache_hit, cache_miss, cache_write, output_tokens}`，
使成本可跨实现对比。

**提案 B：`deny_reasons` 应包含"验证器拒绝"类别（§3.2）**
当前 9 个拒绝码都是授权/策略类。我们实测：插件清单审计（1000+ 插件
零审核的 DSH 生态）产生的拒绝是**验证器拒绝**——"该插件未声明权限范围/
未固定版本/索取凭据无审批"。建议增加：
`PERMISSION_SCOPE_UNDERCLARED`、`VERSION_UNPINNED`、
`CREDENTIAL_ACCESS_WITHOUT_GATE`、`EGRESS_UNCONTROLLED`、
`EXECUTION_WITHOUT_SANDBOX`。这些是供应链审计的拒绝码，
与授权拒绝码互补。

**提案 C：§11 监管映射应增加中国维度**
当前映射覆盖 EU AI Act/SOC2/ISO/PCI。中国《智能体规范应用与
创新发展实施意见》（2026-05）第 8/10/11/12 条与 AAT 的
供应链/人机协同/分类分级/合规服务条款**逐条对应**。建议 §11 增加
§11.7 China 映射表——这是大厂不会做的切片，也是 AAT 被中国采购方
采用的前提。

### 3. 一个互操作观察

§6.4 的 Merkle batch anchoring 与我们的 agentledger 账本（append-only
JSONL + Merkle 根 + HMAC）**形状一致**。建议明确：外部 Merkle 锚
（如 agentledger 的账本根）可作为 AAT 链的**外部时间锚**，
与 `external_timestamp`（TSA）互补——TSA 贵且慢，哈希链锚便宜且即时。

---

## 二、致 draft-nelson-agent-delegation-receipts（12 月到期，先发）

**主题**：Implementation feedback — first independent implementation + 两条提案

### 1. 独立实现已完成

我们是该草案 **-13 版**（读取日 2026-10-14）的**第一个独立实现**
（Implementation Status 此前仅列作者自家的 authproof-cloud，prototype 级；
-13 的实施状态章节已注明采纳了本实现的反馈，编号 INTEROP-15）。
实现为 agentledger v0.4.0 `receipt` 命令组：签发/子签发/验证/链验证/
撤销/互操作语料九个子命令，零依赖、纯标准库、离线优先。
签名支持 **ES256（P-256）+ JWS Compact + JCS（RFC 8785）**，
并保留 **Ed25519（RFC 8032 官方测试向量）** 兼容选项。

对齐情况：

| 草案检查（§6.4） | 覆盖 | 备注 |
|---|---|---|
| 1 撤销 | ✅ | REVOCATION_CHECK_REQUIRED |
| 2 签名 | ✅ | INVALID_SIGNATURE |
| 3 时间窗 | ✅ | 容差 300s（§5.3 推荐值） |
| 4 范围（默认拒绝） | ✅ | ACTION_NOT_IN_SCOPE / EXPLICITLY_DENIED |
| 5 边界 | ✅ | |
| 7 指令哈希 | ✅ | OPERATOR_INSTRUCTIONS_MISMATCH |
| 11 工具模式哈希 | ✅ | TOOL_SCHEMA_DRIFT |
| 13 指令来源 | ✅ | UNTRUSTED_INSTRUCTION_SOURCE |
| 14 父收据包含 | ✅ | 深度 ≤3（§10.3 保守取） |
| 6/8/9/10/12/15 | ✗ | 运行时时钟类，明确划出 CLI 职责边界 |

建议草案显式区分"离线可验证"与"运行时方可验证"两组检查，
避免实现者误判覆盖度。

### 2. 两条提案

**提案 A：工具模式哈希应覆盖权限范围声明（§11）**
投毒面在**权限声明与 schema 的漂移**：一个 skill 升级后从只读变成
可读写凭据。建议 `toolSchemaHash` 扩展为
`toolSchema + permissionScope` 联合哈希，使"模式漂移"包含"权限漂移"。

**提案 B：跨 agent 的 skill 导入应携带来源回执**
三个实证市场（ClawHub 44K skills 7.6% 恶意、DSH 1000+ 插件零审核、
Grok Bot 3954 个 live share）的共同攻击面是"导入即授权"。建议 §4 增加
`skillProvenance` 字段（发布者签名 + 内容摘要），与 AAT 的
`content_fingerprint` 互操作。

### 3. 一个互操作观察

§5.4 的 `NO_OP_WITH_LOG`（拒绝也要留痕）是**最关键的一条**——
它把"被拒绝的尝试"从噪音变成证据。建议在草案示例中突出这一点。

---

## 三、致 draft-gilda-wimse-agent-audit-record（监控，简版）

**主题**：与 AAT 的关系建议

该草案（v01，2027-03 到期）定义"授权决策的审计记录"，与 AAT 的
`decision` action_type 重叠。建议两草案明确分工或合并：
AAT 管"行动日志"，本草案管"授权语义"——若合并，我们的插件与
agentledger 收据（其一）可同时服务于两者。

---

## 发送清单（物理层执行）

1. 三封评论分开发（不同草案不同列表）
2. 邮件列表地址从 datatracker 草案页 "Email discussions" 获取
3. 发送后把 Message-ID 记入 `intel/` 当日报告 → 标准占位证据链
4. draft-sharif-agent-audit-trail 2027-04-02 到期，若出新版本重新对撞
   （harvest 环已监控）
5. **优先级**：AAT 评论 > 委托收据评论（12 月到期）> 审计记录评论

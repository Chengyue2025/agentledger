# Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。
格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [Unreleased]

## [0.3.0] - 2026-10-14

新增**插件/分享包导入前审计**能力——面向 2026-10 实调确认的"三市场验证真空"
（ClawHub 44K skills 静扫已输 / dsh 1000+ 插件零审核 / Grok Bot 3954 个 live share
零审核）。核心命题：**导入即授权，导入前无人验证**。

### 新增

**`aledger audit-share <path>` 命令**（P-05 验证器 CLI 形态）
- 单包模式：输出 BLOCK / CAUTION / CLEAR 裁决 + **信任分（0-100）**
- 批量模式：目录下每个候选包独立裁决，输出排名表（P-04 报告生成器输入）
- 证据包含逐包 findings + 信任分 + 覆盖度，可直接进 CI 门禁 / 导入审批单

**HRN 规则族（7 条）—— harness 插件与运行时**
- `HRN001` 插件清单未声明权限范围（最小权限）
- `HRN002` 插件版本未固定（运行时安装 / 浮动标签）
- `HRN003` 插件可访问凭据但无审批闸门（CRITICAL）
- `HRN004` 插件具有网络能力但无出口白名单控制
- `HRN005` 插件具备代码执行能力但未声明沙箱/隔离
- `HRN006` harness 运行时未声明轨迹/留痕能力（EU AI Act Art.12/26）
- `HRN007` IM 机器人权限档位全员放行且无白名单（dsh-im 类扫码接入）

**SHR 规则族（5 条）—— 分享包 / marketplace bot**
- `SHR001` 分享包内含明文凭据（CRITICAL）
- `SHR002` 分享包技能/例程中存在注入指令（含隐蔽容器，CRITICAL）
- `SHR003` 分享包含高风险自主动作但无审批闸门
- `SHR004` 分享包缺少来源证明（发布者/签名/摘要）
- `SHR005` 分享包索取共享计算机/会话访问但无隔离声明（对齐 DataCamp 实测）

**制品发现扩展**：`plugin.json` / `cordis.json` / `dsh.json` / `share.json` /
`bot.json` / `marketplace.json` / `routine.json` 等进入 AI 攻击面；
`plugins/` `shares/` `bots/` `routines/` `harness/` `.dsh/` 目录整体纳入。

**fixtures 演示样本**：`fixtures/vuln-share`（BLOCK，信任分 0）、
`fixtures/clean-share`（CLEAR，100）、`fixtures/vuln-plugin`、`fixtures/clean-plugin`。

### 说明
- HRN/SHR 两族对同一制品**不重复开火**：share 形态归 SHR，plugin 形态归 HRN
- 信任分权重：CRITICAL −40 / HIGH −20 / MEDIUM −5 / LOW −1，下限 0
- 规则总数 24 → 36；测试 39 → 225（v0.4.0 发布时为 251，见下）

## [0.4.0] - 2026-10-14

同日发布（0.3.0 的当天收尾版），补齐 0.3.0 定稿时已完成但未记录的三块工作。

### 新增

**委托收据升级到 ES256 / JCS / JWS（draft -13）**
- 密钥与签名从 Ed25519 迁到 **ES256（P-256）+ JWS Compact Serialization + JCS
  规范化**（对齐草案 -13 §4.4/§6.2），`--alg Ed25519` 兼容旧密钥
- `p256.py` / `jws.py` / `jcs.py` 三个零依赖纯 Python 模块（RFC 8785 JCS、
  RFC 7515 Compact Profile），与既有 Ed25519 实现同口径测试
- 子命令补齐 9 个：`keygen / issue / sub-issue / verify / chain / revoke /
  record-verify / show / corpus`
- `corpus`：**互操作语料**自测，锁定 -13 的表面积；草案 -13 的实施状态章节已注明
  采纳了本实现的反馈（INTEROP-15）

**`aledger gbz185 <path>` 命令**
- 导出 **GB/Z 185-2026《人工智能 智能体互联》** 注册载荷（含符合度自查），
  国标对接层 `gbz185.py`

**库级能力（测试已覆盖，CLI 尚未暴露——诚实标注）**
- `authority.py` —— 三级决策权限模型，对齐《智能体规范应用与创新发展
  实施意见》第 6 条原文
- `gate.py` —— 审批闸门：把 AGT002「高风险动作缺少审批闸门」从发现项变为
  已交付的修复件
- `fence.py` —— 行为范围围栏
- `runtime.py` —— 运行时行为留痕：让"可追溯"从口号变成可验证的记录
- `pipeline.py` —— 整合层：权限 + 闸门 + 留痕合成单一决策链

**演示语料 fixtures/**（CHANGELOG/README 承诺已久的四个样本，本次重建并校准）
- `fixtures/vuln-share`（BLOCK，信任分 0，命中 SHR001–005 全部五条）
- `fixtures/clean-share`（CLEAR，100）
- `fixtures/vuln-plugin`（BLOCK，0，命中 HRN002–006 五条）
- `fixtures/clean-plugin`（CLEAR，100）

### 修复

- **`receipt issue --schema/--metadata` 与 `--jws @file` 在带 UTF-8 BOM 的
  Windows 文本文件上崩溃**（记事本/PowerShell 默认写 BOM）。所有用户文件
  读取统一改为 `utf-8-sig`；新增 CLI 级回归测试
  `TestCliBomTolerance`（BOM schema + BOM 读回 + 越权拒绝全流程）。

### 说明
- 版本号从 0.3.0 直接进入 0.4.0：0.3.0 条目描述的 audit-share 与两规则族
  为同一代码状态，无行为变化；0.4.0 只追加记录上述已完成件
- 测试总数 225 → 251（14 个测试文件）；规则数仍为 36

## [0.2.0] - 2026-10-13

新增**委托收据（Delegation Receipt）**能力——对齐 IETF Internet-Draft
`draft-nelson-agent-delegation-receipts`（读取时 -12 版）的**第一个独立实现**
（草案实施状态中此前仅有作者自家的 authproof-cloud，prototype 级）。

### 新增

**`aledger receipt` 命令组**
- `keygen` —— Ed25519 密钥生成（私钥种子 + JWK 公钥）
- `issue` —— 签发委托收据：范围/拒绝/硬边界/时间窗/指令哈希/工具模式哈希/可信来源，
  追加进哈希链式收据账本；`--parent` 签发子收据（编排者绑定签名 + 收窄规则）
- `verify` —— 离线验证并裁决动作，对齐草案 §6.4 检查子集与 §6.5 拒绝码，
  DENY 按草案 §6.3 回退 `NO_OP_WITH_LOG` 并留痕（§5.4）
- `revoke` —— 撤销记录（receiptId + 时间 + 撤销方公钥 + 签名）写入撤销表
- `show` —— 收据摘要

**核心模块**
- `agentledger/receipt.py` —— 签发/验证/撤销/收据账本（`receipts.jsonl`，草案 §5
  append-only log 本地形态：seq/ts/kind/body/prev/hash 链）
- `agentledger/ed25519.py` —— 纯 Python Ed25519（RFC 8032），零依赖红线不破；
  含 RFC 8032 §7.1 官方测试向量
- `schemas/drp-receipt.schema.json` —— 收据 JSON Schema（Profile 子集）
- `docs/DRP-ALIGNMENT.md` —— 字段映射、检查覆盖表、撤销语义、对草案的两处
  互操作观察（review comment 素材）

**验证检查覆盖**：撤销 / 签名 / 时间窗 / 范围（默认拒绝）/ 边界 / 指令哈希 /
工具模式哈希 / 可信来源 / 父收据包含与收窄（深度 ≤3）。运行时类检查（TEE、
会话信任、执行图、权威状态）明确划出 CLI 职责边界，见对齐文档。

### 说明
- 外层字段剥改攻击已防护：所有检查只读签名体，外层仅作容器
- 时间戳诚实标注 `local-unverified`（离线无 TSA，草案 §5.3 语义）

## [0.1.0] - 2026-10-13

首个版本。定位：**机器产出技术证据，人签署并担责。**

### 新增

**扫描引擎**
- 制品发现：递归遍历并分类 JSON / TOML / YAML / Markdown / 代码，识别 AI 攻击面
- 覆盖度记录：明确记录被排除的文件及原因（**界定结论适用边界**）
- JSONC 支持：容忍注释与尾逗号（`mcp.json` 常见写法）

**24 条规则，覆盖 5 大攻击面**

| 面 | 规则 |
|---|---|
| MCP 供应链 | `MCP001` 版本未固定 · `MCP002` 运行时自动拉包 · `MCP003` 工具投毒 · `MCP004` 明文凭据 · `MCP005` 权限过宽 · `MCP006` 明文 HTTP 端点 · `MCP007` 缺完整性证明 |
| 模型接入 | `MDL001` 备案状态核验 · `MDL002` 明文密钥 · `MDL003` 浮动别名 · `MDL004` 系统提示词注入 |
| 提示词/技能 | `PRM001` 可见注入 · `PRM002` **注释内隐藏注入** · `PRM003` 零宽/双向控制字符 · `PRM004` base64 载荷 · `PRM005` 拟人化未披露 |
| 依赖与执行 | `DEP001` 硬编码凭据 · `DEP002` 危险执行汇 · `DEP003` 输出未净化进危险汇 · `DEP004` 版本未固定 |
| 智能体治理 | `AGT001` 治理声明缺失 · `AGT002` 高风险动作缺审批闸门 · `AGT003` 缺隔离声明 · `AGT004` 项目缺成文声明 |

**监管义务映射（15 项）**
- 中国 7 项：《智能体规范应用与创新发展实施意见》第 8/10/11/12 条、生成式 AI 备案/登记、拟人化互动办法（2026-07-15 生效）、个人信息保护与数据出境
- 欧盟 5 项：EU AI Act Art. 12/14/15/17/26
- 通用 3 项：ISO/IEC 42001:2023 A.8/A.9、NIST AI RMF MEASURE
- 每项附条文引文与适用范围；自动生成"义务 → 未满足项"整改台账

**防篡改责任留痕**
- 哈希链式账本（JSONL），任一条目被修改/删除均被检出
- 发现项 Merkle 根（与输出顺序无关）
- HMAC-SHA256 分离式签署（附非对称签名的边界说明）

**证据包**
- JSON（机器可读/归档）+ Markdown（人可读/送审）双格式
- 六个章节：完整性锚点、扫描覆盖度、结论摘要、监管义务映射、发现项明细、复核签署
- 凭据一律脱敏后入报告

**集成**
- SARIF 2.1.0 输出，可直接接入 GitHub Code Scanning / GitLab / Azure DevOps
- 退出码可直接作 CI 门禁（`--fail-on`）

**CLI**
- `scan` / `verify` / `history` / `rules` / `init-key`

**测试**：39 个用例

### 修复

开发过程中发现并修复的真实缺陷（非外部 bug）：

- **中文文件被误判为二进制** —— 可打印 ASCII 占比判据导致含 UTF-8 中文的提示词文件被整体跳过，中文提示词注入**完全漏报**。改为"NUL 字节 → UTF-8 可解码 → 比例兜底"三级判定。
- **扫描自我污染** —— 证据包内含问题原文片段（脱敏后仍是注入特征），被下次扫描回灌，发现项数逐次漂移（25 → 30 → 35）。将 `.agentledger/` 排除在遍历之外。
- **URL 被误判为过宽文件权限** —— `//` 同时匹配协议分隔符与文件系统根。先剔除 URL 再判定。
- **本地脚本被误判为"版本未固定"** —— `./vendor/x.js` 不存在供应链问题。新增包引用 / 本地路径区分。
- **证据标签失真** —— 双向控制符被标为"零宽字符"。改为分别统计并如实报告码位。

[Unreleased]: https://github.com/agentledger/agentledger/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/agentledger/agentledger/releases/tag/v0.1.0
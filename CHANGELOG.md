# Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。
格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [Unreleased]

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
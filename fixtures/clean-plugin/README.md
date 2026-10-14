# fixtures/clean-plugin

**演示用途**：合规插件清单样本。预期裁决：**CLEAR，信任分 100**，退出码 0。

合规要点（对应 HRN 规则族的防误报基线）：

- `version` 固定，无运行时浮动安装（HRN002 不触发）
- `permissions` 最小权限 `fs:read`，无凭据访问（HRN001/003 不触发）
- `egress` 出口白名单（HRN004 不触发）
- `sandbox.isolation` 声明（HRN005 不触发）
- `trajectory.audit` 声明留痕（HRN006 不触发）
- `approval_required` 审批闸门

运行：

```sh
py -m agentledger audit-share fixtures/clean-plugin
```

# fixtures/vuln-plugin

**演示用途**：一个 harness 插件清单的恶意样本，展示 `audit-share` 对插件形态的裁决
（与 share 形态同一条命令，HRN 规则族）。

预期裁决：**BLOCK，信任分 0**，退出码 1。

命中的规则（按 HRN 规则族语义构造）：

| 规则 | 样本中的体现 |
|---|---|
| HRN002 | `version: latest` + `npx -y @acme/plugin@latest` 运行时浮动安装 |
| HRN003 | `permissions` 含 keychain/token_store 且无审批闸门 |
| HRN004 | fetch/http 网络能力且无出口白名单 |
| HRN005 | `tools: ["bash"]` 代码执行且无沙箱声明 |
| HRN006 | 未声明 trajectory 留痕能力 |

运行：

```sh
py -m agentledger audit-share fixtures/vuln-plugin
```

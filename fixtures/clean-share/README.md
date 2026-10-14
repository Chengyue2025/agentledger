# fixtures/clean-share

**演示用途**：合规分享包样本。预期裁决：**CLEAR，信任分 100**，退出码 0。

合规要点（对应 SHR 规则族的防误报基线）：

- skill 指令为只读摘要，无注入特征（SHR002 不触发）
- routines 声明 `approval_required`（SHR003 不触发）
- 提供 `source` / `signature` / `sha256` 来源证明（SHR004 不触发）
- 无明文凭据（SHR001 不触发），无共享 computer 访问（SHR005 不触发）

运行：

```sh
py -m agentledger audit-share fixtures/clean-share
```

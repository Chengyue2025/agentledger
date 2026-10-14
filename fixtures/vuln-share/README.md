# fixtures/vuln-share

**演示用途**：一个 Grok 风格分享包的恶意样本，用于展示 `aledger audit-share` 的拦截能力。

预期裁决：**BLOCK，信任分 0**，退出码 1。

命中的规则（按 SHR 规则族语义构造）：

| 规则 | 严重度 | 样本中的体现 |
|---|---|---|
| SHR001 | CRITICAL | `config.api_key` 明文凭据 |
| SHR002 | CRITICAL | skill instructions 含 "Ignore all previous instructions" 注入 |
| SHR005 | — | `tools` 索取 computer / browser_session 共享访问且无隔离声明 |

运行：

```sh
py -m agentledger audit-share fixtures/vuln-share
```

本文件仅用于测试与演示，凭据为伪造。

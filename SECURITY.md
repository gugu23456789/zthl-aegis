# Security Policy / 安全策略

**中文** · [English below](#english)

## 1. 报告渠道

请**不要**为安全问题开公开 issue。使用仓库托管平台提供的**私有漏洞报告**通道
（GitHub / GitLink 的 *Report a vulnerability* / Security Advisory），或在 issue 中只写
「需要私下联络」并等待维护者建立私聊。

报告中请尽量包含：影响版本（提交 sha）、最小复现（命令 + 期望/实际）、影响面
（能否绕过门禁 / 读到密钥 / 写到允许路径外）、以及你建议的判据。

## 2. 在本项目的语境里，「安全」指什么

这是一个**开发期治理工具**（门禁 / 台账 / 预算 / 导出），不是安全产品（见
[`MAINTENANCE.md`](MAINTENANCE.md) 免责声明）。我们优先处理以下**可验证**的类型：

| 类别 | 例子 |
|:--|:--|
| 门禁绕过 | 未走 `advance` 即改变阶段；`--force` 被当常规路径；编辑配额/阶段门被静默跳过 |
| 完整性绕过 | 篡改 state / journal / 卫星片后仍被判 PASS；HMAC / Ed25519 封印可伪造或可跳过 |
| 路径与权限 | `edit`/`read` 越出 allowed_paths；受保护区被改；junction/symlink 重定向绕过 |
| 密钥处理 | 密钥进入 argv/日志/提交；`.keys` 被导出；subagent 沙箱可读密钥 |
| 注入面 | subagent 输出/外部文档经聚合器污染主 agent 决策；命令注入 |
| 任意写入 / 删除 | 回收器误删在用数据；导出包夹带非白名单文件 |

**不在范围**：需要本机管理员权限或物理访问的攻击；已在文档中标注的 by-design 攻击面
（红队阶段本身就是攻击模拟）；第三方依赖自身漏洞（请报给上游，我们跟进升级）。

## 3. 我们的处置

- **安全修复优先**（见 `MAINTENANCE.md`）：确认后先在私有分支修复，再合并并致谢（若你同意）。
- 修复必须带**红先测试**（能复现的最小臂），否则不接受——这是本仓的工程纪律，不是流程偏好。
- 披露：默认在修复合入后公开说明；若你希望延迟披露，请在报告中注明期限。

## 4. 部署者须知

- `state` 与卫星片包含**本机绝对路径、会话 id、部分任务文本**；分享/提交前请按导出面
  （`gatekeeper-cli.sh` 的导出/清洗通道）处理。
- 密钥文件（`.keys/`、HMAC 主密钥、审计私钥）**不得**进入版本库；轮换方式见
  [`references/security-measures.md`](references/security-measures.md)。
- 默认配置面向单机单用户；多用户/多租户部署需要自行补身份隔离。

---

## English

**Do not open a public issue for security problems.** Use the hosting platform's private
vulnerability reporting (Security Advisory) and include: affected commit, minimal reproduction
(command + expected/actual), impact (gate bypass / key exposure / write outside allowed paths),
and the check you would add.

**In scope** (verifiable): gate bypass, integrity/tamper bypass (state, journals, satellite
shards, HMAC/Ed25519 seals), path and permission escapes, secret handling, prompt/command
injection through sub-agent output or external documents, arbitrary write or destructive
reclamation, export packages containing non-whitelisted files.

**Out of scope**: attacks requiring local admin/physical access, documented by-design surfaces
(red-team stages are simulated attacks), and vulnerabilities in third-party dependencies
(report upstream; we will follow up with an upgrade).

**Handling**: security fixes take priority; every accepted fix must ship with a failing-first
test. Disclosure defaults to public after the fix lands unless you request a delay.

**Deployers**: state files and shards contain local absolute paths, session ids and partial task
text — sanitise before sharing. Never commit key material; see
[`references/security-measures.md`](references/security-measures.md) for rotation.

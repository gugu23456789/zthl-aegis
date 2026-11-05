# 与 DeepSeek Harness Super-agent 的架构对照（2026-11-05 重写）

<!-- DOC-META
title: 与 DeepSeek Harness Super-agent 的架构对照
type: reference
owner: spz-gatekeeper-r-sequence
status: public
updated: 2026-11-05
-->

> 对照对象：DeepSeek Harness 团队 2026-10-31 开源的 `dsh-superagent-prototype`
> （MIT；自述为 research prototype，非官方产品；作为 DeepSeek Harness 的插件 bundle 运行，
> 单 GitHub 仓）。只做**架构面**对照，不评价实现质量。外部依据见文末 Sources。

## 更正记录（2026-11-05）

上一版（2026-11-02）凭二手报道写就，三处与一手材料不符，已按仓库文档与两份逐条分析重写：

| 上一版说法 | 实际（据 `docs/002-authorization.md`、`007-architecture.md`、`006-deployment.md`） |
|:--|:--|
| 「云端无状态 loop、DB 存状态、本地执行」 | **本地优先**：`Store` 拥有全部状态，落**单个 SQLite 文件**；回复经持久 **outbox** 提交后发送；重启靠 Source 的读位点（git 历史 + webhook offset）恢复 |
| 「外部 **Watchdog**：AI 监督 AI，可介入修复」 | 原型**没有** Watchdog。监督面 = **无状态 Eval**（按仓库策略判 Trigger）+ 人员 allow-list（初始仅操作者）+ 只列「需人处理」的面板；设计文章里的方向性内容不等于本版已实现 |
| 「不测人」 | 它恰恰把人当作要**计费**的资源：**attention budget**（结构化 handoff、一次一问、释放 worker 槽位）；但确实**不度量操作者能力**——本仓 OPCAP 补的正是这一轴 |

## 一句话

两者都把「会话管理」从人手里移到系统层，让人只做决策与验收；**本仓多守一条前置**：
先让每个结论**可回放、可复算**，再谈自主与并发。Super-agent 优化**人的注意力消耗**，
本仓优化**可审计性与默认拒绝**。

## 逐维对照

| 维度 | Super-agent（DSH 官方原型） | 本仓（ZTHL Aegis） |
|:--|:--|:--|
| 形态与范围 | dsh 的插件 bundle；**单仓**常驻监听 GitHub（可选飞书） | 独立技能 + CLI + hook；多域 state、worktree 隔离 |
| 领域模型 | 五原语 **Sources / Triggers / Threads / Mandates / Tickets**：Source 产不可变 Trigger → 有序 Thread；**无状态 Eval** 按仓库策略判是否建 Ticket；Ticket 获**不可变 Mandate**，固定作用域与「操作强度」 | state 域路由 + 门禁判定 + finding 台账 + 计划冻结；无 Ticket 抽象 |
| 权限面 | 人员 allow-list（示例初始仅操作者）+ 三档接受模式 `off` / `observe`（默认）/ `auto`；`auto` 仍要求至少一条团队写的规则；**消息/评论不能修改权限**（只作为 router 的输入） | hook 写类门禁 + `guard-edit` + 额度银行（配额/提额/申诉）；默认拒绝 |
| 越界与漂移 | 越界请求**交回 router**，worker 不自行扩权；订阅可投递上下文但**不能扩大** Mandate | 域冲突 fail-closed（`STATE_DOMAIN_EXPLICIT_CONFLICT`）+ finding 追责 |
| 状态与恢复 | 单 **SQLite** `Store` + 持久 outbox + Source 读位点（重启安全） | 单源 JSON state + 跨进程锁 + checksum + append-only 卫星 |
| 执行隔离与时限 | 每 Ticket 一个 **git worktree**、`maxWorkers` 池；命令 >5s 自动转后台，**30 分钟硬杀**并留审计 | worktree 隔离 + 单写者；无命令时长模型（同步 CLI） |
| 人的注意力 | **attention budget**：需要人时写结构化字段、释放 worker、只回一个问题；面板只列需人处理项 | 人轴 **OPCAP**（能力/带宽）+ `abstain`（证据不足不下结论） |
| 默认姿态 | `observe`：推断项只记「would accept」，**不执行**；显式请求在所有模式都执行 | 默认拒绝（fail-closed）；信用分默认不进判定（只读观测） |
| 安全边界 | worker 以操作者 **OS 用户**、`danger-full-access` 运行；缓解 = 剥含 KEY/PASSWORD/SECRET/TOKEN 的 env、清 `GH_TOKEN`/`GITHUB_TOKEN`、`blockedCommands`、面板仅 loopback、管理 API 校验 header/host；文档建议专用 OS 账号 | hook 拦截 + 非交互凭据闸（R0.20）+ 密钥完整性 + 专用凭据面 |
| 合并/发布 | auto-merge 默认关；开启需用**另一个账号**的 `gh` 登录 | 门禁硬门；公开面由机检导出（白名单 + 去标识 + 反向检索） |
| 证据 / 基准 | 未发布基准；无可独立复算的入口 | 可回放（checksum / 账本 / `audit` 重放 / ember 快照） |
| 许可 | MIT（自述研究原型，非官方产品） | MulanPSL-2.0 |

## 相同点

1. **Router/Worker 分层**：执行单元不直接占用人的注意力，结果先汇聚再呈现。
2. **会话不是用户负担**：都试图把「开新会话 / 同步上下文」变成系统内部动作。
3. **旁路监督**：都认为「执行者自查」不可靠——它用无状态策略 Eval，本仓用审计署。
4. **注意力是稀缺资源**：它把人打断当预算来扣；本仓把人的带宽单独立轴（OPCAP）并允许 `abstain`。
5. **不信任自然语言授权**：它明确「消息不能改权限」；本仓把授权写在门禁与 state 里，不靠对话。

## 关键差异

1. **默认姿态**：`observe` 是「先记录不执行」（乐观记录、保守执行）；本仓是 fail-closed
   （不满足即拒绝，证据不足则 abstain）。两者都保守，但一个保守在**产出**，一个保守在**放行**。
2. **权威模型**：它用**不可变 Mandate** 把作用域一次钉死；本仓用「门禁 + 额度银行」把作用域
   变成**可计价、可提额、可申诉**的连续量。
3. **证据强度**：它未发布基准、也无复算入口；本仓把「可回放」当准入条件（checksum / 账本 /
   `audit` 重放）。
4. **隔离粒度**：它以同一 OS 用户运行 worker，靠剥 env 与命令黑名单收敛，并建议专用账号；
   本仓在 hook 层做写类门禁，并把凭据面分离（R0.20）。
5. **人的轴**：它**预算**人的注意力但不**度量**人的能力；本仓把二者分开：预算对应带宽，
   度量对应 OPCAP，且单人期只作 case study。

## 可借鉴 / 不借鉴

- **可借鉴**：① 无状态 Eval（判定不持有队列/重试状态，重启靠 Source 读位点）——与「单源
  state + 锁」互补；② 不可变 Mandate 的「订阅不能扩权」写法，可映射到本仓的域路由与
  worktree 作用域；③ 结构化 handoff（一次一问、释放槽位）——比自由文本追问更省注意力。
- **对 OPCAP 的参考**：它的「打断次数 / 承接次数 / 面板停留」是**人轴带宽**的外部效度参照，
  但它不测能力，不能直接照搬成 OPCAP 指标。
- **不借鉴**：worker 以操作者 OS 用户全权运行（与本仓 fail-closed 取舍冲突）；把监督写成
  「AI 可修复」（造成监督者与被监督者权限合并）。

## Sources

- [dsh-superagent-prototype（GitHub，MIT）](https://github.com/deepseek-ai/dsh-superagent-prototype)
- [docs/002-authorization.md（三档 accept mode / allow-list / 消息不能改权限）](https://github.com/deepseek-ai/dsh-superagent-prototype/blob/main/docs/002-authorization.md)
- [docs/007-architecture.md（Trigger→Ticket、worktree、SQLite Store、outbox）](https://github.com/deepseek-ai/dsh-superagent-prototype/blob/main/docs/007-architecture.md)
- [docs/006-deployment.md（danger-full-access / 专用 OS 账号建议）](https://github.com/deepseek-ai/dsh-superagent-prototype/blob/main/docs/006-deployment.md)
- [DeepSeek Super-Agent: Coding Agents on an Attention Budget（dev.to，2026-11-01）](https://dev.to/ali_82f3409ed625e8ba8515b/deepseek-super-agent-coding-agents-on-an-attention-budget-35of)
- [DeepSeek's Super-agent Defaults to Observe Mode（dev.to，2026-11-01）](https://dev.to/gabrielanhaia/deepseeks-super-agent-defaults-to-observe-mode-but-its-workers-get-full-access-as-you-427)
- [DeepSeek 开源 Super-agent：Router–Worker 双层（36Kr）](https://36kr.com/p/4052484771681158)
- [Super-agent: DeepSeek Splits Session Management in Two（aimodeling）](https://www.aimodeling.com/en/news/slug/deepseek-super-agent-router-worker-architecture)
- [DeepSeek's Super Agent Harness（MindStudio）](https://www.mindstudio.ai/blog/deepseek-super-agent-harness-design)

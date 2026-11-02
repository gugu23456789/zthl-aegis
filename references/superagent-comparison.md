# 与 DeepSeek Harness Super-agent 的架构对照（2026-11-02）

> 对照对象：DeepSeek Harness 团队 2026-10-31 公开的 Super-agent 设计与其原型仓
> `dsh-superagent-prototype`（MIT）。本文只做**架构面**对照，不评价其实现质量。
> 外部依据见文末 Sources。

## 一句话

两者都把「会话管理」从人手里移到系统层，让人只做决策与验收；**本仓多守一条前置**：
先让每个结论**可回放、可复算**，再谈自主与并发。Super-agent 优化的是**吞吐与注意力**，
本仓优化的是**可审计性与默认拒绝**。

## 逐维对照

| 维度 | Super-agent（DeepSeek Harness） | 本仓（ZTHL Aegis） |
|:--|:--|:--|
| 核心目标 | 系统接管会话管理与上下文同步，人上移到决策/验收 | 同目标，但以「证据链可复算」为第一约束；自主度受门禁约束 |
| 编排拓扑 | **Router 常驻 + Worker 隔离**双层 | `gk_route_center`（仓库/路径路由）+ `subagent_runner`（7 角色 × 4 档）+ `gatekeeper-cli.sh` 单入口 |
| 会话语义 | Session 是系统实现细节，用户不必感知 | `state_domain` / worktree / session id 显式建模；会话态可迁移、可审计 |
| 状态与执行环境 | 云端无状态 Agent Loop + 数据库存状态；重状态执行环境留在本地（存算分离、脑手分离） | **本地优先**：单源 state + 跨进程锁 + checksum + 原子写；worktree 隔离执行；无云依赖 |
| 消息与事件 | 事件驱动、异步多信道 | append-only 卫星片 + journal 链 + `zthl/eventbus.py`；子代理只回结构化 JSON，不直接对人说话 |
| 监督机制 | **外部 Watchdog**：独立 AI 监督其他 agent，检测故障、无效循环、目标漂移并尝试修复 | **审计署**（只监管、不直接阻断）+ `gk_watch` + `safe_termination_gate`（空转/跳过链尾拦截）+ 证据不足时 abstain |
| 人的角色 | 决策与验收；注意力是稀缺资源 | 否决权不可让渡；先独立打分、再由 CLI 事后裁定（双盲纪律） |
| 度量对象 | 任务与模型（不测人） | 物轴（门禁/收敛/证据）+ **人轴 OPCAP**（操作者驾驭能力与带宽） |
| 失败处理 | Watchdog 介入修复，尽量维持任务连续 | 默认拒绝（fail-closed）；不可判 ⟹ `abstain` / `[UNFITTED]`，不猜 |
| 许可与发布 | MIT 原型仓 | MulanPSL-2.0；公开面由机检导出（白名单 + 去标识 + 反向检索） |

## 相同点

1. **Router/Worker 分层**：都不让执行单元直接占用人的注意力，结果先汇聚再呈现。
2. **会话不是用户负担**：都试图把「开新会话/同步上下文」变成系统内部动作。
3. **独立监督者**：都认为「执行者自查」不可靠，需要一个旁路的监督面。
4. **人只保留高层判断**：都把人的位置从「操作」上移到「决策与验收」。

## 关键差异

1. **优化目标不同**：Super-agent 面向吞吐与 7×24 连续在线；本仓面向「结论可回放、失败可解释」，
   宁可 abstain 也不给无证据的通过。
2. **状态位置不同**：他们存算分离、云端常驻；本仓刻意本地优先，state 单源 + 锁 + 校验和，
   避免「云端状态与本地环境漂移」这一新失败面。
3. **监督的权限不同**：Watchdog 可以「尝试介入修复」；本仓审计署**只出 finding 不直接阻断**，
   执行权留在门禁/额度银行，避免监督者与被监督者权限合并。
4. **度量对象不同**：他们不测人；本仓把「操作者能力面」单独立轴（OPCAP），与物轴分账，
   且明确「单操作者期只能作 case study」。

## 可借鉴 / 不借鉴

- **可借鉴**：Router↔Worker 的异步信道抽象（本仓目前是同步 CLI + 卫星事件，缺少统一的
  异步回传面）、Watchdog 的「目标漂移」检测思路（本仓已有空转/收敛 abstain，但未做漂移轨迹）。
- **不借鉴**：云端常驻状态（与本仓 fail-closed/本地优先的取舍冲突）、监督者直接修复
  （会造成权限合并，与「审计只监管」不变量冲突）。

## Sources

- [Super-agent 双层架构：Router 与 Worker（IT之家）](https://m.ithome.com/html/1020615.htm)
- [DeepSeek 新开源架构 Super-agent（腾讯云开发者社区）](https://cloud.tencent.com/developer/article/2773284)
- [DeepSeek 公布 Super-agent 架构（智东西）](https://m.zhidx.com/p/606311.html)
- [DeepSeek 发布全新 Agent 架构（四川观察）](https://www.sctv.com/news/2116552553092603906)
- [Super-agent 发布报道（爱济南）](http://m.toutiao.com/group/7703377100480332339/)

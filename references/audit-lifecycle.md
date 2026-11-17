# 审计生命周期（Audit Lifecycle）—— 机制正本

**定位**：审计进程的启动、健康检查、停止、租约与定时作业；以及「凭什么允许签发审计结论」。
**单一事实源**：`scripts/gk_audit_lifecycle.py`（生命周期）、`scripts/gk_audit_state.py`（状态与视图）、
`scripts/gk_node_guard.py`（出口判据，见 `report_evidence_ok`）。
额度与违约处置见 `credit-economy.md`；违约定义见 `violation-charter.md`。

## 0. 机制面（自动生成，勿手改）

<!-- GK-MECH:START id=audit-lifecycle（由 scripts/gk_mechanism_docs.py 生成，勿手改） -->
| 事实 | 值 | 来源（可复算） |
|:--|:--|:--|
| 入口脚本 | `gk_audit_lifecycle.py` · `gk_audit_state.py` · `gk_node_guard.py` | `references/mechanism-registry.json` |
| 公开函数 | 58（audit_lifecycle 37 / audit_state 11 / node_guard 10） | `^def <name>` 计数（入口脚本合计） |
| CLI 入口 | `audit` · `node-guard` | `gatekeeper-cli.sh`（`_CMD_REG` 或早期 case 分派） |
| 测试 | `scripts/test_gk_audit_lifecycle.py` · `scripts/test_gk_audit_state.py` · `scripts/test_gk_audit_lifecycle_wiring.py` | `scripts/` |
| 校验 | `python scripts/gk_mechanism_docs.py --check --id audit-lifecycle` | 本闸自身 |
<!-- GK-MECH:END id=audit-lifecycle -->

---

## 1. 三段式启停

启动过程分三段，每段都要留下可核验的证据：

1. **start**：拉起审计进程，写启动 sidecar（含启动器类型、启动耗时）；
2. **health**：连续健康检查，确认进程存活且能响应；
3. **stop**：停止并回收，写停止记录。

启动器类型是判据的一部分：`launcher=external` 表示改由外部通道拉起，此时本机只做健康与停止。

## 2. 自适应启停（E1–E8）收敛到哪

- E1–E8 是本机制的分阶段落地编号，**全部已落地**。
- 其中 E8 的「启动 → 健康 → 停止」由**外部通道**完成实测验证（启动耗时约 5.3 秒），
  不再要求在本机重复三臂对比。
- 生命周期租约改为**单一来源**：谁写租约谁负责回收，读侧不复制写入逻辑。

## 3. 定时作业

- 作业体按 60 秒 tick 设计，调度入口按 1 分钟粒度。
- 每次推进写一份 sidecar（前进标记），并记录返回码与原因，便于事后回放。
- 「僵死检测」（dead-man）由长期告警升级为**直接失败**，并接入审计结论；
  一直告警等于没有告警。

## 4. 证据与签发判据

审计结论的签发不看「跑过没有」，而看**证据是否落盘**：

- 有生产者的域（状态域、文档域）必须**全部**落盘，不是任一域即可；
- 标准路线的审计还需「相位标记」与「证据落盘」同时成立——
  仅进入相位不算证据（进入即 advance 的写法不能当作跑过审计的证明）；
- 证据登记与封印在读取侧采取严格策略：读不到就判失败，不把「无法校验」当成「一致」。

## 5. 与额度面的接口

额度违约不在这里判，但封顶与冷却落在额度账本：
违约后进入冷却期，账本只提供只读投影；提额账本封印在读取侧同样严格。
判据正本在 `credit-economy.md`。

## 6. 能力边界（不要误读为「已完成」）

- 审计域里有一批以扫描计数为形态的存量条目，随代码增长而增长，
  **本机制不承诺把它们清零**；它们是度量，不是待修缺陷。
- 会话分片、审计关账相关的若干实质缺口属未收口主线，按主线节奏处理。

## 7. 常见坑

1. **只看相位标记就签发**：相位标记在进入时写入，不能单独作为「已跑过审计」的证据。
2. **把 sidecar 当装饰**：启动器类型与启动耗时是判据输入，缺了它们，E8 的结论无法复核。
3. **在单域落盘后放行**：有生产者多域时必须是全集，不是任一。

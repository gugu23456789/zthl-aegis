# 违约定义与处置条例（v1，2026-11-11 定稿）

**状态**：生效。**承载面 = 本文**（活文档）。
`references/security-measures.md` 于同批**退役为历史归档**（最后登记 C12 / 2026-09-25，其后 47 天无回流；
`doc_freshness` 因 pin 写死而恒 PASS，无法发现停更）——新机制**不得**再登记进该表。

判据单源（本文只作契约，不复制实现）：

| 职责 | 单源 |
|:--|:--|
| 记账 / 分级 | [`gk_threat.py`](../scripts/gk_threat.py) |
| 诱饵注册表 / 命中取证 | [`gk_canary.py`](../scripts/gk_canary.py) |
| 接线（hook 硬拒绝） | [`pre_tool_hook.py`](../scripts/pre_tool_hook.py) `_deception_gate` |
| cron 存活 | [`gk_self_check.py`](../scripts/gk_self_check.py) `check_cron_health` |

## 0. 边界（硬约束）

适用面 = 本仓 / 授权工作树 / 用户显式指定的自有资产。**不对外部主体做任何反制**：不注入、不反向攻击、
不反洪泛、不产生对外流量。真实 DDoS 只走既有准入控制（`gk_sandbox` 限额）。

## 1. 定义（严格）

**违约 = 一个已识别 sid 的一次工具调用，其参数命中注册表登记的诱饵路径。**

| 要件 | 规定 | 落点 |
|:--|:--|:--|
| 主体 | hook 解析出的 sid（`_env_sid or _pay_sid`）；无法识别归并为 `__anon__` | `_deception_gate` |
| 客体 | 本仓诱饵注册表**全部槽位**（含退役世代；旧地图不作废） | `gk_canary.scan` |
| 行为 | 命令串 / 写入目标 / MCP 写路径中出现诱饵相对路径 | `_mcp_write_path`、`target` |
| 排除 | `owner_sids` 成员；`GK_CANARY_MAINT=1`（宿主注入）；无注册表的仓 | 同上 |
| 取证 | append-only 一行 JSON（ts/iso/sid/kind/detail/target），**一次访问只记一笔**（取 rel 最长者） | `gk_threat.record` |
| 可见面 | 只回一行 `GATEKEEPER: request rejected.`；无错误码 / 无路径 / 无 state / 无修复提示 | `SINGLE_LINE` |

**不属于违约**：hook 拦截本身 ≠ 违约。worktree 越权写、恶意载荷、解释器误用、编辑额度耗尽
**只拒绝、不入本台账**——它们各有独立账本，重复记账等于「一次失误两次判罚」。

## 2. 分类与计分（v1 = 等权计数）

v1 的分级判据是**窗口内条数**（`len(events)`），不引入权重表：

| 类别 | 触发源 | 计分 | 可隔离 | 现状 |
|:--|:--|:--|:--|:--|
| `security/canary_hit` | 诱饵命中 | 1 | 是 | **已接线**（唯一在产 kind） |
| `security/ledger_tamper` | 账本 / 封印校验失败 | 目标态 3 | 是 | **未接线** |
| `security/malware_payload` | 载荷门命中 | 目标态 3 | 是 | **未接线** |
| `governance/worktree_ownership` | 越权写他人 worktree | — | **否** | 只拒 + 日志，不入账 |
| `noisy/rejected_edit` | 重复拒改（cap=120 出窗） | — | 否 | 已有 `rejected-edits-journal.jsonl`，不重复记 |

**原则：只有 security 类可导致隔离。** 治理类若也计入阈值，一次路径笔误就足以把人关进隔离区——
这是最大的误伤面；治理证据归 finding 台账，不归安全隔离。

**权重是目标态，不是现状**：上表「目标态 3」未实现。若将来接入 `ledger_tamper` / `malware_payload`，
必须**同批**修改本节、`QUARANTINE_AT_DEFAULT` 语义与对应测试，禁止只改代码不改条例。

## 3. 处置（分档 / 恢复 / 豁免）

窗口 = 滚动 1h（`GK_THREAT_WINDOW_S`，默认 3600）；判据 = 窗口内**条数**。

| 档 | 判据 | 处置 | 恢复 |
|:--|:--|:--|:--|
| `normal` | 0 | 放行 | — |
| `suspicious` | ≥1 | 放行；诱饵**立即轮转**（60s debounce ⟹ 旧地图作废） | 窗口滑出 |
| `quarantined` | ≥3 | **一切**工具调用 exit 2 + 单行零信息 | 窗口滑出自动恢复 / `gk_threat reset`（改名归档，不删）/ `decay`（先整份归档再压缩） |

- **不设永久封禁**：隔离是窗口态而非终态，避免一次误判把会话彻底打死。
- **豁免只给维护面**：`GK_CANARY_MAINT=1` 由宿主注入、agent 不可自设；`owner_sids` 防防御方巡检自伤。
- **旁路** `GK_THREAT_BYPASS=1` 仅测试用，**无审计后门**（仍留 hook 日志）。
- **无申诉通道**（v1 如实登记）：误判只能等窗口滑出或人工 `reset`；人工解除**不写违约台账**，
  故无法审计「谁在何时解除了谁」。这是已知缺口，不是设计意图。

## 4. 与既有评分机制的分工（**禁止第四套打分器**）

本项目已有三处「窗口计数 → 阈值 → 分档」：`gk_gate_entropy`（熵）、`gk_budget_ledger.edit_spam_flag` /
`file_cap_flag`（额度只读评分）、`gk_monitor_rotation.triage`（monitor 分级）。
本条例**不新增第四套**：`gk_threat` 只是违约**事件单写入口**，读侧沿用既有只读约定
（`{count, window, k}`），不引入通用 `score()` 抽象。

| | 熵监视器 | 违约台账 |
|:--|:--|:--|
| 输入 | `rejected_edits` 比例 / ECO 校准非 PASS 比例 / 当日提额频次 | 诱饵命中等安全事件 |
| 输出 | 0.00–1.00 连续值 | 0/1/2 离散档 |
| 消费方 | `advance` 门禁 + monitor **advisory** | hook **硬拒绝** |
| 语义 | 质量退化（"该停下来看看"） | 安全越界（"现在就不许动"） |
| 可阻断 | 仅 `GK_ENTROPY_RAISE_ENFORCE=1` | 恒阻断（`quarantined`） |

**反互搏规则**（两条硬约束）：

1. monitor 的 `triage` 分**不得**接入 hook 决策——同一事件有两个决策点必然判据漂移。
2. 违约台账的分**不得**回灌熵——熵是质量信号，混入安全事件会让 `advance` 因一次诱饵误触而误判退化。

### 4.1 违约在额度银行的表示（2026-11-11 定案）

**形态 = 冻结提额 + 审计只读投影**：违约**不扣款、不计熵、不改信用分**，只在 `advance` 的
预算注入点**封顶**，并由审计**只读**列出「谁在冷却期、账户在哪、余额多少」。

| 面 | 规定 | 单源 |
|:--|:--|:--|
| 判据 | 该 sid 最近一次安全事件距今 < `GK_THREAT_BUDGET_COOLDOWN_S`（默认 3600） | `gk_threat.budget_freeze` |
| 生效点 | 冷却期内 advance 注入额度**减半**（`max(1, candidate//2)`）；只影响下一次注入，不追溯已发额度 | `gk_advance._threat_budget_cap` |
| 审计面 | `audit --cost` 的 `cost_threat_budget`：冷却期 sid ↔ `edit_budget.sessions.<key>` 必须可对齐；接线被删即 FAIL | `gk_audit_state._threat_budget_projection` |
| 键对齐 | 台账明文 sid（hook 侧 = 载荷 sid，常见 24 hex）↔ 银行会话键（CLI 侧 = worktree token，常见 8 hex）：**别名分片** `.gatekeeper.session.alias.<sid>` 优先，其次精确相等，最后**短者 ≥8 位**的前缀对齐 | `gk_threat.session_alias` / `gk_audit_state._bank_key` |

边界（沿用 §4 反互搏）：

- **不扣款**：不写 `used`、不发 `charge` 行、不动 `remaining`——只影响**下一次注入**的上限。
- **不进熵**：违约分不得进入 `compute_entropy` / 信用分 / `score()`；`advance` 不因此阻断
  （硬拒绝面仍只在 hook，见 §3）。
- **为什么不是「隔离期冻结」**：`quarantined` 期间 hook 对所有工具调用 exit 2 ⟹ 对方连 advance
  都调不了，冻结不可观测也无意义；真正有牙齿的形态是**解除后的冷却期**（窗口滑出后 hook 放行、
  额度仍受限）。
- **fail-open**：无 `GK_SESSION_ID` / 台账不可读 ⟹ 原样放行并留 `threat_advisory`
  （`fail_open: true`）；`GK_THREAT_BUDGET_FREEZE=0` 是运维 kill switch。键对不上时审计
  **FAIL**（`cost_threat_budget`），不静默放过。

## 5. cron dead-man switch

判据单源 = `gk_self_check.check_cron_health`（审计侧 `SELF-05` 只委托，不复制阈值）：

| 档 | 判据 | 动作 |
|:--|:--|:--|
| FAIL | `tick.log` 年龄 > 6h（连续漏 6 次每小时触发） | finding `AUDIT-SELF 失效: self_cron_health` |
| FAIL | 任一**启用**作业 `failure_streak ≥ 3`（实测 `model-radar` 长期 3 而零告警） | 同上 |
| WARN | `tick.log` 年龄 > 2h，或有作业 `next_run_at` 超期 > 1h | 只告警（单次漏跳 / 人为暂停属合法形态） |
| WARN | `tick.log` 缺失 | 不升级为 FAIL（首装未 tick 与从未启动不可区分，防首次部署即红） |
| SKIP | `jobs.json` 不存在 | 不判（cron 未初始化） |

边界：本开关是**拉式**——审计不跑就看不见。推式（10min monitor 周期）另议，且必须先有本条。

## 6. 变更规则

- 改判据（阈值 / 窗口 / 档位 / 计入 kind）⟹ **同批**改本条例 + 单测 + `audit --cost` 的
  `cost_threat_thresholds` 守护项；三者任缺即视为未完成。
- 新机制**禁止**登记进 `references/security-measures.md`（该表已冻结为历史归档，不再接收登记）；需要新承载面时在本文件追加节，
  并在 `references/architecture-overview.md` 文件地图同步。

## 7. 已知缺口（如实清单，不粉饰）

1. 低频探测不累积：1h 窗口滑出即清零，攻击者按 1 次/小时节奏可永不触发隔离。
2. 无累犯机制：跨窗口的重复行为不跨窗累计（由 finding 台账人工兜）。
3. `canary_hit` 是唯一在产 kind：`ledger_tamper` / `malware_payload` 未接，故「3 次即隔离」目前只能被诱饵触发。
4. 无申诉 / 无解除审计（见 §3）。
5. 诱饵注册表按仓隔离：跨仓攻击者需逐仓命中，本台账不跨仓聚合。

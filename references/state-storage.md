# State 存储与回收（ZTHL Aegis）

<!-- DOC-META
title: State 存储与回收（ZTHL Aegis）
type: reference
owner: spz-gatekeeper-r-sequence
status: public
updated: 2026-11-02
-->

> 本文是 **state 存储面**的公开单一事实源：有哪几种 state、各自作用、卫星片（bulk sidecar）
> 的容量/生命周期/回收判定，以及体积水位怎么告警与拦截。
> 项目名 = **ZTHL Aegis**；安装目录沿用历史名 `spz-gatekeeper-r-sequence`（包名不改，避免破坏既有安装）。
> 实现单源：`scripts/gk_state_forms.py`（形态）、`scripts/gk_satellite.py`（卫星）、
> `scripts/gk_json_utils.py`（墙/水位/三条腿）、`scripts/gk_state_map.py`（归档）。
> 相关：域解析与路由见 [`meta-routing-protocol.md`](meta-routing-protocol.md)；命令清单见
> [`cli-protocol.md`](cli-protocol.md)；finding 写入规范见 [`ecc-write-spec.md`](ecc-write-spec.md)。

## 1. 术语与边界

| 叫法 | 是不是 state | 说明 |
|:--|:--|:--|
| base state | ✅ | `.gatekeeper.state`，主台账（唯一权威） |
| domain state | ✅ | `.gatekeeper.state.<repo>.<plan>`，计划/跨仓隔离 |
| legacy_plan / worktree_local | ✅（**只读**） | 迁移遗留、他仓副本；只读，不动 |
| baseline | ❌ **不是 state 形态** | 见 §2 末尾的三种「baseline」 |
| 卫星片 / journal / 日志 | ❌（artifact 旁挂） | `<state>.<kind>-archive.jsonl` 等，随 state 走，不是 state |

判据单源 = `gk_state_forms.state_form()`，只有 `base|domain|legacy_plan|worktree_local|artifact` 五值；
写门 `assert_writable_form()` 只放行前两类。

## 2. 三种 state 的分工

| 形态 | 落点 | 可写 | 作用 | 何时用 |
|:--|:--|:--|:--|:--|
| **base** | 技能根 `.gatekeeper.state` | ✅ | 主台账：阶段/R、预算、`task_pipeline`、`subagent_history`、`ecc_findings`、`satellite_index` | 单仓单计划、技能自维护 |
| **domain** | 同目录 `.gatekeeper.state.<repo>.<plan>` | ✅（D3 opt-in） | 按计划/仓隔离，防跨仓 finding 互相污染 | 计划头声明 `META.state_domain: <repo>.<plan>`，或 CLI 直传 `--domain` |
| **legacy_plan** | `.gatekeeper.state.<YYYY-MM-DD-plan>` | ❌ 只读 | 迁移前的裸计划名 state，冻结留证 | 只读审计；需要续用先迁成 domain |
| **worktree_local** | 技能根之外的 `.gatekeeper.state` | ❌ 只读 | 属他仓/worktree 副本，归该仓自己管 | 只读消费 |

纪律：声明了域就**不静默回退** base —— 目标域 state 不存在时 fail-closed（`FINDING_DOMAIN_STATE_MISSING`）。

**「baseline」在本项目里指三处不同的基线，都不是 state 形态**：

1. 经济基线（`gk_econ_baseline`）：`<state>.credit-baseline.json`，Ed25519 签名 + 绑 state 身份；
   无效 ⟹ fail-closed，**不**回退无签名的 `econ_enabled_at`。
2. gitnexus 图基线：`release-check` 的 baseline↔final 对比（STAGE 0 vs STAGE 3）。
3. 命令输出基线：`scripts/test_baselines/baseline_*.json`（`capture_baselines.sh` 产），供回归对比。

## 3. 卫星片（bulk sidecar）

**问题**：`subagent_history` / `task_pipeline` / 归档 finding 是「短寿命、大批量」的臂输出。
留在主 state 会让唯一权威文件无限膨胀 ⟹ 撞墙时**所有**治理写一起失败。

**方案**：主 state 只留**元数据 + 索引**，批量产物落**扁平 append-only 片**：

```
<state>.history-archive.jsonl     # kind=history   子代理臂输出
<state>.task-pipeline-archive.jsonl # kind=pipeline 任务流水
<state>.finding-archive.jsonl     # kind=finding   归档/溢出的 finding
```

- 片名单源 = `gk_satellite.KIND_SUFFIX`（禁第二份字面量）。
- 写入唯一入口 = `gk_satellite.append()`（片 + 冷索引侧车 + 判活锚同批）。
- 索引 = **内联 ∪ 冷**：S3 起写侧**停更**内联热索引（`INLINE_INDEX_WRITES=False`），
  新叶只落 `<state>.satellite-index.jsonl`（append-only：`put`/`del`）；内联
  `gate_data.satellite_index.<batch_id>.<arm>` 只留历史叶，由 GC 按 cap（6）溢出到侧车。
  读面统一走 `gk_satellite.index_entries()`（侧车同键优先），禁直读 `gate_data.satellite_index`。
- 拓扑与崩溃安全见 README「元数据路由（DAG）」：`写 → 网关 → state` 与 `片/侧车 → 读面`
  两条支路，GC（`gc_index` / `reclaim`）是唯一索引删除者（追加 `del` + 整键重写），读面无回写边。
- `rejected_edits` 出窗条目落 `<state>.rejected-edits-journal.jsonl`（append-only、**永不回收**，
  `gk_advance._append_rejected` → `REJECTED_CAP`）；live 只留窗口内条目，审计读 journal。
  2026-11-01 改名（原 `-archive` 会落进卫星 `*-archive` 认知域）；旧名不自动迁移，读面两代都认。
  上限：软线 3MB（≈100 轮 × 6 臂，80% 硬顶 `WARN`）/ 硬顶 8MB → 轮转 `-1`（总量 ≤16MB）。

<!-- GK-CAP:START（由 scripts/gk_docgen_facts.py 生成，勿手改） -->
**容量标定**（owner 2026-11-01 明确口径）：**一轮 = 6 个 subagent（档位 4，单臂 token 预算跑满）
产生的 history 总量 × 120% 余量**；一片 = 10 轮。

| 项 | 值 | 口径 |
|:--|:--|:--|
| 单臂预算 | 16 KB | 档位 4 跑满时 history 实测 10.9–12.7 KB 的上抬值 |
| 一轮预算 | **117,964 B（≈115.2 KB）** | 6 臂 × 16 KB × 120%（`SAT_ROUND_BUDGET_BYTES`） |
| 片容量 | **1,179,640 B（≈1.12 MB）** | 10 轮（`SAT_SHARD_BUDGET_BYTES`） |
| 臂数上限 | **60 臂 / kind** | 10 轮 × 6 臂（`SAT_MAX_ARMS_PER_KIND`） |
| 超限动作 | **只报不删** | 有片的叶子保留可回溯性；越线进自检 WARN |
<!-- GK-CAP:END -->

## 4. 生命周期

```
append ──► per-arm 叶子(ttl_s) ──► 过期 ──► 墓碑 reclaimed_ts ──► 片级可回收
   │                                  │
   └─ claim_anchor（判活锚）           └─ 片仍被 live claim 持有 ⟹ held（不回收）
```

| 阶段 | 判定 | 入口 | 默认 |
|:--|:--|:--|:--|
| 写入 | — | `gk_satellite.append()`（内部调用，用户无感） | 立即 |
| 判过期 | per-arm `ttl_s`（缺省取租约 3600s） | `gk_satellite.reclaim()` | **dry-run** |
| 判活 | write-claims 台账覆盖该片 ⟹ `held`（即便过期也不回收） | 同上；台账不可读 ⟹ **fail-closed 拒刀** | — |
| 片级可回收 | 该 kind **全臂**过期 **且** 无 held 臂 | 同上输出 `shard_reclaimable` | 只标记 |
| 索引 GC | 删「已墓碑」与「片不存在（悬空）」叶子 | `state --satellite --apply` | **dry-run** |
| 片文件物理删除 | **未实装**（append-only 可回溯优先） | — | — |

**回收命令**（口径：只报不删是缺省）

```bash
bash gatekeeper-cli.sh state --satellite                 # 只读验：悬空/孤儿/越容量
bash gatekeeper-cli.sh state --satellite --apply         # 索引 GC（只删墓碑/悬空）
bash gatekeeper-cli.sh state --map                       # state 地图（只读）
bash gatekeeper-cli.sh state --archive-isolated [--apply] # 隔离 state 可逆归档（缺省只出计划）
```

`state --archive-isolated` 的**四重判据**（全满足才归档）：形态 ∈ `domain|legacy_plan`；不是当前
`STATE_FILE`；`mtime` 早于 TTL（默认 7 天）；不被 live write claim 覆盖（台账不可读 ⟹ 全拒）。
动作 = `os.replace` 把 state **连同全部旁挂**搬到 `state-archive/<UTC-ts>/` 并写 `manifest.json`，
**永不 `rm`** ⟹ 误判可原路搬回。

**健康面**：`self-check` 第 38 项 `satellite`（悬空叶子 / 孤儿片 / 越 60 臂 ⟹ WARN，
修复入口 = `state --satellite --apply`）。这是**体检**不是自动回收 —— 破坏性动作仍需显式 `--apply`。

## 5. 体积水位与三条腿

<!-- GK-WALL:START（由 scripts/gk_docgen_facts.py 生成，勿手改） -->
整墙 = `STATE_SIZE_WALL = 2,621,440 B`（2.5 MB）。水位阈值单源 = `gk_json_utils.WALL_LEVELS`：

| 水位 | level | 含义 | 行为 |
|:--|:--|:--|:--|
| ≥ 50% | `notice` | 过半 | `state_size_report` / `two_legs_report` 出 `WALL_NOTICE` 告警 |
| ≥ 80% | `warn` | 警告 | 同上 `WALL_WARN` |
| ≥ 90% | `trim` | 需要裁剪 | 同上 `WALL_TRIM`；先裁再裁决 |
| ≥ 95% | `block` | **触发拦截** | `dump_state` **拒写**（`STATE_WALL_BLOCK`） |

拦截的两条边界：**收缩写放行**（新体积 < 磁盘现有体积 ⟹ 裁剪正在生效，不自锁）；
逃生舱 `GK_STATE_WALL_BLOCK=0`（显式放行，留 stderr 痕迹）。

**三条腿**（各自独立的裁剪线，按墙的比例定价，各 5%、合计 15%，留 85% 给其余字段）：

| 腿 | 落点 | 比例 | 值 | 越线动作 |
|:--|:--|:--|:--|:--|
| `subagent_history` | `gatekeeper-cli.sh` `_HIST_MAX_BYTES` | 5% | 128 KB | 最旧条目出窗 → 落 history 片 |
| `task_pipeline` | `gk_json_utils.TASK_PIPE_MAX_BYTES` | 5% | 128 KB | 已决条目出窗 → 落 pipeline 片 |
| `ecc_findings` | `gk_json_utils.ECC_MAX_BYTES` | 5% | 128 KB | closed 可归档；open 超 `ECC_MAX_OPEN(96)` 就地溢出 |

另两个计数轴：`ECC_MAX_ENTRIES=256`、`ECC_MAX_OPEN=96`。运维覆盖口：`GK_STATE_TRIM_KB=<KB>`
（只覆盖 history 腿，不改源码）。
<!-- GK-WALL:END -->

## 5.1 接线：FIFO / 归档 / 余烬 / 熵 各自吃什么

| 消费方 | 读什么 | 说明 |
|:--|:--|:--|
| `state --map` / `--archive-isolated` | `<state>*` 全部旁挂 | `gk_state_map.sidecars()` 前缀带尾点（`<basename>.`）⟹ 两个归档文件随 state 一起统计/搬迁 |
| `audit --state`（`subagent_unlogged` / `fifo_archives`） | `subagent_history` + 两个 `<state>.*-archive.jsonl` | history 归档参与对账；`fifo_archives` 报两个归档的条数与最近一条（只读、不并回窗口） |
| 熵（`gk_gate_entropy`） | **live 20 条** `rejected_edits` + `subagent_history[-5:]` | 只吃窗口、**不吃归档**：旧信号不复燃（设计如此，非断线） |
| 余烬（`gk_ember_replay`） | `.gatekeeper.ember.<phase>.json` 快照 + `archive_digest`（两个归档的条数/字节/sha256） | 相位切换抓整份 state；归档只带摘要、不并入 `gate_data_full`，两机制保持分离 |
| hook 删除闸 | `.gatekeeper.state*` 的 `rm/unlink/shred/truncate`、`find -delete` | 2026-11-01 接线：直接删台账/归档即 BLOCK；可逆归档唯一入口 = `state --archive-isolated` |

> 现状：两个归档都是 append-only 证据，**已有读面**（`audit --state` 的 `fifo_archives` +
> `--map` 可见 + 余烬摘要）；熵刻意只吃 live 窗口，避免旧违规复燃。

## 6. 快速判读

```bash
bash gatekeeper-cli.sh state                 # 当前 state 原文（JSON）
bash gatekeeper-cli.sh state --satellite     # 卫星索引一致性/容量（只读）
bash gatekeeper-cli.sh finding status        # 台账计数 + repo_index（只读）
bash gatekeeper-cli.sh self-check            # 含卫星/水位等体检项
```

- 看到 `WALL_TRIM` ⟹ 先 `state --satellite --apply` + `finding archive-closed`，再继续。
- 看到 `dangling` 叶子 ⟹ 片文件已不在（归档不可回溯），GC 会清掉这些登记。
- 卫星片**不要手工编辑**：append-only + 索引叶子两处必须一致，唯一写者是 `gk_satellite`。

## 7. 蓝鳍瞭望（Bluefin Watch，`state --watch`）

代号取「蓝色大肥鱼」→ 蓝鳍（仅作标识，无其它含义）。双向、只读的**跨平台缺陷探针**：两侧
（WSL / Windows）各跑一套 agent，同一份代码在两套解释器、路径形态、换行与大小写语义下必然分叉；
探针在**任一侧**都能跑，输出同一份规范化快照，供两侧互比。

```bash
bash gatekeeper-cli.sh state --watch                      # 只读快照（JSON）
bash gatekeeper-cli.sh state --watch --save .zthl/watch/wsl.json    # 显式落盘（read_only=false）
bash gatekeeper-cli.sh state --watch --compare .zthl/watch/win.json # 与另一侧快照比对 ⟹ divergences[]
```

探针与 zthl-adapter §ZH4 的对应（`issues[].os_ref`）：

| 探针 | 看什么 | os_ref |
|:--|:--|:--|
| `path_forms` / `state_owner` | `C:/…` vs `/mnt/c/…` 归一后是否同一棵树；各 state 顶层 `worktree` | OS-6 |
| `worktree_git_view` | 每个 worktree 的 `.git` 文件形态（win/posix/dir）与本侧可解析性 | OS-6 |
| `line_endings` | CRLF-only / 混合换行文件（跨侧编辑高频污染） | OS-5 |
| `identity_literals` | `/mnt/<d>/Users/…`、`<X>:\Users\…` 字面量 | OS-6 |
| `runtime_artifacts` | 运行期产物是否在跟踪面（state/scopes/log/analysis） | OS-5 |
| `remote_whitelist` | 远端 vs `_ALLOWED_REMOTE_PATTERNS` | OS-7 |
| `case_sensitivity` | 大小写变体路径是否可解析（Windows 不敏感 / WSL 敏感） | — |
| `interpreter` | 本侧解释器、pytest 可用性（分档测试腿真假 SKIP 的判据） | — |

比对口径：路径一律先 `_canon`（`\→/`、小写、去尾斜杠、`/mnt/c`→`c:`）再比；`_local` 负责转回本侧
可解析形态。默认零写入；`--save` 才落盘，且快照里 `read_only=false` 自证。

**边界（不是阶段门，是读/写/输出三道门）**：

| 面 | 规则 |
|:--|:--|
| 准入（hook） | Gate R0.15：默认只放「本侧 + 脱敏」；`--reveal`、`--cross-side` 需 `GK_WATCH_APPROVED=1` |
| 读 | 不进 `.trae-cn/`、`AppData/Roaming/Trae CN/`、`.keys/`（约束 M；连文件名都不进快照） |
| 写 | `--save` 只允许 `<skill_dir>/.zthl/watch/**` 或 `~/.trae/watch/**`；其余 `SAVE_PATH_NOT_ALLOWED`（exit 2） |
| 输出 | 身份字面量默认脱敏为 `<user>`；`--reveal` 才回显全文 |
| 访客记录 | `.gatekeeper.state.watch-log.jsonl`（技能目录 sidecar，默认与 state 同目录；`GK_SKILL_DIR` 可覆盖；append-only；allow/deny 都记） |

访客记录字段：`ts / event(observe|observe-hook) / decision / reason / scope(own|cross-side) /
reveal / cmd / cwd / user / host / pid / agent_id / counts / snapshot_sha256`。
**不存快照明文**，只存摘要（sha256）⟹ 事后可证明「看过什么」，又不再复制一份敏感快照。

落点为何是技能目录 sidecar（而非 `gate_data` / `~/.trae` / hook 的 cwd）：① 与 edit-log/budget-log/step-log
同族，`state --map` 的 `sidecars` 自动可见；② 每 worktree 一份 ⟹ 两侧/各 worktree 的访客天然隔离；
③ 命中 `^\.gatekeeper\.state` 导出排除 ⟹ 不进开源包；④ 高频 append 不占 state 的 2.6MB 墙；
⑤ 两端同源（`gk_watch` 与 hook 都按 `GK_SKILL_DIR` > 技能目录解析）⟹ 不落 agent 的 cwd，不污染被治理项目。

不设阶段门：只读诊断恰恰要在 state 坏掉/阶段未推进时可用；把它绑到 stage 上会让故障期失去观测手段。



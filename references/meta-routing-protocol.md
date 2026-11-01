# META 路由协议 — 工作发现 + 仓库路由 + 阶段推进

**核心机制**: CLI 从文档中的 `<!-- META ... -->` 注释块读取配置，确定"去哪干活"、"干什么活"、"怎么干"。这构成了一个**基于文档的 repo-路由 + phase-发现 + project-type 门禁**的治理协议。

> **唯一路由声明（2026-09-02 用户定案）**：元数据路由不是文档而是**唯一可执行路由中枢**。
> 全部路由判定收编进 `scripts/gk_route_center.py` 五层链（L1 plan → L2 repo → L3 worktree →
> L4 state → L5 narrow），CLI 只做参数传递与结果消费，**不内嵌路由逻辑**。state 解析链 /
> worktree 匹配 / 窄任务查询均为中枢的分级延展，层层咬合不分散。本文档是协议规格（契约），
> 执行入口是 `gk_route_center.py`（CLI 命令经 `_read_plan_metadata` / `_resolve_repo_path` /
> `resolve-state` / `resolve-narrow` 薄壳调用）。旧独立机制（gk_state_route.py 直接 CLI 调用、
> gk_narrow_route.py 直接 CLI 调用）已收编，降为中枢内部实现模块。

## 五层路由链（gk_route_center.py）

```
┌─ L1 plan 解析   resolve_plan()    META 块 + 5 层金字塔搜索 + standing 常驻检测
│                                     （迁自 gatekeeper-cli.sh _read_plan_metadata）
├─ L2 repo 解析   resolve_repo()    target_repo → 绝对路径（迁自 _resolve_repo_path）
├─ L3 worktree 检测 resolve_worktree() feature worktree 定位（迁自 cmd_discover）
├─ L4 state 解析链 resolve_state()   plan 指针 → 域解析 → worktree 匹配 → 归属校验 → 默认
│                                    （迁自 gk_state_route.py，含 2026-09-01 worktree 匹配路由
│                                     与 2026-09-15 A6-P2 域解析）
└─ L5 窄任务查询  resolve_narrow()   narrow_tasks[] → tier / poison / schema
                                     （迁自 gk_narrow_route.py）
```

**L4 state 解析链优先级（显式优先 + 隐式兜底）**：
1. **plan 指针**（`.gatekeeper.plan`，`discover --plan` 写入，TTL 24h）→ 显式绑定，尊重不纠正
**1b. 域解析（2026-09-15，A6-P2 接线；REV-3 质询修订）**：计划声明的 `META.state_domain`
   （或 CLI **`--domain <repo>.<plan>`** 直传）→ **当前 state 同级**
   `.gatekeeper.state.<token>`。位置 = plan 指针**之后**（运行时显式绑定优先）、worktree
   匹配**之前**（计划侧显式声明优先于隐式启发式）。
   **落点解析单一事实源 = `gk_finding.resolve_domain_state`**（与 finding 写入点同源，禁第二套
   基址）。**纪律同构：声明域后不静默回退**（目标不存在 → `error:STATE_DOMAIN_MISSING`；
   token 非法 → `STATE_DOMAIN_TOKEN_INVALID`；域与当前 state 已携带域不符 →
   `STATE_DOMAIN_MISMATCH`）。**开关 `GK_STATE_DOMAIN_ROUTE`：省略 = `1`（启用）；
   `=0` ⟹ 跳过本步（完全回原链）**；无域声明 ⟹ 不触发（既有行为不变）。
   **执行侧入口**：`discover --plan` 读未声明/声明的 `META.state_domain` 决定隔离 state 名
   （声明 ⟹ `.gatekeeper.state.<token>` 并写入指针，后续任意 CLI 进程经启动块跟随 ⟹
   `STATE_FILE` 端到端切换；未声明 ⟹ 沿用 plan-basename）。域 state 缺失时 `discover --plan`
   **fail-closed**（不建指针、不静默回退）。启动块消费 `resolve-state` 时：`source=state_domain`
   **会被采用**（不再因 `corrected=False` 而静默丢弃）；`error` 字段**不再被吞**——显式打印
   `ERROR[state-routing]` 并 `exit 1`（逃生口 `GK_STATE_DOMAIN_ROUTE=0`）。
   **REV-5（第三/四轮质询）七点收敛**：
   - **命名基址 = 契约常量 `_DEFAULT_STATE_FILE`**（默认 state 落点）——域块**不得**内联字面量；
     改常量即改全局基址，与 `gk_finding.resolve_domain_state` 同源。
   - **指针 `domain` 标记**：域绑定成功时指针写 `"domain":"<token>"` ⟹ 开关 `=0` 的进程在启动块
     **拒绝跟随域化指针**（否则 kill switch 被上一次写入的指针跨进程绕过）。缺失该标记 = 非域绑定
     —— **迁移期提示**：REV-3/REV-4 写下的旧域化指针无此字段（实测 0 例）；**不可**改用
     "state_file 形态判定"替代（`.gatekeeper.state.<suffix>` 与 legacy plan-basename 同形，会误伤）。
   - **fail-closed 路径清理旧指针**：`PLAN_NOT_FOUND` / `STATE_DOMAIN_MISSING` /
     `STATE_DOMAIN_UNRESOLVED` / **`cd SKILL_DIR` 失败（后置）** / **no META phases（后置）**
     一律 `rm` 旧指针 ⟹ "失败"语义 = **没有绑定**（而非"回到上一次的账本"）。
     `STATE_DOMAIN_EXPLICIT_CONFLICT` 出口**不适用**——显式 env 态下本进程无指针通道，既不写也不删。
   - **显式 env `STATE_FILE` + 域声明**：原为 stderr WARN 后继续（成功 JSON 无域字段 ⟹ 只读
     stdout 的调用方无从得知域未生效 = 静默降级）；现 **fail-closed**
     `STATE_DOMAIN_EXPLICIT_CONFLICT`（显式 state 恰等域化 state 时幂等放行）。
   - **开关口径（禁过度声明）**：`=0` ⟹ 回到**REV-3 前**解析链 = 三个**主动采用点**跳过
     （1b 步 / `discover --plan` 域绑定 / 启动块域指针跟随）；指针文件**保留不删**（可逆）。
     **不声称"域不可达"**：域化 state 仍在 `_collect_state_files` 的 `.gatekeeper.state.*` 候选集内，
     worktree 匹配 / 安全网仍可能选中它（REV-3 前既有语义）。
2. **worktree 匹配**（state.worktree 指向开发 worktree → 隔离 state 精确匹配唯一候选）
   —— discover --plan 的隐式补位：无指针时自动咬合（2026-09-01 新增）
3. **归属校验**（state.worktree ∈ 技能仓库/开发 worktree 树 = 合法）
4. **safety_net**（冲突 + 恰好 1 候选 → 纠正；多候选 → WARN 不武断）

**CLI 契约**：`python3 scripts/gk_route_center.py route-all|resolve-plan|resolve-repo|resolve-worktree|resolve-state|resolve-narrow`（JSON on stdout，exit 0/1；resolve-narrow 失败 exit 3/4）。`resolve-state` 支持
`--plan-file <p>` / `--plan-override <p>`：未传 `--domain` 时读其 `META.state_domain` 兜底。测试：`scripts/test_gk_route_center.py`（用例数以该文件为准，勿在文档硬编码计数——原记 23 已漂移）。

## 完整形态（10 个字段）

```html
<!-- META
phases: <空格分隔的阶段列表>
target_repo: <仓库标识符>
project_type: standard|standing|analysis
worktree_needed: true|false
state_domain: <repo>.<plan>    <!-- 可选；worktree_needed=true 时必填（2026-09-04 B） -->
source_docs: <逗号分隔路径>     <!-- 可选；计划引用的源文档清单（2026-09-10） -->
work_dir: <工作目录路径>
commit_obj: <主要改动文件>
commit_format: <commit 前缀格式>
review: <审查方式>
-->
```

> **state_domain（2026-09-04 新增，worktree↔state 域绑定声明）**：worktree 流程的计划
> （`worktree_needed: true`）**必须声明** `state_domain` —— 域 token 形如 `<repo>.<plan>`
> （如 `gatekeeper.r7`），对应 A2/D5 域化命名 `.gatekeeper.state.<repo>.<plan>` 前向接口；
> 未声明 → 路由只能靠启发式兜底（worktree 匹配/归属/safety_net），运行时五层校准
> （`calibrate`）state_domain 检查项 FAIL 驱动存量计划迁移。无 worktree 计划可省略（SKIP）。

> **source_docs（2026-09-10 新增，序列节点安全网前置接源）**：计划引用的源文档清单
> （逗号分隔路径，如 `docs/plans/x.md, docs/analysis/y.md`）。`advance` 自动读取该字段并
> 转交 `node-guard --source-docs` → CLI 逐条校验磁盘可读性 → 注入 `ctx.source_docs`
> （**缺失清单**，空 = 齐备）→ 序列节点安全网 G 谓词判定"源文档"前置。
> **路径基准（F-REV-15，2026-09-10）**：**相对路径按仓根（`MAIN_REPO_WSL`）解析**，不是调用方
> cwd——`cmd_advance` 不 `cd`，cwd 随调用点漂移会误判缺（实测同一相对路径在主仓目录判 OK、
> 在技能目录判 missing）；绝对路径原样判定。
> **读哪份计划（F-REV-14，2026-09-10）**：META 源 = **state 绑定计划**（计划指针 `plan` 字段 /
> 隔离 state 文件名后缀，见 `gk_route_center.resolve_bound_plan`）；未绑定 → 回退默认 PLAN_FILE。
> **未声明 → 该前置归 info 跳过**（不再恒判缺/在 `GK_GUARD_STRICT=1` 下恒 BLOCK）；
> 声明且存在不可读路径 → fail-closed 并在 `missing` 中回显具体缺失路径。
> 解析实现 = `gk_route_center._META_FIELDS` + `gatekeeper-cli.sh _read_plan_metadata`
> （`META_source_docs`）+ `cmd_advance` guard 注入点 + `gk_node_guard.missing_source_docs`
> 磁盘校验；测试见 `test_gk_route_center.py` / `test_gk_node_guard.py`。

也支持 inline 格式：

```html
<!-- META phases: R1 R2 R3 -->
<!-- META target_repo: gatekeeper -->
<!-- META project_type: standard -->
```

## 路由协议三要素

| 要素 | 负责 | 代码位置 | 说明 |
|:--|:--|:--|:--|
| **发现 (Discovery)** | `_read_plan_metadata` | gatekeeper-cli.sh | 5 层金字塔搜索 + `docs/plans/*-standing-plan.md` 常驻计划自动检测 |
| **路由 (Routing)** | `_resolve_repo_path` | `gatekeeper-cli.sh::_resolve_repo_path` | META `target_repo` → 仓库绝对路径，unknown 报错 |
| **推进 (Advance)** | `cmd_advance` + `cmd_discover` | `gatekeeper-cli.sh::cmd_advance` / `::cmd_discover` | `project_type` 决定 STAGE_0-5 标准机 / 自定义直接推进 |

## project_type 三种模式

| type | 含义 | advance 行为 | 门禁 | 适用场景 |
|:--|:--|:--|:--|:--|
| `standard` | 标准项目阶段 | STAGE_0→5 完整 stage 机 | 全部 gate | 门卫 R1-R13、Bridge R1-R14 |
| `standing` | 常驻生态阶段 | 跳过 stage 机，直接写 phase 名；AUDIT-* 和 RED-* 阶段有 advance hooks（数据采集），非完全空跑；F8.1 push 门禁通过 _verify_remote 强制执行 | 跳过 | ECO-*、RED-*（技能自维护）；AUDIT-*（审计署下属，归属域见下方 `Phase 命名规范` 表） |
| `analysis` | 分析审查阶段 | 跳过 stage 机，直接写 phase 名 | 跳过 | ECC-*（分析审查项） |

## Phase 命名规范

| 前缀 | 类型 | 示例 | 说明 |
|:--|:--|:--|:--|
| `R` | 标准项目阶段 | R1, R2, R5.5, R6 | 门卫 / Bridge 的标准 R 序列 |
| `ECO-` | 常驻生态阶段 | ECO-RESEARCH, ECO-EDIT, ECO-VERIFY, ECO-DOC（旧名 SCAN/READ/AUDIT 为别名） | 技能自维护，常驻可用 |
| `ECC-` | 分析审查阶段 | ECC-C1, ECC-P1-1 | 外部项目交叉分析 |
| `AUDIT-` | 审计子流程 | AUDIT-STATE, AUDIT-MEMORY, AUDIT-CROSSR, AUDIT-REPORT | 审计子流程（蓝队防御）, 含 F81-01~08 远端门禁审计；**归属域 = `skill.2026-10-04-audit-bureau-plan`**（D7-B，2026-10-27） |
| `RED-` | 红队子流程 | RED-SCOPE, RED-SURFACE, RED-CONSTRAINTS, RED-EXPLOIT, RED-POSTEX, RED-REPORT, RED-HINT, RED-HOOK, RED-PY, RED-POISON, RED-REGISTRY, RED-GHOST, RED-COVERAGE | 红队子流程（红队攻击）, 13 阶段全链路（2026-08-28 扩展 4 确定性扫描站: poison/registry/ghost/coverage） |
| `F81-` | F8.1 审计检查项 | F81-01~F81-08 | 远端白名单门禁审计 (8 项检查 point, 属于 AUDIT-* 子流程), 含 _verify_remote / git-workflow / RunCommand / STATE_FILE |

> **归属声明（2026-10-26，D7-A）**：审计序列（`AUDIT-*` 相位）自 2026-10-26 起**整建制并入审计署**，本计划只保留相位表；审计署正本 = `docs/plans/2026-10-04-audit-bureau-plan.md`。
>
> **D7-B 派发归属落刀（2026-10-27，owner 裁 J1+S1）**：`_ROUTES["audit"]` / `_HINT_PHASES[AUDIT-*]` 增 `owner` 字段（值 = 上述正本的 `state_domain`），`route_map` 透传；**不搬迁 state、不改节点集/分发方式**（被审证据仍留在被审 state）。账务侧 J1：`credit-ledger.ref` 只接 `raise.id`，finding id 一律拒写（`outcome_ref_namespace_violation`）。

## 5 层金字塔搜索路径

```
层1: ${MAIN_REPO_WSL}/docs/plans/           # 主项目计划目录
层2: ${MAIN_REPO_WSL}/docs/plan-backup/      # 主项目计划备份
层3: ${SKILL_DIR}/references/                # 技能参考文档
层4: ${SKILL_DIR}/references/docs/plan-backup/# 技能备份
层5: {user}/.codex/docs/plans/               # 用户计划目录（{user} = 用户目录；ZTHL、batch8 等）
常驻: ${SKILL_DIR}/docs/plans/*-standing-plan.md  # 常驻计划（auto-detect）
```

搜索规则: 按顺序搜索。每层按 mtime 降序，读文件前 2000 字节，找到第一个包含 `META` 关键词**且 phases 非空（2026-09-02 增强：残缺 META 跳过继续搜，防空壳计划当路由输入）**的文件即停止。常驻计划在 5 层未命中时自动检测。

## 路由白名单基线（代码常量权威值，doc-align route_center_alignment ⑦ 校验）

> **目的（2026-09-02 红队 D 层）**：白名单常量 = 代码内硬编码信任锚点，篡改代码常量即防线失效。
> 本文档登记权威值 → doc-align 比对「代码常量值 == 文档声明值」。
> 篡改代码常量不改文档 → ⑦ 检出；代码+文档同改 → git 层（tracked 文件 diff，运行仓库 HEAD 完整性）检出。
> ⚠️ 修改下述任一常量的代码实现时**必须同步更新本表**，否则 doc-align 报 WARN。

| 常量 | 权威值（代码必须等于此处） | 用途 / 比对方式 |
|:--|:--|:--|
| `MAIN_REPO_WSL` | `<home>/Downloads/<workspace>/spz_gatekeeper_project` | L2 主仓库锚点（单值精确比对） |
| `DEV_WORKTREE_ROOTS` | `<home>/.trae/worktrees/`, `c:/users/hp/.trae/worktrees/`, `/root/.config/superpowers/worktrees/` | L3/L4 worktree 前缀白名单（集合比对；route_center + state_route 双副本同值，⑤ 另查副本一致） |
| `SEARCH_DIRS` | `{main}/docs/plans/`, `{main}/docs/plan-backup/`, `{skill}/references/`, `{skill}/references/docs/plan-backup/`, `{user}/.codex/docs/plans/` | L1 5 层金字塔搜索目录（集合比对，顺序按上方搜索规则；`{user}` = `gk_host_paths.user_home()`） |

## 仓库路由表

| `target_repo` | 解析路径 | 角色 |
|:--|:--|:--|
| `gatekeeper` | `$MAIN_REPO_WSL` | 门卫 C++ 项目（格式验证引擎） |
| `skill` | `$SKILL_DIR` | 技能仓库（spz-gatekeeper-r-sequence） |
| `bridge` | `$BRIDGE_DIR` (默认 ~/.codex) | Bridge Python 运行时 |
| `bridge-r-phase` | `$BRIDGE_R_PHASE_DIR` | Bridge R-phase 管线 (9-gate HL pipeline) |
| `git-workflow` | `$GIT_WORKFLOW_DIR` (默认 ../git-workflow) | git 工作流管理 (推送/分支/worktree/安全审查/CI cron, 待 CLI 集成) |
| `supply-chain` | `$SUPPLY_CHAIN_DIR` | 供应链集群 |
| `research` | `$RESEARCH_DIR` | 研究集群 |
| `agentteams` | `<用户目录>\Downloads\AgentTeams-1.2.2` | 外部参考项目（GOAI 基点 / 吸收来源 / 论文第二引擎） |
| `aig` | `<用户目录>\Downloads\AI-Infra-Guard-4.5.1` | 外部参考项目（R-T8+ 红队引擎） |

**unknown → 报错**，不再静默 fallback。新增仓库只需加一条 `case`。

## 插件路由表

> **插件 = 按需加载的探测式验证工具**（确定性验证引擎——生成交 LLM，工具只做验证/分析/审计）。
> 统一入口 `cmd_migrate`（`_CMD_REG[migrate]=cmd_migrate|partial|any|`，无副作用）。
> 加载/调用协议见 `plugin-loading-test-framework.md`（插件加载安全网协议）；本表是其元数据路由层的登记。
> （2026-08-25 计划质询收敛 + 晚修订：吸收 Cordis declarative configuration + sandbox + revertible effects（write 分级）。
>  探测式插件 = 单位效应特值；完整循环 `define→run→stop→undefine` 已落地，见下方映射表。）

| 插件 | 路由标识 | 加载链 | 安全网 | 能力白名单 | 门禁 | 调用点 |
|:--|:--|:--|:--|:--|:--|:--|
| bashpy-migrate | `migrate` | WSL PATH → WSL python3 → ZTHL_BASHPY_DIR → Windows Python | gk_bashpy_loader（`_RELEASE_PINS` SHA256 pin；hash_mismatch/error 拦截） | `analyze\|verify\|audit`（**拒绝未知子命令**） | partial/any | **STAGE 0 START baseline 扫描**（迁移炸弹清单，对齐 gitnexus pre-R baseline）→ batch8 R-T6 迁移执行 → **STAGE 3 L3.5 死代码门禁二次扫描**（shellcheck_scan 确定性实现，对齐 gitnexus post-R delta） |

**插件配置（声明式，对齐 Cordis §5.2.1 declarative configuration）**:
- dev 源: `ZTHL_BASHPY_DIR`（环境变量优先 + 已知路径回退，Windows/WSL 双形态）
- 发布哈希表: `_RELEASE_PINS`（只登记 CI 跑过的产物）
- 状态对账: `load_status()` → `{source, version, hash_verified, detail, module_file}`（对齐 Cordis configuration reconciliation）
- 升级提示: `load_status()` 新字段 `upgrade_pending=True`（last-check 缓存有更高版本）→ `cmd_migrate` WARN 提示运行 `scripts/gk_bashpy_upgrade.py upgrade`（平滑升级命令，2026-08-26）。

**能力边界（对齐 Cordis §6.3 Access Control and Sandboxing + DSH 400G 事故教训）**:
- 子命令白名单（拒绝未知）——插件无法通过未登记入口获得能力
- 探测式定位（只读分析/验证，无破坏性 shell 权限）
- 供应链 SHA256 pin——发布包被篡改即拦截，永不静默使用哈希不匹配的包

## 插件完整循环映射（复刻 DSH/Cordis，2026-08-25 落地）

> 数学依据（cordis 论文，本地副本）：
> - **Theorem 7（式 10）**：合法插件必须满足 `recover(track(f,g)(γ,φ)) = recover(γ,φ)`——卸载后回到加载前状态。
> - **Theorem 10**：单位效应 `𝜂Γ ≔ γ ↦ (γ, idΓ)`（`f=id, g=id`）——探测式插件的精确特值，recover 平凡成立。
> - **Definition 74**：entry 六字段（id/url/isolate/intercept/config/disabled）——manifest 注册表声明结构。

| DSH/Cordis 循环步 | 论文公式 | 落地实现 | 防护含义 |
|:--|:--|:--|:--|
| `cordis_define` | Definition 74 entry | `gk_plugin_manifest.py` `MANIFESTS` 注册表 + `validate_manifest()` | **define 门禁**：未登记/disabled/write 无 undo → 拒绝加载（Theorem 7 代码级强制） |
| `cordis_run` | track（Definition 3，式 6） | `load_plugin()`：校验通过 → 记录 sys.path 快照 → 注入 dev 源 → 登记 `_ACTIVE` | 加载副作用被快照记录（逆 g 的最小实现） |
| `cordis_stop` | recover（Definition 6，式 9） | `unload_plugin()`：撤销注入 → 恢复 sys.path → 注销登记（幂等） | 卸载后回到加载前（recover 不变性） |
| `cordis_undefine` | — | `unload_plugin()` 注销 `_ACTIVE`；`cap <pid> <cap>` 白名单检查 | 未登记插件无法获得能力（§6.3 能力最小化） |

**write 分级（Theorem 7 防护论证）**：DSH 400G 事故 = 插件执行无逆写效应、违反 Theorem 7。
- `write: false`（探测式，`f=id`）：免逆，recover 平凡成立——bashpy-migrate 当前形态。
- `write: true`（可写插件）：**必须声明 `undo` 卸载回滚钩子**，否则 `validate_manifest()` 拒绝加载。
  业务 undo 由调用点在写操作完成后显式执行（manifest.undo 声明其位置）；`unload_plugin()` 只回滚加载副作用快照。

**调用链（cmd_migrate，2026-08-25 接入）**：子命令 → `cap` 白名单检查（manifest.intercept 单一事实来源）→ `validate` define 门禁 → `load_status()` SHA256 安全网（gk_bashpy_loader）→ 插件执行。

**DSH 生态插件对接**（2026-08-25 实测 v0.1.1-rc.2 源码）：结构同构（cordis.yml entry ↔ MANIFESTS），
`unload_plugin` ↔ `cordis_stop` 语义精确一致；差异 = DSH 支持运行时自进化（cordis_define→run），
本表是管理方预登记（防御姿态）。npm 供应链 pin 已封（`url: npm:` 强制 `config.integrity`，
`TestNpmSupplyChainPin`）；loader 侧 integrity 对账留待首个真实 npm 插件接入。
详见 plugin-loading-test-framework.md §4.4。

### 推送路由 — F8.1 远端白名单

```
gatekeeper project:   atomgit.com/<user>/spz_gatekeeper.git
                     github.com/spz-ecosystem/spz_gatekeeper.git
skill repo:           atomgit.com/<user>/spz-gatekeeper-r-sequence.git
git-workflow repo:    github.com/spz-ecosystem/git-workflow.git
ALLOWED patterns:     github.com/spz-ecosystem/*
                     atomgit.com/<user>/*

推送路径:
  gatekeeper-cli.sh push confirm → _verify_remote() → ALLOWED_PATTERNS check
  git-workflow push → gatekeeper CLI delegation (if available) → _verify_remote()
                  → native git push fallback (no gate, Bridge standalone mode)
  git-workflow pr-fallback → independent white list check (git-workflow.sh 白名单检查)
  Direct git push via RunCommand → PreToolUse matcher (IDE hook, `~/.trae-cn/hooks.json` 全局 catch-all)
```

## 状态指纹

| 指纹 | 类型 | 生成方式 | 用途 |
|:--|:--|:--|:--|
| `hash_static` | 固定 | `SHA256(git_remote_url)[:8]` | 仓库身份验证、search 标注 |
| `hash_dynamic` | 实时 | `git rev-parse --short HEAD` | 状态版本验证、block_log 归属 |

**已知静态哈希**:

| 仓库 | 哈希 |
|:--|:--|
| skill (spz-gatekeeper-r-sequence) | `d67b1270` |
| gatekeeper (spz_gatekeeper_project) | `15309a63` |

## 路由表 — 5 种输入 → 3 轮映射

> **此路由为决策路由**：由人类 agent 根据信号类型选择走对应路径。CLI 不自动检测输入类型。
> CLI 只执行具体的 `discover` / `advance` / `guard-edit` 命令。路由判断是决策层（本文档），执行层（CLI）不包含路由逻辑。
>
> **依赖关系**: `release-check` 命令是路由的前置依赖。它扫描 8 个 tracked 项目的 GitHub release，发现新版本/安全事件时产出 JSON 报告，为外部冲击路由提供触发信号。
> 每天早上 9 点由应用级 Cron 调度器自动触发（`cmd_cron` → `cron_jobs.py` → `cron_scheduler.py`），完成后自动写入 `_latest_release_check` 到 state.json。Agent 随后可手动执行 `advance ECO-RESEARCH` 处理检测到的冲击。
> **新增功能**: I9 红队发现自动回写 ECC-FINDING（ECO-DOC 阶段触发）+ I3 成就系统（advance 成功时自动发放 10 种成就）。

```
输入类型             →    第一站          →    第二站          →    第三站          →    所属轮
──────────────────────────────────────────────────────────────────────────────────────────────
外部冲击              standing (ECO)      analysis (ECC)       standard (R-T)       外循环
（spz新版本/CVE等）    ECO-RESEARCH        ECC-IMPACT-*         升级执行

内部需求              standing (ECO)      analysis (ECC)       standard (R-T)       内循环
（新功能/架构变更）     ECO-RESEARCH→EDIT   ECC-PLAN-*           R-T* 执行

技能自维护            standing (ECO)      ECC-FINDING-* 登记   R-T* 执行            内循环（强制，hook Gate 8 保障）
（target_repo=skill）  ECO-RESEARCH→EDIT   修复→复验→回流        STAGE_0-5

插件生态维护          standing (ECO)      analysis (ECC)       standard (R-T)       内循环
（自研插件迭代）       ECO-RESEARCH→EDIT   ECC-FINDING 登记     R-T* 执行 + 插件调用
                     插件作探测工具定位    归档进 R-T 序列      读取 ECC 继续调用插件
                     问题→写 ECC           （双序列交替）        执行（确定性工具层）

内部发现              analysis (ECC)      standing (ECO)       standard (R-T)       内循环
（执行中发现的问题）    ECC-FINDING-*       ECO-EDIT 计划更新     R-T* 执行

标准执行              standard (R-T*)     —                    —                    标准执行
（已有计划的任务）      STAGE_0-5

临时补丁              直通 CI             —                 —
```

### ECO 插件双循环（2026-08-26，ECO 质询收敛：单循环 → 双循环）

> 插件（zthl-bashpy-migrate）是独立仓库（GitHub `zthl-harness`）。ECO 计划质询（plan-refinement）
> 裁定：**单循环设计语义混乱，拆为两个循环**——循环 A 是泛化的生命周期维护（standing 驱动），
> 循环 B 是具体的任务执行（standard 调用）。当前只有 bashpy 插件，未来多插件共享循环 A 基础设施。

```
┌─ 循环 A：插件生命周期维护循环（standing 驱动，泛化，面向所有插件）────────┐
│  触发：发版信号（release-check）/ 新插件接入 / 安全事件 / 升级登记          │
│  ECO-RESEARCH ── release-check 检测插件 Release 新版本                      │
│      │        gitnexus analyze 插件仓库                                    │
│  ECC-FINDING：新版本/缺陷记录                                              │
│  （RESEARCH 内）读插件 CHANGELOG / CI / 代码变更                           │
│  ECO-EDIT：guard-edit 下更新升级配置/模板（升级登记 / 测试模板 / CI 模板） │
│  ECO-VERIFY：审计插件供应链状态（pin/integrity）                           │
│  ECO-DOC：同步插件测试框架 / CI 模板 / 路由                                │
│  维护对象：加载+运行时安全网 / 平滑升级机制 / 测试模板 / CI 模板 / 文档 /    │
│           问题分类学文档（权威源=插件 docs/migration-issues.md，技能侧      │
│           指针=references/bashpy-problem-taxonomy.md，双文档同步，仅限      │
│           文档更新禁止触碰循环逻辑；2026-08-27 合并，见分类学 §3/§I）       │
└────────────────────────────────────────────────────────────────────────────┘
┌─ 循环 B：插件任务执行循环（standard 调用，bashpy 具体）───────────────────┐
│  cmd_migrate → cap 白名单 → validate 门禁 → load_status 安全网             │
│  → 插件执行（analyze/verify/audit）→ 确定性输出                            │
│  → 问题分类学记录：verify 契约改进白名单（path 匹配）写入分类学类别；        │
│    audit --bomb 计数漂移上报循环 A（2026-08-27 新增维护任务，见分类学 §3） │
│  依赖：循环 A 维护的基础设施（已登记 pin / 已装插件）——非"循环 A 在跑"      │
└────────────────────────────────────────────────────────────────────────────┘
        ↕ 流转：插件功能迭代 = standard R-T* 执行 → 发版 → 循环 A 升级登记
          → 循环 B 用新版本（无热插拔：升级替换配置，重启进程生效）
```

**治理前置（worktree 不豁免）**：插件仓库登记进 `.gatekeeper.scopes.json`（marker 含主检出路径；
用 git-worktree 开发时**必须追加 worktree 路径片段 marker**，worktree 不豁免门禁）。
release-check 的 `cmd_release_check` tracked 列表含插件条目 → standing 自动检测新版本（发新 tag 即触发循环 A）。

**触发词**：插件发版 / 插件升级 / 登记 pin / 插件红队 / 新插件接入 —— 走循环 A；migrate 任务执行 —— 走循环 B。

## ECO 内部执行序列

> **ECO 循环是 standing 模式的执行引擎**。每个 Phase 必须完整走完 4 步，禁止跳过。

```
ECO-RESEARCH: 扫描 + 深读参考项目 (discover + gitnexus analyze/context/impact + subagent)
    ↓ advance
ECO-EDIT: 通过 CLI gate 编辑 (guard-edit + pre-tool-check → SearchReplace)
    ↓ advance (需要 adjudicate 先)
ECO-VERIFY: 审计检查 (audit --all + advance 门禁)
    ↓ advance
ECO-DOC: 文档同步 + Slow Update (docgen + update architecture)
```

**门禁规则**:
- ECO-EDIT → ECO-VERIFY: 需要 `adjudicate` 先执行（写入 human_calibration_log）
- ECO-VERIFY → ECO-DOC: 必须先 `audit --all`
- ECO-DOC → ECO-RESEARCH: 开始新循环（必须先 `docgen`）

> 旧站名 `ECO-SCAN` / `ECO-READ` / `ECO-AUDIT` 仍可 `advance`（别名归一，2026-10-28 A4）。
> **下文历史场景/示例中出现的旧站名一律按此归一**（SCAN+READ→RESEARCH，AUDIT→VERIFY）；示例命令可直接执行。

> **⚠ standing 豁免声明（2026-09-17 实测定案：以代码为准）**
>
> 本文档下述三处的「三步分工（勿截断）」**均为 standard（计划质询）口径，standing 常驻序列不适用**：
> ① §双循环+标准执行元循环 的「ECO-EDIT 计划质询序列」；② §执行流程「外循环：外部冲击处理」第 5 步；
> ③ §执行流程「内循环：内部发现处理」第 3 步。

| 步骤 | standard | **standing** | 证据（符号引用） |
|:--|:--|:--|:--|
| ① subagent 点检 | **硬门**（ECO-READ → ECO-EDIT） | **豁免** | `scripts/gk_advance.py` 该分支带 `ptype != "standing"` 条件；回归锁 `test_gk_advance.py::test_standing_eco_read_to_edit_no_plan_refinement_required` |
| ② `Skill(plan-refinement)` 完整质询 | 质量闸 | **按需**（本轮是否产出**计划增量**） | 无校验代码，仅 `_HINT_PHASES` 文案 |
| ③ `adjudicate` 密封 | **硬门** + F1-F7 必填 + plan-refinement 前置 | **硬门**，但上述两项**全豁免**（只需 `score∈[0,1]` + 非空 `decision`） | `scripts/gk_advance.py::_check_adjudicate` 的 `ptype != "standing"` 分支同时护住「前置点检」与「F1-F7 缺失校验」；反面控制 `test_gk_advance.py::test_nonstandard_eco_read_to_edit_requires_plan_refinement` |

> **含义**：standing 下 ECO-EDIT 段**只有 ③ 是硬门**；① 作为自律动作可保留（非门禁），② 由「本轮是否改计划」决定。
> 代价实测：一次 ① 点检 = 660,059 tok（cap 500,000，**+32%**）。
> 重组前景（前置 = 收敛评估器实装 + 计划质询公理验证；届时退场三项）见
> `docs/plans/2026-09-14-convergence-evaluator-subplan.md` 的「流程重组前置依赖」登记。
（热修）
```

## 双循环进化飞轮

```
                   外循环（吸收外部冲击）
  ┌───────────────────────────────────────────────┐
  │  外部冲击                                      │
  │  (zstd v1.7 / spz v3.1 / CVE-2026-xxxx)       │
  │       │                                        │
  │       ▼                                        │
  │  ECO-SCAN: 扫描冲击范围                          │
  │  ECO-READ: 分析 API 变更 + 安全影响              │
  │       │                                        │
  │       ▼                                        │
  │  ECC-IMPACT-YYYYMMDD: 记录冲击分析              │
  │       │                                        │
  │       ▼                                        │
  │  ECO-EDIT: 计划质询 + 让步打分                   │
  │       │                                        │
  │       ▼                                        │
  │  R-T*: 标准执行（升级/适配）                     │
  │       │                                        │
  └───────┴───────────────────────────────────────┘
                                      │
                         ┌────────────┘
                         ▼
                    内循环（驱动自我进化）
  ┌───────────────────────────────────────────────┐
  │  执行中发现                                    │
  │  (架构缺陷 / 流程漏洞 / 改进机会)                │
  │       │                                        │
  │       ▼                                        │
  │  ECC-FINDING-YYYYMMDD: 记录发现                │
  │       │                                        │
  │       ▼                                        │
  │  ECO-SCAN: 重新扫描上下文                        │
  │  ECO-EDIT: 计划更新 + 质询                       │
  │       │                                        │
  │       ▼                                        │
  │  ECC-PLAN-YYYYMMDD: 记录更新计划                │
  │       │                                        │
  │       ▼                                        │
  │  R-T*: 标准执行                                 │
  │       │                                        │
  └───────┴───────────────────────────────────────┘
```

## 双循环+标准执行 元循环

双循环 (standing, 计划探索) 和标准执行 (standard, 执行阶段) 构成一个**交替循环**——和 SkillOpt 的 epoch 模式同构。

> **RED 和 AUDIT 是正交子流程**，不从属于双循环+标准执行。它们可被任意 ECO 阶段触发，作为独立的红队攻击或蓝队防御审计流程运行。

> **ECO-EDIT 计划质询序列 = 三步分工（2026-08-15 补全 + 2026-08-26 统一入口，勿截断）**：
> 1. **subagent 点检**（`gatekeeper-cli.sh plan-refinement <plan> --task "<质询任务>"` = **统一入口**，2026-08-26 新增：preflight 前置产物检查 + 委托 `monitor --subagent` 写 `subagent_history`）= **门禁证据**，解锁 ECO-READ → ECO-EDIT；
> 2. **Skill(plan-refinement) 完整质询** = **质量闸**（brainstorming → plan-refinement → writing-plans，F1-F7 SCR + 魔鬼代言人 + 6维评分，产出 PASS 报告）——subagent 点检只是窄点检，不等于完整质询；主 agent 复用同一套协议评估 subagent 输出（四重角色：确定性交叉验证/双盲评分/divergence 调解/人类终裁）；
> 3. **adjudicate 密封** = **门禁证据**（ECO-EDIT → ECO-AUDIT 强制要求），把质询结论写入 `human_calibration_log`。
> 缺任一步，计划质询链即断裂：无点检 → advance ECO-EDIT 被拒；无 Skill 质询 → 质量闸空转；无 adjudicate → advance ECO-AUDIT 被拒。

```
  ┌─────────────────┐        ┌─────────────────┐
  │  双循环 (ECO)    │───────→│ 标准执行 (R-T)    │
  │   计划探索轮      │        │    执行轮        │
  │                  │        │                 │
  │  ECO-SCAN: 扫描  │        │  STAGE 0-5:     │
  │  ECO-READ: 审查  │        │  编码→CI→审查    │
  │  ECO-EDIT: 质询  │        │  →PR→合并→退休   │
  │  ECO-AUDIT: 计划 │        └────────┬────────┘
  │  ECO-DOC: 同步   │                 │
  └────────▲────────┘                 │
           │                          │
           │    ECO-DOC: 文档同步      │
           │    (baseline→final)      │
           └──────────────────────────┘
```

### 轮切规则

| 规则 | 说明 |
|:--|:--|
| **双循环产出** | ECO-AUDIT 质询报告 (收敛方案) + 注册表同步 |
| **标准执行入口** | 双循环收敛方案作为 STAGE 0 的输入 |
| **标准执行产出** | 代码提交 + CI 通过 + PR 合并 |
| **ECO-DOC 衔接** | 标准执行结束后同步 SKILL.md/extension-registry → 写回 baseline |
| **下一轮起点** | 读取上轮 ECO-DOC 的 final 作为新 baseline → 纵向对比 |

### 触发条件

| 信号 | 说明 |
|:--|:--|
| 双循环 ECO-EDIT 产出收敛方案 | → 触发标准执行 R-T* |
| 标准执行完成 | → ECO-DOC 同步结果 → 更新基线 |
| 标准执行中发现计划偏差 | 让步率 >30% → 中断执行，回到双循环重新规划 |
| 外部变化 | 新版本依赖 / 安全事件 / 架构变更 → 直接进入双循环 |
| **每轮双循环+标准执行构成一个完整元循环** | |

### 与 SkillOpt epoch 同构

| SkillOpt epoch | MPR 元循环 | 说明 |
|:--|:--|:--|
| 一轮 epoch | 双循环 + 标准执行 | 一个完整周期 |
| Edit budget (scheduler) | 双循环阶段任务数 | 这轮计划探索多少新东西 |
| Slow Update | ECO-DOC GitNexus delta | baseline vs final 纵向对比 |
| Best Snapshot | ECO-AUDIT 质询报告 | 这轮的最佳计划版本 |
| Rejected Buffer | B4 让步记录 + F1-F7 | 被砍掉的任务 = 负反馈 |
| 下一轮 epoch 输入 | ECO-SCAN 读取上轮 ECO-DOC final | Slow Update 信息来源 |

## 执行流程

### 外循环：外部冲击处理

```bash
# 1. 激活 standing plan
cd <skill dir>
bash gatekeeper-cli.sh discover
# → standing, r_phase: ECO-SCAN

# 2. 扫描冲击
bash gatekeeper-cli.sh advance ECO-SCAN
search --repo gatekeeper "zstd version"
search --repo skill "reference_projects"

# 3. 深度分析
bash gatekeeper-cli.sh advance ECO-READ
subagent "analyze zstd v1.7 API changes vs v1.6"

# 4. 记录冲击分析 → ECC-IMPACT-YYYYMMDD
#    创建 ECC-IMPACT-20260609-zstd.md (project_type: analysis)

# 5. 质询 + 决策（完整计划质询序列，勿在 subagent 点检后截断）
bash gatekeeper-cli.sh advance ECO-EDIT
# 5a. subagent 点检（门禁证据）— 写入 subagent_history，解锁 ECO-READ → ECO-EDIT
bash gatekeeper-cli.sh monitor --subagent "plan-refinement: <task>"
# 5b. Skill(plan-refinement) 完整质询（质量闸）— brainstorming → plan-refinement → writing-plans，
#     F1-F7 SCR + 魔鬼代言人 + 6维评分 → 得到 PASS 报告。subagent 点检≠完整质询。
# 5c. adjudicate 密封（门禁证据）— ECO-EDIT → ECO-AUDIT 强制要求
bash gatekeeper-cli.sh adjudicate --verdicts '{"F1":"PASS","F2":"WARN","F3":"PASS","F4":"PASS","F5":"WARN","F6":"PASS","F7":"PASS"}' --score 0.90 --decision "WARN: upgrade with verification" --impact references/ecc-impact-*.md

# 6. 记录冲击分析 → ECC-IMPACT-YYYYMMDD
#    创建 ECC-IMPACT-20260609-zstd.md (project_type: analysis)

# 7. 执行升级
bash gatekeeper-cli.sh advance R1-T1  # 如果 plan 中有对应任务
```

### 内循环：内部发现处理

```bash
# 1. 记录发现 → ECC-FINDING-YYYYMMDD
#    创建 ECC-FINDING-20260609-bypass.md

# 2. 重新进入 standing plan
bash gatekeeper-cli.sh advance ECO-SCAN
bash gatekeeper-cli.sh advance ECO-READ  # 审查当前上下文

# 3. 计划更新（完整计划质询序列，勿在 subagent 点检后截断）
bash gatekeeper-cli.sh advance ECO-EDIT
# 3a. subagent 点检（门禁证据）— 写入 subagent_history，解锁 ECO-READ → ECO-EDIT
bash gatekeeper-cli.sh monitor --subagent "plan-refinement: <task>"
# 3b. Skill(plan-refinement) 完整质询（质量闸）— F1-F7 SCR + 6维评分 → PASS 报告
# 3c. adjudicate 密封（门禁证据）— ECO-EDIT → ECO-AUDIT 强制要求
bash gatekeeper-cli.sh adjudicate --verdicts '{"F1":"PASS",...}' --score 0.90 --decision "..." --impact references/ecc-impact-*.md

# 4. 记录计划 → ECC-PLAN-YYYYMMDD
#    创建 ECC-PLAN-20260609-bypass-fix.md

# 5. 执行
bash gatekeeper-cli.sh advance R1-T1
```

### 标准执行（流程 D）

```bash
bash gatekeeper-cli.sh advance R1-T1 --check
bash gatekeeper-cli.sh advance R1-T1
bash gatekeeper-cli.sh guard-edit cpp/src/file.cc
```

#### STAGE 段职责与门禁来源（STAGE-DUTY-MAP，2026-10-29 / T3=A-1）

standard 六段（`STAGE_0→1 … STAGE_5→DONE`）的**唯一事实源**：每段一句话职责 + 该段转换的
硬门 gate-id 清单。机检 = `gk_doc_align.py::check_stage_duty_map`（挂 `run_all`）：本表与
`gk_advance.py::_structural_gates` 的 `fail()` 分支**双向比对**，漏登/多登/新增未登记均 FAIL。
gate-id 词表与 `fail()` 字面量的映射单源 = `gk_doc_align._GATE_ID_RULES`。

<!-- STAGE-DUTY-MAP:BEGIN -->
| 转换 | 职责 | gate-id |
|:--|:--|:--|
| STAGE_0→STAGE_1 | 建树并绑定工作分支（主分支禁止直进） | worktree_exists, branch_not_main, worktree_registered |
| STAGE_1→STAGE_2 | 提交前清场、分支命名齐备、CI 触发登记 | worktree_accessible, no_uncommitted_changes, branch_not_main, branch_nonempty, ci_trigger_registered |
| STAGE_2→STAGE_3 | 进入评审前须有真实改动（空 diff 视为 `--allow-empty` 绕过） | diff_nonempty |
| STAGE_3→STAGE_4 | 评审前声明 sprint 契约，且计划备份在场 | plan_backup_exists, sprint_contract_declared |
| STAGE_4→STAGE_5 | 合并校验（feature 须为 origin/main 祖先） | pr_merged |
| STAGE_5→DONE | 退役前的最终计划备份 | final_plan_backup_exists |
<!-- STAGE-DUTY-MAP:END -->

**门禁冗余实测（T4 产出物，2026-10-29 机检）**：
- 跨段重复谓词：`branch_not_main` ×2（0→1、1→2）；`plan_backup_exists` ×2（3→4、5→DONE，
  文案不同但同一谓词）；`gitnexus_fresh` ×3（3→4、4→5、5→DONE，均为 WARN，不入硬门词表）。
- 每段独有硬门：0→1 有 2、1→2 有 4、2→3 有 1、3→4 有 1、4→5 有 1、**5→DONE 有 0**
  ⟹ 结构合并（B）的现实上限是 **6→5**（`STAGE_5→DONE` 可并入 `STAGE_4→5`）；
  6→4 会丢独有硬门，须另裁。
- 与 standing 豁免表（本文件「standing 豁免声明」节）**零重叠**：那张表管 ECO-* 流程步骤
  （点检 / adjudicate），本表管 STAGE 转换的 git/文件状态门 ⟹「门禁去重」的合法删除集为空。

### 临时补丁（流程 C）

```bash
# 开 fix 分支 → 改代码 → push → CI → PR → merge → 删分支
```

## block_log 审计

所有 IDLE/DONE 状态下的拦截自动写入 `gate_data.block_log[]`：

```json
{"command":"pre-tool-check","reason":"stage=IDLE","timestamp":"2026-06-09T12:00:00Z"}
```

cap=100，满时丢弃最旧。用于论文选择压力数据测量。

## 应用实例

### 标准项目（门卫 C++）

```html
<!-- META phases: R1 R2 R3 R4 R5 R5.5 R6 -->
<!-- META target_repo: gatekeeper -->
<!-- META project_type: standard -->
<!-- META worktree_needed: true -->
```

```bash
bash gatekeeper-cli.sh discover           # auto-detect from 202 plan
bash gatekeeper-cli.sh advance R1
bash gatekeeper-cli.sh guard-edit cpp/src/file.cc
```

### 常驻生态（技能自维护）

```html
<!-- META
phases: ECO-SCAN ECO-READ ECO-EDIT ECO-AUDIT ECO-DOC AUDIT-STATE AUDIT-MEMORY AUDIT-CROSSR AUDIT-REPORT RED-SCOPE RED-SURFACE RED-CONSTRAINTS RED-EXPLOIT RED-POSTEX RED-REPORT RED-HINT RED-HOOK RED-PY
target_repo: skill
project_type: standing
worktree_needed: false
-->
```

```bash
bash gatekeeper-cli.sh discover           # auto-detect via *-standing-plan.md
bash gatekeeper-cli.sh advance ECO-READ
bash gatekeeper-cli.sh guard-edit gatekeeper-cli.sh
```

### 分析审查（ECC 交叉分析）

```html
<!-- META
target_repo: skill
project_type: analysis
phases: ECC-C1 ECC-C2 ECC-P1-1 ECC-P1-2
worktree_needed: false
-->
```

```bash
bash gatekeeper-cli.sh discover --plan references/ecc-analysis-findings.md
bash gatekeeper-cli.sh advance ECC-C1
bash gatekeeper-cli.sh reflect ECC-C1
```

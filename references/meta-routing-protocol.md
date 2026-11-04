# META 路由协议 — 工作发现 + 仓库路由 + 阶段推进

<!-- DOC-META
title: META 路由协议 — 工作发现 + 仓库路由 + 阶段推进
type: reference
owner: spz-gatekeeper-r-sequence
status: public
updated: 2026-11-02
-->

**核心机制**：CLI 从文档中的 `<!-- META ... -->` 注释块读取配置，确定「去哪干活 / 干什么活 / 怎么干」。这是**基于文档的 repo 路由 + phase 发现 + project-type 门禁**协议。

> **唯一路由声明（2026-09-02 定案）**：元数据路由不是普通文档，而是**唯一可执行路由中枢**。
> 全部路由判定收编进 `scripts/gk_route_center.py` 五层链（L1 plan → L2 repo → L3 worktree →
> L4 state → L5 narrow）；CLI 只做参数传递与结果消费，**不内嵌路由逻辑**。
> 本文档是协议规格（契约），执行入口是 `gk_route_center.py`（`resolve_plan` / `resolve_repo` /
> `resolve_worktree` / `resolve_state` / `resolve_narrow`）。

## 1. 五层路由链（`scripts/gk_route_center.py`）

```
┌─ L1 plan 解析   resolve_plan()     META 块 + 5 层金字塔搜索 + standing 常驻检测
├─ L2 repo 解析   resolve_repo()     target_repo → 绝对路径（未知 → 报错，不静默回退）
├─ L3 worktree    resolve_worktree() feature worktree 定位（含 route 白名单）
├─ L4 state 解析  resolve_state()    plan 指针 → 域解析 → worktree 匹配 → 归属校验 → 默认
└─ L5 窄任务查询  resolve_narrow()   narrow_tasks[] → tier / poison / schema
```

**L4 state 解析链优先级**：

1. **plan 指针**（`.gatekeeper.plan`，`discover --plan` 写入，TTL 24h）——显式绑定，尊重不纠正。
2. **域解析**（`META.state_domain` 或 `--domain <repo>.<plan>`）——当前 state 同级
   `.gatekeeper.state.<token>`；位置 = 指针之后、worktree 匹配之前。开关
   `GK_STATE_DOMAIN_ROUTE`（省略 = 启用，`=0` 跳过并保留指针）。
3. **worktree 匹配**——`state.worktree` 指向开发 worktree 时精确匹配唯一候选。
4. **归属校验**——`state.worktree` ∈ 技能仓库/开发 worktree 树 = 合法。
5. **safety_net**——冲突且恰好 1 候选 → 纠正；多候选 → WARN，不武断。

**CLI 契约**：

```bash
python3 scripts/gk_route_center.py route-all|resolve-plan|resolve-repo|resolve-worktree|resolve-state|resolve-narrow
```

`resolve-state` 支持 `--plan-file <p>` / `--plan-override <p>`；未传 `--domain` 时读
`META.state_domain` 兜底。测试：`scripts/test_gk_route_center.py`（用例数以文件为准，
本文档不硬编码计数）。

## 2. META 完整形态（11 个字段）

```html
<!-- META
phases: <空格分隔的阶段列表>
target_repo: <仓库标识符>
project_type: standard|standing|analysis
worktree_needed: true|false
state_domain: <repo>.<plan>    <!-- 可选；worktree_needed=true 时必填 -->
source_docs: <逗号分隔路径>     <!-- 可选；计划引用的源文档清单 -->
edit_budget_declared: <整数>    <!-- 可选；计划声明的编辑预算（硬上限内） -->
work_dir: <工作目录路径>
commit_obj: <主要改动文件>
commit_format: <commit 前缀格式>
review: <审查方式>
-->
```

字段单源 = `scripts/gk_route_center.py::_META_FIELDS`（11 项）：

`phases, target_repo, project_type, worktree_needed, work_dir, commit_obj, commit_format,
review, state_domain, source_docs, edit_budget_declared`

- **state_domain**：worktree 流程的计划必须声明；域 token 形如 `<repo>.<plan>`。
  未声明 → 只能走 worktree 匹配/归属/safety_net 启发式；无 worktree 计划可省略。
- **source_docs**：逗号分隔路径；`advance` 读取后交 `node-guard --source-docs` 逐条校验
  磁盘可读性，注入 `ctx.source_docs`（缺失清单）。相对路径按**仓根**解析，不是调用方 cwd；
  未声明 → 该前置归 info 跳过。
- **edit_budget_declared**：计划声明的编辑预算（`int ∈ [0, DECLARED_HARD_CAP]`），
  实现 = `scripts/gk_route_center.py::edit_budget_declared`。

也支持 inline 格式：

```html
<!-- META phases: R1 R2 R3 -->
<!-- META target_repo: skill -->
<!-- META project_type: standard -->
```

## 3. 路由协议三要素

| 要素 | 负责 | 代码位置 | 说明 |
|:--|:--|:--|:--|
| **发现 (Discovery)** | `resolve_plan()` | `scripts/gk_route_center.py` | 5 层金字塔搜索 + `docs/plans/*-standing-plan.md` 常驻计划自动检测 |
| **路由 (Routing)** | `resolve_repo()` | `scripts/gk_route_center.py` | `target_repo` → 绝对路径；未知 → 报错（不静默 fallback） |
| **推进 (Advance)** | `cmd_advance` / `cmd_discover` | `gatekeeper-cli.sh` → `scripts/gk_advance.py` | `project_type` 决定 STAGE_0–5 标准机 / 直接写 phase |

## 4. project_type：`standard` 与「非 standard」

**`project_type` 是开放字符串，不是封闭三值枚举**。代码只分两支：
`== "standard"` 走 STAGE_0→5 的 stage 机；**其余任意值**走非 standard 直推（直接写 phase 名）。

| type | 含义 | advance 行为 | 门禁 | 典型场景 |
|:--|:--|:--|:--|:--|
| `standard` | 标准项目阶段 | STAGE_0→5 完整 stage 机 | 全部 gate | 门卫 / Bridge 的 R 序列 |
| `standing` | 常驻生态阶段 | 跳过 stage 机；AUDIT-* / RED-* 有 advance hooks | 跳过 stage 门；序列门仍生效 | ECO-*、RED-*、AUDIT-* |
| `analysis` | 分析审查阶段 | 跳过 stage 机 | 跳过 | ECC-*（分析审查项） |
| 其它（如 `plan` / `skill-maintenance` / `paper-maintenance`） | 自由标签 | 同非 standard 直推 | 由具体 phase 钩子决定 | 计划/维护类工作 |

> 2026-11-02 修正：旧版写成「三种模式」并当作穷举，与代码不符（代码只判 `standard`/非
> `standard`；`plan` 等标签实际在用）。新增 `project_type` 不需要改代码，除非它需要专属门禁。

## 5. Phase 命名规范

| 前缀 | 类型 | 示例 | 说明 |
|:--|:--|:--|:--|
| `R` | 标准项目阶段 | R1, R2, R5.5, R6 | 门卫 / Bridge 的标准 R 序列 |
| `ECO-` | 常驻生态阶段 | ECO-RESEARCH, ECO-EDIT, ECO-VERIFY, ECO-DOC（旧名 SCAN/READ/AUDIT 为别名） | 技能自维护，常驻可用 |
| `ECC-` | 分析审查阶段 | ECC-C1, ECC-P1-1 | 外部项目交叉分析 |
| `AUDIT-` | 审计子流程 | AUDIT-STATE, AUDIT-MEMORY, AUDIT-CROSSR, AUDIT-REPORT | 蓝队防御；归属域 = `skill.2026-10-04-audit-bureau-plan` |
| `RED-` | 红队子流程 | RED-SCOPE, RED-SURFACE, RED-CONSTRAINTS, RED-EXPLOIT, RED-POSTEX, RED-REPORT, RED-HINT, RED-HOOK, RED-PY, RED-POISON, RED-REGISTRY, RED-GHOST, RED-COVERAGE, RED-DIFF, RED-INTEGRITY, RED-AIG | **16 阶段**；每站必须有 `monitor-schemas/<NODE>.json`，缺件 = `scripts/gk_package_integrity.py` error |
| `F81-` | F8.1 审计检查项 | F81-01~F81-08 | 远端白名单门禁审计（AUDIT-* 子流程） |

节点名单一真源 = `scripts/gk_node_guard.py::route_map()`；本表只做命名说明。
新增/删除站点必须同批更新 `route_map`、`monitor-schemas/` 与 `scripts/gk_chain.py`。

## 6. 5 层金字塔搜索路径

`scripts/gk_route_center.py::SEARCH_DIRS`（占位符在运行时展开）：

```
层1: {main}/docs/plans/                 # 主项目计划目录
层2: {main}/docs/plan-backup/           # 主项目计划备份
层3: {skill}/references/                # 技能参考文档
层4: {skill}/references/docs/plan-backup/
层5: {user}/.codex/docs/plans/          # 用户计划目录（{user} = 用户主目录）
常驻: {skill}/docs/plans/*-standing-plan.md
```

搜索规则：按顺序搜索；每层按 mtime 降序，读文件前 2000 字节，找到第一个包含 `META`
**且 `phases` 非空**的文件即停止（残缺 META 跳过，防空壳计划当路由输入）。常驻计划在
5 层未命中时自动检测。

## 7. 仓库路由（运行时解析）

`resolve_repo` 内建表（`target_repo` → 路径）：

| `target_repo` | 解析路径 | 角色 |
|:--|:--|:--|
| `gatekeeper` | 主仓（运行时解析，见下） | 门卫项目 |
| `skill` | `$SKILL_DIR` | 技能仓库（spz-gatekeeper-r-sequence） |
| `spz2glb` | `$SPZ2GLB_DIR` 或主仓同级 `spz_ecosystem_simplified/tools/spz_to_glb` | 3D/GLB 工具 |
| `bridge` | `$BRIDGE_DIR` 或 `~/.codex` | Bridge Python 运行时 |
| `bridge-r-phase` | `$BRIDGE_R_PHASE_DIR` 或技能同级 `bridge-r-phase` | Bridge R-phase 管线 |
| `supply-chain` | `$SUPPLY_CHAIN_DIR` | 供应链集群 |
| `research` | `$RESEARCH_DIR` | 研究集群 |

**主仓解析优先级**：`GK_MAIN_REPO`（绝对路径）→ `state.target_repo` → `META target_repo`
→ `git rev-parse`。相对路径 / 含 `..` 一律拒绝；解析为空 ⟹ 依赖主仓的检查 fail-closed。
**不在文档中写死主机绝对路径**；内建表未命中时回退 scopes `read_repo` 别名（单一事实源）。

## 8. 插件路由（按需加载的探测式工具）

> 插件 = 按需加载的确定性验证/分析/审计工具；入口 `cmd_migrate` 等由 `_CMD_REG` 注册。
> 加载/调用协议见 `references/plugin-loading-test-framework.md`；插件登记表见 `references/extension-registry.md`。

当前随包插件：

| 插件 | 源 | 能力 | 备注 |
|:--|:--|:--|:--|
| bashpy-migrate | `pip:zthl-bashpy-migrate` / dev `${ZTHL_BASHPY_DIR}` | analyze / verify / audit | 外部包；SHA256 pin + `load_status()` |
| paper-review | `builtin:scripts/gk_paper_review.py` | 论文写作投稿前置模拟评审（投稿前自检） | 仅私仓随附（公开包条件登记自动摘除） |
| git-workflow | `../git-workflow/scripts/git-workflow.sh` | 推送/分支/worktree/安全审查 | 独立技能；外部源 |

**manifest 契约**（`scripts/gk_plugin_manifest.py`）：`id == key`、`intercept` 非空、
`write: true` 必须声明 `undo`（Theorem 7 卸载可逆）；`builtin:` 源缺失 = 包完整性 error；
外部源（pip/npm/独立技能）只 WARN，不属本包缺件。

## 9. 推送路由 — F8.1 远端白名单

`_ALLOWED_REMOTE_PATTERNS` 默认放行常见托管站（任意 owner）：
`github.com/`、`gitlab.com/`、`atomgit.com/`、`gitee.com/`、`codeberg.org/`。
组织可用 `GK_PUSH_REMOTE_ALLOW`（逗号/冒号分隔）收紧；未知 host / 本地路径仍拒绝。

```
push confirm → _verify_remote() → ALLOWED_PATTERNS
git-workflow push → gatekeeper CLI（可用时）→ _verify_remote()
                  → native git push fallback（无门，Bridge standalone）
Direct git push via RunCommand → PreToolUse hook（用户级 hooks.json）
```

## 10. 状态指纹

| 指纹 | 类型 | 生成方式 | 用途 |
|:--|:--|:--|:--|
| `hash_static` | 固定 | `SHA256(git_remote_url)[:8]` | 仓库身份验证、search 标注 |
| `hash_dynamic` | 实时 | `git rev-parse --short HEAD` | 状态版本验证、block_log 归属 |

已知静态哈希（只作稳定标识，不含本机路径/账号）：

| 仓库 | 哈希 |
|:--|:--|
| skill（spz-gatekeeper-r-sequence） | `d67b1270` |
| gatekeeper | `15309a63` |

## 11. 路由表 — 输入 → 轮次

| 输入类型 | 第一站 | 第二站 | 第三站 | 所属轮 |
|:--|:--|:--|:--|:--|
| 外部冲击（新版本/CVE） | standing：`ECO-RESEARCH` | analysis：`ECC-IMPACT-*` | standard：`STAGE_0–5` | 外循环 |
| 内部需求（新功能/架构） | `ECO-RESEARCH → ECO-EDIT` | `ECC-PLAN-*` | `STAGE_0–5` | 内循环 |
| 技能自维护（`target_repo=skill`） | `ECO-RESEARCH → ECO-EDIT` | `ECC-FINDING-*` 登记 | `STAGE_0–5` | 内循环 |
| 插件生态维护 | `ECO-RESEARCH → ECO-EDIT` | `ECC-FINDING` 登记 | `STAGE_0–5` + 插件调用 | 内循环 |
| 内部发现（执行中） | analysis：`ECC-FINDING-*` | `ECO-EDIT` 计划更新 | `STAGE_0–5` | 内循环 |
| 标准执行（已有计划） | `STAGE_0–5` | — | — | 标准执行 |
| 临时补丁 | 直通 CI | — | — | — |

`release-check` 是外部冲击路由的前置信号：扫描 tracked 项目 release，写入
`_latest_release_check`；cron 可每日触发。

## 12. ECO 内部执行序列

```
ECO-RESEARCH: 扫描 + 深读参考项目（discover + gitnexus analyze/context/impact + subagent）
    ↓ advance
ECO-EDIT:     CLI gate 下编辑（guard-edit + pre-tool-check → SearchReplace）
    ↓ advance（需先 adjudicate）
ECO-VERIFY:   审计检查（audit --all + advance 门禁）
    ↓ advance
ECO-DOC:      文档同步 + Slow Update（docgen + update architecture）
```

门禁：

- `ECO-EDIT → ECO-VERIFY`：先 `adjudicate`（写 `human_calibration_log`）。
- `ECO-VERIFY → ECO-DOC`：先 `audit --all`。
- `ECO-DOC → ECO-RESEARCH`：先 `docgen`。

旧站名 `ECO-SCAN` / `ECO-READ` / `ECO-AUDIT` 仍可 `advance`（别名归一，2026-10-28 A4）；
下文示例统一使用现行站名。

### standing 豁免声明（以代码为准）

| 步骤 | standard | standing | 证据 |
|:--|:--|:--|:--|
| ① subagent 点检 | **硬门**（RESEARCH → EDIT） | **豁免** | `scripts/gk_advance.py` 的 `ptype != "standing"` 分支 |
| ② `Skill(plan-refinement)` 完整质询 | 质量闸 | **按需**（本轮是否产出计划增量） | `_HINT_PHASES` 文案 |
| ③ `adjudicate` 密封 | **硬门** + F1–F7 必填 + 质询前置 | **硬门**，但①②豁免（`score∈[0,1]` + 非空 `decision`） | `scripts/gk_advance.py::_check_adjudicate` |

## 13. STAGE 段职责与门禁来源（STAGE-DUTY-MAP）

standard 六段（`STAGE_0→1 … STAGE_5→DONE`）的唯一事实源：每段一句话职责 + 该段转换的
硬门 gate-id 清单。机检 = `scripts/gk_doc_align.py::check_stage_duty_map`（挂 `run_all`）：本表与
`scripts/gk_advance.py::_structural_gates` 的 `fail()` 分支**双向比对**，漏登/多登/新增未登记均 FAIL。
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

**门禁冗余实测（T4）**：跨段重复谓词 `branch_not_main` ×2、`plan_backup_exists` ×2；
每段独有硬门 0→1 有 2、1→2 有 4、2→3 有 1、3→4 有 1、4→5 有 1、5→DONE 有 0
⟹ 结构合并的现实上限是 6→5；6→4 会丢独有硬门。

## 14. 执行流程（现行站名）

### 外循环：外部冲击处理

```bash
# 1. 激活 standing plan
bash gatekeeper-cli.sh discover

# 2. 扫描冲击
bash gatekeeper-cli.sh advance ECO-RESEARCH
bash gatekeeper-cli.sh search --repo gatekeeper "<impact keyword>"

# 3. 记录冲击分析（ECC-IMPACT-*），进入编辑
bash gatekeeper-cli.sh advance ECO-EDIT
bash gatekeeper-cli.sh monitor --subagent "plan-refinement: <task>"
bash gatekeeper-cli.sh adjudicate --verdicts '{"F1":"PASS","F2":"WARN","F3":"PASS","F4":"PASS","F5":"WARN","F6":"PASS","F7":"PASS"}' \
  --score 0.90 --decision "WARN: upgrade with verification" --impact references/ecc-impact-<date>.md

# 4. 验证 → 文档 → 标准执行
bash gatekeeper-cli.sh advance ECO-VERIFY
bash gatekeeper-cli.sh advance ECO-DOC
bash gatekeeper-cli.sh advance STAGE_0
```

### 内循环：内部发现处理

```bash
# 1. 记录发现（ECC-FINDING-*）
# 2. 回到 standing
bash gatekeeper-cli.sh advance ECO-RESEARCH
bash gatekeeper-cli.sh advance ECO-EDIT
bash gatekeeper-cli.sh monitor --subagent "plan-refinement: <task>"
bash gatekeeper-cli.sh adjudicate --verdicts '{"F1":"PASS",...}' --score 0.90 --decision "..." --impact references/ecc-impact-<date>.md
# 3. 进入标准执行
bash gatekeeper-cli.sh advance STAGE_0
```

### 标准执行

```bash
bash gatekeeper-cli.sh advance STAGE_0 --check
bash gatekeeper-cli.sh advance STAGE_0
bash gatekeeper-cli.sh guard-edit <file>
```

### 临时补丁

```bash
# 开 fix 分支 → 改代码 → push → CI → PR → merge → 删分支
```

## 15. block_log 审计

IDLE/DONE 状态下的拦截写入 `gate_data.block_log[]`（ring 上限
`_BLOCK_LOG_MAX = 24`；另有 `hook_block_log` 记 BLOCK 意图）：

```json
{"command":"pre-tool-check","reason":"stage=IDLE","timestamp":"2026-06-09T12:00:00Z"}
```

## 16. 应用实例

### 标准项目

```html
<!-- META phases: R1 R2 R3 R4 R5 R5.5 R6 -->
<!-- META target_repo: gatekeeper -->
<!-- META project_type: standard -->
<!-- META worktree_needed: true -->
```

```bash
bash gatekeeper-cli.sh discover
bash gatekeeper-cli.sh advance STAGE_0
bash gatekeeper-cli.sh guard-edit <file>
```

### 常驻生态（技能自维护）

```html
<!-- META
phases: ECO-RESEARCH ECO-EDIT ECO-VERIFY ECO-DOC AUDIT-STATE AUDIT-MEMORY AUDIT-CROSSR AUDIT-REPORT RED-SCOPE RED-SURFACE RED-CONSTRAINTS RED-EXPLOIT RED-POSTEX RED-REPORT RED-HINT RED-HOOK RED-PY RED-POISON RED-REGISTRY RED-GHOST RED-COVERAGE RED-DIFF RED-INTEGRITY RED-AIG
target_repo: skill
project_type: standing
worktree_needed: false
-->
```

```bash
bash gatekeeper-cli.sh discover
bash gatekeeper-cli.sh advance ECO-RESEARCH
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
bash gatekeeper-cli.sh discover
bash gatekeeper-cli.sh advance ECC-C1
```

## 双循环+标准执行（已合并，保留锚点）

> 旧章节名仅作锚点保留；内容已合并到 §11（输入路由）、§12（ECO 序列）与 §14（执行流程）。
> 「双循环」不再作为独立机制描述：现行实现 = standing 四站 + standard 六段，RED/AUDIT 为正交子流程。

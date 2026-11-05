# Extension Registry — 扩展注册表

<!-- DOC-META
title: Extension Registry — 扩展注册表
type: reference
owner: spz-gatekeeper-r-sequence
status: public
updated: 2026-11-05
-->

> **本文件是什么**：扩展的**登记表** + 添加/修改扩展的 SOP + 校验命令。
> **不是什么**：不是实现说明。每张表都标注**事实源**；正文以代码/阶段文档为准，本文件只做索引与对账。
>
> **2026-11-05 全面重写**（旧表已与实现漂移，逐条列出以便审计）：
> 1. **命令表**：原表列了 3 条从未实装的命令（`ci-stats` / `ci-security` / `setup-local`，仅 planned），
>    又把 `ember-replay-audit` 当独立命令（实为 `replay --ember` 模式），且缺 20+ 条现行命令
>    （`audit` / `finding` / `trace` / `attribution` / `workers` / `project-register` …）。
>    现改为**从 `_CMD_REG` 生成**，不再手抄。
> 2. **审查层**：原审查层表只到 L7，且标题与现行序列不符（L1 实为 Git history/`audit --crossr`，
>    不是 "Git Integrity"；L2 实为 Plan conformance，不是 "Code-to-Spec"），并缺 L8/L9/L10。
>    现以 `references/stage-3-review.md` 的 L1-L10 序列为事实源。
> 3. **模型表**：原表写 `v4-flash` / `v2.6` 等一代模型名，已过期 ⟹ 本文件不再复制模型清单。
> 4. **优化器 ①-⑪ 表**：R5.5 时期的历史映射，现行流程已改为 R 序列 + 双循环，移入 §6 历史附录。

---

## 1. 命令面（事实源 = `gatekeeper-cli.sh::_CMD_REG`，共 52 条）

### CLI 命令

字段原样取自注册串 `fn|gate_level|stage_constraint|side_effects`（中文仅为注释，不改变枚举值）：
**门禁级** = `_dispatch` 前的门禁强度枚举（none/partial/full）；**阶段约束** = 允许运行的阶段；
**副作用面** = 需要登记的写类副作用（计费与审计按该字段取数）。

| 命令 | 实现函数 | 门禁级 | 阶段约束 | 副作用面 |
|:--|:--|:--|:--|:--|
| discover | `cmd_discover` | none | any | — |
| state | `cmd_state` | none | any | — |
| migrate | `cmd_migrate` | partial | any | — |
| swe-rb | `cmd_swe_rb` | partial | any | 写 state |
| guard-edit | `cmd_guard_edit` | full | any | — |
| pre-tool-check | `pre_tool_check` | partial | any | — |
| advance | `cmd_advance` | full | active-r（需活跃 R 相位） | 写 state |
| node-guard | `cmd_node_guard` | none | any | — |
| monitor | `cmd_monitor` | partial | any | — |
| stage-detail | `cmd_stage_detail` | none | any | — |
| balance | `cmd_balance` | none | any | — |
| self-check | `cmd_self_check` | none | any | — |
| calibrate | `cmd_calibrate` | none | any | — |
| doc-align | `cmd_doc_align` | none | any | — |
| paper-review | `cmd_paper_review` | partial | any | 写 state |
| help | `cmd_help` | none | any | — |
| moa-aggregate | `cmd_moa_aggregate` | none | any | — |
| set-key | `cmd_set_key` | none | any | 写密钥 |
| docgen | `cmd_docgen` | none | any | 写 state |
| reflect | `cmd_reflect` | partial | active-r（需活跃 R 相位） | — |
| appeal | `cmd_appeal` | full | active-r（需活跃 R 相位） | 权限升级 |
| escalate | `cmd_escalate` | full | active-r（需活跃 R 相位） | 权限升级 |
| resolve | `cmd_resolve` | full | active-r（需活跃 R 相位） | 写 state |
| replay | `cmd_replay` | none | any | — |
| ember | `cmd_ember` | none | any | — |
| pr-score | `cmd_pr_score` | partial | any | 写 state |
| cron | `cmd_cron` | none | any | 写 state |
| push | `cmd_push` | full | any | git push |
| ci-status | `cmd_ci_status` | none | any | — |
| state-patch | `cmd_state_patch` | none | any | 写 state |
| ci-diagnose | `cmd_ci_diagnose` | none | any | — |
| check-changes | `cmd_check_changes` | none | any | — |
| apply-worktree | `cmd_apply_worktree` | partial | any | 写 state |
| pre-check | `cmd_pre_check` | none | any | — |
| t-star | `cmd_t_star` | none | any | 写 state |
| workers | `cmd_workers` | none | any | — |
| commit | `cmd_commit` | none | active-r（需活跃 R 相位） | git 写 |
| search | `cmd_search` | none | any | — |
| release-check | `cmd_release_check` | none | any | — |
| plan-refinement | `cmd_plan_refinement` | partial | any | 写 state |
| plan-lint | `cmd_plan_lint` | none | any | — |
| anchor-rebase | `cmd_anchor_rebase` | none | any | 写 state |
| model-probe | `cmd_model_probe` | none | any | — |
| phase-probe | `cmd_phase_probe` | none | any | — |
| adjudicate | `cmd_adjudicate` | none | any | 写 state |
| project-register | `cmd_project_register` | partial | any | 写 state |
| audit | `cmd_audit` | none | any | 写 state |
| finding | `cmd_finding` | none | any | 写 state |
| achievements | `cmd_achievements` | none | any | 写 state |
| context | `cmd_context` | none | any | 写 state |
| trace | `cmd_trace` | none | any | — |
| attribution | `cmd_attribution` | none | any | — |

### 对账与新增纪律

**对账方式**（本表与代码不一致即视为漂移）：

```bash
bash gatekeeper-cli.sh help                 # 命令面（cli-protocol.md 为文案单源）
python scripts/check_tool_cfg.py            # 工具面（hook 白名单 vs 实际工具）
python scripts/gk_doc_align.py              # 文档交叉引用漂移（含本篇锚点）
```

> 新增命令必须同时改三处：`_CMD_REG`（注册）→ `references/cli-protocol.md`（文案/参数）
> → 本表（本节由 `_CMD_REG` 生成，重跑生成器即可）。漏任一处由上面的对账命令兜住。

---

## 2. 审查层（事实源 = `references/stage-3-review.md` §一次性 L1-L10 完整序列）

| ID | 名称 | 车道 | 一句话 |
|:--|:--|:--|:--|
| L1 | Git history | 确定性 | `audit --crossr` 跨 R 一致性 + git 并发/工作流双字段 |
| L2 | Plan conformance | LLM | `--crossrev`：先 preflight B/L3 基线，再以图谱证据审查计划符合性 |
| L3 | GitNexus baseline | 确定性 | `monitor --gitnexus` 聚合 + PDG 可达性（死代码第二关） |
| L4 | 上游依赖版本检查 | 确定性 | `reference-projects/{project}.yaml` 对照 |
| L5 | Blind spots | 确定性 | `project_rules.md §Red Flags` 逐条 + taint 补 hook 盲区 |
| L6 | Architecture sync | 确定性 | `doc-align` 静态检查器（含符号实存 + CALLS 入边） |
| L7 | Security posture | 确定性 | 供应链 import 未解析扫描 + hook 审计 |
| L8 | Hook 部署 | 确定性 | `self-check` hook 项 + 走私向量 A/B/C 回归 |
| L9 | 安全网 | 确定性 | `monitor --local` 三 items（l9_runtime_safenet / gatechain_prereq / entropy_appeal） |
| L10 | 红队引擎 | 确定性 | `audit --red` 15 阶段（含 RED-INTEGRITY 产品完整性） |

> 新增/调整审查层：改 `stage-3-review.md` 的序列 → 同步本表 → `doc-align` 复核。
> 层号是**评审序列位置**，不是 CLI 命令；不要为某一层新增同名命令。

---

## 3. 阶段面（不在本文件登记）

- 六段职责与转换硬门：`references/meta-routing-protocol.md §13 STAGE-DUTY-MAP`
  （机检 = `gk_doc_align.check_stage_duty_map`，与 `gk_advance._structural_gates` 双向比对）。
- 阶段细节：`references/stages.md` + `stage-0…stage-5b`。

## 4. 模型 Provider（不在本文件登记）

模型名、默认 provider、降级链属**运行时配置**，事实源是 `scripts/` 下的 provider 解析与
环境变量（`DEEPSEEK_API_KEY` / `MIMO_API_KEY` 等）。旧表把型号写死在文档里，换代即过期 ——
本文件不再复制；需要看当前值用：

```bash
bash gatekeeper-cli.sh state | rg -i 'provider|model'
bash gatekeeper-cli.sh model-probe        # 元数据层指纹 + 行为层周期（resolved=false fail-loud）
```

## 5. 添加扩展的 SOP

| Step | 扩展类型 | 必改文件 |
|:--|:--|:--|
| 1 | CLI 命令 | `_CMD_REG` → `references/cli-protocol.md` → 本文件 §1（重跑生成器） |
| 2 | 审查层 | `references/stage-3-review.md` 序列 → 本文件 §2 |
| 3 | 阶段转换硬门 | `gk_advance._structural_gates` → `meta-routing-protocol §13` 表（`doc_align` 双向比对） |
| 4 | 插件（探测式工具） | `scripts/gk_plugin_manifest.py::MANIFESTS` → `references/plugin-loading-test-framework.md` |
| 5 | 文档面 | `references/README.md` 索引 + `gk_docgen_facts.py` 分类映射（否则导出期事实块对不上） |

**验证**（提交前必须全绿）：

```bash
python scripts/gk_doc_align.py          # 引用链/锚点漂移
python scripts/gk_docgen_facts.py --check
python scripts/check_tool_cfg.py
```

## 6. 历史附录（仅存档，不是现行契约）

- **R5.5 优化器组件 ①-⑪**：Reflect/Edit/Gate/Buffer/Slow Update/Scheduler/Protected Regions/
  Best Snapshot/CI-CD Optimizer/WASM Engineering/Human Optimizer + Flow B wrapper。
  该映射是 2026-06 的设计，现行流程为「R 序列 + 双循环（外循环/内循环）+ 标准执行」；
  组件能力已并入对应命令与审查层，**不要再按 ①-⑪ 登记新扩展**。
- **2026-06 吸收结论**（ECC-C1 安装器 / ECC-C2 GateGuard / ECC-C3 config-protection /
  ECC-OCR 工具集 / ECC-PB 约束-难度矩阵）：均已落地并融入现行实现，逐条 commit 明细见
  各 `ecc-audit-*.md` 与 git 历史，本文件不再维护子项清单。
- **2026-06-07 架构断链发现 / 2026-06-12 OCR 记忆压缩（已否决）**：决策已结案，保留在
  `ecc-finding-20260612-flywheel.md` 与对应审计文档，不在注册表重复。

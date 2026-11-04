# Extension Registry — Gatekeeper Skill 扩展注册表

<!-- DOC-META
title: Extension Registry — Gatekeeper Skill 扩展注册表
type: reference
owner: spz-gatekeeper-r-sequence
status: public
updated: 2026-11-02
-->

> **类比**: spz_gatekeeper 的 `ExtensionSpecRegistry` (extension_spec_registry.h)
> **用途**: 标准化引入新审查项、新优化器组件、新交叉引用的 SOP
> **原则**: 每个扩展必须在本文件注册，然后按 SOP 更新所有受影响的文件

---

## 注册表结构

每个扩展项是一个结构化条目：

```json
{
  "id": "L7",
  "type": "review_layer",
  "name": "Security Audit Pre-Check",
  "stage": "STAGE_1",
  "added_in": "R5.1",
  "source_files": ["references/stage-1-code.md:L32-34"],
  "description": "推送前安全审计预检：zizmor + SHA pin + persist-credentials",
  "review_points": [
    "zizmor --format plain .github/workflows/",
    "rg 'uses:.*@v[0-9]' .github/workflows/",
    "确认 persist-credentials: false 在所有 checkout 步骤中"
  ],
  "optimizer_item": null,
  "cross_refs": [
    "SKILL.md::Cross-Stage Invariants",
    "references/stage-3-review.md (L1-L9)",
    "references/security-measures.md:A.措施表",
    "references/architecture-overview.md:文件地图"
  ],
  "dependencies": [],
  "status": "active"
}
```

---

## 已注册扩展

### 审查层 (Review Layers)

| ID | Name | Stage | Added | Status |
|:--|:--|:--|:--|:--|
| L1 | Git Integrity | STAGE_1 | R1 | active |
| L2 | Code-to-Spec | STAGE_3 | R1 | active |
| L3 | GitNexus Baseline | STAGE_3 | R2 | active |
| L4 | Reference Projects | STAGE_3 | R1 | active |
| L5 | Known Blind Spots | STAGE_3 | R1 | active |
| L6 | Architecture Sync | STAGE_3 | R1 | active |
| **L7** | **Security Audit Pre-Check** | **STAGE_1** | **R5.1** | **active** |

### 优化器组件 (Optimizer Components)

> **三层架构**: Level 1 (①-⑧ 代码优化 + ⑨ CI/CD 优化 + ⑩ WASM 工程) / Level 2 (⑪ 思维优化) / Level 3 (Flow B wrapper 系统优化)
> 详见 `docs/plan-backup/2026-05-30-zero-trust-hl-harness-optimizer-architecture.md`

| ID | Name | SkillOpt 映射 | Level | Added | Status |
|:--|:--|:--|:--|:--|:--|
| ① Reflect | GitNexus analyze + context | Reflect | L1 | R5.5 | active |
| ② Edit | guard-edit + pre-tool-check | Edit | L1 | R5.5 | active (edit-level Step 1: R5.5) |
| ③ Gate | cmd_advance + cmd_monitor (5 modes: --local/--api/--align/--subagent/--gitnexus) | Gate | L1 | R5.5 | active |
| ④ Buffer | rejected_edits (unified schema: score+source+violations) + cross-R history | Buffer | L1 | R5.5 | active (enhanced) |
| ⑤ Slow Update | retrospect + reflect (cross-R history[] reading) | Slow Update | L1 | R5.5 | active (enhanced) |
| ⑥ Scheduler | cosine 4 模式 (init bug fixed R5.5) + **edit_budget hook** (R5.9++) | Scheduler | L1 | R5.5/R5.9++ | active (hook tested 2026-06-02) |
| ⑦ Protected Regions | 5 区域 10 标记 | Protected Regions | L1 | R5.7 | active |
| ⑧ Best Snapshot+Reflect | v4-flash API | Best Snapshot+Reflect | L1 | R5.8 | active |
| ⑨ CI/CD Optimizer | Pre-Push Gate + CI Diagnosis + Auto-Fix Loop + CI Buffer + Observability | (扩展：CI/CD 优化器新维度) | L1 | R5.9++ | partial (2026-08-27 校正×2): T43✅(ci-diagnose) T48✅ T42✅等价(spz ci.yml security-audit zizmor) T44◐雏形(wasm-pre-check P0-P7 --auto-fix=安全网雏形) T45✅等价(spz ci.yml failure() 日志+smoke 重试+challenge gate + spz2glb build.log) T46✅等价(spz ci.yml 失败/WASM artifact + spz2glb test-wasm-build logging) — 剩余缺口 = W9 流程级 auto-fix（80% 确定性修复 + 20% default subagent LLM 兜底→standard 序列，待 R-T8） |
| ⑩ WASM Engineering | 构建缓存 + 双 profile + 静态分析 + smoke test 加固 | (扩展：WASM 工程优化新维度) | L1 | R5.9+++ | planned (T49-T52, optional) |
| ⑪ Human Optimizer | plan-refinement SCR loop | Human Optimizer | L2 | R5.5 | active |
| Flow B Wrapper | B0 context + B4-pre/post + B6 registry sync + B9 doc sync | (无 SkillOpt 等价) | L3 | R5.5 | active (设计完成) |

### CLI 命令 (CLI Commands)

| ID | Name | Source | Added | Status |
|:--|:--|:--|:--|:--|
| discover | 状态发现 | gatekeeper-cli.sh | R5 | active |
| state | 状态查询 | gatekeeper-cli.sh | R5 | active |
| guard-edit | 编辑门禁 | gatekeeper-cli.sh | R5 | active (edit-level Step 1: R5.5) |
| pre-tool-check | 工具检查 | gatekeeper-cli.sh | R5.5 | active |
| advance | 阶段推进 | gatekeeper-cli.sh | R5 | active |
| monitor | PRM 审查 | gatekeeper-cli.sh | R5 | active |
| stage-detail | 阶段详情 | gatekeeper-cli.sh | R5 | active |
| reflect | 动态反思 | gatekeeper-cli.sh | R5.9 | active |
| appeal | 上诉 | gatekeeper-cli.sh | R5 | active |
| escalate | 升级 | gatekeeper-cli.sh | R5 | active |
| balance | 余额查询 | gatekeeper-cli.sh | R5 | active |
| set-key | Token 设置 | gatekeeper-cli.sh | R5 | active |
| docgen | 文档生成 | gatekeeper-cli.sh | R5 | active |
| push | git push 封装（远端白名单：`GK_PUSH_REMOTE_ALLOW` 可收紧） | gatekeeper-cli.sh | R5.9++ | active |
| _CMD_REG + _dispatch | **内部 helper（非命令）**：命令注册表 + 统一调度器 | gatekeeper-cli.sh | R5.9++ | active |
| _run_linter | **内部 helper（非命令）**：多语言死代码检测 | gatekeeper-cli.sh | R5.5 | active |
| ci-diagnose | CI 失败自动诊断 | gatekeeper-cli.sh | R5.9++ | active (T43) |
| search | 关键词检索（路由 = `gk_route_center` 五层链；检索 = gitnexus 语义 → rg 文本） | gatekeeper-cli.sh | R5.9++ | active |
| self-check | 系统自检 | gatekeeper-cli.sh | R5.9++ | active |
| release-check | GitHub release 版本扫描 | gatekeeper-cli.sh | R5.9++ | active |
| adjudicate | 裁决记录工具 | gatekeeper-cli.sh | R5.9++ | active |
| audit | 审计重放命令 | gatekeeper-cli.sh | R6 | active |
| achievements | 成就检查与解锁 | gatekeeper-cli.sh | R6 | active |
| cron | 定时任务调度 | gatekeeper-cli.sh | R6 | active |
| context | 上下文管理 | gatekeeper-cli.sh | R6 | active |
| trace | IFR 因果链追踪 | gatekeeper-cli.sh | R6 | active |
| attribution | LOO logprobs 归因 | gatekeeper-cli.sh | R6 | active |
| replay | 决策重放 | gatekeeper-cli.sh | R6 | active |
| ember | 余烬快照只读面（list/get/verify = get_state_history 同构） | gatekeeper-cli.sh + scripts/gk_ember_replay.py | C10 (2026-09-05) | active |
| ember-replay-audit | 余烬快照回判（cmd_replay --ember + self-check #22 + A3 seal） | gatekeeper-cli.sh + scripts/gk_ember_replay.py | C10 (2026-09-05) | active |
| resolve | 争议解决（终裁） | gatekeeper-cli.sh | R5 | active |
| finding | finding 生命周期（discovery→triage→fix→track） | gatekeeper-cli.sh | R6 | active |
| plan-refinement | 计划质询统一入口（preflight + monitor --subagent） | gatekeeper-cli.sh | R5.9++ | active |
| plan-lint | 计划写入安全网机检（PW-SN：锚点/假设编号/开关/消费者/判据可执行性）；`--stats`（2026-09-15，R-13）= 只读计数（裸行锚段级分类 + 锚类 reason 计数），不改既有输出/退出码 | gatekeeper-cli.sh + scripts/gk_plan_lint.py | 2026-09-15 | active |
| anchor-rebase | 行锚重钉（代码改写后把文档里的行锚按符号重新钉位）；默认**只读预览**，仅 `--apply` 落刀 —— 该模式会绕过 edit_budget（既有缺口 ECC-1E6BFDD7A207）⟹ 属显式人工放行动作，须在 commit message 留痕 | gatekeeper-cli.sh + scripts/gk_anchor_rebase.py | 2026-09-20 | active |
| t-star | 收敛评估 T* 冻结登记（§1-C3 前提门；freeze/show/evaluate/gate） | gatekeeper-cli.sh + scripts/gk_convergence_estimator.py | 2026-09-14 | active |
| ci-status | CI 状态查询（gh REST） | gatekeeper-cli.sh | R5.9++ | active |
| check-changes | 变更检查（与 previous_push_failures 并列） | gatekeeper-cli.sh | R5.9++ | active |
| pre-check | 预检（wasm P0-P7 含 --auto-fix） | gatekeeper-cli.sh | R5.9++ | active |
| commit | git 提交封装（拆小 commit） | gatekeeper-cli.sh | R5.9++ | active |
| doc-align | 文档确定性对齐引擎（0 API 静态扫描） | gatekeeper-cli.sh | 2026-08-27 | active |
| migrate | bashpy 迁移状态（dev/release_unverified） | gatekeeper-cli.sh | R6.1 | active |
| ci-stats | CI Observability 趋势监控 | gatekeeper-cli.sh | R5.9++ | planned (T46 已等价实现于 spz CI observability，独立命令待做) |
| ci-security | OpenSSF Scorecard 安全评估 | gatekeeper-cli.sh | R5.9++ | planned (T47) |
| setup-local | MiniCPM5-1B 本地安装指导 | gatekeeper-cli.sh | R6.1 | planned (T58) |
| swe-rb | SWE-bench 重构契约面（analyze/verify/audit，plugin-c） | gatekeeper-cli.sh | R5.9++ | active |
| node-guard | 序列节点出站守卫（G/B/C/T/D 五元组谓词 + 总运行线路） | gatekeeper-cli.sh | 2026-08-27 | active |
| calibrate | 运行时五层校准（只读诊断：路由/相位三角链/声明绑定） | gatekeeper-cli.sh | 2026-09-04 | active |
| help | 命令帮助（cli-protocol.md 单一事实源，`help [cmd]`） | gatekeeper-cli.sh | R5.9++ | active |
| paper-review | 论文写作投稿前置模拟评审（--local/--subagent/--camera-ready + 加载安全网；投稿前自检，非同行审稿） | gatekeeper-cli.sh | 2026-08-29 | active |
| moa-aggregate | MoA 多源聚合（归属指纹 + verdicts 词表联动） | gatekeeper-cli.sh | R6 | active |
| state-patch | state 原子补丁（flock 单写者，编辑预算扣减） | gatekeeper-cli.sh | 2026-09-07 | active |
| pr-score | 双盲评分锚定（seal/verify + 快照 + A3 seal） | gatekeeper-cli.sh + scripts/gk_pr_score.py | 2026-09-06 | active |
| project-register | 治理范围注册（register/list/remove/seal + A3 建基线） | gatekeeper-cli.sh + scripts/gk_project_register.py | 2026-08-28 | active |
| apply-worktree | 编码代理 worktree 申请—分发（幂等；branch=agent/&lt;family&gt;/&lt;hash8&gt;） | gatekeeper-cli.sh + scripts/gk_route_center.py | 2026-09-23 | active |
| model-probe | 模型版本探针（判 stride/相位周期禁据 alias；元数据层 `system_fingerprint` + 行为层测周期；`resolved=false` fail-loud） | gatekeeper-cli.sh + scripts/gk_model_probe.py | 2026-10-12 | active |
| phase-probe | 相位探针（密集 sweep × **每 stride** 置换检验 + Bonferroni；`N_LENGTHS<2S` 标 UNDER-POWERED；**机制实装在本仓**，外部 `phase_probe.py` 仅为记录副本、**不作源**（ECC-42B4A6E15927）） | gatekeeper-cli.sh + scripts/gk_phase_probe.py | 2026-10-12 | active |
| workers | 后台 worker 管理（`cmd_workers`） | gatekeeper-cli.sh | 2026-10-26 | active |

> 表内 `planned` 行 = **未实装**（分派表无此命令，调用会 `unknown command`）；标注「内部 helper」的行
> 不是对外命令。对账脚本：`scripts/check_tool_cfg.py`（工具面）+ `gatekeeper-cli.sh help`（命令面）。

### 模型 Provider (Model Providers)

| ID | Provider | Model | Type | Role | Status |
|:--|:--|:--|:--|:--|:--|
| P1 | DeepSeek | v4-flash | 云 API | 主 critic (CLI monitor/reflect) | active |
| P2 | DeepSeek | v4-pro | 云 API | 主 actor (Trae 主 agent) | active (Trae 控制) |
| P3 | MiMo | v2.6 | 云 API | 云 fallback (DS 不可用时) | active |
| P4 | MiMo | v2.6-pro | 云 API | 云 actor fallback (Trae 主 agent) | active (Trae 控制) |
| P5 | MiniCPM5-1B (Ollama) | minicpm5:1b | 本地 | 本地 fallback (DS+MiMo 均不可用时) | R6.1 planned (T53-T58) |

---

## 添加新扩展的 SOP

### Step 1: 注册

在本文件的对应表格中添加新条目，填写所有字段。

### Step 2: 源码定义

| 扩展类型 | 定义位置 |
|:--|:--|
| 审查层 (L*) | `references/stage-1-code.md` (Pre-Push) 或 `references/stage-3-review.md` (STAGE_3) |
| 优化器组件 | `SKILL.md §优化器架构` + `gatekeeper-cli.sh` |
| CLI 命令 | `gatekeeper-cli.sh` case 语句 + `references/cli-protocol.md` |
| 交叉审查项 | `references/stage-3-review.md` Step-by-step 脚本 |

### Step 3: 交叉引用更新

**必须更新的文件**（添加新审查层时）：

| 文件 | 更新内容 |
|:--|:--|
| `SKILL.md::Cross-Stage Invariants` | Cross-Stage Invariants 表添加新行 |
| `docs/plans/2026-06-11-mpr-redteam-plan.md` | Red Flags 如有相关更新（已迁移至 redteam-plan.md） |
| `references/stage-1-code.md` | PRE-PUSH REVIEW 范围 |
| `references/stage-3-review.md` | 触发词更新 + 完整脚本添加检查项 |
| `references/security-measures.md` | A.措施表更新 |
| `references/architecture-overview.md` | 文件地图注释更新 |
| `references/cli-protocol.md` | CLI 命令表 + subagent 预设更新 |
| `docs/plans/2026-06-09-mpr-standing-plan.md` | META phases 更新（新增 AUDIT-*/RED-* phase 时） |

### Step 4: 验证

```bash
# 检查所有交叉引用一致性
rg "L1-L[0-9]" references/ SKILL.md | grep -v "L1-L9"
# 应返回空（如果 L9 是最新的）
```

---

## 已规划扩展（Planned）

### guard-edit Edit-Level Extension

| Field | Value |
|:--|:--|
| **ID** | ② Edit (edit-level enhancement) |
| **Cross-review date** | 2026-05-30 |
| **SkillOpt reference** | update_modes.py describe_item() — op/target/content/support_count |
| **Status** | Step 1 已实施 (R5.5)，Step 2-3 待实施 |

**设计概要**：

```
新签名（向后兼容）: cmd_guard_edit "$path" "$op" "$target" "$line_start" "$line_end"

Step 1 已实现字段:
  protection_status  — clear/blocked（利用 _protected_region_check 行级能力）✅ DONE
  detail             — blocked 时包含保护区域详情

Step 2 待实现:
  similar_rejections — 同文件/同 target 历史拒绝次数（需扩展 rejected_edits 写入端增加 target 字段）

Step 3 待实现:
  estimated_impact   — high/medium/low（基于 category 映射）
```

**实施路径**（3 步渐进）：

| Step | 范围 | 风险 | 状态 |
|:--|:--|:--|:--|
| Step 1 | 暴露保护区行级 + protection_status + detail | 低 | ✅ R5.5 已实施 |
| Step 2 | 拒绝历史查询 + similar_rejections | 中 | 待实施（需扩展 rejected_edits schema） |
| Step 3 | 影响评估 + estimated_impact | 低 | 待实施（可选） |

**交叉审查关键发现**：
- SkillOpt 无 guard-edit 等价物，gate 在聚合层（clip.py rank_and_select）
- Gatekeeper 的 guard-edit 是**预拦截机制**（edit 提出前阻止），SkillOpt 是**后过滤机制**（edit 提出后排序）
- SkillOpt 用 LLM 做 edit 排序而非启发式（clip.py L75-100），Gatekeeper 的 estimated_impact 应标注为 hint
- 向后兼容：新参数默认空，`guard-edit <path>` 现有调用不受影响

---

### 2026-06-07 架构断链发现

> subagent 横跨优化器循环 (Level 1) 和 B+D 元循环 (Level 2) — 是共享基础设施，不是独立流程。
> 子循环的"先进特性"（5 工具、ReLocation、约束矩阵）是独立进化的结果，需要回注主流程。

**进化洞见**: cmd_monitor --subagent 从 ③ Gate 的一个执行模式，进化为填补"缺失子 agent"空白的共享执行引擎。它自然地把 B4 计划质询和 ③ Gate 串起来，是流程编排断裂的解法，不是架构漂移。

**待做改进**:
| 回流目标 | 特性 | 优先级 | 说明 |
|:--|:--|:--|:--|
| ③ Gate --api | ReLocation (行号) | P2 | system_prompt 加行号要求 |
| STAGE 3 交叉审查 | 约束-难度矩阵 | P2 | L1-L9 × 3 级难度 |
| ④ Buffer | 验证清单 | P2 | gate_data 记录 verification_checklist |

### 2026-06-07 rtp-llm 缓存优化吸收

> 源项目: rtp-llm (阿里内部 LLM 推理引擎)
> 分析文件: LRUCache.h, FIFOScheduler.cc, BlockRefCounter.h

**P1 待做**:
| 改进 | 来源 | 说明 |
|:--|:--|:--|
| _v3 已否决 — 见对话 2026-06-09_ | — | — |

**P2 待做**:
| 改进 | 来源 | 说明 |
|:--|:--|:--|
| `version++` 增量快照 | LRUCache.h L90,111,147 | gate_data 加 version 字段 |
| `busyBlockNum` 统计 | BlockRefCounter.h L52-58 | cmd_state 输出 gate_data_size |
| 稀疏引用计数 | BlockRefCounter.h L29-50 | rejected_edits 条目加 ref_count |

### 2026-06-12 OCR 三区记忆压缩 + 智能分组并行 — 已否决

> 来源: OCR 1.1.18 (Alibaba)
> 决策: **不适用** — gatekeeper 记忆层是结构化 key-value/FIFO（subagent_history cap=5, rejected_edits cap=20），不是 LLM 对话历史。结构化数据无需压缩。智能分组并行（按仓库分组 → dispatching-parallel-agents）由用户自行触发，无需自动化。

**GitNexus**: v1.6.6 正式发布

## 命名规范

| 类型 | 前缀 | 示例 |
|:--|:--|:--|
| 审查层 | `L` + 数字 | `L7`, `L8` |
| 优化器组件 | `①`-`⑧` | `⑨` (新组件) |
| CLI 命令 | 无前缀 | `new-command` |
| Invariant | 描述性 | `new invariant rule` |

---

## 2026-06-02 三项目交叉审查发现

### 关键洞见

优化器已有大量确定性门禁 (pre_tool_check/guard-edit/advance/PROTECTED_REGION/SHA256/flock/CMD_REG)，但 `_monitor_api` 把确定性 if-then 判断也交给 LLM 做了。system_prompt 里的 6 条规则（`ci_trigger=absent → FAIL` 等）全是确定性判断。

**SafeHarness 参考**: L2 三层级联 — Tier 1 确定性规则短路 → Tier 2 LLM → Tier 3 causal reasoning。gatekeeper 应采用相同架构。

**澄清**: --local 模式已经是纯确定性 if-then 检查（不调 LLM）。--api 模式调 LLM 是因为需要矛盾检测/语义推理/reasoning 生成——这些是 --local 做不了的。

### 改进清单

**P0: 需要修的 bug**

| 改进 | 来源 | 状态 |
|:--|:--|:--|
| match_count 截断后不准（head 截断后 wc -l 算的是截断行数） | OpenCodeReview | 待修 |

**P1: 代码健壮性增强（可做）**

| 改进 | 来源 | 对应 T | 状态 |
|:--|:--|:--|:--|
| rg `--max-count` 替代 head 截断 | OpenCodeReview | T43++b | 待做 |
| 搜索截断通知 | OpenCodeReview | T43++b | 待做 |
| edit_budget 渐进降级（WARN→FAIL） | SafeHarness | T43++c | 待做 |
| autonomous 模式修正 (999→max_lr) | SkillOpt scheduler.py | T43++d | 待做 |

**P2: 防御性增强（零信任 HL harness 通用抽象，可顺手做）**

| 改进 | 来源 | 说明 |
|:--|:--|:--|
| context loading 添加文件总行数 | OpenCodeReview | 小改动 |
| _resolve_repo_path 未知 repo 警告 | OpenCodeReview | 小改动 |
| 搜索支持大小写选项 | OpenCodeReview | 小改动 |
| 搜索超时保护 | OpenCodeReview | 小改动 |

**P3: 学术参考（不需要做）**

| 改进 | SkillOpt 来源 | 为什么不需要 |
|:--|:--|:--|
| 三态门禁 (accept/accept_new_best/reject) | gate.py | gatekeeper 不需要区分"超过最佳" |
| 智能裁剪 (rank_and_select) | clip.py | gatekeeper 没有编辑列表可以排序 |
| 多模态度量 (hard/soft/mixed) | gate.py | gatekeeper 的 edit 计数是确定性的 |

**开源重构候选**

| 改进 | 说明 | 时机 |
|:--|:--|:--|
| state_dict (调度器显式序列化) | 当前内联 Python 实现等价逻辑，开源时需改成 CosineScheduler.state_dict()/load_state_dict() | 开源时 |
| autonomous 模式修正 | 当前 lr=999（无限预算）→ 应改为 max_lr 作为预算上限 | 可现在做 |

---

## 2026-06-07 ECC 结论吸收注册

> ECC (arXiv:2605.20873 + SafeHarness arXiv:2604.13630 + OpenCodeReview v1.1.18)
> 每个结论作为扩展项注册，按 SOP 更新受影响文件。

### 结论 1: `.trae/` 安装器模式

| Field | Value |
|:--|:--|
| **ID** | ECC-C1 |
| **类型** | 基础设施 |
| **源** | ECC `.trae/install.sh` |
| **状态** | **已完成** — install.sh + uninstall.sh + LOOKUP_DIRS |
| **commit** | b1ea57b |

**已完成子项**:
| 子项 | 状态 | commit |
|:--|:--|:--|
| install.sh (非破坏性安装 + manifest) | ✅ | b1ea57b |
| uninstall.sh (manifest 精确删除) | ✅ | b1ea57b |
| gatekeeper-cli.sh LOOKUP_DIRS | ✅ | b1ea57b |

**待做改进**:
| 子项 | 优先级 | 说明 | 时机 |
|:--|:--|:--|:--|
| 路径遍历保护 | P0 | 从 ECC `is_valid_manifest_entry()` 搬 | ✅ ee27a46 |
| 卸载确认提示 | P0 | 从 ECC `read -p` 搬 | ✅ ee27a46 |
| `.trae-cn` 支持 | P2 | 从 ECC `get_trae_dir()` 搬 | ✅ fd43bad |
| ed25519 签名校验 | P1 | 构建签名 + 安装验签 | P1 增强 |
| 通用化 `--skill` 参数 | P2 | R6/R7 重写时统一清理所有硬编码路径 | 重写时 |
| subagent 输出 → gate_data | P2 | subagent conclusion/evidence 写入 gate_data audit trail | ✅ fd43bad |
| ReLocation 回流 --api | P2 | system_prompt 加行号要求 | ✅ fd43bad |
| 约束-难度矩阵 → STAGE 3 | P2 | L1-L9 × 3 级难度 | ✅ fd43bad |
| 友好 IDLE 提示 | P0 | pre-tool-check / guard-edit 加下一步指引 | ✅ fb0a5d3 |
| cmd_reflect 持久化 | P1 | 分析结果写入 gate_data.rejected_patterns | ✅ fb0a5d3 |
| self-check 命令 | P1 | 系统自检 (state/provider/gitnexus/subagent_python/gate_data) | ✅ fb0a5d3 |

### 结论 2: GateGuard

| Field | Value |
|:--|:--|
| **ID** | ECC-C2 |
| **状态** | **已超越** — gatekeeper 结构门禁更强 |

### 结论 3: config-protection

| Field | Value |
|:--|:--|
| **ID** | ECC-C3 |
| **状态** | **已完成** — PROTECTED_REGION 等价实现 |

### OCR 1.1.18: subagent 工具集 + ReLocation

| Field | Value |
|:--|:--|
| **ID** | ECC-OCR |
| **状态** | **已完成** — 5 工具 (search/read/gitnexus/code_search/read_doc) + ReLocation 约束 |
| **commit** | 1697f04 + 39bdb24 |

### PlanningBench: 约束-难度矩阵 + 闭环反馈

| Field | Value |
|:--|:--|
| **ID** | ECC-PB |
| **状态** | **已完成** — F1-F7 升级为 3 级矩阵 + B4 Round 1/2/3 闭环 |
| **commit** | b72cdb6 |

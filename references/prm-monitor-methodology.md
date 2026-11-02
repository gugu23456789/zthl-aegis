# PRM Monitor：方法论与交叉审查

<!-- DOC-META
title: PRM Monitor：方法论与交叉审查
type: reference
owner: spz-gatekeeper-r-sequence
status: public
updated: 2026-11-02
-->

> **所属系统**: SPZ Gatekeeper CLI — Pipeline Governance as Heuristic System  
> **文献来源**: Bridge HL Harness v4.18 架构（已适配），5 篇同行评审论文（同 Bridge）  
> **日期**: 2026-05-26（R5 定型）  
> **用途**: Gatekeeper R-序列过程监督方法论——供 STAGE_3/4 API monitor + 人类审查时引用

---

## 0. 系统架构全景

> 完整文件地图见 `architecture-overview.md`。本章节聚焦 Gatekeeper CLI 的 PRM Monitor 层面的数据流、角色分离以及与 Bridge 的关键差异。

### 0.1 核心角色分离（Actor-Critic）

```
┌─ v4-flash Agent (Actor / 执行者) ─────────────────────────┐
│  SKILL.md 路由 → stage reference → 执行 stage 任务           │
│  → 完成后调用 gatekeeper-cli.sh advance <to_stage>           │
│  → 收到 violations → agent-self-correction → fix → retry    │
│  同一 v4-flash, 同一 DEEPSEEK_API_KEY                       │
└────────────────────┬────────────────────────────────────────┘
                     │ gatekeeper-cli.sh advance <to_stage>
                     ▼
┌─ gatekeeper-cli.sh (Deterministic Execution Layer) ────────┐
│                                                              │
│  discover / state / guard-edit / pre-tool-check /            │
│  advance / monitor / appeal / escalate / stage-detail         │
│                                                              │
│  ├─ Structural gate rules (stage transition rules)           │
│  │   worktree 存在? CI 触发器注册? plan 备份存在?              │
│  │                                                           │
│  ├─ _collect_hard_evidence(stage)                            │
│  │   23 项真实产物收集 + repo_hash (git log / ctest 输出 /            │
│  │   spec_url 文件存在性 / CI trigger / L4 marker /          │
│  │   工作目录干净 / 分支状态 / plan mtime)                    │
│  │   → Agent 控制范围之外，不可篡改                           │
│  │                                                           │
│  └─ 分层调度 monitor (5 种模式):                              │
│      关键 stage (STAGE_3/4) → --api (v4-flash, reasoning=high)│
│      非关键 stage          → --local (0.1s, 0 tokens)          │
│      --gitnexus           → GitNexus 索引只检查               │
│      --align              → 文档-代码对齐检查 (0 API)          │
│      --subagent           → 约束审查 subagent 驱动             │
└────────────────────┬────────────────────────────────────────┘
                     │ subprocess: monitor score <stage>
                     ▼
┌─ cmd_monitor --api (Semantic Critic / PRM) ────────────────┐
│  模型: deepseek-v4-flash (同一 DEEPSEEK_API_KEY)             │
│  reasoning_effort: STAGE_1/2=low, STAGE_3/4=high             │
│  temperature=0.0                                             │
│                                                              │
│  输入: stage schema (JSON)                                   │
│      + state JSON (agent 写)                                 │
│      + hard evidence JSON (CLI 收集, 不可伪造)                │
│      + appeal notes (可选, 一次性)                           │
│                                                              │
│  输出: structured JSON                                       │
│      { overall_score, checks[{item,status,evidence}],         │
│        violations, contradictions, next_action }              │
│                                                              │
│  temperature=0.0 (确定性, 可复现)                             │
└────────────────────┬────────────────────────────────────────┘
                     │ structured JSON
                     ▼
┌─ gatekeeper-cli.sh 门禁裁决 ───────────────────────────────┐
│                                                              │
│  ┌─ score > 0.5 → monitor.verdict = "PASS"                  │
│  │   + 结构门禁 PASS → advance allowed                       │
│  │                                                           │
│  ├─ score ≤ 0.5 → monitor.verdict = "BLOCKED"               │
│  │   hint: "Fix violations, re-run advance"                  │
│  │   → Agent 修复后重新 advance                               │
│  │                                                           │
│  ├─ appeal <stage> "<notes>" → 一次性上诉                   │
│  │   monitor 重评 → 终裁 → 写入 appeal_records                │
│  │   驳回 → gate 入 appeal_denied_gates → 永久拦截            │
│  │   (仅 --force 可覆盖)                                      │
│  │                                                           │
│  └─ escalate <stage> "<reason>"                              │
│      仅 appeal DENIED 后可触发                                │
│      生成 Markdown 报告 → 供人类审查                          │
└────────────────────┬────────────────────────────────────────┘
                     │ read / write
                     ▼
┌─ .gatekeeper.state (JSON, 跨会话持久化) ───────────────────┐
│  monitor_scores.{stage}.{score, verdict, model, reasoning}  │
│  gate_data.{sprint_contract, pr_number}                     │
│  appeal_records.{gate}.{verdict, score, notes}               │
│  appealed_gates + appeal_denied_gates                        │
│  _checksum: SHA256(所有字段) ← 防篡改                         │
└────────────────────────────────────────────────────────────┘

临时文件 (每轮刷新, 被 .gitignore 排除):
  .gatekeeper_monitor_api_tmp.json — monitor 完整输出 (人类审计用)
```

### 0.2 与 Bridge HL Harness 的关键差异

| 维度 | Bridge HL Harness | SPZ Gatekeeper CLI | 理由 |
|:---|:---|:---|:---|
| **Actor 模型** | v4-pro（独立推理） | v4-flash（当前会话 LLM） | Gatekeeper 不需要全天候独立 actor——代码由 Agent 写入，非循环调用 |
| **Critic 模型** | v4-flash, temperature=0.0 | v4-flash, reasoning=low/high | 复用同一 v4-flash，通过 `reasoning_effort` 参数切换深度——Bridge 的 v4-pro+v4-flash 替换为 v4-flash(v2) 统一 |
| **执行层语言** | Python 850+ 行 | Shell ~1.16 万行（2026-10-28 实测 11578） | Gatekeeper 的工具面是 bash/WSL/cmake/ctest，Shell 比 Python 更接近执行环境 |
| **硬证据数量** | 12 项 | 23 项 | 增加 spec_url 文件存在性验证、CI trigger 检测、L4/git-workflow marker、repo_hash 等审计项 |
| **pre_tool_hook** | 引擎 engine.py 层 | gatekeeper-cli.sh 内置 | Gatekeeper 没有独立 engine——`pre_tool_check()` 直接集成在 CLI 中 |
| **关键 gate 筛选** | Gate 3/6/7/8 | STAGE_3/4 | Gatekeeper pipeline 为 5-stage（非 9-gate），结构更简洁 |

---

## 1. 论文基础（信息来源）

> 与 Bridge 同一 5 篇论文体系。Gatekeeper 的具体实现差异在 §2 逐个交叉审查。

| 编号 | 论文 | 发表场合 | 核心贡献 |
|:--|:---|:---|:---|
| P1 | [PRM Survey](https://arxiv.org/abs/2510.08049) — Zheng et al. | arXiv 2025 | 完整 PRM 闭环：数据生成 → PRM 构建 → 测试时扩展 / RL |
| P2 | [AgentPRM](https://arxiv.org/abs/2502.10325) — Choudhury | Cornell 2025 | 轻量 actor-critic，3B 模型评分能力超过 GPT-4o |
| P3 | [RLAIF](https://arxiv.org/abs/2309.00267) — Lee et al. | ICML 2024 | d-RLAIF：现成 LLM 直接当奖励函数，同 size 评分者有效 |
| P4 | [CSO](https://arxiv.org/abs/2602.03412) — Li et al. | ACL 2026 | 只需 16% 轨迹步骤接受监督即可 |
| P5 | [PURE](https://arxiv.org/abs/2504.15275) — Cheng et al. | CAS/上海 AI Lab 2025 | min-form 信用分配解决奖励劫持 |

---

## 2. 交叉审查：论文原则 vs Gatekeeper 实现

### 2.1 步骤级细粒度

**论文说 (P1, §2)**: PRM 应在步骤级别评估，而非仅看最终结果。

**Gatekeeper 做**: Stage 级别打分。5 个 stage = 5 个离散过程步骤。每个 stage 有结构化 JSON schema（`requires/produces/evidence/must_not/failure` 五字段）。

**判定**: ✅ **对齐**。Gatekeeper 的 stage 粒度比 token 级 PRM 更粗，但对 C++ 编码管线是合适的——每个 stage 对应一次明确的上下文切换（编码→CI→审查→合并→退休）。

### 2.2 d-RLAIF：用现成 LLM 直接打分

**论文说 (P3)**: "d-RLAIF 绕过了 reward model 训练，直接用现成 LLM 获得 reward。"

**Gatekeeper 做**: `cmd_monitor --api` 直接调 v4-flash，零 reward model 训练。monitor prompt 包含 stage schema + state + hard evidence。

**判定**: ✅ **对齐**。Gatekeeper 更进一步——**actor 和 critic 共用同一 v4-flash**，利用 P3 证明的 "同 size/同 checkpoint 即可" 原则。Bridge 用 v4-pro+v4-flash，Gatekeeper 用 v4-flash+reasoning_effort。

### 2.3 生成式 PRM + CoT 推理

**论文说 (P1, §3.2)**: 输出显式推理再打分的生成式 PRM 优于判别式 PRM。

**Gatekeeper 做**: v4-flash 输出结构化 JSON，每条 requirement 附带 `evidence` 字符串。`reasoning` 字段提供一句话摘要。STAGE_3/4 启用 `reasoning_effort=high` 增加推理深度。

**判定**: ✅ **对齐**。关键 stage 启用高推理深度——深度语义审查比 Bridge 的 `temperature=0.0` 单一输出模式更接近 CoT 审计轨迹。

### 2.4 轻量 Actor-Critic 分离

**论文说 (P2)**: "critic（PRM）与 actor（策略）分离。小 critic 模型（3B）就够了。"

**Gatekeeper 做**: actor（当前会话的 v4-flash）与 critic（CLI 调用的 v4-flash, reasoning_effort=high）**模型相同但实例不同**。Critic 使用 `temperature=0.0` 确保确定性输出。

**判定**: ⚠️ **已增强**。Gatekeeper 的 actor-critic 不是 Bridge 那种 "不同模型 size" 的分离，而是 **同一模型 + 不同参数 + 不同实例** 的分离。Critic 启用 reasoning 模式时推理深度超过无思考的 actor——这构成功能层面的分离，尽管模型相同。P2 的 3B 级即可的结论支撑此设计。

### 2.5 关键步骤选择

**论文说 (P4)**: 仅 16% 轨迹步骤需要监督。

**Gatekeeper 做**: 5 个 stage 中仅 2 个（STAGE_3/4）走 API monitor。其余 3 个 stage 走 local-only 结构化检查。实际 API monitor 覆盖率为 40%。

**判定**: ✅ **对齐**。STAGE_1(编码) 和 STAGE_5(退休) 的结构化规则足够确定——不需要语义审查。P4 的 16% 观点是下限，Gatekeeper 的 40% 是保守但合理的选择。

### 2.6 奖励劫持防护

**论文说 (P5)**: "min-form 信用分配防止奖励劫持。"

**Gatekeeper 做**: PRM 分数**仅在 test-time 使用**，不参与策略优化。无 RL 训练循环。但 Gatekeeper 特有的风险是：Agent 可以通过反复 `--force` 绕过 monitor。对此的防御是：force 操作在 CLI 输出中显式标记 `"FORCE mode — PRM monitor bypassed"`，写入 state 文件，且 override 次数受 `appeal_denied_gates` 机制限制。

**判定**: ✅ **按设计免疫**。因无 RL 训练循环，P5 的奖励劫持问题不适用。force 操作风险被显式标记 + 审计轨迹控制。

### 2.7 结构化 + 语义双层评分

**论文说 (P1, §7 + GuardAgent)**: 生成可执行 guardrail 代码做确定性检查，叠加 LLM 语义推理。

**Gatekeeper 做**: `--local` 模式 = 结构化检查（文件存在? 字段非空? 分支 clean?）、API 模式 = v4-flash 语义审查。STAGE_3/4 用 reasoning_effort=high 加深语义层。

**判定**: ✅ **对齐**。与 GuardAgent 的确定性代码 + LLM 推理双层架构一致。

### 2.8 pre_tool_check：引擎级强制

**论文说 (GuardAgent, ICML 2025)**: Guardrail 必须确定性阻断违规。

**Gatekeeper 做**: `pre_tool_check()` 在 edit/commit/push 前做 4 层拦截——不依赖 Agent 主动调用 skill。这是 Bridge v4.18 的 `pre_tool_hook` 模式在 Shell 中的等价实现。

**判定**: ✅ **超越 Bridge**。Gatekeeper 的 `pre_tool_check` 直接集成在 CLI 中（~1.16 万行单一文件，2026-10-28 实测 11578 行），不需要独立 engine.py。GuardAgent 的"确定性阻断"要求：裸跑检测（stage=IDLE/DONE）→ 主仓库写保护 → commit 格式校验 → push token URL 校验。4 层全部覆盖。

---

## 3. 综合：PRM Monitor 最佳实践

### 原则 1：Actor-Critic 分离 (P2, P3)
- Actor（当前 Agent）和 critic（CLI 子进程 v4-flash）必须是不同实例
- Gatekeeper 使用同一 v4-flash，通过 `reasoning_effort` 做功能分离
- Critic 使用 `temperature=0.0`、结构化 prompt、hard evidence 约束

### 原则 2：Schema 即 Constitution (CAI)
- 每个 stage 必须有 JSON schema（`requires/produces/evidence/must_not/failure`）
- Monitor 只收到当前 stage 的 schema（渐进披露）
- Schema 路径：`monitor-schemas/STAGE_N.json`

### 原则 3：生成式审计轨迹 (P1 §3.2)
- Monitor 输出逐项 `checks[].evidence` 字符串
- Agent 可见 `violations[]` 列表（不暴露逐项权重）
- 全量输出转储 `.gatekeeper_monitor_api_tmp.json`（人类审计用）

### 原则 4：双层验证 (GuardAgent)
- `--local`（结构化，0 tokens）+ `--api`（语义，关键 stage 启用 reasoning=high）
- 结构门禁不依赖 LLM，确定性阻断常见违规
- API monitor 仅在 STAGE_3/4 激活（非关键 stage=local-only）

### 原则 5：仅 Test-Time 使用 (P5)
- PRM 分数不参与训练循环
- force 操作显式标记 + 审计轨迹
- Appeal 机制防滥用：一次性上诉，被驳则永久拦截

### 原则 6：关键 Stage 筛选 (P4)
- 5 个 stage 中 2 个关键（STAGE_3/4）→ reasoning=high
- 3 个非关键（STAGE_1/2/5）→ local-only
- API 调用节省：~60%（3/5 stage 零 token）

### 原则 7：主动门禁
- 分数 ≤ 0.5 → BLOCK advance（主动阻断，非旁路打分器）
- 仅 `--force` 可覆盖（显式标记为危险）
- CONTRADICTION 检测（state vs hard evidence 不匹配）自动判 0.0

---

## 4. Bridge 适配差异详细表

| 原则 | Bridge 实现 | Gatekeeper 实现 | 差异原因 |
|:---|:---|:---|:---|
| Actor-Critic 分离 | v4-pro + v4-flash | v4-flash + reasoning_effort | Gatekeeper 无独立 actor 进程；同一 Agent 做 actor，CLI 子进程做 critic |
| 硬证据采集 | _collect_hard_evidence() 12 项 | _collect_hard_evidence() 23 项 | 增加 CTest output、spec_url 验证、CI trigger、L4 marker、repo_hash |
| pre_tool_hook | engine.py (Python, 独立层) | pre_tool_check() (Shell, CLI 内置) | Gatekeeper 无 engine；guard 逻辑直接在 CLI 中 |
| 关键门禁 | Gate 3/6/7/8 (4/9=44%) | STAGE_3/4 (2/5=40%) | Pipeline 长度不同，比例相近 |
| State 格式 | YAML | JSON | 项目习惯差异 |
| Reasoning | temperature=0.0 固定 | reasoning_effort=low/high | Gatekeeper 利用 v4-flash 新参数切换深度 |

---

## 5. 评审者批判——预期挑战与答复

### Q1: 同一 v4-flash 做 actor+critic 能实现真正的分离吗？

**评审者**: "Bridge 用 v4-pro 做 actor、v4-flash 做 critic。你们用同一个模型——v4-flash 做 actor，同一个 v4-flash 做 critic。这算什么分离？"

**答复**:

这是最直接的质疑。我们承认：**这不是 Bridge 意义上的模型分离**。

但我们的分离体现在三个不同层面：

1. **实例分离**: Actor（IDE 中的 Agent 会话）与 critic（gatekeeper-cli.sh 调用的 curl 子进程）是两个**不同进程**。Critic 运行在 `temperature=0.0`、`reasoning_effort=high` 的约束下，上下文仅包含 stage schema + state + hard evidence。Actor 的完整推理链对 critic 不可见。

2. **上下文分离**: Critic 收到的不是 Agent 的全部对话历史。它只看到：当前 stage 的 JSON schema、state 文件（Agent 写的）、23 项 hard evidence + repo_hash（CLI 采集的）。Critic 不知道 Agent 之前说了什么、写代码时的思考过程。这种**渐进披露**防止 critic 被 actor 的推理偏差影响。

3. **功能分离** (`reasoning_effort`): Critic 在 STAGE_3/4 启用 `reasoning_effort=high`——推理深度超过用于日常对话的无思考 actor。深层推理 vs. 快速响应构成功能层分离。

**判定**: ⚠️ **诚实的有限分离**。不是 Bridge 的模型级分离，但三个独立维度的实例 + 上下文 + 功能分离共同创建了有效的 actor-critic 分工。P3 证明 "same checkpoint is sufficient" 支撑此设计。

### Q2: pre_tool_check 能替代 Bridge 的 engine.py pre_tool_hook 吗？

**评审者**: "Bridge 的 pre_tool_hook 是引擎层强制——在工具调用面阻断。你的 pre_tool_check 是 CLI 的一部分——Agent 需要主动调用它。这和 guard-edit 一样的被动问题。"

**答复**:

Gatekeeper 的 pre_tool_check 和 Bridge 的 engine.py pre_tool_hook 属于不同的执行层：

- **Bridge**: engine.py 是 LLM 调用的代理层——所有工具调用（SearchReplace/Write）经过 engine.py 的 `on_tool_start` hook。pre_tool_hook 在这里阻断是**引擎强制**。

- **Gatekeeper**: 没有 engine.py。CLI 是 Gatekeeper 的执行层。Agent 的工具调用直接作用于 WSL 文件系统。pre_tool_check 是 CLI 命令——Agent 需要主动调用它。

这是 Gatekeeper 架构的已知约束：**没有 agent-agnostic 的工具调用中介层**。R5 的 bare-run 教训正是由此产生。

**缓解**: pre_tool_check 在 CLI 中执行三层检查：（1）state 文件存在性（2）stage 不是 IDLE/DONE（3）路径合法性。如果 Agent 完全不调用 CLI，这些检查不会触发。这确实是个缺口——但比 R5 的完全裸跑好：至少当 Agent**选择**调用 CLI 时，pre_tool_check 提供阻断。

**真实修复（R6 待实现 — 架构限制，需 git hooks）**: 在 WSL bashrc 或 git pre-push hook 层面增加强制调用。这将使 pre_tool_check 突破 Agent 选择不调 CLI 的缺口。

### Q3: 23 项硬证据足够防御 Agent 刷分吗？

**评审者**: "23 项听起来很多。几项真正有效？"

**答复**:

真实防御价值逐项：

| 证据项 | 防御价值 | Agent 可绕过？ |
|:---|:---:|:---|
| `worktree_exists` | 低 | 创建 worktree 即可 |
| `branch_not_main` | 低 | 切分支即可 |
| `commits_ahead_of_main` | 中 | 做空 commit 即可 |
| `pushed_to_remote` | 中 | 裸 push 即可 |
| `git_uncommitted` | **高** | 发现脏工作区 |
| `git_log_tail` | **高** | 无法伪造 git 历史 |
| `ci_trigger` | 中 | 改 ci.yml 即可 |
| `build_exists` | 中 | 创建 build 目录即可 |
| `ctest_output` | **高** | 不可伪造——现场跑 |
| `l4_marker` | **高** | 无法在 git 历史插入虚假 marker |
| `git_workflow_marker` | **高** | 同上 |
| `spec_urls_valid` | **高** | 文件存在性不可伪造 |
| `plan_backup` | 低 | 复制文件即可 |
| `gitnexus_status` | **高** | 不可在 gitnexus index 中伪造 |
| `merge_commit` | **高** | 不可在 git 历史中插入 |
| `main_aligned` | 中 | fetch+reset 即可 |

**真正有效的防御项**: 10 项（标"高"的）。这 10 项共同覆盖了 Agent 最主要的绕过路径：虚假 commit 历史、虚假 CTest 结果、虚假路径引用、虚假 git 历史插入。23 项中 10 项高价值，对 Shell 脚本实现的 ~1.16 万行 CLI 来说是合理的覆盖率。

---

> 同 Bridge 的论文基础（P1-P5）和 CAI/GuardAgent 引用在此适用。具体论文引用索引见 Bridge `prm-monitor-methodology.md §5`。

---

## §8. 优化器架构：SkillOpt × GitNexus × PRM (R5.6)

> **定位**: R5.6 将 GitNexus 接入 CLI 形成完整优化器。R5.5 提供 gate+buffer (T29-T31)，R5.6 提供 analysis engine (T32-T35)。
>
> **论文基础**: SkillOpt arXiv:2605.23904 §3 (Reflect/Edit/Gate/Buffer) + CSO ACL 2026 P4 (16% 关键步骤)

### 8.1 四组件优化器

```
SkillOpt Loop                Gatekeeper 等价物
════════════════════════════════════════════════
Reflect (分析失败)          GitNexus analyze (代码图基线)
                              GitNexus context/impact (调用链分析)
                                ↓
Edit (编辑)                 agent 编码
                              guard-edit + pre-tool-check
                                ↓
Gate (验证)                 CLI advance (3 条路径)
                              PRM monitor --local (结构化)
                              PRM monitor --api (语义, 含 gitnexus context)
                                ↓
Buffer (存储)               rejected_edits (T30 写入, T32 回读)
                              edit_budget (T29)
                                ↓
[反馈]                      previous_rejections (JSON 结构化输出)
                              GitNexus analyze delta (pre-R vs post-R)
```

### 8.2 GitNexus 分阶段触发

| Stage | GitNexus 模式 | 注入目标 | 实现状态 |
|:--|:--|:--|:--:|
| STAGE_0 | `analyze` | gate_data.gitnexus.baseline | ✅ |
| STAGE_1 | `context <file>` | guard-edit 上下文 | ⚠️ P1 (C++ only) |
| STAGE_2 | `detect-changes` | monitor --local 证据 + advance gate | ✅ 832e41f+16a60f8 |
| STAGE_3 | `impact <symbol>` + `context` | monitor --api prompt | ✅ T34 16a60f8 |
| STAGE_4 | `analyze` (delta) | retrospect + advance gate | ✅ T31 + 16a60f8 |
| STAGE_5 | `status` | 退休确认 + advance gate | ✅ 832e41f+16a60f8 |

### 8.3 PRM + GitNexus 融合 (T34)

`_monitor_api()` 在 user_prompt 中注入 `gate_data.gitnexus`:

```
GATE SCHEMA: ...
STATE FILE: ...
HARD EVIDENCE: ...
GITNEXUS CODE GRAPH: {"nodes":"1415","edges":"3537","clusters":"42","flows":"66",...}
Score this gate. Output only JSON.
```

API 评分者现在能看到完整代码图状态——不仅是"文件是否修改"，而是"代码图规模 1415 nodes/3537 edges"。关键阶段 (STAGE_3/4) 的 reasoning=high 深度分析可利用此上下文做跨模块影响评估。

### 8.4 rejected_edits 闭环 (T32)

三条路径均输出 `previous_rejections`:

| 路径 | 输出字段 | 用途 |
|:--|:--|:--|
| ALLOWED | `previous_rejections` | 告知 agent 之前犯过什么错 |
| BLOCKED_BY_MONITOR | `previous_rejections` | 告知 agent 这次又犯了什么 |
| BLOCKED_BY_GATES | `previous_rejections` | 同上 + violations 明细 |

### 8.6 R5.5-R5.8 综合

四轮 16 子 agent 交叉审查闭环 (R5.5→R5.8, 15 commits):

| 阶段 | 可交付物 | commits |
|:--|:--|:--|
| R5.5 | T29-T31: edit budget + rejected buffer + slow update | `d6f5a55` ~ `4b1466e` |
| R5.6 | T32-T35: rejected 闭环 + GitNexus + PRM+GitNexus + gate | `7a44998` ~ `65318fb` |
| R5.7 | T36-T38: 文档对齐 + Red Flag + Bridge 同步 | `32508bb` |
| R5.8 | 4 轮 cross-review: 22 漏洞修复 (2 CRITICAL + 11 HIGH) | `48e0ca4` ~ `d953c97` |

门禁清单 (P0-P9):
| # | 门禁规则 | 引入 |
|:--|:--|:--:|
| P0 | realpath 符号链解析 | R5.8 |
| P1 | SHA256 state 校验 (exit 1 on mismatch) | R5.8 |
| P2 | git worktree list 注册验证 | R5.6 |
| P3 | path-R-phase 匹配 | R5.6 |
| P4 | plan 恢复路径正确 (检查 worktree 非主仓库) | R5.6 |
| P5 | empty worktree/branch 阻断 | R5.8 |
| P6 | --allow-empty commit 阻断 | R5.8 |
| P7 | PR merge 验证 | R5.8 |
| P8 | Push URL 正则 (`^https://[^/@]+@github\.com/spz-ecosystem/...`) | R5.8 |
| P9 | git stash 检测 (worktree_dead fallback) | R5.8 |

### 8.7 R5.9 ✅ 已完成

| 组件 | SkillOpt 增益 | 优先级 | 设计完成 |
|:--|:--:|:--:|:--:|
| Protected Regions (marker 阻断编辑) | **+22.5** | P0 | ✅ 116be6d |
| Cosine Scheduler (跨 R-phase 预算衰减) | +3.8 | P1 | ✅ 116be6d |
| Best Snapshot (best_score/best_step) | 中 | P1 | ✅ 06336fe |
| Reflect Optimizer (消费 rejected 产生改进) | — | P3 | ✅ 06336fe |

### 8.8 经验管理层设计规格 (R6.X 实现)

> **实现时机**: R6.X — Bridge Python 侧
> **Gatekeeper 职责**: 输出结构化数据，Bridge 负责存储/检索/蒸馏

#### 8.8.1 四层记忆金字塔

借鉴 TDAI (Tencent DB-Agent-Memory) 分层架构:

| 层级 | 内容 | 格式 | 谁写 |
|:--|:--|:--|:--|
| L3 R-phase 纲要 | 每个 R 的经验摘要 | Markdown | Bridge 蒸馏 |
| L2 操作级经验块 | 按操作类型分组（push/commit/merge） | JSON | Bridge 聚合 |
| L1 原子记录 | 每次具体操作的结果 | JSON | Gatekeeper 输出 |
| L0 原始日志 | 完整执行 trace | Raw | Gatekeeper 输出 |

#### 8.8.2 质量控制机制

借鉴 TDAI l1-dedup + SkillOpt reflect.py:

| 机制 | 作用 | 来源 |
|:--|:--|:--|
| 写入前冲突检测 | 新经验与已有经验重复？store/merge/skip | TDAI l1-dedup |
| 引用计数 + TTL | 被多次验证的 pattern 升级，长期未验证降权 | ECHO + Memory Management |
| 错误传播防护 | 错误 pattern 导致更多失败时自动标记删除 | Memory Management 2025 |
| Mini-batch 聚合 | 同类操作失败按类型分组，提取共性模式 | SkillOpt reflect.py |
| 成功/失败平衡 | 不只存失败，也存成功路径 | ERL 2026 |

#### 8.8.3 消费方

| 消费方 | 用途 | Gatekeeper 参与 |
|:--|:--|:--|
| advance gate | 历史失败注入 prompt | 已实现 (previous_rejections) |
| reflect API | 动态反思 | 已实现 (v4-flash) |
| guard-edit | 成功路径放行 | 待实现 |
| scheduler | edit_budget 动态调整 | 待实现 |
| project_rules.md | 规则沉淀 | 待实现 |

#### 8.8.4 Gatekeeper 输出格式对齐

Gatekeeper 需确保以下 JSON 输出可被 Bridge L1 层消费:
- `rejected_edits`: 已有，需补充 `failure_type` 字段（推理断裂/约束违反/循环/遗漏）
- `hard_evidence`: 已有，格式已标准化
- `reflect`: 已实现 API 调用，返回值需补充 `patch` 字段（可执行补丁，非泛泛建议）
- `best`: 已有，需跨 R 持久化（当前 discover 会清空 gate_data）

#### 8.8.5 合格标准

- 新操作失败时，3 步内找到历史上类似失败案例（L3→L2→L1 钻取）
- 同类操作的失败模式被聚合为可执行补丁
- 跨 3 个 R-phase 未验证的 pattern 自动降权
- 成功路径和失败路径都被记录
- 经验库不随时间膨胀（冲突检测 + TTL）

---

## 9. Design Provenance

Patterns adapted across academic-research-skills (CC BY-NC-SA 4.0), bridge-r-phase, and SPZ native:

| Pattern | Adapted For Gatekeeper |
|:---|:---|
| **SCR Protocol** (Socratic Mentor) | STAGE -1 流程 B 大版本计划质询 (plan-refinement v2.0) |
| **Devil's Advocate** (F1-F7 + Concession Threshold) | STAGE -1 流程 B 大版本评估对抗审查 |
| **Phase Boundary** (Pipeline Orchestrator) | 已在 bridge-r-phase 实现，Gatekeeper 待吸收 |
| **Sprint Contract** (L2 Review) | 已在 bridge-r-phase Gate 3 实现，Gatekeeper 待吸收 |

| **Progressive Disclosure** (Anthropic Skills 3-level) | Core SKILL.md 189 行 + references/ 31 文件 (.md + .json，含 stage 定义/红队 schema/审计 schema) |
| **RETROSPECTIVE Gate 9** (bridge-r-phase) | STAGE 5b — 每 R 结束后技能自我改进 |
| **Dependency Upgrade Assessment** (STAGE -1 流程 A) | bridge-r-phase Gate 1.5 4 行矩阵版 |
| **GitNexus 4-Layer Architecture** (rg + ast-grep + context + query) | Gatekeeper 统一 --skip-git 移除 + impact/context 死代码检测 |

| **Test Self-Cycle Dead Code Detection** (bridge-r-phase Gate 7) | 死代码检测三关：context → rg production scan → plan table。Bridge R7.5: verify_integration.py 自循环掩盖死代码 |

**Differentiation Principle**: bridge-r-phase 和 spz-gatekeeper-r-sequence 共享 DNA（L1-L9 审查、Phase Boundaries、Sprint Contracts），但**不得成为镜像**。Gatekeeper 的 CI/worktree/token 旋转/CTest 是 Bridge 不具有的执行机制。借鉴时适配，不复制。

---

## 10. MoA 聚合：归属、批边界与失败补救（2026-11-02）

**默认设计（有意，不是缺陷）**：

- `task_bound`：只聚合与锚任务指纹一致的 references；task 不同 ⟹ 排除，trace 记
  `attribution.excluded_other_tasks`。目的 = 防跨任务污染（论文页「归属」项按此显示）。
- `batch`：同计划多批默认按批分节、单臂批降权；跨批比较必须显式 `--allow-cross-batch`。
- 因此 6 臂若回答 Q1–Q4（task 串不同），默认只会留 1 条；这是**调用面**要显式放开，
  不是聚合器 bug。

**6 臂调用公式**：

```bash
moa-aggregate --chain --allow-cross-task --allow-cross-batch --expect 6 \
  --auto-remediate --out <聚合.md> --html <报告.html>
```

**失败显形**：

- `degraded:true` + hint（只聚合 1 条且排除了异任务）；
- `--expect N` 不符 ⟹ `EXPECTED_ARMS_MISMATCH`，rc=1；
- `--html` 模式 error 也 rc=1；未给 `--out` ⟹ `aggregate_omitted`（正文不留档）。

**自动补救（有界）**：

- `--auto-remediate` 仅在 `--expect` 给定且不足、`suspect_count=0`、且缺口可由 task/批边界解释时，
  自动放宽一次并重聚合；trace 记 `auto_remediation: {applied, before, after}`。
- 有 `suspect`（投毒可疑）时不自动放宽，必须人工复核。

**人工补救顺序**：

1. 看 `trace.attribution.excluded_other_tasks` / `trace.batch.single_arm_batches`；
2. 补 `--allow-cross-task` / `--allow-cross-batch`（或 `--auto-remediate`）；
3. 用 `--expect 6` 断言臂数；4. 用 `--out` 留档；5. 页面按本轮 state 重生成，别复用旧 HTML。

---

## 附录：CLI 通信协议 + Provider 架构

> 与论文无关，是 Gatekeeper 特有的工程约束。但影响 monitor 输出的读取方式和 Provider 选择。

**通信优先级** (R5 编码转义教训: WSL UTF-8 → trae-sandbox CP936 → 乱码):

| 优先级 | 渠道 | 用途 | 不受编码转义影响 |
|:--:|:--|:--|:--:|
| 1 | exit code | agent 主通信 (0=PASS, 1=BLOCK) | ✅ 数字 |
| 2 | JSON stdout | 人类/审计读取 | JSON field 纯 ASCII, 安全 |
| 3 | `.gatekeeper_monitor_api_tmp.json` | 人类审计全量 | 文件系统, 无 pipe |

exit code 是唯一的零损耗通信渠道——因为 0 和 1 在任何编码下字节相同。
详见 `project_rules.md §WSL 命令转义防护 #2` 和 `SKILL.md §CLI Execution Layer`。

---

**Provider 架构** (v4.18 — MiMo v2.6 平替集成；v2.5 系 2026-10-21 下线):

| 维度 | DeepSeek (默认) | MiMo (平替) |
|:--|:--|:--|
| **激活方式** | 默认 | `GATEKEEPER_PROVIDER=mimo` |
| **Actor 模型** | deepseek-v4-flash | mimo-v2.6-pro (旗舰全模态, 1M ctx；2026-09-22 起) |
| **Critic 模型** | deepseek-v4-flash | mimo-v2.6-flash (全模态高效；2026-09-22 起) |
| **API Base** | `api.deepseek.com/beta` | `api.xiaomimimo.com/v1`（2026-09-22 P0：Token Plan 旧域已弃） |
| **Key 变量** | `DEEPSEEK_API_KEY` | `MIMO_API_KEY` |
| **reasoning_effort** | `max` (思考模式) | 不传 (MiMo 不支持) |
| **response_format** | `json_object` | `json_object` |
| **Score scale** | 0-1 (原生) | 0-100 → CLI 归一化到 0-1 |
| **余额查询** | `/user/balance` endpoint | 无 (输出 warning + plan-manage 链接) |
| **reasoning_content** | 不回传 (单轮) | 不回传 (单轮, 无死循环风险) |

**Key 集中管理** (`set-key` 命令):
- `set-key deepseek sk-xxx` → 设置 `DEEPSEEK_API_KEY` (WSL env + Windows User env)
- `set-key mimo tp-xxx` → 设置 `MIMO_API_KEY` (WSL env + Windows User env)
- 持久化方式: PowerShell `SetEnvironmentVariable("...", "User")` → 注册表 `HKCU\Environment`
- 轮换: 同一命令覆盖旧 key, 重启 IDE 后 Process scope 生效

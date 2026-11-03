---
name: "spz-gatekeeper-r-sequence"
description: "ZTHL Aegis — deterministic governance harness for AI agents. Routes any gatekeeper-related request by change type: (1) plan phase advance (R-sequence / standing sequences), (2) skill self-maintenance (hook / gates / scripts), (3) ad-hoc patches, (4) cross-review / red-team / audit sequences, (5) finding registration. Invoke when entering, changing, or advancing ANY plan phase; when running cross-review/red-team/audit; or when a defect must be registered and closed. Trigger words: '推进' 'advance' 'R阶段' '交叉审查' '红队' '审计' 'standing' '提PR' '收尾' '计划评估' '发现登记' '技能自维护'."
---

# ZTHL Aegis（SPZ Gatekeeper）— 路由与契约层

本文件只做**路由与契约**；细节的单一事实源在 `references/`。执行任何阶段前必须 `Read` 对应文件，禁止凭记忆总结。

## ⛔ 硬约束：门禁域禁止裸 `Task`

本技能管辖的一切工作（技能自维护 / 阶段推进 / 交叉审查 / 计划质询 / 红队·审计序列 / 验收复验）**禁止**用宿主默认 `Task` 派子 agent，必须走 CLI 受约束通道：

| 场景 | 唯一通道 |
|:--|:--|
| 交叉审查 / 后 R 双独立 | `monitor --subagent --crossrev "<任务>"` |
| 计划质询 | `plan-refinement <plan> --task "<任务>"` |
| 红队角色 | `monitor --subagent RED-SCOPE\|RED-EXPLOIT\|RED-POSTEX\|RED-REPORT` |
| 自由文本窄任务 | `monitor --subagent "<任务>"`（档位 = env `SUBAGENT_TIER=1-4`，无 `--tier` flag） |

理由：宿主默认 Task 无工具白名单、无 token/item 预算、无轮数上限、不产生 audit/finding 留痕 ⟹ 治理不可审计。

## 零参入口（裸调用契约）

用户只发技能名而**没有任务描述**时，唯一允许的行为是**先出状态、再等指令**：

1. `bash gatekeeper-cli.sh state`：有 active 阶段 ⟹ 打印阶段 / 分支 / worktree / 编辑预算 / 下一步建议，然后停。
2. IDLE / DONE ⟹ 读 state 的 `project_type` / `target_repo` / `gate_data` 摘要；**只有 state 缺失**才跑 `discover` 重建。随后列出三选一：新序列 / standing 序列 / 临时补丁。
3. 只有 1、2 双双失败才允许提问，且必须附失败原文。

## 变更类型路由

| 用户说 | 变更类型 | 路由目标 |
|:--|:--|:--|
| `上游更新` / `依赖升级` | 外部冲击 | standing (ECO-RESEARCH) → 评估 → ECC-IMPACT |
| `开始下一个版本` | 内部需求 | standing → 规划 → ECC-PLAN → 执行 |
| `改技能自身` / `修 hook` | 技能自维护 | ECO-RESEARCH → 登记 finding/plan → 落刀 → 复验 |
| `进入 R<N>` / `推送` / `提PR` / `收尾` | 标准执行 | STAGE 0-5 |
| `修个小 bug` / hotfix | 临时补丁 | **未实装**：CLI 无 hotfix/patch 命令；当前只能走 STAGE 1-2 手工流程（勿宣称「直通 CI」） |
| `记录发现` | 内部发现 | 写 ECC-FINDING |
| `重写计划` / `挑刺` / `质询` | 计划维护 | `plan-refinement` + 写侧机检 |

详细流程与 **STAGE-DUTY-MAP**（段职责 + 硬门 gate-id 清单，单一事实源）见 `references/meta-routing-protocol.md`。

## 事实基线（自动生成，勿手改）

<!-- GK-FACTS:START（由 scripts/gk_docgen_facts.py 生成，勿手改） -->
| 事实 | 值 | 来源（可复算） |
|:--|:--|:--|
| CLI 行数 | 12676 | `wc -l gatekeeper-cli.sh` |
| CLI 命令数 | 52 | `^_CMD_REG[` 计数 |
| 红队站点 | 16 | `gk_chain.py` 的 `Step("RED-*")` |
| 自检检查函数 | 37 | `gk_self_check.py` 的 `def check_*` |
| references 入库 md | 27 | `git ls-files references/*.md`（顶层） |
| 子代理角色 | 8 | `subagent_runner.ROLE_TOOLS` |
| hook R0 门禁 | Gate R0.1–R0.18（18 个） | `pre_tool_hook.py` 的 `Gate R0.N` |
| 红队向量 | 156 | `references/red-vectors.json` |
| 情报源 | 24 | `references/red-intel-sources.json` |
| 解释器解析 | `scripts/py_resolve.sh`（发现式，无绝对路径） | `scripts/py_resolve.sh` |
<!-- GK-FACTS:END -->

> 漂移由 `doc-align` 的 `gk_facts` 项守护；更新跑 `python scripts/gk_docgen_facts.py --write`。

## CLI 与门禁

- `bash gatekeeper-cli.sh <cmd>` — 确定性执行层，CLI 支持 52 命令（清单单一事实源 = `references/cli-protocol.md`；未知命令/参数 → `exit 2` + `help [cmd]`）。
- 解释器：一律经 `scripts/py_resolve.sh` 发现式解析（`GK_PYTHON` → 本机 pin → 仓内 `.venv` → 通配 → PATH），**禁止写死个人 venv 路径**。
- hook 门禁：`pre_tool_hook.py`（Gate 0-9 + R0.x 家族）；治理范围 = 技能目录 + `.gatekeeper.scopes.json` 登记项目，范围外放行。
- 文档对齐：`doc-align`（0 API、IDLE 可用）；每轮 commit 前跑一次。

## 状态与容量

`.gatekeeper.state` 是单源（2.6 MB 墙，50/80/90/95% 水位，95% 拒写）。形态分工（base / domain / legacy_plan / worktree_local / artifact）、卫星片容量（10 轮 × 6 臂）、TTL/GC 与回收判据见 `references/state-storage.md`。

> 写入语义边界：`_checksum` 与 `state_lock` 只覆盖主 state 写路径；派生/归档写面是裸 `json.dump` ⟹ 不得宣称「所有 state 写入原子/带校验」。

## 子代理与工具面

- 工具面单源 = `scripts/subagent_runner.py::ROLE_TOOLS`（逃生位 `SUBAGENT_TOOLS` > 角色表 > 档位阶梯）。
- 红队三角色（scanner / exploiter / auditor）额外持有 `red_search` / `red_fetch`：只读文本、**禁下载**、`risk_tier=high` 的情报源须 `GK_RED_INTEL_SANDBOX=1` + KVM probe 通过（fail-closed）。
- 出网单口：`gk_web_tools` → `gk_evidence.record_egress`（链式台账）；**不新建出网口**。

## 红队与审计

- 16 站序列见 `scripts/gk_chain.py`；向量登记表 = `references/red-vectors.json`（代码只做执行器，`gk_red_vectors.py check` 守护双向集合等价）。
- 情报源登记 = `references/red-intel-sources.json`（顶会/预印本/厂商/高校/挑战库/CVE）。
- finding → 向量晋升须 `confirmed` + `repro_cmd` + `pre_fix_commit`；红队自产还须 `independent_verification`（防飞轮自证）。

## 跨阶段不变量（仍可执行的部分）

| 规则 |
|:--|
| 代码只在 feature worktree 改；主树只读（`pre-tool-check` + `cmd_push` 阶段门） |
| 计划不入 git（`docs/plans/` 被 gitignore），备份在 `docs/plan-backup/` |
| 推送 / PR 走 `git-workflow`，token 不入库、不进日志 |
| 每次改动后跑对应验证；禁止同文件 sed + Python 混改 |
| 复杂脚本 → 先 Write 落盘再执行（规避 WSL 引号逃逸链） |
| `state_lock` 唯一持有者 = python（`gk_json_utils.state_lock`，可重入） |
| 编辑预算按会话隔离；单文件编辑有硬上限（`GK_EDIT_FILE_CAP` 可调） |
| 工具调用（edit/commit/push）前先 `pre-tool-check`；阶段 IDLE/DONE 时阻断编辑 |

## 死代码检测

三关（**不可停在第 1 关**）：① `context` 的 incoming 为空 → ② 查生产入口（可执行入口 / 图级 PDG 可达性 = `audit --pdg`）→ ③ plan 对应阶段显式登记消费目标。**只被 `test_*` 调用 = 测试自循环 = 死代码**。自动化：`monitor --local` 的 dead_code_gate1/2/3、`audit --depth`。

## Red Flags — STOP

- `pre-tool-check` 返回 BLOCK → STOP，先补阶段/门禁。
- 裸 `Task` 派子 agent → 违规（无 hook 兜底，只在事后审计里表现为证据链缺失）。
- 保护区编辑：行级命中 = WARN 放行 + 强制留痕；落刀须 commit + 文档双留痕。
- 跨 OS 跑 git **写**操作 → 统一 `wsl git -C`（抢锁/refs 丢失面）。
- `git reset --hard` / `git push --force` 未备份 → STOP。
- 危险命令藏脚本内 → Gate R0.3 逐行扫描；测试脚本禁含指向自身/未备份目录的 `rm -rf`。
- 文档-代码对齐靠手比 → 跑 `doc-align`（有 `gk_facts` 自动事实块与文件地图机检）。
- 给用户阶段指令前不 Read 对应 reference → step omission（见 `agent-self-correction`）。

## Stage Detail Files（按需加载）

| Stage | Reference | 何时读 |
|:--|:--|:--|
| STAGE 0 | `references/stage-0-start.md` | "进入 R<N>" |
| STAGE 1 | `references/stage-1-code.md` | 开始编码 / 首次 push 前 |
| STAGE 2 | `references/stage-2-ci.md` | "推送然后监控" / CI 失败 |
| STAGE 3 | `references/stage-3-review.md` | "CI 过了" / "跑交叉审查" |
| STAGE 4 | `references/stage-4-merge.md` | "提PR" / "PR 已合并" |
| STAGE 5 | `references/stage-5-retire.md` | "收尾" |
| STAGE 5b | `references/stage-5b-retrospective.md` | 每轮结束后的回顾 |
| 流程 A/B/C | `references/meta-routing-protocol.md`（含 STAGE-DUTY-MAP） | 路由 / 门禁来源 |
| R6 工作流 | `references/stage-6-r6-flow.md` | "进入 R6" |
| WASM / CI 模板 | `references/wasm-engineering-template.md` / `references/ci-pipeline-template.md` | 新项目初始化 / workflow 改动 |
| 插件加载安全网 | `references/plugin-loading-test-framework.md` | 新增按需加载插件 |
| 序列节点安全网 | `references/sequence-node-safety-net-template.md` | 新增/强化序列节点 |
| 标准维护模块 | `references/standard-maintenance-module.md`（实存能力 + 未接线缺口表；约定本身失效时的发现→归属→修复→回归） | 改标准/模板/维护约定 |
| 红先测试模版 | `references/red-arm-templates.json` + `scripts/gk_red_arm_gen.py` | 写红先臂 |
| 红队向量登记 | `references/red-vectors.json` + `scripts/gk_red_vectors.py` | 加/改/复核向量 |
| 红队情报准入 | `references/red-intel-sources.json` + `scripts/gk_red_intel.py` | 红队联网检索 |

> 给用户阶段指令前，必须 Read 对应的 reference 文件，禁止凭记忆总结。

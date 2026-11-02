# 标准维护模块（自愈层）

<!-- DOC-META
title: 标准维护模块（自愈层）
type: reference
owner: spz-gatekeeper-r-sequence
status: public
updated: 2026-11-02
-->

> **性质**：batch8 **R-T7.13c「4 制品」中的第 2 件 = CI 标准维护模块（自愈层）**。
> 4 制品 = ① CI 模板 ② **CI 标准维护模块（本件）** ③ WASM 模板 ④ WASM 标准维护模块；
> 本仓实存 ①②③，④ 的实现属 WASM 项目（本仓只有委派入口，见 §2）。
> （2026-11-02 口径订正：旧版把本件写成「4 制品第 4 件，前 3 件 = ci/wasm/sequence-node」——
> 与 batch8 R-T7.13c 的清单不符。`sequence-node-safety-net-template.md` 是 standing 侧的**安全网模板**，
> 不在 batch8 的 4 制品计数内，见 §0。）
> **边界原则**：本模块**只登记实存能力**。规划里有、本仓未接线的能力一律标 `未接线`，**不写成已具备** ——
> 门禁文档写空头承诺，等于给假绿背书。
> **锚形态**：一律**符号锚**（`path::symbol` / 命令名 / 文件名），不写行号 —— 行号会漂，且本文件旧版
> 就因写死行号而在两周内全部失效（2026-11-02 逐项复核）。
> **最后核对**：2026-11-02（逐项 grep 实证，见 §4）。
> **所属计划**：`docs/plans/2026-10-28-standard-sequence-compression-plan.md` T5（✅ 已收口）。
> 该计划 T2/T6 **仍阻塞**（coder 族可判样本 = 0、`state.findings = 0`，无可绑红先臂的缺陷），
> T4 已降级并入 T10，T9 已落刀为「门去重」（段数保持 6）—— 引用本文件时不要假设计划已 100% 完成。

---

## 0. 工程模板目录（谁定义「长什么样才算对」）

本仓的「模板」分四层，**不要混用**：工程模板 = 可复制的产物骨架；安全网模板 = 守卫的设计规范；
任务族模板 = 子代理的窄任务卡；输出 schema = 机器可读契约。

| 制品 | 层 | 回答什么问题 | 何时用 | 谁检查 | 公开包 |
|:--|:--|:--|:--|:--|:--|
| [`ci-pipeline-template.md`](ci-pipeline-template.md) | 工程模板 | CI 管线长什么样（矩阵 / 触发 / 产物缺失检测 / `set -euo pipefail` + `shell: bash`） | 新仓接入 CI、改 workflow | `gatekeeper-cli.sh doc-align` 的模板符合性面 + CI `security-audit`（actionlint，观察期） | ✅ |
| [`wasm-engineering-template.md`](wasm-engineering-template.md) | 工程模板 | WASM 构建 / 验证骨架（Emscripten 统一版本、`-Oz`、导出前缀、native 对照） | 有 wasm 产物、改构建链 | `pre-check wasm`（委派项目 `wasm-pre-check.sh`）+ CI 构建矩阵 | ✅ |
| [`sequence-node-safety-net-template.md`](sequence-node-safety-net-template.md) | 安全网模板 | 新增序列节点时 G/B/C/T/D 怎么实例化、A1–A8 如何裁剪、落笔前纪律 | 新增/强化 standing、standard、审计、红队节点 | `gk_node_guard` 的节点注册与前置谓词 + `doc-align` | ✅ 正文随包；`docs/plans` 内部计划指涉由导出时 `GK-PUBLIC:CUT-*` 标记剥离（收敛正本已转公开，指针保留） |
| **本件**（standard-maintenance-module） | 自愈层 | 上述约定**本身失效**时，谁发现、谁修、怎么回归 | 改模板 / 改门禁 / 门禁失效复盘 | 本文件 §4 的复核命令 + `doc-align` | ✅ |
| [`red-arm-templates.json`](red-arm-templates.json) | 数据模板 | 红队打击臂的模板（向量、情报源、约束） | `audit --red` / RED-* 站 | `gk_red_vectors` / `gk_chain` | ✅ |
| `references/agent-families/*.json` | 任务族模板 | 子代理的窄任务卡（`test_first` / `verify_cmd` / `allowed_paths` / `family`） | 派发 coder / docs / audit 子代理 | `gk_agent_family.classify` + runner 侧校验 | ✅（paper-review 族按白名单排除） |
| `monitor-schemas/*.json` | 输出 schema | 各站 subagent 输出的字段契约 | `monitor --subagent` / `audit --crossr` 派发 | `subagent_runner` 后处理（fail-closed） | ✅ |
| [`stages.md`](stages.md) + `references/stage-*.md` | 流程指南（**非模板**） | 每段做什么、退出条件是什么 | 推进 STAGE_0→5 | `meta-routing-protocol.md` 的 `STAGE-DUTY-MAP` 机检 | ✅ |

**选型口诀**：产物骨架找 `ci-pipeline` / `wasm-engineering`；节点守卫找 `sequence-node`；
任务派发找 `agent-families`；输出对不上就查 `monitor-schemas`；**模板本身坏了才找本件**。

### 0.1 与前 3 件模板的分工

| 制品 | 回答的问题 | 失败时的动作 |
|:--|:--|:--|
| ci-pipeline-template | CI 管线长什么样 | 红了按 [`stage-2-ci.md`](stage-2-ci.md) 诊断 |
| wasm-engineering-template | WASM 工程约定 | 按 PRE/P2 约定改 |
| sequence-node-safety-net-template | 序列节点安全网怎么设计 | 按节点门禁拦 |
| **standard-maintenance-module（本件）** | **上述约定本身失效时，怎么被发现、谁修** | **发现 → 归属 → 修复 → 回归** |

一句话：前 3 件是**被检查的对象**，本件是**检查者与修复者的编成**。

---

## 0.2 各类安全网目录（谁在什么时候拦）

> 完整的方法论正本分散在各文件；本节只做**索引 + 边界**，避免把「检测」误当「边界」。
> 状态：✅ 实装 ／ ◐ 部分（有入口但非硬门）／ ✗ 未装。

| 安全网 | 拦什么（对象） | 触发点 / 判据（符号） | 失败语义 | 适用边界 |
|:--|:--|:--|:--|:--|
| **计划写入安全网（PW-SN）** | 计划文本的**可机检项**（判据现状、开关命名、锚形态） | `scripts/gk_plan_lint.py`；质询前置 `plan-gate` | 红先不过 → 拒进质询 | 只管机检项；语义判断留 R 侧（`plan-refinement`） |
| **插件加载安全网** | 按需加载的探测式插件（漏加载 / 误加载 / 错误加载） | `scripts/gk_bashpy_loader.py::load_status`（`release` → `dev` → `missing`） | 具名状态；tampered/missing 不静默 | 只覆盖加载侧；调用契约由 `plugin-loading-test-framework.md` 约束 |
| **序列节点安全网（SN 五元组）** | 节点**进入**执行体前的四类失败（前置缺失 / 输入不全 / 名称歧义 / 无复验） | `scripts/gk_node_guard.py`（`NODE_REGISTRY` / `node_guard` / `route_map`）+ `pre_tool_hook.py` 的 `_hslsn_*` | fail-closed 阻断 + 引导补全 | 节点级；**不保证序列收敛**（A8/RCA 另见 `sequence-node-safety-net-template.md §2.3`） |
| **XSPI 污染防御** | 不可信内容（跨站 / 间接提示注入）导致的越权动作 | `scripts/gk_task_gate.py::check`（provenance / leading / poison / bounded）+ 容器化（权限与路径边界） | 命中 → 阻断或要求 ACK | **检测不是边界**：词表必然漏（GB-1/GB-2 已登记）；靠容器限制「能导致什么」 |
| **文档一致性** | 文档 ↔ 代码 ↔ 索引漂移 | `scripts/gk_doc_align.py::run_all`（C1–C5、`check_stage_duty_map`、`GK-FACTS`/`GK-REFS`）+ `gk_docgen_facts.py` 再生 | FAIL / SKIP 分流；**锚失效必须 FAIL，不得 SKIP** | 只查可机检事实；措辞与语义不在面内 |
| **CI / 构建** | CI 红、workflow 变更、WASM 构建失败 | `scripts/ci_smoke.sh` + `.github/workflows/ci.yml`（`smoke` / `platform-smoke` / `security-audit`）+ `ci-diagnose` + `pre-check wasm` | 红即停；`actionlint` 缺工具时 **SKIP ≠ PASS** | **无自动修复回路**（§2）；修复仍由人或子代理推进 |
| **密钥 / 签名** | 密钥泄露、私钥替换、过期、签发面篡改 | `_verify_key_integrity`（`key-meta.json` + SHA256 + pubkey 指纹）、Ed25519 验签、`security-incident-response.md` 处置流程 | `tampered:*` → fail-closed，拒绝使用该密钥面 | 不保护宿主环境；`.keys/` 永不入公开包 |
| **状态完整性** | state 篡改、并发读-改-写、半写 | `scripts/gk_json_utils.py::state_lock`（`fcntl` / `msvcrt`）+ `_checksum` + CLI 单一写入口 `_state_write` + `PROTECTED_REGION` | 失配 → 拒写 / 拦停并留痕 | 不覆盖外部进程直写；hook 侧另有 `pre-tool-check` 复核 |
| **经济 / 额度门** | 编辑配额、提额、熵、申诉 | `scripts/gk_budget_ledger.py` + `scripts/gk_gate_entropy.py` + `scripts/gk_gate_appeal.py` + `gk_advance` 的 appeal 门 | 超额 → BLOCK；熵越线 → `APPEAL_REQUIRED` | standard 侧 **credit 记账未接**（计划 §11）；`credit_score` 目前零消费点 |
| **审计 / 红队** | 治理面缺陷（策略、密钥面、供应链、逃逸） | `gatekeeper-cli.sh audit --red`、RED-* 站（`scripts/gk_chain.py`）、审计署 registry | 产出 finding + 报告；高优项进阻塞面 | 需解释器与密钥面；无 gold 的读数不得宣称共识 |
| **收敛早停（A8/RCA）** | 迭代审查空转（分数不涨 / `μ` 不降） | `scripts/gk_convergence_evaluator.py`（`pre-check convergence --loop`）+ `gk_convergence_estimator.py`（数学核） | `NO_CONVERGENCE` ⟹ 早停 + 强制转机制修复 | 需 `μ` 序列；测量 finding 不入 `μ`；轮数不足只报 `INSUFFICIENT_ROUNDS` |

**三条使用纪律**：

1. **检测 ≠ 边界**（XSPI）：措辞词表只能降噪，真正的边界是容器（路径 / 权限 / 外发通道）。
2. **现状即 PASS = 假绿**（`sequence-node-safety-net-template.md §2.2`）：每条判据必须给出修前必失败的读数。
3. **未接线不得当门禁**（本文件 §2）：把规划里的能力当已有门禁依赖，等于给假绿背书。

---

## 1. 实存能力（已接线，可直接调用）

### 1.1 `ci-diagnose` —— CI 失败的**取数**层

CLI 面（`gatekeeper-cli.sh`，无 LLM、纯取数）：

```
bash gatekeeper-cli.sh ci-diagnose list [COUNT]        # 列最近 workflow_runs
bash gatekeeper-cli.sh ci-diagnose fetch <RUN_ID>      # 下载失败 job 日志到 /tmp/ci_logs/<run_id>/
```

- **注册面**：`_CMD_REG[ci-diagnose]`；子代理工具白名单 `valid_tools` 含它；`gk_suba_tiers.ROLE_TOOLS` 的
  tier2 / tier3 工具串均含它 ⟹ **子代理可自主取 CI 日志**，不需人转贴。
- **视图层**：`gk_views.py::cmd_ci_runs_table` 渲染定宽表；`ci-diagnose fetch` 无失败 job 时返回
  `{"ok": true, "jobs": 0}`。
- **接线**：`subagent_runner.py::gk_ci_diagnose_gk` → `_gatekeeper_cli("ci-diagnose", ...)`。
- **节点归属**：`gk_node_guard.py::_CHECKLISTS["STAGE_2"]` 登记为 STAGE_2 能力项。
- **前置**：需 `GITHUB_TOKEN` / `GH_TOKEN`（或 `--token`）；仓内无 origin 远端时直接报错。

### 1.2 `actionlint` —— workflow 静态校验（**部分接线**）

- `.github/workflows/ci.yml` 的 `security-audit` 作业会调 `actionlint`，但：
  ① 该作业 `continue-on-error: true`（**观察期，不拦合并**）；
  ② 未安装 `actionlint` 时打印 `SKIP (not a pass)` 并继续 ⟹ **缺工具不等于通过**。
- 结论：**有自动化入口，但还不是门**；把它当硬门使用前须先去掉 `continue-on-error` 并让缺工具 FAIL。

### 1.3 STAGE 归属

| STAGE | 本模块提供的能力 | 载体 |
|:--|:--|:--|
| STAGE_1（code） | 模板符合性 —— 产出物对不对得上前 3 件模板 | 前 3 件模板 + `doc-align` |
| STAGE_2（CI） | CI 红了的**诊断取数** | `ci-diagnose` list/fetch |

> 段职责与 gate-id 的**唯一事实源** = [`meta-routing-protocol.md`](meta-routing-protocol.md) 的
> `STAGE-DUTY-MAP` 块（机检 = `gk_doc_align.py::check_stage_duty_map`）。本文件**不复制**该表，
> 只声明本模块在某段「提供什么能力」。

---

## 2. 未接线 / 部分接线能力（规划有、本仓无）

> 这一节是本文件的核心价值：**把「规划里有」与「仓里有」分开**。
> 下表每一项都 grep 实证过（见 §4 命令）。未接线 ≠ 否定其价值，而是
> **当前不能当作已有门禁来依赖**。

| 能力 | batch8 出处 | 本仓实态 | 影响 |
|:--|:--|:--|:--|
| **actionlint** 自动校验 | R-T7.13c「workflow 变更后强制 actionlint + zizmor」 | **◐ 部分接线**：CI `security-audit` 调用，但 `continue-on-error` + 缺工具 SKIP（§1.2） | workflow 改动**无硬校验门** |
| **zizmor** 静态分析 | 同上 | **✗ 未接线**：仅 `gk_doc_align.py` 注释与 `gk_self_check.py` 的 `na` 理由提及 | 供应链静态面（权限/注入/凭证）无机器校验 |
| **Auto-Fix 自愈循环**（≤3 次） | R-T7.13c「CI 失败自动诊断→修复循环」 | **✗ 未接线**：`ci-diagnose` 只取数，无修复回路；仓内唯一 `--auto-fix` 属 **WASM 项目脚本**（`pre-check wasm` 委派） | CI 红仍需人/子代理介入修 |
| **结构化失败摘要**（T45） | R-T7.13c T42–T48 | **✗ 未接线**：`ci-diagnose fetch` 只落原始日志（每 job 末 50KB） | 失败信息靠人读原始日志 |
| **WASM 标准维护模块**（PRE.10 错配 + P2 符号前缀） | batch8 WASM 自愈层（4 制品第 4 件） | **✗ 本仓无实现**：`pre-check wasm` 只把参数转交项目侧 `<worktree>/scripts/wasm-pre-check.sh`；项目无该脚本时 fail-loud | 本模块不覆盖 WASM 自愈；能力边界在 WASM 项目 |

### 2.1 `_check_ci.sh` 的实态

`scripts/_check_ci.sh` = **11 字节，仅 `#!/bin/bash`**（无换行结尾，故 `wc -l` 报 0）。
即：**它是个桩，不是检查器**。任何引用它当作「CI 检查」的地方都是假锚。

---

## 3. STAGE_1/2 如何引用本模块

- **STAGE_1**：产出物须符合前 3 件模板 ⟹ 见各模板自身 §0 适用边界；本模块不重复其内容，只声明「模板符合性由 STAGE_1 门禁承载」。
- **STAGE_2**：CI 红时的取数入口 = `ci-diagnose list` → `ci-diagnose fetch <RUN_ID>`；诊断后的修复循环**目前无自动化载体**，由执行者（人或子代理）按 [`stage-2-ci.md`](stage-2-ci.md) 的诊断流程推进。
- 两段的**职责与硬门 gate-id** 不在本文件重述 —— 以 `meta-routing-protocol.md` 的 `STAGE-DUTY-MAP` 为准。

---

## 4. 缺口的复核命令（可复算）

```bash
# 逐项实证（在仓根执行）；输出为 0 / 仅注释命中 = 未接线
rg -n "actionlint" .github/workflows/ scripts/ gatekeeper-cli.sh   # 期望：ci.yml + 注释
rg -n "zizmor"      .github/workflows/ scripts/ gatekeeper-cli.sh  # 期望：仅注释/na 理由
rg -n "pre-check wasm" gatekeeper-cli.sh scripts/                   # 期望：cmd_pre_check 委派
wc -c scripts/_check_ci.sh                                          # 期望：11（纯 shebang）

# ci-diagnose 实存确认（符号锚，不记行号）
rg -n "ci-diagnose" gatekeeper-cli.sh scripts/gk_suba_tiers.py scripts/subagent_runner.py scripts/gk_node_guard.py
```

**缺口补齐时的义务**：把 §2 表中对应行从「未接线」改「已接线」并**填上载体坐标（符号）**，
且同批新增红臂（无臂不算接线 —— T10 的教训：代码在、臂缺 ⟹ 假绿）。

---

## 5. 本文件自身的维护契约

- 被 STAGE_1 / STAGE_2 指南引用（公开包 = [`stages.md`](stages.md)；T5 出口判据）。
- §0 的模板目录与 §0.2 的安全网目录是**索引**，不是正本：新增/删除模板或安全网时同步本表，
  方法细节仍以各自文件为准。
- §2 缺口表是**活的**：每接线一项，改一行并补臂。
- **禁**把 §2 的项直接删掉当作「已解决」——必须改成「已接线 + 载体坐标」，否则缺口史丢失，下轮又会有人按 batch8 规划误以为已具备。
- **禁**在本文件写死行号；锚形态一律符号（`path::symbol` / 命令名 / 文件名）。
- **公开副本单源**：正文可公开、但夹带内部资料的文档（当前 = `sequence-node-safety-net-template.md`），
  用 `GK-PUBLIC:CUT-START` / `GK-PUBLIC:CUT-END` 两个 HTML 注释标记包住内部块；`oss_scrub export`
  导出时整块剥离（标记不平衡 ⟹ 该文件拒发），`pack_release.py` 拒收仍含标记的树 ⟹
  **公开副本永远由私仓生成，改私仓即自动刷新，不维护第二份手工副本**。

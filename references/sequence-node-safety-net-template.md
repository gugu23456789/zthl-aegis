# 序列节点安全网模板（Sequence-Node Safety Net Template）

<!-- DOC-META
title: 序列节点安全网模板（Sequence-Node Safety Net Template）
type: reference
owner: spz-gatekeeper-r-sequence
status: public
updated: 2026-11-02
-->

> **性质**：技能仓库基础设施模式文档（target_repo=skill）。2026-08-27 由用户质询驱动——
> 暴露 standing 序列安全网不完善（subagent 读不全/名称歧义投毒/基线未刷新），要求参考
> 加载安全网 + H-SLSN + 数学形式化设计固定模板。
> **参考实现**：`scripts/gk_bashpy_loader.py`（加载安全网）、`scripts/pre_tool_hook.py` 的 `_hslsn_*`（H-SLSN，符号引用）。
> 数学形式化的早期设计记录属内部计划（`docs/` 不随开源发布）；现行口径以本文件 §1 为准。
> **公开副本（2026-11-02）**：`scripts/oss_scrub.py export` 会按本文件的**内部块标记**整块剥离 ⟹
> 公开包中的本文件是**导出时自动生成**的脱敏版（无第二份手工副本，改私仓即自动刷新）；
> `scripts/pack_release.py` 拒收仍含内部块标记的树（防把私仓原件打进发布包）。
> **适用范围**：standing 序列节点（`ECO-RESEARCH`→`ECO-EDIT`→`ECO-VERIFY`→`ECO-DOC`；2026-10-28 A4
> 由 5 站压缩为 4 站，`ECO-SCAN`/`ECO-READ`/`ECO-AUDIT` 仅作别名）、
> standard 节点（STAGE_0-5）、plan-refinement 节点、任何 R-T* 子任务节点。

---

## 0. 为什么需要这份模板

> **实装状态（2026-10-26 复核）**：本模板由 `scripts/gk_node_guard.py` 承载——
> `NODE_REGISTRY` 节点注册（`advance` 未知节点硬阻断）、`node_guard` 前置产物 G 谓词、
> `route_map()` 总运行线路、`station_announcement()` 车站播报均在（按符号核对，不写行号）。
> 本文件继续作为**新增节点守卫的设计规范**（新增节点时按 §6 验收逐条核对）。

序列节点 = standing/standard 管道中一个可独立执行的阶段（`ECO-RESEARCH`、`ECO-EDIT`、STAGE_1……）。
每个节点由 agent 驱动，天然有四种失败模式，缺省实现必然踩：

| 失败模式 | 语义 | 默认实现的坑 |
|:--|:--|:--|
| **前置缺失** | 节点所需前置产物不存在（源文档/基线/上下文） | 带缺开工 → 结论建立在缺失事实上 |
| **输入不全** | subagent 没读全大文档/工具截断无提示 | 结论基于部分输入（质询 root cause A） |
| **名称歧义** | CLI 名 vs Skill 名混淆、未知命令放行 | 错误名被放行 = 天然投毒点（质询 root cause B） |
| **无复验** | subagent 输出后不评审/不双盲评分/不密封 | 单点结论无交叉验证（质询 root cause D） |

协议目标：四种失败模式全部**显式检测**，节点执行决策可审计（GK_DBG_LOG + 观测链），
前置产物齐备（代码库地图 + 窄任务清单）后才允许节点进入执行体。

---

## 1. 统一范式（数学形式化，对齐 H-SLSN §4.3）

每个序列节点安全网 = 同一五元组 `SN = ⟨G, B, C, T, D⟩`（**安全网五元组**，下称 `SN_net`；**勿与 H-SLSN §4.3 的「守卫状态机五元组」`M = (S_g, E₂, δ, s₀, F)` 混用** —— 二者同称"五元组"但**对象不同**）：

| 分量 | 语义 | 数学类型 |
|:--|:--|:--|
| **G** guard 谓词 | 进入检测（前置产物齐备 + 名称精确 + 输入完整） | G: 事件流 E → {0,1} |
| **B** body | 拦截/引导/修复 + 状态更新 | B: E × S → S |
| **C** 计数器 | attempts/迭代上限（有界重试） | C: S → ℕ |
| **T** 时间守卫 | TTL/冷却（时间自愈） | T: S → ℝ |
| **D** 降级策略 | fail-closed 硬阻断 \| fail-open 软提示 \| 人工升级 | D: S → 动作 |

统一循环（与 H-SLSN 同构）：

```
for each 节点事件 e ∈ E_node:
    while G(e) ∧ (C ≤ MAX) ∧ ¬T_expired:
        B(e)                      # 拦截 + 引导（含前置补全）
        C++
        if C > MAX: D()           # 降级（冷却降频/升级人工）
```

> **编号映射（仓库 ↔ 论文，2026-10-26）**：**对外引用一律用论文编号**；仓库 A1–A8 仅作内部子标签。
>
> | 论文 | 仓库 | 语义 |
> |:--|:--|:--|
> | **A1**（substrate，7 个 trace predicates） | A1–A7 | 原子性 / 完整性 / 谓词完备 / 有界终止 / 时间有界 / **可观测** / 可逆 |
> | **A2**（residual convergence） | **A8（RCA）** | 停止判据（`r̂` / `N*`） |
> | **A3**（admissible convergence） | 相位准入（P1–P8） | A2 只作用于准入观测 |
>
> 依据：论文 `app:axioms`「The three axioms are trace predicates ... $A_1$ (substrate) requires ... observability ... $A_2$ ... $A_3$」。
> **论文不改编号**：A1 已含 observability（append-only log 即其实现），A2/A3 是序列层贡献。

**公理（对齐 H-SLSN A1-A8，按节点裁剪）**：
- A1 原子性：状态更新 read-modify-write 串行化（`_hslsn_transact` 模式）
- A2 完整性：前置产物 checksum/存在性校验（缺失 → fail-safe 阻断）
- A3 谓词完备性：G 对同构失败形态封闭（名称精确匹配 + 文档分页读全标记）
- A4 有界终止：C 单调递增（A1）→ 循环必然终止
- A5 时间有界：T 单调流逝 → 节点必然自愈
- A6 **可观测性（论文 A1 的 observability 谓词）**：每事件判定 v 写入观测链 —— **已实装**：`zthl/acp/amp.py`（规范层，`LogRecord` 对齐 ACPs v2.2.0 §5.1.2）+ `zthl/acp/amp_bridge.py`（采集层），六类日志分文件写 **`<仓>/.zthl/amp/*.log`**（7 天轮转；不跟 `Path.home()`，因 hook 由 `wsl bash` 以 root 启动）；hook 进程出口对**每次调用**写 `access`（`allow` / `block` / `error`，`GK_AMP=0` 或 `GK_ACCESS_LOG=0` 关闭），`_log_hook` 追加 `HOOK_LOG`，block 另落 `gate_data.hook_block_log`（TTL ring）。`message` 类为 seam（ZH3-H14d 前不产出）；**不部署官方 `monitor-server`**（零服务依赖），论文只要求 append-only log、**不要求 AMP**。
- **A6 消费方（2026-10-26 收口）**：此前 AMP **无任何消费方**（叶子遥测，"判定⟺logged" 只有自证）⟹ 现由 `gk_self_check.py::check_amp_observability`（自检 #32）消费：schema 合规 FAIL + 新鲜度 >24h WARN；人工/审计面 = `scripts/gk_amp_query.py`。`access` 由 hook 实时写；`heartbeat`/`metrics`/`system`/`audit` 由 `scripts/gk_amp_collect.py` 采集（`audit` 以 journal 自然键幂等去重）。
- A7 可逆性：节点副作用可回滚（前置补全/状态恢复）
- A8 **残差收敛公理（Residual Convergence Axiom, RCA；论文 A2）**·元循环收敛性：节点**所属序列**的迭代终止**不**由节点内部计数保证（A4 不可上推）——势函数 `Φ_n = μ_n`（缺陷存量）；**判决量 = stock 比 `r̂ = (μ_N/μ_0)^{1/N}`**（相邻轮 `μ_n/μ_{n−1}` 的几何均值；`a_n` 按 `fid` 去重）；`r̂ < 1` ⟹ 几何收敛（`N* = ⌈ln(μ̂₀/μ_tgt)/ln(1/r̂)⌉` 有限；噪声区间 `N*_hi = N*(r̂+δ)`，`δ = GK_CONV_DELTA = 0.1`）；`r̂ ≥ 1` ⟹ `N* = ∞`（自锁）⟹ 须**外部熔断**（冻结扩张 `b→0` + 预算闸门）。**A8 与 A4 对偶**（节点层 ⟷ 序列层）。**判据量唯一 = `r̂`（stock 轴）；`r_n = b_n/a_n`（flow 比）已弃用、禁作判决量**（二者在真实 journal 上可给出相反结论，F-REV-62）——**机制正本 = `references/convergence-evaluator.md` §2/§3**

> **A8 / RCA 性质（2026-09-13 写入，2026-09-14 命名；对齐 H-SLSN §4.3）**：对象层循环有内部上界（`C ≤ MAX`）；**序列层无内部计数器** ⟹ 有界终止只能是**条件性**的（外部势函数单调或熔断介入）。实证 = ember §17/§18 与 crossreview §13.3-§13.6 的 `r≈1` 不动点。俗称"反常积分公理"。属本体层变更，正式批准须走技能自维护序列（见 H-SLSN §4.3 门禁注记）。**2026-10-05 口径订正（flow→stock，人类显式授权）**：判决量由 `r_n = b_n/a_n`（flow 比）订正为 `r̂ = (μ_N/μ_0)^{1/N}`（stock 比）；本次**未**走 batch→质询→seal→adjudicate 序列（先例 = H-SLSN §4.3 的人类显式授权注记）。

> **论证保守化**：SN 是 H-SLSN 的**参数实例化**（G/B/C/T/D 换参数），不是新定理——数学论证复用
> H-SLSN §4.4b 的 DSH Metatheory 映射，不新增不存在参数。

> **A8-RCA 聚合公理扩展（2026-10-06，owner 裁定；机制落点 = `gk_moa_aggregate.py`）**：A8 只管「序列何时该停」，未管「每一轮的聚合产出什么」。补三条**聚合侧**子公理（**RCA 的直接扩展，不另立公理体系**）：
> - **A8-①（去重与一致度）**：一次 MoA 聚合**必须**产出**去重簇**与**加权一致度**（冗余折叠，防「众口一词的错」confabulation consensus）；**一致度不足 ⟹ 弃权（abstain）**，禁以「数量多」充当「证据强」。落点 = `cluster_references`（确定性、零 LLM：归一化→shingle→Jaccard→单链接）。
> - **A8-②（批级单一判定）**：agent 侧评分 = **批级**（禁单臂冒充；`_sealed_agent_score` = 同批 running mean）；人评页同理 **全批一份 F1–F7**（删 per-arm 列）。落点 = `merge_sealed_agent_score` / `render_html`。
> - **A8-③（finding 载体化）**：每轮聚合**须**落 finding 且**载体化**（P 计划文本 / L 机检规则 / M 机制修复，见 §11 三向分流）并**可分类**为 `plan-error` / `infra-defect`。落点 = `assess_findings` / `emit_aggregate_finding`。
> - **A8-④（污染杠杆有界性 + 检出衰减）**：污染注入的累积效应**须按 `φ(κ,n)=(1−κ_cap)·κ_tilt·n^(−p_tilt)` 记账**（κ 样本单源 = `references/moa-kappa-ledger.json`；估计器 = `scripts/gk_moa_kappa.py`）。**幅度先验 = 次线性/线性**：`p_tilt<1` ⟹ `N^(1−p_tilt)`，`p_tilt>1` ⟹ 有界（ζ 收敛）；**默认先验**取此（对齐 arXiv:2602.13320「MCP 鞅：失真线性、非指数」的**定理**），**非绝对排除**指数——**该先验可被后续样本推翻**（RCA 是**可拟合公理**，非绝对律）。**真正风险 = 检出率随阶段衰减**（arXiv:2608.14588：4 态 Markov 逐边界逃逸 24.6%/48.3%/89.3% —— ⚠ **绝对数值限定 gpt-4o 检测器 + FinanceBench 单域 + 单拓扑，禁外推**；同文最强模型 Qwen3.5-397B 亦撞**结构性天花板**（Stage1 实测 87.0%，Stage4 **投影** ~60–65%，投影未实测）⟹ 命题是**管线结构**层，非模型能力层）⟹ 门禁须设**早边界**（呼应 F-REV-47「词汇门≠事实门」）。落点 = `gk_moa_kappa.phi` / `cumulative_leverage`（当前 `[UNFITTED]`：κ_tilt 零膨胀 + 未记 `n_events`）。

## 1b. 与论文 spec 逐条对齐（RCA 正本，2026-10-26）


### 1b-public. 论文 spec 概述对账（公开版）

> 公开版只保留**要求概述**与仓内锚点；稿件文件名与逐字原句只在私仓保留，导出时整块剥离。
> 判定与锚点与私仓版逐行一致，改的只是表述，不是结论。

| # | 论文 spec（要求概述） | 本仓现状（锚） | 判定 |
|:--|:--|:--|:--|
| R1 | **去重签名是外生输入、不可被修订者移动**：停止检验的分母由外生签名去重决定，修订方不得移动它；严重度只作敏感性检查。 | 写面：`gk_finding.register` 仅在**显式** `merge_into` 时并条，缺省只提示 `dup_candidates` + journal `dup_suspect`；读面：`gk_finding.principal` 事后 RC 塌缩（Jaccard `--tau` + LSH） | 一致（缺省不改分母） |
| R2 | **快照未 pin、跨仪器拒比**：解码固定（温度 0、token 上限固定），但模型快照、provider 路由、推理强度不固定 ⟹ 跨仪器数值不得直接比较。 | `scripts/gk_model_shelf.py` 的 `PINNED.repo_commit=1bae0e10…`（1017）、`system_fingerprint=e72d3c7f…`，`stride_S` 取证指纹仍为 `aeb56401…` ⟹ `stride_S_freshness` 判 FAIL、退出码 1 | 一致；**执行含义**：`r̂`/`N*` 序列不得跨指纹拼接 |
| R3 | **相位是准入边界**：只有相位检查不拒绝的批次才准入；批次须在预设 δ 下通过 TOST 式检验才算认证估计，否则只能记准入未知。 | 1017 上 `S` 不可测 ⟹ `S=UNKNOWN`（D 子计划 §14.7.15：logP 全 0、熵与 accuracy 均 `resolved=false`）⟹ 该仪器批次只能标 `admission-unknown`，评估器不从该批出 `N*` | 一致（fail-loud 同向）；论文六格证据属旧快照，禁跨代引用 |
| R4 | **fixture 逐字节**：已准入的判定可从记录的 verdict 与随包复现件重算，重算须端到端闭合；任一摘要被翻转即拒收，且输出须与期望文件逐字节比对。 | 论文读数绑定复现包（期望输出 + 校验和）；本仓 `references/moa-kappa-ledger.json` 是工作台账（13 行），≠ 复现包冻结样本（11 行 / 24 前提） | **须声明边界**：本仓读数不得冒充论文 fixture 复算 |
| R5 | **κ 与 φ 只作界、不作拟合律**：采样侧无非零事件时，杠杆账必须给出明确的未拟合判定，不得给点估计；结构性上界成立时也不把 φ 当拟合律。 | `gk_moa_kappa.estimate_p_tilt` 具名拒估 `MISSING_EVENT_COUNT`（非零点 3、带 `n_events` 者 1）；`phi` / `cumulative_leverage` 在 `p_tilt` 未拟合时返回 `P_TILT_UNFITTED` | 一致 |

**由本表直接推出的三条口径**：

1. **不拼序列**：`r̂` / `N*` 只在同一 `system_fingerprint` 内估计；指纹变 ⟹ 旧 `S`、旧相位格、旧批次一律不续用（R2/R3）。
2. **不借读数**：本仓 ledger 与其 `n_events` 工作样本只服务运行时拒估判断；论文 11 批 / 24 前提、`κ_cap=0.89`、
   `p_tilt=[UNFITTED]` 只能由复现包文件复算（R4/R5）。
3. **不动作**：不改论文仓、不改复现包（含 `CHECKSUMS.sha256`）；本表不新增门禁、不改评估器语义。

---

## 2. 节点前置产物清单（G 的检查项）

节点进入执行体前，G 必须验证以下前置（缺任一 → 阻断 + 引导补全）：

| 前置 | 检查 | 缺失处置 |
|:--|:--|:--|
| **代码库地图** | `context --update` 已刷新 `references/subagent-context.json`（签名+行号最新） | 引导跑 `gatekeeper-cli.sh context --update` |
| **基线** | **`baseline_status` 必填且四态**：`current` / `reusable`（两者均判齐备，内容一致即复用）/ `stale` / `unavailable`（后两者判缺）—— 由 CLI `_gitnexus_baseline_status` **单点**判定并注入。白名单外取值 fail-closed 且回报真实取值（禁报"未注入"）。**⚠ 存在性口径已撤销**（原写"索引存在"）：`{"baseline": true}` 不再参与判据（F-REV-76） | `current`/`reusable` ⟹ 直接复用；`stale`/`unavailable` ⟹ `context --update`（**单一入口**，内含增量 `analyze`；是否加 `--embeddings` 以所属序列站点清单为准，standing 序列 = ECO-DOC 站恒加）；未注入 ⟹ 经 CLI 入口重跑（勿手传 ctx） |
| **源文档** | 计划引用的 source_docs 全部可读（Read 工具可达） | 阻断 + 列缺失清单 |
| **窄任务清单** | 本节点任务可拆分为可下发窄任务（≤1 子任务/agent） | 引导拆分（见 §4） |
| **名称精确** | CLI 命令名/Skill 名与注册表一致（无旧名/歧义名） | 拦截 + 引导全名（H-SLSN `_HSLSN_LEGACY_NAMES`） |
| **输入完整** | subagent read 大文档无 `[chars X-Y of Z]` 未读全标记残留 | 续读至无标记 |
| **收敛预判**（迭代审查循环） | 进入**迭代审查循环**（6 臂质询 / 多轮 plan-refinement / R 复查）前，跑 `pre-check convergence --loop` 判 `r̂ ≥ r_min 连续 K 轮`（**A8/RCA**；判据单源 = `references/convergence-evaluator.md §5`） | `NO_CONVERGENCE` ⟹ **fail-loud 早停 + 转 M**（见 §2.3） |

---

## 2.1 入站 / 出站纪律 = 本安全网的**引导词**（B 分量，2026-09-14 增补）

> **用户定案（2026-09-14）**：「**入站出站门，MoA 聚合需要接入序列节点安全网。入站出站纪律就是对应安全网的引导词。**」
> ⟹ **门（gate）= G/D 的实例化；纪律（discipline）= B 的 `fix_hint` 文本**。二者同源，不分家：G 判定 + B 引导 + D 降级，纪律文本即 B 的输出。

**命名空间消歧（2026-09-14，用户"会不会重叠？改名字吧"）** —— 三套东西历史上都用了 `G<n>`，必须拆开：

| 命名空间 | 前缀 | 语义 | 实例 |
|:--|:--|:--|:--|
| **bridge MCP 传输层门** | **`BR-`** | 守护 MCP stdio 服务本体（信封/认证/限速/熔断/审计） | `BR-G0` schema / `BR-G1` API Key / `BR-G2` 限速 / **`BR-G3` 熔断** / `BR-G4` 审计（`bridge/mcp/server.py`） |
| **技能侧内容/命令门** | **`G-`** + 方向 | 守护 agent 的入站内容与出站命令 | **`G-IN`**（入站）/ **`G-OUT`**（出站）/ **`G-READ`**（回读点） |
| **R8 实验分组** | **`R8-`** | 实验自变量标签（**非门**） | `R8-相同` / `R8-互补` / `R8-污染`（原 G1/G2/G3） |

> **重叠结论（不重叠，仅同层同形）**：`BR-*` 与 `G-*` **对象不同** —— `BR-*` 拦的是 **MCP 传输信封**（JSON-RPC/API key/速率/熔断/审计），`G-*` 拦的是 **内容与命令**（--task 文本 / shell 命令 / 回读归属）。**唯一真重叠面 = 审计与认证**（`BR-G4` ↔ hook 审计、`BR-G1` ↔ `.keys` HMAC），属基础设施重复而非门禁重复 ⟹ **不合并**，仅登记。

| 门 | SN 分量 | 现状实现 | 纪律（引导词 = B 输出） |
|:--|:--|:--|:--|
| **`G-IN`（入站门）** | G（入站内容合法性） | `scripts/gk_task_gate.py check`（provenance / leading / poison / bounded） | 维度名**复用目标文档既有词汇**；避免 `①②③` 枚举与括号清单；禁写方案内容/预期结论 |
| **`G-OUT`（出站门）** | G（出站命令合法性） | `R0.1/R0.2/R0.3` pre-tool hook | 写操作先 `guard-edit`；命令名须 ∈ `_CMD_REG`（旧名/歧义名 = 天然投毒点） |
| **`G-READ`（回读点）** | G（归属/权威校验） | **段1 已落地**（`gk_moa_aggregate`：`task_fingerprint` 归属绑定 + `collect_entries` 缺省拒跨任务，F-REV-8 2026-09-11）；**段2 = 降级链处置**（技能侧先实装；**2026-09-14 裁定：降为登记、不排期**，四要素见 convergence 子计划 §2.1/§8.4） | 回读消费前校验**通道 × 归属**（完整性 ≠ 权威性） |
| （参照）**`BR-G0…G4`** | G/D（传输层） | `bridge/mcp/server.py` | 与本安全网**不同层**；技能侧仅引用，不改 bridge |

**已知限制（2026-10-26 复核；仅保留可复现项）**：

| # | 门 | 限制 | 证据（符号） |
|:--|:--|:--|:--|
| **GB-1** | 入站 | **无归一化**：`mat = material.lower()` + 裸子串匹配 ⟹ 目标文档的 `**粗体**`/反引号**切断短语** ⟹ 自家文档不可逐字引用 ⟹ `novel_phrase_ungrounded` **误报** | `gk_task_gate.py` 的 `check`（`mat = (material or "").lower()`） |
| **GB-2** | 入站 | **ACK 可脚本化**：`acknowledge_hint` 原样可粘贴 ⟹ 自动转录 ⟹ 豁免门形同无 | `gk_task_gate.py` 的 `check`（`acknowledge_hint`） |

> 2026-09-14 登记的其余项（GB-3..GB-8，含 bridge 熔断编号/半开语义）属跨仓历史登记，已从本模板移除；需要时以 bridge 仓自身台账为准，不再作为本安全网的现状清单。

---

## 2.2 落笔前**三**步骤（**强制**；2026-09-14 增补，同日 REV-2 扩为三步）

> **背景**：本安全网的**判据**与**开关**连续两轮出现**同族缺陷** —— crossreview 子计划判据 #9「**假绿**」与 `GK_MOA_ATTR_GATE`「**幻影开关**」被抓出后，**同一模式在"降级链处置"草案上再次复发**（J1「**假红**」+ `GK_DEGRADE_TRACE`「**幻影开关 + 默认值自相矛盾**」）。更进一步：12 臂实测表明 **`b̄`（每轮新增缺陷）不衰减**，其中 **28% 是"修复动作本身引入的"**（**F-REV-50**）⟹ 故把三步**必须在落笔/修复时执行**的机械动作上升为强制纪律，列入 §6 验收清单。

| 步骤 | 动作（机械可执行） | 反例（本仓真实复发） |
|:--|:--|:--|
| **① 判据先跑现状** | 每条**可机检判据**落笔时必须给出「**现状运行结果**」，并满足 **red-first**：修前**必失败**（`FAIL`）且失败原因 = 该判据要修的对象；修后转 `PASS`。**现状即 `PASS` ⟹ 假绿**（零判别力）；**前提不可达**而失败/无法构造 ⟹ **假红**（在测一条不存在的路径） | **假绿**：判据 #9 用 `**拆的是权限粒度**`，星号在 CJK 段**之外** ⟹ CJK 段本身即 material 裸子串 ⟹ 现状就通过。**假红**：J1「mock 主 provider 空返回 ⟹ 切 mimo」—— `_is_retryable("")` 恒 `return 1` ⟹ `:3359` 早退 ⟹ 前提**不可达** |
| **② 开关先 grep 全仓** | 任何新增 env 变量 / kill switch 落笔时**必须先** `rg '<NAME>'` 全仓：① 命名唯一；② 命中数 = 0 ⟹ 本轮**新引入**（**不得**写作"既有开关/复用既有"）。并**必须**显式给出「**省略时行为**」，且默认值须 = **原行为**（fail-soft / **opt-in**） | **幻影开关**：`GK_MOA_ATTR_GATE` 全仓 0 匹配却写作既有开关。**同形复发**：`GK_DEGRADE_TRACE` 0 匹配 + §6「省略时=1」与 §2.1「省略即原行为」**自相矛盾** |

| **③ 修复后立刻复扫**（**REV-2 新增**，消 **F-REV-50**） | 任何**修复动作**（改判据 / 改落刀点 / 改开关 / 改假设编号）落笔后，**立刻**跑复扫：`rg` 核 ① env 存在性 ② 开关命名唯一性 ③ **假设编号唯一性**（`ASSUMPTION-` 计数无重复号）④ 消费者 import ⑤ 行锚。**修复须跑双向 red-first**：**新判据 × 旧文档 = 必失败** **且** **旧判据 × 新文档 = 仍通过**。**禁**在修复时顺带改写已定案段落。 | **修复自伤**：本轮 18 条命中中 **5 条（28%）**由前两轮修复引入（**F-REV-50**）—— 例：D4 修复 → 落刀点漏语料侧（S1）；T8 重写 → 新样例假红（S2）；D3 修复 → 自称"4 消费者"实为 0（S3）；D22 修复 → 假设**撞号**（R2）+ 判据**假绿**（R3）。**同族三联** = D1 假绿 → J1 假红 → 判据 #10 假红（**分层复制**） |

**执行时点**：①② 必须在**设计质询（plan-refinement）前**完成 —— 否则质询必然以「假绿 / 假红 / 幻影」命中，白烧一轮（本轮两臂各 ~0.65M tokens）；③ 必须在**每次修复提交前**完成（F-REV-50：28% 的命中来自修复本身）。

---

## 2.3 收敛预判节点（**A8/RCA 元循环**；2026-10-05 增补，Infra-4）

> **动机**：四轮 6 臂质询实测 —— **分数不增长 / `μ_n` 不衰减** = **基础设施缺陷**，此时继续改计划
> 文本 = **空转烧钱**（≈14M+ tok；R3/R4 本可省）。**A8（RCA）**要求节点在**进入迭代审查循环之前**
> 先做**收敛预判**，不收敛即 **fail-loud 早停**（本模板 = 节点安全网，不是事后记账）。

**触发点**：任何**迭代审查循环**（6 臂质询 / 多轮 plan-refinement / R-sequence 复查）**进入前**。

**G 谓词（前置检查）**：取该循环历史 `μ_n`（每轮新开 finding 数，**排除测量 finding**），跑
`bash gatekeeper-cli.sh pre-check convergence --loop --mu "<μ_1,μ_2,…>"`
（或直调 `scripts/gk_convergence_evaluator.py loop`）。

**判据（单源 = `references/convergence-evaluator.md §5`）**：`r̂ ≥ r_min 连续 K 轮`
（`GK_CONV_R_MIN` 默认 **0.9** / `GK_CONV_K_ROUNDS` 默认 **2**）⟹ `verdict = NO_CONVERGENCE`。

**D 降级（fail-loud）**：`NO_CONVERGENCE` ⟹ **早停**：落 `noconv:` finding（`gate_data.ecc_findings`）
+ `switch_to = "M"` = **强制转机制修复**（三向分流），**禁**再以「改计划文本」结案。
`INSUFFICIENT_ROUNDS` ⟹ 继续（轮数不足，不可判）；`UNDEFINED`（μ 负值）⟹ 报账/journal 不同源。

**SN 五元组映射**：

| 分量 | 实例 |
|:--|:--|
| **G** | `pre-check convergence --loop` 出 `verdict`（`μ_n` 序列可取） |
| **B** | 落 `noconv:` finding + 引导「转 M」 |
| **C** | 循环轮数（迭代审查有界） |
| **T** | —（不引入时间轴；早停由判据触发） |
| **D** | `NO_CONVERGENCE` ⟹ **fail-loud 早停**（禁静默继续） |

**kill switch**：`GK_CONV_EARLY_STOP=0` ⟹ 只出 verdict、不落 finding（**已实装**：`scripts/gk_convergence_evaluator.py`；`scripts/test_gk_convergence_evaluator.py` 有对应用例）。

---

## 3. 模板（节点安全网实现骨架）

```python
# 节点安全网骨架 — 复制此结构到每个序列节点守卫
# 对齐 _hslsn_*（pre_tool_hook.py）与 _hslsn_transact（原子事务）

_NODE_TTL = 1800.0          # A5 时间自愈
_NODE_MAX_ATTEMPTS = 3      # A4 有界终止

def _node_load() -> dict:
    """读节点状态 + checksum 校验（A2 完整性）。"""
    # 同 _hslsn_load：_checksum 失配 → 视为 inactive（fail-safe）

def _node_transact(mutator) -> dict:
    """flock 临界区 + SHA256 嵌入 + os.replace 原子替换（A1 原子性）。"""
    # 同 _hslsn_transact

def _node_guard(event) -> str | None:
    """G 谓词：前置产物齐备性 + 名称精确性 + 输入完整性。合法 None，缺失返回引导消息。"""
    # 1. 名称精确：命令名/Skill 名 ∈ 注册表（旧名 → _LEGACY_NAMES 映射引导）
    # 2. 前置齐备：代码库地图/基线/源文档/窄任务清单（见 §2 表）
    # 3. 输入完整：read 无 [chars X-Y of Z] 残留标记
    return None

def _node_verdict(bypass: str) -> tuple[str, str] | None:
    """记录拦截模式 + 回环裁决（A6 可观测性）。超阈降级冷却降频 + 留痕。"""
    # 同 _hslsn_record_and_verdict：attempts ≤ MAX → (bypass, fix_hint)；> MAX → log-only

# 节点执行入口（每节点事件触发）
def node_execute(event):
    if _node_guard(event) is None:
        run_node_body(event)                    # 前置齐备 → 执行体
    else:
        bypass = _node_guard(event)
        verdict = _node_verdict(bypass)
        if verdict:
            block(verdict[0], verdict[1])       # 拦截 + 引导补全前置
```

---

## 4. 窄任务清单机制（G 的"窄任务"检查项）

> 2026-08-27 用户质询：standing 流程需"可下发的多组窄任务清单"。机制如下。

**定义**：窄任务 = 单个 subagent 可在 `item_budget` 内独立完成的原子任务
（读 1-2 个文档 / 跑 1 个确定性命令 / 1 个窄范围代码搜索）。

**拆分规则**（节点 → 窄任务清单）：
1. **单一职责**：每窄任务 ≤ 1 个目标（如"读取并总结 batch8 R-T8 段" ≠ "读取 batch8 全文"）
2. **输入有界**：每窄任务输入 ≤ 2 个 source_docs（大文档 180KB 拆 2-3 个窄任务各读一段）
3. **可验证**：每窄任务有确定性验收（`read` 无截断标记 / `audit` 指定项通过）
4. **可并行**：独立窄任务可并行下发（`dispatching-parallel-agents`）

**清单产出**：节点执行前生成 `窄任务清单`（JSON），登记到 `gate_data.narrow_tasks[]`。

> **登记落点（2026-09-01 修正）**：窄任务清单写入**执行节点所属 plan/worktree 的隔离 state**（`.gatekeeper.state.<plan>`），**不写入技能默认 `.gatekeeper.state`**——默认 state 是技能级独立 state，承载全局调度；窄任务是节点执行级产物，随 plan/worktree 隔离（含 worktree 归属路由场景：隔离 state 的 `worktree` 字段指向执行 worktree）。迁移：`.gatekeeper.state` → `.gatekeeper.state.r7`（R7 隔离 state，2026-09-01 实装）。

```json
{"node": "ECO-RESEARCH", "tasks": [
  {"id": "T1", "goal": "读 batch8 R-T8 段(L1046-1057)", "input": ["docs/plan-backup/...", "offset:1046"], "verify": "read 无未读全标记", "tier": 2},
  {"id": "T2", "goal": "核对 zthl-adapter ZH3 依赖", "input": ["~/docs/plans/...", "offset:0"], "verify": "read_bridge 分页读全"}
]}
```

**4.1 档位路由规范（2026-08-28 实装，`gatekeeper-cli.sh cmd_monitor --subagent`）**

- 清单条目可带 **`tier` 字段（1-4）** → CLI 下发 subagent 时命中任务即覆盖 `SUBAGENT_TIER` 透传 runner；未声明 → 落节点默认档位（standard 序列 = tier 3 中间档）。
- **档位梯度**（单一事实源 = `scripts/gk_suba_tiers.py`，`subagent_runner.py` 从此 import；2026-10-03 起 tier3/4 全维 ×2）：`token_budget`（**输入+输出累计成本当量** 100K/200K/1M/3M）、`item_budget`（375/750/4000/8000）、`max_turns`（100/200/800/1600）、`max_output_tokens`（**单次响应输出上限** 10000/20000/80000/160000，且经 `clamp_max_output_tokens` 钳到 provider 硬上限：MiMo 131072 / DeepSeek 393216）、`timeout`（**单次 API 调用** 375/450/1200/1800s）、`max_file_bytes`（10/20/30/30MB）。
- **输出契约**：subagent 提示词硬性要求纯 JSON（禁止 markdown 包裹/前后文字）；runner 后处理 fail-closed——输出非合法 JSON → error 退出 → CLI 触发重试链（DS 重试 1 次 → MiMo 降级）。
- **ECO 聚合**：ECC 字段上限由 runner 侧档位界限（`_ECC_BOUNDS`：conclusion 800-16000 / evidence 5-30，随 tier 缩放）权威裁切，聚合端保留有界全文不二次截断；全量输出另落 `docs/analysis/subagent/{id}.json`——超大 tier 4 输出不撑爆 state。
- **治理链条**：模板（本节）→ `gk_node_guard.py`（node_guard 前置 G 谓词检查 narrow_tasks 非空）→ CLI（路由）→ `subagent_runner.py`（档位执行）——四层同源。

**4.2 清单格式规范与校验规则（2026-08-28，`gk_narrow_route.validate_narrow_tasks`）**

```json
{"gate_data": {"narrow_tasks": [
  {"id": "T1",                     // 必填，≤64 字符
   "task": "读 batch8 R-T8 段",    // task/name 至少其一；task ≤500 字符
   "name": "read-rt8",             // 可选，≤100 字符
   "tier": 2,                      // 可选，∈{1,2,3,4}；越界不参与路由（防档位操纵）
   "input": ["...", "offset:1046"],// 可选，≤2 个 source_docs
   "verify": "read 无未读全标记"}]}} // 可选，确定性验收
```

- **校验规则**：条目必为 dict；id 必填；task/name 至少其一；tier∈1-4（`_VALID_TIERS`）；单清单 ≤20 条目；单条目 ≤8KB；全清单 ≤64KB。
- **下发三连闸**（cmd_monitor --subagent 前置）：`--check-poison`（强注入 exit 3）→ `--check-schema`（格式/复杂度 exit 4）→ 档位路由——任一 FAIL fail-closed 阻断。
- **边界原则**：单窄任务 ≤1 目标、输入 ≤2 source_docs（§4 拆分规则）；超界 → schema 拒绝。

---

## 5. 六类安全网 × 序列节点映射（模板适用性；**节点名权威清单 = `gk_advance._registered_node` 的 NODE_REGISTRY** —— 下表"节点实例"仅为举例，非全集）

| 安全网类 | 节点实例 | 模板应用 |
|:--|:--|:--|
| ① 加载类 | H-SLSN / 插件加载 | G=双条件（hook ∧ Skill），C=3，T=1800s，D=fail-open→WARN |
| ② 文档审查引擎 | audit --docs / doc-align | G=C1-C5 漂移，B=docgen 再生→re-audit，D=fail-closed（ECC 循环） |
| ③ 运行时 | state 篡改/flock | G=checksum 失配，B=阻断+修复，D=fail-closed exit 2 |
| ④ 序列节点引导 | ECO-RESEARCH/ECO-EDIT/ECO-VERIFY/ECO-DOC/STAGE_1 | **本模板**：G=前置齐备+名称精确+输入完整 |
| ⑤ 门禁 | guard-edit/advance | G=stage/worktree/保护区，B=BLOCK+修复，D=fail-closed+escalate |
| ⑥ wasm+ci | CI 红/wasm 构建 | G=CI 红，B=ci-diagnose→auto-fix，C=3（W9），D=升级人工 |

---

## 6. 验收要求（新增节点安全网时逐条核对）

```
□ 前置清单：代码库地图/基线/源文档/窄任务清单 四件套是否纳入 G？
□ 名称精确：命令名/Skill 名与注册表精确一致？旧名/歧义名是否拦截？（投毒点关闭）
□ 输入完整：subagent read 大文档分页续读标记是否处理？
□ 数学公理：A1-A8 按节点裁剪后是否满足？（原子性/完整性/有界终止/时间自愈/可观测/可逆/**元循环收敛**）
□ **收敛预判**（§2.3）：迭代审查循环进入前已跑 `pre-check convergence --loop`？`NO_CONVERGENCE` ⟹ 已 fail-loud 早停 + 转 M（禁再以改计划文本结案）？
□ 观测链：判定 v 写入 HOOK_LOG → block_log → AMP access？（判定⟺logged）
□ **落笔前**三**步骤（§2.2）**：① 每条判据已给「现状运行结果」（**red-first**，无**假绿/假红**）？② 每个新开关已 `rg` 全仓 + 已给「省略时行为 = **原行为**」（无**幻影开关**）？③ **每次修复后**已复扫（env / 开关 / **假设编号** / 消费者 / 行锚）+ 已跑**双向 red-first**（新判据×旧文档必失败 ∧ 旧判据×新文档仍通过）？（无**修复自伤**，**F-REV-50**）
□ 测试：漏加载/误加载/错误加载三态 + 前置缺失/名称歧义/输入不全 用例
```

---

## 参考来源

- H-SLSN 实现：`scripts/pre_tool_hook.py` 的 `_hslsn_*`（符号引用）
- 加载安全网框架：`references/plugin-loading-test-framework.md`
- 元循环定义：`references/meta-routing-protocol.md` 的「双循环 + 标准执行」
- 内部计划（`docs/`，不随开源发布）：安全加固评估（2026-08-28）、H-SLSN 数学形式化（2026-08-27）——仅作历史溯源，不作为现行口径

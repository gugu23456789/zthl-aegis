# ZTHL Aegis（SPZ Gatekeeper）— 架构自述

<!-- DOC-META
title: ZTHL Aegis（SPZ Gatekeeper）— 架构自述
type: reference
owner: spz-gatekeeper-r-sequence
status: public
updated: 2026-11-02
-->

> **这是什么**：AI Agent 的确定性治理层 = 门禁（hook + CLI）+ 阶段推进 + 审计/红队 + 证据留痕。
> **架构原则**：文档是 CLI 的输出，不是输入。数据流 = CLI → state/gate_data → 回写 → 规则文档。
> **面向谁**：人类开发者；Agent 入口是 `SKILL.md`（路由层）。

### 事实基线（自动生成，勿手改）

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
> `references/` 文件地图在 §1（`git ls-files` 机检，C3）；本机另有 gitignore 的 `ecc-audit-*.md` 运行档案，不计入。

---

## 1. 文件地图

```
spz-gatekeeper-r-sequence/
├── SKILL.md                          # Agent 入口：路由 / 契约 / 强制 invoke 表
├── gatekeeper-cli.sh                 # 确定性执行层（12,083 行；命令注册表单源 = _CMD_REG）
├── install.sh / uninstall.sh         # .trae 安装 / manifest 精确卸载
│
├── scripts/                          # Python 执行层（按职责分组，完整清单以目录为准）
│   ├── 门禁与状态   pre_tool_hook.py / gk_state*.py / gk_state_route.py / gk_gate_*.py / gk_json_utils.py
│   ├── 审计与红队   gk_audit_*.py / _red_attacks.py / gk_red_vectors.py / gk_red_intel.py / gk_ecc_sink.py
│   ├── 自检与文档   gk_self_check.py / gk_doc_align.py / gk_plan_lint.py
│   ├── 子代理       subagent_runner.py / gk_agent_edit.py / gk_agent_family.py / gk_satellite.py
│   ├── 联网         gk_web_tools.py / gk_evidence.py（受治车道 + egress 链式台账）
│   ├── 沙箱与执行   gk_kvm_launcher.py / gk_worker.py / gk_worker_client.py
│   └── 调度与工具   cron_*.py / gk_io.py / gk_path.py / gk_views.py / gk_finding.py
│
├── references/
│   ├── architecture-overview.md
│   ├── README.md
│   ├── cli-protocol.md
│   ├── stages.md
│   ├── state-storage.md
│   ├── meta-routing-protocol.md
│   ├── plan-writing-safety-net.md
│   ├── extension-registry.md
│   ├── security-measures.md
│   ├── security-incident-response.md
│   ├── prm-monitor-methodology.md
│   ├── plugin-loading-test-framework.md
│   ├── sequence-node-safety-net-template.md
│   ├── stage-0-start.md
│   ├── stage-1-code.md
│   ├── stage-2-ci.md
│   ├── stage-3-review.md
│   ├── stage-4-merge.md
│   ├── stage-5-retire.md
│   ├── stage-5b-retrospective.md
│   ├── stage-6-r6-flow.md
│   ├── red-arm-templates.json
│   ├── red-vectors.json
│   ├── red-intel-sources.json
│   ├── oss-export-whitelist.json
│   ├── doc-align-contracts.json
│   ├── predicates.json
│   ├── agent-families/
│   ├── xspi-defense.md
│   ├── bashpy-problem-taxonomy.md
│   ├── bashpy-ab-loop-safety-net.md
│   ├── standard-maintenance-module.md
│   ├── wasm-engineering-template.md
│   ├── ci-pipeline-template.md
│   ├── game-path-audit.md
│   ├── trae-cross-user-leakage-report.md
│   ├── convergence-evaluator.md
│   ├── predicate-applicability.md
│   ├── e1e4-evaluator-matrix.md
│   ├── flywheel-implementation-plan.md
│   ├── superagent-comparison.md
│   ├── research-408.md
│   ├── ecc-write-spec.md
│   ├── ecc-analysis-findings.md
│   ├── ecc-finding-20260612-flywheel.md
│   ├── ecc-finding-20260802-feature-prefix-wsl-hardcode.md
│   ├── ecc-finding-20260917-toolface-consolidation-and-pr-mechanism.md
│   ├── ecc-finding-20261003-moa-face-consolidation.md
│   ├── ecc-impact-20260609-gitnexus.md
│   ├── ecc-impact-2026-08-13-key-question.md
│   ├── ecc-impact-20260826-plugin-dual-loop.md
│   ├── ecc-impact-flywheel.md
│   ├── ecc-impact-v7.md
│   ├── oss-hooks.md
│   ├── oss-moa-phase-provenance.md
│   └── flows-a-b-c.md
│
├── monitor-schemas/                  # STAGE_0..5 门禁 schema（JSON）
└── docs/                             # 内部计划/分析/备份（不随公开包导出）
```

> 文件地图由 `gk_audit_docs.py` C3 机检（`references/` 下 md 集合须与本段**完全相等**）；
> 导出面（哪些不进公开包）以 `oss-export-whitelist.json` 为唯一事实源。

---

## 2. 数据流（三条主线）

```
Agent 工具调用 ──► pre_tool_hook.py ──► 门禁链（Gate 0-9 + R0.x 家族）
                                         ├─ 允许 → 工具执行
                                         └─ 拒绝 → exit 2 + 可读理由（fail-closed）

Agent 阶段推进 ──► gatekeeper-cli.sh advance ──► 硬证据（CLI 采集，Agent 不可见）
                                              + monitor（local 零成本 / api 语义）
                                              + 结构门禁 → 双通过才落 state

红队/审计     ──► _red_attacks.py（16 站）──► ECC finding 台账
                 └─ 向量登记 = references/red-vectors.json（代码只做执行器）
```

**状态单源**：`.gatekeeper.state`（2.6 MB 墙 + 50/80/90/95% 水位，95% 拒写）。
形态与分工（base / domain / legacy_plan / worktree_local / artifact）、卫星片容量（10 轮 × 6 臂）、
TTL/GC、回收判据全在 `references/state-storage.md`，本文不复制。

**写入语义边界**：`_checksum` 与 `state_lock` 只覆盖**主 state 写路径**；派生/归档写面
（`gk_state_ops.py` / `gk_views.py` / `gk_discover_archive.py`）是裸 `json.dump` ⟹ 对外安全声明
**不得**概括为「所有 state 写入都原子/带校验」。

**WAL 写路径（M1–M4）**：`gk_state_wal.py` 逐条 WAL（`{seq,pid,ts,ops,crc}`）→ 每 200 条 / 1 MB
checkpoint；读序 **WAL → state**，进程退出 flush、尾部坏行修复。写放大 128–512x → < 1.3。
基准套件 `gk_bench_*.py` 与 `references/bench-baseline.json` 由 `bench-quick`（CI）与
`bench-nightly`（每日 full）守护；跨 OS 只守硬失败（失败写 / 崩溃校验 / 场景 ok），
写放大与 p99 只作 WARN。

**MCP 工具面**：`gk_mcp_loader.py` 按 `sealed / egress / gated / ui / read / write / command`
分类校验；hook R0.18 对 `install_browser`、`browser_record_*` 默认 BLOCK（显式 env 才放行）；
出网仍单口（R0.14）。

---

## 3. 门禁分层（hook 侧）

| 层 | 作用 | 失败语义 |
|:--|:--|:--|
| Gate 0 | 禁止裸 `Task` 派发（治理域必须走 CLI 受约束通道） | BLOCK |
| Gate 1-3 | 阶段/工作树/写入路径（改文件必须在活动 worktree 内） | BLOCK |
| Gate 4-7 | CLI 预检 + 读/检索/LS 范围（防越界读） | BLOCK |
| Gate 8-9 | 归属与交互闸（无人时段/纯确认型提问） | BLOCK |
| Gate R0.x | 危险命令、跨 OS 写、MCP 出网（R0.14）、观测准入（R0.15）、解释器（R0.16） | BLOCK |

治理范围 = 技能目录 + `.gatekeeper.scopes.json` 登记项目；范围外放行（不误伤无关仓库）。

---

## 4. 红队与审计

- **序列**：16 站（`scripts/gk_chain.py`）＝ SCOPE / SURFACE / CONSTRAINTS / EXPLOIT / POSTEX / REPORT /
  HINT / HOOK / PY / POISON / REGISTRY / GHOST / COVERAGE / DIFF / INTEGRITY / AIG。
- **schema 覆盖（2026-11-02 硬门）**：每个核心序列站（standing/standard/audit/red）必须有
  `monitor-schemas/<NODE>.json`；`scripts/gk_package_integrity.py` 把缺件判 **error**（CI 的
  `package-integrity` job 与 release 预检自动跑）⟹ 防 `advance` 时 `no schema` 被银行 monitor
  判 0.5 静默拦停。新增站点必须同批补 schema。
- **向量登记（2026-11-01 数据化）**：`references/red-vectors.json`（156 条静态向量 + 3 个动态模板 +
  22 组），锚点 = `<文件>::<符号>`，复核 TTL 180 天。机检：`scripts/gk_red_vectors.py check`
  （代码 ↔ 登记表**双向集合等价**）、`stale`、`reopen`（锚点文件在复核后被改动 ⟹ 待复核）。
- **情报准入（2026-11-01 第二期）**：`references/red-intel-sources.json` + `scripts/gk_red_intel.py`。
  红队 subagent 用 `red_search` / `red_fetch`：**只读文本、禁下载**（二进制/压缩/可执行/PDF/Office/脚本后缀）、
  宿主白名单单源；`risk_tier=high`（漏洞库）⟹ 必须 `GK_RED_INTEL_SANDBOX=1` + KVM probe 通过，
  否则 fail-closed。出网仍走受治车道（`gk_web_tools` → `gk_evidence.record_egress`），**不新建出网口**。
- **finding → 向量晋升**：`gk_red_vectors.py promote` 只出提案，要求 `confirmed` + `repro_cmd` +
  `pre_fix_commit`；红队自产 finding 还须 `independent_verification`（**防飞轮自证**）。

---

## 5. “记忆”的真实形态：FIFO 窗口 + 溢出归档（**不是分层记忆**）

本技能**没有**分层记忆系统：没有独立记忆库、没有层级迁移、没有分层淘汰策略。实际只有**同一个
`.gatekeeper.state` 里的两个 FIFO 窗口 + 全量文件**：

| 结构 | 窗口 | 溢出行为 |
|:--|:--|:--|
| `gate_data.subagent_history` | **20 条** 且 ≤ 800 KB | 出窗条目 → `<state>.history-archive.jsonl`（append-only）+ `history` 卫星片；读侧经 `gk_moa_aggregate.history_union` 合并 live 与片 |
| `gate_data.rejected_edits` | **20 条** | 出窗条目 → `<state>.rejected-edits-journal.jsonl`（append-only、永不回收，硬顶 8MB 轮转 `-1`）；live 只留窗口内条目，审计读 journal |
| `.gatekeeper.state` | 墙 2.6 MB | 95% 拒写；经 `state --map` 归档 |

对外只能说**功能近似**（保留近期审计证据）；旧文档的「L1/L2/L3 记忆分层」与「5 条」窗口均为过时说法，**已删除**。

---

## 6. 已删除 / 纠正的过时说法（2026-11-01 重写）

| 旧说法 | 实际（以顶部 GK-FACTS 为准，不在此重复数字） |
|:--|:--|
| CLI「~11578 行」 | 事实块「CLI 行数」（`wc -l` 可复算） |
| 「31 条 / 35 条命令」 | 事实块「CLI 命令数」（`_CMD_REG` 计数） |
| 红队「8 阶段」 | 事实块「红队站点」（`gk_chain.py`） |
| `gk_self_check.py`「11 项」 | 事实块「自检检查函数」（quick/full 两档选取不同子集） |
| 「references 公开文档 10 份」 | 事实块「references 入库 md」（gitignore 的 `ecc-audit-*.md` 是运行档案，不是仓库内容） |
| Bridge 对比表（12 项数字对照） | **整段删除**：对照对象已不维护，数字全部过期，留之只会误导 |
| 「外部依赖 202 份 plan 文档」 | 删除：不可核且与架构无关（计划在 `docs/plans/`，不入库） |
| `scripts/` 逐文件长注释 | 改为职责分组；逐文件细节以目录与 `cli-protocol.md` 为准 |

> 维护纪律：本文件任何数字都必须可机检复算；改代码导致数字变化时**同批**更新，否则按过时文档处理。

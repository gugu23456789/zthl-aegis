# ZTHL Aegis (智御)

[English](#english) · [中文](#中文)

> Project name: **ZTHL Aegis**; the installable skill/package directory keeps its historical name
> `spz-gatekeeper-r-sequence`.

---

## English

A deterministic governance layer for AI-assisted software work. It turns "the agent says it is
done" into a set of checks a third party can rerun: every stage transition, edit, dispatch and
verdict is gated by a command-line tool that writes a signed, replayable record.

This repository is the public release channel. The documentation index is
[`references/README.md`](references/README.md); every exported document is linked from it.

### License

Mulan Permissive Software License, Version 2 (Mulan PSL v2). The full bilingual text is in
[`LICENSE`](LICENSE); the canonical Chinese text is published at
<http://license.coscl.org.cn/MulanPSL2>.

- Copyright owner: **Pu Junhan** (2026). The full notice block is at the end of [`LICENSE`](LICENSE).
- Third-party components shipped in this repository (currently Apache ECharts 5.6.0) are listed,
  with their upstream notices and license copies, in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)
  and [`THIRD_PARTY_LICENSES/`](THIRD_PARTY_LICENSES/).

### What it does

- **Stage gates** — work moves through explicit stages (`discover` → `guard-edit` → `advance`),
  and out-of-stage edits are refused rather than merely warned about.
- **Edit budget** — per-session, per-phase edit quotas (cosine schedule) plus a per-file cap;
  both are enforced before a write lands.
- **Audit and findings** — defects are registered with an id, a closure oracle and an evidence
  chain; closure must cite a source that the tool can verify.
- **State compaction** — long-lived state is split into a small metadata head plus append-only
  satellite shards, with a single writer for each shard and a read-side union.
- **Cross-review** — review and plan-refinement run through a constrained sub-agent channel with
  token/item budgets, rather than an unconstrained chat call.

### Repository layout

| Path | Purpose |
|---|---|
| `gatekeeper-cli.sh` | Deterministic CLI: state, gates, audit, review, findings, cron |
| `scripts/` | Python modules behind the CLI (each with `test_*.py` siblings) |
| `references/` | Protocols and stage references loaded on demand; index at [`references/README.md`](references/README.md) |
| `monitor-schemas/` | Schemas for monitor output |
| `assets/`, `zthl/` | Runtime assets and optional harness integration |
| `install.sh`, `uninstall.sh` | Non-destructive install of the skill directory into `.trae/skills/` |

### Requirements

`bash gatekeeper-cli.sh self-check` includes a `dependencies` check that reports the live status of
every item below (with the exact install / substitute command), so you can copy it from the output.

| Tool | Needed for | If missing | Install | In-repo substitute (env) |
|---|---|---|---|---|
| `bash` | every entry point (`gatekeeper-cli.sh`, `scripts/*.sh`) | nothing runs | Linux/macOS built-in; on Windows use **WSL** or Git Bash | — |
| `python3` (3.10+) | all CLI internals | nothing runs | `apt install python3` / `winget install Python.Python.3.12` | `GK_PYTHON=/path/to/python` (consumed by `scripts/py_resolve.sh`) |
| `git` | state, discover, worktrees, review evidence | state/route features fail | <https://git-scm.com/downloads> | — |
| `rg` (ripgrep) | text search and several guard predicates | those predicates cannot fire (degrade, never silently "pass") | `apt install ripgrep` / `brew install ripgrep` / `winget install BurntSushi.ripgrep.MSVC` | `GK_RG=/path/to/rg` |
| `node` (20+) | **optional** GitNexus graph index | graph checks degrade to a named `WARN`/`SKIP` | <https://nodejs.org/> | — |
| `gitnexus` | **optional** graph index / call chains / change impact (needs `node`) | same as above; use `search` / `code_search` instead | `npm i -g gitnexus` | — |
| `markitdown` | **optional** `read_doc` (document → text) | only `read_doc` is unavailable | `pipx install markitdown` | — |
| Python packages `openai`, `openai-agents`, `pydantic`, `pytest` | subagent runtime / acceptance suite | subagent dispatch and `_accept_cli.sh` are unavailable | `pip install openai openai-agents pydantic pytest` | `SUAGENT_PYTHON` / `ACCEPT_PY` |

- Python **>= 3.11** is required by the test/acceptance suite (`scripts/_accept_cli.sh`); the CLI
  itself runs on 3.10+. Verified: 3.11.5 (Windows venv) and 3.12 (WSL reference).
- Graph checks wait up to the per-command timeout (default 300 s) before degrading when the GitNexus
  index is absent — that is expected, not a hang.
- Interpreter discovery order (no absolute path is baked in): `GK_PYTHON` → `SUAGENT_PYTHON` →
  `ACCEPT_PY` → `scripts/_accept_py.local` (private pin) → in-repo `.venv` / `.venv-*` →
  `GK_PY_GLOBS` → `PATH`.

### Install

```bash
bash install.sh      # copies the skill into <target>/.trae/skills/spz-gatekeeper-r-sequence
bash uninstall.sh    # removes exactly what install.sh recorded in .spz-manifest
```

Hook registration is part of the installer and goes through the same loading safety net the
skill uses for plugins (`scripts/gk_hook_manage.py`): non-destructive merge into the user-level
`hooks.json`, backup before every write, atomic replace, read-back verification, and fail-closed
when the target JSON cannot be parsed. Only entries pointing at this skill's wrapper are added or
removed — your own hook entries are preserved verbatim.

```bash
bash install.sh --no-hooks                       # copy only, leave hooks.json untouched
bash install.sh --hook-profile full              # match all tools (default: safe = write/exec tools)
bash install.sh --hook-profile off               # remove this skill's entry only
python3 scripts/gk_hook_manage.py status --json  # registered / absent / foreign / unparseable
```

### Quickstart

```bash
bash gatekeeper-cli.sh discover                 # resolve repo, plan and state
bash gatekeeper-cli.sh state                    # current stage, phase, budgets
bash gatekeeper-cli.sh pre-tool-check --path <file>
bash gatekeeper-cli.sh audit --state            # state audit (writes audit_state_result into state)
bash gatekeeper-cli.sh doc-align                # documentation/code drift check
```

### One-click slash commands

The following **optional** command shims are thin wrappers: each one delegates to
`gatekeeper-cli.sh` (or to `scripts/gk_chain.py`, which itself only drives `advance`); none of
them re-implements a gate or an evidence collector. They live outside this repository as
user-level skills (`~/.trae/skills/gk-*`) and are **not** installed by `install.sh`; without
them, run the equivalent CLI invocation directly (shown in the last column).

| Command | What it does | CLI equivalent |
|---|---|---|
| `/gk-chain` | Run a sequence chain: `run standing\|audit\|red`, with `--only`, `--from/--to`, `--dry-run` | `python3 scripts/gk_chain.py run <chain> [flags]` |
| `/gk-audit` | Audit bureau: `plan_lint` gate, then the per-station audit sequence or `audit --all` | `scripts/gk_chain.py run audit` / `gatekeeper-cli.sh audit --all` |
| `/gk-red` | Red-team sequence: the 16 `RED-*` stations, composable per station | `python3 scripts/gk_chain.py run red [--only ...]` |
| `/gk-refine` | Plan refinement: `plan_lint` → six arms → MoA aggregate/HTML | `gatekeeper-cli.sh plan-refinement <plan> --task "<task>"` |
| `/gk-accept` | Acceptance run: affected subset or full regression (`scripts/_accept_cli.sh`) | `bash scripts/_accept_cli.sh` |
| `/gk-finding` | Finding ledger: `dup-check` / `register` / `verify` / `close` / `status` | `gatekeeper-cli.sh finding <sub> ...` |
| `/gk-status` | Read-only overview: stage, budget, credit score (observation only), debt, findings, worktrees | `gatekeeper-cli.sh state` + `apply-worktree --reclaim` (dry-run) |
| `/gk-selfcheck` | Environment self-check: state integrity, provider, graph baseline, subagent env | `gatekeeper-cli.sh self-check` |
| `/gk-doc` | Documentation sync: `docgen --check` → `docgen` → `doc-align` | `gatekeeper-cli.sh docgen --check` / `doc-align` |

Commands resolve the skill root at runtime instead of hardcoding a user path:

```bash
GK="${GK_SKILL_DIR:-$HOME/.trae/skills/spz-gatekeeper-r-sequence}"
PY="${GK_PY:-python3}"       # optional interpreter override
# GK_BASH overrides the shell used by gk_chain.py (default: bash)
```

`audit` has two distinct shapes and they are not interchangeable: the **audit sequence**
(`gk_chain.py run audit`) advances `AUDIT-STATE → AUDIT-MEMORY → AUDIT-CROSSR → AUDIT-REPORT`
and records phase markers; the **bureau aggregate** (`gatekeeper-cli.sh audit --all`) runs the
six deterministic domains and aggregates them without writing phase markers.

### Configuration

All variables are optional; without credentials the LLM lanes degrade to local-only.

| Variable | Default | Purpose |
|---|---|---|
| `GATEKEEPER_API_KEY` / `DEEPSEEK_API_KEY` | unset | LLM-side key; absent = local-only monitor/agent lanes |
| `MIMO_API_KEY` | unset | Failover provider key (second leg) |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | DeepSeek-compatible endpoint |
| `GK_CRITIC_MODEL` | `deepseek-flash` | Critic model for CLI review lanes |
| `GK_REASONING_EFFORT` | `max` | Reasoning effort for the critic |
| `MIMO_BASE_URL` / `GK_MIMO_CRITIC_MODEL` | `https://api.xiaomimimo.com/v1` / `mimo-v2.6-flash` | Failover endpoint/model |
| `GK_FAILOVER_CHAIN` | `deepseek,mimo,local` | Provider retry order |
| `GK_SUBAGENT_API_MODEL` | unset | Overrides the model used by sub-agent dispatches (incl. L2 cross-review) |
| `SUBAGENT_TIER` | role default | Sub-agent budget tier |
| `GATEKEEPER_HMAC_KEY` | auto from `.keys/` | ECC HMAC key; absent = unsigned |
| `GATEKEEPER_AGENT_KEY` / `GATEKEEPER_AGENT_PUBKEY_DIR` | unset / `.keys/agents` | Ed25519 agent identity for ECC outputs |
| `GK_MAIN_REPO` | runtime-resolved | Explicit main-repo path (relative paths and `..` rejected) |
| `GATEKEEPER_WORKTREE_ROOT` | auto-detect | Worktree parent (must lie under `DEV_WORKTREE_ROOTS`) |
| `GK_AUDIT_OUTCOME_ENDPOINT` | unset | Decision backend for `monitor --api`; unset = advisory only |
| `GK_SELFCHECK_GITNEXUS_MS` | `5000` | Self-check WARN threshold for a single GitNexus call |
| `GK_SANDBOX_SUBAGENT` | `1` | Wrap every subagent dispatch (mem/time/proc limits); `0` opts out |
| `GK_SANDBOX_MODE` | `limits` | `limits` (resource limiter) or `bwrap` (filesystem isolation, requires bubblewrap) |
| `GK_SANDBOX_NET` | `allow` | `bwrap` mode only: `allow` (default; refinement needs network) or `deny` |
| `GK_SANDBOX_MEM_MB` | `2048` | Per-process address-space cap in the wrapper |
| `GK_SANDBOX_TIMEOUT_S` | unset | Wall-clock cap (unset = no extra limit) |
| `GK_SANDBOX_MAX_PROC` | unset | Process-count cap (unset = no extra limit) |
| `GK_SANDBOX_FAIL_OPEN` | `0` | `1` = run unsandboxed if the wrapper is missing (logged) |

`GK_SANDBOX_*` is a **resource limiter** (memory / wall-clock / process count), not a
filesystem, network, or kernel isolation boundary. Set `GK_SANDBOX_SUBAGENT=0` only if you
deliberately accept unsandboxed execution.

Model defaults are code constants (see the `DS_*` / `MIMO_*` block at the top of
`gatekeeper-cli.sh`) and are overridable only through the env vars above; no model weights are
downloaded by this repository.

**Self-check / doctor**: `gatekeeper-cli.sh self-check` is the doctor entry point (30+ checks:
state/checksums, HMAC, API-key presence and provider reachability, GitNexus baseline plus
version/latency, `hooks.json` registration state, model/endpoint/env value validation, sandbox
wrapper state, cron tick freshness and overdue jobs, tenant safety, review coverage). WARN items
are reported without changing the exit code; FAIL items do.

### Tests

```bash
python -m pytest scripts/ -q
```

Tests are red-first: a fix lands with a test that fails on the previous commit. Performance-
sensitive suites (WASM, long-context probes) are marked and skipped when their toolchain is
absent.

### Security posture

- No credentials are stored in the repository; `.keys/` and environment files are ignored.
- The CLI reads its API key from the environment (`GATEKEEPER_API_KEY` / `DEEPSEEK_API_KEY`) and
  degrades to a local, zero-API monitor mode when none is present.
- State files, plan backups, generated reports and review caches are git-ignored; only code,
  references and tests are tracked.
- Reporting a vulnerability: [`SECURITY.md`](SECURITY.md) (please use private reporting, not a
  public issue). Deployment caveats and secret rotation are in
  [`references/security-measures.md`](references/security-measures.md).

### Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md): the four pre-PR gates, the red-first rule, symbolic
anchors, finding registration, and what must never be committed. Maintenance expectations and the
disclaimer are in [`MAINTENANCE.md`](MAINTENANCE.md).

### Known limitations

- The hook only governs paths inside a configured worktree; unrelated tool calls pass through.
- Windows and WSL path translation is handled explicitly, and some scripts assume a POSIX shell.
- Cross-review evidence is only as good as the recorded state; the repository keeps the raw
  records so that a claim can be re-checked rather than trusted.
- **OPCAP readings need a state file**: [`scripts/opcap_evidence.py`](scripts/opcap_evidence.py)
  is a thin alias of [`gk_opcap_export.py`](scripts/gk_opcap_export.py) (same CLI, byte-identical
  output), kept so the historical entry name keeps working. It reads a state
  read-only; the state itself is not shipped, so those figures cannot be re-derived from this
  package alone.

### Positioning: Super-agent vs. this repository

Architecture-only comparison with the Super-agent prototype published by the DeepSeek Harness
team (2026-10-31, MIT). Full version:
[`references/superagent-comparison.md`](references/superagent-comparison.md).

| Dimension | Super-agent (DeepSeek Harness) | This repository (ZTHL Aegis) |
|---|---|---|
| Goal | System owns session management; humans move up to decision & acceptance | Same goal, with **replayability first**: autonomy is bounded by gates |
| Topology | Resident **Router** + isolated **Worker** | `gk_route_center` (repo routing) + `subagent_runner` (7 roles) + single CLI entry |
| Session semantics | Session is an implementation detail | `state_domain` / worktree / session id are explicit and auditable |
| State & execution | Stateless loop in the cloud, DB-held state, local execution env | **Local-first**: single-source state + lock + checksum + worktrees |
| Messaging | Event-driven, async multi-channel | Append-only satellites + journal chain + event bus; workers return structured JSON only |
| Supervision | External **Watchdog** (an AI that supervises agents and may repair) | **Audit bureau** (reports findings, does not block) + safe-termination gate + abstain |
| Human role | Decision and acceptance; attention is scarce | Veto is non-delegable; independent scoring first, adjudication later (double-blind discipline) |
| What is measured | Tasks and models; humans are not measured | Object axis (gates/evidence) + **human axis (OPCAP: operator capability & bandwidth)** |
| Failure handling | Watchdog intervenes to keep work continuous | Fail-closed; undecidable ⟹ abstain / `[UNFITTED]` |
| License / release | MIT prototype repo | MulanPSL-2.0; public tree produced by a checked export |

**Shared:** router/worker split, "session is not the user's burden", an independent supervisor
beside the executors, and humans kept at the decision layer.
**Different:** throughput vs. replayability; cloud-resident state vs. local fail-closed state;
a supervisor that may repair vs. one that only reports; measuring tasks only vs. measuring the
operator as a separate axis.

### Roadmap (one line)

T2/T6 stay dormant until a real `standard` task exists (no manufactured findings or family
files), while the near-term deliverable — the decision-model calibration loop — is complete to
instrumentation level: the synthetic pipeline shows the instrument runs, not that the model is
promotable.

---

## 中文

面向 AI 辅助软件工程的**确定性治理层**。它把「agent 说做完了」变成一组**第三方可复跑**的检查：
每一次阶段推进、编辑、派发与裁决，都由一个命令行工具把关，并写下**带签名、可回放**的记录。

本仓是公开发布通道。文档索引见 [`references/README.md`](references/README.md)，所有导出的文档都由它链接。

### 许可

木兰宽松许可证第 2 版（Mulan PSL v2）。双语全文见 [`LICENSE`](LICENSE)，中文正本见
<http://license.coscl.org.cn/MulanPSL2>。

- 版权人：**Pu Junhan**（2026），完整声明块在 [`LICENSE`](LICENSE) 末尾。
- 随包分发的第三方组件（当前为 Apache ECharts 5.6.0）的许可见
  [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) 与 [`THIRD_PARTY_LICENSES/`](THIRD_PARTY_LICENSES/)。

### 它做什么

- **阶段门**：工作沿显式阶段推进（`discover` → `guard-edit` → `advance`），越阶段编辑是**拒绝**，
  不是警告。
- **编辑预算**：按会话/阶段分配额度（余弦调度）+ 单文件上限，**落盘前**执行。
- **审计与 finding**：缺陷带 id、关闭判据与证据链登记；关闭必须引用工具可验证的来源。
- **状态压缩**：长寿命 state 拆成小的元数据头 + append-only 卫星片，每片单写者、读侧做并集。
- **交叉审查**：评审与计划质询走受约束的子代理通道（token/条数预算），而不是不受约束的对话调用。

### 目录结构

| 路径 | 用途 |
|---|---|
| `gatekeeper-cli.sh` | 确定性 CLI：state、门禁、审计、评审、finding、cron |
| `scripts/` | CLI 背后的 Python 模块（每个都有配对的 `test_*.py`） |
| `references/` | 按需加载的协议与阶段参考；索引见 [`references/README.md`](references/README.md) |
| `monitor-schemas/` | monitor 输出的 schema |
| `assets/`、`zthl/` | 运行时资产与可选的 harness 集成 |
| `install.sh`、`uninstall.sh` | 非破坏安装到 `.trae/skills/` |

### 环境要求

`bash gatekeeper-cli.sh self-check` 的 `dependencies` 检查会**实测**下列每一项（并给出确切的安装/平替命令），可直接从输出复制。

| 工具 | 用途 | 缺失时 | 安装 | 仓内平替（env） |
|---|---|---|---|---|
| `bash` | 所有入口（`gatekeeper-cli.sh`、`scripts/*.sh`） | 全部不可用 | Linux/macOS 自带；Windows 用 **WSL** 或 Git Bash | — |
| `python3`（3.10+） | CLI 全部内部实现 | 全部不可用 | `apt install python3` / `winget install Python.Python.3.12` | `GK_PYTHON=/path/to/python`（由 `scripts/py_resolve.sh` 消费） |
| `git` | state、discover、worktree、评审证据 | state/路由类功能失败 | <https://git-scm.com/downloads> | — |
| `rg`（ripgrep） | 文本检索与若干门禁谓词 | 谓词无法触发（降级，绝不静默「通过」） | `apt install ripgrep` / `brew install ripgrep` / `winget install BurntSushi.ripgrep.MSVC` | `GK_RG=/path/to/rg` |
| `node`（20+） | **可选** GitNexus 图索引 | 图检查降级为具名 `WARN`/`SKIP` | <https://nodejs.org/> | — |
| `gitnexus` | **可选** 图索引/调用链/变更影响（依赖 `node`） | 同上；改用 `search` / `code_search` | `npm i -g gitnexus` | — |
| `markitdown` | **可选** `read_doc`（文档转文本） | 仅 `read_doc` 不可用 | `pipx install markitdown` | — |
| Python 包 `openai`、`openai-agents`、`pydantic`、`pytest` | 子代理运行时/验收套件 | 子代理派发与 `_accept_cli.sh` 不可用 | `pip install openai openai-agents pydantic pytest` | `SUAGENT_PYTHON` / `ACCEPT_PY` |

- 测试/验收套件（`scripts/_accept_cli.sh`）要求 Python **>= 3.11**；CLI 本体 3.10+ 即可。
  已验证：3.11.5（Windows venv）与 3.12（WSL 参考）。
- GitNexus 索引缺失时，图检查会等到单命令超时（默认 300s）再降级 —— 这是预期行为，不是卡死。
- 解释器发现顺序（不写死绝对路径）：`GK_PYTHON` → `SUAGENT_PYTHON` → `ACCEPT_PY` →
  `scripts/_accept_py.local`（本机私有 pin）→ 仓内 `.venv` / `.venv-*` → `GK_PY_GLOBS` → `PATH`。

### 安装

```bash
bash install.sh      # 安装到 <target>/.trae/skills/spz-gatekeeper-r-sequence
bash uninstall.sh    # 只删 install.sh 记在 .spz-manifest 里的内容
```

钩子注册由安装器完成，并走与插件同源的加载安全网（`scripts/gk_hook_manage.py`）：
非破坏合并进用户级 `hooks.json`、写前备份、原子替换、回读校验、目标 JSON 不可解析时
fail-closed。只增删指向本技能 wrapper 的条目，你自己的钩子条目原样保留。

```bash
bash install.sh --no-hooks                       # 只复制，不动 hooks.json
bash install.sh --hook-profile full              # 匹配全部工具（默认 safe = 写/执行类）
bash install.sh --hook-profile off               # 只摘除本技能条目
python3 scripts/gk_hook_manage.py status --json  # registered / absent / foreign / unparseable
```

### 快速开始

```bash
bash gatekeeper-cli.sh discover                 # 解析仓库、计划与 state
bash gatekeeper-cli.sh state                    # 当前阶段、相位、预算
bash gatekeeper-cli.sh pre-tool-check --path <file>
bash gatekeeper-cli.sh audit --state            # state 审计（把 audit_state_result 写入 state）
bash gatekeeper-cli.sh doc-align                # 文档/代码漂移检查
```

### 一键斜杠命令

下列命令是**可选**的薄壳：每个都委托给 `gatekeeper-cli.sh`（或 `scripts/gk_chain.py`，后者本身只驱动
`advance`），**没有一个**重新实现门禁或证据采集器。它们位于仓外的用户级技能目录（`~/.trae/skills/gk-*`），
`install.sh` **不会**安装；没有它们时，直接跑最后一列的等价命令即可。

| 命令 | 作用 | CLI 等价 |
|---|---|---|
| `/gk-chain` | 跑序列链：`run standing\|audit\|red`，支持 `--only`、`--from/--to`、`--dry-run` | `python3 scripts/gk_chain.py run <chain> [flags]` |
| `/gk-audit` | 审计署：先 `plan_lint`，再逐站审计序列或 `audit --all` | `scripts/gk_chain.py run audit` / `gatekeeper-cli.sh audit --all` |
| `/gk-red` | 红队序列：16 个 `RED-*` 站，可逐站组合 | `python3 scripts/gk_chain.py run red [--only ...]` |
| `/gk-refine` | 计划质询：`plan_lint` → 六臂 → MoA 聚合/HTML | `gatekeeper-cli.sh plan-refinement <plan> --task "<task>"` |
| `/gk-accept` | 验收：受影响子集或全量回归（`scripts/_accept_cli.sh`） | `bash scripts/_accept_cli.sh` |
| `/gk-finding` | finding 台账：`dup-check` / `register` / `verify` / `close` / `status` | `gatekeeper-cli.sh finding <sub> ...` |
| `/gk-status` | 只读总览：阶段、预算、信用分（仅观测）、未审债、finding、worktree | `gatekeeper-cli.sh state` + `apply-worktree --reclaim`（dry-run） |
| `/gk-selfcheck` | 环境自检：state 完整性、provider、图基线、子代理环境 | `gatekeeper-cli.sh self-check` |
| `/gk-doc` | 文档同步：`docgen --check` → `docgen` → `doc-align` | `gatekeeper-cli.sh docgen --check` / `doc-align` |

命令在运行时解析技能根，不写死用户路径：

```bash
GK="${GK_SKILL_DIR:-$HOME/.trae/skills/spz-gatekeeper-r-sequence}"
PY="${GK_PY:-python3}"       # 可选：覆盖解释器
# GK_BASH 覆盖 gk_chain.py 使用的 shell（默认 bash）
```

`audit` 有两种**不可互换**的形态：**审计序列**（`gk_chain.py run audit`）推进
`AUDIT-STATE → AUDIT-MEMORY → AUDIT-CROSSR → AUDIT-REPORT` 并记录相位标记；**审计署聚合**
（`gatekeeper-cli.sh audit --all`）跑六个确定性域并聚合，不写相位标记。

### 配置

所有变量都是可选的；没有凭据时 LLM 车道降级为纯本地。

| 变量 | 默认 | 用途 |
|---|---|---|
| `GATEKEEPER_API_KEY` / `DEEPSEEK_API_KEY` | 未设 | LLM 侧密钥；缺失 = 仅本地 monitor/agent 车道 |
| `MIMO_API_KEY` | 未设 | 容灾提供方密钥（第二腿） |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | DeepSeek 兼容端点 |
| `GK_CRITIC_MODEL` | `deepseek-flash` | CLI 评审车道的 critic 模型 |
| `GK_REASONING_EFFORT` | `max` | critic 的推理强度 |
| `MIMO_BASE_URL` / `GK_MIMO_CRITIC_MODEL` | `https://api.xiaomimimo.com/v1` / `mimo-v2.6-flash` | 容灾端点/模型 |
| `GK_FAILOVER_CHAIN` | `deepseek,mimo,local` | provider 重试顺序 |
| `GK_SUBAGENT_API_MODEL` | 未设 | 覆盖子代理派发所用模型（含 L2 交叉审查） |
| `SUBAGENT_TIER` | 角色默认 | 子代理预算档位 |
| `GATEKEEPER_HMAC_KEY` | 自动从 `.keys/` | ECC HMAC 密钥；缺失 = 不签名 |
| `GATEKEEPER_AGENT_KEY` / `GATEKEEPER_AGENT_PUBKEY_DIR` | 未设 / `.keys/agents` | ECC 输出的 Ed25519 代理身份 |
| `GK_MAIN_REPO` | 运行时解析 | 显式主仓路径（拒绝相对路径与 `..`） |
| `GATEKEEPER_WORKTREE_ROOT` | 自动探测 | worktree 父目录（必须位于 `DEV_WORKTREE_ROOTS` 下） |
| `GK_AUDIT_OUTCOME_ENDPOINT` | 未设 | `monitor --api` 的决策后端；未设 = 仅建议 |
| `GK_SELFCHECK_GITNEXUS_MS` | `5000` | 单次 GitNexus 调用的自检 WARN 阈值 |
| `GK_SANDBOX_SUBAGENT` | `1` | 包裹每次子代理派发（内存/时间/进程限制）；`0` 关闭 |
| `GK_SANDBOX_MODE` | `limits` | `limits`（资源限制）或 `bwrap`（文件系统隔离，需 bubblewrap） |
| `GK_SANDBOX_NET` | `allow` | 仅 `bwrap`：`allow`（默认，质询需要网络）或 `deny` |
| `GK_SANDBOX_MEM_MB` | `2048` | 包装器内的单进程地址空间上限 |
| `GK_SANDBOX_TIMEOUT_S` | 未设 | 墙钟上限（未设 = 不额外限制） |
| `GK_SANDBOX_MAX_PROC` | 未设 | 进程数上限（未设 = 不额外限制） |
| `GK_SANDBOX_FAIL_OPEN` | `0` | `1` = 包装器缺失时不隔离运行（会记日志） |

`GK_SANDBOX_*` 是**资源限制器**（内存/墙钟/进程数），不是文件系统、网络或内核隔离边界。
只有在明确接受无沙箱执行时才设 `GK_SANDBOX_SUBAGENT=0`。

模型默认值是代码常量（见 `gatekeeper-cli.sh` 顶部的 `DS_*` / `MIMO_*` 块），只能通过上述环境变量覆盖；
本仓不下载任何模型权重。

**自检 / doctor**：`gatekeeper-cli.sh self-check` 是医生入口（30+ 项：state/校验和、HMAC、API key
存在性与 provider 可达性、GitNexus 基线与版本/延迟、`hooks.json` 注册状态、模型/端点/env 值校验、
沙箱包装器状态、cron tick 新鲜度与逾期作业、租户安全、评审覆盖）。WARN 不改退出码，FAIL 改。

### 测试

```bash
python -m pytest scripts/ -q
```

测试是红先的：修复必须带一个在上一提交上会失败的测试。性能敏感套件（WASM、长上下文探针）
在工具链缺失时标记跳过。

### 安全姿态

- 仓内不存凭据；`.keys/` 与环境文件被忽略。
- CLI 从环境读 API key（`GATEKEEPER_API_KEY` / `DEEPSEEK_API_KEY`），无 key 时降级为本地零 API 的 monitor 模式。
- state、计划备份、生成报告、评审缓存均被 git ignore；只跟踪代码、参考与测试。
- 漏洞报告：见 [`SECURITY.md`](SECURITY.md)（请走私报，不要开公开 issue）。部署注意事项与密钥轮换见
  [`references/security-measures.md`](references/security-measures.md)。

### 贡献

见 [`CONTRIBUTING.md`](CONTRIBUTING.md)：四道 PR 前置门、红先规则、符号锚、finding 登记，以及
禁止提交清单。维护预期与免责声明见 [`MAINTENANCE.md`](MAINTENANCE.md)。

### 已知限制

- 钩子只治理配置 worktree 内的路径；无关的工具调用会直接放行。
- Windows 与 WSL 的路径转换是显式处理的，部分脚本假设 POSIX shell。
- 交叉审查证据的可靠性取决于记录的 state；本仓保留原始记录，以便**复核**而不是**相信**。
- **OPCAP 读数需要 state 文件**：[`scripts/opcap_evidence.py`](scripts/opcap_evidence.py) 是
  [`gk_opcap_export.py`](scripts/gk_opcap_export.py) 的薄别名（同 CLI、输出逐字一致），保留该入口名以兼容既有脚本。
  它只读 state；state 本体不随包发布，因此这些数字**无法仅凭本包**重算。

### 定位：Super-agent 与本仓的对照

仅做架构面对照，对象是 DeepSeek Harness 团队 2026-10-31 公开的 Super-agent 原型（MIT）。完整版见
[`references/superagent-comparison.md`](references/superagent-comparison.md)。

| 维度 | Super-agent（DeepSeek Harness） | 本仓（ZTHL Aegis） |
|---|---|---|
| 目标 | 系统接管会话管理，人上移到决策与验收 | 同目标，但**先保证可回放**，自主度受门禁约束 |
| 拓扑 | 常驻 **Router** + 隔离 **Worker** | `gk_route_center`（仓库路由）+ `subagent_runner`（7 角色）+ CLI 单入口 |
| 会话语义 | Session 是实现细节 | `state_domain` / worktree / session id 显式建模、可审计 |
| 状态与执行 | 云端无状态 loop、DB 存状态、本地执行 | **本地优先**：单源 state + 锁 + 校验和 + worktree |
| 消息 | 事件驱动、异步多信道 | append-only 卫星 + journal 链 + event bus；子代理只回结构化 JSON |
| 监督 | 外部 **Watchdog**（AI 监督 AI，可介入修复） | **审计署**（只出 finding，不直接阻断）+ 安全终止门 + abstain |
| 人的角色 | 决策与验收；注意力稀缺 | 否决权不可让渡；先独立打分、事后裁定（双盲纪律） |
| 度量对象 | 任务与模型，不测人 | 物轴（门禁/证据）+ **人轴（OPCAP：操作者能力与带宽）** |
| 失败处理 | Watchdog 介入，维持任务连续 | 默认拒绝；不可判 ⟹ abstain / `[UNFITTED]` |
| 许可/发布 | MIT 原型仓 | MulanPSL-2.0；公开树由机检导出产生 |

**相同**：Router/Worker 分层、会话不是用户负担、执行者旁边有独立监督面、人留在决策层。
**不同**：吞吐 vs 可回放；云端常驻状态 vs 本地 fail-closed；监督者可否修复 vs 只报告；
只测任务 vs 把人作为独立轴测量。

### 路线图（一行）

在出现真实的 `standard` 任务前，T2/T6 保持休眠（不制造 finding、不造族文件）；近期交付物
—— 决策模型校准闭环 —— 已到「仪器可跑」的程度：合成管线证明**仪器能跑**，不证明模型可推广。

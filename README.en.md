# ZTHL Aegis (智御)

**English** · [中文](README.md)

> Project name: **ZTHL Aegis**; the installable skill/package directory keeps its historical name
> `spz-gatekeeper-r-sequence`.

---

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

### Independent Work Statement

This repository is an independent personal work of **Pu Junhan**. The views and technical choices are
the author's own and do not represent any employer, client, or organization. It was developed without
using any employer/client proprietary code, confidential information, or resources. Third-party
dependencies and reference implementations are used under their respective licenses and attributed in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and [`references/`](references/). This repository is
not a commercial commitment, legal advice, or authorization to operate any third-party system.

### Intended use and boundaries (responsible-use statement)

This repository is a **governance and audit tool for software engineering processes**. Its intended use
is limited to stage gating, audit trails, and quality review for software you own or are authorized to
work on.

**Prohibited**: using this project, or any part of it, for unauthorized intrusion, bypassing access
controls, delivering malicious payloads, establishing persistence, evading security auditing, or any
unlawful purpose. The built-in interception/detection features exist to **defend this project's own
engineering chain**; they do not provide offensive capability and grant no authorization over any system.

**Liability boundaries**:

- Provided without warranty of any kind (see the Mulan PSL v2 disclaimer); you are responsible for
  deployment, configuration, and consequences of use.
- Not legal, compliance, or security-certification advice; consult a qualified third party.
- Default settings are **not** a hardening baseline; production use requires your own threat modeling,
  least privilege, and key management.
- This project does not proactively probe or scan third-party systems, and must not be repurposed to do so.

**Responsible disclosure**: please do **not** open a public issue for security problems. Follow
[`SECURITY.md`](SECURITY.md) and contact the maintainer privately; we will confirm, fix, and coordinate
disclosure. Exploit requests and automated attack payloads are out of scope.

**AI capability boundaries**: review/triage features are **advisory only** — they never change a verdict.
"Pre-submission simulated review" is a self-check before submission; it produces no referee report and
does not replace any venue's review process.

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

### Supported plugins (loading safety net)

The plugin loading safety net is `scripts/gk_plugin_manifest.py`: an **unregistered id cannot be
loaded**; `disabled` is refused; `write=True` requires an `undo` hook (no inverse effect = refused);
`npm:` sources must carry a tarball `integrity` (supply-chain pin); every capability call passes
`check_capability`; load/unload take a snapshot and can be rolled back.

This repository registers **three** plugins; the **public package ships two** (`paper-review`
source is not included — see below):

| Plugin id | Name / source | Form in this package | Capability allow-list |
|---|---|---|---|
| `paper-review` | `gk_paper_review` (builtin; pre-submission simulated review — a self-check before submission, **not peer review**) | **Private-only**; not shipped publicly (source is in the export exclusion face) ⟹ the command entry returns the loading-safety-net `source=missing` | `paper-review` |
| `bashpy-migrate` | `zthl-bashpy-migrate` (pip / npm wrapper) | Loader `scripts/gk_bashpy_loader.py`; the plugin itself is a separate package | `analyze` `verify` `audit` `status` `check` `upgrade` `rollback` |
| `git-workflow` | Standalone skill (MulanPSL-2.0) | Loader lives in the skill: `../git-workflow/scripts/gk_gitworkflow_loader.py` | `push` `branch` `worktree` `release` `security` `cleanup` `history` `selfcheck` `version` |

**Not covered by the plugin net**: `doc-align` is a CLI subcommand (`_CMD_REG[doc-align]`, a
zero-API static scan), not a plugin; the **command entry points** of `migrate` / `paper-review`
also live in `_CMD_REG`. The manifest governs loadability, capability allow-lists and unload
rollback — not command routing.

**Open-source surface**: `paper-review` source is **not shipped** (`gk_paper_review.py` /
`_loader.py` are in the export exclusion face); `bashpy-migrate` ships its loader here while the
plugin body is a separate package; `git-workflow` is a standalone skill with the loader on the
skill side. In the public package the plugin manifest registers `paper-review` **conditionally**
(no entry when the source is absent), so there is no registration pointing at a missing file.

### Safety nets and templates (overview and provenance)

**Templates** here are copyable skeletons for deliverables; **safety nets** are deterministic
intercepts before a node runs or a write lands. Both are distilled from the same engineering
practice: the `spz2glb` toolchain (3D asset conversion and glTF/GLB pipelines, including
browser-side WASM delivery) and the R7 port into `spz_gatekeeper`; build/format conventions come
from glTF/GLB pipeline development and standards discussions. We **only register what actually
works in this repository**; anything present in a plan but absent in code is marked `not wired`
in [`standard-maintenance-module.md`](references/standard-maintenance-module.md) §2.

**Templates**

| Template | What it defines | When to use |
|---|---|---|
| [`ci-pipeline-template.md`](references/ci-pipeline-template.md) | CI skeleton: matrix, triggers, artifact-missing checks, `set -euo pipefail` + `shell: bash` | New repository CI, workflow changes |
| [`wasm-engineering-template.md`](references/wasm-engineering-template.md) | WASM build/verify skeleton: pinned Emscripten, `-Oz`, zero-copy, serial semantics, unified resource surface | Browser-side WASM delivery |
| [`sequence-node-safety-net-template.md`](references/sequence-node-safety-net-template.md) | Design spec for sequence-node safety nets: G/B/C/T/D tuple + A1–A8 | Adding or hardening node guards |
| [`standard-maintenance-module.md`](references/standard-maintenance-module.md) | Self-healing layer: who notices and fixes it when a template or gate **itself** breaks | Template/gate changes, gate-failure reviews |

Data and contract templates: `references/red-arm-templates.json` (red-team arms),
`references/agent-families/*.json` (narrow-task cards for subagents), `monitor-schemas/*.json`
(per-station output contracts).

**Safety nets**

| Safety net | What it intercepts | Entry point |
|---|---|---|
| Plan writing (PW-SN) | Machine-checkable plan defects (baseline readings, switch naming, anchors) | `scripts/gk_plan_lint.py` |
| Plugin loading | Missing / wrong / broken loads | `scripts/gk_bashpy_loader.py` + plugin manifest |
| Sequence nodes (SN tuple) | Missing prerequisites, incomplete input, ambiguous names, no re-verification | `scripts/gk_node_guard.py` + `_hslsn_*` in `pre_tool_hook.py` |
| XSPI pollution defense | Privileged actions induced by untrusted content | `scripts/gk_task_gate.py` + containment boundaries |
| Document consistency | Drift across docs ↔ code ↔ index | `gatekeeper-cli.sh doc-align` + `docgen` |
| CI / build | Red CI, workflow changes, WASM build failures | `scripts/ci_smoke.sh`, `ci-diagnose`, `pre-check wasm` |
| Keys / signatures | Leakage, replacement, expiry, tampered trust anchors | Key-integrity checks + Ed25519 verification |
| State integrity | Tampering, concurrent read-modify-write, partial writes | `gk_json_utils.state_lock` + checksum + single write entry |
| Budget / economy | Edit quota, raises, entropy, appeals, credit score | `gk_budget_ledger` + `gk_credit_ledger` ([spec](references/credit-economy.md)) + `gk_gate_entropy` + `gk_gate_appeal` |
| Audit / red team | Governance defects | `audit --red` + `RED-*` stations |
| Convergence early stop (A8/RCA) | Idle iteration (scores flat / `μ` not falling) | `gk_convergence_evaluator.py` + `pre-check convergence` |

Failure semantics and applicability boundaries are listed in
[`standard-maintenance-module.md` §0.2](references/standard-maintenance-module.md); what to do
when a safety net itself fails is covered by §1–§2 of the same file.

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

**API key setup (open-source package)** — no code changes and no Windows registry required:

```bash
bash gatekeeper-cli.sh set-key deepseek sk-...   # persists to <skill>/.keys/api_key (0600) + session
bash gatekeeper-cli.sh set-key mimo sk-...       # persists to <skill>/.keys/mimo_key
bash gatekeeper-cli.sh set-key status            # source + masked value only (never the full key)
export GATEKEEPER_API_KEY=sk-...                 # or DEEPSEEK_API_KEY (one-off / container)
GATEKEEPER_KEY_FILE=/run/secrets/ds_key          # explicit key file (CI / mounted secret)
```

Precedence: `--api-key` > environment > key file (`.keys/` or `GATEKEEPER_KEY_FILE`) > Windows user
environment. `.keys/` is git-ignored and excluded from the release archive; the key file is written
with `0600`.

| Variable | Default | Purpose |
|---|---|---|
| `GATEKEEPER_API_KEY` / `DEEPSEEK_API_KEY` | unset (`set-key` persists to `.keys/api_key`) | LLM-side key; absent = local-only monitor/agent lanes |
| `MIMO_API_KEY` | (empty) | Failover provider key (second leg); the leg is skipped unless set |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | DeepSeek-compatible endpoint |
| `GK_CRITIC_MODEL` | `deepseek-flash` | Critic model for CLI review lanes |
| `GK_REASONING_EFFORT` | `max` | Reasoning effort for the critic |
| `MIMO_BASE_URL` / `GK_MIMO_CRITIC_MODEL` | `https://api.xiaomimimo.com/v1` / `mimo-v2.6-flash` | Failover endpoint/model |
| `GK_FAILOVER_CHAIN` | `deepseek,mimo,local` | Provider retry order |
| `GK_SUBAGENT_API_MODEL` | unset (= role default model; not a missing key) | Overrides the model used by sub-agent dispatches (incl. L2 cross-review) |
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

### Configure the audit bureau (decision model)

The audit bureau calls a `/v1/systemone`-compatible HTTP endpoint. No model weights and no
default endpoint are bundled; **without an endpoint it returns advisory only and never
fabricates success/fail**.

| Setting | Entry point | Default |
|:--|:--|:--|
| Endpoint | `GK_AUDIT_OUTCOME_ENDPOINT` or `--endpoint` | unset ⟹ advisory |
| Key directory | `--key-dir` (seal material; API key via `set-key` to `.keys/api_key`) | `.keys/` |
| Think mode | `--think-mode auto\|never\|always\|hybrid\|plain\|think` | `auto` |
| Temperature / seed | `--temperature` / `--seed` | `0.0` / `0` |
| Timeout | `--timeout` (seconds) | `30` |
| Model version | `--model-version` (falls back to response `model`; still empty ⟹ `model_version_unknown`) | backend decides |

```bash
export GK_AUDIT_OUTCOME_ENDPOINT="https://<your-backend>"
bash gatekeeper-cli.sh self-check
python scripts/gk_audit_outcome.py sweep --state .gatekeeper.state \
  --endpoint "$GK_AUDIT_OUTCOME_ENDPOINT"
```

The model is selected by the backend; the client only records the returned `model`. Criteria
wording and calibration thresholds (`MIN_N` / `rho` / agreement) are still code constants —
unified configuration and provider adapters are on the roadmap.

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

### Roadmap

T2/T6 stay dormant until a real `standard` task exists (no manufactured findings or family
files), while the near-term deliverable — the decision-model calibration loop — is complete to
instrumentation level: the synthetic pipeline shows the instrument runs, not that the model is
promotable.

- Release surface: the `bashpy` A/B dual-loop design document has been withdrawn from the
  published tree (**kept privately, to be reworked**); it returns once its tuple instantiations
  are rewritten against the current `STAGE-DUTY-MAP` and the 4-station standing sequence.
- **Long term: full platform support.** Linux is a hard gate today, Windows is in an observation
  window, and macOS has no CI leg yet. Remaining work: shims for GNU-only calls (`stat -c` /
  `date -d` / `ps -o etimes` / `timeout` / `sha256sum`), a macOS CI leg, and a **bash ≥ 4**
  requirement (stock macOS bash 3.2 lacks `${x^^}` / `mapfile` / `declare -A`), then promote the
  Windows leg to a hard gate.
- **Decision-model replacement slot.** The audit bureau (`gk_audit_outcome`) and `monitor --api`
  (`gk_monitor_decision`) already share one `/v1/systemone` backend, but configuration is
  scattered: endpoint/timeout/`think_mode` come from flags or env, while the model,
  `temperature`/`seed`, prompt text and calibration thresholds (`MIN_N` / `ρ` / agreement) are
  backend- or code-constants. Next: one model-agnostic slot with unified configuration
  (endpoint, model id, parameters, prompt version, thresholds) + provider adapters, recording
  the model version/parameters for every verdict.

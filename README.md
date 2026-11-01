# ZTHL Aegis (智御)

> Project name: **ZTHL Aegis**; the installable skill/package directory keeps its historical name
> `spz-gatekeeper-r-sequence`.

A deterministic governance layer for AI-assisted software work. It turns "the agent says it is
done" into a set of checks a third party can rerun: every stage transition, edit, dispatch and
verdict is gated by a command-line tool that writes a signed, replayable record.

This repository is the public release channel. The documentation index is
[`references/README.md`](references/README.md); every exported document is linked from it.

## License

Mulan Permissive Software License, Version 2 (Mulan PSL v2). The full bilingual text is in
[`LICENSE`](LICENSE); the canonical Chinese text is published at
<http://license.coscl.org.cn/MulanPSL2>.

- Copyright owner: **Pu Junhan** (2026). The full notice block is at the end of [`LICENSE`](LICENSE).
- Third-party components shipped in this repository (currently Apache ECharts 5.6.0) are listed,
  with their upstream notices and license copies, in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)
  and [`THIRD_PARTY_LICENSES/`](THIRD_PARTY_LICENSES/).

## What it does

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

## Repository layout

| Path | Purpose |
|---|---|
| `gatekeeper-cli.sh` | Deterministic CLI: state, gates, audit, review, findings, cron |
| `scripts/` | Python modules behind the CLI (each with `test_*.py` siblings) |
| `references/` | Protocols and stage references loaded on demand; index at [`references/README.md`](references/README.md) |
| `monitor-schemas/` | Schemas for monitor output |
| `assets/`, `zthl/` | Runtime assets and the harness integration used by the companion paper |
| `install.sh`, `uninstall.sh` | Non-destructive install of the skill directory into `.trae/skills/` |

## Requirements

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

## Install

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

## Quickstart

```bash
bash gatekeeper-cli.sh discover                 # resolve repo, plan and state
bash gatekeeper-cli.sh state                    # current stage, phase, budgets
bash gatekeeper-cli.sh pre-tool-check --path <file>
bash gatekeeper-cli.sh audit --state            # state audit (writes audit_state_result into state)
bash gatekeeper-cli.sh doc-align                # documentation/code drift check
```

## One-click slash commands

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

## Configuration

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

## Tests

```bash
python -m pytest scripts/ -q
```

Tests are red-first: a fix lands with a test that fails on the previous commit. Performance-
sensitive suites (WASM, long-context probes) are marked and skipped when their toolchain is
absent.

## Security posture

- No credentials are stored in the repository; `.keys/` and environment files are ignored.
- The CLI reads its API key from the environment (`GATEKEEPER_API_KEY` / `DEEPSEEK_API_KEY`) and
  degrades to a local, zero-API monitor mode when none is present.
- State files, plan backups, generated reports and review caches are git-ignored; only code,
  references and tests are tracked.
- Reporting a vulnerability: [`SECURITY.md`](SECURITY.md) (please use private reporting, not a
  public issue). Deployment caveats and secret rotation are in
  [`references/security-measures.md`](references/security-measures.md).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md): the four pre-PR gates, the red-first rule, symbolic
anchors, finding registration, and what must never be committed. Maintenance expectations and the
disclaimer are in [`MAINTENANCE.md`](MAINTENANCE.md).

## Known limitations

- The hook only governs paths inside a configured worktree; unrelated tool calls pass through.
- Windows and WSL path translation is handled explicitly, and some scripts assume a POSIX shell.
- Cross-review evidence is only as good as the recorded state; the repository keeps the raw
  records so that a claim can be re-checked rather than trusted.

## Roadmap (one line)

T2/T6 stay dormant until a real `standard` task exists (no manufactured findings or family
files), while the near-term deliverable — the decision-model calibration loop — is complete to
instrumentation level: the synthetic pipeline shows the instrument runs, not that the model is
promotable.

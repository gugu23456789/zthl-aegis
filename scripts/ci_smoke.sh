#!/usr/bin/env bash
# ci_smoke.sh — CI 快速门（语法 / 计划 linter / 受影响快速子集；不依赖密钥、不联网）。
# 用法：bash scripts/ci_smoke.sh
# Env：PY（缺省走单源 `scripts/gk_accept_py.py`：env ACCEPT_PY → scripts/_accept_py.local → python3）、
#      CI_BASE_REF（PR base sha / push before；缺省 HEAD~1）
set -euo pipefail
BASE="${CI_BASE_REF:-}"
cd "$(dirname "$0")/.."
# 解释器单源（2026-10-31）：原缺省裸 `python3` 在本机 WSL 缺 pytest ⟹ 本地快速门必挂，
#   而 CI（setup-python + pip install）恰好能过 ⟹ 本地与 CI 判据分叉。改走同源解析。
PY="${PY:-$(python3 scripts/gk_accept_py.py 2>/dev/null || echo python3)}"

echo "== 1/4 shell syntax =="
bash -n gatekeeper-cli.sh

echo "== 2/4 python compile (tracked) =="
mapfile -t pyfiles < <(git ls-files 'scripts/*.py')
"$PY" -m py_compile "${pyfiles[@]}"

echo "== 3/4 plan linter (pw-sn 前置，可选；非仓库级 lint) =="
# 2026-10-31 口径修正：`gk_plan_lint.py` 是**计划质询前置 pw-sn 安全网**
# （对「本轮要质询的那份计划」跑，不是全仓文档 lint）。默认不跑；CI 侧用独立
# `plan-gate` 作业按手填 plan 路径触发。CI_PLAN_LINT=1 仅供本地临时对「变更计划」自检。
if [ "${CI_PLAN_LINT:-0}" = "1" ]; then
  if [ -z "$BASE" ] || [ "$BASE" = "0000000000000000000000000000000000000000" ]; then
    BASE="HEAD~1"
  fi
  plans=""
  if git rev-parse --verify -q "$BASE" >/dev/null 2>&1; then
    plans="$(git diff --name-only "$BASE"...HEAD -- 'docs/plans/*.md' || true)"
  fi
  if [ -n "$plans" ]; then
    while IFS= read -r p; do
      [ -f "$p" ] || continue
      echo "-- lint $p"
      "$PY" scripts/gk_plan_lint.py "$p"
    done <<< "$plans"
  else
    echo "(no changed plan)"
  fi
else
  echo "(skipped: plan_lint 属质询前置 pw-sn，见 CI 的 plan-gate 作业)"
fi

echo "== 4/4 fast pytest =="
"$PY" -m pytest -q \
  scripts/test_gk_plan_lint.py \
  scripts/test_gk_gate_appeal.py \
  scripts/test_gk_econ_params.py \
  scripts/test_gk_monitor_m1.py \
  scripts/test_gk_budget_ledger.py \
  scripts/test_gk_credit_floor.py \
  scripts/test_gk_main_repo.py \
  scripts/test_main_repo_value_sync.py \
  scripts/test_gk_advance_transition_table.py \
  scripts/test_gk_ecc_sink.py \
  scripts/test_gk_finding_open_spillover.py \
  scripts/test_gk_state_map.py \
  scripts/test_gk_monitor_decision.py \
  scripts/test_gk_agent_identity.py \
  scripts/test_gk_subagent_model_chain.py \
  scripts/test_opcap_evidence_alias.py \
  scripts/test_pack_release.py

echo "ci_smoke: OK"

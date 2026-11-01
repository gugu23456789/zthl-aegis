#!/usr/bin/env bash
# 月度模型货架 guard（应用级 cron 调用；只检测，不自动改 S）。
# 用法：gatekeeper-cli.sh cron create ... --script scripts/gk_guard_cron.sh --no-agent
set -u
set -o pipefail

SKILL_DIR="${SKILL_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
LOG_DIR="${HOME}/.gatekeeper"
LOG_FILE="${LOG_DIR}/model-shelf.log"

mkdir -p "${LOG_DIR}"
cd "${SKILL_DIR}" || exit 2

# 解释器：单源 `scripts/py_resolve.sh`（2026-11-01 去硬编码；原写死某个 /opt 隔离 venv）
_PY="$(bash "${SKILL_DIR}/scripts/py_resolve.sh" any 2>/dev/null || true)"
[ -n "${_PY}" ] || _PY="python3"

{
  echo "=== $(date -Is) guard start (cwd=${SKILL_DIR}) ==="
  # cron 调度器会剥离 key；显式允许 gk_model_shelf 从 Windows 注册表注入。
  export GK_ENV_INJECT=1
  "${_PY}" scripts/gk_model_shelf.py guard --allow-stale-phase
  rc=$?
  echo "=== $(date -Is) guard exit=${rc} ==="
  exit "${rc}"
} 2>&1 | tee -a "${LOG_FILE}"

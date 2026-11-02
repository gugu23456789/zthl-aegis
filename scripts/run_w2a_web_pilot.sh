#!/usr/bin/env bash
# 2026-10-18: W2A Web L0 pilot wrapper (avoids PowerShell '$' expansion).
set -u
SKILL_DIR="${SKILL_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
W2A_WORKTREE="${W2A_WORKTREE:-$(git -C "$SKILL_DIR" rev-parse --show-toplevel 2>/dev/null || printf '%s' "$SKILL_DIR")}"
cd "$W2A_WORKTREE" || exit 2
export STATE_FILE="${STATE_FILE:-$SKILL_DIR/.gatekeeper.state}"
export GK_ENV_INJECT=1
export SUBAGENT_TIER=2
# 2026-10-18 pilot: context sig 因脚本改动失效，且 gitnexus 全量重嵌在此环境超时
# （3 臂 × 10min 串行）。pilot 只验证 web_search/web_fetch 通道，显式降级：
#   关自愈 + 允许 stale ctx/baseline + analyze fail-fast。
export GK_NO_CTX_SELFHEAL=1
export GK_ALLOW_STALE_CTX=1
export GK_ALLOW_STALE_BASELINE=1
export GK_GX_ANALYZE_TIMEOUT=30
PLAN="${W2A_PLAN:-$W2A_WORKTREE/docs/plans/2026-10-18-w2a-web-pilot-plan.md}"
NARROW="${W2A_NARROW:-$W2A_WORKTREE/docs/plans/2026-10-18-w2a-web-narrow-tasks.json}"
LOG="${W2A_LOG_PREFIX:-/tmp/w2a-web}-pilot.log"
TASK='请逐条核查本计划的 5 条断言。若上下文已注入共享外部证据，优先使用；未覆盖的断言再用 web_search / web_fetch 补充；禁止使用本地 search。每条给出 verdict=support/refute/abstain、source URL、<=200 字原文片段；不确定就 abstain。最后输出 SOURCES: ...'
bash ./gatekeeper-cli.sh state-patch --narrow-register "$NARROW" > /tmp/w2a-web-narrow-register.log 2>&1 || {
  echo "narrow register failed:"; cat /tmp/w2a-web-narrow-register.log; exit 2
}
cat /tmp/w2a-web-narrow-register.log
bash ./gatekeeper-cli.sh plan-refinement "$PLAN" --task "$TASK" --arms-per-group 1 --run > "$LOG" 2>&1
rc=$?
echo "RC=$rc"
tail -n 80 "$LOG"

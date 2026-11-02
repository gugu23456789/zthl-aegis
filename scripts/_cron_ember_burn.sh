#!/bin/bash
# _cron_ember_burn.sh — cron 作业内核（`no_agent` + `script`）：让**余烬系统定期处理** state 体积。
# =============================================================================
# 2026-09-25（`ECC-3802B43E4EF9`）：「state 名义上受余烬管理却从不被处理」的闭法 ——
#   病根 = 配额归档通道（`gk_finding.archive_closed`）已实现且 CLI 已暴露，但**无任何自动触发**
#   （相位切换的全量 ember 快照只在 `discover` 且相位真变化时才写）⟹ 十几天增长只能靠人工调配额。
# 注册（写 `~/.gatekeeper/cron/jobs.json`，经 CLI 而非手改 —— 该文件有 checksum + flock 护）：
#   gatekeeper-cli.sh cron create ember-burn "49 * * * *" "(no_agent script job)" \
#     --script scripts/_cron_ember_burn.sh --no-agent
# 契约（`cron_scheduler` 的「no_agent + script」分支）：stdout **末行**须是含 `wakeAgent` 的 JSON；
#   本作业 0 API、无需唤醒 agent ⟹ 恒 `{"wakeAgent": false}`（与 `gk_cron_night_batch.py` 同形）。
# 单源：动作 = `gatekeeper-cli.sh ember burn`（内部转调 `gk_finding.archive_closed`，**禁第二实现**）；
#   **预算足时零写盘**（`archived=0`）⟹ 本作业可安全地高频跑。
# 相位：时钟 = Windows 计划任务 `GatekeeperCronTick`（每小时 :49 跑 `cron_scheduler.py --once`）
#   ⟹ 表达式对齐 `49 * * * *`（晚触发不丢作业：`cron_jobs.get_due_jobs` 有 catch-up 语义）。
set -uo pipefail
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
_out="$(bash "$SKILL_DIR/gatekeeper-cli.sh" ember burn 2>&1)"
printf '%s\n' "$_out"
printf '{"wakeAgent": false}\n'
# fail-loud（本行决定 rc）：失败**不静默**进入 tick.log —— 否则体积问题无声累积（正是本刀要闭的病根）。
case "$_out" in
  *'"ok": false'*|*'"ok":false'*) echo "[ember-burn] 归档失败（见上 JSON）" >&2; exit 1 ;;
esac
exit 0

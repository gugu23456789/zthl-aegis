#!/usr/bin/env bash
# 定时审计触发器（cron no_agent 作业体）—— 2026-11-01 起薄封装。
#
# 内核 = scripts/gk_audit_cron_run.py：
#   ① 指纹跳过（git HEAD + state mtime/size 未变且上次成功 ⟹ 直接复用，默认 7 天强制重跑）
#   ② 逐域计时日志（domain=… rc=… sec=… verdict=…）
#   ③ 失败告警 ~/.gatekeeper/audit-cron.alert.json（成功即删），rc 真实
# 默认域 = state docs memory（实测 ~10s；**不要**把 crossr/depth/report 放进日常，
# 它们派 subagent / 跑 gitnexus 全量，属人工触发的重量级域）。
#
# env：GK_AUDIT_CRON_DOMAINS="state docs memory"  GK_AUDIT_CRON_TIMEOUT=600
#      GK_AUDIT_CRON_FORCE=1（忽略缓存立即重跑）
set -u
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "${SKILL_DIR}/scripts/gk_audit_cron_run.py" --skill-dir "${SKILL_DIR}" "$@"

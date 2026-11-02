#!/bin/bash
# 红队统一 runner — 隔离 state + 密钥备份恢复 + 全部批次一键执行
# 2026-08-14: 修复早期红队脚本硬编码主仓库 state 路径的技术债。
# 隔离原理: CLI 的 STATE_FILE 默认 = ${SKILL_DIR}/.gatekeeper.state（plan 指针被 discover 清除后复位）。
#           因此 runner 备份真实 .gatekeeper.state → 写入测试 state → 跑全部批次 → 恢复。
#           脚本与 CLI 天然读取同一文件，消除路径错位假阳性。
# 密钥策略: context 24h 轮换自愈 + audit 30d 必须 restore → runner 备份 .keys → 跑后恢复。
set +e

SKILL="<home>/.trae/skills/spz-gatekeeper-r-sequence"
REAL_STATE="${SKILL}/.gatekeeper.state"
BACKUP_DIR=$(mktemp -d /tmp/gk_redteam_bak_XXXXXX)

echo "==========================================="
echo "R7 RED-TEAM RUNNER (isolated) — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "==========================================="

# ── 1. 备份真实 state + keys + context（A5 会篡改 subagent-context.json，恢复不完整会损坏 JSON）──
cp -a "$REAL_STATE" "$BACKUP_DIR/state" 2>/dev/null && echo "state backed up" || echo "WARN: no real state to back up"
cp -a "${SKILL}/.keys" "$BACKUP_DIR/keys" 2>/dev/null && echo "keys backed up" || echo "WARN: no keys to back up"
[ -f "${SKILL}/.gatekeeper.plan" ] && cp -a "${SKILL}/.gatekeeper.plan" "$BACKUP_DIR/plan_pointer" && echo "plan pointer backed up"
if [ -f "${SKILL}/references/subagent-context.json" ]; then
  cp -a "${SKILL}/references/subagent-context.json" "$BACKUP_DIR/ctx.json"
  cp -a "${SKILL}/references/subagent-context.json.sig" "$BACKUP_DIR/ctx.json.sig" 2>/dev/null
  echo "context + sig backed up"
fi

# ── 2. 写入测试 state（standing 类型，覆盖 ECO/ECC 测试面）──
python3 -c "
import json, time
d = {
    'r_phase': 'ECO-SCAN', 'stage': 'ECO-SCAN', 'branch': 'master',
    'worktree': '$SKILL', 'main_repo': '$SKILL',
    'gate_data': {
        'project_type': 'standing',
        'scheduler': {'mode': 'cosine', 'max_lr': 4, 'min_lr': 1, 'total_steps': 6, 'current_step': 1, 'current_lr': 4},
        'rejected_edits': []
    },
    'monitor_scores': {}, 'history': []
}
json.dump(d, open('$REAL_STATE', 'w'), indent=2)
print('TEST_STATE_WRITTEN')
" 2>&1
export REDTEAM_STATE="$REAL_STATE"

# ── 3. 依次执行全部红队批次 ──
SCRIPTS=(
  _r7_redteam.sh
  _r7_redteam_batch1.sh
  _r7_redteam_batch2.sh
  _r7_redteam_batch3a.sh
  _r7_redteam_batch4.sh
  _r7_redteam_batch5.sh
  _r7_redteam_batch6.sh
  _r7_redteam_batch9.sh
  _r7_redteam_medium_gates.sh
  _r7_redteam_f01_f02.sh
  _r7_redteam_p1_seal.sh
  _r7_redteam_i2.sh
  _r7_redteam_i67.sh
  _r7_redteam_eco_escape.sh
  _r7_redteam_gatefix.sh
  _r7_redteam_cron.sh
  _r7_redteam_cron_v2.sh
)
TOTAL_VULN=0; TOTAL_FAIL=0; TOTAL_PASS=0
for f in "${SCRIPTS[@]}"; do
  echo ""
  echo "########## $f ##########"
  OUT=$(bash "$SKILL/scripts/$f" 2>&1)
  RC=$?
  echo "$OUT" | rg "VULN|FAIL|RESULTS|PASS:" | tail -40
  # 汇总计数
  V=$(echo "$OUT" | rg -c "  VULN:" 2>/dev/null || echo 0)
  P=$(echo "$OUT" | rg -c "  PASS:" 2>/dev/null || echo 0)
  F=$(echo "$OUT" | rg -c "  FAIL:" 2>/dev/null || echo 0)
  echo "  [$f] VULN=$V PASS=$P FAIL=$F exit=$RC"
  TOTAL_VULN=$((TOTAL_VULN + V)); TOTAL_PASS=$((TOTAL_PASS + P)); TOTAL_FAIL=$((TOTAL_FAIL + F))
done

# ── 4. 恢复真实 state + keys（audit 30d 必须 restore，context 依赖 24h 自愈但一并恢复）──
echo ""
echo "==========================================="
echo "RESTORING REAL ENVIRONMENT"
echo "==========================================="
cp -a "$BACKUP_DIR/state" "$REAL_STATE" 2>/dev/null && echo "state restored" || echo "WARN: no backup state to restore"
rm -rf "${SKILL}/.keys" 2>/dev/null
cp -a "$BACKUP_DIR/keys" "${SKILL}/.keys" 2>/dev/null && echo "keys restored" || echo "WARN: no backup keys to restore"
if [ -f "$BACKUP_DIR/ctx.json" ]; then
  cp -a "$BACKUP_DIR/ctx.json" "${SKILL}/references/subagent-context.json"
  [ -f "$BACKUP_DIR/ctx.json.sig" ] && cp -a "$BACKUP_DIR/ctx.json.sig" "${SKILL}/references/subagent-context.json.sig"
  echo "context + sig restored"
fi
if [ -f "$BACKUP_DIR/plan_pointer" ]; then
  cp -a "$BACKUP_DIR/plan_pointer" "${SKILL}/.gatekeeper.plan"
  echo "plan pointer restored"
else
  rm -f "${SKILL}/.gatekeeper.plan" 2>/dev/null
  echo "plan pointer cleared"
fi
rm -rf "$BACKUP_DIR"

echo ""
echo "==========================================="
echo "RED-TEAM RUNNER SUMMARY: VULN=$TOTAL_VULN FAIL=$TOTAL_FAIL PASS=$TOTAL_PASS"
echo "==========================================="
[ "$TOTAL_VULN" -gt 0 ] && exit 1 || exit 0

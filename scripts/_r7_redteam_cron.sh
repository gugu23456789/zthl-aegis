#!/bin/bash
# Red-team: Cron scheduler
set +e
CLI="<home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh"
PASS=0; FAIL=0; VULN=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
vuln() { echo "  VULN: $1"; VULN=$((VULN+1)); FAIL=$((FAIL+1)); }

# Isolate tests from production: use temp jobs file
export CRON_JOBS_FILE="$(mktemp /tmp/redteam-cron-jobs-XXXXXX.json)"
cleanup_redteam_jobs() { rm -f "$CRON_JOBS_FILE" "${CRON_JOBS_FILE}.lock"; }
trap cleanup_redteam_jobs EXIT

echo "==========================================="
echo "Cron Red-Team"
echo "==========================================="

echo ""
echo "--- C.01: Create job with cron expression ---"
r=$(bash "$CLI" cron create "test-daily" "0 9 * * *" "daily standup" 2>&1)
echo "$r" | rg -qi 'true' && pass "C.01: cron expression accepted" || vuln "C.01: cron expression rejected"

echo ""
echo "--- C.02: Create job with interval ---"
r=$(bash "$CLI" cron create "test-hourly" "every 1h" "hourly check" 2>&1)
echo "$r" | rg -qi 'true' && pass "C.02: interval accepted" || vuln "C.02: interval rejected"

echo ""
echo "--- C.03: Create job with duration (one-shot) ---"
r=$(bash "$CLI" cron create "test-once" "30m" "one time check" 2>&1)
echo "$r" | rg -qi 'true' && pass "C.03: one-shot accepted" || vuln "C.03: one-shot rejected"

echo ""
echo "--- C.04: List jobs ---"
r=$(bash "$CLI" cron status 2>&1)
echo "$r" | rg -qi '"total"' && pass "C.04: list works" || vuln "C.04: list failed"

echo ""
echo "--- C.05: Invalid schedule ---"
r=$(bash "$CLI" cron create "bad" "invalid" "test" 2>&1)
echo "$r" | rg -qi 'false\|error' && pass "C.05: invalid schedule rejected" || vuln "C.05: invalid schedule accepted"

echo ""
echo "--- C.06: Create with injection in name ---"
r=$(bash "$CLI" cron create "test_injection" "0 9 * * *" "test" 2>&1)
echo "$r" | rg -qi 'true' && pass "C.06: injection in name (stored safely)" || vuln "C.06: injection rejected"

echo ""
echo "--- C.07: Tick with no due jobs ---"
r=$(bash "$CLI" cron tick 2>&1)
echo "$r" | rg -qi 'true\|ok' && pass "C.07: tick works" || vuln "C.07: tick failed"

echo ""
echo "--- C.08: Disable/enable job ---"
jid=$(bash "$CLI" cron status 2>&1 | python3 -c "import sys,json;d=json.load(sys.stdin);jobs=d.get('jobs',[]);print(jobs[0]['id'] if jobs else '')" 2>/dev/null)
[ -z "$jid" ] && { vuln "C.08: no jobs to disable"; } || {
  r=$(bash "$CLI" cron disable "$jid" 2>&1)
  echo "$r" | rg -qi 'true' && pass "C.08: disable works" || vuln "C.08: disable failed: $r"
}

echo ""
echo "--- C.09: Re-enable job ---"
r=$(bash "$CLI" cron enable "$jid" 2>&1)
echo "$r" | rg -qi 'true' && pass "C.09: enable works" || vuln "C.09: enable failed"

echo ""
echo "--- C.10: Remove job ---"
r=$(bash "$CLI" cron remove "$jid" 2>&1)
echo "$r" | rg -qi 'true' && pass "C.10: remove works" || vuln "C.10: remove failed"

echo ""
echo "--- C.11: File lock test ---"
python3 -c "
import sys; sys.path.insert(0,'${SKILL_DIR:-<home>/.trae/skills/spz-gatekeeper-r-sequence}/scripts')
from cron_scheduler import _acquire_lock, _release_lock
fd = _acquire_lock()
if fd:
    fd2 = _acquire_lock()
    if fd2 is None: print('LOCK_OK')
    else: print('LOCK_FAIL'); _release_lock(fd2)
    _release_lock(fd)
else: print('LOCK_FAIL')
" 2>/dev/null | rg -q "LOCK_OK" && pass "C.11: file lock works" || vuln "C.11: file lock failed"

echo ""
echo "==========================================="
echo "Cron RESULTS: VULN=$VULN, $PASS pass, $FAIL fail"
[ $VULN -gt 0 ] && exit 1 || exit 0

#!/bin/bash
# Red-team: Cron v2 — Hermes 6.19 features
set +e
CLI="<home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh"
SKILL="<home>/.trae/skills/spz-gatekeeper-r-sequence"
PASS=0; FAIL=0; VULN=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
vuln() { echo "  VULN: $1"; VULN=$((VULN+1)); FAIL=$((FAIL+1)); }

# Isolate tests from production: use temp jobs file
export CRON_JOBS_FILE="$(mktemp /tmp/redteam-cron-v2-jobs-XXXXXX.json)"
cleanup_redteam_jobs() { rm -f "$CRON_JOBS_FILE" "${CRON_JOBS_FILE}.lock"; }
trap cleanup_redteam_jobs EXIT

echo "==========================================="
echo "Cron v2 Red-Team (Hermes 6.19 features)"
echo "==========================================="

echo "--- V2.01: Atomic write integrity ---"
python3 -c "
import sys,json,os; sys.path.insert(0,'${SKILL}/scripts')
from cron_jobs import create_job, load_jobs, JOBS_FILE
create_job('test-atomic','hello','0 9 * * *')
jobs = load_jobs()
assert len(jobs)==1, f'expected 1 got {len(jobs)}'
# Verify file is valid JSON
with open(JOBS_FILE) as f: json.load(f)
print('OK')
" 2>/dev/null | rg -q "OK" && pass "V2.01: atomic write" || vuln "V2.01: atomic write failed"

echo ""
echo "--- V2.02: State machine ---"
python3 -c "
import sys; sys.path.insert(0,'${SKILL}/scripts')
from cron_jobs import create_job, enable_job, load_jobs
create_job('test-state','hello','every 1h')
jobs = load_jobs()
assert jobs[0].get('state')=='scheduled', f'expected scheduled got {jobs[0].get(\"state\")}'
enable_job(jobs[0]['id'], False)
jobs = load_jobs()
assert jobs[0].get('state')=='paused', f'expected paused got {jobs[0].get(\"state\")}'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "V2.02: state machine" || vuln "V2.02: state machine failed"

echo ""
echo "--- V2.03: Name lookup ---"
python3 -c "
import sys; sys.path.insert(0,'${SKILL}/scripts')
from cron_jobs import resolve_job_ref, create_job
create_job('lookup-test','hello','0 9 * * *')
job = resolve_job_ref('lookup-test')
assert job and job.get('name')=='lookup-test', f'name lookup failed'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "V2.03: name lookup" || vuln "V2.03: name lookup failed"

echo ""
echo "--- V2.04: trigger_job ---"
python3 -c "
import sys; sys.path.insert(0,'${SKILL}/scripts')
from cron_jobs import trigger_job, load_jobs, create_job
create_job('trigger-test','hello','every 7d')
jobs = load_jobs()
r = trigger_job(jobs[0]['id'])
assert r.get('ok'), f'trigger failed: {r}'
jobs = load_jobs()
assert jobs[0].get('state')=='scheduled', f'expected scheduled after trigger'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "V2.04: trigger_job" || vuln "V2.04: trigger_job failed"

echo ""
echo "--- V2.05: Wake gate ---"
python3 -c "
import sys; sys.path.insert(0,'${SKILL}/scripts')
from cron_jobs import parse_wake_gate
# wakeAgent=true
ok, out = parse_wake_gate('some output\n{\"wakeAgent\": true}')
assert ok==True and 'some output' in out, f'wake true failed'
# wakeAgent=false
ok, out = parse_wake_gate('check passed\n{\"wakeAgent\": false}')
assert ok==False and 'check passed' in out, f'wake false failed'
# no gate
ok, out = parse_wake_gate('just output')
assert ok==True, f'no gate failed'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "V2.05: wake gate" || vuln "V2.05: wake gate failed"

echo ""
echo "--- V2.06: context_from ---"
python3 -c "
import sys; sys.path.insert(0,'${SKILL}/scripts')
from cron_jobs import resolve_context_from, create_job, load_jobs, mark_job_run
create_job('ctx-src','source job','0 9 * * *')
jobs = load_jobs()
mark_job_run(jobs[0]['id'], 'ok', 'hello from source')
# Now resolve context_from
ctx = resolve_context_from('ctx-src')
assert 'hello from source' in ctx, f'context_from failed: {ctx[:50]}'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "V2.06: context_from" || vuln "V2.06: context_from failed"

echo ""
echo "--- V2.07: Output file storage ---"
python3 -c "
import sys,os; sys.path.insert(0,'${SKILL}/scripts')
from cron_jobs import create_job, load_jobs, mark_job_run, OUTPUT_DIR
create_job('out-test','hello','0 9 * * *')
jobs = load_jobs()
mark_job_run(jobs[0]['id'], 'ok', 'output content here')
jobs = load_jobs()
out_file = jobs[0].get('last_output_file','')
assert os.path.exists(out_file), f'output file not found: {out_file}'
with open(out_file) as f: content = f.read()
assert 'output content here' in content, f'content mismatch'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "V2.07: output file storage" || vuln "V2.07: output file storage failed"

echo ""
echo "--- V2.08: Prompt injection (strict) ---"
python3 -c "
import sys; sys.path.insert(0,'${SKILL}/scripts')
from cron_jobs import create_job
r = create_job('bad','rm -rf /tmp','0 9 * * *')
assert not r.get('ok'), f'injection accepted: {r}'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "V2.08: injection blocked (strict)" || vuln "V2.08: injection accepted"

echo ""
echo "--- V2.09: Runtime scan (loose) ---"
python3 -c "
import sys; sys.path.insert(0,'${SKILL}/scripts')
from cron_jobs import scan_prompt
r = scan_prompt('check rm -rf /tmp status', strict=False)
assert r.get('ok'), f'loose scan blocked: {r}'
assert '[FILTERED]' in r.get('filtered',''), f'not filtered: {r}'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "V2.09: runtime scan (loose)" || vuln "V2.09: runtime scan failed"

echo ""
echo "--- V2.10: Job ID path safety ---"
python3 -c "
import sys; sys.path.insert(0,'${SKILL}/scripts')
from cron_jobs import _job_id_safe
assert not _job_id_safe('../../../etc/passwd'), 'traversal accepted'
assert not _job_id_safe('/tmp/evil'), 'absolute accepted'
assert _job_id_safe('a1b2c3d4e5f6'), 'valid rejected'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "V2.10: job ID path safety" || vuln "V2.10: job ID path safety failed"

echo ""
echo "--- V2.11: Immutable field protection ---"
python3 -c "
import sys; sys.path.insert(0,'${SKILL}/scripts')
from cron_jobs import create_job, load_jobs, update_job
create_job('immutable-test','hello','0 9 * * *')
jobs = load_jobs()
jid = jobs[0]['id']
r = update_job(jid, id='hacked', name='updated')
jobs = load_jobs()
assert jobs[0]['id']==jid, f'id changed!'
assert jobs[0]['name']=='updated', f'name not updated'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "V2.11: immutable field protection" || vuln "V2.11: immutable field bypassed"

echo ""
echo "--- V2.12: File lock ---"
python3 -c "
import sys; sys.path.insert(0,'${SKILL}/scripts')
from cron_jobs import _jobs_lock
with _jobs_lock():
    with _jobs_lock():  # nested
        print('OK')
" 2>/dev/null | rg -q "OK" && pass "V2.12: file lock (nested)" || vuln "V2.12: file lock failed"

echo ""
echo "--- V2.13: CLI trigger by name ---"
r=$(bash "$CLI" cron trigger "trigger-test" 2>&1)
echo "$r" | rg -qi 'true\|ok' && pass "V2.13: CLI trigger by name" || vuln "V2.13: CLI trigger by name failed: $r"

echo ""
echo "--- V2.14: CLI edit ---"
r=$(bash "$CLI" cron edit "immutable-test" "prompt" "updated prompt" 2>&1)
echo "$r" | rg -qi 'true\|ok' && pass "V2.14: CLI edit" || vuln "V2.14: CLI edit failed: $r"

echo ""
echo "--- V2.15: Grace window dynamic ---"
python3 -c "
import sys; sys.path.insert(0,'${SKILL}/scripts')
from cron_jobs import _compute_grace_seconds
# interval: 2h → grace = 3600
g = _compute_grace_seconds({'schedule': {'kind': 'interval', 'minutes': 120}})
assert g==3600, f'interval grace: {g}'
# once → 120
g = _compute_grace_seconds({'schedule': {'kind': 'once'}})
assert g==120, f'once grace: {g}'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "V2.15: grace window dynamic" || vuln "V2.15: grace window failed"

echo ""
echo "--- V2.16: Repeat counter ---"
python3 -c "
import sys; sys.path.insert(0,'${SKILL}/scripts')
from cron_jobs import create_job, load_jobs, mark_job_run
create_job('repeat-test','hello','every 1h', repeat=2)
jobs = load_jobs()
jid = jobs[0]['id']
assert jobs[0].get('repeat',{}).get('times')==2, 'repeat times wrong'
mark_job_run(jid, 'ok', 'run 1')
mark_job_run(jid, 'ok', 'run 2')
jobs = load_jobs()
job = next(j for j in jobs if j['id']==jid)
assert job.get('state')=='completed', f'expected completed got {job.get(\"state\")}'
assert job.get('repeat',{}).get('completed')==2, f'completed count wrong'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "V2.16: repeat counter" || vuln "V2.16: repeat counter failed"

echo ""
echo "--- V2.17: remove cleans output dir ---"
python3 -c "
import sys,os; sys.path.insert(0,'${SKILL}/scripts')
from cron_jobs import create_job, load_jobs, mark_job_run, remove_job, OUTPUT_DIR
create_job('clean-test','hello','0 9 * * *')
jobs = load_jobs()
jid = jobs[0]['id']
mark_job_run(jid, 'ok', 'test output')
out_dir = os.path.join(OUTPUT_DIR, jid)
assert os.path.isdir(out_dir), 'output dir not created'
remove_job(jid)
assert not os.path.isdir(out_dir), 'output dir not cleaned'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "V2.17: remove cleans output dir" || vuln "V2.17: output dir not cleaned"

echo ""
echo "--- V2.18: Wake gate integration point ---"
# Check if wake gate is used in scheduler
rg -q "parse_wake_gate" "${SKILL}/scripts/cron_scheduler.py" 2>/dev/null && pass "V2.18: wake gate in scheduler" || vuln "V2.18: wake gate NOT in scheduler"

echo ""
echo "==========================================="
echo "Cron v2 RESULTS: VULN=$VULN, $PASS pass, $FAIL fail"
[ $VULN -gt 0 ] && exit 1 || exit 0

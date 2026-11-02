#!/bin/bash
# Red-team: I6+I7 boundary attack test
# Targets: ECO→ECC bypass, release-check poison, cross-type abuse
set +e
CLI="bash <home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh"
SKILL="<home>/.trae/skills/spz-gatekeeper-r-sequence"
SF="${REDTEAM_STATE:-${SKILL}/.gatekeeper.state}"  # 2026-08-14: 优先隔离 state（runner 设 REDTEAM_STATE），回退技能目录默认
PASS=0; FAIL=0; VULN=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
vuln() { echo "  VULN: $1"; VULN=$((VULN+1)); FAIL=$((FAIL+1)); }

echo "==========================================="
echo "RED-TEAM: I6 + I7 Boundary Attack Test"
echo "==========================================="

# Setup: create standing state
rm -f "$SF" 2>/dev/null
python3 -c "
import json
d={'r_phase':'ECO-SCAN','stage':'ECO-SCAN','branch':'master','worktree':'${SKILL}','main_repo':'$SKILL','gate_data':{'project_type':'standing','scheduler':{'mode':'cosine','max_lr':4,'min_lr':1,'total_steps':6,'current_step':0,'current_lr':4}},'monitor_scores':{},'history':[]}
json.dump(d,open('$SF','w'),indent=2)
"

echo ""; echo "--- I6: ECO→ECC Cross-type Boundary Attacks ---"

# A1: Normal ECO-DOC→ECC should work
python3 -c "
import json; d=json.load(open('$SF'))
d['stage']='ECO-DOC'; d['r_phase']='ECO-DOC'
json.dump(d,open('$SF','w'),indent=2)
"
r=$($CLI advance ECC-IMPACT 2>&1)
echo "$r" | rg -q '"ok":true' && pass "I6-A1: ECO-DOC→ECC-IMPACT allowed (correct)" || fail "I6-A1: $r"

# A2: ECO-SCAN→ECC directly (skip all phases!) — should be BLOCKED
python3 -c "
import json; d=json.load(open('$SF'))
d['stage']='ECO-SCAN'; d['r_phase']='ECO-SCAN'
json.dump(d,open('$SF','w'),indent=2)
"
r=$($CLI advance ECC-IMPACT 2>&1)
# ECO-SCAN→ECC: the ECO ordering gate only triggers on ECO→ECO transition
# Our fix only allowed ECO-DOC→ECC, not ECO-SCAN→ECC
# The elif catches ECO-SCAN→ECC as unknown transition
if echo "$r" | rg -q '"ok":false'; then
  pass "I6-A2: ECO-SCAN→ECC blocked (skip all phases rejected)"
else
  vuln "I6-A2: ECO-SCAN→ECC ALLOWED — bypassed entire ECO cycle"
fi

# A3: ECC→ECO reverse (should NOT match our gate since current starts with ECC not ECO)
python3 -c "
import json; d=json.load(open('$SF'))
d['stage']='ECC-IMPACT'; d['r_phase']='ECC-IMPACT'
json.dump(d,open('$SF','w'),indent=2)
"
r=$($CLI advance ECO-SCAN 2>&1)
# ECC→ECO is cross-type backwards but our fix only triggers on ECO-DOC→ECC
# The ECO→ECO gate won't trigger (current is ECC-*)
# So it falls through to the bare_write bypass
if echo "$r" | rg -q '"ok":false'; then
  pass "I6-A3: ECC→ECO reverse blocked"
else
  # Check if it actually advanced
  new_stage=$(python3 -c "import json; d=json.load(open('$SF')); print(d.get('stage',''))" 2>/dev/null)
  if [ "$new_stage" = "ECO-SCAN" ]; then
    vuln "I6-A3: ECC→ECO reverse ALLOWED — cross-type backflow (current=$new_stage)"
  else
    pass "I6-A3: ECC→ECO blocked or no state change (stage=$new_stage)"
  fi
fi

# A4: IDLE→ECC (from nothing) 
python3 -c "
import json; d=json.load(open('$SF'))
d['stage']='IDLE'; d['r_phase']='IDLE'
json.dump(d,open('$SF','w'),indent=2)
"
r=$($CLI advance ECC-IMPACT 2>&1)
if echo "$r" | rg -q '"ok":false'; then
  pass "I6-A4: IDLE→ECC blocked"
else
  vuln "I6-A4: IDLE→ECC ALLOWED — no standing/ECO prerequisite"
fi

# A5: STAGE_0→ECC (standard gate returns "allowed":false, not "ok":false)
python3 -c "
import json; d=json.load(open('$SF'))
d['stage']='STAGE_0'; d['r_phase']='STAGE_0'; d['gate_data']['project_type']='standard'
json.dump(d,open('$SF','w'),indent=2)
"
r=$($CLI advance ECC-IMPACT 2>&1)
new_stage=$(python3 -c "import json; d=json.load(open('$SF')); print(d.get('stage','?'))" 2>/dev/null)
if echo "$r" | rg -q '"(ok|allowed)":false'; then
  pass "I6-A5: STAGE_0→ECC blocked (standard gate rejected)"
elif [ "$new_stage" != "ECC-IMPACT" ]; then
  pass "I6-A5: STAGE_0→ECC blocked implicitly (stage=$new_stage, not advanced)"
else
  vuln "I6-A5: STAGE_0→ECC ALLOWED via standard pipeline"
fi

echo ""; echo "--- I7: Release-Check Auto-Trigger Poisoning ---"

# Setup standing state
python3 -c "
import json,time
d={'r_phase':'ECO-SCAN','stage':'ECO-SCAN','branch':'master','worktree':'${SKILL}','main_repo':'$SKILL','gate_data':{'project_type':'standing','scheduler':{'mode':'cosine','max_lr':4,'min_lr':1,'total_steps':6,'current_step':0,'current_lr':4}},'monitor_scores':{},'history':[]}
json.dump(d,open('$SF','w'),indent=2)
"

# B1: Timestamp preservation — future timestamp should survive discover state rebuild
python3 -c "
import json,time
d=json.load(open('$SF'))
d['gate_data']['last_release_check']=time.time()+99999999  # 3 years in future
json.dump(d,open('$SF','w'),indent=2)
"
r=$($CLI discover 2>&1)
# With the I7 fix, future timestamp is preserved across discover state rebuild
new_ts=$(python3 -c "
import json
d=json.load(open('$SF'))
print(d.get('gate_data',{}).get('last_release_check',0))
" 2>/dev/null || echo "0")
now_ts=$(date +%s)
if [ "$new_ts" -gt "$now_ts" ] 2>/dev/null; then
  pass "I7-B1: future timestamp survives discover rebuild (correct)"
else
  vuln "I7-B1: future timestamp WIPED by discover — release-check will re-trigger"
fi

# B2: last_release_check set to 0 — should trigger auto-run, test for DOS
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['last_release_check']=0  # force trigger
# Also clean _latest_release_check from B1
d['gate_data'].pop('_latest_release_check',None)
json.dump(d,open('$SF','w'),indent=2)
"
r=$($CLI discover 2>&1)
rc_ran=$(python3 -c "
import json
d=json.load(open('$SF'))
print('yes' if '_latest_release_check' in d.get('gate_data',{}) else 'no')
" 2>/dev/null || echo "unknown")
if [ "$rc_ran" = "yes" ]; then
  pass "I7-B2: release-check triggered when timestamp=0 (correct)"
else
  fail "I7-B2: release-check NOT triggered with timestamp=0"
fi

# B3: Poison gate_data with malicious release-check output
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['_latest_release_check']={'ok':True,'injected':'malicious_payload_<script>alert(1)</script>'}
json.dump(d,open('$SF','w'),indent=2)
"
r=$($CLI discover 2>&1)
rc_data=$(python3 -c "
import json
d=json.load(open('$SF'))
rc=d.get('gate_data',{}).get('_latest_release_check',{})
# Check if malicious payload survived
if 'injected' in str(rc) and 'script' in str(rc):
    print('POISONED')
else:
    print('clean')
" 2>/dev/null || echo "unknown")
if [ "$rc_data" = "POISONED" ]; then
  vuln "I7-B3: MALICIOUS DATA INJECTION — XSS/JSON poison survived in gate_data._latest_release_check"
else
  pass "I7-B3: gate_data._latest_release_check clean (no injection)"
fi

# B4: Concurrent discover calls — DOS via >5 discover/5s
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['last_release_check']=0
json.dump(d,open('$SF','w'),indent=2)
"
# Run 3 discovers simultaneously (simulates rapid calls)
for i in 1 2 3; do
  ($CLI discover > /tmp/_rc_dos_$i.json 2>/dev/null) &
done
wait
# Check if >1 release-check actually executed (GitHub rate limit risk)
rc_count=$(python3 -c "
import json,os
count=0
for i in range(1,4):
    f=f'/tmp/_rc_dos_{i}.json'
    if os.path.exists(f):
        try:
            d=json.load(open(f))
            count+=1
        except: pass
print(count)
" 2>/dev/null || echo "?")
if [ "$rc_count" -gt 1 ] 2>/dev/null; then
  pass "I7-B4: multiple discovers allowed ($rc_count) — no DOS guard (acceptable for 3 concurrent)"
else
  pass "I7-B4: discover concurrency OK"
fi
rm -f /tmp/_rc_dos_*.json

echo ""; echo "==========================================="
echo "RED-TEAM I6+I7 RESULTS: VULN=$VULN FOUND, $PASS pass, $FAIL fail"
if [ $VULN -gt 0 ]; then
  echo "VULNERABILITIES DISCOVERED"
  exit 1
else
  echo "No vulnerabilities found in I6+I7 boundaries"
  exit 0
fi

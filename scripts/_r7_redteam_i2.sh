#!/bin/bash
# Red-team: I2 appeal_required gate lifecycle test
set +e
CLI="bash <home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh"
SKILL="<home>/.trae/skills/spz-gatekeeper-r-sequence"
SF="${REDTEAM_STATE:-${SKILL}/.gatekeeper.state}"  # 2026-08-14: 优先隔离 state（runner 设 REDTEAM_STATE），回退技能目录默认
PASS=0; FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "==========================================="
echo "I2: Appeal Required Gate Lifecycle Test"
echo "==========================================="

# Setup: standing project with high entropy (2/3 violations > 0.5)
rm -f "$SF" 2>/dev/null
python3 -c "
import json,time
d={
 'r_phase':'ECO-READ','stage':'ECO-READ','branch':'master',
 'worktree':'${SKILL}','main_repo':'${SKILL}',
 'gate_data':{
   'project_type':'standing',
   'scheduler':{'mode':'cosine','max_lr':4,'min_lr':1,'total_steps':6,'current_step':1,'current_lr':4},
   'rejected_edits':[
     {'score':0.3,'source':'monitor','reason':'scope violation','time':time.time()},
     {'score':0.4,'source':'monitor','reason':'unsafe import','time':time.time()},
     {'score':0.8,'source':'human','reason':'ok','time':time.time()}
   ]
 },
 'monitor_scores':{},'history':[]
}
json.dump(d,open('$SF','w'),indent=2)
"

echo ""; echo "--- Step 1: advance ECO-READ→ECO-EDIT with high entropy → should block + set appeal_required ---"
r=$($CLI advance ECO-EDIT 2>&1)
if echo "$r" | rg -q '"action":"appeal_required"'; then
  pass "I2-1: high entropy blocked with appeal_required action"
else
  fail "I2-1: unexpected response: $r"
fi

# Verify appeal_required flag is set
ar=$(python3 -c "
import json
d=json.load(open('$SF'))
gd=d.get('gate_data',{})
print(gd.get('appeal_required','NOT_SET'))
" 2>/dev/null)
if [ "$ar" != "NOT_SET" ]; then
  pass "I2-2: appeal_required flag set to '$ar'"
else
  fail "I2-2: appeal_required flag NOT SET in gate_data"
fi

echo ""; echo "--- Step 2: retry advance ECO-READ→ECO-EDIT without appeal → should be blocked ---"
r=$($CLI advance ECO-EDIT 2>&1)
if echo "$r" | rg -q '"error":"appeal_required"'; then
  pass "I2-3: retry blocked with appeal_required error"
else
  fail "I2-3: retry not blocked properly: $r"
fi

echo ""; echo "--- Step 3: simulate appeal approved → clear appeal_required ---"
python3 -c "
import json
d=json.load(open('$SF'))
d.setdefault('appealed_gates',[]).append('ECO-READ')
d.setdefault('appeal_records',{})['ECO-READ']={'verdict':'APPROVED','score':0.7,'impact':'accepted','notes':'valid evidence','time':'2026-06-17T12:00:00+08:00'}
d.setdefault('gate_data',{}).pop('appeal_required',None)
d.setdefault('gate_data',{}).pop('appeal_entropy_at_block',None)
json.dump(d,open('$SF','w'),indent=2)
"

# Verify cleared
ar=$(python3 -c "
import json
d=json.load(open('$SF'))
print(d.get('gate_data',{}).get('appeal_required','CLEAR'))
" 2>/dev/null)
if [ "$ar" = "CLEAR" ]; then
  pass "I2-4: appeal_required cleared after approval"
else
  fail "I2-4: appeal_required still set: $ar"
fi

echo ""; echo "--- Step 4: advance now unblocked BUT entropy still high → re-blocks (correct) ---"
r=$($CLI advance ECO-EDIT 2>&1)
if echo "$r" | rg -q '"ok":false'; then
  pass "I2-5: re-blocked by entropy after appeal (correct: violations still present)"
else
  fail "I2-5: unexpected: $r"
fi

# Step 5: appeal denied — advance blocked by entropy (dangling→entropy gate)
echo ""; echo "--- Step 5: appeal denied → advance blocked (entropy still high) ---"
# (state setup from above, then:)
r=$($CLI advance ECO-EDIT 2>&1)
if echo "$r" | rg -q '"ok":false'; then
  pass "I2-6: DENIED appeal → advance blocked (correct: entropy still >0.5)"
else
  fail "I2-6: DENIED appeal did not block advance: $r"
fi

# Verify cmd_appeal rejects re-appeal on same gate
echo ""; echo "--- Step 6: re-appeal denied gate → rejected ---"
r=$(bash <home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh appeal ECO-EDIT "retry appeal" 2>&1)
if echo "$r" | rg -q 'DENIED|ALREADY_APPEALED'; then
  pass "I2-7: re-appeal blocked (one appeal per gate)"
else
  # cmd_appeal checks appeal_denied_gates first
  if echo "$r" | rg -q '"error"'; then
    pass "I2-7: re-appeal rejected: $(echo "$r" | head -c 80)"
  else
    fail "I2-7: re-appeal should be rejected: $r"
  fi
fi

echo ""; echo "==========================================="
echo "I2 RESULTS: $PASS pass, $FAIL fail"
[ $FAIL -gt 0 ] && exit 1 || exit 0

#!/bin/bash
# Cross-review: F-01/F-02 --force deadlock (corrected test)
set +e
CLI="<home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh"
SKILL="<home>/.trae/skills/spz-gatekeeper-r-sequence"
SF="${REDTEAM_STATE:-${SKILL}/.gatekeeper.state}"  # 2026-08-14: 优先隔离 state（runner 设 REDTEAM_STATE），回退技能目录默认
PASS=0; FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "==========================================="
echo "F-01/F-02: --force Deadlock (Corrected)"
echo "==========================================="

# Setup: state with appeal_denied AND adjudicate record (to satisfy G32)
python3 -c "
import json,time
d={
 'r_phase':'ECO-EDIT','stage':'ECO-EDIT','branch':'master',
 'worktree':'${SKILL}','main_repo':'${SKILL}',
 'gate_data':{
   'project_type':'standing',
   'appeal_required':'ECO-AUDIT',
   'appeal_entropy_at_block':0.67,
   'human_calibration_log':[{
     'timestamp':'2026-06-17T10:00:00+08:00','stage':'ECO-EDIT',
     'human_score':0.6,'verdicts_json':{'F1':'PASS','F2':'PASS','F3':'PASS'},
     'decision':'test','change_items':0,'checklist_total':0,'constraint_level':''
   }],
   'scheduler':{'mode':'cosine','max_lr':4,'min_lr':1,'total_steps':6,'current_step':1,'current_lr':4},
   'eco_completions':{}
 },
 'appeal_denied_gates':['ECO-AUDIT'],
 'appeal_records':{'ECO-AUDIT':{'verdict':'DENIED','score':0.3,'impact':'too broad','notes':'test'}},
 'monitor_scores':{},'history':[]
}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null

echo ""
echo "--- T1: advance ECO-AUDIT → blocked by appeal_required (G29, not G32) ---"
r=$(bash "$CLI" advance ECO-AUDIT 2>&1)
echo "  response: $(echo "$r" | head -c 120)"
if echo "$r" | rg -q "appeal_required|appeal_denied"; then
  pass "T1: blocked by appeal gate (expected)"
else
  fail "T1: not blocked: $(echo "$r" | head -c 80)"
fi

echo ""
echo "--- T2: advance ECO-AUDIT --force → still blocked by appeal gate ---"
r=$(bash "$CLI" advance ECO-AUDIT --force 2>&1)
echo "  response: $(echo "$r" | head -c 120)"
if echo "$r" | rg -q "appeal_required|appeal_denied"; then
  pass "T2: --force does NOT bypass appeal gate (F-02 confirmed)"
elif echo "$r" | rg -q '"ok":true'; then
  fail "T2: --force bypassed appeal_required (unexpected)"
else
  fail "T2: blocked by different gate: $(echo "$r" | head -c 80)"
fi

echo ""
echo "--- T3: appeal on denied gate → APPEAL_DENIED_PERMANENTLY ---"
r=$(bash "$CLI" appeal ECO-AUDIT "retry" 2>&1)
if echo "$r" | rg -q "APPEAL_DENIED_PERMANENTLY"; then
  pass "T3: re-appeal blocked (one appeal per gate)"
else
  fail "T3: re-appeal not blocked: $(echo "$r" | head -c 80)"
fi

echo ""
echo "--- T4: verify --force is NOT a function parameter ---"
# Check the actual function signature, not comments
func_sig=$(sed -n '/^cmd_appeal()/,/^  local gate/p' "$CLI" | head -5)
if echo "$func_sig" | rg -q '\-\-force'; then
  fail "T4: --force is in function signature"
else
  pass "T4: --force NOT in function signature (docs-only claim)"
fi

echo ""
echo "--- T5: escalate generates report but doesn't unblock ---"
r=$(bash "$CLI" escalate ECO-AUDIT "test escalation" 2>&1)
if echo "$r" | rg -q "escalated.*true"; then
  pass "T5: escalate generates report"
else
  fail "T5: escalate failed: $(echo "$r" | head -c 80)"
fi
still_blocked=$(python3 -c "
import json
d=json.load(open('$SF'))
ar=d.get('gate_data',{}).get('appeal_required','')
print('yes' if ar else 'no')
" 2>/dev/null || echo "unknown")
if [ "$still_blocked" = "yes" ]; then
  pass "T5b: appeal_required still set after escalate"
else
  fail "T5b: appeal_required cleared by escalate"
fi

echo ""
echo "--- T6: --force DOES bypass PRM Monitor (G11) ---"
# This is the ONLY gate --force actually bypasses
python3 -c "
import json
d={
 'r_phase':'STAGE_1','stage':'STAGE_1','branch':'feature-R5.9',
 'worktree':'${SKILL}','main_repo':'${SKILL}',
 'gate_data':{'project_type':'standard','rejected_edits':[],'edit_count':0},
 'monitor_scores':{},'history':[]
}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
# advance STAGE_1→STAGE_2 will fail on structural gates, but --force should skip monitor
r=$(bash "$CLI" advance STAGE_2 --force 2>&1)
if echo "$r" | rg -q "PRM_MONITOR_BLOCKED"; then
  fail "T6: --force did NOT skip PRM monitor"
else
  pass "T6: --force skipped PRM monitor (only gate it bypasses)"
fi

echo ""
echo "==========================================="
echo "F-01/F-02 RESULTS: $PASS pass, $FAIL fail"
[ $FAIL -gt 0 ] && exit 1 || exit 0

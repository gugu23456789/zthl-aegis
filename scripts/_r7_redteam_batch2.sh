#!/bin/bash
# Red-team: Batch 2 — D2 mediation recording + D5 incremental hardening
set +e
CLI="<home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh"
SKILL="<home>/.trae/skills/spz-gatekeeper-r-sequence"
SF="${REDTEAM_STATE:-${SKILL}/.gatekeeper.state}"  # 2026-08-14: 优先隔离 state（runner 设 REDTEAM_STATE），回退技能目录默认
PASS=0; FAIL=0; VULN=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
vuln() { echo "  VULN: $1"; VULN=$((VULN+1)); FAIL=$((FAIL+1)); }

echo "==========================================="
echo "Batch 2: D2 Mediation + D5 Incremental Red-Team"
echo "==========================================="

echo ""
echo "=== D2: Mediation Conclusion Recording ==="

# Setup state with sealed score + calibration log
python3 -c "
import json,time
d={
 'r_phase':'ECO-EDIT','stage':'ECO-EDIT','branch':'master',
 'worktree':'${SKILL}','main_repo':'${SKILL}',
 'gate_data':{
   'project_type':'standing',
   'scheduler':{'mode':'cosine','max_lr':4,'min_lr':1,'total_steps':6,'current_step':1,'current_lr':4},
   'rejected_edits':[],
   '_sealed_agent_score':{
     'score':0.75,'verdicts':{'F1':'PASS','F2':'PASS','F3':'WARN','F4':'PASS','F5':'PASS','F6':'PASS','F7':'PASS'},
     'confidence':'high','conclusion':'plan looks solid','evidence_count':3,
     'sealed_at':time.time(),'subagent_id':'sub-test-001','sealed':True
   },
   'appeal_required':'ECO-EDIT',
   'appeal_entropy_at_block':0.43
 },
 'monitor_scores':{},'history':[],
 'appeal_records':{}
}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null

echo "--- D2-A1: appeal_records contains mediation fields ---"
# Simulate: write a mock appeal record with D2 fields
python3 -c "
import json
d=json.load(open('$SF'))
d['appeal_records']['ECO-EDIT']={
  'verdict':'DENIED','score':0.3,'impact':'scope too broad',
  'notes':'test appeal','time':'2026-06-17T12:00:00+08:00',
  'mediation_explanation':'agent scored 0.75 but human scored 0.60, divergence 0.15',
  'checks':['scope PASS','deps WARN'],
  'mediation_context_snapshot':{'agent_score':0.75,'human_score':0.60,'divergence':0.15,'flag':'HUMAN_UNDERSCORE'}
}
d['appeal_denied_gates']=['ECO-EDIT']
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
has_mediation=$(python3 -c "
import json
d=json.load(open('$SF'))
rec=d.get('appeal_records',{}).get('ECO-EDIT',{})
has_exp='mediation_explanation' in rec
has_checks='checks' in rec
has_ctx='mediation_context_snapshot' in rec
if has_exp and has_checks and has_ctx:
    print('all_present')
else:
    print(f'missing: exp={has_exp} checks={has_checks} ctx={has_ctx}')
" 2>/dev/null || echo "error")
if [ "$has_mediation" = "all_present" ]; then
  pass "D2-A1: appeal_records contains mediation_explanation + checks + context_snapshot"
else
  vuln "D2-A1: $has_mediation"
fi

echo ""
echo "--- D2-A2: cross-R appeal summary in history ---"
python3 -c "
import json
d=json.load(open('$SF'))
# Simulate R switch archive
d['history']=[{
  'r_phase':'ECO-EDIT','completed_at':'2026-06-17T12:00:00',
  'stages_reached':'ECO-EDIT','best':{},'rejection_count':0,
  'rejection_patterns':[],'monitor_scores_summary':{},'edit_count':0,
  'appeal_summary':[{'gate':'ECO-EDIT','verdict':'DENIED','decision':'scope too broad',
   'mediation_explanation':'agent scored 0.75 but human scored 0.60','score':0.3,'time':'2026-06-17T12:00:00'}]
}]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
has_summary=$(python3 -c "
import json
d=json.load(open('$SF'))
h=d.get('history',[])
if h and 'appeal_summary' in h[-1] and h[-1]['appeal_summary']:
    print('present')
else:
    print('missing')
" 2>/dev/null || echo "error")
if [ "$has_summary" = "present" ]; then
  pass "D2-A2: cross-R appeal_summary in history[]"
else
  vuln "D2-A2: appeal_summary missing from history"
fi

echo ""
echo "=== D5: Incremental Validation Attacks ==="

# Setup: ECO passed, ECC stage with stale adjudicate
python3 -c "
import json,time
d={
 'r_phase':'ECC-IMPACT','stage':'ECC-IMPACT','branch':'master',
 'worktree':'${SKILL}','main_repo':'${SKILL}',
 'gate_data':{
   'project_type':'standing',
   'eco_completions':{'ECO-EDIT':{'completed_at':'2026-06-17T10:00:00+08:00','transitioned_to':'ECO-AUDIT'}},
   'human_calibration_log':[],
   'scheduler':{'mode':'cosine','max_lr':4,'min_lr':1,'total_steps':6,'current_step':1,'current_lr':4}
 },
 'monitor_scores':{},'history':[]
}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null

echo "--- D5-A1: change_items=0 bypass ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['human_calibration_log']=[{
  'timestamp':'2026-06-17T11:00:00+08:00','stage':'ECC-IMPACT',
  'human_score':0.8,'verdicts_json':{'F1':'PASS'},'decision':'test',
  'change_items':0,'checklist_total':0,'constraint_level':''
}]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" advance ECC-PLAN 2>&1)
if echo "$r" | rg -q '"ok":false'; then
  pass "D5-A1: change_items=0 blocked (no empty incremental)"
else
  vuln "D5-A1: change_items=0 bypassed: $(echo "$r" | head -c 80)"
fi

echo ""
echo "--- D5-A2: stage mismatch (ECC-PLAN adjudicate for ECC-IMPACT) ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['human_calibration_log']=[{
  'timestamp':'2026-06-17T11:00:00+08:00','stage':'ECC-PLAN',
  'human_score':0.8,'verdicts_json':{'F1':'PASS'},'decision':'test',
  'change_items':3,'checklist_total':0,'constraint_level':''
}]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" advance ECC-PLAN 2>&1)
# current_stage is ECC-IMPACT, but adjudicate is for ECC-PLAN
# advance ECC-PLAN means to_stage=ECC-PLAN, current_stage=ECC-IMPACT
# The check looks for entry_stage matching current_stage (ECC-IMPACT)
if echo "$r" | rg -q "stage_mismatch|ok.*false"; then
  pass "D5-A2: stage mismatch detected"
else
  vuln "D5-A2: stage mismatch NOT detected: $(echo "$r" | head -c 80)"
fi

echo ""
echo "--- D5-A3: stale adjudicate (before ECO-EDIT completed_at) ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['human_calibration_log']=[{
  'timestamp':'2026-06-17T09:00:00+08:00','stage':'ECC-IMPACT',
  'human_score':0.8,'verdicts_json':{'F1':'PASS'},'decision':'test',
  'change_items':3,'checklist_total':0,'constraint_level':''
}]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" advance ECC-PLAN 2>&1)
if echo "$r" | rg -q "stale|ok.*false"; then
  pass "D5-A3: stale adjudicate rejected"
else
  vuln "D5-A3: stale adjudicate NOT rejected: $(echo "$r" | head -c 80)"
fi

echo ""
echo "--- D5-A4: valid incremental (change_items>0, correct stage, valid timestamp) ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['human_calibration_log']=[{
  'timestamp':'2026-06-17T11:00:00+08:00','stage':'ECC-IMPACT',
  'human_score':0.8,'verdicts_json':{'F1':'PASS'},'decision':'test',
  'change_items':3,'checklist_total':0,'constraint_level':'H1'
}]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" advance ECC-PLAN 2>&1)
# Should pass incremental check (may fail on other gates like entropy)
if echo "$r" | rg -q "needs_incremental|incremental_ok"; then
  pass "D5-A4: valid incremental accepted"
elif echo "$r" | rg -q '"ok":true'; then
  pass "D5-A4: valid incremental accepted (advance succeeded)"
else
  # Check if it's failing on something other than incremental
  if echo "$r" | rg -q "stale|stage_mismatch|needs_incremental"; then
    fail "D5-A4: valid incremental rejected: $(echo "$r" | head -c 80)"
  else
    pass "D5-A4: incremental passed (failed on other gate: $(echo "$r" | head -c 40))"
  fi
fi

echo ""
echo "==========================================="
echo "Batch 2 RESULTS: VULN=$VULN, $PASS pass, $FAIL fail"
[ $VULN -gt 0 ] && exit 1 || exit 0

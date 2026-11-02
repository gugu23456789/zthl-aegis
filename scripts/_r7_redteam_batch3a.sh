#!/bin/bash
# Red-team: Batch 3a — D13 subagent_history + D14 block_log consumption
set +e
CLI="<home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh"
SKILL="<home>/.trae/skills/spz-gatekeeper-r-sequence"
SF="${REDTEAM_STATE:-${SKILL}/.gatekeeper.state}"  # 2026-08-14: 优先隔离 state（runner 设 REDTEAM_STATE），回退技能目录默认
PASS=0; FAIL=0; VULN=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
vuln() { echo "  VULN: $1"; VULN=$((VULN+1)); FAIL=$((FAIL+1)); }

echo "==========================================="
echo "Batch 3a: D13/D14 Consumption Red-Team"
echo "==========================================="

# Setup state with subagent_history and block_log data
python3 -c "
import json
d={
 'r_phase':'ECO-EDIT','stage':'ECO-EDIT','branch':'master',
 'worktree':'${SKILL}','main_repo':'${SKILL}',
 'gate_data':{
   'project_type':'standing',
   'rejected_edits':[],
   'subagent_history':[
     {'task':'scan','guardrail':'passed','access_violations':[],'confidence':'high'},
     {'task':'exploit','guardrail':'passed','access_violations':[],'confidence':'medium'},
     {'task':'audit','guardrail':'passed','access_violations':[],'confidence':'high'},
   ],
   'block_log':[
     {'command':'pre-tool-check','reason':'stage=IDLE','stage':'IDLE','timestamp':'2026-06-17T10:00:00'},
     {'command':'pre-tool-check','reason':'stage=IDLE','stage':'IDLE','timestamp':'2026-06-17T10:01:00'},
     {'command':'pre-tool-check','reason':'stage=IDLE','stage':'IDLE','timestamp':'2026-06-17T10:02:00'},
   ],
   'human_calibration_log':[],
   'scheduler':{'mode':'cosine','max_lr':4,'min_lr':1,'total_steps':6,'current_step':1,'current_lr':4}
 },
 'monitor_scores':{},'history':[]
}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null

echo ""
echo "--- D13-A1: clean subagent_history (all guardrail=passed) ---"
r=$(bash "$CLI" audit --state 2>&1)
sh_match=$(echo "$r" | python3 -c "import sys,json;d=json.load(sys.stdin);checks=d.get('result',{}).get('state_checks',[]);print(next((c.get('match') for c in checks if c.get('field')=='subagent_history'),None))" 2>/dev/null || echo "None")
if [ "$sh_match" = "True" ]; then
  pass "D13-A1: clean subagent_history passes"
else
  vuln "D13-A1: clean subagent_history should pass, got: $sh_match"
fi

echo ""
echo "--- D13-A2: subagent with guardrail=failed ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['subagent_history'].append({'task':'test','guardrail':'failed','access_violations':[],'confidence':'high'})
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" audit --state 2>&1)
sh_match=$(echo "$r" | python3 -c "import sys,json;d=json.load(sys.stdin);checks=d.get('result',{}).get('state_checks',[]);print(next((c.get('match') for c in checks if c.get('field')=='subagent_history'),None))" 2>/dev/null || echo "None")
if [ "$sh_match" = "False" ]; then
  pass "D13-A2: guardrail=failed detected"
else
  vuln "D13-A2: guardrail=failed NOT detected, got: $sh_match"
fi

echo ""
echo "--- D13-A3: subagent with access_violations ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['subagent_history']=[{'task':'test','guardrail':'passed','access_violations':['file_read:/etc/passwd'],'confidence':'high'}]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" audit --state 2>&1)
sh_match=$(echo "$r" | python3 -c "import sys,json;d=json.load(sys.stdin);checks=d.get('result',{}).get('state_checks',[]);print(next((c.get('match') for c in checks if c.get('field')=='subagent_history'),None))" 2>/dev/null || echo "None")
if [ "$sh_match" = "False" ]; then
  pass "D13-A3: access_violations detected"
else
  vuln "D13-A3: access_violations NOT detected, got: $sh_match"
fi

echo ""
echo "--- D14-A1: block_log concentrated on one command ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['subagent_history']=[{'task':'test','guardrail':'passed','access_violations':[],'confidence':'high'}]
d['gate_data']['block_log']=[
  {'command':'push','reason':'stage=DONE','stage':'DONE','timestamp':'2026-06-17T10:00:00'},
  {'command':'push','reason':'stage=DONE','stage':'DONE','timestamp':'2026-06-17T10:01:00'},
  {'command':'push','reason':'stage=DONE','stage':'DONE','timestamp':'2026-06-17T10:02:00'},
  {'command':'push','reason':'stage=DONE','stage':'DONE','timestamp':'2026-06-17T10:03:00'},
]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" audit --state 2>&1)
bl_match=$(echo "$r" | python3 -c "import sys,json;d=json.load(sys.stdin);checks=d.get('result',{}).get('state_checks',[]);print(next((c.get('match') for c in checks if c.get('field')=='block_log'),None))" 2>/dev/null || echo "None")
if [ "$bl_match" = "False" ]; then
  pass "D14-A1: concentrated block_log detected"
else
  vuln "D14-A1: concentrated block_log NOT detected, got: $bl_match"
fi

echo ""
echo "--- D14-A2: empty block_log (should pass) ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['block_log']=[]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" audit --state 2>&1)
bl_match=$(echo "$r" | python3 -c "import sys,json;d=json.load(sys.stdin);checks=d.get('result',{}).get('state_checks',[]);print(next((c.get('match') for c in checks if c.get('field')=='block_log'),None))" 2>/dev/null || echo "None")
if [ "$bl_match" = "True" ]; then
  pass "D14-A2: empty block_log passes"
else
  vuln "D14-A2: empty block_log should pass, got: $bl_match"
fi

echo ""
echo "==========================================="
echo "Batch 3a RESULTS: VULN=$VULN, $PASS pass, $FAIL fail"
[ $VULN -gt 0 ] && exit 1 || exit 0

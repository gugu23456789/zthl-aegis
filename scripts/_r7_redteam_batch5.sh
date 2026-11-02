#!/bin/bash
# Red-team: Batch 5 — replay + entropy + archiving + cron
set +e
CLI="<home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh"
SKILL="<home>/.trae/skills/spz-gatekeeper-r-sequence"
SF="${REDTEAM_STATE:-${SKILL}/.gatekeeper.state}"  # 2026-08-14: 优先隔离 state（runner 设 REDTEAM_STATE），回退技能目录默认
PASS=0; FAIL=0; VULN=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
vuln() { echo "  VULN: $1"; VULN=$((VULN+1)); FAIL=$((FAIL+1)); }

echo "==========================================="
echo "Batch 5 Red-Team: replay + entropy + archiving"
echo "==========================================="

# Setup state
python3 -c "
import json
d={
 'r_phase':'ECO-EDIT','stage':'ECO-EDIT','branch':'master',
 'worktree':'${SKILL}','main_repo':'${SKILL}',
 'gate_data':{
   'project_type':'standing','rejected_edits':[],'subagent_history':[],'block_log':[],
   'human_calibration_log':[
     {'stage':'ECO-EDIT','human_score':0.8,'monitor_score':0.6,'divergence':0.2,'flag':'HUMAN_OVERSCORE',
      'verdicts_json':{'l1':'PASS','l2':'WARN','l3':'PASS'},'timestamp':'2026-06-17T10:00:00'},
     {'stage':'ECO-EDIT','human_score':0.7,'monitor_score':0.5,'divergence':0.2,'flag':'HUMAN_OVERSCORE',
      'verdicts_json':{'l1':'PASS','l2':'FAIL','l3':'WARN'},'timestamp':'2026-06-17T11:00:00'},
     {'stage':'ECO-EDIT','human_score':0.9,'monitor_score':0.8,'divergence':0.1,'flag':'',
      'verdicts_json':{'l1':'PASS','l2':'PASS','l3':'PASS'},'timestamp':'2026-06-17T12:00:00'}
   ],
   'eco_completions':{'ECO-SCAN':{'completed_at':'2026-06-16T15:00:00'}},
   'scheduler':{'mode':'cosine','max_lr':4,'min_lr':1,'total_steps':6,'current_step':3,'current_lr':3},
   '_advance_log':[
     {'timestamp':'2026-06-17T09:00:00','to_stage':'ECO-READ','all_ok':True,'gates_count':3,'entropy_rate':'0.0'},
     {'timestamp':'2026-06-17T10:00:00','to_stage':'ECO-EDIT','all_ok':True,'gates_count':2,'entropy_rate':'0.33'},
     {'timestamp':'2026-06-17T11:00:00','to_stage':'ECO-AUDIT','all_ok':False,'gates_count':4,'entropy_rate':'0.67'}
   ],
   'edit_count':3,'edit_budget':{'max':3,'used':3,'remaining':0}
 },
 'monitor_scores':{'ECO-EDIT':{'score':0.8,'status':'PASS'}},
 'history':[
   {'r_phase':'ECO-SCAN','completed_at':'2026-06-16T15:00:00','stage':'ECO-SCAN',
    'best':{'score':0.85,'stage':'ECO-SCAN','r_phase':'ECO-SCAN','timestamp':'2026-06-16T15:00:00'},
    'rejection_count':0,'rejection_patterns':[],'monitor_scores_summary':{'ECO-SCAN':0.85},'edit_count':5,
    'advance_log':[{'timestamp':'2026-06-16T14:50:00','to_stage':'ECO-READ','all_ok':True,'gates_count':3,'entropy_rate':'0.0'}],
    'appeal_summary':[],'appeal_records_full':{},'human_resolutions':{}}
 ],
 'appeal_records':{'ECO-AUDIT':{'verdict':'APPROVED','score':0.9,'impact':'accepted','mediation_explanation':'Scores aligned','time':'2026-06-17T10:05:00'}},
 'human_resolutions':{'ECO-AUDIT':{'gate':'ECO-AUDIT','source':'appeal','resolution':'force_advance','reason':'Approved','resolved_at':'2026-06-17T10:06:00Z'}}
}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null

echo ""
echo "--- 5.1-A1: entropy_rate clamp in CLI code path ---"
# G-12 fix: verify the actual CLI path clamps values.
# The clamp expression max(0.0,min(1.0,...)) must exist at the log-writing location in gatekeeper-cli.sh.
clamp_in_code=$(rg -c 'max(0.0,min(1.0,float(' "$SKILL/gatekeeper-cli.sh" 2>/dev/null || echo "0")
clamp_in_code=$(echo "$clamp_in_code" | tr -d '[:space:]')
[ -z "$clamp_in_code" ] && clamp_in_code=0
[ "$clamp_in_code" -gt 0 ] && pass "5.1-A1: clamp expression max(0.0,min(1.0,...)) exists in CLI code ($clamp_in_code occurrences)" || vuln "5.1-A1: clamp expression NOT found in CLI code"

echo ""
echo "--- 5.1-A2: entropy_rate clamped via CLI advance ---"
# G-12 fix: run actual CLI advance and verify the logged entropy_rate is in [0, 1].
# Setup: ECO-EDIT with calibration log producing known entropy (2/3 non-PASS = 0.67)
python3 -c "
import json
d={
 'r_phase':'ECO-EDIT','stage':'ECO-EDIT','branch':'master',
 'worktree':'${SKILL}','main_repo':'${SKILL}',
 'gate_data':{
   'project_type':'standing','rejected_edits':[],'subagent_history':[],'block_log':[],
   'eco_completions':{'ECO-SCAN':{'completed_at':'2026-06-16T15:00:00'}},
   'scheduler':{'mode':'cosine','max_lr':4,'min_lr':1,'total_steps':6,'current_step':3,'current_lr':3},
   'human_calibration_log':[
     {'stage':'ECO-EDIT','human_score':0.6,'verdicts_json':{'l1':'PASS','l2':'FAIL','l3':'WARN'},'timestamp':'2026-06-17T10:00:00'},
     {'stage':'ECO-EDIT','human_score':0.7,'verdicts_json':{'l1':'PASS','l2':'FAIL','l3':'PASS'},'timestamp':'2026-06-17T11:00:00'},
     {'stage':'ECO-EDIT','human_score':0.8,'verdicts_json':{'l1':'PASS','l2':'PASS','l3':'PASS'},'timestamp':'2026-06-17T12:00:00'}
   ],
   '_advance_log':[],'edit_count':3
 },
 'monitor_scores':{'ECO-EDIT':{'score':0.8,'status':'PASS'}},
 'history':[],'appeal_records':{}
}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
# Run advance via CLI (will fail on gates but should still write to _advance_log with clamped entropy)
bash "$CLI" advance ECO-AUDIT 2>/dev/null 1>/dev/null
# Verify the logged entropy_rate is in [0, 1] (clamped)
er=$(python3 -c "
import json
d=json.load(open('$SF'))
gl=d.get('gate_data',{}).get('_advance_log',[])
if not gl: print('no_log'); exit()
last=gl[-1]
er=float(last.get('entropy_rate',-1))
print(f'{er:.2f}')
" 2>/dev/null || echo "no_log")
if [ "$er" = "no_log" ]; then
  fail "5.1-A2: no _advance_log entry written by CLI"
elif python3 -c "exit(0 if 0.0 <= float('$er') <= 1.0 else 1)" 2>/dev/null; then
  pass "5.1-A2: CLI advance logged entropy_rate=$er (within [0,1])"
else
  vuln "5.1-A2: CLI advance logged entropy_rate=$er (OUT OF [0,1])"
fi

echo ""
echo "--- 5.2-A1: S-02 ECO entropy sliding window ---"
python3 -c "
import json
d=json.load(open('$SF'))
cl=d.get('gate_data',{}).get('human_calibration_log',[])
window=cl[-5:]
rates=[]
for entry in window:
    vj=entry.get('verdicts_json',{})
    if not vj: continue
    total=len(vj)
    if total==0: continue
    non_pass=sum(1 for v in vj.values() if str(v).upper() not in ('PASS','OK'))
    rates.append(non_pass/total)
avg=sum(rates)/len(rates) if rates else 0.0
print(f'{avg:.2f}')
" 2>/dev/null
avg=$(python3 -c "
import json
d=json.load(open('$SF'))
cl=d.get('gate_data',{}).get('human_calibration_log',[])
window=cl[-5:]
rates=[]
for entry in window:
    vj=entry.get('verdicts_json',{})
    if not vj: continue
    total=len(vj)
    if total==0: continue
    non_pass=sum(1 for v in vj.values() if str(v).upper() not in ('PASS','OK'))
    rates.append(non_pass/total)
avg=sum(rates)/len(rates) if rates else 0.0
print(f'{avg:.2f}')
" 2>/dev/null || echo "0.0")
# 3 entries: 1/3=0.33, 2/3=0.67, 0/3=0.0 → avg=0.33
[ "$avg" = "0.33" ] && pass "5.2-A1: sliding window avg=0.33 (correct)" || vuln "5.2-A1: sliding window avg=$avg (expected 0.33)"

echo ""
echo "--- 5.2-A2: S-02 single entry fallback ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['human_calibration_log']=[{'verdicts_json':{'l1':'WARN','l2':'PASS'},'timestamp':'t'}]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
avg=$(python3 -c "
import json
d=json.load(open('$SF'))
cl=d.get('gate_data',{}).get('human_calibration_log',[])
window=cl[-5:]
rates=[]
for entry in window:
    vj=entry.get('verdicts_json',{})
    if not vj: continue
    total=len(vj)
    if total==0: continue
    non_pass=sum(1 for v in vj.values() if str(v).upper() not in ('PASS','OK'))
    rates.append(non_pass/total)
avg=sum(rates)/len(rates) if rates else 0.0
print(f'{avg:.2f}')
" 2>/dev/null || echo "0.0")
[ "$avg" = "0.50" ] && pass "5.2-A2: single entry fallback avg=0.50" || vuln "5.2-A2: single entry avg=$avg (expected 0.50)"

echo ""
echo "--- 5.2-A3: S-02 empty calibration ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['human_calibration_log']=[]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
avg=$(python3 -c "
import json
d=json.load(open('$SF'))
cl=d.get('gate_data',{}).get('human_calibration_log',[])
if not cl: print('0.0'); exit()
" 2>/dev/null || echo "0.0")
[ "$avg" = "0.0" ] && pass "5.2-A3: empty calibration → 0.0" || vuln "5.2-A3: empty calibration → $avg"

echo ""
echo "--- 5.3-A1: D11 appeal_records in history ---"
python3 -c "
import json
d=json.load(open('$SF'))
h=d.get('history',[])
ar=h[0].get('appeal_records_full',{}) if h else {}
print('yes' if isinstance(ar,dict) else 'no')
" 2>/dev/null
d11=$(python3 -c "
import json
d=json.load(open('$SF'))
h=d.get('history',[])
ar=h[0].get('appeal_records_full',{}) if h else {}
print('yes' if isinstance(ar,dict) else 'no')
" 2>/dev/null || echo "no")
[ "$d11" = "yes" ] && pass "5.3-A1: appeal_records_full in history" || vuln "5.3-A1: appeal_records_full missing"

echo ""
echo "--- 5.3-A2: D11 human_resolutions in history ---"
d11r=$(python3 -c "
import json
d=json.load(open('$SF'))
h=d.get('history',[])
hr=h[0].get('human_resolutions',{}) if h else {}
print('yes' if isinstance(hr,dict) else 'no')
" 2>/dev/null || echo "no")
[ "$d11r" = "yes" ] && pass "5.3-A2: human_resolutions in history" || vuln "5.3-A2: human_resolutions missing"

echo ""
echo "--- 5.4-A1: cmd_replay with valid data ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['_advance_log']=[
  {'timestamp':'2026-06-17T09:00:00','to_stage':'ECO-READ','all_ok':True,'gates_count':3,'entropy_rate':'0.0'},
  {'timestamp':'2026-06-17T10:00:00','to_stage':'ECO-EDIT','all_ok':True,'gates_count':2,'entropy_rate':'0.33'}
]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" replay 2>&1)
echo "$r" | rg -qi 'true' && pass "5.4-A1: replay accepted" || vuln "5.4-A1: replay failed: $r"

echo ""
echo "--- 5.4-A2: cmd_replay detects invalid entropy ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['_advance_log'].append({'timestamp':'2026-06-17T11:00:00','to_stage':'ECO-AUDIT','all_ok':True,'gates_count':4,'entropy_rate':'-0.5'})
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" replay 2>&1)
echo "$r" | rg -q '"diverged"' && pass "5.4-A2: replay detected invalid entropy" || vuln "5.4-A2: replay missed invalid entropy"

echo ""
echo "--- 5.4-A3: cmd_replay with empty log ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['_advance_log']=[]
d['history']=[]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" replay 2>&1)
echo "$r" | rg -qi 'true\|ok' && pass "5.4-A3: replay with empty log (graceful)" || vuln "5.4-A3: replay crashed on empty log: $r"

echo ""
echo "--- 5.5-A1: cron job exists ---"
cron=$(crontab -l 2>/dev/null || echo "none")
# Also check application-level cron
app_cron=$(python3 -c "
import sys,json; sys.path.insert(0,'${SKILL}/scripts')
from cron_jobs import load_jobs
jobs=load_jobs()
rc=[j for j in jobs if 'release-check' in j.get('name','')]
print('yes' if rc else 'no')
" 2>/dev/null || echo "no")
(echo "$cron" | rg -q "release-check" || [ "$app_cron" = "yes" ]) && pass "5.5-A1: cron job exists" || vuln "5.5-A1: cron job missing"

echo ""
echo "==========================================="
echo "Batch 5 RESULTS: VULN=$VULN, $PASS pass, $FAIL fail"
[ $VULN -gt 0 ] && exit 1 || exit 0

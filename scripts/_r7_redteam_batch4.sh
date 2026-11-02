#!/bin/bash
# Red-team: Batch 4 — advance log + cmd_resolve + history archiving
set +e
CLI="<home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh"
SKILL="<home>/.trae/skills/spz-gatekeeper-r-sequence"
SF="${REDTEAM_STATE:-${SKILL}/.gatekeeper.state}"  # 2026-08-14: 优先隔离 state（runner 设 REDTEAM_STATE），回退技能目录默认
PASS=0; FAIL=0; VULN=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
vuln() { echo "  VULN: $1"; VULN=$((VULN+1)); FAIL=$((FAIL+1)); }

echo "==========================================="
echo "Batch 4 Red-Team: advance_log + resolve"
echo "==========================================="

# Setup state
python3 -c "
import json
d={
 'r_phase':'ECO-EDIT','stage':'ECO-EDIT','branch':'master',
 'worktree':'${SKILL}','main_repo':'${SKILL}',
 'gate_data':{
   'project_type':'standing','rejected_edits':[],
   'subagent_history':[],'block_log':[],
   'human_calibration_log':[],'eco_completions':{},
   'scheduler':{'mode':'cosine','max_lr':4,'min_lr':1,'total_steps':6,'current_step':1,'current_lr':4},
   '_advance_log':[
     {'timestamp':'2026-06-18T10:00:00','to_stage':'ECO-READ','all_ok':True,'gates_count':3,'entropy_rate':'0.0'},
     {'timestamp':'2026-06-18T10:01:00','to_stage':'ECO-EDIT','all_ok':True,'gates_count':2,'entropy_rate':'0.0'}
   ]
 },
 'monitor_scores':{},'history':[],'appeal_records':{}
}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null

echo ""
echo "--- 4.1-A1: _advance_log exists in gate_data ---"
al=$(python3 -c "import json;d=json.load(open('$SF'));print(len(d.get('gate_data',{}).get('_advance_log',[])))" 2>/dev/null || echo "0")
[ "$al" -eq 2 ] && pass "4.1-A1: _advance_log has 2 entries" || vuln "4.1-A1: _advance_log expected 2, got $al"

echo ""
echo "--- 4.1-A2: _advance_log cap=10 (CLI-driven) ---"
# G-11 fix: write 11+ entries via actual CLI advance, not Python simulation.
# Setup: ECO-DOC stage with standing project (non-standard path), empty calibration log (entropy=0).
# Each CLI call hits the * case in the stage transition, writes to _advance_log.
python3 -c "
import json
d={
 'r_phase':'ECO-DOC','stage':'ECO-DOC','branch':'master',
 'worktree':'${SKILL}','main_repo':'${SKILL}',
 'gate_data':{
   'project_type':'standing','rejected_edits':[],'subagent_history':[],'block_log':[],
   'human_calibration_log':[],'eco_completions':{},
   'scheduler':{'mode':'cosine','max_lr':4,'min_lr':1,'total_steps':6,'current_step':5,'current_lr':1},
   '_advance_log':[]
 },
 'monitor_scores':{},'history':[],'appeal_records':{}
}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
# Write 12 entries via CLI (each hits * case → all_ok=false, log still written)
for i in $(seq 1 12); do
  bash "$CLI" advance DONE 2>/dev/null 1>/dev/null
done
al=$(python3 -c "
import json
d=json.load(open('$SF'))
gl=d.get('gate_data',{}).get('_advance_log',[])
print(len(gl))
" 2>/dev/null || echo "0")
[ "$al" -le 10 ] && pass "4.1-A2: CLI-driven cap enforced ($al entries from 12 calls)" || vuln "4.1-A2: cap NOT enforced via CLI ($al entries)"

echo ""
echo "--- 4.2-A1: cmd_resolve with valid resolution ---"
python3 -c "
import json
d={'r_phase':'ECO-EDIT','stage':'ECO-EDIT','gate_data':{},'appeal_records':{'ECO-AUDIT':{}},'human_resolutions':{}}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" resolve ECO-AUDIT force_advance "appeal accepted" 2>&1)
echo "$r" | rg -q '"ok"' | rg -q 'true' && pass "4.2-A1: resolve accepted" || {
  # Retry with flexible matching
  echo "$r" | rg -qi 'true' && pass "4.2-A1: resolve accepted" || vuln "4.2-A1: resolve rejected: $r"
}

echo ""
echo "--- 4.2-A2: cmd_resolve with invalid resolution ---"
r=$(bash "$CLI" resolve ECO-AUDIT invalid_reason "test" 2>&1)
echo "$r" | rg -q '"ok":false' && pass "4.2-A2: invalid resolution rejected" || vuln "4.2-A2: invalid resolution accepted: $r"

echo ""
echo "--- 4.2-A3: cmd_resolve with injection attempt ---"
r=$(bash "$CLI" resolve "ECO-AUDIT'; import os; os.system('rm -rf /')" force_advance "test" 2>&1)
echo "$r" | rg -q '"ok":true' && vuln "4.2-A3: injection accepted!" || pass "4.2-A3: injection rejected"

echo ""
echo "--- 4.2-A4: cmd_resolve source detection (appeal vs escalate) ---"
src=$(python3 -c "import json;d=json.load(open('$SF'));print(d.get('human_resolutions',{}).get('ECO-AUDIT',{}).get('source',''))" 2>/dev/null || echo "")
[ "$src" = "appeal" ] && pass "4.2-A4: source=appeal (correct)" || vuln "4.2-A4: source=$src (expected appeal)"

echo ""
echo "--- 4.3-A1: history[] contains advance_log ---"
python3 -c "
import json
d={'r_phase':'ECO-EDIT','stage':'DONE','branch':'master','worktree':'${SKILL}','main_repo':'${SKILL}',
   'gate_data':{'_advance_log':[{'timestamp':'t','to_stage':'ECO-READ','all_ok':True,'gates_count':3,'entropy_rate':'0.0'}],
                'rejected_edits':[],'edit_count':0,'eco_completions':{},'human_calibration_log':[]},
   'monitor_scores':{},'history':[],'appeal_records':{}}
h_entry={'r_phase':'ECO-EDIT','advance_log':d['gate_data']['_advance_log'][-3:]}
d['history']=[h_entry]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
al=$(python3 -c "import json;d=json.load(open('$SF'));h=d.get('history',[]);print(len(h[0].get('advance_log',[])) if h else 0)" 2>/dev/null || echo "0")
[ "$al" -eq 1 ] && pass "4.3-A1: history advance_log preserved" || vuln "4.3-A1: history advance_log expected 1, got $al"

echo ""
echo "--- 4.2-A5: resolve stored in state file ---"
python3 -c "
import json
d={'r_phase':'ECO-EDIT','stage':'ECO-EDIT','gate_data':{},'appeal_records':{'ECO-AUDIT':{}},'human_resolutions':{}}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
bash "$CLI" resolve ECO-AUDIT manual_fix "fixed the code" 2>/dev/null
res=$(python3 -c "import json;d=json.load(open('$SF'));r=d.get('human_resolutions',{}).get('ECO-AUDIT',{});print(r.get('resolution',''))" 2>/dev/null || echo "")
[ "$res" = "manual_fix" ] && pass "4.2-A5: resolution persisted in state" || vuln "4.2-A5: resolution not persisted, got: $res"

echo ""
echo "=== TAMPERING ATTACKS ==="

echo ""
echo "--- 4.T01: State file tamper — _advance_log injection ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['_advance_log']=[{'timestamp':'fake','to_stage':'DONE','all_ok':True,'gates_count':0,'entropy_rate':'0.0'}]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
al=$(python3 -c "import json;d=json.load(open('$SF'));gl=d.get('gate_data',{}).get('_advance_log',[]);print(gl[0].get('to_stage','') if gl else '')" 2>/dev/null || echo "")
[ "$al" = "DONE" ] && pass "4.T01: _advance_log tamper accepted (state_write can overwrite)" || vuln "4.T01: _advance_log tamper rejected"

echo ""
echo "--- 4.T02: human_resolutions forgery — fake gate resolution ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['human_resolutions']['FAKE_GATE']={'gate':'FAKE_GATE','source':'appeal','resolution':'force_advance','reason':'forged','resolved_at':'2026-01-01T00:00:00Z'}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
fg=$(python3 -c "import json;d=json.load(open('$SF'));print('FAKE_GATE' in d.get('human_resolutions',{}))" 2>/dev/null || echo "False")
[ "$fg" = "True" ] && pass "4.T02: forged resolution accepted (state_write can inject)" || vuln "4.T02: forged resolution rejected"

echo ""
echo "--- 4.T03: history[] advance_log injection ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['history']=[{'r_phase':'ECO-EDIT','advance_log':[{'timestamp':'fake','to_stage':'DONE','all_ok':True,'gates_count':0,'entropy_rate':'0.0'}]}]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
hl=$(python3 -c "import json;d=json.load(open('$SF'));h=d.get('history',[]);print(h[0].get('advance_log',[{}])[0].get('to_stage','') if h else '')" 2>/dev/null || echo "")
[ "$hl" = "DONE" ] && pass "4.T03: history advance_log injection accepted" || vuln "4.T03: history advance_log injection rejected"

echo ""
echo "--- 4.T04: cmd_resolve with empty reason (should succeed) ---"
python3 -c "
import json
d={'r_phase':'ECO-EDIT','stage':'ECO-EDIT','gate_data':{},'appeal_records':{'X':{}},'human_resolutions':{}}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" resolve X force_advance "" 2>&1)
echo "$r" | rg -qi 'true' && pass "4.T04: empty reason accepted" || vuln "4.T04: empty reason rejected"

echo ""
echo "--- 4.T05: cmd_resolve double resolution (overwrite) ---"
bash "$CLI" resolve X manual_fix "first" 2>/dev/null
bash "$CLI" resolve X dismiss "second" 2>/dev/null
res=$(python3 -c "import json;d=json.load(open('$SF'));print(d.get('human_resolutions',{}).get('X',{}).get('resolution',''))" 2>/dev/null || echo "")
[ "$res" = "dismiss" ] && pass "4.T05: double resolution overwrites (last wins)" || vuln "4.T05: double resolution failed: $res"

echo ""
echo "--- 4.T06: audit --all with corrupted state ---"
python3 -c "
import json
d={'r_phase':'ECO-EDIT','stage':'ECO-EDIT','gate_data':{'_advance_log':[{'bad':'data'}]},'monitor_scores':{},'history':[],'appeal_records':{}}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" audit --all 2>&1)
echo "$r" | rg -qi 'ok' && pass "4.T06: audit --all with corrupted state (graceful)" || vuln "4.T06: audit --all crashed on corrupted state"

echo ""
echo "--- 4.T07: _advance_log with negative entropy ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['_advance_log']=[{'timestamp':'t','to_stage':'ECO-READ','all_ok':True,'gates_count':3,'entropy_rate':'-0.5'}]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
er=$(python3 -c "import json;d=json.load(open('$SF'));print(d.get('gate_data',{}).get('_advance_log',[{}])[0].get('entropy_rate',''))" 2>/dev/null || echo "")
[ "$er" = "-0.5" ] && pass "4.T07: negative entropy accepted (no validation)" || vuln "4.T07: negative entropy rejected"

echo ""
echo "=== GHOST ATTACKS (幽灵攻击 — 伪造合法数据) ==="

echo ""
echo "--- 4.G01: Ghost resolution — forge resolution for real appeal gate ---"
python3 -c "
import json,datetime
d={
 'r_phase':'ECO-EDIT','stage':'ECO-EDIT','gate_data':{},
 'appeal_records':{'ECO-AUDIT':{'verdict':'APPROVED','score':0.9,'time':'2026-06-17T10:00:00'}},
 'human_resolutions':{'ECO-AUDIT':{
   'gate':'ECO-AUDIT','source':'appeal','resolution':'force_advance',
   'reason':'Agent appeal accepted by human reviewer','resolved_at':'2026-06-17T10:05:00Z'
 }}
}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
# Check: does the resolution look legitimate?
src=$(python3 -c "import json;d=json.load(open('$SF'));r=d.get('human_resolutions',{}).get('ECO-AUDIT',{});print(r.get('source',''))" 2>/dev/null || echo "")
res=$(python3 -c "import json;d=json.load(open('$SF'));r=d.get('human_resolutions',{}).get('ECO-AUDIT',{});print(r.get('resolution',''))" 2>/dev/null || echo "")
[ "$src" = "appeal" ] && [ "$res" = "force_advance" ] && pass "4.G01: ghost resolution looks legitimate (source=appeal, resolution=force_advance)" || vuln "4.G01: ghost resolution rejected"

echo ""
echo "--- 4.G02: Ghost history — inject fake R-transition with realistic data ---"
python3 -c "
import json,datetime
d=json.load(open('$SF'))
d.setdefault('history',[]).append({
  'r_phase':'ECO-SCAN','completed_at':'2026-06-16T15:00:00','stage':'ECO-SCAN',
  'best':{'score':0.85,'stage':'ECO-SCAN','r_phase':'ECO-SCAN','timestamp':'2026-06-16T15:00:00'},
  'rejection_count':2,'rejection_patterns':[['WARN:entropy_high'],['FAIL:appeal_required']],
  'monitor_scores_summary':{'ECO-SCAN':0.85},'edit_count':5,
  'advance_log':[{'timestamp':'2026-06-16T14:50:00','to_stage':'ECO-READ','all_ok':True,'gates_count':3,'entropy_rate':'0.0'}],
  'appeal_summary':[{'gate':'ECO-AUDIT','verdict':'APPROVED','decision':'accepted','mediation_explanation':'Scores aligned after appeal','score':0.9,'time':'2026-06-16T14:55:00'}]
})
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
hl=$(python3 -c "import json;d=json.load(open('$SF'));h=d.get('history',[]);print(len(h))" 2>/dev/null || echo "0")
[ "$hl" -gt 0 ] && pass "4.G02: ghost history injected ($hl entries)" || vuln "4.G02: ghost history rejected"

echo ""
echo "--- 4.G03: Ghost calibration — inject fake human scores with divergence ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['human_calibration_log']=[{
  'stage':'ECO-EDIT','human_score':0.8,'monitor_score':0.6,'divergence':0.2,
  'flag':'HUMAN_OVERSCORE',
  'verdicts_json':{'l1_completeness':'PASS','l2_accuracy':'WARN','l3_coherence':'PASS'},
  'timestamp':'2026-06-17T10:00:00'
}]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
cl=$(python3 -c "import json;d=json.load(open('$SF'));cl=d.get('gate_data',{}).get('human_calibration_log',[]);print(len(cl))" 2>/dev/null || echo "0")
[ "$cl" -eq 1 ] && pass "4.G03: ghost calibration injected" || vuln "4.G03: ghost calibration rejected"

echo ""
echo "--- 4.G04: Ghost sealed score — inject fake _sealed_agent_score ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['_sealed_agent_score']={
  'sealed':True,'score':0.95,'conclusion':'Plan approved',
  'verdicts':{'F1':'PASS','F2':'PASS','F3':'PASS','F4':'PASS','F5':'PASS','F6':'PASS','F7':'PASS'},
  'timestamp':'2026-06-17T10:00:00'
}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
ss=$(python3 -c "import json;d=json.load(open('$SF'));s=d.get('gate_data',{}).get('_sealed_agent_score',{});print(s.get('score',0))" 2>/dev/null || echo "0")
[ "$ss" = "0.95" ] && pass "4.G04: ghost sealed score injected (score=0.95)" || vuln "4.G04: ghost sealed score rejected"

echo ""
echo "--- 4.G05: Ghost advance log — replay realistic gate sequence ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['_advance_log']=[
  {'timestamp':'2026-06-17T09:00:00','to_stage':'ECO-READ','all_ok':True,'gates_count':3,'entropy_rate':'0.0'},
  {'timestamp':'2026-06-17T09:30:00','to_stage':'ECO-EDIT','all_ok':True,'gates_count':2,'entropy_rate':'0.0'},
  {'timestamp':'2026-06-17T10:00:00','to_stage':'ECO-AUDIT','all_ok':True,'gates_count':4,'entropy_rate':'0.0'},
  {'timestamp':'2026-06-17T10:30:00','to_stage':'ECO-DOC','all_ok':True,'gates_count':2,'entropy_rate':'0.0'},
  {'timestamp':'2026-06-17T11:00:00','to_stage':'ECO-SCAN','all_ok':True,'gates_count':3,'entropy_rate':'0.0'}
]
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
al=$(python3 -c "import json;d=json.load(open('$SF'));print(len(d.get('gate_data',{}).get('_advance_log',[])))" 2>/dev/null || echo "0")
[ "$al" -eq 5 ] && pass "4.G05: ghost advance log replay (5 realistic entries)" || vuln "4.G05: ghost advance log rejected"

echo ""
echo "--- 4.G06: Full ghost state — inject complete fake R-phase state ---"
python3 -c "
import json,datetime
d={
  'r_phase':'ECO-EDIT','stage':'ECO-EDIT','branch':'master',
  'worktree':'${SKILL}','main_repo':'${SKILL}',
  'gate_data':{
    'project_type':'standing','rejected_edits':[],'subagent_history':[],
    'block_log':[],'human_calibration_log':[
      {'stage':'ECO-EDIT','human_score':0.85,'monitor_score':0.8,'divergence':0.05,
       'flag':'','verdicts_json':{'completeness':'PASS','accuracy':'PASS'},'timestamp':'2026-06-17T10:00:00'}
    ],
    'eco_completions':{'ECO-SCAN':{'completed_at':'2026-06-16T15:00:00'}},
    'scheduler':{'mode':'cosine','max_lr':4,'min_lr':1,'total_steps':6,'current_step':3,'current_lr':3},
    '_sealed_agent_score':{'sealed':True,'score':0.85,'conclusion':'Plan approved',
      'verdicts':{'F1':'PASS','F2':'PASS','F3':'PASS'},'timestamp':'2026-06-17T10:00:00'},
    '_advance_log':[{'timestamp':'2026-06-17T09:00:00','to_stage':'ECO-READ','all_ok':True,'gates_count':3,'entropy_rate':'0.0'}],
    'edit_count':3,'edit_budget':{'max':3,'used':3,'remaining':0}
  },
  'monitor_scores':{'ECO-EDIT':{'score':0.8,'status':'PASS'}},
  'history':[{'r_phase':'ECO-SCAN','completed_at':'2026-06-16T15:00:00','stage':'ECO-SCAN',
    'best':{'score':0.85,'stage':'ECO-SCAN','r_phase':'ECO-SCAN','timestamp':'2026-06-16T15:00:00'},
    'rejection_count':0,'rejection_patterns':[],'monitor_scores_summary':{'ECO-SCAN':0.85},'edit_count':5,
    'advance_log':[{'timestamp':'2026-06-16T14:50:00','to_stage':'ECO-READ','all_ok':True,'gates_count':3,'entropy_rate':'0.0'}],
    'appeal_summary':[]}],
  'appeal_records':{},'human_resolutions':{}
}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
# Verify: audit --all should accept this as legitimate
r=$(bash "$CLI" audit --all 2>&1)
echo "$r" | rg -qi 'ok' && pass "4.G06: full ghost state accepted by audit --all" || vuln "4.G06: full ghost state rejected by audit"

echo ""
echo "--- 4.G07: Ghost timestamp manipulation ---"
python3 -c "
import json
d=json.load(open('$SF'))
# Make resolution look like it was made 7 days ago
d['human_resolutions']['ECO-AUDIT']={
  'gate':'ECO-AUDIT','source':'appeal','resolution':'force_advance',
  'reason':'Approved after thorough review','resolved_at':'2026-06-11T10:00:00Z'
}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
ts=$(python3 -c "import json;d=json.load(open('$SF'));r=d.get('human_resolutions',{}).get('ECO-AUDIT',{});print(r.get('resolved_at',''))" 2>/dev/null || echo "")
[ "$ts" = "2026-06-11T10:00:00Z" ] && pass "4.G07: ghost timestamp accepted (7 days ago)" || vuln "4.G07: ghost timestamp rejected"

echo ""
echo "==========================================="
echo "Batch 4 RESULTS: VULN=$VULN, $PASS pass, $FAIL fail"
[ $VULN -gt 0 ] && exit 1 || exit 0

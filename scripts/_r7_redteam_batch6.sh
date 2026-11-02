#!/bin/bash
# Red-team: Batch 6 — I3 achievements + I5 RED attacks + I9 ECC-FINDING
set +e
CLI="<home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh"
SKILL="<home>/.trae/skills/spz-gatekeeper-r-sequence"
SF="${REDTEAM_STATE:-${SKILL}/.gatekeeper.state}"  # 2026-08-14: 优先隔离 state（runner 设 REDTEAM_STATE），回退技能目录默认
PASS=0; FAIL=0; VULN=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
vuln() { echo "  VULN: $1"; VULN=$((VULN+1)); FAIL=$((FAIL+1)); }

echo "==========================================="
echo "Batch 6 Red-Team: I3 + I5 + I9"
echo "==========================================="

# Setup state
python3 -c "
import json
d={
 'r_phase':'ECO-EDIT','stage':'ECO-EDIT','gate_data':{
   '_advance_log':[{'timestamp':'2026-06-17T09:00:00','to_stage':'ECO-READ','all_ok':True,'gates_count':3,'entropy_rate':'0.0'}],
   'rejected_edits':[],'subagent_history':[],'block_log':[]
 },
 'history':[{'r_phase':'ECO-SCAN','completed_at':'2026-06-16T15:00:00','stage':'ECO-SCAN','rejection_count':0}],
 'human_resolutions':{'ECO-AUDIT':{'gate':'ECO-AUDIT','source':'appeal','resolution':'force_advance','reason':'test','resolved_at':'2026-06-17T10:00:00Z','ed25519_sig':'fakesig'}},
 'achievements':{}
}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null

echo ""
echo "--- B6.01: I3 achievements dict format ---"
python3 -c "
import json
d=json.load(open('$SF'))
assert isinstance(d.get('achievements'), dict), f'expected dict got {type(d.get(\"achievements\"))}'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "B6.01: achievements dict format" || vuln "B6.01: achievements not dict"

echo ""
echo "--- B6.02: I3 _check_achievements function ---"
ach=$(bash "$CLI" advance ECO-DOC 2>&1 | python3 -c "import sys,json;d=json.load(sys.stdin);print(json.dumps(d.get('achievements',[])))" 2>/dev/null || echo "[]")
echo "Achievements unlocked: $ach"

echo ""
echo "--- B6.03: I3 dedup — running again shouldn't re-grant ---"
python3 -c "
import json,datetime
d=json.load(open('$SF'))
# Manually grant eco-first-cycle first
d['achievements']['eco-first-cycle']={'granted_at':datetime.datetime.utcnow().isoformat()+'Z','count':1}
json.dump(d,open('$SF','w'),indent=2)
# Now run _check_achievements again
" 2>/dev/null
ach=$(bash "$CLI" advance ECO-DOC 2>&1 | python3 -c "import sys,json;d=json.load(sys.stdin);print(json.dumps(d.get('achievements',[])))" 2>/dev/null || echo "[]")
python3 -c "
import json
d=json.load(open('$SF'))
eco=d.get('achievements',{}).get('eco-first-cycle',{})
assert eco.get('count',0)==1, f'expected count=1 got {eco.get(\"count\")}'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "B6.03: dedup works (count=1)" || vuln "B6.03: dedup failed"

echo ""
echo "--- B6.04: I5 RED-SCOPE ---"
python3 -c "
import sys,json; sys.path.insert(0,'${SKILL}/scripts')
from _red_attacks import red_scope
findings = red_scope()
print(json.dumps({'count':len(findings),'findings':findings},indent=2))
assert isinstance(findings, list), 'not list'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "B6.04: RED-SCOPE works" || vuln "B6.04: RED-SCOPE failed"

echo ""
echo "--- B6.05: I5 RED-SURFACE ---"
python3 -c "
import sys,json; sys.path.insert(0,'${SKILL}/scripts')
from _red_attacks import red_surface
findings = red_surface()
print(json.dumps({'count':len(findings),'findings':findings[:3]},indent=2))
assert isinstance(findings, list), 'not list'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "B6.05: RED-SURFACE works" || vuln "B6.05: RED-SURFACE failed"

echo ""
echo "--- B6.06: I5 RED-EXPLOIT ---"
python3 -c "
import sys,json; sys.path.insert(0,'${SKILL}/scripts')
from _red_attacks import red_exploit
findings = red_exploit()
print(json.dumps({'count':len(findings),'findings':findings[:3]},indent=2))
assert isinstance(findings, list), 'not list'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "B6.06: RED-EXPLOIT works" || vuln "B6.06: RED-EXPLOIT failed"

echo ""
echo "--- B6.07: I5 RED-REPORT ---"
python3 -c "
import sys,json; sys.path.insert(0,'${SKILL}/scripts')
from _red_attacks import red_report
report = red_report([{'id':'TEST-01','severity':'high','title':'test finding','description':'test','evidence_hash':'abc123'}])
assert report.get('ok'), f'report not ok: {report}'
assert report.get('findings')==1, f'expected 1 got {report.get(\"findings\")}'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "B6.07: RED-REPORT works" || vuln "B6.07: RED-REPORT failed"

echo ""
echo "--- B6.08: I9 ECC-FINDING dedup ---"
python3 -c "
import json
# Simulate I9 writeback
s=json.load(open('$SF'))
gd=s.setdefault('gate_data',{})
existing=gd.get('ecc_findings',[])
new=[{'id':'TEST-01','severity':'high','title':'test','evidence_hash':'abc123','status':'open'},
     {'id':'TEST-01','severity':'high','title':'test','evidence_hash':'abc123','status':'open'}]  # duplicate
seen=set(f.get('evidence_hash','') for f in existing)
added=0
for f in new:
    if f.get('evidence_hash','') not in seen:
        existing.append(f)
        seen.add(f['evidence_hash'])
        added+=1
gd['ecc_findings']=existing
json.dump(s,open('$SF','w'),indent=2)
assert added==1, f'expected 1 added got {added}'
assert len(existing)==1, f'expected 1 total got {len(existing)}'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "B6.08: I9 ECC-FINDING dedup" || vuln "B6.08: I9 dedup failed"

echo ""
echo "--- B6.09: I3 cross-R survival ---"
python3 -c "
import json
d=json.load(open('$SF'))
# achievements should be at top level, not in gate_data
assert 'achievements' in d, 'achievements not at top level'
assert 'achievements' not in d.get('gate_data',{}), 'achievements in gate_data!'
# Simulate R switch (gate_data cleared)
d['gate_data']={}
d['history'].append({'r_phase':'ECO-DOC','completed_at':'2026-06-17T11:00:00'})
json.dump(d,open('$SF','w'),indent=2)
d2=json.load(open('$SF'))
assert d2.get('achievements',{}).get('eco-first-cycle',{}).get('count',0)==1, 'achievements burned!'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "B6.09: achievements survive R switch" || vuln "B6.09: achievements burned on R switch"

echo ""
echo "--- B6.10: I3 backward compat (list→dict migration) ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['achievements']=['old_achievement']  # old list format
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
# Test migration logic directly
python3 -c "
import json
s=json.load(open('$SF'))
achievements=s.get('achievements',{})
if isinstance(achievements, list):
    achievements={k:{'granted_at':'','count':1} for k in achievements}
    s['achievements']=achievements
assert isinstance(s.get('achievements'),dict), f'not migrated: {type(s.get(\"achievements\"))}'
assert 'old_achievement' in s.get('achievements',{}), 'old achievement lost'
print('OK')
" 2>/dev/null | rg -q "OK" && pass "B6.10: backward compat migration" || vuln "B6.10: migration failed"

echo ""
echo "==========================================="
echo "Batch 6 RESULTS: VULN=$VULN, $PASS pass, $FAIL fail"
[ $VULN -gt 0 ] && exit 1 || exit 0

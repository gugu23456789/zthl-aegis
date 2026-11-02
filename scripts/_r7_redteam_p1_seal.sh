#!/bin/bash
# Red-team: Phase 1 Sealed Scoring Attack Test
set +e
CLI="<home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh"
SKILL="<home>/.trae/skills/spz-gatekeeper-r-sequence"
SF="${REDTEAM_STATE:-${SKILL}/.gatekeeper.state}"  # 2026-08-14: 优先隔离 state（runner 设 REDTEAM_STATE），回退技能目录默认
PASS=0; FAIL=0; VULN=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
vuln() { echo "  VULN: $1"; VULN=$((VULN+1)); FAIL=$((FAIL+1)); }

echo "==========================================="
echo "Phase 1: Sealed Scoring Red-Team Test"
echo "==========================================="

# Setup state via Python file (avoids WSL quoting hell)
python3 "${SKILL}/scripts/_write_test_state.py" 2>/dev/null
echo ""

echo "--- Test 1: divergence reads _sealed_agent_score, not monitor_scores ---"
r=$(bash "$CLI" adjudicate \
  --verdicts '{"F1":"PASS","F2":"PASS","F3":"WARN","F4":"PASS","F5":"PASS","F6":"PASS","F7":"PASS"}' \
  --score 0.60 --decision "test sealed divergence" --stage ECO-EDIT \
  --concessions '{"F3":"acceptable risk"}' 2>&1)
echo "  adjudicate output: $r"
sealed_used=$(echo "$r" | python3 -c "
import sys,json
try:
    d=json.loads(sys.stdin.read())
    mon=d.get('monitor_score')
    if mon is None: print('sealed_none')
    elif abs(mon - 0.75) < 0.01: print('sealed_ok')
    else: print('other:' + str(mon))
except Exception as e: print('parse_error:' + str(e))
" 2>/dev/null || echo "pipe_error")
echo "  divergence source: $sealed_used"
if [ "$sealed_used" = "sealed_ok" ] || [ "$sealed_used" = "sealed_none" ]; then
  pass "P1-1: divergence reads _sealed_agent_score"
else
  vuln "P1-1: divergence reads wrong source: $sealed_used"
fi

echo ""
echo "--- Test 2: blind mode records correctly ---"
python3 "${SKILL}/scripts/_write_test_state.py" 2>/dev/null
r=$(bash "$CLI" adjudicate \
  --verdicts '{"F1":"PASS","F2":"PASS","F3":"PASS","F4":"PASS","F5":"PASS","F6":"PASS","F7":"PASS"}' \
  --score 0.70 --decision "blind test" --stage ECO-EDIT --blind 2>&1)
echo "  adjudicate output: $r"
blind_recorded=$(python3 -c "
import json
d=json.load(open('$SF'))
cl=d.get('gate_data',{}).get('human_calibration_log',[])
if cl and cl[-1].get('blind'):
    print('blind_ok')
elif cl:
    print('blind_not_recorded: blind=' + str(cl[-1].get('blind','MISSING')))
else:
    print('no_log')
" 2>/dev/null || echo "error")
echo "  blind result: $blind_recorded"
if echo "$blind_recorded" | rg -q "blind_ok"; then
  pass "P1-2: --blind mode recorded in calibration_log"
else
  fail "P1-2: blind mode not recorded: $blind_recorded"
fi

echo ""
echo "--- Test 3: checklist recording ---"
python3 "${SKILL}/scripts/_write_test_state.py" 2>/dev/null
r=$(bash "$CLI" adjudicate \
  --verdicts '{"F1":"PASS","F2":"PASS","F3":"PASS","F4":"PASS","F5":"PASS","F6":"PASS","F7":"PASS"}' \
  --score 0.85 --decision "checklist test" --stage ECO-EDIT \
  --checklist '[{"name":"scope","status":"PASS"},{"name":"deps","status":"PASS"},{"name":"risk","status":"WARN"}]' 2>&1)
echo "  adjudicate output: $r"
cl_ok=$(python3 -c "
import json
d=json.load(open('$SF'))
cl=d.get('gate_data',{}).get('human_calibration_log',[])
if cl:
    last=cl[-1]
    ct=last.get('checklist_total',0)
    cp=last.get('checklist_passed',0)
    if ct==3 and cp==2:
        print('checklist_ok')
    else:
        print('checklist_bad: total=' + str(ct) + ' passed=' + str(cp))
else:
    print('no_log')
" 2>/dev/null || echo "error")
echo "  checklist result: $cl_ok"
if echo "$cl_ok" | rg -q "checklist_ok"; then
  pass "P1-3: checklist total=3, passed=2"
else
  fail "P1-3: checklist wrong: $cl_ok"
fi

echo ""
echo "--- Test 4: change_items recording ---"
python3 "${SKILL}/scripts/_write_test_state.py" 2>/dev/null
r=$(bash "$CLI" adjudicate \
  --verdicts '{"F1":"PASS","F2":"PASS","F3":"PASS","F4":"PASS","F5":"PASS","F6":"PASS","F7":"PASS"}' \
  --score 0.90 --decision "change test" --stage ECO-EDIT --change-items 5 2>&1)
ci_ok=$(python3 -c "
import json
d=json.load(open('$SF'))
cl=d.get('gate_data',{}).get('human_calibration_log',[])
if cl and cl[-1].get('change_items',0)==5:
    print('ci_ok')
else:
    print('ci_bad')
" 2>/dev/null || echo "error")
echo "  change_items result: $ci_ok"
if echo "$ci_ok" | rg -q "ci_ok"; then
  pass "P1-4: change_items=5 recorded"
else
  fail "P1-4: change_items not recorded: $ci_ok"
fi

echo ""
echo "--- Test 5: constraint_level recording ---"
python3 "${SKILL}/scripts/_write_test_state.py" 2>/dev/null
r=$(bash "$CLI" adjudicate \
  --verdicts '{"F1":"PASS","F2":"PASS","F3":"PASS","F4":"PASS","F5":"PASS","F6":"PASS","F7":"PASS"}' \
  --score 0.88 --decision "constraint test" --stage ECO-EDIT --constraint-level "H1" 2>&1)
clv_ok=$(python3 -c "
import json
d=json.load(open('$SF'))
cl=d.get('gate_data',{}).get('human_calibration_log',[])
if cl and cl[-1].get('constraint_level','')=='H1':
    print('clv_ok')
else:
    print('clv_bad')
" 2>/dev/null || echo "error")
echo "  constraint_level result: $clv_ok"
if echo "$clv_ok" | rg -q "clv_ok"; then
  pass "P1-5: constraint_level=H1 recorded"
else
  fail "P1-5: constraint_level not recorded: $clv_ok"
fi

echo ""
echo "--- Test 6: seal isolation - sealed score not in monitor_scores ---"
isolation=$(python3 -c "
import json
d=json.load(open('$SF'))
sealed=d.get('gate_data',{}).get('_sealed_agent_score',{})
has_monitor_eco='ECO-EDIT' in d.get('monitor_scores',{})
sealed_ok=sealed.get('sealed',False)
if sealed_ok and not has_monitor_eco:
    print('isolation_ok')
elif sealed_ok and has_monitor_eco:
    print('monitor_scores_contaminated')
else:
    print('no_seal')
" 2>/dev/null || echo "error")
echo "  isolation result: $isolation"
if echo "$isolation" | rg -q "isolation_ok"; then
  pass "P1-6: _sealed_agent_score isolated from monitor_scores"
else
  vuln "P1-6: seal isolation failed: $isolation"
fi

echo ""
echo "--- Test 7: cap=50 calibration_log ---"
# Add 55 entries to calibration_log
python3 -c "
import json,time
d=json.load(open('$SF'))
cl=d.get('gate_data',{}).get('human_calibration_log',[])
for i in range(55):
    cl.append({'timestamp':time.time(),'test':i})
d['gate_data']['human_calibration_log']=cl
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" adjudicate \
  --verdicts '{"F1":"PASS","F2":"PASS","F3":"PASS","F4":"PASS","F5":"PASS","F6":"PASS","F7":"PASS"}' \
  --score 0.77 --decision "cap test" --stage ECO-EDIT 2>&1)
cap_ok=$(python3 -c "
import json
d=json.load(open('$SF'))
cl=d.get('gate_data',{}).get('human_calibration_log',[])
if len(cl)<=51:
    print('cap_ok:' + str(len(cl)))
else:
    print('cap_bad:' + str(len(cl)))
" 2>/dev/null || echo "error")
echo "  cap result: $cap_ok"
if echo "$cap_ok" | rg -q "cap_ok"; then
  pass "P1-7: calibration_log capped: $cap_ok"
else
  fail "P1-7: cap broken: $cap_ok"
fi

echo ""
echo "==========================================="
echo "Phase 1 RESULTS: VULN=$VULN, $PASS pass, $FAIL fail"
[ $VULN -gt 0 ] && exit 1 || exit 0

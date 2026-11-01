#!/bin/bash
# Red-team: ECO escape/penetration vulnerabilities
set +e
CLI="<home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh"
SKILL="<home>/.trae/skills/spz-gatekeeper-r-sequence"
STATE="${REDTEAM_STATE:-${SKILL}/.gatekeeper.state}"  # 2026-08-14: 优先隔离 state（runner 设 REDTEAM_STATE），回退技能目录默认
PASS=0; FAIL=0; VULN=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
vuln() { echo "  VULN: $1"; VULN=$((VULN+1)); FAIL=$((FAIL+1)); }

echo "==========================================="
echo "ECO Escape/Penetration Red-Team"
echo "==========================================="

echo ""
echo "--- ECO.01: resolve force_advance blocked when appeal_required ---"
# Set appeal_required flag
python3 -c "
import json,hashlib
d=json.load(open('$STATE'))
d['gate_data']['appeal_required']='ECO-AUDIT'
gd=d['gate_data']
h=hashlib.sha256(json.dumps(gd,sort_keys=True).encode()).hexdigest()[:16]
d['_checksum']=h
json.dump(d,open('$STATE','w'),indent=2)
" 2>/dev/null
result=$(bash "$CLI" resolve ECO-AUDIT force_advance "test" 2>/dev/null)
echo "$result" | rg -q "APPEAL_REQUIRED_BEFORE_RESOLVE" && pass "ECO.01: resolve blocked" || vuln "ECO.01: resolve not blocked"
# Clean up
python3 -c "
import json,hashlib
d=json.load(open('$STATE'))
d['gate_data'].pop('appeal_required',None)
gd=d['gate_data']
h=hashlib.sha256(json.dumps(gd,sort_keys=True).encode()).hexdigest()[:16]
d['_checksum']=h
json.dump(d,open('$STATE','w'),indent=2)
" 2>/dev/null

echo ""
echo "--- ECO.02: advance blocked on checksum mismatch ---"
# Tamper with checksum
python3 -c "
import json
d=json.load(open('$STATE'))
d['_checksum']='0000000000000000'
json.dump(d,open('$STATE','w'),indent=2)
" 2>/dev/null
result=$(bash "$CLI" advance ECO-AUDIT 2>/dev/null)
echo "$result" | rg -q "STATE_FILE_TAMPERED" && pass "ECO.02: tampered checksum blocked" || vuln "ECO.02: tampered checksum not blocked"
# Restore
python3 -c "
import json,hashlib
d=json.load(open('$STATE'))
gd=d['gate_data']
h=hashlib.sha256(json.dumps(gd,sort_keys=True).encode()).hexdigest()[:16]
d['_checksum']=h
json.dump(d,open('$STATE','w'),indent=2)
" 2>/dev/null

echo ""
echo "--- ECO.03: adjudicate records written to state ---"
python3 -c "
import json,hashlib
d=json.load(open('$STATE'))
gd=d['gate_data']
gd['adjudicate_records']=[]
gd['human_calibration_log']=[]
h=hashlib.sha256(json.dumps(gd,sort_keys=True).encode()).hexdigest()[:16]
d['_checksum']=h
json.dump(d,open('$STATE','w'),indent=2)
" 2>/dev/null
bash "$CLI" adjudicate --verdicts '{"F1":"PASS","F2":"PASS","F3":"PASS","F4":"PASS","F5":"PASS","F6":"PASS","F7":"PASS"}' --score 0.90 --decision "test" --concessions "{}" 2>/dev/null
count=$(python3 -c "import json;d=json.load(open('$STATE'));print(len(d.get('gate_data',{}).get('adjudicate_records',[])))" 2>/dev/null)
[ "$count" -gt 0 ] && pass "ECO.03: adjudicate wrote $count records" || vuln "ECO.03: adjudicate wrote 0 records"

echo ""
echo "--- ECO.04: advance auto-updates checksum ---"
# Get checksum before advance
before=$(python3 -c "import json;d=json.load(open('$STATE'));print(d.get('_checksum',''))" 2>/dev/null)
# Advance
bash "$CLI" advance ECO-DOC 2>/dev/null
after=$(python3 -c "import json;d=json.load(open('$STATE'));print(d.get('_checksum',''))" 2>/dev/null)
[ "$before" != "$after" ] && pass "ECO.04: checksum updated after advance" || vuln "ECO.04: checksum not updated"

echo ""
echo "--- ECO.05: foreign content guard in appeal ---"
result=$(bash "$CLI" appeal ECO-AUDIT "<home>\test" 2>/dev/null)
echo "$result" | rg -q "FOREIGN_CONTENT_DETECTED" && pass "ECO.05: foreign content blocked" || vuln "ECO.05: foreign content not blocked"

echo ""
echo "--- ECO.06: foreign content guard in resolve ---"
result=$(bash "$CLI" resolve ECO-AUDIT manual_fix "<home>\test" 2>/dev/null)
echo "$result" | rg -q "FOREIGN_CONTENT_DETECTED" && pass "ECO.06: resolve foreign content blocked" || vuln "ECO.06: resolve foreign content not blocked"

echo ""
echo "--- ECO.07: gate validation in resolve ---"
result=$(bash "$CLI" resolve INVALID_GATE manual_fix "test" 2>/dev/null)
echo "$result" | rg -q "Unknown gate" && pass "ECO.07: invalid gate blocked" || vuln "ECO.07: invalid gate not blocked"

echo ""
echo "--- ECO.08: reason injection in resolve ---"
result=$(bash "$CLI" resolve ECO-AUDIT manual_fix 'test"; rm -rf /; echo "' 2>/dev/null)
echo "$result" | rg -q "FOREIGN_CONTENT_DETECTED|ok.*true|ok.*false" && pass "ECO.08: reason injection handled" || vuln "ECO.08: reason injection not handled"

echo ""
echo "--- ECO.09: audit --crossr uses subagent_runner ---"
rg -q "subagent_runner.py" "${SKILL}/gatekeeper-cli.sh" && pass "ECO.09: crossr uses subagent_runner" || vuln "ECO.09: crossr missing subagent_runner"

echo ""
echo "--- ECO.10: audit --all includes report ---"
rg -q "audit --report" "${SKILL}/gatekeeper-cli.sh" && pass "ECO.10: --all includes report" || vuln "ECO.10: --all missing report"

echo ""
echo "--- ECO.11: audit --depth has dead code gate ---"
rg -q "dead_code_risk" "${SKILL}/gatekeeper-cli.sh" && pass "ECO.11: --depth has dead_code_risk" || vuln "ECO.11: --depth missing dead_code_risk"

echo ""
echo "--- ECO.12: parallel audit uses bash & + wait ---"
rg -q 'bash "$0" audit.*&$' "${SKILL}/gatekeeper-cli.sh" && pass "ECO.12: parallel audit uses bash &" || vuln "ECO.12: parallel audit missing bash &"

echo ""
echo "--- ECO.13: resolve force_advance blocked (no appeal_required) ---"
# Set active stage so resolve passes stage_constraint check
python3 -c "
import json,hashlib
d=json.load(open('$STATE'))
d['stage']='ECO-AUDIT'
d['r_phase']='ECO-AUDIT'
d['gate_data'].pop('appeal_required',None)
gd=d['gate_data']
h=hashlib.sha256(json.dumps(gd,sort_keys=True).encode()).hexdigest()[:16]
d['_checksum']=h
json.dump(d,open('$STATE','w'),indent=2)
" 2>/dev/null
# Without appeal_required, resolve should work
result=$(bash "$CLI" resolve ECO-AUDIT manual_fix "test" 2>/dev/null)
echo "$result" | rg -q '"ok":true' && pass "ECO.13: resolve works without appeal_required" || vuln "ECO.13: resolve blocked without appeal_required"

echo ""
echo "--- ECO.14: appeal denied permanently ---"
# Check if appeal_denied_gates is respected
python3 -c "
import json,hashlib
d=json.load(open('$STATE'))
d['gate_data']['appeal_denied_gates']=['ECO-AUDIT']
gd=d['gate_data']
h=hashlib.sha256(json.dumps(gd,sort_keys=True).encode()).hexdigest()[:16]
d['_checksum']=h
json.dump(d,open('$STATE','w'),indent=2)
" 2>/dev/null
result=$(bash "$CLI" appeal ECO-AUDIT "test" 2>/dev/null)
echo "$result" | rg -q "APPEAL_DENIED_PERMANENTLY" && pass "ECO.14: permanently denied appeal blocked" || vuln "ECO.14: permanently denied appeal not blocked"
# Clean up
python3 -c "
import json,hashlib
d=json.load(open('$STATE'))
d['gate_data'].pop('appeal_denied_gates',None)
gd=d['gate_data']
h=hashlib.sha256(json.dumps(gd,sort_keys=True).encode()).hexdigest()[:16]
d['_checksum']=h
json.dump(d,open('$STATE','w'),indent=2)
" 2>/dev/null

echo ""
echo "--- ECO.15: audit --all output has all 5 fields ---"
result=$(bash "$CLI" audit --all 2>/dev/null)
echo "$result" | python3 -c "
import sys,json
d=json.load(sys.stdin)
fields=['state','docs','memory','crossr','report']
missing=[f for f in fields if f not in d]
if not missing: print('PASS: all 5 fields present')
else: print('VULN: missing fields:', missing)
" 2>/dev/null | rg -q "PASS" && pass "ECO.15: --all has all 5 fields" || vuln "ECO.15: --all missing fields"

echo ""
echo "==========================================="
echo "ECO Escape RESULTS: VULN=$VULN, $PASS pass, $FAIL fail"
[ $VULN -gt 0 ] && exit 1 || exit 0

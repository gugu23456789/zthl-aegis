#!/bin/bash
# Red-team: Batch 1 — D1 checksum tamper + D3 foreign content guard
# Attack vectors: subtle, stealthy, edge-case
set +e
CLI="<home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh"
SKILL="<home>/.trae/skills/spz-gatekeeper-r-sequence"
SF="${REDTEAM_STATE:-${SKILL}/.gatekeeper.state}"  # 2026-08-14: 优先隔离 state（runner 设 REDTEAM_STATE），回退技能目录默认
PASS=0; FAIL=0; VULN=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
vuln() { echo "  VULN: $1"; VULN=$((VULN+1)); FAIL=$((FAIL+1)); }

echo "==========================================="
echo "Batch 1: D1 Checksum + D3 Foreign Content Red-Team"
echo "==========================================="

# Setup clean state
python3 "${SKILL}/scripts/_write_test_state.py" 2>/dev/null
# Ensure checksum exists
bash "$CLI" discover > /dev/null 2>&1

echo ""
echo "=== D1: Checksum Tamper Attacks ==="

echo "--- D1-A1: Direct gate_data tamper (flip a bit) ---"
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['fake_field']='tampered_value'
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" advance ECO-EDIT 2>&1)
if echo "$r" | rg -q "TAMPERED|checksum"; then
  pass "D1-A1: direct tamper detected and blocked"
else
  vuln "D1-A1: direct tamper NOT detected: $(echo "$r" | head -c 100)"
fi

echo ""
echo "--- D1-A2: Tamper + preserve old checksum (leave _checksum unchanged) ---"
python3 "${SKILL}/scripts/_write_test_state.py" 2>/dev/null
bash "$CLI" discover > /dev/null 2>&1
# Read current checksum, tamper gate_data, keep old checksum
python3 -c "
import json
d=json.load(open('$SF'))
old_checksum=d.get('_checksum','')
d['gate_data']['_sealed_agent_score']={'score':0.99,'sealed':True,'verdicts':{},'fake':True}
d['_checksum']=old_checksum  # keep old checksum
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" advance ECO-EDIT 2>&1)
if echo "$r" | rg -q "TAMPERED|checksum"; then
  pass "D1-A2: tamper with stale checksum detected"
else
  vuln "D1-A2: tamper with stale checksum NOT detected: $(echo "$r" | head -c 100)"
fi

echo ""
echo "--- D1-A3: Tamper _checksum field itself (forge a fake checksum) ---"
python3 "${SKILL}/scripts/_write_test_state.py" 2>/dev/null
bash "$CLI" discover > /dev/null 2>&1
python3 -c "
import json
d=json.load(open('$SF'))
d['_checksum']='0000000000000000'  # fake checksum
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" advance ECO-EDIT 2>&1)
if echo "$r" | rg -q "TAMPERED|checksum"; then
  pass "D1-A3: forged checksum detected"
else
  vuln "D1-A3: forged checksum NOT detected: $(echo "$r" | head -c 100)"
fi

echo ""
echo "--- D1-A4: Remove _checksum entirely (no checksum = no protection) ---"
python3 "${SKILL}/scripts/_write_test_state.py" 2>/dev/null
bash "$CLI" discover > /dev/null 2>&1
python3 -c "
import json
d=json.load(open('$SF'))
d.pop('_checksum',None)
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" advance ECO-EDIT 2>&1)
# Missing checksum should NOT block (first-time or legacy state)
if echo "$r" | rg -q "TAMPERED"; then
  vuln "D1-A4: missing checksum BLOCKED (false positive — should allow)"
else
  pass "D1-A4: missing checksum allowed (correct: no checksum = no tamper claim)"
fi

echo ""
echo "--- D1-A5: Verify tamper detection does NOT write state (D1 fix) ---"
python3 "${SKILL}/scripts/_write_test_state.py" 2>/dev/null
bash "$CLI" discover > /dev/null 2>&1
python3 -c "
import json
d=json.load(open('$SF'))
d['gate_data']['injected']='malicious'
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
# Read file mtime before
mtime_before=$(python3 -c "import os;print(int(os.path.getmtime('$SF')))" 2>/dev/null)
bash "$CLI" advance ECO-EDIT > /dev/null 2>&1
mtime_after=$(python3 -c "import os;print(int(os.path.getmtime('$SF')))" 2>/dev/null)
# Check if _checksum_warning was written (D1 fix: should NOT be written)
has_warning=$(python3 -c "
import json
d=json.load(open('$SF'))
print('yes' if '_checksum_warning' in d else 'no')
" 2>/dev/null || echo "unknown")
if [ "$has_warning" = "no" ]; then
  pass "D1-A5: tamper detection did NOT write _checksum_warning (D1 fix working)"
else
  vuln "D1-A5: _checksum_warning still written on tamper (D1 fix incomplete)"
fi

echo ""
echo "=== D3: Foreign Content Guard Attacks ==="

# Setup clean state for D3 tests
python3 "${SKILL}/scripts/_write_test_state.py" 2>/dev/null
bash "$CLI" discover > /dev/null 2>&1

echo "--- D3-A1: Direct <home> path ---"
r=$(bash "$CLI" appeal ECO-EDIT "check <home>\project\file.py" 2>&1)
if echo "$r" | rg -q "FOREIGN_CONTENT"; then
  pass "D3-A1: <home> blocked"
else
  vuln "D3-A1: <home> NOT blocked: $(echo "$r" | head -c 80)"
fi

echo ""
echo "--- D3-A2: Forward slash variant <home> ---"
r=$(bash "$CLI" appeal ECO-EDIT "see <home>/project" 2>&1)
if echo "$r" | rg -q "FOREIGN_CONTENT"; then
  pass "D3-A2: <home> blocked"
else
  vuln "D3-A2: <home> NOT blocked: $(echo "$r" | head -c 80)"
fi

echo ""
echo "--- D3-A3: Mixed case C:\USERS\PENG ---"
r=$(bash "$CLI" appeal ECO-EDIT "ref C:\USERS\PENG\file" 2>&1)
if echo "$r" | rg -q "FOREIGN_CONTENT"; then
  pass "D3-A3: C:\\USERS\\PENG blocked (case insensitive)"
else
  vuln "D3-A3: C:\\USERS\\PENG NOT blocked: $(echo "$r" | head -c 80)"
fi

echo ""
echo "--- D3-A4: xhs-copilot marker ---"
r=$(bash "$CLI" appeal ECO-EDIT "from xhs-copilot context" 2>&1)
if echo "$r" | rg -q "FOREIGN_CONTENT"; then
  pass "D3-A4: xhs-copilot blocked"
else
  vuln "D3-A4: xhs-copilot NOT blocked: $(echo "$r" | head -c 80)"
fi

echo ""
echo "--- D3-A5: Unicode variant \u5c0f\u7ea2\u4e66 (小红书) ---"
r=$(bash "$CLI" appeal ECO-EDIT "from 小红书 project" 2>&1)
if echo "$r" | rg -q "FOREIGN_CONTENT"; then
  pass "D3-A5: 小红书 blocked"
else
  vuln "D3-A5: 小红书 NOT blocked: $(echo "$r" | head -c 80)"
fi

echo ""
echo "--- D3-A6: Clean notes should pass ---"
r=$(bash "$CLI" appeal ECO-EDIT "legitimate appeal: plan scope is correct" 2>&1)
if echo "$r" | rg -q "FOREIGN_CONTENT"; then
  vuln "D3-A6: clean notes incorrectly blocked"
else
  pass "D3-A6: clean notes passed (no false positive)"
fi

echo ""
echo "--- D3-A7: Subtle injection in longer text ---"
r=$(bash "$CLI" appeal ECO-EDIT "the plan looks good but check <home>\secret\config.json for details" 2>&1)
if echo "$r" | rg -q "FOREIGN_CONTENT"; then
  pass "D3-A7: subtle <home> injection blocked"
else
  vuln "D3-A7: subtle injection NOT blocked: $(echo "$r" | head -c 80)"
fi

echo ""
echo "--- D3-A8: identity-tracker marker ---"
r=$(bash "$CLI" appeal ECO-EDIT "imported from identity-tracker module" 2>&1)
if echo "$r" | rg -q "FOREIGN_CONTENT"; then
  pass "D3-A8: identity-tracker blocked"
else
  vuln "D3-A8: identity-tracker NOT blocked: $(echo "$r" | head -c 80)"
fi

echo ""
echo "=== D3 Extended: Two-Layer Boundary Attacks ==="

echo "--- D3-A9: WSL path <home> ---"
r=$(bash "$CLI" appeal ECO-EDIT "see <home>/project" 2>&1)
if echo "$r" | rg -q "FOREIGN_CONTENT"; then
  pass "D3-A9: <home> blocked"
else
  vuln "D3-A9: <home> NOT blocked: $(echo "$r" | head -c 80)"
fi

echo ""
echo "--- D3-A10: Linux path /home/alice ---"
r=$(bash "$CLI" appeal ECO-EDIT "see /home/alice/project" 2>&1)
if echo "$r" | rg -q "FOREIGN_CONTENT"; then
  pass "D3-A10: /home/alice blocked"
else
  vuln "D3-A10: /home/alice NOT blocked: $(echo "$r" | head -c 80)"
fi

echo ""
echo "--- D3-A11: Whitelisted 'Public' should pass ---"
r=$(bash "$CLI" appeal ECO-EDIT "see <home>\file.txt" 2>&1)
if echo "$r" | rg -q "FOREIGN_CONTENT"; then
  vuln "D3-A11: <home> false positive (should be whitelisted)"
else
  pass "D3-A11: <home> allowed (whitelisted)"
fi

echo ""
echo "--- D3-A12: 副驾驶 marker ---"
r=$(bash "$CLI" appeal ECO-EDIT "from 副驾驶 project" 2>&1)
if echo "$r" | rg -q "FOREIGN_CONTENT"; then
  pass "D3-A12: 副驾驶 blocked"
else
  vuln "D3-A12: 副驾驶 NOT blocked: $(echo "$r" | head -c 80)"
fi

echo ""
echo "--- D3-A13: pc-web marker ---"
r=$(bash "$CLI" appeal ECO-EDIT "from pc-web module" 2>&1)
if echo "$r" | rg -q "FOREIGN_CONTENT"; then
  pass "D3-A13: pc-web blocked"
else
  vuln "D3-A13: pc-web NOT blocked: $(echo "$r" | head -c 80)"
fi

echo ""
echo "--- D3-A14: Unknown user <home> ---"
r=$(bash "$CLI" appeal ECO-EDIT "check <home>\config" 2>&1)
if echo "$r" | rg -q "FOREIGN_CONTENT"; then
  pass "D3-A14: <home> blocked (generic pattern)"
else
  vuln "D3-A14: <home> NOT blocked: $(echo "$r" | head -c 80)"
fi

echo ""
echo "--- D3-A15: Empty notes should pass ---"
r=$(bash "$CLI" appeal ECO-EDIT "" 2>&1)
if echo "$r" | rg -q "FOREIGN_CONTENT"; then
  vuln "D3-A15: empty notes false positive"
else
  pass "D3-A15: empty notes allowed (no false positive)"
fi

echo ""
echo "--- D3-A16: Windows system dir 'Default' should pass ---"
r=$(bash "$CLI" appeal ECO-EDIT "<home>\Desktop" 2>&1)
if echo "$r" | rg -q "FOREIGN_CONTENT"; then
  vuln "D3-A16: <home> false positive (whitelisted)"
else
  pass "D3-A16: <home> allowed (whitelisted)"
fi

echo ""
echo "--- D3-A17: Nested marker in long text ---"
r=$(bash "$CLI" appeal ECO-EDIT "The plan analysis shows F3=WARN. However, when we checked <home>/workspace/config.json the dependency chain was broken. Recommend revising scope." 2>&1)
if echo "$r" | rg -q "FOREIGN_CONTENT"; then
  pass "D3-A17: nested <home> in long text blocked"
else
  vuln "D3-A17: nested WSL path NOT blocked: $(echo "$r" | head -c 80)"
fi

echo ""
echo "=== D1 Extended: Checksum Edge Cases ==="

echo "--- D1-A6: Empty gate_data (should not crash verify) ---"
python3 -c "
import json
d={'r_phase':'ECO-EDIT','stage':'ECO-EDIT','branch':'master','worktree':'${SKILL}','main_repo':'${SKILL}','gate_data':{},'monitor_scores':{},'history':[],'_checksum':''}
json.dump(d,open('$SF','w'),indent=2)
" 2>/dev/null
r=$(bash "$CLI" advance ECO-EDIT 2>&1)
# Empty checksum = no tamper claim, should proceed
if echo "$r" | rg -q "TAMPERED"; then
  vuln "D1-A6: empty checksum BLOCKED (false positive)"
else
  pass "D1-A6: empty checksum allowed (no tamper claim)"
fi

echo ""
echo "--- D1-A7: Checksum with corrupted JSON (malformed state) ---"
echo '{"r_phase":"ECO-EDIT","stage":"ECO-EDIT","gate_data":{"broken":true},"bad json' > "$SF"
r=$(bash "$CLI" advance ECO-EDIT 2>&1)
if echo "$r" | rg -q "error|TAMPERED|parse"; then
  pass "D1-A7: corrupted JSON handled gracefully"
else
  vuln "D1-A7: corrupted JSON not handled: $(echo "$r" | head -c 80)"
fi

echo ""
echo "==========================================="
echo "Batch 1 RESULTS: VULN=$VULN, $PASS pass, $FAIL fail"
[ $VULN -gt 0 ] && exit 1 || exit 0

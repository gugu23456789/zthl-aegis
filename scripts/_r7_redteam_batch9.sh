#!/bin/bash
# Red-team: Batch 9 Phase 1 — audit capability enhancement
set +e
CLI="<home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh"
SKILL="<home>/.trae/skills/spz-gatekeeper-r-sequence"
PASS=0; FAIL=0; VULN=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
vuln() { echo "  VULN: $1"; VULN=$((VULN+1)); FAIL=$((FAIL+1)); }

echo "==========================================="
echo "Batch 9 Phase 1 Red-Team"
echo "==========================================="

echo ""
echo "--- B9.01: audit --crossr uses subagent_runner ---"
rg -q "subagent_runner.py" "${SKILL}/gatekeeper-cli.sh" && pass "B9.01: crossr uses subagent_runner" || vuln "B9.01: crossr still uses raw curl"

echo ""
echo "--- B9.02: audit --crossr no raw curl ---"
# Check the crossr section specifically for curl POST to API
crossr_section=$(sed -n '/--crossr|crossr)/,/^;;$/p' "${SKILL}/gatekeeper-cli.sh")
echo "$crossr_section" | rg -q "curl -s -X POST.*chat/completions" && vuln "B9.02: crossr still has raw curl to API" || pass "B9.02: no raw curl to API in crossr"

echo ""
echo "--- B9.03: audit --all includes report ---"
rg -q "r_result.*audit --report" "${SKILL}/gatekeeper-cli.sh" && pass "B9.03: --all includes --report" || vuln "B9.03: --all missing --report"

echo ""
echo "--- B9.04: audit --depth exists ---"
rg -q "\-\-depth|depth)" "${SKILL}/gatekeeper-cli.sh" && pass "B9.04: --depth exists" || vuln "B9.04: --depth missing"

echo ""
echo "--- B9.05: audit --depth calls gitnexus context ---"
depth_section=$(sed -n '/--depth|depth)/,/^;;$/p' "${SKILL}/gatekeeper-cli.sh")
echo "$depth_section" | rg -q "gitnexus context" && pass "B9.05: --depth calls gitnexus context" || vuln "B9.05: --depth missing gitnexus context"

echo ""
echo "--- B9.06: audit --depth calls detect-changes ---"
echo "$depth_section" | rg -q "detect-changes" && pass "B9.06: --depth calls detect-changes" || vuln "B9.06: --depth missing detect-changes"

echo ""
echo "--- B9.07: audit --depth has dead code 3-gate ---"
echo "$depth_section" | rg -q "production_consumer" && pass "B9.07: --depth has dead code gate" || vuln "B9.07: --depth missing dead code gate"

echo ""
echo "--- B9.08: audit --depth has dead_code_risk ---"
echo "$depth_section" | rg -q "dead_code_risk" && pass "B9.08: --depth has dead_code_risk" || vuln "B9.08: --depth missing dead_code_risk"

echo ""
echo "--- B9.09: audit --all output includes report field ---"
# Check the Python code that builds all_results
all_section=$(sed -n '/I1: Unified audit/,/^;;$/p' "${SKILL}/gatekeeper-cli.sh")
echo "$all_section" | rg -q "'report':r" && pass "B9.09: --all output has report field" || vuln "B9.09: --all output missing report field"

echo ""
echo "--- B9.10: audit --depth in usage string ---"
rg -q "depth" "${SKILL}/gatekeeper-cli.sh" && pass "B9.10: --depth in code" || vuln "B9.10: --depth missing"

echo ""
echo "==========================================="
echo "Batch 9 Phase 1 RESULTS: VULN=$VULN, $PASS pass, $FAIL fail"
[ $VULN -gt 0 ] && exit 1 || exit 0

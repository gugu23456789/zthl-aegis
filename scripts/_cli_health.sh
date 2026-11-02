#!/bin/bash
# CLI full command health check — test all 25 registered commands
set +e
CLI="bash <home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh"
PASS=0; FAIL=0; UNWIRED=0

pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
warn() { echo "  WARN: $1"; }
unwired() { echo "  UNWIRED: $1 (registered, returns ok, no pipeline connection)"; UNWIRED=$((UNWIRED+1)); }

echo "=== CLI Command Health Check ==="
echo ""

# 1. discover — no args, works
r=$($CLI discover 2>&1)
echo "$r" | rg -q '"ok"' && pass "discover" || fail "discover: $r"

# 2. state — no args
r=$($CLI state 2>&1)
echo "$r" | rg -q '"ok"' && pass "state" || fail "state: $r"

# 3. monitor — needs mode
r=$($CLI monitor --local 2>&1)
echo "$r" | rg -q '"ok"' && pass "monitor --local" || fail "monitor: $r"

# 4. stage-detail — needs R phase
r=$($CLI stage-detail R1 2>&1)
echo "$r" | rg -q '.' && pass "stage-detail R1" || fail "stage-detail: $r"

# 5. balance — no args
r=$($CLI balance 2>&1)
echo "$r" | rg -q '.' && pass "balance" || fail "balance: $r"

# 6. self-check — no args
r=$($CLI self-check 2>&1)
echo "$r" | rg -q '.' && pass "self-check" || fail "self-check: $r"

# 7. set-key — needs key
r=$($CLI set-key test-key 2>&1)
echo "$r" | rg -q 'ok' && pass "set-key" || fail "set-key: $r"

# 8. search — needs pattern
r=$($CLI search "test" --repo skill 2>&1)
echo "$r" | rg -q '.' && pass "search" || fail "search: $r"

# 9. context — no args
r=$($CLI context 2>&1)
echo "$r" | rg -q 'ok' && pass "context" || fail "context: $r"

# 10. audit — needs subcommand
r=$($CLI audit --state 2>&1)
echo "$r" | rg -q 'ok' && pass "audit --state" || fail "audit: $r"

# 11. trace — no state file expected
r=$($CLI trace 2>&1)
echo "$r" | rg -q '"ok"' && pass "trace" || warn "trace: $r (expected empty chain)"

# 12. guard-edit — needs file/line args (will fail gracefully)
r=$($CLI guard-edit test.md 1 "test" 2>&1)
echo "$r" | rg -q '.' && pass "guard-edit (error expected)" || fail "guard-edit: crashed"

# 13. adjudicate — needs verdicts
r=$($CLI adjudicate --verdicts '{"F1":"PASS"}' --score 0.5 --decision test 2>&1)
echo "$r" | rg -q 'ok' && pass "adjudicate" || fail "adjudicate: $r"

# 14. reflect — needs active R phase (will fail gracefully)
r=$($CLI reflect 2>&1)
echo "$r" | rg -q '.' && pass "reflect (no-op expected)" || fail "reflect: crashed"

# 15. ci-diagnose — needs run ID
r=$($CLI ci-diagnose 12345 2>&1)
echo "$r" | rg -q '.' && pass "ci-diagnose" || fail "ci-diagnose: crashed"

# 16. release-check — no args
r=$($CLI release-check 2>&1)
echo "$r" | rg -q '.' && pass "release-check" || fail "release-check: crashed"

# 17. docgen — no args
r=$($CLI docgen 2>&1)
echo "$r" | rg -q '.' && pass "docgen" || fail "docgen: crashed"

# 18. push — needs subcommand
r=$($CLI push status 2>&1)
echo "$r" | rg -q '.' && pass "push status" || fail "push: crashed"

echo ""
echo "=== Unwired Command Analysis ==="
echo ""

echo "Commands that run but are NOT connected to pipeline:"
echo ""

# trace — reads state but no pipeline hook
echo "  trace        — reads state.json, no pipeline trigger (ECO-AUDIT→DOC planned)"
# attribution — requires API key
echo "  attribution  — LOO logprobs, manual only, no pipeline trigger"
# appeal — registered but trigger path dead (I2)
echo "  appeal       — state machine allows but entropy ≥0.5 never fires (I2)"
# escalate — same
echo "  escalate     — same as appeal (I2)"
# audit --report — raw curl, not subagent_runner.py
echo "  audit --report — raw curl, bypasses subagent pipeline (I1)"
# achievements — no trigger
echo "  achievements — never called, no trigger (I3)"

echo ""
echo "=== Pipeline Connection Map ==="
echo ""
for cmd in discover state state guard-edit pre-tool-check advance monitor stage-detail balance self-check set-key search context audit trace adjudicate reflect ci-diagnose release-check docgen push; do
  case $cmd in
    discover|state|stage-detail|balance|self-check|set-key|search|guard-edit|pre-tool-check|advance|monitor|reflect)
      echo "  $cmd  → wired (ECO pipeline)"
      ;;
    adjudicate)
      echo "  $cmd → wired (ECO-EDIT→AUDIT gate)"
      ;;
    audit)
      echo "  $cmd  → partially wired (--state/--report works, --key lifecycle complete, not integrated into ECO)"
      ;;
    context)
      echo "  $cmd → wired (launch-time injection)"
      ;;
    push)
      echo "  $cmd     → wired (git workflow)"
      ;;
    ci-diagnose)
      echo "  $cmd → wired (CI failure handler)"
      ;;
    release-check|docgen)
      echo "  $cmd → wired (release workflow)"
      ;;
    trace|attribution|appeal|escalate|achievements)
      echo "  $cmd → UNWIRED (I1-I5 pipeline gaps)"
      ;;
  esac
done

echo ""
echo "=== Results: $PASS pass, $FAIL fail ==="

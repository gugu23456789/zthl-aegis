#!/usr/bin/env python3
"""D8: Decision replay — deterministic gate replay + format validation"""
import json, sys, os
sf = sys.argv[1] if len(sys.argv) > 1 else os.environ.get('STATE_FILE', '')
if not sf or not os.path.exists(sf):
    print(json.dumps({"ok": False, "error": "No state file"})); sys.exit(1)
with open(sf) as f: d = json.load(f)
h = d.get('history', [])
gd = d.get('gate_data', {})
adv_log = gd.get('_advance_log', [])
# Collect all advance logs (current + history)
all_logs = list(adv_log)
for entry in h:
    all_logs.extend(entry.get('advance_log', []))
if not all_logs:
    print(json.dumps({"ok": True, "replayed": 0, "matched": 0, "diverged": 0, "message": "No advance logs to replay"})); sys.exit(0)

# Phase 1: Format validation
replayed = 0; matched = 0; diverged = 0; divergences = []
for log in all_logs:
    replayed += 1
    # entropy_rate in [0,1]
    er = float(log.get('entropy_rate', 0.0))
    if er < 0.0 or er > 1.0:
        diverged += 1; divergences.append({"entry": log.get("to_stage"), "issue": "entropy_rate=%s out of [0,1]" % er})
    # timestamp ISO format
    ts = log.get('timestamp', '')
    if not ts or 'T' not in str(ts):
        diverged += 1; divergences.append({"entry": log.get("to_stage"), "issue": "invalid timestamp"})
    # all_ok boolean
    if log.get('all_ok') not in (True, False):
        diverged += 1; divergences.append({"entry": log.get("to_stage"), "issue": "all_ok not boolean"})
    # to_stage in known stages
    valid_stages = {"ECO-RESEARCH","ECO-EDIT","ECO-VERIFY","ECO-DOC",
                    "ECO-SCAN","ECO-READ","ECO-AUDIT",
                    "ECC-ANALYSIS","ECC-SCOPE","ECC-PLAN","ECC-VERIFY","ECC-MERGE",
                    "RED-SCOPE","RED-SURFACE","RED-CONSTRAINTS","RED-EXPLOIT","RED-POSTEX","RED-REPORT"}
    to = log.get('to_stage', '')
    if to and to not in valid_stages:
        diverged += 1; divergences.append({"entry": to, "issue": "unknown stage"})
    # gates_count reasonable
    gc = log.get('gates_count', 0)
    if gc < 1 or gc > 10:
        diverged += 1; divergences.append({"entry": to, "issue": "gates_count=%s unreasonable" % gc})
    if not divergences or divergences[-1].get("entry") != to:
        matched += 1

# Phase 2: Deterministic replay — verify gate logic consistency
# Re-derive expected all_ok from gate conditions
replay_checks = []
for log in all_logs:
    to = log.get('to_stage', '')
    declared_ok = log.get('all_ok')
    # Re-derive: what should all_ok be?
    # Based on gate_data state at that point
    expected_ok = True
    issues = []
    # Gate: entropy < 0.5 for advance
    er = float(log.get('entropy_rate', 0.0))
    if er > 0.5 and declared_ok == True:
        expected_ok = False
        issues.append("entropy=%s>0.5 but all_ok=True" % er)
    # Gate: edit_budget remaining > 0
    eb = gd.get('edit_budget', {})
    remaining = eb.get('remaining', eb.get('max', 3) - eb.get('used', 0))
    if remaining <= 0 and declared_ok == True:
        expected_ok = False
        issues.append("edit_budget=0 but all_ok=True")
    # Gate: no open ECC findings
    ecc_open = sum(1 for f in gd.get('ecc_findings', []) if f.get('status') == 'open')
    if ecc_open > 0 and declared_ok == True and to.startswith('ECC-'):
        expected_ok = False
        issues.append("%s open ECC findings but all_ok=True" % ecc_open)
    replay_checks.append({
        "stage": to,
        "declared_ok": declared_ok,
        "expected_ok": expected_ok,
        "match": declared_ok == expected_ok,
        "issues": issues
    })

# Summary
mismatches = [r for r in replay_checks if not r.get("match")]
result = {
    "ok": True,
    "phase1_format": {"replayed": replayed, "matched": matched, "diverged": diverged, "divergences": divergences[:5]},
    "phase2_replay": {"checked": len(replay_checks), "matched": len(replay_checks) - len(mismatches), "mismatches": len(mismatches), "details": mismatches[:5]},
    "total_divergences": diverged + len(mismatches)
}
print(json.dumps(result, indent=2, ensure_ascii=False))

#!/usr/bin/env python3
"""Debug: check audit --state output structure"""
import json, subprocess

CLI = "<home>/.trae/skills/spz-gatekeeper-r-sequence/gatekeeper-cli.sh"
SF = "<home>/.trae/skills/spz-gatekeeper-r-sequence/.gatekeeper.state"

# Setup state with subagent_history and block_log
d = {
    "r_phase": "ECO-EDIT", "stage": "ECO-EDIT", "branch": "master",
    "worktree": "<home>/.trae/skills/spz-gatekeeper-r-sequence",
    "main_repo": "<home>/.trae/skills/spz-gatekeeper-r-sequence",
    "gate_data": {
        "project_type": "standing",
        "rejected_edits": [],
        "subagent_history": [
            {"task": "scan", "guardrail": "passed", "access_violations": [], "confidence": "high"},
            {"task": "exploit", "guardrail": "failed", "access_violations": [], "confidence": "high"},
        ],
        "block_log": [
            {"command": "push", "reason": "stage=DONE", "stage": "DONE", "timestamp": "2026-06-17T10:00:00"},
            {"command": "push", "reason": "stage=DONE", "stage": "DONE", "timestamp": "2026-06-17T10:01:00"},
            {"command": "push", "reason": "stage=DONE", "stage": "DONE", "timestamp": "2026-06-17T10:02:00"},
        ],
        "human_calibration_log": [],
        "scheduler": {"mode": "cosine", "max_lr": 4, "min_lr": 1, "total_steps": 6, "current_step": 1, "current_lr": 4}
    },
    "monitor_scores": {}, "history": []
}
json.dump(d, open(SF, "w"), indent=2)
print("STATE_WRITTEN")

# Run audit --state
r = subprocess.run(["bash", CLI, "audit", "--state"], capture_output=True, text=True, timeout=30)
output = r.stdout.strip()
print(f"STDOUT ({len(output)} chars): {output[:800]}")
if r.stderr: print(f"STDERR: {r.stderr[:300]}")

# Parse
try:
    data = json.loads(output)
    print(f"\nTop keys: {list(data.keys())}")
    result = data.get("result", data)
    print(f"Result keys: {list(result.keys())}")
    checks = result.get("state_checks", result.get("checks", []))
    print(f"Checks count: {len(checks)}")
    for c in checks:
        print(f"  {c.get('field','?')}: match={c.get('match')} issues={c.get('issues','')}")
except Exception as e:
    print(f"Parse error: {e}")

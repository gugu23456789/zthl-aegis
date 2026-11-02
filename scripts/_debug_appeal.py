#!/usr/bin/env python3
"""Debug: test appeal_required gate logic"""
import json

SF = "<home>/.trae/skills/spz-gatekeeper-r-sequence/.gatekeeper.state"
SKILL = "<home>/.trae/skills/spz-gatekeeper-r-sequence"

d = {
    "r_phase": "ECO-EDIT", "stage": "ECO-EDIT", "branch": "master",
    "worktree": SKILL, "main_repo": SKILL,
    "gate_data": {
        "project_type": "standing",
        "appeal_required": "ECO-AUDIT",
        "appeal_entropy_at_block": 0.67,
        "human_calibration_log": [{
            "timestamp": "2026-06-17T10:00:00+08:00", "stage": "ECO-EDIT",
            "human_score": 0.6, "verdicts_json": {"F1": "PASS"},
            "decision": "test", "change_items": 0, "checklist_total": 0, "constraint_level": ""
        }],
        "scheduler": {"mode": "cosine", "max_lr": 4, "min_lr": 1, "total_steps": 6, "current_step": 1, "current_lr": 4},
        "eco_completions": {}
    },
    "appeal_denied_gates": ["ECO-AUDIT"],
    "appeal_records": {"ECO-AUDIT": {"verdict": "DENIED", "score": 0.3}},
    "monitor_scores": {}, "history": []
}
json.dump(d, open(SF, "w"), indent=2)
print("STATE_WRITTEN")

# Now test the gate logic
d2 = json.load(open(SF))
gd = d2.get("gate_data", {})
ar = gd.get("appeal_required", "")
appealed = d2.get("appeal_records", {}).get(ar) if ar else None
print(f"appeal_required={repr(ar)}")
print(f"appealed={repr(appealed)}")
if ar and not appealed:
    print(f"RESULT: blocked:{ar}")
elif ar and appealed and appealed.get("verdict", "") == "APPROVED":
    print("RESULT: resolved")
elif ar:
    print(f"RESULT: dangling:{ar}")
else:
    print("RESULT: clear")

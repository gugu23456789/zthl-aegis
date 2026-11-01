#!/usr/bin/env python3
"""Write test state for Phase 1 sealed scoring red-team tests."""
import json, time, os

SF = os.environ.get("REDTEAM_STATE", "<home>/.trae/skills/spz-gatekeeper-r-sequence/.gatekeeper.state")  # 2026-08-14: 优先隔离 state（runner 设 REDTEAM_STATE）
SKILL = "<home>/.trae/skills/spz-gatekeeper-r-sequence"

d = {
    "r_phase": "ECO-EDIT",
    "stage": "ECO-EDIT",
    "branch": "master",
    "worktree": SKILL,
    "main_repo": SKILL,
    "gate_data": {
        "project_type": "standing",
        "scheduler": {"mode": "cosine", "max_lr": 4, "min_lr": 1, "total_steps": 6, "current_step": 1, "current_lr": 4},
        "rejected_edits": [],
        "_sealed_agent_score": {
            "score": 0.75,
            "verdicts": {"F1": "PASS", "F2": "PASS", "F3": "WARN", "F4": "PASS", "F5": "PASS", "F6": "PASS", "F7": "PASS"},
            "confidence": "high",
            "conclusion": "plan looks solid",
            "evidence_count": 3,
            "sealed_at": time.time(),
            "subagent_id": "sub-test-001",
            "sealed": True
        }
    },
    "monitor_scores": {},
    "history": []
}
json.dump(d, open(SF, "w"), indent=2)
print("STATE_WRITTEN")

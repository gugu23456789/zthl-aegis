#!/usr/bin/env python3
"""Write test state for Phase 1 sealed scoring red-team tests."""
import json, os, sys, time
from pathlib import Path

# 技能根从本文件位置派生（禁写死某台机器的绝对路径：导出/并行 worktree 下会指错树）
SKILL = str(Path(__file__).resolve().parent.parent)
# 测试 state 必须**显式**给出（runner 设 REDTEAM_STATE）；缺省拒写 ——
#   否则会静默覆盖生产 `.gatekeeper.state`（2026-11-13：默认值直指生产 state）
SF = os.environ.get("REDTEAM_STATE", "")
if not SF:
    sys.stderr.write("_write_test_state: REDTEAM_STATE 未设置 —— 只接受显式测试 state，"
                     "拒绝默认写生产 .gatekeeper.state\n")
    raise SystemExit(2)

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

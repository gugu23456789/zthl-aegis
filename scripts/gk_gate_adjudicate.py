#!/usr/bin/env python3
"""Gate: ECO-EDIT → ECO-VERIFY requires adjudicate first.

2026-08-15 hardening: 原实现只查 calibration_log 存在 stage=ECO-EDIT 条目 →
空 adjudicate（无 verdicts/score/decision）即可穿门（遗留风险）。
现在验证完整「双盲评分 → 仲裁」链：
  1. plan-refinement subagent 点检（双盲评分证据）— subagent_history 最新条目
  2. verdicts F1..F7 全部存在
  3. human_score 为 [0,1] 数值
  4. decision 非空且 != 'pending'（显式仲裁结论）

Usage: python3 gk_gate_adjudicate.py <state_file>
Output: 'ok' 或具体缺失原因。
"""
import json
import sys

F1_F7 = [f"F{i}" for i in range(1, 8)]


def check_adjudicate(state_file: str) -> str:
    try:
        with open(state_file) as f:
            d = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return "missing"
    gd = d.get("gate_data", {})
    # 1) 双盲评分证据: 最新 subagent_history 条目必须是 plan-refinement 点检
    sh = gd.get("subagent_history") or []
    if not sh:
        return "no_plan_refinement_checkpoint"
    if "plan-refinement" not in str(sh[-1].get("task", "")):
        return "no_plan_refinement_checkpoint"
    # 2) 仲裁记录: 最新 ECO-EDIT 阶段条目须含真实 verdicts/score/decision
    cl = gd.get("human_calibration_log") or []
    for entry in reversed(cl):
        if entry.get("stage", "") not in ("ECO-EDIT", ""):
            continue
        verdicts = entry.get("verdicts_json") or {}
        if not isinstance(verdicts, dict):
            return "verdicts_invalid"
        missing = [k for k in F1_F7 if k not in verdicts]
        if missing:
            return "missing_verdicts:" + ",".join(missing)
        score = entry.get("human_score")
        if not isinstance(score, (int, float)) or not (0 <= score <= 1):
            return "score_invalid"
        decision = str(entry.get("decision", "") or "")
        if not decision.strip() or decision.strip().lower() == "pending":
            return "decision_pending"
        return "ok"
    return "no_eco_edit_entry"


if __name__ == "__main__":
    sf = sys.argv[1] if len(sys.argv) > 1 else ""
    print(check_adjudicate(sf) if sf else "missing")

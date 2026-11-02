#!/usr/bin/env python3
"""§18 红先臂：MoA 按**计划锚**聚合（6 臂 3 组 ⟹ 逐字指纹结构上不可齐）。

finding: ECC-096264506280（默认 task_bound 丢臂）。
红先（实现前须见红）：臂① mode!=plan_bound / 臂② 缺失。
"""
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import gk_moa_aggregate as M  # noqa: E402

PLAN = "/p/docs/plans/x-plan.md"


def _state(tmp_path, tasks):
    d = {"gate_data": {"subagent_history": [
        {"task": t, "subagent_id": "s%d" % i} for i, t in enumerate(tasks)]}}
    p = tmp_path / ".gatekeeper.state"
    p.write_text(json.dumps(d), encoding="utf-8")
    return str(p)


# ── 臂① 计划锚：6 臂（3 组窄任务，逐字各不同）全聚 + 排除异计划 1 ──
def test_arm1_plan_anchor_aggregates_six_arms(tmp_path):
    tasks = ([f"plan-refinement: {PLAN} — 质询 组1 相同 A"] * 2
             + [f"plan-refinement: {PLAN} — 质询 组2 正交互补 a",
                f"plan-refinement: {PLAN} — 质询 组2 正交互补 b",
                f"plan-refinement: {PLAN} — 质询 组3 污染 a",
                f"plan-refinement: {PLAN} — 质询 组3 污染 b"]
             + ["plan-refinement: /p/docs/plans/other-plan.md — 质询 异计划"])
    sf = _state(tmp_path, tasks)
    entries, at = M.collect_entries(sf, None, None, plan=PLAN)
    assert at.get("mode") == "plan_bound", at
    assert len(entries) == 6, ("应聚齐 6 臂", len(entries), at)
    assert at.get("excluded_other_tasks") == 1, at


# ── 臂② 缺省仍 task_bound（逐字指纹；回归护栏）──
def test_arm2_default_still_task_bound(tmp_path):
    sf = _state(tmp_path, ["t1 组1", "t2 组2", "t3 组3"])
    entries, at = M.collect_entries(sf, None, None)
    assert at.get("mode") == "task_bound", at
    assert len(entries) == 1, entries

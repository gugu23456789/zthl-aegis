#!/usr/bin/env python3
"""预算解耦红先臂（2026-09-23 用户裁定：**梯度×2 + agent 池 additive + 单节点硬顶 16**）。

背景（本轮实测，非推测）：节点 `edit_budget.max` 长期靠人工 `state-patch` 抬到 6，
高于调度器天花板 `max_lr=4` ⟹ **梯度被绕过**；而「一刀 = 一单位」的固定计数使
多文件批次（3 文件 × 2 刀）必然撞顶，撞一次就写一条 `overrides[]` 噪声。

口径（用户裁定原文）：
  `node.max = scheduler.current_lr × EDIT_BUDGET_PER_LR`（梯度真正生效：退火给每单位额度）
  `+ agent 池 additive`（Σ agents.allowed ≤ k × current_lr；代码代理外包后主 agent 的
   验收 / 收口 / 修坏 手改需求**不降反升**，见设计 §4）
  `单节点硬顶 EDIT_BUDGET_HARD_CAP`（= 16）

红先语义：臂①（standing 注入）与臂②（standard `_edit_budget`）在修前**必红**
（`max` 恒 == `current_lr`，即 4，而非 `current_lr × PER_LR`）。

⚠ 期望值**一律从 `gk_advance` 常量派生**（2026-09-23 实测教训）：本文件原把倍率写死成
`× 2`，`a8ed437` 把 `EDIT_BUDGET_PER_LR` 2→4 后这里**全量验收 3 条红** —— 写死即漂移。
"""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from gk_advance import (  # noqa: E402
    EDIT_BUDGET_HARD_CAP, EDIT_BUDGET_PER_LR, _edit_budget, _run,
)

# 各臂共用期望额度（`current_lr = 4` 时；硬顶 clamp 与实现同源，勿再写死字面量）
_BUDGET_AT_LR4 = min(4 * EDIT_BUDGET_PER_LR, EDIT_BUDGET_HARD_CAP)


def _cs(gate_data):
    return hashlib.sha256(json.dumps(gate_data, sort_keys=True).encode()).hexdigest()[:16]


def _write_state(path, stage, gate_data=None, **extra):
    d = {"r_phase": "R1", "stage": stage, "branch": "feature/r1", "worktree": "/tmp/wt",
         "gate_data": gate_data or {}, "monitor_scores": {}, "history": []}
    d.update(extra)
    d["_checksum"] = _cs(d["gate_data"])
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
    return str(path)


def _sched(step: int, max_lr: int = 4) -> dict:
    return {"mode": "cosine", "max_lr": max_lr, "min_lr": 1,
            "total_steps": 6, "current_step": step, "current_lr": 1}


def test_standing_node_budget_scales_with_gradient(tmp_path):
    """臂①（红先）：standing 注入 = `current_lr × PER_LR`，不是 `current_lr`。

    step0→1 cosine ⟹ `current_lr = 4` ⟹ 期望 `max == remaining == 4 × PER_LR`
    （现行值 = `_BUDGET_AT_LR4`）。**修前实测 `max == remaining == 4`** ⟹ 本臂红。
    """
    gd = {"project_type": "standing", "scheduler": _sched(0)}
    sf = _write_state(tmp_path / "s.json", "ECO-SCAN", gate_data=gd)
    r = _run(sf, "ECO-READ", force=False, dry_run=False, env={}, monitor_json=None,
             cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("ok") is True, f"advance 未放行：{r}"
    d = json.load(open(sf, encoding="utf-8"))
    eb = d["gate_data"]["edit_budget"]
    assert d["gate_data"]["scheduler"]["current_lr"] == 4, (
        f"前置不成立：cosine step1 应给 lr=4（{d['gate_data']['scheduler']}）")
    assert eb["max"] == _BUDGET_AT_LR4, (
        f"梯度未生效：节点 max 应 = current_lr×PER_LR = {_BUDGET_AT_LR4}，实测 {eb['max']}"
        "（修前 = current_lr = 4 ⟹ 多文件批次必撞顶、只能人工 state-patch 抬）")
    assert eb["remaining"] == _BUDGET_AT_LR4, f"remaining 未同步：{eb}"
    assert eb["used"] == 0, f"used 非零：{eb}"


def test_standard_node_budget_scales_with_gradient():
    """臂②（红先）：standard `_edit_budget` 同口径 —— `max = sched_lr × PER_LR`。

    **修前实测 `max == 4`** ⟹ 本臂红。
    """
    d = {"r_phase": "R1", "gate_data": {"project_type": "standard",
                                        "scheduler": _sched(1)}}
    got = _edit_budget(d, {}, True)          # dry_run ⟹ 零副作用
    assert got is not None, got
    assert got["max"] == _BUDGET_AT_LR4, (
        f"standard 侧梯度未生效：期望 max={_BUDGET_AT_LR4}"
        f"（sched_lr 4 × PER_LR {EDIT_BUDGET_PER_LR}），实测 {got['max']}（{got}）")


def test_advance_resets_agent_pool_per_node(tmp_path):
    """臂③（负臂 · 守「池随节点重置」）：advance 进新节点时 agent 池**不得跨节点残留**。

    设计 §4 不变式 2：「agent 池**随节点推进重置**」。若 advance 沿用上一节点签发的
    `agents[]`，则 `max` 会随节点数**单调膨胀**（直到硬顶）——那是记账漂移而非授权。
    """
    stale = {"max": 8, "used": 0, "remaining": 8,
             "overrides": [],
             "agents": [{"agent_id": "a1", "worktree": "/tmp/w1", "allowed": 4,
                         "used": 0, "status": "granted"}]}
    gd = {"project_type": "standing", "scheduler": _sched(0), "edit_budget": stale}
    sf = _write_state(tmp_path / "s.json", "ECO-SCAN", gate_data=gd)
    r = _run(sf, "ECO-READ", force=False, dry_run=False, env={}, monitor_json=None,
             cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("ok") is True, f"advance 未放行：{r}"
    eb = json.load(open(sf, encoding="utf-8"))["gate_data"]["edit_budget"]
    assert not (eb.get("agents") or []), (
        f"上一节点的 agent 池残留到了新节点（max 会单调膨胀）：{eb.get('agents')}")
    assert eb["max"] == _BUDGET_AT_LR4, f"残留池被计入 max：{eb}"

#!/usr/bin/env python3
"""T-c 红先：`_sealed_agent_score` 由「单臂覆盖」改为「同批臂间均值」（2026-10-06）。

缺陷（实测）：CLI 落 `_sealed_agent_score` 为**单槽覆盖** ⟹ 该槽 = **最后完成的那条臂**
（本批实测值 0.4471 = 某单臂 7 维均）⟹ 「单臂冒充 agent 侧」，adjudicate 的 divergence
拿它与人类分比对，基准随完成顺序漂移。（原注释称「覆盖即设计意图」，owner 裁定改为全批聚合。）

修法：抽纯函数 `merge_sealed_agent_score(prev, arm, batch_id)` —— 同批 ⟹ running mean；
跨批/无批 ⟹ 重置为该臂。**形状不变** ⟹ D10 / appeal / mediation 消费者零回归。
HEAD 必红：函数不存在（ImportError）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gk_moa_aggregate import merge_sealed_agent_score  # noqa: E402


def test_same_batch_averages():
    prev = {"score": 0.4, "batch_id": "b1", "arm_count": 1, "arm_ids": ["a1"]}
    arm = {"subagent_id": "a2", "seven_dim_score": {"scope": 60}, "verdicts": {"F1": "WARN"}}
    out = merge_sealed_agent_score(prev, arm, "b1")
    assert out["score"] == round((0.4 + 0.6) / 2, 4), out
    assert out["arm_count"] == 2
    assert out["arm_ids"] == ["a1", "a2"]
    assert out["batch_id"] == "b1" and out["sealed"] is True


def test_cross_batch_resets():
    prev = {"score": 0.4, "batch_id": "b1", "arm_count": 3}
    arm = {"subagent_id": "a9", "seven_dim_score": {"scope": 60}}
    out = merge_sealed_agent_score(prev, arm, "b2")
    assert out["score"] == 0.6 and out["arm_count"] == 1 and out["arm_ids"] == ["a9"]


def test_no_prev_single_arm_equals_old_semantics():
    out = merge_sealed_agent_score({}, {"subagent_id": "a1", "seven_dim_score": {"scope": 70}}, "b1")
    assert out["score"] == 0.7 and out["arm_count"] == 1

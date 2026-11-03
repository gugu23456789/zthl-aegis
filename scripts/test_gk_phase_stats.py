#!/usr/bin/env python3
"""公开臂：`gk_phase_stats` 的统计核心（无模型/无网络/无稿件数据）。

覆盖：均值口径、相位结构化 ⟹ 拒绝 H0、无相位效应 ⟹ 不拒绝 H0、确定性可复现。
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gk_phase_stats import mean, phase_invariance_test  # noqa: E402


def test_mean():
    assert mean([1, 2, 3]) == 2
    assert mean([0.5]) == 0.5


def test_structured_phase_rejects_h0():
    rng = random.Random(11)
    labels = [i % 2 for i in range(400)]
    outcomes = [rng.random() < (0.9 if lab == 0 else 0.1) for lab in labels]
    p = phase_invariance_test(outcomes, labels, 500, random.Random(12))
    assert p < 0.01


def test_no_phase_effect_does_not_reject_h0():
    rng = random.Random(21)
    labels = [i % 2 for i in range(400)]
    outcomes = [rng.random() < 0.5 for _ in labels]
    p = phase_invariance_test(outcomes, labels, 500, random.Random(22))
    assert p > 0.05


def test_same_seed_same_p():
    rng = random.Random(31)
    labels = [i % 3 for i in range(300)]
    outcomes = [rng.random() < (0.7 if lab == 0 else 0.3) for lab in labels]
    p1 = phase_invariance_test(outcomes, labels, 300, random.Random(32))
    p2 = phase_invariance_test(outcomes, labels, 300, random.Random(32))
    assert p1 == p2

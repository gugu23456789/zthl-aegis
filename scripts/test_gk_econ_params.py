#!/usr/bin/env python3
"""经济参数单源（owner 2026-10-31 签 §8 #4）—— 红先臂。

签定值：F=1 / K=4 / CAP=6 / N=15 / T_API=0.3 / T_BLOCK=0.5。
熵公式：`min(1, max(0, n−F)/K)`；阻断判据**严格** `> T_BLOCK`。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_econ_params as E  # noqa: E402


def test_signed_values_are_single_source():
    assert (E.F, E.K, E.CAP, E.N) == (1, 4, 6, 15)
    assert E.T_API == 0.3
    assert E.T_BLOCK == 0.5


class TestRaiseEntropy:
    def test_arm1_n0_is_zero(self):
        assert E.raise_entropy(0) == 0.0

    def test_arm2_free_quota_is_zero(self):
        assert E.raise_entropy(E.F) == 0.0

    def test_arm3_one_over_quota(self):
        assert E.raise_entropy(E.F + 1) == 1 / E.K

    def test_arm4_knee_is_exactly_half_not_blocking(self):
        """n=F+K/2 = 3 ⟹ 0.50（严格 > 才阻断 ⟹ 不阻断，但强制 --api）。"""
        rate = E.raise_entropy(3)
        assert rate == 0.5
        assert E.should_block(rate) is False
        assert E.should_force_api(rate) is True

    def test_n4_crosses_block_line(self):
        assert E.raise_entropy(4) == 0.75
        assert E.should_block(0.75) is True

    def test_saturates_at_one(self):
        assert E.raise_entropy(99) == 1.0

    def test_negative_and_bad_input(self):
        assert E.raise_entropy(-3) == 0.0
        assert E.raise_entropy("bad") == 0.0


def test_thresholds_are_strictly_greater_than():
    assert E.should_block(E.T_BLOCK) is False
    assert E.should_block(E.T_BLOCK + 1e-6) is True
    assert E.should_force_api(E.T_API) is False
    assert E.should_force_api(E.T_API + 1e-6) is True

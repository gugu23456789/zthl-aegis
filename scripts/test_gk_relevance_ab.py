#!/usr/bin/env python3
"""相关性闸回归测试（2026-11-06）—— 复用基准 `gk_bench_relevance` 的同一数据集与口径。

判据：
  1. 现行 4-gram 锚定闸在对抗集上 **零误放、零误拒**（发布门）；
  2. tokenizer 臂当前仍存在误放 ⟹ 不切换（棘轮：若将来归零，此测红，提示重评）。
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_bench_relevance as B  # noqa: E402


def test_adopted_gate_is_clean():
    """采纳臂 = 4gram + 结构锚 + ECC 身份锚：核心集零误放/零误拒，硬负例零放行。"""
    res = B.run()
    arm = res["arms"]["4gram+struct+ecc"]
    assert arm["core_fp"] == []
    assert arm["core_fn"] == []
    assert arm["hard_negative_fp"] == [], "仍有硬负例被放行：%s" % arm["hard_negative_fp"]


def test_baseline_alone_false_rejects_legit_verdict():
    """无身份锚时，合法人评（仅引用 ECC id、无 token 重叠）会被误拒 ⟹ 记录该缺口。"""
    res = B.run()
    assert "ecc_verdict" in res["arms"]["4gram"]["core_fn"]


def test_fake_ecc_id_is_not_identity_anchor():
    res = B.run()
    assert res["rows"]["ecc_fake"]["ecc_ok"] is False
    assert res["arms"]["4gram+struct+ecc"]["core_fp"] == []


def test_tokenizer_arm_still_has_false_accepts():
    res = B.run()
    if not res["arms"]["tokenizer_rare"].get("available"):
        pytest.skip("无 tokenizer 后端：该臂跳过")
    assert res["arms"]["tokenizer_rare"]["fp"] > 0, "tokenizer 臂已无通用子词误放 ⟹ 重新评估是否切换"

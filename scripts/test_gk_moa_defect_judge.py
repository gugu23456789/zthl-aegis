#!/usr/bin/env python3
"""W2A §6.3(1) ①② **红先臂**（`ECC-0FC756057411`）。

缺陷：六臂神鬼实验**缺两项载体** —— ① **缺陷计划族**（D1–D5 自动注入 + 金标 + `det_F1` 输入）
与 ② **可复现判分**（当前无 ⟹ `det_F1` 不可复现）。且判分器若相位敏感，会与被测臂构成
**双重相位混杂**（spec §6.3 **F3**）。

修法 = 新 `scripts/gk_defect_gen.py`（确定性注入 + 金标 clause + 防天花板 `--escalate`）
+ `scripts/gk_moa_judge.py`（**规则式** `det_F1`：位置无关 ⟹ **按构造相位不变**）。
"""
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def test_defect_gen_injects_d1_d5():
    """① 合成题：确定性 / 金标 clause 可 grep / D1–D5 可达 / 防天花板加 k。"""
    import gk_defect_gen as G

    assert G.generate(1, 3) == G.generate(1, 3)          # deterministic in (seed, k)
    assert G.generate(1, 3) != G.generate(2, 3)          # seed varies the plan

    seen = set()
    for s in range(60):
        plan = G.generate(s, 5)
        seen.update(plan["codes"])
        for g in plan["gold"]:
            assert g["clause"] in plan["plan_text"], "gold clause must be greppable"
    assert seen == set(G.CODES), "D1-D5 must all be reachable"

    assert G.generate(1, 4)["k"] == 4                    # anti-ceiling hook: k+1


def test_moa_judge_det_f1_phase_invariant():
    """② 判分：规则式 det_F1；漏检降 recall、噪声降 precision；**shuffle 不变 = 相位不变**。"""
    import gk_defect_gen as G
    import gk_moa_judge as J

    gold = G.generate(7, 4)["gold"]
    text = G.generate(7, 4)["plan_text"]
    arm = "\n".join("- " + s for s in text.splitlines() if any(g["clause"] in s for g in gold))

    r = J.score(gold, arm)
    assert r["det_F1"] == 1.0 and r["false_positives"] == 0
    assert J.score(gold, "\n".join(arm.splitlines()[:-1]))["det_F1"] < 1.0   # b) miss -> recall
    assert J.score(gold, arm + "\n- an unrelated concern")["det_F1"] < 1.0  # c) noise -> precision

    lines = arm.splitlines()                             # d) phase-invariant (F3)
    random.Random(9).shuffle(lines)
    assert J.score(gold, "\n".join(lines))["det_F1"] == r["det_F1"]

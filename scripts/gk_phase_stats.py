#!/usr/bin/env python3
"""Phase-invariance statistics（通用统计核心，2026-11-03 拆分开源）。

H0：观测结果与相位标签**独立**。统计量 = 各标签组均值的极差（max − min）；
置换检验 p = (ge + 1) / (perms + 1)，`ge` = 置换后极差 ≥ 观测极差的次数。

纯标准库、无 API、无模型/数据依赖；调用方注入 `outcomes` 与 `labels`。
臂设计、题面夹具与模型指纹证据**不在**本模块（闭源），这里只提供可复现的检验。
"""
import random


def mean(xs):
    """算术均值（空序列由调用方保证不出现；与置换检验内部口径一致）。"""
    return sum(xs) / len(xs)


def phase_invariance_test(outcomes, labels, perms, rng):
    """置换检验：返回 H0 的 p 值（双侧极差统计）。

    `outcomes[i]` 为第 i 个观测，`labels[i]` 为其相位标签；`rng` 须为
    `random.Random` 实例（调用方给种子 ⟹ 可复现）。
    """
    def spread(vals, labs):
        by = {}
        for v, lab in zip(vals, labs):
            by.setdefault(lab, []).append(v)
        ms = [mean(g) for g in by.values() if g]
        return max(ms) - min(ms)

    obs = spread(outcomes, labels)
    labs = list(labels)
    ge = 0
    for _ in range(perms):
        rng.shuffle(labs)
        if spread(outcomes, labs) >= obs - 1e-12:
            ge += 1
    return (ge + 1) / (perms + 1)

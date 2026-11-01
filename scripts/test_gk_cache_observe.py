#!/usr/bin/env python3
"""W2A §6.3(6) ④ 缓存观测 **红先臂**（`ECC-F0D3F78E9F58`）。

缺陷：MoA 六臂批次**无缓存命中协变量** ⟹ §6.3(6) 红线 ②（`cache-hit` 逐调用记录）/
③（`L` 的 token 块边界对齐）/④（跨轮 cache 失效点）三条**均无载体**；相位效应可能与
缓存命中漂移混杂而不可分离。

修法 = 新 `scripts/gk_cache_observe.py`：raw provider usage → 归一桶（`{input, uncached,
cacheRead, cacheWrite, output}`）+ `token_count_of` 消毒（dsh-context `tokenCountOf` 移植）
+ `block_alignment(l, block)` + 跨轮失效点。**P1**：raw→桶映射由**本模块自建**
（dsh-context 只读**已归一** usage，该映射它不提供）。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


def test_gk_cache_observe_normalizes_and_aligns():
    """④：归一桶 / 命中率 / 块对齐 / 失效点 / 消毒 / 多 vendor 同形。"""
    import gk_cache_observe as C

    calls = [
        {"turn": 0, "provider": "deepseek", "l": 0,
         "usage": {"prompt_tokens": 100, "prompt_cache_hit_tokens": 0,
                   "prompt_cache_miss_tokens": 100, "completion_tokens": 50}},
        {"turn": 1, "provider": "deepseek", "l": 8,
         "usage": {"prompt_tokens": 200, "prompt_cache_hit_tokens": 192,
                   "prompt_cache_miss_tokens": 8, "completion_tokens": 60}},
        {"turn": 2, "provider": "deepseek", "l": 9,
         "usage": {"prompt_tokens": 220, "prompt_cache_hit_tokens": 190,
                   "prompt_cache_miss_tokens": 30, "completion_tokens": 55}},
    ]
    rows, summary = C.observe(calls, block=8, stride=4)

    # raw -> normalized buckets (P1: our own table)
    assert rows[1]["cacheRead"] == 192 and rows[1]["uncached"] == 8
    assert rows[0]["cache_hit_ratio"] == 0.0 and rows[1]["cache_hit_ratio"] == 0.96
    # token-block alignment + phase (F2: L in tokens)
    assert rows[1]["block_crossed"] is False and rows[2]["block_crossed"] is True
    assert rows[1]["phase"] == 0 and rows[2]["phase"] == 1
    # cross-turn cache invalidation (a read that DROPS after a warm turn)
    assert summary["invalidation_points"] == [{"turn": 2, "from": 192, "to": 190}]

    # sanitizer (dsh-context tokenCountOf port): fraction rounds, negative clamps, junk absent
    assert C.token_count_of(2.6) == 3 and C.token_count_of(-5) == 0
    assert C.token_count_of("12") == 12 and C.token_count_of("x") is None and C.token_count_of(True) is None

    # vendor tables normalize to the SAME bucket shape
    assert C.normalize_usage("anthropic", {"input_tokens": 10,
                                           "cache_creation_input_tokens": 4})["cacheWrite"] == 4
    assert C.normalize_usage("openai", {"prompt_tokens": 10,
                                        "prompt_tokens_details": {"cached_tokens": 7}})["cacheRead"] == 7


def _call(hit, miss, provider="deepseek", l=0):
    return {"provider": provider, "l": l,
            "usage": {"prompt_tokens": hit + miss, "prompt_cache_hit_tokens": hit,
                      "prompt_cache_miss_tokens": miss, "completion_tokens": 1}}


def test_gk_cache_observe_steady_window_and_status():
    """二条件 (a)：剔除 warm-up 后给稳态命中率；≥extreme=EXTREME、≥target=PASS、否则 BELOW_TARGET。"""
    import gk_cache_observe as C

    # 1 warm-up（0%）+ 20 稳态（95%）⟹ EXTREME（默认 extreme=0.95）
    calls = [_call(0, 100)] + [_call(95, 5) for _ in range(20)]
    _rows, s = C.observe(calls, warmup_rounds=1, target=0.90, extreme=0.95, min_steady=20)
    assert s["warmup_calls"] == 1 and s["steady_calls"] == 20
    assert s["warmup_cache_hit_ratio"] == 0.0
    assert s["steady_cache_hit_ratio"] >= 0.95
    assert s["cache_status"] == "EXTREME", s

    # 稳态 80% ⟹ BELOW_TARGET（不得读成「极高」）
    calls = [_call(0, 100)] + [_call(80, 20) for _ in range(20)]
    _rows, s = C.observe(calls, warmup_rounds=1, target=0.90, extreme=0.95, min_steady=20)
    assert s["cache_status"] == "BELOW_TARGET", s

    # 稳态样本不足 ⟹ UNKNOWN（禁把短会话均值当结论）
    _rows, s = C.observe([_call(0, 100), _call(95, 5)], warmup_rounds=1, min_steady=20)
    assert s["cache_status"] == "UNKNOWN", s

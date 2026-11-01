"""红先测试：RCA 污染调控 φ(κ,n) 可估框架（W2，2026-10-06）。

要点：
  · 实盘 κ 普查（11 批）→ `p_tilt` **不可估**，且具名 reason 精确指认是零膨胀还是缺 `n_events`；
  · 合成数据可正确回收 `p_tilt`（防止框架"永远 UNFITTED"的假绿）；
  · φ / Λ 的**有界性**与次线性形态（对齐 arXiv:2602.13320 线性非指数结论）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_moa_kappa as K  # noqa: E402


def test_ledger_enumerates_all_batches():
    s = K.load_ledger()
    assert len(s) >= 11
    assert len({x["batch"] for x in s}) == len(s)   # batch 名唯一


def test_kappa_ratio():
    by = {x["batch"]: x for x in K.load_ledger()}
    assert K.kappa(by["R5"]) == (1.0, 0.0)
    assert K.kappa(by["12arm-1of4"]) == (0.25, 0.75)


def test_real_data_p_tilt_unfitted_zero_inflated():
    r = K.estimate_p_tilt(K.load_ledger())
    assert r["ok"] is False and r["unfitted"] is True
    # 2026-10-26（D 子计划 §14.4-5 增 R1/R2）后：非零点 = 3（suba-ctx-degraded / 12arm-1of4 / R1）
    # ⟹ 不再先撞零膨胀，而撞**缺 n_events**（带 n_events 的非零点仅 R1 一个 < 3）。两类 reason 都是
    # 具名拒估（禁冒充已拟合）；断言当前实盘的**精确**一类，防口径漂移被静默吞掉。
    assert r["reason"] == "MISSING_EVENT_COUNT", r
    assert r["n_with_events"] == 1, r


def test_missing_event_count_is_named():
    samples = [{"batch": "b%d" % i, "cap": [2, 2], "tilt": [1, 2], "n_events": None}
               for i in range(3)]
    r = K.estimate_p_tilt(samples)
    assert r["unfitted"] is True and r["reason"] == "MISSING_EVENT_COUNT"


def test_synthetic_slope_recovered():
    # tilt ∝ n^-2（den=1e6）：n=10→0.5, n=100→0.005, n=1000→0.00005
    pts = [(10, 500000), (100, 5000), (1000, 50)]
    samples = [{"batch": str(n), "cap": [2, 2], "tilt": [num, 1000000], "n_events": n}
               for n, num in pts]
    r = K.estimate_p_tilt(samples)
    assert r["ok"] is True
    assert abs(r["p_tilt"] - 2.0) < 0.05


def test_phi_requires_p_tilt():
    s = {"batch": "x", "cap": [2, 2], "tilt": [0, 2]}
    r = K.phi(s, 10)
    assert r["unfitted"] is True and r["reason"] == "P_TILT_UNFITTED"
    assert K.phi(s, 0, p_tilt=2.0)["reason"] == "N_EVENTS_INVALID"


def test_phi_value():
    s = {"batch": "x", "cap": [1, 2], "tilt": [1, 2]}   # cap=.5 tilt=.5
    r = K.phi(s, 4, p_tilt=2.0)
    assert abs(r["phi"] - 0.5 * 0.5 * (4 ** -2)) < 1e-12
    assert abs(r["escape"] - 0.5) < 1e-12


def test_cumulative_bounded_when_p_gt_1():
    s = {"batch": "x", "cap": [1, 2], "tilt": [1, 2]}
    c1 = K.cumulative_leverage(s, 10, p_tilt=2.0)
    c2 = K.cumulative_leverage(s, 10 ** 6, p_tilt=2.0)
    assert c1["bounded"] is True
    # N→∞ 收敛（ζ(2)*0.25≈0.411）；尾部 Σ_{n>10} n^-2 ≈ 1/10 ⟹ 差 ≈ 0.025
    assert abs(c2["leverage"] - c1["leverage"]) < 0.03


def test_cumulative_linear_when_p_zero():
    s = {"batch": "x", "cap": [1, 2], "tilt": [1, 2]}   # 0.25/round
    r = K.cumulative_leverage(s, 100, p_tilt=0.0)
    assert r["bounded"] is False
    assert abs(r["leverage"] - 25.0) < 1e-9


# ─── D 子计划 §14.4-5（2026-10-26）：三通道 ledger 行可参与 p_tilt 拟合 ─────────
def test_estimate_p_tilt_accepts_channels_only_samples():
    """只给 `channels.p_in` 的样本（无顶层 cap/tilt）不得抛 KeyError；
    n_events 不足时须回具名 MISSING_EVENT_COUNT（不冒充已拟合）。"""
    samples = [{"batch": "R1", "channels": {"p_in": {"tilt": [1, 2]}}, "n_events": 2},
               {"batch": "R3", "channels": {"p_in": {"tilt": [1, 2]}}, "n_events": 4},
               {"batch": "R4", "channels": {"p_in": {"tilt": [1, 4]}}, "n_events": 8}]
    r = K.estimate_p_tilt(samples)
    assert r["ok"] is True and "p_tilt" in r, r

    few = [{"batch": "R1", "channels": {"p_in": {"tilt": [1, 2]}}, "n_events": 2},
           {"batch": "R2", "channels": {"p_in": {"tilt": [0, 2]}}, "n_events": 2},
           {"batch": "R3", "channels": {"p_in": {"tilt": [1, 2]}}},
           {"batch": "R4", "cap": [1, 2], "tilt": [1, 4]}]
    r2 = K.estimate_p_tilt(few)
    assert r2["ok"] is False and r2["reason"] == "MISSING_EVENT_COUNT", r2

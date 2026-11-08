"""红先测试：A8-④ 乘性污染折扣 —— φ(κ,n) 在 MoA 聚合的**批级**落点（A，2026-10-06）。

要点：
  · `pollution_tilt is None` ⟹ **逐字零回归**（agreement_eff == agreement，abstain 判定不变）；
  · 折扣 = **批级、全臂**，但当前**只接 P-in 一个通道**（污染实为三通道 P-in/P-art/P-meta，
    遍及 G1/G2/G3 与**人类评审**；G3 只是明确投毒，**不作判据**）；
  · 越界输入夹逼到 [0,1]；κ_tilt 来源 = 人类标注（ledger），**不**从 arm_group 结构推导。
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_moa_aggregate as M  # noqa: E402
import gk_moa_kappa as K  # noqa: E402


def _refs():
    # 两臂结论逐字相同 ⟹ 同签名 ⟹ 单簇（agreement 高）；arm_group 不影响签名
    return [{"subagent_id": "a", "conclusion": "same text here", "arm_group": "G1"},
            {"subagent_id": "b", "conclusion": "same text here", "arm_group": "G2"}]


def _prov():
    return {"fingerprint": "x", "S": 2, "N": 200,
            "batch_id": "R5", "measured_at": "2026-11-03T00:00:00Z"}


def test_none_means_zero_regression():
    c = M.cluster_references(_refs())["consensus"]
    assert c["pollution_tilt"] == 0.0
    assert c["agreement_eff"] == c["agreement"]
    assert c["abstain"] == (c["agreement"] < c["min_agreement"])
    assert c["adjusted"] is False and c["adjustment_verified"] is False


def test_multiplicative_discount():
    base = M.cluster_references(_refs())["consensus"]
    d = M.cluster_references(_refs(), pollution_tilt=0.5,
                             provenance=_prov())["consensus"]
    assert abs(d["agreement_eff"] - round(base["agreement"] * 0.5, 4)) < 1e-9
    assert d["abstain"] == (d["agreement_eff"] < d["min_agreement"])
    assert d["adjusted"] is True and d["adjustment_verified"] is True
    assert d["pollution_provenance"]["fingerprint"] == "x"


def test_tilt_without_provenance_is_unverified():
    base = M.cluster_references(_refs())["consensus"]
    d = M.cluster_references(_refs(), pollution_tilt=0.5)["consensus"]
    assert d["agreement_eff"] == round(base["agreement"] * 0.5, 4)  # 零回归
    assert d["adjusted"] is True and d["adjustment_verified"] is False
    assert d["pollution_provenance"] is None


def test_tilt_clamped_to_unit_interval():
    hi = M.cluster_references(_refs(), pollution_tilt=2.0,
                              provenance=_prov())["consensus"]
    assert hi["pollution_tilt"] == 1.0 and hi["agreement_eff"] == 0.0
    lo = M.cluster_references(_refs(), pollution_tilt=-1.0,
                              provenance=_prov())["consensus"]
    assert lo["pollution_tilt"] == 0.0 and lo["agreement_eff"] == lo["agreement"]
    assert lo["adjusted"] is False


def test_batch_tilt_lookup_is_batch_level():
    assert K.batch_tilt("R5") == 0.0
    assert K.batch_tilt("12arm-1of4") == 0.75
    assert K.batch_tilt("no-such-batch") is None    # 未知批 ⟹ 调用方退化为无折扣


# ── 接通（2026-10-06 晚）：aggregate 读 divergence → p_meta 通道 ──────────────
_PLAN = "/p/docs/plans/x-plan.md"


def _hist2():
    return [{"subagent_id": "a%d" % i, "batch_id": "R5", "arm_group": "G1",
             "task": "plan-refinement: %s — 质询" % _PLAN,
             "conclusion": "同一结论：验证充分，无缺口。",
             "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]}
            for i in (1, 2)]


def test_aggregate_connects_p_meta_divergence(tmp_path):
    """批 R5 的 ledger p_in tilt=0；state 的 divergence=0.4 ⟹ pollution_tilt=1−(1−0)(1−0.4)=0.4。"""
    sf = tmp_path / "state.json"
    sf.write_text(json.dumps({"gate_data": {
        "subagent_history": _hist2(),
        "human_calibration_log": [{"divergence": 0.4}]}}, ensure_ascii=False),
        encoding="utf-8")
    out = M.aggregate(str(sf), None, "plan-refinement", plan=_PLAN, batch="R5")
    assert out["consensus"]["pollution_tilt"] == 0.4, out["consensus"]
    assert out["consensus"]["agreement_eff"] == round(out["consensus"]["agreement"] * 0.6, 4)
    assert out["consensus"]["adjusted"] is True
    assert out["consensus"]["adjustment_verified"] is False  # aggregate 未带 provenance


def test_aggregate_no_divergence_keeps_ledger_only(tmp_path):
    """零回归：state 无 divergence ⟹ 不落 p_meta 通道，pollution_tilt = ledger（R5 = 0）。"""
    sf = tmp_path / "state.json"
    sf.write_text(json.dumps({"gate_data": {"subagent_history": _hist2()}},
                             ensure_ascii=False), encoding="utf-8")
    out = M.aggregate(str(sf), None, "plan-refinement", plan=_PLAN, batch="R5")
    assert out["consensus"]["pollution_tilt"] == 0.0, out["consensus"]

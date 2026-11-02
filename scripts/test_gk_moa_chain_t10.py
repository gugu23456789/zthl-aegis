"""
test_gk_moa_chain_t10.py -- T10 红先臂：链尾**完整性出口**（报 `gk_moa_integrity.arm_dispersion`）
================================================================================
正本：`docs/plans/2026-10-14-moa-chain-automation-plan.md` §3-T10 / §7.1 R4。

缺口：`gk_moa_integrity.arm_dispersion`（ANOVA F + 置换 p）**零生产消费者** —— 链尾不出臂间
离散/组间分离判据。本切片：按 `arm_group` 汇总臂 `overall_score` → `arm_dispersion`；
**缺分数 / <2 组 ⟹ `UNDER-POWERED`**（估计器自带声明，禁冒充 SEPARATED）。
"""
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))


def _agg(refs: list) -> dict:
    return {
        "trace": {"count": len(refs), "attribution": {"mode": "batch_bound",
                                                      "batch_id": "66bae2b0678a"}},
        "consensus": {"n_refs": len(refs), "n_clusters": 1, "top_weight": 0.5,
                      "min_agreement": 0.66, "abstain": True, "contradictions": []},
        "clusters": [], "references": refs,
    }


_DISP_REFS = (
    [{"arm_group": "G1", "overall_score": s} for s in (1, 2, 1, 2)]
    + [{"arm_group": "G2", "overall_score": s} for s in (9, 10, 9, 10)]
)


def _stub(monkeypatch, agg: dict):
    import gk_moa_aggregate as M
    monkeypatch.setattr(M, "aggregate", lambda *a, **k: json.loads(json.dumps(agg)))
    monkeypatch.setattr(M, "emit_aggregate_finding", lambda *a, **k: {"ok": True, "id": "ECC-STUB"})
    monkeypatch.setattr(M, "render_html", lambda *a, **k: "<html>STUB</html>")


def _state(tmp_path) -> str:
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {"ecc_findings": []}}), encoding="utf-8")
    return str(st)


# ── ① 两组分离 ⟹ ANOVA F + 置换 p ⟹ `SEPARATED` ──────────────────────────────
def test_integrity_separated(tmp_path, monkeypatch):
    _stub(monkeypatch, _agg(_DISP_REFS))
    from gk_moa_aggregate import chain
    r = chain(_state(tmp_path), batch="66bae2b0678a")
    it = r["steps"]["integrity"]
    assert it["check"] == "arm_dispersion", it
    assert it["k"] == 2 and it["n"] == 8, it
    assert it["f"] is not None and it["verdict"] == "SEPARATED", it
    assert it["metric"] == "arm_score", it   # T14：口径改单源 arm_score（自报优先，缺⟹七维派生）


# ── ② 无分数 ⟹ `UNDER-POWERED`（估计器自带声明，禁冒充）────────────────────────
def test_integrity_under_powered_without_scores(tmp_path, monkeypatch):
    _stub(monkeypatch, _agg([{"arm_group": "G1"}, {"arm_group": "G2"}]))
    from gk_moa_aggregate import chain
    r = chain(_state(tmp_path), batch="66bae2b0678a")
    it = r["steps"]["integrity"]
    assert it["verdict"] == "UNDER-POWERED", it


# ── ③ 形态臂：链接线 `gk_moa_integrity.arm_dispersion`（单源）──────────────────
def test_python_wires_t10():
    src = (SCRIPTS / "gk_moa_aggregate.py").read_text(encoding="utf-8")
    assert "import gk_moa_integrity" in src, "chain 未接完整性出口"
    assert "arm_dispersion" in src, "chain 未走 arm_dispersion（R4 单源）"

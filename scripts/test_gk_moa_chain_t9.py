"""
test_gk_moa_chain_t9.py -- T9 红先臂：链尾**κ 通道接通**（报 `gk_moa_kappa.combined_tilt`）
================================================================================
正本：`docs/plans/2026-10-14-moa-chain-automation-plan.md` §3-T9 / §7.1 R2。

缺口：`gk_moa_kappa.combined_tilt`（`tilt_total=1−Π(1−κ_tilt_i)`）**零生产消费者** —— 链尾
不报 κ，调用方拿不到本批污染合成落地率。本切片：链尾读该批 ledger 行 → `combined_tilt`；
**无行 ⟹ 具名拒估**（`UNKNOWN` / `NO_LEDGER_ROW`），**不冒充**（R2/R3）。
"""
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

_AGG = {
    "trace": {"count": 2, "attribution": {"mode": "batch_bound", "batch_id": "66bae2b0678a"}},
    "consensus": {"n_refs": 2, "n_clusters": 1, "top_weight": 0.5, "min_agreement": 0.66,
                  "abstain": True, "contradictions": []},
    "clusters": [], "references": [],
}


def _stub(monkeypatch):
    import gk_moa_aggregate as M
    monkeypatch.setattr(M, "aggregate", lambda *a, **k: json.loads(json.dumps(_AGG)))
    monkeypatch.setattr(M, "emit_aggregate_finding", lambda *a, **k: {"ok": True, "id": "ECC-STUB"})
    monkeypatch.setattr(M, "render_html", lambda *a, **k: "<html>STUB</html>")


def _state(tmp_path) -> str:
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {"ecc_findings": []}}), encoding="utf-8")
    return str(st)


# ── ① 批在 ledger 有行 ⟹ `combined_tilt` 合成（缺通道按 0）────────────────────
def test_kappa_estimated_from_ledger(tmp_path, monkeypatch):
    _stub(monkeypatch)
    import gk_moa_kappa as K
    monkeypatch.setattr(K, "load_ledger", lambda *a, **k: [
        {"batch": "66bae2b0678a",
         "channels": {"p_in": {"tilt": 0.2}, "p_art": {"tilt": 0.3}}}])
    from gk_moa_aggregate import chain
    r = chain(_state(tmp_path), batch="66bae2b0678a")
    k = r["steps"]["kappa"]
    assert k["status"] == "estimated", k
    assert k["tilt_total"] == 0.44, k          # 1 − (1−0.2)(1−0.3) = 0.44
    assert k["source"] == "gk_moa_kappa.combined_tilt", k


# ── ② 批不在 ledger ⟹ 具名拒估（UNKNOWN / NO_LEDGER_ROW），禁冒默认值 ─────────
def test_kappa_unknown_without_ledger_row(tmp_path, monkeypatch):
    _stub(monkeypatch)
    import gk_moa_kappa as K
    monkeypatch.setattr(K, "load_ledger", lambda *a, **k: [])
    from gk_moa_aggregate import chain
    r = chain(_state(tmp_path), batch="66bae2b0678a")
    k = r["steps"]["kappa"]
    assert k["status"] == "UNKNOWN", k
    assert k["tilt_total"] is None and k["reason"] == "NO_LEDGER_ROW", k


# ── ③ 形态臂：链接线 `gk_moa_kappa.combined_tilt`（单源，禁第二实现）───────────
def test_python_wires_t9():
    src = (SCRIPTS / "gk_moa_aggregate.py").read_text(encoding="utf-8")
    assert "import gk_moa_kappa" in src, "chain 未接 κ 通道"
    assert "combined_tilt" in src, "chain 未走 combined_tilt（R2 单源）"

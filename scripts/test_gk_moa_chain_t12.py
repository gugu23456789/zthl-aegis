"""
test_gk_moa_chain_t12.py -- T12 红先臂：链内散文摄取**默认启用 BM25 相关性闸**
================================================================================
正本：`docs/plans/2026-10-14-moa-chain-automation-plan.md` §3-T12。

缺口：T5 的 `gk_prose_findings.convert(refs=None)` ⟹ 相关性闸（`relevance_judge`）**未启用**
⟹ 外源散文可**无闸入账**（不落 `relevance:in|out` / `bm25:` facet）。本切片：`chain()` 传
`refs=_refs_of(agg)`（单源，禁第二实现）⟹ 外源散文逐条过闸。
"""
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))


def _agg_with_refs(conclusion: str) -> dict:
    return {
        "trace": {"count": 2, "attribution": {"mode": "batch_bound", "batch_id": "66bae2b0678a"}},
        "consensus": {"n_refs": 2, "n_clusters": 1, "top_weight": 0.5, "min_agreement": 0.66,
                      "abstain": True, "contradictions": []},
        "clusters": [], "references": [{"conclusion": conclusion}],
    }


def _agg_no_refs() -> dict:
    a = _agg_with_refs("")
    a["references"] = []
    return a


def _stub(monkeypatch, agg: dict):
    import gk_moa_aggregate as M
    monkeypatch.setattr(M, "aggregate", lambda *a, **k: json.loads(json.dumps(agg)))
    monkeypatch.setattr(M, "emit_aggregate_finding", lambda *a, **k: {"ok": True, "id": "ECC-STUB"})
    monkeypatch.setattr(M, "render_html", lambda *a, **k: "<html>STUB</html>")


def _state(tmp_path) -> str:
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {"ecc_findings": []}}), encoding="utf-8")
    return str(st)


def _prose_facets(state) -> list:
    d = json.loads(Path(state).read_text(encoding="utf-8"))
    return [f.get("facets") or [] for f in (d.get("gate_data") or {}).get("ecc_findings") or []
            if str(f.get("root_key", "")).startswith("prose:")]


# ── ① 锚定命中的散文 ⟹ `relevance:in`（+ `bm25:` facet）──────────────────────
def test_relevance_in_when_anchored(tmp_path, monkeypatch):
    _stub(monkeypatch, _agg_with_refs("计划缺 X 需要澄清"))
    from gk_moa_aggregate import chain
    pf = tmp_path / "p.txt"
    pf.write_text("- (P) 计划缺 X\n", encoding="utf-8")
    st = _state(tmp_path)
    r = chain(st, batch="66bae2b0678a", prose_file=str(pf))
    assert r["steps"]["prose"]["count"] == 1, r["steps"]["prose"]
    fs = _prose_facets(st)
    assert fs and any("relevance:in" in f for f in fs[0]), fs
    assert any(str(x).startswith("bm25:") for x in fs[0]), fs


# ── ② 与批内证据无重叠的散文 ⟹ `relevance:out`（不冒充相关）──────────────────
def test_relevance_out_when_unrelated(tmp_path, monkeypatch):
    _stub(monkeypatch, _agg_with_refs("毫不对应内容"))
    from gk_moa_aggregate import chain
    pf = tmp_path / "p.txt"
    pf.write_text("- (P) 计划缺 X\n", encoding="utf-8")
    st = _state(tmp_path)
    chain(st, batch="66bae2b0678a", prose_file=str(pf))
    fs = _prose_facets(st)
    assert fs and "relevance:out" in fs[0] and "relevance:in" not in fs[0], fs


# ── ③ 无 refs ⟹ 仍落库，但判 out（无证据锚 ⟹ 未验证，禁默认放行）─────────────
def test_no_refs_still_registers_but_out(tmp_path, monkeypatch):
    _stub(monkeypatch, _agg_no_refs())
    from gk_moa_aggregate import chain
    pf = tmp_path / "p.txt"
    pf.write_text("- (P) 计划缺 X\n", encoding="utf-8")
    st = _state(tmp_path)
    r = chain(st, batch="66bae2b0678a", prose_file=str(pf))
    assert r["steps"]["prose"]["count"] == 1, r["steps"]["prose"]
    fs = _prose_facets(st)
    assert fs and "relevance:out" in fs[0], fs


# ── ④ 形态臂：chain 把 aggregate refs 传进散文转换（单源 `_refs_of`）──────────
def test_python_wires_t12():
    src = (SCRIPTS / "gk_moa_aggregate.py").read_text(encoding="utf-8")
    assert "refs=_refs_of(agg)" in src, "chain 未把 aggregate refs 传入散文转换（闸未启用）"

"""
test_gk_moa_chain_t13.py -- T13 红先臂：链尾 **中文嵌入向量落盘**（`gk_finding_embed.run`）
================================================================================
正本：`docs/plans/2026-10-14-moa-chain-automation-plan.md` §3-T13（finding `ECC-FAF2A8F0A0DF`）。

缺口：chain 尾不落 finding 向量 ⟹ `principal` 的中文嵌入召回对**新 finding**不可用（Jaccard 中文
近重复盲区）。本切片：链尾 `steps["embeddings"]` **复用** `gk_finding_embed.run`（**单一源**）；
**契约存在时**才维护（opt-in by presence）；不可用 ⟹ 具名 `error`（**禁静默假绿**）。
"""
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import gk_finding_embed  # noqa: E402


def _stub(monkeypatch):
    import gk_moa_aggregate as M
    agg = {"trace": {"count": 1, "attribution": {"mode": "batch_bound",
                                                 "batch_id": "66bae2b0678a"}},
           "consensus": {"n_refs": 1, "n_clusters": 1, "top_weight": 0.5,
                         "min_agreement": 0.66, "abstain": True, "contradictions": []},
           "clusters": [], "references": [{"arm_group": "G1", "overall_score": 1}]}
    monkeypatch.setattr(M, "aggregate", lambda *a, **k: json.loads(json.dumps(agg)))
    monkeypatch.setattr(M, "emit_aggregate_finding", lambda *a, **k: {"ok": True, "id": "ECC-STUB"})
    monkeypatch.setattr(M, "render_html", lambda *a, **k: "<html>STUB</html>")


def _state(tmp_path, contract=False) -> str:
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {"ecc_findings": []}}), encoding="utf-8")
    if contract:
        (tmp_path / ".gatekeeper.state.finding-embeddings.jsonl").write_text(
            '{"id":"ECC-A","vec":[0.1,0.2]}\n', encoding="utf-8")
    return str(st)


# ── ① 契约存在 + producer 可用 ⟹ 落盘 `written`（单一源 gk_finding_embed.run）───
def test_embeddings_written_when_contract_present(tmp_path, monkeypatch):
    _stub(monkeypatch)
    seen = {}
    monkeypatch.setattr(gk_finding_embed, "run",
                        lambda sf, **k: seen.update(sf=sf) or {"ok": True, "vectors": 3,
                                                               "targets": 3, "path": sf + ".x"})
    from gk_moa_aggregate import chain
    sf = _state(tmp_path, contract=True)
    r = chain(sf, batch="66bae2b0678a")
    em = r["steps"]["embeddings"]
    assert em["status"] == "written" and em["vectors"] == 3, em
    assert em["source"] == "gk_finding_embed.run", em
    assert seen.get("sf") == sf, "未以本 state 调 producer（禁第二实现）"


# ── ② 契约缺失 ⟹ `disabled`（opt-in by presence，不强制起 Node）────────────────
def test_embeddings_disabled_without_contract(tmp_path, monkeypatch):
    _stub(monkeypatch)
    monkeypatch.setattr(gk_finding_embed, "run",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("不应调用 producer")))
    from gk_moa_aggregate import chain
    r = chain(_state(tmp_path, contract=False), batch="66bae2b0678a")
    em = r["steps"]["embeddings"]
    assert em["status"] == "disabled" and em["reason"] == "NO_CONTRACT", em


# ── ③ producer 失败 ⟹ 具名 `error`（禁静默假绿）───────────────────────────────
def test_embeddings_error_is_named(tmp_path, monkeypatch):
    _stub(monkeypatch)
    monkeypatch.setattr(gk_finding_embed, "run",
                        lambda sf, **k: {"ok": False, "error": "NO_NODE_STACK"})
    from gk_moa_aggregate import chain
    r = chain(_state(tmp_path, contract=True), batch="66bae2b0678a")
    em = r["steps"]["embeddings"]
    assert em["status"] == "error" and em["error"] == "NO_NODE_STACK", em


# ── ④ 形态臂：链接线 `gk_finding_embed.run`（单源）─────────────────────────────
def test_python_wires_t13():
    src = (SCRIPTS / "gk_moa_aggregate.py").read_text(encoding="utf-8")
    assert "import gk_finding_embed" in src, "chain 未接嵌入 producer"
    assert "_E.run(state_file)" in src, "chain 未走 gk_finding_embed.run（T13 单源）"
    assert '"embeddings"' in src, "chain 尾未落 steps.embeddings"

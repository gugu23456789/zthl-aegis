"""
test_gk_moa_chain_t14.py -- T14 红先臂：臂级标量分**单源** `arm_score`（落库面 ↔ seal 面同口径）
================================================================================
正本：finding `ECC-03DF9BDC3A1B`（subagent `sub-1792078787-70-4795` 查清）。

根因：`overall_score` 全域恒 null —— ① runner 不计算（`subagent_runner.py:3054` 硬写 None）；
② CLI 落库 `gatekeeper-cli.sh:4844` 裸透传 null；③ **真缺口 = 派生值落点错位**：7 维均值归一化
派生只存在于 `merge_sealed_agent_score` 内嵌闭包，只写 seal 槽、**从不回写** history。

本切片：①`arm_score` 提为**模块级单源**（落库面/链面共用）；②CLI 落库改用它（七维派生回填
history）；③链 `steps.integrity` 改用它（**存量** history 也能取分）+ 缺分**计数**（禁静默 continue）；
④「真链」臂（七维-only ⟹ 可估，非 UNDER-POWERED）。
"""
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
CLI = SCRIPTS.parent / "gatekeeper-cli.sh"


def _sd(v):
    return {"dim1": v}


def _agg(refs: list) -> dict:
    return {
        "trace": {"count": len(refs), "attribution": {"mode": "batch_bound",
                                                      "batch_id": "66bae2b0678a"}},
        "consensus": {"n_refs": len(refs), "n_clusters": 1, "top_weight": 0.5,
                      "min_agreement": 0.66, "abstain": True, "contradictions": []},
        "clusters": [], "references": refs,
    }


def _stub(monkeypatch, agg: dict):
    import gk_moa_aggregate as M
    monkeypatch.setattr(M, "aggregate", lambda *a, **k: json.loads(json.dumps(agg)))
    monkeypatch.setattr(M, "emit_aggregate_finding", lambda *a, **k: {"ok": True, "id": "ECC-STUB"})
    monkeypatch.setattr(M, "render_html", lambda *a, **k: "<html>STUB</html>")


def _state(tmp_path) -> str:
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {"ecc_findings": []}}), encoding="utf-8")
    return str(st)


# ── ① `arm_score` 模块级单源（seal 面不再内嵌闭包）───────────────────────────
def test_arm_score_is_module_level_single_source():
    import gk_moa_aggregate as M
    assert callable(getattr(M, "arm_score", None)), "arm_score 未提为模块级"
    assert M.arm_score({"overall_score": 0.42}) == 0.42
    assert M.arm_score({"seven_dim_score": {"a": 10, "b": 20}}) == 0.15   # mean/100
    assert M.arm_score({}) is None


# ── ② 真链：七维-only ⟹ 可估（arm_score 派生）⟹ 非 UNDER-POWERED ────────────
def test_chain_integrity_estimable_from_seven_dim(tmp_path, monkeypatch):
    refs = ([{"arm_group": "G1", "seven_dim_score": _sd(v)} for v in (10, 20, 10, 20)]
            + [{"arm_group": "G2", "seven_dim_score": _sd(v)} for v in (90, 100, 90, 100)])
    _stub(monkeypatch, _agg(refs))
    from gk_moa_aggregate import chain
    r = chain(_state(tmp_path), batch="66bae2b0678a")
    it = r["steps"]["integrity"]
    assert it["k"] == 2 and it["n"] == 8, it
    assert it["verdict"] == "SEPARATED", it
    assert it["n_missing"] == 0, it


# ── ③ 缺分**计数**（禁静默 continue）────────────────────────────────────────
def test_chain_integrity_counts_missing(tmp_path, monkeypatch):
    refs = ([{"arm_group": "G1", "seven_dim_score": _sd(v)} for v in (10, 20, 10, 20)]
            + [{"arm_group": "G2", "seven_dim_score": _sd(v)} for v in (90, 100, 90, 100)]
            + [{"arm_group": "G3"}])                      # 无任何分数 ⟹ 应计数
    _stub(monkeypatch, _agg(refs))
    from gk_moa_aggregate import chain
    r = chain(_state(tmp_path), batch="66bae2b0678a")
    it = r["steps"]["integrity"]
    assert it["n_missing"] == 1, it
    assert it["missing_reason"] == "ARM_SCORE_MISSING", it


# ── ④ 形态臂：CLI 落库面改用单源 `arm_score`（七维派生回填 history）──────────
def test_cli_writes_arm_score():
    """落库面单源：2026-11-04 起从 CLI 内联块下沉到 gk_monitor_payload.py。"""
    payload = SCRIPTS / "gk_monitor_payload.py"
    s = payload.read_text(encoding="utf-8")
    assert "arm_score(" in s, "落库面未用单源 arm_score（history 仍恒 null）"
    assert "'overall_score':out.get('overall_score')," not in s, "落库面仍是裸透传"


# ── ⑤ 真链（CLI 落库面）：七维-only 臂 ⟹ `overall_score` **派生回填**（禁裸透传 null）──
def test_cli_payload_fills_overall_score_from_seven_dim(tmp_path):
    from test_gk_moa_batch_identity import _ecc, _run_payload
    ecc = _ecc("plan-refinement: 落库派生 overall_score")
    ecc["seven_dim_score"] = {"d1": 15}          # ⟹ arm_score = 15/100 = 0.15
    st = _run_payload(tmp_path, ecc)
    ent = st["gate_data"]["subagent_history"][-1]
    assert ent["overall_score"] == 0.15, ent.get("overall_score")


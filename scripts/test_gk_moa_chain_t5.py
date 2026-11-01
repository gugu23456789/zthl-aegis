"""
test_gk_moa_chain_t5.py -- MoA 链 T5 红先臂：散文接收 + 二次合并（并入台账，root_key=prose:<hash> 幂等）
================================================================================
正本：`docs/plans/2026-10-14-moa-chain-automation-plan.md` §3-T5「链收 `--prose <file>` / stdin；
非空 ⟹ 自动 `from-prose` → 结果并入台账（`root_key=prose:<hash>` 幂等）」。

现状：`chain()` 收 `prose_file` 却只标 `steps["prose"]={"status":"pending(T5)"}` —— **收参不干活**
（假状态）。本切片：①缺省无散文不动作；②非空 ⟹ `gk_prose_findings.convert` → `gk_finding.register`
并入台账；③重跑**幂等**（root_key 双档合并不重复）；④空散文不落库；⑤文件不可读如实报 `error`；
⑥`--prose -` 读 stdin；⑦CLI 转发 `--prose`（挂既有命令，零新增 `_CMD_REG`）；⑧python 接线无 pending 假状态。
"""
import io
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
CLI = SCRIPTS.parent / "gatekeeper-cli.sh"

_AGG = {
    "trace": {"count": 6, "attribution": {"mode": "batch_bound", "batch_id": "66bae2b0678a"}},
    "consensus": {"n_refs": 6, "n_clusters": 2, "top_weight": 0.33, "min_agreement": 0.66,
                  "abstain": True, "pollution_tilt": 0.1, "contradictions": ["c1"]},
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


def _findings(state) -> list:
    d = json.loads(Path(state).read_text(encoding="utf-8"))
    return (d.get("gate_data") or {}).get("ecc_findings") or []


# ── ① 缺省无散文：不动作（且非 pending 假状态）──────────────────────────────
def test_chain_prose_absent(tmp_path, monkeypatch):
    _stub(monkeypatch)
    from gk_moa_aggregate import chain
    r = chain(_state(tmp_path), batch="66bae2b0678a")
    pr = r["steps"]["prose"]
    assert pr["requested"] is False, pr
    assert pr.get("status") != "pending(T5)", pr


# ── ② 非空散文 ⟹ 转换并入台账（root_key=prose:<hash>）────────────────────────
def test_chain_prose_merges(tmp_path, monkeypatch):
    _stub(monkeypatch)
    from gk_moa_aggregate import chain
    pf = tmp_path / "prose.txt"
    pf.write_text("- (P) 计划缺 X\n- (L) 机制缺 Y\n", encoding="utf-8")
    st = _state(tmp_path)
    r = chain(st, batch="66bae2b0678a", prose_file=str(pf))
    pr = r["steps"]["prose"]
    assert pr["status"] == "merged" and pr["count"] == 2, pr
    fs = _findings(st)
    assert len(fs) == 2, [f.get("root_key") for f in fs]
    assert all(str(f.get("root_key", "")).startswith("prose:") for f in fs)


# ── ③ 幂等：同散文重跑不产生重复条目 ────────────────────────────────────────
def test_chain_prose_idempotent(tmp_path, monkeypatch):
    _stub(monkeypatch)
    from gk_moa_aggregate import chain
    pf = tmp_path / "prose.txt"
    pf.write_text("- (P) 计划缺 X\n", encoding="utf-8")
    st = _state(tmp_path)
    chain(st, batch="66bae2b0678a", prose_file=str(pf))
    chain(st, batch="66bae2b0678a", prose_file=str(pf))
    assert len(_findings(st)) == 1, [f.get("root_key") for f in _findings(st)]


# ── ④ 空散文：不落库（count=0）──────────────────────────────────────────────
def test_chain_prose_empty(tmp_path, monkeypatch):
    _stub(monkeypatch)
    from gk_moa_aggregate import chain
    pf = tmp_path / "empty.txt"
    pf.write_text("\n\n", encoding="utf-8")
    st = _state(tmp_path)
    r = chain(st, batch="66bae2b0678a", prose_file=str(pf))
    assert r["steps"]["prose"]["count"] == 0, r["steps"]["prose"]
    assert _findings(st) == []


# ── ⑤ 文件不可读：如实报 error（禁静默/假绿）─────────────────────────────────
def test_chain_prose_unreadable(tmp_path, monkeypatch):
    _stub(monkeypatch)
    from gk_moa_aggregate import chain
    st = _state(tmp_path)
    r = chain(st, batch="66bae2b0678a", prose_file=str(tmp_path / "nope.txt"))
    assert r["steps"]["prose"]["status"] == "error", r["steps"]["prose"]


# ── ⑥ `--prose -` 读 stdin ──────────────────────────────────────────────────
def test_chain_prose_stdin(tmp_path, monkeypatch):
    _stub(monkeypatch)
    monkeypatch.setattr("sys.stdin", io.StringIO("- (M) 机制缺 Z\n"))
    from gk_moa_aggregate import chain
    st = _state(tmp_path)
    r = chain(st, batch="66bae2b0678a", prose_file="-")
    assert r["steps"]["prose"]["count"] == 1, r["steps"]["prose"]
    assert len(_findings(st)) == 1


# ── ⑦ 形态臂：CLI 转发 `--prose` + python 接线无 pending 假状态 ──────────────
def test_cli_forwards_prose():
    s = CLI.read_text(encoding="utf-8")
    assert "--prose) prose_file=" in s, "--prose 未解析"
    assert 'args+=(--prose "$prose_file")' in s, "--prose 未转发"


def test_python_wires_t5_no_pending():
    src = (SCRIPTS / "gk_moa_aggregate.py").read_text(encoding="utf-8")
    assert 'add_argument("--prose"' in src, "python 未注册 --prose"
    assert '"pending(T5)"' not in src, "T5 仍是 pending 假状态"
    assert "gk_prose_findings" in src, "未接散文转换（from-prose 单源）"

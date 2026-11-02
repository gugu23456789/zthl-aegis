"""
test_gk_moa_chain_t4.py -- MoA 链 T4 红先臂：链尾 HTML **自动导出**（路径规则化）
================================================================================
正本：`docs/plans/2026-10-14-moa-chain-automation-plan.md` §3-T4「HTML 自动导出：链尾自动
`--html`（路径规则化）」。

现状：`chain()` 收了 `html_path` 却只标 `steps["html"]={"status":"pending(T4)"}` —— **收参不干活**
（假状态）。本切片：① 链尾缺省 `render_html(agg)` 写盘（`state` 域规则化路径）；② `--no-html`
opt-out；③ `html_path` 显式覆盖；④ CLI 转发 `--no-html`（挂既有命令，零新增 `_CMD_REG`）。
"""
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
    st.write_text("{}", encoding="utf-8")
    return str(st)


# ── ① 缺省：链尾写盘（state 域规则化路径）──────────────────────────────────
def test_chain_writes_html_by_default(tmp_path, monkeypatch):
    _stub(monkeypatch)
    from gk_moa_aggregate import chain
    r = chain(_state(tmp_path), batch="66bae2b0678a")
    h = r["steps"]["html"]
    assert h["status"] == "written", h
    p = h["path"]
    assert Path(p).is_file(), p
    assert "STUB" in Path(p).read_text(encoding="utf-8")
    assert p.endswith("moa-chain-66bae2b0678a.html"), p


# ── ② `--no-html` opt-out ───────────────────────────────────────────────────
def test_chain_no_html_disables(tmp_path, monkeypatch):
    _stub(monkeypatch)
    from gk_moa_aggregate import chain
    r = chain(_state(tmp_path), batch="66bae2b0678a", no_html=True)
    assert r["steps"]["html"]["status"] == "disabled", r["steps"]["html"]


# ── ③ 显式 `html_path` 覆盖 ─────────────────────────────────────────────────
def test_chain_html_path_override(tmp_path, monkeypatch):
    _stub(monkeypatch)
    from gk_moa_aggregate import chain
    tgt = tmp_path / "sub" / "x.html"
    r = chain(_state(tmp_path), batch="66bae2b0678a", html_path=str(tgt))
    assert r["steps"]["html"]["status"] == "written", r["steps"]["html"]
    assert Path(r["steps"]["html"]["path"]) == tgt and tgt.is_file()


# ── ④ 形态臂：CLI 转发 + python 接线 + 无 pending 假状态 ─────────────────────
def test_cli_forwards_no_html():
    s = CLI.read_text(encoding="utf-8")
    assert "--no-html) no_html_flag=true" in s, "--no-html 未解析"
    assert "$no_html_flag && args+=(--no-html)" in s, "--no-html 未转发"


def test_python_wires_t4_no_pending():
    src = (SCRIPTS / "gk_moa_aggregate.py").read_text(encoding="utf-8")
    assert "_chain_html_path" in src, "未见路径规则化 helper"
    assert 'status": "pending(T4)' not in src, "T4 仍是 pending 假状态"
    assert 'add_argument("--no-html"' in src, "python 未注册 --no-html"

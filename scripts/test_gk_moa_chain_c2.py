"""
test_gk_moa_chain_c2.py -- C2 轮次止损接入 `moa-aggregate --chain`（自动）
================================================================================
正本：owner 2026-10-27 令「C2 接入改自动」。修前 `chain()` 的 `steps.convergence`
只读 `gk_convergence_estimator.evaluate`（自锁 `r̂≥1`），**不跑** C2 早停
（`gk_convergence_evaluator`：`r̂ ≥ r_min` 连续 K 轮 ⟹ NO_CONVERGENCE + switch_to="M"）。

本切片：链内**默认**增 `steps.early_stop`（μ 源 = `_trend_from_state` 的 `moa-agg:` 行；
`noconv:` 行 mu=0 须排除）；kill switch 沿用 `GK_CONV_EARLY_STOP=0`。
"""
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

PLAN = "docs/plans/probe-plan.md"


def _stub(monkeypatch):
    import gk_moa_aggregate as M
    agg = {"trace": {"count": 3}, "consensus": {"n_refs": 3, "n_clusters": 1},
           "clusters": [], "references": []}
    monkeypatch.setattr(M, "aggregate", lambda *a, **k: json.loads(json.dumps(agg)))
    monkeypatch.setattr(M, "emit_aggregate_finding", lambda *a, **k: {"ok": True, "id": "ECC-AGG"})
    monkeypatch.setattr(M, "render_html", lambda *a, **k: "<html>STUB</html>")


def _seed(tmp_path, mus, *, extra=None) -> str:
    """按轮次造 `moa-agg:` 测量 finding（`facets: refs:<μ>`），可选追加干扰行。"""
    fs = []
    for i, m in enumerate(mus):
        fs.append({"id": "ECC-R%d" % i, "title": "moa r%d" % i, "source": "review",
                   "status": "open", "root_key": "moa-agg:%08x" % (0xA000 + i),
                   "created_at": "2026-10-27T00:%02d:00Z" % (10 + i),
                   "anchors": ["plan:" + PLAN], "facets": ["refs:%d" % m, "weight:0.90"]})
    fs.extend(extra or [])
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {"ecc_findings": fs}}), encoding="utf-8")
    return str(st)


def _run(st):
    from gk_moa_aggregate import chain
    return chain(st, plan=PLAN, no_html=True)


# ── ① 形态 + 判定：不收敛（末尾 K 轮比值 ≥ r_min）⟹ NO_CONVERGENCE + 转 M ──────
def test_chain_early_stop_no_convergence(tmp_path, monkeypatch):
    _stub(monkeypatch)
    monkeypatch.delenv("GK_CONV_EARLY_STOP", raising=False)
    r = _run(_seed(tmp_path, [100, 98, 97]))
    es = r["steps"]["early_stop"]
    assert es["source"] == "gk_convergence_evaluator.no_convergence_finding", es
    assert es["verdict"] == "NO_CONVERGENCE", es
    assert es["switch_to"] == "M", es
    assert es["finding"], "NO_CONVERGENCE 必须落 noconv: finding"
    assert es["rounds"] == 3, es


# ── ② 收敛（比值 < r_min）⟹ CONVERGING，且**不**落 finding ────────────────────
def test_chain_early_stop_converging(tmp_path, monkeypatch):
    _stub(monkeypatch)
    monkeypatch.delenv("GK_CONV_EARLY_STOP", raising=False)
    r = _run(_seed(tmp_path, [100, 50, 20]))
    es = r["steps"]["early_stop"]
    assert es["verdict"] == "CONVERGING", es
    assert not es["finding"] and not es["switch_to"], es


# ── ③ kill switch：仍出判决，但不落账（suppressed）────────────────────────────
def test_chain_early_stop_kill_switch(tmp_path, monkeypatch):
    _stub(monkeypatch)
    monkeypatch.setenv("GK_CONV_EARLY_STOP", "0")
    r = _run(_seed(tmp_path, [100, 98, 97]))
    es = r["steps"]["early_stop"]
    assert es["verdict"] == "NO_CONVERGENCE", es
    assert es["suppressed"] is True, es
    assert not es["finding"], "kill switch 生效时不得落 finding"


# ── ④ 轮次不足（< K+1 轮）⟹ INSUFFICIENT_ROUNDS，不误判不收敛 ────────────────
def test_chain_early_stop_insufficient_rounds(tmp_path, monkeypatch):
    _stub(monkeypatch)
    monkeypatch.delenv("GK_CONV_EARLY_STOP", raising=False)
    r = _run(_seed(tmp_path, [100, 99]))
    es = r["steps"]["early_stop"]
    assert es["verdict"] == "INSUFFICIENT_ROUNDS", es
    assert not es["finding"], es


# ── ⑤ μ 源过滤：`noconv:` 行（mu=0）不得混入序列 ─────────────────────────────
def test_chain_early_stop_excludes_noconv_rows(tmp_path, monkeypatch):
    _stub(monkeypatch)
    monkeypatch.delenv("GK_CONV_EARLY_STOP", raising=False)
    pollution = {"id": "ECC-NC", "title": "noconv", "source": "review", "status": "open",
                 "root_key": "noconv:deadbeefdeadbeef", "created_at": "2026-10-27T00:30:00Z",
                 "anchors": ["plan:" + PLAN], "facets": []}
    r = _run(_seed(tmp_path, [100, 98, 97], extra=[pollution]))
    es = r["steps"]["early_stop"]
    assert es["rounds"] == 3, es          # 只数 moa-agg 行
    assert es["verdict"] == "NO_CONVERGENCE", es

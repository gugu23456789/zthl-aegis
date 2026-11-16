"""MoA 链尾 HTML 的**版本/轮次/批次**标识（2026-11-12，owner 令红先）。

病象：旧命名 `moa-chain-<batch>.html` / `moa-chain-<plan>.html` 无版本、无轮次，
人工无法判断「哪一版、哪一轮」，也无法从页面判断跨轮聚合是否跑过。
判据：
  ① 命名 = `moa-chain-<plan-key>-<DRAFT-N>-<Rk>-<batch>.html`；
  ② 页内 `<body data-plan/data-version/data-round/data-batch>` + 跨轮结论 banner；
  ③ 计划/批次缺省时回落旧名（批锚自解析通道零回归）。
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_moa_aggregate as M  # noqa: E402


def test_chain_html_path_has_version_and_round():
    p = M._chain_html_path(
        "", "/tmp/x.state",
        plan="docs/analysis/2026-11-12-audit-model-adaptive-lifecycle-408.md",
        batch="eb696a83dc04", version="DRAFT-4", round_label="R1")
    assert p.endswith(
        "moa-chain-2026-11-12-audit-model-adaptive-lifecycle-408-DRAFT-4-R1-eb696a83dc04.html"), p


def test_chain_html_path_legacy_fallback():
    p = M._chain_html_path("", "/tmp/x.state", "66bae2b0678a")
    assert p.endswith("moa-chain-66bae2b0678a.html"), p


def test_plan_version_reads_draft(tmp_path):
    p = tmp_path / "x-plan.md"
    p.write_text("# x\n\n> 状态：DRAFT-4（2026-11-12）\n", encoding="utf-8")
    assert M.plan_version(str(p)) == "DRAFT-4"


def test_trend_plan_filter_normalizes_path(tmp_path, monkeypatch):
    """计划过滤走 `plan_identity`：路径形态入参必须命中 basename facet（否则误报样本不足）。"""
    import gk_finding

    st = tmp_path / "s.state"
    st.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(gk_finding, "load_findings_union", lambda _s: [{
        "root_key": "moa-agg:x", "id": "ECC-X", "created_at": "2026-11-12T10:00:00Z",
        "source_note": "引用=6 簇=1 一致度=0.9",
        "facets": ["plan:2026-11-12-audit-model-adaptive-lifecycle-408.md", "refs:6"],
    }])
    tr = M._trend_from_state(
        str(st), plan="docs/analysis/2026-11-12-audit-model-adaptive-lifecycle-408.md")
    assert len(tr) == 1 and tr[0]["mu"] == 6, tr


def test_render_html_shows_identity_and_cross_round_banner():
    agg = {"mode": "moa_chain", "references": [{"task": "t", "conclusion": "c"}],
           "trace": {}}
    meta = {"plan": "docs/analysis/x.md", "batch": "abc123def456",
            "version": "DRAFT-4", "round": "R3",
            "stop": {"verdict": "NO_CONVERGENCE", "r_hat": 1.0, "r_min": 0.9,
                     "k_rounds": 2, "trailing_k": [1.0, 1.0], "rounds": 3,
                     "switch_to": "M", "suppressed": False,
                     "finding": "ECC-D748D5BEDD3E", "source": "evaluator"},
            "journal": {"verdict": "RATES_DEGENERATE_SINGLE_ROUND", "n_star": None,
                        "breaker": False, "source": "estimator"},
            "rounds_detail": [
                {"round": "2026-11-12T10:00:00Z", "mu": 6, "top_weight": 0.9,
                 "batch": "abc123def456", "finding": "ECC-D748D5BEDD3E"},
            ],
            "mu": [6, 6, 6]}
    html = M.render_html(agg, meta, trend=[])
    for s in ('data-version="DRAFT-4"', 'data-round="R3"', 'data-batch="abc123def456"',
              "跨轮聚合：NO_CONVERGENCE", "μ=[6, 6, 6]", "switch_to=M",
              "ECC-D748D5BEDD3E", "r_min", "trailing_k", "K（连续轮数）",
              "RATES_DEGENERATE_SINGLE_ROUND", "测量序列", "μ(refs)"):
        assert s in html, s

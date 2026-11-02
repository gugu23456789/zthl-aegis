#!/usr/bin/env python3
"""红先：MoA HTML 必须把**污染台账（P5）与相位屏（P6）**显示出来（2026-11-02）。

缺陷（实测）：`render_html` 只显示 `agreement` / `top_weight`，而 `pollution_tilt` 只在
M 建议的 evidence 文本里出现；`agreement_eff = agreement·(1−κ_tilt)` 完全不显示；
`phase-probe` 的结果也从不进页面。⟹ 读者看到的是「没有污染」而不是「污染未被观测」。

论文口径（WWW'27 v35 App C/D）：
  · P5：`κ_cap ≥ 0.75` 且 `κ_tilt ≤ 0.25`（批均值；pooled 仅描述性）
  · 未观测的 tilt **按 0 填补** ⟹ 页面必须显式区分「未观测」与「真 0」
  · P6：相位屏只作 screen-pass，不称「相位安全」

本臂钉住：
  ① 有观测时显示 κ_tilt 数值 + 阈值 0.25；
  ② `pollution_tilt=None` 显示「未观测」，**不得**渲染成 `0.000`；
  ③ agreement 与 agreement_eff 并列（折减可见）；
  ④ 相位屏缺失时显式「未运行」，有数据时显示 p 值与 screen-pass 语义；
  ⑤ 旧 agg（无 consensus 污染字段）零回归 —— 不出该面板。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gk_moa_aggregate import render_html  # noqa: E402
from gk_moa_aggregate import _trend_from_state, _trend_svg  # noqa: E402


def _agg(**cons_over):
    cons = {"agreement": 0.8, "n_clusters": 2, "top_weight": 0.8, "abstain": False}
    cons.update(cons_over)
    return {
        "mode": "moa_aggregate",
        "references": [{"subagent_id": "sub-1", "conclusion": "ok"}],
        "consensus": cons,
        "trace": {},
    }


def test_pollution_panel_shows_tilt_and_threshold():
    html = render_html(_agg(pollution_tilt=0.1, agreement_eff=0.72))
    assert "κ_tilt" in html, "污染面板缺失（页面看不到 tilt）"
    assert "0.25" in html, "P5 阈值 0.25 未显示"
    assert "0.100" in html, "已观测的 tilt 值未渲染"


def test_agreement_discount_is_visible():
    html = render_html(_agg(agreement=0.8, pollution_tilt=0.25, agreement_eff=0.6))
    assert "0.8" in html and "0.6" in html, "agreement 与 agreement_eff 未并列（折减不可见）"
    assert "agreement_eff" in html or "折减" in html, "折减语义未标注"


def test_unobserved_tilt_is_not_rendered_as_zero():
    html = render_html(_agg(pollution_tilt=None))
    start = html.find("κ_tilt")
    assert start != -1, "污染面板缺失"
    seg = html[start:start + 260]
    assert "未观测" in seg, "未观测 tilt 未显式标注（会被误读成真 0）：%r" % seg
    assert "0.000" not in seg, "未观测被渲染成 0.000（语义失真）：%r" % seg


def test_phase_screen_absent_is_explicit_not_pass():
    html = render_html(_agg())
    assert "相位屏" in html, "相位屏条目缺失"
    assert "未运行" in html, "相位屏缺失时未显式标注（默认 pass 即假绿）"


def test_phase_screen_renders_pvalue_and_screen_pass_only():
    a = _agg()
    a["trace"]["phase_screen"] = {"alpha": 0.05, "p_value": 0.31, "cells": 6, "mde": 0.63}
    html = render_html(a)
    assert "0.31" in html, "相位屏 p 值未渲染"
    assert "screen-pass" in html, "相位屏结论未按论文口径标注（screen-pass only）"


def test_legacy_agg_without_pollution_keys_has_no_panel():
    html = render_html({"mode": "moa_aggregate",
                        "references": [{"subagent_id": "s", "conclusion": "c"}],
                        "trace": {}})
    assert "κ_tilt" not in html, "无污染字段的旧 agg 被强行渲染出面板（零回归破坏）"


# ── 跨轮：facet → trend → SVG（2026-11-02）─────────────────────────────────

def _state(tmp_path, facets):
    st = tmp_path / ".gatekeeper.state"
    st.write_text(__import__("json").dumps({"gate_data": {"ecc_findings": [{
        "id": "ECC-AAAAAAAAAAAA", "status": "open",
        "root_key": "moa-agg:deadbeefdeadbeef",
        "created_at": "2026-11-01T10:00:00Z",
        "facets": facets,
    }]}}), encoding="utf-8")
    return str(st)


def test_trend_reads_tilt_facet(tmp_path):
    trend = _trend_from_state(_state(
        tmp_path, ["refs:3", "clusters:1", "weight:0.70", "tilt:0.200",
                   "tilt-state:observed"]))
    assert len(trend) == 1
    assert trend[0]["tilt"] == 0.2 and trend[0]["tilt_state"] == "observed"


def test_trend_unobserved_tilt_is_none_not_zero(tmp_path):
    trend = _trend_from_state(_state(tmp_path, ["refs:0", "clusters:0", "weight:0.00"]))
    assert trend[0]["tilt"] is None, "旧账/未观测被读成 0（会把「没观测」当「没污染」）"


def test_kpi_marks_empty_batch():
    html = render_html({"mode": "moa_aggregate", "references": [],
                        "consensus": {"n_clusters": 0, "pollution_tilt": 0.0},
                        "trace": {}})
    assert "空批" in html, "空批未在 KPI 显式标注"


def test_pollution_empty_batch_not_zero():
    html = render_html({"mode": "moa_aggregate", "references": [],
                        "consensus": {"n_clusters": 0, "pollution_tilt": 0.0},
                        "trace": {}})
    start = html.find("κ_tilt")
    assert start != -1
    seg = html[start:start + 260]
    assert "未观测（空批）" in seg, seg
    assert "0.000" not in seg, "空批被渲染成 0.000"


def test_trend_svg_has_tilt_series_and_hollow_missing():
    svg = _trend_svg([
        {"round": "r1", "mu": 1, "top_weight": 0.5, "tilt": 0.2},
        {"round": "r2", "mu": 2, "top_weight": 0.6, "tilt": None},
    ])
    assert "c-tilt" in svg, "污染序列未绘制"
    assert "c-tilt-miss" in svg, "未观测点未用空心标记（会被误读为 0）"

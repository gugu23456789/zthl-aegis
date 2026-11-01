#!/usr/bin/env python3
"""C 期(ii) 红先：MoA HTML 图表精细化 —— **ECharts 主路**（生产实际渲染路径）。

（`ECC-93F54BA38157`，族 `MOA-ECHARTS-REFINE`；续 plan 2026-10-04 §12.4-3）

C 期已精细化**手写 SVG 降级路**；但生产 `assets/echarts.min.js` 在库 ⟹ 页面实际走**主路**
⟹ 须**同口径**精细化 `_ECHARTS_INIT_JS`。

现状缺口（HEAD）：
  · 调色板用 `#b58900`（≠ 页面 token `--warn #a9761a`）⟹ 与 CSS 观感不统一；
  · 图② 环形**无中心汇总**（簇数 / 总臂数）；
  · 图④ 热力**缺轴名**（组 / 结论簇）与色标说明；
  · tooltip **无统一圆角样式**。

本节只钉「主路观感精细化」，不改数据口径、不加 HTML 页、不碰 7 维分。
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_moa_aggregate as M  # noqa: E402

PLAN = "/p/docs/plans/x-plan.md"
BATCH = "abc123def456"
_A = "结论：本轮改动范围蔓延超出计划边界，建议收窄到原定模块，禁止顺手重构无关代码。" * 6
_B = "结论：回滚路径缺失，若中途失败将无法恢复现场，须补齐退路与快照机制。" * 6
TREND = [{"round": "R1", "mu": 8, "top_weight": 0.50},
         {"round": "R2", "mu": 10, "top_weight": 0.40},
         {"round": "R3", "mu": 9, "top_weight": 0.33}]


def _agg(tmp_path):
    hist = [
        {"subagent_id": "a1", "batch_id": BATCH, "arm_group": "G1",
         "task": "plan-refinement: %s — 质询" % PLAN, "conclusion": _A,
         "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}],
         "budget_status": "hard", "total_tokens": 9000, "token_budget": 8000},
        {"subagent_id": "a2", "batch_id": BATCH, "arm_group": "G1",
         "task": "plan-refinement: %s — 质询" % PLAN, "conclusion": _A,
         "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]},
        {"subagent_id": "g3", "batch_id": BATCH, "arm_group": "G3",
         "task": "plan-refinement: %s — 质询" % PLAN, "conclusion": _B,
         "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]},
    ]
    sf = tmp_path / "state.json"
    sf.write_text(json.dumps({"gate_data": {"subagent_history": hist, "ecc_findings": []}},
                             ensure_ascii=False), encoding="utf-8")
    return M.aggregate(str(sf), None, "plan-refinement", plan=PLAN, batch=BATCH)


def test_echarts_palette_token_unified():
    """调色板须统一到页面 token（`--warn #a9761a`），旧 `#b58900` 不得残留。"""
    js = M._ECHARTS_INIT_JS
    assert "#a9761a" in js, "调色板未统一到页面 token --warn(#a9761a)"
    assert "#b58900" not in js, "旧调色板 #b58900 残留"


def test_echarts_donut_center_summary():
    """图② 环形须有**中心汇总**（`graphic` 元素：簇数 / 总臂数）。"""
    js = M._ECHARTS_INIT_JS
    assert "graphic:" in js, "图② 缺中心汇总（graphic 元素）"
    assert "簇" in js and "臂" in js, "中心汇总须含簇数/臂数文案"


def test_echarts_heatmap_axis_names():
    """图④ 热力须补**轴名**（组 / 结论簇）。"""
    js = M._ECHARTS_INIT_JS
    assert "name:'组'" in js, "图④ y 轴缺轴名（组）"
    assert "name:'结论簇'" in js, "图④ x 轴缺轴名（结论簇）"


def test_echarts_tooltip_uniform_style():
    """tooltip 须有统一圆角样式（`borderRadius`）。"""
    js = M._ECHARTS_INIT_JS
    assert "borderRadius" in js, "tooltip 缺统一圆角样式"


def test_echarts_rendered_page_carries_refinements(tmp_path, monkeypatch):
    """渲染页须带上主路精细化。

    固定走 ECharts 分支（`_echarts_js` 打桩）：red-first 沙箱只取 `scripts/`、无 `assets/`
    ⟹ 不固定则误走 SVG 降级路、断言环境相关。`低 → 高` 仅主路模板独有（`#a9761a` 不可用作
    判据 —— 页面 CSS `--warn` 恒含该色）。
    """
    monkeypatch.setattr(M, "_echarts_js", lambda: "/*stub*/")
    html = M.render_html(_agg(tmp_path), trend=TREND)
    assert "低 → 高" in html, "图④ 色标说明未进主路页面"

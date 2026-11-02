#!/usr/bin/env python3
"""C 期红先：MoA HTML 图表精细化 —— 手写内联 SVG 降级路对齐 ECharts 主路观感。

（`ECC-BF39D6698097`，族 `MOA-CHART-REFINE`；闭环 plan 2026-10-04 §12.4-3）

现状缺口（HEAD）：
  · 图② `_svg_divergence_clusters` 只画**横条**（`<rect class="c-bar">`），ECharts 主路是**环形**；
  · 图③ `_svg_identity_states` 只画**表格**（`<rect class="c-cell">`），ECharts 主路是**散点**；
  · 趋势 `_trend_svg` 只有**一条裸折线**（无轴/无刻度/无双序列/无图例），主路是双轴双序列；
  · 图④ `_svg_group_cluster_heatmap` 有热力格但**无色标图例**。

本节只钉「降级路须补齐到与主路同一观感」，不改数据口径、不加 HTML 页、不碰 7 维分。
不变量（纯函数 / 零外链 / 禁分数字面量）由既有 `test_svg_charts_pure_no_external_no_forbidden`
与本节 `test_refined_charts_pure_no_external_no_leak` 共同守着。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_moa_aggregate as M  # noqa: E402

_A = "结论：本轮改动范围蔓延超出计划边界，建议收窄到原定模块，禁止顺手重构无关代码。" * 6
_B = "结论：回滚路径缺失，若中途失败将无法恢复现场，须补齐退路与快照机制。" * 6
TREND = [{"round": "R1", "mu": 8, "top_weight": 0.50},
         {"round": "R2", "mu": 10, "top_weight": 0.40},
         {"round": "R3", "mu": 9, "top_weight": 0.33}]


def _refs():
    return [
        {"subagent_id": "a1", "batch_id": "b1", "arm_group": "G1",
         "task": "plan-refinement: /p/x — 质询", "conclusion": _A,
         "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}],
         "budget_status": "hard", "total_tokens": 9000, "token_budget": 8000},
        {"subagent_id": "a2", "batch_id": "b1", "arm_group": "G1",
         "task": "plan-refinement: /p/x — 质询", "conclusion": _A,
         "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}],
         "total_tokens": 4000},
        {"subagent_id": "g3", "batch_id": "b1", "arm_group": "G3",
         "task": "plan-refinement: /p/y — 质询", "conclusion": _B,
         "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}],
         "total_tokens": 2000},
    ]


def _trace():
    return {"attribution": {"anchor": "abc", "mode": "batch"}, "suspect_count": 0}


def _heat_agg():
    return {"references": _refs(),
            "clusters": [{"id": "c0", "size": 3, "arm_groups": {"G1": 2, "G3": 1},
                          "contradiction": False}],
            "consensus": {"top_id": "c0"}}


def test_trend_svg_dual_series_axes_legend():
    """趋势降级路须双序列（引用数 + 一致度）+ 轴/刻度 + 图例（HEAD：单条裸折线 ⟹ 红）。"""
    svg = M._trend_svg(TREND)
    assert svg.count("<polyline") >= 2, "趋势须双序列（引用数 + 一致度）"
    assert "引用" in svg and "一致度" in svg, "缺序列图例/标签"
    assert svg.count("<text") >= 3, "缺轴刻度/标签"
    assert "<line" in svg, "缺轴线/网格"


def test_clusters_svg_donut_arcs():
    """图② 降级路须环形扇区（arc `<path>`）+ 占比（HEAD：只画横条 ⟹ 红）。"""
    svg = M._svg_divergence_clusters(_refs(), _trace())
    assert "<path" in svg, "图② 须环形扇区（arc path）"
    assert "c-arc" in svg, "缺扇区样式类"
    assert "%" in svg, "缺占比标注"


def test_identity_svg_scatter_points():
    """图③ 降级路须散点（每臂一点 `<circle>`）+ 坐标轴（HEAD：只画表格 ⟹ 红）。"""
    svg = M._svg_identity_states(_refs(), _trace())
    assert svg.count("<circle") >= 3, "图③ 须散点（每臂一点）"
    assert "c-pt" in svg, "缺点样式类"
    assert "<line" in svg, "缺坐标轴"


def test_heatmap_svg_color_scale():
    """图④ 降级路须补色标图例（低→高）（HEAD：仅热力格 ⟹ 红）。"""
    svg = M._svg_group_cluster_heatmap(_heat_agg())
    assert "c-scale" in svg, "图④ 缺色标图例"
    assert "低" in svg and "高" in svg, "色标须标低/高端"


def test_refined_charts_pure_no_external_no_leak():
    """四图仍守硬不变量：纯函数（同输入两跑逐字相等）/ 零外链 / 禁分数字面量。"""
    refs, trace, agg = _refs(), _trace(), _heat_agg()
    for fn in (lambda: M._svg_divergence_clusters(refs, trace),
               lambda: M._svg_identity_states(refs, trace),
               lambda: M._svg_group_cluster_heatmap(agg),
               lambda: M._trend_svg(TREND)):
        s1, s2 = fn(), fn()
        assert s1 == s2, "非纯函数（同输入异输出）"
        for bad in ("url(", "href=", "<image", "xlink:"):
            assert bad not in s1, "含外链形态 " + bad
        for leak in ("_sealed_agent_score", "monitor_score", "seven_dim_score"):
            assert leak not in s1, "泄漏禁字面量 " + leak

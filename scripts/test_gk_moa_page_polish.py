#!/usr/bin/env python3
"""人评页观感升级红先（2026-10-31，owner 裁定「是的就这么搞」）：
  ① 顶部 KPI 带 —— 新用户 3 秒抓重点（臂数/簇/一致度/判定/优化项/suspect/趋势方向）；
  ② 术语 tooltip —— jargon（divergence/HUMAN_OVERSCORE/adjudicate/suspect）就地可懂；
  ③ 三视图分段（材料 / 图表 / 裁定，默认=裁定）—— 5000px 长页折叠成一屏一个工作区；
  ④ 表格密度（斑马纹 + tabular-nums + sticky 表头）与图表卡标题规范化；
  ⑤ 深色主题（data-dark 切换 + prefers-color-scheme + 持久化；硬编码色全变量化）。

双盲/自足红线沿用：KPI 带与 tooltip 不得含 agent 侧分数锚；零外部资源。
HEAD 必红面见各臂 docstring。
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_moa_aggregate as M  # noqa: E402

TREND = [{"round": "R1", "mu": 8, "top_weight": 0.50},
         {"round": "R2", "mu": 10, "top_weight": 0.40},
         {"round": "R3", "mu": 9, "top_weight": 0.33}]


def _agg(tmp_path, batch="B"):
    hist = [
        {"subagent_id": "a1", "batch_id": batch, "arm_group": "G1",
         "task": "plan-refinement: /p/x.md — 质询",
         "conclusion": "本轮改动范围蔓延超出计划边界" * 8,
         "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}],
         "challenges": ["挑战甲"], "kept": ["保留甲"], "slashed": ["砍甲"],
         "budget_status": "hard", "total_tokens": 9000, "token_budget": 8000},
        {"subagent_id": "a2", "batch_id": batch, "arm_group": "G1",
         "task": "plan-refinement: /p/x.md — 质询",
         "conclusion": "本轮改动范围蔓延超出计划边界" * 8,
         "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]},
        {"subagent_id": "g3", "batch_id": batch, "arm_group": "G3",
         "task": "plan-refinement: /p/x.md — 质询",
         "conclusion": "回滚路径缺失，若中途失败将无法恢复现场" * 8,
         "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]},
    ]
    sf = tmp_path / "s.json"
    sf.write_text(json.dumps({"gate_data": {"subagent_history": hist,
                                            "ecc_findings": []}},
                             ensure_ascii=False), encoding="utf-8")
    return M.aggregate(str(sf), None, "plan-refinement", plan="/p/x.md", batch=batch)


# ── ① KPI 带 ────────────────────────────────────────────────────
def test_kpi_band_present_in_first_screen(tmp_path):
    """KPI 带须在首屏（banner 与导航之间），且关键读数齐：臂数/一致度/判定/趋势。"""
    html = M.render_html(_agg(tmp_path), trend=TREND)
    assert 'id="kpi-band"' in html, "缺 KPI 带"
    i_kpi = html.index('id="kpi-band"')
    i_nav = html.index('class="nav"')
    assert i_kpi < i_nav, "KPI 带须在导航之前（首屏）"
    for lab in ("臂数", "一致度", "判定", "趋势"):
        assert lab in html[i_kpi:i_nav], "KPI 带缺读数 " + lab


def test_kpi_band_values_come_from_agg(tmp_path):
    """KPI 值须来自 agg（禁猜）：臂数=references 长；一致度=consensus.agreement；
    弃权⟹bad 判定；趋势方向= trend 末轮−首轮。"""
    agg = _agg(tmp_path)
    html = M.render_html(agg, trend=TREND)
    band = html[html.index('id="kpi-band"'):html.index('class="nav"')]
    assert str(len(agg["references"])) in band, "臂数未取自 references"
    assert "弃权" in band or "收敛" in band, "判定未取自 consensus.abstain"
    assert "↓" in band, "趋势方向未按 trend 末轮−首轮标注（0.33<0.50 ⟹ ↓）"


def test_kpi_band_accept_mode(tmp_path):
    """accept 聚合（mode=moa_accept）也有 KPI 带：裁决/worktrees/新增失败/修复。"""
    html = M.render_html({"mode": "moa_accept",
                          "accept": {"global": {"verdict": "pass", "worktrees": ["w1"],
                                                "new_failures": [], "fixed": ["x"]}}})
    band = html[html.index('id="kpi-band"'):html.index('class="nav"')]
    for lab in ("裁决", "worktrees", "新增失败", "修复"):
        assert lab in band, "accept KPI 缺 " + lab


def test_kpi_band_double_blind(tmp_path):
    """双盲红线：KPI 带与 tooltip 区不得含 agent 侧分数锚键名。"""
    html = M.render_html(_agg(tmp_path), trend=TREND)
    head = html[:html.index('id="sec-mat"')]
    for k in ("seven_dim_score", "overall_score", '"score"'):
        assert k not in head, "首屏泄 agent 分数锚：" + k


# ── ② 术语 tooltip ──────────────────────────────────────────────
def test_jargon_tooltips_in_banner(tmp_path):
    """banner 内 jargon 须就地可懂（abbr title），不再裸奔。"""
    html = M.render_html(_agg(tmp_path))
    assert "<abbr title=" in html, "缺术语 tooltip（<abbr>）"
    i_b = html.index("双盲纪律")
    seg = html[i_b:html.index("</div>", i_b)]
    assert "偏离" in seg or "终审" in seg, "tooltip 未给中文释义"


def test_jargon_tooltip_uses_standalone_helper():
    """tooltip 词典须是模块级单源 helper（禁在 render_html 里散写字符串）。"""
    assert hasattr(M, "_abbr"), "缺 _abbr 单源 helper"
    out = M._abbr("divergence")
    assert "<abbr" in out and "divergence" in out and "title=" in out, out


# ── ③ 三视图分段 ────────────────────────────────────────────────
def test_view_switcher_three_tabs_default_prose(tmp_path):
    """三视图 tab（材料/图表/裁定）+ body 默认 data-view=prose（owner：默认停在裁定）。"""
    html = M.render_html(_agg(tmp_path), trend=TREND)
    for v in ("tab-mat", "tab-chart", "tab-prose"):
        assert 'id="%s"' % v in html, "缺视图 tab " + v
    assert 'data-view="prose"' in html, "body 默认视图须为 prose（裁定）"


def test_view_sections_in_dom_and_css(tmp_path):
    """三视图内容必须恒在 DOM（隐藏靠 CSS，锚点/检索/grep 不失效）。"""
    html = M.render_html(_agg(tmp_path), trend=TREND)
    for cls in ("vw-mat", "vw-chart", "vw-prose"):
        assert 'class="vw %s"' % cls in html or ('vw-%s' % cls.split("-")[1]) in html, \
            "缺视图容器 " + cls
    css = M._CSS.replace(" ", "")
    assert "body[data-view=mat]" in css, "CSS 缺 mat 视图显隐规则"
    assert "body[data-view=prose]" in css, "CSS 缺 prose 视图显隐规则"


def test_gate_banner_stays_visible_in_all_views(tmp_path):
    """跨批门 banner（agg.error）是安全面 ⟹ 不得被卷进任何视图容器而随 tab 隐藏。"""
    hist = []
    for bid, n in (("B_BIG", 3), ("B_SMALL", 1)):
        for i in range(n):
            hist.append({"subagent_id": "%s-%d" % (bid, i), "batch_id": bid, "arm_group": "G1",
                         "task": "plan-refinement: /p/x.md — 质询",
                         "conclusion": "本轮改动范围蔓延超出计划边界" * 8,
                         "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]})
    sf = tmp_path / "s.json"
    sf.write_text(json.dumps({"gate_data": {"subagent_history": hist, "ecc_findings": []}},
                             ensure_ascii=False), encoding="utf-8")
    agg = M.aggregate(str(sf), None, "plan-refinement", plan="/p/x.md")
    html = M.render_html(agg)
    i_err = html.index("聚合错误")
    assert 'class="vw' not in html[max(0, i_err - 200):i_err], \
        "跨批门 banner 被卷进视图容器 ⟹ 隐藏视图下读不到门"


def test_view_switch_js_wired(tmp_path):
    """tab 点击 ⟹ setView 切 body[data-view]；进图表视图须重建/resize ECharts（防 0 宽）。"""
    html = M.render_html(_agg(tmp_path), trend=TREND)
    assert "setView" in html, "缺 setView"
    assert "__gkChartsRebuild" in html, "缺图表重建钩子（隐藏容器 init ⟹ 0 宽错位）"
    assert "gk-moa-view" in html, "视图选择未持久化"


# ── ④ 表格密度 + 图表卡标题 ─────────────────────────────────────
def test_table_density_css():
    """表格密度三件套：斑马纹 / tabular-nums / sticky 表头。"""
    css = M._CSS.replace(" ", "")
    assert "nth-child(even)" in css, "缺斑马纹"
    assert "tabular-nums" in css, "缺数字对齐"
    assert "position:sticky" in css, "缺 sticky 表头"


def test_chart_caption_title_bold(tmp_path):
    """图表卡标题规范化：figcaption 首段加粗（标题/说明分离），原文串不变（既有臂不破）。"""
    html = M.render_html(_agg(tmp_path), trend=TREND)
    assert "<figcaption><b>图②" in html, "图② 卡标题未加粗分离"
    assert "图④ 组 × 结论簇 贡献热力图" in html, "图④ 原文串被改动（既有臂会红）"


# ── ⑤ 深色主题 ──────────────────────────────────────────────────
def test_dark_theme_wiring(tmp_path):
    """深色主题接线：切换按钮 + data-dark 持久化 + prefers-color-scheme 缺省。"""
    html = M.render_html(_agg(tmp_path))
    assert 'id="dark"' in html, "缺深色切换按钮"
    assert "gk-moa-dark" in html, "主题选择未持久化"
    assert "prefers-color-scheme" in html, "缺系统主题跟随"
    assert "data-dark" in M._CSS, "CSS 缺 data-dark 覆盖块"


def test_hardcoded_colors_are_variables():
    """原硬编码色须全变量化（否则深色下出白块/白底表头）：banner/pre/th/input/svg-bg/tt。"""
    for var in ("--bnn-bg", "--pre-bg", "--th-bg", "--inp-bg", "--svg-bg", "--tt-bg"):
        assert var in M._CSS, "缺主题变量 " + var
    # 旧字面色不得再裸用（:root 定义行除外）
    body = M._CSS.split("}", 1)[1] if "}" in M._CSS else M._CSS
    for lit in ("#e9f2fa", "#f6efdb", "#f3ecd8", "#fffdf6", "#fbf6e8"):
        assert lit not in body, "硬编码色残留（深色必裂）：" + lit


def test_echarts_theme_read_at_build(tmp_path):
    """ECharts 颜色须在 build 时读 body[data-dark]（深色下轴/tooltip 不再白底）；
    并暴露 __gkChartsRebuild 供 tab 切换重建。"""
    html = M.render_html(_agg(tmp_path), trend=TREND)
    assert "getAttribute('data-dark')" in html or 'getAttribute("data-dark")' in html, \
        "ECharts 未读深色状态"
    assert "__gkChartsRebuild=" in html, "缺重建钩子导出"


def test_js_still_no_interval_poll():
    """升级不许把每秒轮询带回来（沿用 T-b 约束）。"""
    assert "setInterval" not in M._JS
    assert "pagehide" in M._JS


def test_existing_invariants_survive(tmp_path):
    """既有关键面不破：countItems 单源注入 / data-pend 零残留 / prose 在 / 三步链文案。"""
    html = M.render_html(_agg(tmp_path), trend=TREND)
    assert M._json_embed(M._MARKER_RE.pattern) in html
    assert "data-pend" not in html
    assert 'id="prose"' in html
    assert "复制三步命令链" in html
    assert html.count("<details") == html.count("</details>")

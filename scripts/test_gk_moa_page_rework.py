#!/usr/bin/env python3
"""S3 红先：人评页重做 —— 删 per-arm 广播 + 批级单判 + 运行态/聚合/finding/趋势面板（2026-10-06）。

缺陷（实测）：
  ① 裁决矩阵**画 per-arm 列**（`data-pend="F1-0"`/`"F1-1"`…）却由 `paint()` 用
     `k.split("-")[0]` 把**一份判定广播**到所有臂列 ⟹「随便动一个评分项一排 subagent 全变」；
  ② 缺「subagent 运行态」面板（`machine_check`/`access_violations`/`tools_used` 从未被消费，
     「是否启动」在 history 无字段）；
  ③ 缺聚合详情（簇/三组）与 ecc-finding 详情（分类/优化项）与跨轮趋势图。

修法：删 per-arm 列（改**批级单判**）；新增四个面板（聚合详情 / finding 详情 / 运行态 / 跨轮趋势 Plotly）。
HEAD 必红：`render_html` 无 `trend` 参数且仍渲 per-arm 格。
"""
import json
import os
import sys
from pathlib import Path

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
         "budget_status": "hard", "total_tokens": 9000, "token_budget": 8000,
         "challenges": ["挑战甲"], "kept": ["保留甲"], "slashed": ["砍甲"],
         "machine_check": {"verification": {"status": "ok"},
                           "evidence_anchor": {"status": "incomplete"}},
         "access_violations": [{"tool": "read", "path": "x", "reason": "out_of_scope"}]},
        {"subagent_id": "a2", "batch_id": BATCH, "arm_group": "G1",
         "task": "plan-refinement: %s — 质询" % PLAN, "conclusion": _A,
         "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]},
        {"subagent_id": "g3", "batch_id": BATCH, "arm_group": "G3",
         "task": "plan-refinement: %s — 质询" % PLAN, "conclusion": _B,
         "slashed": ["砍乙"],
         "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]},
    ]
    sf = tmp_path / "state.json"
    sf.write_text(json.dumps({"gate_data": {"subagent_history": hist, "ecc_findings": []}},
                             ensure_ascii=False), encoding="utf-8")
    return M.aggregate(str(sf), None, "plan-refinement", plan=PLAN, batch=BATCH)


def test_no_scoring_ui_at_all(tmp_path):
    """S3-4（2026-10-06）：评分矩阵整体移除 ⟹ 页内无任何 `data-pend`；只有散文输入。"""
    html = M.render_html(_agg(tmp_path))
    assert "data-pend" not in html, "评分矩阵未移除"
    assert 'id="prose"' in html, "缺散文输入框"


def test_run_status_panel_present(tmp_path):
    html = M.render_html(_agg(tmp_path))
    assert "subagent 运行态" in html, "缺运行态面板"
    assert "machine_check" in html or "证据锚" in html, "未消费 machine_check"
    assert "越权读" in html, "未消费 access_violations"
    assert "未知" in html, "「是否启动」须如实标未知（history 无字段）"


def test_agg_and_finding_detail_present(tmp_path):
    html = M.render_html(_agg(tmp_path))
    assert "聚合详情" in html and "一致度" in html, "缺聚合详情面板"
    assert "ecc-finding 详情" in html, "缺 finding 详情面板"
    assert "优化项" in html, "缺优化项"
    assert "P=计划文本" in html and "L=机检" in html and "M=机制" in html, \
        "载体简写缺释义（页面出现裸 P/L/M，人评者无从解读）"


def test_trend_chart_present(tmp_path):
    html = M.render_html(_agg(tmp_path), trend=TREND)
    assert "跨轮趋势" in html, "缺跨轮趋势图"
    assert 'id="fig-trend"' in html, "趋势图未走 ECharts 容器"


def test_charts_use_echarts_when_asset_present(tmp_path):
    """S9（2026-10-06）：图②③④ + 趋势统一 ECharts；且 vendor **只内联一次**（禁每图重复）。"""
    html = M.render_html(_agg(tmp_path), trend=TREND)
    assert "echarts.init(" in html, "未走 ECharts 主路"
    for _id in ("fig-clusters", "fig-arms", "fig-heat", "fig-trend"):
        assert 'id="%s"' % _id in html, "缺 ECharts 容器 " + _id
    assert html.count("Licensed to the Apache Software Foundation") == 1, \
        "echarts vendor 被内联多次（须全页一次）"
    assert "plotly" not in html, "Plotly 残留（S9 已单库化为 ECharts）"


def test_charts_degrade_to_svg_without_asset(tmp_path, monkeypatch):
    """vendor 缺失 ⟹ 显式降级为手写内联 SVG（不静默、不报错、仍离线可开）。"""
    monkeypatch.setattr(M, "_echarts_js", lambda: "")
    html = M.render_html(_agg(tmp_path), trend=TREND)
    assert "已降级为内联 SVG" in html and "polyline" in html, "趋势降级路径不完整"
    assert "c-heat" in html, "热力图 SVG 降级缺失"
    assert 'id="fig-clusters"' not in html, "降级时不应再出 ECharts 容器"


def test_cli_no_longer_probes_plotly():
    """S9：图表后端与解释器解耦 ⟹ CLI 不得再探测 plotly（`GK_HTML_PYTHON` 已删）。"""
    cli = (Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    assert "GK_HTML_PYTHON" not in cli, "GK_HTML_PYTHON 残留（已改 ECharts，无需探测解释器）"
    assert "import plotly" not in cli, "CLI 仍在探测 plotly"


def test_command_chain_matches_cli_file_flag(tmp_path):
    """S3-4 修正：页面「复制命令链」须与实际 CLI 契约一致（`--file`）。

    实测：`gk_prose_findings.py`/`gk_finding_score.py` 只认 `--file`；旧链用**位置参数**
    （`from-prose prose.txt`）⟹ 用户复制即报 `unrecognized arguments`，链整体不可用。
    """
    html = M.render_html(_agg(tmp_path))
    assert "finding from-prose --file" in html, "from-prose 命令链缺 --file（位置参数不可用）"
    assert "finding score --file" in html, "score 命令链缺 --file（位置参数不可用）"


def test_css_self_consistent_no_dead_scoring(tmp_path):
    """S7 修：① 被引用的 `rowwarn`/`h3` 须有 CSS 定义；② 删评分矩阵后死人 CSS 不得残留。"""
    html = M.render_html(_agg(tmp_path))
    assert "tr.rowwarn" in html, "`.rowwarn` 被用却未定义 ⟹ 矛盾行无高亮"
    assert "h3{" in html, "`h3` 未定义 ⟹ 落到 UA 默认（>h2）造成层级倒置"
    for dead in (".score{", ".miss{", ".hidden{", ".c-pend"):
        assert dead not in html, "死人 CSS 残留：" + dead


def test_trend_reads_structured_facets_over_prose(tmp_path):
    """S7 修：趋势读侧优先 `refs:`/`weight:` facet（旧账无 facet 才退回 source_note 正则）。"""
    import json as _j
    st = tmp_path / "s.json"
    st.write_text(_j.dumps({"gate_data": {"ecc_findings": [
        {"root_key": "moa-agg:abc", "created_at": "2026-10-06T01:00:00Z",
         "facets": ["refs:6", "clusters:3", "weight:0.81"],
         "source_note": "这里故意不含可匹配的模式"},
    ]}}), encoding="utf-8")
    tr = M._trend_from_state(str(st))
    assert tr and tr[0]["mu"] == 6 and abs(tr[0]["top_weight"] - 0.81) < 1e-9, tr


def test_reference_details_balanced(tmp_path):
    """T-b 修：每个 Reference 的 `<details class="ref">` 须闭合。

    实测：原 ref 循环只 append `</div>`（卡片）而**无** `</details>` ⟹ 6 处未闭合，
    后续 Reference 与「本批实质汇总」被嵌套进前一个折叠块（默认收起 ⟹ 不可见）。
    """
    html = M.render_html(_agg(tmp_path))
    assert html.count("<details") == html.count("</details>"), (
        "details 开合不平衡：%d open / %d close"
        % (html.count("<details"), html.count("</details>")))


def test_banner_reflects_current_export(tmp_path):
    """T-b 修：banner 不得再称「下载两个 JSON」（S3-4 已删两个 JSON 下载，出口只有散文链）。"""
    html = M.render_html(_agg(tmp_path))
    assert "下载两个 JSON" not in html, "banner 文案过时（S3-4 后无两个 JSON 下载口）"
    assert "复制三步命令链" in html, "banner 未更新为当前出口文案"


def test_no_localstorage_poll_interval():
    """T-b 修：原 `setInterval(...,1000)` 每秒轮写 localStorage ⟹ 改事件驱动 debounce。

    S9 注：只断言**页面自身脚本**（`M._JS`）—— vendor 的 `echarts.min.js` 内部含 `setInterval`，
    对整页断言会误判（且失败时 pytest 会打印 1MB HTML）。
    """
    assert "setInterval" not in M._JS, "localStorage 仍在每秒轮询写"
    assert "pagehide" in M._JS, "缺 pagehide 兜底落盘"


def test_command_chain_score_scale_explicit(tmp_path):
    """T-b 修：`finding score` 出 0-100，而 `adjudicate --score` 只收 0.0-1.0 ⟹ 链须显式换算。

    实测：`gk_finding_score.main` 打印 `score`（整 0-100）；`gk_adjudicate._score_in_0_1`
    对越界直接 rc=2 ⟹ 不换算则复制即报错。
    """
    html = M.render_html(_agg(tmp_path))
    assert "÷100" in html, "命令链未标明 0-100→0.0-1.0 换算（直喂将被 adjudicate 越界拒绝）"
    assert 'id="copy-p"' in html, "缺「复制散文」出口（下载落 Downloads ⟹ 与 ./prose.txt 引用脱节）"


def test_anchors_and_summary_before_refs(tmp_path):
    """T-b 修：加顶部锚点导航 + 全展开/全折叠；「本批实质汇总」须在 References 之前。"""
    html = M.render_html(_agg(tmp_path))
    for a in ("sec-mat", "sec-sum", "sec-prose", "sec-out"):
        assert 'id="%s"' % a in html, "缺锚点 " + a
    assert 'href="#sec-mat"' in html, "缺导航链接"
    assert "全展开" in html and "全折叠" in html, "缺全展开/全折叠按钮"
    assert html.index('id="sec-sum"') < html.index('<details class="ref">'), (
        "本批实质汇总仍在 References 之后 ⟹ 人评者读完材料才见实质")


def test_group_cluster_heatmap_rows_cols_and_totals(tmp_path):
    """S8/S9：图④ 组 × 结论簇 热力图（ECharts 主路）。

    行 = **实际出现**的 arm_group（禁反推）、列 = clusters、格 = 归属臂数；
    行列合计须与 consensus.n_refs 恒等对账；只消费簇归属（结构量），不含分数锚。
    """
    agg = _agg(tmp_path)
    html = M.render_html(agg)
    assert "图④" in html and "组 × 结论簇" in html, "缺图④ 组×结论簇 热力图"
    assert 'id="fig-heat"' in html, "图④ 未走 ECharts 容器"
    i = html.index("图④")
    blk = html[i:html.index("</figure>", i)]
    for g in ("G1·相同对", "G3·污染组"):
        assert g in blk, "热力图缺实际出现的组行 " + g
    assert "正交互补" not in blk, "未出现的组不得渲（禁反推）"
    tot = sum(n for c in agg["clusters"] for n in (c.get("arm_groups") or {}).values())
    assert tot == (agg.get("consensus") or {}).get("n_refs") == len(agg["references"]), \
        "行列合计与 consensus.n_refs 不对账"
    assert ("总计 %d（= refs 数）" % len(agg["references"])) in blk, "缺行列合计对账行"
    assert i < html.index('<details class="ref">'), "热力图须在 References 之前"


def test_heat_cells_global_max_color_and_contradiction_red():
    """S9/D7：热力格颜色 —— 按**全局最大**归一（1/4 ⟹ 0.41，列最大口径会误给 0.90）；
    矛盾簇格用 `--bad` 红；零格留空底色。"""
    refs = [{"arm_group": "G1"}, {"arm_group": "G2"}, {"arm_group": "G2"},
            {"arm_group": "G2"}, {"arm_group": "G2"}]
    clusters = [{"id": "c0", "size": 1, "arm_groups": {"G1": 1}, "contradiction": False},
                {"id": "c1", "size": 4, "arm_groups": {"G2": 4}, "contradiction": True}]
    rows, cells = M._heat_cells(refs, clusters)
    assert rows == ["G1", "G2"], rows
    col = {(c["value"][0], c["value"][1]): c["itemStyle"]["color"] for c in cells}
    assert col[(0, 0)] == "rgba(56,139,253,%s)" % ("%.2f" % (0.25 + 0.65 * (1 / 4))), \
        "1/4 应弱档（列最大口径会误给 0.90 ⟹ 此断言区分两种口径）"
    assert col[(1, 1)].startswith("rgba(248,81,73,"), "矛盾簇格须用 --bad 红"
    assert col[(1, 0)] == "rgba(42,47,54,0.35)", "零格须留空底色"


def test_svg_heatmap_fallback_still_renders():
    """S9 降级：`_svg_group_cluster_heatmap` 仍是可用兜底（vendor 缺失时渲染，口径不变）。"""
    agg = {
        "references": [{"arm_group": "G1"}, {"arm_group": "G1"}, {"arm_group": "G2"}],
        "clusters": [{"id": "c0", "size": 3, "arm_groups": {"G1": 2, "G2": 1},
                      "contradiction": False}],
        "consensus": {"top_id": "c0"},
    }
    svg = M._svg_group_cluster_heatmap(agg)
    assert 'fill-opacity="%s"' % ("%.2f" % (0.25 + 0.65 * (2 / 2))) in svg, "全局最大应满档"
    assert 'fill-opacity="%s"' % ("%.2f" % (0.25 + 0.65 * (1 / 2))) in svg, "1/2 应半档"
    assert "c0 主" in svg and "n=3" in svg, "主簇须标「主」并显规模"


def _synth_dialectic_agg(abstain=True):
    """② 辩证论证单测夹具：主簇(G1) / 次簇(G2+G3 矛盾) / 纯污染簇(G3)。"""
    refs = [{"subagent_id": "a1", "arm_group": "G1"}, {"subagent_id": "a2", "arm_group": "G1"},
            {"subagent_id": "b1", "arm_group": "G2"}, {"subagent_id": "p1", "arm_group": "G3"},
            {"subagent_id": "p2", "arm_group": "G3"}]
    clusters = [
        {"id": "c0", "size": 2, "weight": 0.4, "members": ["a1", "a2"],
         "representative_id": "a1", "representative_text": "正题文本",
         "arm_groups": {"G1": 2}, "contradiction": False},
        {"id": "c1", "size": 2, "weight": 0.4, "members": ["b1", "p1"],
         "representative_id": "b1", "representative_text": "反题文本",
         "arm_groups": {"G2": 1, "G3": 1}, "contradiction": True},
        {"id": "c2", "size": 1, "weight": 0.2, "members": ["p2"],
         "representative_id": "p2", "representative_text": "污染文本",
         "arm_groups": {"G3": 1}, "contradiction": True},
    ]
    return {"references": refs, "clusters": clusters,
            "consensus": {"n_refs": 5, "n_clusters": 3, "top_id": "c0", "top_weight": 0.4,
                          "agreement": 0.4, "min_agreement": 0.6667, "abstain": abstain,
                          "contradictions": ["c1", "c2"]}}


def test_dialectic_roles_thesis_antithesis_pollution_resolution():
    """② 辩证论证：正题=主簇 / 反题=次簇 / 污染=G3 落非主簇 / 合题=一致度 vs 阈值。"""
    d = M.dialectic(_synth_dialectic_agg(abstain=True))
    assert d["thesis"]["id"] == "c0", d
    assert d["antithesis"] and d["antithesis"]["id"] == "c1", d
    assert d["g3"]["n"] == 2 and d["g3"]["n_out"] == 2, d
    assert d["resolution"]["abstain"] is True, d


def test_dialectic_section_rendered(tmp_path):
    """② 页面须有「辩证论证」四要素（正题/反题/污染/合题）。"""
    html = M.render_html(_agg(tmp_path))
    for s in ("辩证论证", "正题", "反题", "污染（G3）", "合题"):
        assert s in html, "缺辩证论证要素 " + s


def test_dialectic_no_antithesis_when_single_cluster():
    """② 单簇（全体一致）⟹ 反题显式标「无实质分歧」，不臆造分歧。"""
    agg = _synth_dialectic_agg()
    agg["clusters"] = [agg["clusters"][0]]
    agg["consensus"]["n_clusters"] = 1
    html = M._html_dialectic(agg)
    assert "无实质分歧" in html, html
    assert "反题" in html, html


def test_prose_empty_guard_on_page(tmp_path):
    """① 页面护栏：散文框下须有实时告警位 + 列表项计数逻辑 + 后果提示。"""
    html = M.render_html(_agg(tmp_path))
    assert 'id="prose-warn"' in html, "缺空 findings 告警位"
    assert "countItems" in html and "banner-warn" in html, "缺列表项计数/告警样式"
    assert "0 条 finding" in html, "未提示「0 条 finding ⟹ 全 PASS」的后果"


def test_dialectic_resolution_uses_agreement_not_top_weight():
    """回归（实测发现）：合题阈值比较须用 `consensus.agreement`（= abstain 的判据量），
    否则页面出现「一致度 0.50 ≥ 阈值 0.67 ⟹ 收敛」式自相矛盾。"""
    agg = _synth_dialectic_agg(abstain=False)
    agg["consensus"]["top_weight"] = 0.50
    agg["consensus"]["agreement"] = 0.80
    agg["consensus"]["min_agreement"] = 0.6667
    html = M._html_dialectic(agg)
    assert "批内一致度 0.80 ≥ 阈值 0.67" in html, html
    assert "最大簇权重 0.50" in html, html


def test_finding_detail_text_readable(tmp_path):
    """③ 详情文本可读化：分节（归属/规模/结论簇）+ 优化项，不再是一行机器码。"""
    t = M.assess_findings(_agg(tmp_path))["detail_text"]
    assert "· 归属" in t and "· 规模" in t and "结论簇" in t, t
    assert "优化项" in t, t


def test_dialectic_summary_in_detail_text(tmp_path):
    """③ 论证入台账：辩证摘要并进 detail_text（→ source_note），供跨轮比对。"""
    t = M.assess_findings(_agg(tmp_path))["detail_text"]
    assert "· 辩证" in t and "正题" in t and "合题" in t, t


def test_direction_context_and_i18n_wiring(tmp_path):
    """② 方向开关 + 相关性闸上下文 + i18n 开关的命令链/控件接线。"""
    html = M.render_html(_agg(tmp_path))
    assert 'id="mode"' in html and "--direction" in html, "缺结论方向开关 / 命令链接线"
    for v in ("reject", "allow", "abstain"):
        assert 'value="%s"' % v in html, "缺方向选项 " + v
    assert 'id="ctx"' in html and "--context" in html, "缺批上下文（相关性闸）接线"
    assert 'id="lang"' in html and "data-i18n" in html, "缺 i18n 中英开关"

#!/usr/bin/env python3
"""T-a 红先：MoA HTML 须展示 plan-refinement 报告的**实质字段**（2026-10-06）。

缺陷（实测）：`render_html` 只渲染 `conclusion` / `evidence[]` / `findings{worked,failed,not_tried}`，
而 plan-refinement 报告的实质住在 **`challenges[]` / `kept[]` / `slashed[]`**（其 `findings[]` 按
设计本就空 —— 见 `gk_moa_aggregate._suspect_flags` L202-204）⟹ 页面「发现」面板恒空、
观感=「MoA 没聚合出任何有效信息」（owner 实测反馈 2026-10-06）。

修法：per-ref 增渲染 `challenges`（编号全文）/ `kept` / `slashed`；批级增「本批实质汇总」面板。
HEAD 必红（三断言全挂）；本批 6 臂实测报告即含这些字段，非构造。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gk_moa_aggregate import render_html  # noqa: E402

CH = "挑战②（验签单源收敛面）：判据4b 要求收敛到既有真验签 gk_ember_replay::verify_seal"
SL = "判据2a 中 poka-yoke control 级的定级措辞（应降为信息级）"
KP = "单人前提威胁模型：人员级独立性 / SoD / 双人双控一律不落"

AGG = {
    "mode": "moa_aggregate",
    "aggregator_guidance": "g",
    "references": [{
        "subagent_id": "sub-x-1", "task": "plan-refinement: x — t",
        "conclusion": "WARN ...",
        "challenges": [CH, "挑战③（可机检面）：判据5 无载体"],
        "kept": [KP],
        "slashed": [SL],
        "evidence": [{"file": "a.py", "lines": "1-2", "status": "confirmed"}],
        "findings": {},
        "verdicts": {"F1": "WARN", "F4": "PASS"},
        "confidence": "medium", "hmac_status": "unverified",
        "batch_id": "batch1", "arm_group": "G1", "suspect": [],
    }],
    "trace": {"count": 1, "ids": ["sub-x-1"], "suspect_count": 0,
              "attribution": {"mode": "batch_bound"}, "batch": {"mode": "single_batch"}},
}


def test_html_surfaces_challenges_kept_slashed():
    html = render_html(AGG)
    assert "判据4b 要求收敛到既有真验签" in html, "challenges 未渲染（页面看不到质询挑战）"
    assert "poka-yoke control 级" in html, "slashed 未渲染（看不到应砍项）"
    assert "单人前提威胁模型" in html, "kept 未渲染（看不到保留项）"


def test_html_has_substance_panel():
    html = render_html(AGG)
    assert "本批实质汇总" in html, "缺批级实质汇总面板"

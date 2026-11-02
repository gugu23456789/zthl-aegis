#!/usr/bin/env python3
"""S2 红先：MoA finding 实质化 —— 分类（计划错误 / 基建缺陷）+ 优化项 + 详情文本（2026-10-06）。

缺陷（实测）：`emit_aggregate_finding` 只落**一行计数台账**
（`MoA聚合批裁决: batch=… n=… suspect=…`），**无分类 / 无优化项 / 无详情文本**
（「怎么什么都没有」）。

修法（确定性、零 LLM）：`assess_findings(agg)` 由 `clusters`/`consensus` + 逐臂运行态信号推出
  ① 分类 `plan-error` / `infra-defect` / `unknown`
  ② `optimization_items[]`（每项 `carrier ∈ {P,L,M}`，对齐 group-dispatch §11 三向分流）
  ③ `detail_text`（簇代表 + 成员臂 + 三组分布；落 `source_note`）。

HEAD 必红：`assess_findings` 不存在（ImportError）。
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_moa_aggregate as M  # noqa: E402

PLAN = "/p/docs/plans/x-plan.md"
BATCH = "abc123def456"
_CONCL_A = "结论：本轮改动范围蔓延超出计划边界，建议收窄到原定模块，禁止顺手重构无关代码。" * 6
_CONCL_B = "结论：回滚路径缺失，若中途失败将无法恢复现场，须补齐退路与快照机制。" * 6


def _state(tmp_path, rows):
    hist = []
    for sid, grp, concl, extra in rows:
        e = {"subagent_id": sid, "batch_id": BATCH, "arm_group": grp,
             "task": "plan-refinement: %s — 质询" % PLAN,
             "conclusion": concl,
             "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]}
        e.update(extra or {})
        hist.append(e)
    sf = tmp_path / "state.json"
    sf.write_text(json.dumps({"gate_data": {"subagent_history": hist, "ecc_findings": []}},
                             ensure_ascii=False), encoding="utf-8")
    return str(sf)


def _agg(tmp_path, rows):
    sf = _state(tmp_path, rows)
    return sf, M.aggregate(sf, None, "plan-refinement", plan=PLAN, batch=BATCH)


def test_classification_plan_error_on_substantive_disagreement(tmp_path):
    _, agg = _agg(tmp_path, [
        ("a1", "G1", _CONCL_A, None), ("a2", "G1", _CONCL_A, None),
        ("a3", "G1", _CONCL_A, None), ("a4", "G2", _CONCL_B, None)])
    a = M.assess_findings(agg)
    assert a["classification"] == "plan-error", a
    assert a["optimization_items"], a
    assert all(it["carrier"] in ("P", "L", "M") for it in a["optimization_items"]), a


def test_classification_infra_defect_on_budget_exhausted(tmp_path):
    _, agg = _agg(tmp_path, [
        ("b1", "G1", _CONCL_A, {"budget_status": "hard"}),
        ("b2", "G1", _CONCL_A, {"budget_status": "hard"})])
    a = M.assess_findings(agg)
    assert a["classification"] == "infra-defect", a


def test_detail_text_has_cluster_members_and_groups(tmp_path):
    _, agg = _agg(tmp_path, [
        ("a1", "G1", _CONCL_A, None), ("a2", "G1", _CONCL_A, None),
        ("g3", "G3", _CONCL_B, None)])
    t = M.assess_findings(agg)["detail_text"]
    assert "簇" in t, t
    assert "G1" in t and "G3" in t, t          # 三组分布
    assert "a1" in t and "g3" in t, t          # 成员臂
    assert "优化项" in t, t                     # 优化项入详情


def test_emit_finding_carries_classification_facets_and_detail(tmp_path):
    sf, agg = _agg(tmp_path, [
        ("a1", "G1", _CONCL_A, None), ("a2", "G1", _CONCL_A, None),
        ("a3", "G1", _CONCL_A, None), ("a4", "G2", _CONCL_B, None)])
    res = M.emit_aggregate_finding(sf, agg, plan=PLAN, batch=BATCH)
    assert res.get("ok") is True, res
    f = json.loads(Path(sf).read_text(encoding="utf-8"))["gate_data"]["ecc_findings"][0]
    assert any(str(x).startswith("classification:") for x in (f.get("facets") or [])), f
    assert "簇" in (f.get("source_note") or ""), f


def test_emit_without_anchor_still_refused(tmp_path):
    _, agg = _agg(tmp_path, [("a1", "G1", _CONCL_A, None)])
    res = M.emit_aggregate_finding(tmp_path / "nope.json", agg, plan="", batch="")
    assert res.get("ok") is False, res


def test_assess_findings_emits_structured_metric_facets(tmp_path):
    """S7 修：`refs:`/`clusters:`/`weight:` **结构化**落 facet —— 趋势读侧不再靠
    对人类可读 `source_note` 的正则（措辞一变即静默退化为 0）。"""
    _, agg = _agg(tmp_path, [
        ("a1", "G1", _CONCL_A, None), ("a2", "G1", _CONCL_A, None),
        ("a3", "G1", _CONCL_A, None), ("a4", "G2", _CONCL_B, None)])
    fs = [str(x) for x in M.assess_findings(agg)["facets"]]
    assert any(x.startswith("refs:") for x in fs), fs
    assert any(x.startswith("clusters:") for x in fs), fs
    assert any(x.startswith("weight:") for x in fs), fs

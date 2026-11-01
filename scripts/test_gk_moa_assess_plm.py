#!/usr/bin/env python3
"""红先臂：`assess_findings` 的 P/L/M 分组正确性（`ECC-81F6D83D153B`）。

病象（2026-10-10 实测）：聚合 ECC 的载体分组**系统性失真**——
  · **L 通道结构性缺席**：`optimization_items` 只产 M/P，从不产 L（「机检规则」名不副实）；
  · **矛盾簇误判为 M**：`consensus.contradictions` 语义（P2/去 G3 标签后）= 与逐 F 多数**相左的
    判定** = 计划文本分歧，原却记 `M·修复污染探测/隔离机制`；
  · **平局偏置**：`infra >= plan ⟹ infra-defect` 在 1:1 时隐式偏 infra-defect；
  · **merge 叠加 scalar facet**：`root_key` 重跑时 `classification:`/`refs:` 叠加（实测
    `ECC-9186B25360D6` 两个 classification、`refs:6`+`refs:2`）⟹ 下游 `_facet_value("refs")` 取首个 = 读错。

判据面 = **已跟踪** `scripts/gk_moa_aggregate.py` + `scripts/gk_finding.py`（禁第二事实源）。
red-first 沙箱按 `git archive HEAD` 取**未修**版 ⟹ 本文件对 HEAD 必红（arm_l / arm_contradiction /
arm_tie / arm_merge）。两条 `test_guard_*` 为**非红**回归守卫（HEAD 即绿），不入选红先集。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_moa_aggregate as M  # noqa: E402
import gk_finding as F  # noqa: E402

PLAN = "/p/docs/plans/x-plan.md"
BATCH = "abc123def456"
_CONCL_A = "结论：本轮改动范围蔓延超出计划边界，建议收窄到原定模块，禁止顺手重构无关代码。" * 6
_CONCL_B = "结论：回滚路径缺失，若中途失败将无法恢复现场，须补齐退路与快照机制。" * 6


def _agg(tmp_path, rows):
    hist = []
    for sid, grp, concl, extra in rows:
        e = {"subagent_id": sid, "batch_id": BATCH, "arm_group": grp,
             "task": "plan-refinement: %s — 质询" % PLAN, "conclusion": concl,
             "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]}
        e.update(extra or {})
        hist.append(e)
    sf = tmp_path / "state.json"
    sf.write_text(json.dumps({"gate_data": {"subagent_history": hist, "ecc_findings": []}},
                             ensure_ascii=False), encoding="utf-8")
    return M.aggregate(str(sf), None, "plan-refinement", plan=PLAN, batch=BATCH)


def test_arm_l_lane_emitted(tmp_path):
    """臂 l（主判据）：臂级**机检层**未过（`machine_check.verification`）⟹ 须产 `carrier:"L"`。
    HEAD：判据只看 `suspect`，机检层信号**无面认领** ⟹ 零 L。"""
    agg = _agg(tmp_path, [("a1", "G1", _CONCL_A, {"machine_check": {"verification": "incomplete"}}),
                          ("a2", "G1", _CONCL_A, None)])
    a = M.assess_findings(agg)
    assert any(it["carrier"] == "L" for it in a["optimization_items"]), a


def test_arm_contradiction_is_plan_not_machine(tmp_path):
    """臂 contradiction：`consensus.contradictions` ⟹ **P（计划文本分歧）**，非 M（污染）。
    HEAD：写成 `M·修复污染探测/隔离机制（G3 离群已命中）`（P2 去 G3 标签后该动作语义已失效）。"""
    agg = _agg(tmp_path, [("a1", "G1", _CONCL_A, None), ("b1", "G2", _CONCL_B, None)])
    agg["consensus"]["contradictions"] = ["c1"]
    a = M.assess_findings(agg)
    cs = [it for it in a["optimization_items"] if "contradiction" in it["evidence"]]
    assert cs and cs[0]["carrier"] == "P", a


def test_arm_tie_not_biased_to_infra(tmp_path):
    """臂 tie：1×P + 1×M ⟹ **无主导 ⟹ unknown** + `class-tie:` 留痕（HEAD：`>=` 偏 infra-defect）。"""
    agg = _agg(tmp_path, [("a1", "G1", _CONCL_A, None), ("b1", "G2", _CONCL_B, None)])
    agg["consensus"].update({"contradictions": ["c1"], "abstain": False,
                             "top_weight": 0.8, "min_agreement": 0.67, "n_clusters": 2})
    agg["references"][0]["budget_status"] = "hard"         # → 1×M
    a = M.assess_findings(agg)
    assert a["classification"] == "unknown", a
    assert any(str(x).startswith("class-tie:") for x in a["facets"]), a


def test_arm_merge_facets_replace_scalar(tmp_path):
    """臂 merge：同 `root_key` 重跑 ⟹ 标量命名空间（classification/refs/…）**后写覆盖**，非叠加。
    HEAD：`_extend_unique` 叠加 ⟹ 一条 finding 出现两个 `classification:` ⟹ 下游读错。"""
    sf = tmp_path / "state.json"
    sf.write_text(json.dumps({"gate_data": {"subagent_history": [], "ecc_findings": []}}),
                  encoding="utf-8")
    F.register(str(sf), "t", "review", root_key="rk1",
               facets=["classification:infra-defect", "refs:6", "carrier:M", "provenance:untrusted"])
    F.register(str(sf), "t", "review", root_key="rk1",
               facets=["classification:plan-error", "refs:2", "carrier:P", "provenance:untrusted"])
    fs = [str(x) for x in json.loads(sf.read_text(encoding="utf-8"))["gate_data"]["ecc_findings"][0]
          .get("facets") or []]
    assert sum(1 for x in fs if x.startswith("classification:")) == 1, fs
    assert "classification:plan-error" in fs, fs          # 后写覆盖
    assert sum(1 for x in fs if x.startswith("refs:")) == 1 and "refs:2" in fs, fs
    assert "carrier:P" in fs and "carrier:M" not in fs, fs
    assert "provenance:untrusted" in fs, fs               # 非标量 → 保留


def test_guard_no_signal_is_unknown(tmp_path):
    """守卫臂（**非红**：HEAD 即绿）：无任何载体信号 ⟹ `unknown` + 零优化项。"""
    a = M.assess_findings(_agg(tmp_path, [("a1", "G1", _CONCL_A, None)]))
    assert a["classification"] == "unknown" and a["optimization_items"] == [], a


def test_guard_substantive_disagreement_is_plan_error(tmp_path):
    """守卫臂（**非红**：HEAD 即绿）：臂间实质分歧（≥2 簇、无矛盾/无机制信号）仍须 plan-error。"""
    a = M.assess_findings(_agg(tmp_path, [
        ("a1", "G1", _CONCL_A, None), ("a2", "G1", _CONCL_A, None),
        ("a3", "G1", _CONCL_A, None), ("a4", "G2", _CONCL_B, None)]))
    assert a["classification"] == "plan-error", a

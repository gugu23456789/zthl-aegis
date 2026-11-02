#!/usr/bin/env python3
"""S1 红先：MoA 聚合实质化 —— 跨臂去重聚类 + 三组语义（2026-10-06）。

缺陷（实测）：`aggregate()` 逐 entry append，**结论层零去重 / 零聚类 / 零一致度**；
`arm_group`(G1/G2/G3) 聚合端**零消费** ⟹ 6 臂 = 6 条散装 reference
（观感 = 「MoA 没聚合出任何有效信息」）。

修法：新增纯函数 `cluster_references(refs, tau=...)` ——
  归一化 → 字符 shingle → Jaccard → **单链接**成簇 → `clusters[]` + `consensus{}`；
  三组语义：G1 相同对 = 一致性、G2 正交互补 = **覆盖度**、G3 = 明确投毒（元数据）；
  矛盾探测**去 G3 标签**（P2，2026-10-06）：① verdicts 与逐 F 多数相左 / ② 非最大簇 且 size≥2；
  一致度不足 ⟹ `abstain`（弃权优先于硬判，对齐 Raven-ADK SelfConsistency）。

HEAD 必红：`cluster_references` 不存在（ImportError）。
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_moa_aggregate as M  # noqa: E402

PLAN = "/p/docs/plans/x-plan.md"
BATCH = "abc123def456"


def _ref(sid, concl, grp="G1", **kw):
    d = {"subagent_id": sid, "conclusion": concl, "arm_group": grp,
         "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]}
    d.update(kw)
    return d


def _task_ref(sid, nid, task, concl, grp="G1"):
    """带逐臂窄任务标记的 reference（题面 = 标记之后的正文）。"""
    return _ref(sid, concl, grp,
                task="plan-refinement: /p/x.md — x\n\n"
                     f"【本臂窄任务（{grp}｜id={nid}）】\n{task}")


def test_heterogeneous_tasks_do_not_form_consensus_or_contradiction():
    """2026-10-21（`ECC-65986D800D26`）：各臂回答**不同问题** ⟹ 无复现、无矛盾、无 n_eff。

    实跑病象：Q4 单臂被标 `contradiction c1`、`n_eff=1.8` 把「题目不同」误报成「臂不独立」。
    """
    refs = [
        _task_ref("a", "nt-q1", "Q1 复算 P7", "Q1：不可复算，需改正文。", "G1"),
        _task_ref("b", "nt-q2", "Q2 W 单位", "Q2：应为 per-level W=1。", "G2"),
        _task_ref("c", "nt-q4", "Q4 ECT 定位", "Q4：必须限定化。", "G3"),
    ]
    out = M.cluster_references(refs)
    cons = out["consensus"]
    assert cons["task_heterogeneous"] is True, cons
    assert cons["task_count"] == 3, cons
    assert cons["contradictions"] == [], cons
    assert cons["n_eff"] is None and cons["independence_ok"] is None, cons
    assert cons["n_eff_raw"] is not None, cons
    assert cons["agreement_comparable"] is False, cons
    assert cons["abstain"] is True and "task_heterogeneous" in cons["abstain_reason"], cons
    assert cons["abstain_reason"] == "task_heterogeneous", cons
    assert all(not c["contradiction"] for c in out["clusters"]), out["clusters"]


def test_heterogeneous_batch_not_classified_as_convergence_defect():
    """`ECC-0D9E26B22529`：异构批弃权不得归因「批内一致度不足（基础设施缺陷）」。

    实跑病象：3 臂 = 3 个不同窄任务，`abstain_reason=task_heterogeneous` 已正确，但
    `assess_findings` 仍无条件把 abstain 落成 infra-defect 优化项，并渲染
    「一致度 0.76 < 0.67」式自相矛盾文本。
    """
    refs = [
        _task_ref("a", "nt-q1", "Q1 复算 P7", "Q1：不可复算，需改正文。", "G1"),
        _task_ref("b", "nt-q2", "Q2 W 单位", "Q2：应为 per-level W=1。", "G2"),
        _task_ref("c", "nt-q4", "Q4 ECT 定位", "Q4：必须限定化。", "G3"),
    ]
    out = M.cluster_references(refs)
    agg = {"references": refs, "trace": {"attribution": {"mode": "plan_bound", "anchor": "x"}},
           **out}
    a = M.assess_findings(agg)
    _acts = " ".join(it["action"] for it in a["optimization_items"])
    assert "收敛机制" not in _acts, a["optimization_items"]
    assert "题面异构" in a["detail_text"], a["detail_text"]
    assert "一致度不足" not in a["detail_text"], a["detail_text"]
    assert "0.76 < 0.67" not in a["detail_text"], a["detail_text"]


def test_same_task_replicas_keep_consensus_semantics():
    """同题复现（标记 id 不同但题面相同）⟹ task_heterogeneous=False，仍按旧语义算一致度 / n_eff（零回归）。"""
    refs = [
        _task_ref("a", "nt-g1a", "同一问题：证据是否充分？", "结论A：证据充分。", "G1"),
        _task_ref("b", "nt-g1b", "同一问题：证据是否充分？", "结论A：证据充分。", "G1"),
    ]
    cons = M.cluster_references(refs)["consensus"]
    assert cons["task_heterogeneous"] is False, cons
    # 同题且结论相同 ⟹ 折成一簇：n_eff=n²/Σsize²=1（旧语义零回归），不是 None。
    assert cons["n_eff"] == 1.0 and cons["independence_ok"] is False, cons
    assert cons["contradictions"] == [], cons


def test_same_conclusion_collapses_to_one_cluster():
    refs = [_ref("a1", "范围蔓延：本轮改动超出计划边界，建议收窄。", "G1"),
            _ref("a2", "范围蔓延：本轮改动超出计划边界，建议收窄。", "G1")]
    out = M.cluster_references(refs)
    assert out["consensus"]["n_clusters"] == 1, out
    c = out["clusters"][0]
    assert c["size"] == 2 and len(c["members"]) == 2, c
    assert c["arm_groups"] == {"G1": 2}, c
    assert c["weight"] == 1.0, c
    assert out["consensus"]["abstain"] is False, out["consensus"]


def test_minority_consensus_flagged_contradiction_label_free():
    """P2（2026-10-06）：矛盾判据**去 G3 标签** —— 少数**共识簇**（size≥2）即判矛盾，
    与 arm_group 无关（本用例少数簇来自 **G2**、且**全程无 G3**）。"""
    refs = [
        _ref("a1", "结论A：验证充分，证据链完整，无缺口。", "G1"),
        _ref("a2", "结论A：验证充分，证据链完整，无缺口。", "G1"),
        _ref("b1", "结论Z：该计划完全不可行，应立即废弃重写。", "G2"),
        _ref("b2", "结论Z：该计划完全不可行，应立即废弃重写。", "G2"),
    ]
    out = M.cluster_references(refs)
    cons = out["consensus"]
    assert cons["n_clusters"] == 2, out
    assert cons["top_weight"] == 0.5, cons
    contras = [c for c in out["clusters"] if c["contradiction"]]
    assert contras and all("G3" not in c["arm_groups"] for c in contras), contras
    assert cons["abstain"] is True, cons


def test_singleton_minority_not_flagged_contradiction():
    """P2：单例少数簇**不判**矛盾（噪音 vs 真矛盾无法用标签区分；防过标）。"""
    refs = [
        _ref("a1", "结论A：验证充分，无缺口。", "G1"),
        _ref("a2", "结论A：验证充分，无缺口。", "G1"),
        _ref("z", "结论Z：应立即废弃。", "G3"),
    ]
    out = M.cluster_references(refs)
    assert out["consensus"]["n_clusters"] == 2, out
    assert out["clusters"][1]["contradiction"] is False, out["clusters"][1]


def test_single_arm_not_collapsed():
    out = M.cluster_references([_ref("solo", "唯一结论：无缺口。", "G1")])
    assert out["consensus"]["n_clusters"] == 1
    assert out["clusters"][0]["size"] == 1
    assert out["clusters"][0]["contradiction"] is False


def test_g2_coverage_counts_distinct_clusters():
    refs = [_ref("g2a", "覆盖点一：并发写未加锁。", "G2"),
            _ref("g2b", "覆盖点二：回滚路径缺失。", "G2")]
    out = M.cluster_references(refs)
    assert out["consensus"]["coverage_g2"] == 2, out


def test_aggregate_exposes_clusters_and_keeps_old_keys(tmp_path):
    hist = [{"subagent_id": "a%d" % i, "batch_id": BATCH, "arm_group": "G1",
             "task": "plan-refinement: %s — 质询" % PLAN,
             "conclusion": "同一结论：验证充分，无缺口。",
             "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]}
            for i in range(2)]
    sf = tmp_path / "state.json"
    sf.write_text(json.dumps({"gate_data": {"subagent_history": hist}}, ensure_ascii=False),
                  encoding="utf-8")
    out = M.aggregate(str(sf), None, "plan-refinement", plan=PLAN, batch=BATCH)
    assert "clusters" in out and "consensus" in out, sorted(out)
    assert out["consensus"]["n_clusters"] == 1, out["consensus"]
    for k in ("mode", "aggregator_guidance", "references", "trace"):  # 旧键零回归
        assert k in out, k
    assert out["trace"]["count"] == 2


# ── S1-2（2026-10-06）：结构化字段签名取代整段 conclusion ─────────────────────
_V1 = {"F1": "WARN", "F2": "WARN", "F3": "WARN", "F4": "WARN", "F5": "WARN",
       "F6": "PASS", "F7": "PASS"}
_V2 = {"F1": "BLOCKED", "F2": "BLOCKED", "F3": "BLOCKED", "F4": "WARN", "F5": "WARN",
       "F6": "WARN", "F7": "WARN"}


def _refv(sid, grp, verdicts, concl=""):
    return {"subagent_id": sid, "arm_group": grp, "verdicts": verdicts,
            "conclusion": concl, "evidence": []}


def test_verdicts_drive_clustering_over_prose():
    """S1-2：长散文完全不同但 verdicts 相同 ⟹ 仍聚为一簇（不再按散文散开）。"""
    refs = [_refv("a1", "G1", _V1, "完全不同的长结论一" * 40),
            _refv("a2", "G1", _V1, "毫不相干的长结论二" * 40),
            _refv("a3", "G3", _V2, "第三段长结论三" * 40)]
    out = M.cluster_references(refs)
    assert out["consensus"]["n_clusters"] == 2, out
    big = out["clusters"][0]
    assert big["size"] == 2 and set(big["members"]) == {"a1", "a2"}, big
    assert big["signature_source"] == "verdicts", big
    assert out["clusters"][1]["contradiction"] is True, out["clusters"][1]


def test_verdict_conflict_flags_contradiction_label_free():
    """P2：有 verdicts ⟹ 语义矛盾（与逐 F 多数相左）判矛盾 —— 少数簇为 **G2**（无 G3）。"""
    refs = [_refv("a1", "G1", _V1), _refv("a2", "G1", _V1), _refv("b1", "G2", _V2)]
    out = M.cluster_references(refs)
    assert out["consensus"]["n_clusters"] == 2, out
    assert out["clusters"][1]["contradiction"] is True, out["clusters"][1]
    assert "G3" not in out["clusters"][1]["arm_groups"], out["clusters"][1]


def test_verdict_consensus_per_f():
    refs = [_refv("a1", "G1", dict(_V1)), _refv("a2", "G1", {**_V1, "F5": "BLOCKED"})]
    out = M.cluster_references(refs)
    vc = out["consensus"]["verdict_consensus"]
    assert vc["F1"]["majority"] == "WARN" and vc["F1"]["unanimous"] is True, vc
    assert vc["F5"]["unanimous"] is False and vc["F5"]["counts"]["WARN"] == 1, vc
    assert 0.0 < out["consensus"]["agreement"] <= 1.0, out["consensus"]


def test_challenges_used_when_no_verdicts():
    """无 verdicts ⟹ 退到 challenges/kept/slashed 条目签名。"""
    refs = [{"subagent_id": "a1", "arm_group": "G1", "challenges": ["范围蔓延须收窄"],
             "conclusion": "甲" * 300},
            {"subagent_id": "a2", "arm_group": "G1", "challenges": ["范围蔓延须收窄"],
             "conclusion": "乙" * 300}]
    out = M.cluster_references(refs)
    assert out["consensus"]["n_clusters"] == 1, out
    assert out["clusters"][0]["signature_source"] == "items"

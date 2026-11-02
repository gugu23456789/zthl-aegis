#!/usr/bin/env python3
"""红先臂（2026-10-10，ECC-0BA041A4284E）：MoA 聚合 ECC finding 批身份适配**跨批比对机制**。

缺陷（实读 + 真链复现，非推测）：
  · 生产者 `emit_aggregate_finding` 的 `root_key = sha256(plan|batch)[:16]`（批号**不可读**）；
    消费端 `_latest_defect_rate` 却按 `batch in root_key` 取批 ⟹ **恒 None**（p_art 通道死）。
  · finding **无** `batch:`/`plan:` 结构化 facet ⟹ 跨批比对（§18.2「按 batch_id 读组」）无从分组。
  · 批锚两 id 空间混用（聚合指纹 vs 流水线批号 `pr-<epoch>-<hex>`）⟹ 统一到聚合指纹 + 非指纹 fail-loud。
  · `_trend_from_state` 不按 plan 分组 ⟹ base 态多计划混线。

HEAD 必红：`_finding_batch` / `_finding_plan` 尚不存在；finding 无 batch facet；批锚无守卫。
"""
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import gk_moa_aggregate as M  # noqa: E402

PLAN = "/p/docs/plans/x-plan.md"
BATCH = "abc123def456"
PIPE_BATCH = "pr-1791623376-407ff82b"   # 流水线批号（非聚合指纹）


def _state(tmp_path, rows):
    """rows = [(subagent_id, batch_id, arm_group)]；task 含 PLAN 以便 plan 锚。"""
    hist = [{"subagent_id": sid, "batch_id": bid, "arm_group": g,
             "task": "plan-refinement: %s — 质询 %s" % (PLAN, sid),
             "conclusion": "结论" * 200,
             "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]}
            for (sid, bid, g) in rows]
    d = {"gate_data": {"subagent_history": hist, "ecc_findings": []}}
    p = tmp_path / "state.json"
    p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    return str(p)


def _write_findings(tmp_path, fs):
    d = {"gate_data": {"ecc_findings": fs}}
    p = tmp_path / "s.json"
    p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    return str(p)


def test_arm_real_chain_defect_rate(tmp_path):
    """真链：aggregate(--batch) → emit_aggregate_finding → 置 rejected ⟹ 消费者命中该批。"""
    sf = _state(tmp_path, [("sub-%d" % i, BATCH, "G1") for i in range(6)])
    agg = M.aggregate(sf, None, "plan-refinement", plan=PLAN, batch=BATCH)
    M.emit_aggregate_finding(sf, agg, plan=PLAN, batch=BATCH)
    d = json.loads(Path(sf).read_text(encoding="utf-8"))
    d["gate_data"]["ecc_findings"][0]["status"] = "rejected"
    Path(sf).write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    assert M._latest_defect_rate(sf, BATCH) == 1.0


def test_arm_emitted_finding_has_batch_plan_facet(tmp_path):
    """finding 带 `batch:<id>` / `plan:<归一路径>` 结构化 facet（跨批比对读组单源）。

    2026-10-26：`plan:` facet 落 `_plan_anchor` 归一值（`docs/plans/<basename>`）—— 绝对
    worktree / skills 绝对 / 相对三种写法必须同键，否则读组把同一计划拆成多组（RC0 实测）。
    """
    sf = _state(tmp_path, [("sub-%d" % i, BATCH, "G1") for i in range(6)])
    agg = M.aggregate(sf, None, "plan-refinement", plan=PLAN, batch=BATCH)
    f = M.emit_aggregate_finding(sf, agg, plan=PLAN, batch=BATCH)["finding"]
    fs = [str(x) for x in (f.get("facets") or [])]
    assert ("batch:" + BATCH) in fs, fs
    assert "plan:docs/plans/x-plan.md" in fs, fs
    assert "cross-batch:0" in fs, fs   # 恒落放开态（同 root_key 重跑可后写覆盖，防 stale）


def test_arm_legacy_anchor_only_batch_readable(tmp_path):
    """旧账：只带 `anchors:["batch:X"]`（无 facet）仍可读（防回归）。"""
    f = {"id": "1", "anchors": ["batch:" + BATCH]}
    assert M._finding_batch(f) == BATCH


def test_arm_batch_not_fingerprint_refused(tmp_path):
    """G2 守卫：流水线批号 `pr-<epoch>-<hex>`（非聚合指纹）⟹ fail-loud 拒落。"""
    sf = _state(tmp_path, [("sub-1", BATCH, "G1")])
    agg = M.aggregate(sf, None, "plan-refinement", plan=PLAN, batch=BATCH)
    res = M.emit_aggregate_finding(sf, agg, plan=PLAN, batch=PIPE_BATCH)
    assert res.get("ok") is False, res
    assert res.get("error") == "batch_not_fingerprint", res
    assert json.loads(Path(sf).read_text(encoding="utf-8"))["gate_data"]["ecc_findings"] == []


def test_arm_trend_filter_by_plan(tmp_path):
    """G3：趋势按 plan 过滤（base 态多计划不混线）。"""
    sf = _write_findings(tmp_path, [
        {"root_key": "moa-agg:a", "created_at": "2026-10-06T01:00:00Z",
         "facets": ["refs:6", "weight:0.81", "plan:" + PLAN]},
        {"root_key": "moa-agg:b", "created_at": "2026-10-06T02:00:00Z",
         "facets": ["refs:3", "weight:0.5", "plan:/other/plan.md"]},
    ])
    tr = M._trend_from_state(sf, plan=PLAN)
    assert len(tr) == 1 and tr[0]["mu"] == 6, tr


def test_guard_other_batch_excluded(tmp_path):
    """守卫：异批 finding 不计入（防误配）。"""
    sf = _write_findings(tmp_path, [
        {"id": "1", "facets": ["batch:OTHERBATCH12"], "status": "rejected"},
        {"id": "2", "facets": ["batch:" + BATCH], "status": "open"}])
    assert M._latest_defect_rate(sf, BATCH) == 0.0

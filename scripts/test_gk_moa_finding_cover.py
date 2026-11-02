#!/usr/bin/env python3
"""红先臂：MoA 聚合 finding 须声明「应拦审查层」（cover_layers）⟹ gap=False。

缺陷（实测 2026-10-11，`ECC-95277E21EF31`）：`emit_aggregate_finding` 调
`gk_finding.register(..., "review", ...)` **不传 cover_layers** ⟹ 每条 MoA 批裁决 finding 恒
`cover_layers=[]` + `gap=true` + `cover_warnings=[...]`（`source=review` ∈ `_COVER_REQUIRED_SOURCES`）。
实测：默认 state 65/67 条 finding 皆空；本域 state 亦然。C2/E2 要求缺陷族登记应拦审查层
（L1-L10/PR）——MoA 批裁决 = `plan-refinement`（**L2** code-to-spec）的产物层。

判据（HEAD 必红 —— register 未传 cover_layers）：
  1) `cover_layers` 非空且含 L2；
  2) `gap` 为 False；
  3) `cover_warnings` 空。
守卫（幂等合并不丢）：同 (plan,batch) 重发 ⟹ cover_layers 仍在（`register` merge 分支
须保留 cover_layers，而非只合 anchors/facets）。
"""
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import gk_moa_aggregate as M  # noqa: E402

PLAN = "/p/docs/plans/x-plan.md"
BATCH = "abc123def456"


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


def test_emit_finding_declares_cover_layers(tmp_path):
    """主判据：MoA 聚合 finding 须带 cover_layers（含 L2）且 gap=False、无 gap 告警。"""
    sf = _state(tmp_path, [("sub-%d" % i, BATCH, "G1") for i in range(6)])
    agg = M.aggregate(sf, None, "plan-refinement", plan=PLAN, batch=BATCH)
    f = M.emit_aggregate_finding(sf, agg, plan=PLAN, batch=BATCH)["finding"]
    assert f.get("cover_layers"), "cover_layers 空 —— MoA finding 未声明应拦审查层（E2 gap）"
    assert "L2" in f["cover_layers"], f["cover_layers"]
    assert f.get("gap") is False, "登记 cover_layers 后 gap 须为 False"
    assert not f.get("cover_warnings"), f.get("cover_warnings")


def test_emit_finding_reemit_keeps_cover_layers(tmp_path):
    """守卫：同 (plan,batch) 重发（root_key merge）⟹ cover_layers 不被清空。"""
    sf = _state(tmp_path, [("sub-%d" % i, BATCH, "G1") for i in range(6)])
    agg = M.aggregate(sf, None, "plan-refinement", plan=PLAN, batch=BATCH)
    M.emit_aggregate_finding(sf, agg, plan=PLAN, batch=BATCH)
    f = M.emit_aggregate_finding(sf, agg, plan=PLAN, batch=BATCH)["finding"]
    assert f.get("cover_layers"), "重发后 cover_layers 被清空（merge 丢字段）"
    assert f.get("gap") is False, f.get("gap")

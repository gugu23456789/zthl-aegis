#!/usr/bin/env python3
"""红先臂：MoA 聚合 `--batch` **批号双轨 / 未知批号静默** 的可观测性（`ECC-449948814679`）。

病象（2026-10-10 实测）：`--batch` 传**流水线批号** `pr-<epoch>-<hex>`（enqueue 回执 /
`task_pipeline[].batch`）而非 `subagent_history[].batch_id` 指纹时，`collect_entries` **静默**
返回 0 条（`mode=batch_bound` + `batch_size=0`），`aggregate` 不报错、`main` 仍落 finding ⟹
把「批号写错」误归因为「批内一致度不足 / 基础设施缺陷」（实测落 `ECC-37985D9A67BE`）。

判据（**HEAD 必红**）：未知批号须 `collect_entries` 返回 `mode=batch_unresolved` +
`available_batch_ids`，`aggregate` 落 `error=no_entry_matches_batch` + hint，且 `main` 的
`_emit` 受 `not agg.get("error")` 门控（禁落误归因 finding）。
判据面 = **已跟踪** `scripts/gk_moa_aggregate.py`（禁第二事实源；不新建模块）。
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_moa_aggregate as M  # noqa: E402

_HERE = Path(__file__).resolve().parent


def _mk_state(tmp: str) -> str:
    doc = {"gate_data": {"subagent_history": [
        {"subagent_id": "a1", "task": "plan-refinement: p — 组1", "batch_id": "deadbeef0001",
         "conclusion": "WARN"},
        {"subagent_id": "a2", "task": "plan-refinement: p — 组2", "batch_id": "deadbeef0001",
         "conclusion": "WARN"},
        {"subagent_id": "b1", "task": "plan-refinement: p — 组3", "batch_id": "cafebabe0002",
         "conclusion": "PASS"},
    ]}}
    p = os.path.join(tmp, "state.json")
    Path(p).write_text(json.dumps(doc), encoding="utf-8")
    return p


def test_arm1_unknown_batch_not_silent(tmp_path):
    """臂1（主判据）：未知批号 ⟹ `mode=batch_unresolved` + `available_batch_ids`（非静默 0 条）。"""
    st = _mk_state(str(tmp_path))
    entries, attr = M.collect_entries(st, None, None, batch="pr-1791623376-407ff82b")
    assert entries == [], "未知批号不得返回条目"
    assert attr.get("mode") == "batch_unresolved", "未知批号须显式标 batch_unresolved（HEAD 静默 batch_bound）"
    assert "deadbeef0001" in (attr.get("available_batch_ids") or []), "须给出可用 batch_id 清单"


def test_arm2_aggregate_errors_on_unknown_batch(tmp_path):
    """臂2：`aggregate` 在未知批号上须落 `error=no_entry_matches_batch` + hint（rc≠0）。"""
    st = _mk_state(str(tmp_path))
    agg = M.aggregate(st, None, None, batch="pr-unknown")
    assert agg.get("error") == "no_entry_matches_batch", "未知批号须报错（HEAD 返回无 error 的空聚合）"
    assert "batch_id" in (agg.get("hint") or ""), "hint 须点明 --batch 吃的是 batch_id 指纹"


def test_arm3_known_batch_still_binds(tmp_path):
    """守卫臂（**非红**：HEAD 即绿，不入选红先集）：已知 batch_id 仍精确绑定 2 臂。"""
    st = _mk_state(str(tmp_path))
    entries, attr = M.collect_entries(st, None, None, batch="deadbeef0001")
    assert len(entries) == 2 and attr.get("mode") == "batch_bound"


def test_arm4_emit_gated_on_error():
    """臂4：`main()` 的 `_emit` 须受 `not agg.get("error")` 门控（未知批号禁落 finding）。"""
    src = (_HERE / "gk_moa_aggregate.py").read_text(encoding="utf-8")
    assert 'and not agg.get("error")' in src, \
        "未知批号仍会落 finding ⟹ 误归因台账（HEAD 无该门）"

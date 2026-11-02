#!/usr/bin/env python3
"""红先臂：`gk_finding.register` 合并时**派生标题须刷新**（`ECC-60BF82183364`）。

病象（2026-10-10 实测）：同 `root_key` 重跑（= 同 (plan,batch) 再聚合）时，`register` 只合并
`anchors`/`facets`、**不更新 `title`** ⟹ 派生计数标题与 facets 口径分叉 —— 实测
`ECC-6A8E27475130` title `n=2 clusters=1 unknown` 而其 facets 已是 `refs:8 / infra-defect`
（人读被误导）。修法 = 仅对**派生标题**（前缀登记 `MoA聚合批裁决: `）刷新为最新；人工/策展标题
不动；历史不丢（merge 事件已把每次新标题记入 journal，`gk_finding.py:1112-1114`）。

判据面 = **已跟踪** `scripts/gk_finding.py`（禁第二事实源）。
red-first 沙箱按 `git archive HEAD` 取**未修**版 ⟹ 本文件对 HEAD 必红（两条 `arm_derived_title_*`）。
`test_guard_manual_title_preserved` 为**非红**回归守卫（HEAD 即绿），不入选红先集。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_finding as F  # noqa: E402


def _st(tmp_path) -> str:
    sf = tmp_path / "state.json"
    sf.write_text(json.dumps({"gate_data": {"subagent_history": [], "ecc_findings": []}}),
                  encoding="utf-8")
    return str(sf)


def _title(sf: str) -> str:
    return json.loads(Path(sf).read_text(encoding="utf-8"))["gate_data"]["ecc_findings"][0]["title"]


def test_arm_derived_title_refreshed(tmp_path):
    """臂（主判据）：派生标题同 root_key 重跑 ⟹ **刷为最新**（HEAD：冻结首条 ⟹ title↔facets 分叉）。"""
    sf = _st(tmp_path)
    F.register(sf, "MoA聚合批裁决: batch=b1 n=6 clusters=4 suspect=0 infra-defect", "review",
               root_key="moa-agg:rk1", facets=["classification:infra-defect", "refs:6"])
    F.register(sf, "MoA聚合批裁决: batch=b1 n=2 clusters=2 suspect=0 plan-error", "review",
               root_key="moa-agg:rk1", facets=["classification:plan-error", "refs:2"])
    t = _title(sf)
    assert "n=2 clusters=2" in t and t.endswith("plan-error"), t


def test_arm_derived_title_refreshed_cross_format(tmp_path):
    """臂（跨标题形态）：旧格式（无 `clusters=`）→ 新格式亦须刷新（防只认单一字面）。"""
    sf = _st(tmp_path)
    F.register(sf, "MoA聚合批裁决: batch=b2 n=6 suspect=0", "review",
               root_key="moa-agg:rk2", facets=["classification:infra-defect"])
    F.register(sf, "MoA聚合批裁决: batch=b2 n=8 clusters=1 suspect=0 plan-error", "review",
               root_key="moa-agg:rk2", facets=["classification:plan-error"])
    t = _title(sf)
    assert "n=8 clusters=1" in t and t.endswith("plan-error"), t


def test_guard_manual_title_preserved(tmp_path):
    """守卫臂（**非红**：HEAD 即绿）：人工/策展标题**不得**被刷新覆盖（防过度修复）。"""
    sf = _st(tmp_path)
    F.register(sf, "人工标题甲", "manual", root_key="rk3", facets=["alpha:1"])
    F.register(sf, "人工标题乙", "manual", root_key="rk3", facets=["beta:1"])
    assert _title(sf) == "人工标题甲", _title(sf)

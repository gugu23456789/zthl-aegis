#!/usr/bin/env python3
"""G2 红先臂：跨域重复登记检测（同 `root_key` 跨源）。

背景（2026-10-03 crossfull 交叉审查）：同缺陷在**不同域 state** 各自登记（id 不同、domain
不同）⟹ 一域已 close、另一域仍 open（实测 `ECC-9D69CA476E5C` open @review-runtime vs
`ECC-E2AE7C65A71D` closed @base，后者 `verify_source=s18-moa-plan-anchor`）。

判据（红先，HEAD 必红`cross_domain_dups` 不存在）：
  - 跨源同**非空** `root_key` ⟹ 报 1 条（机械键）；
  - 单源 / `root_key` 空 ⟹ **不报**（无 key 不可机检，是「未判」非「无重复」）；
  - 挂 `finding status` 只读字段 `cross_domain_dup`（不新增子命令）。
"""
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import gk_finding as F  # noqa: E402


def _mk(tmp_path, name, findings):
    p = tmp_path / name
    p.write_text(json.dumps({"gate_data": {"ecc_findings": findings}}), encoding="utf-8")
    return p


def test_cross_domain_dup_hits(tmp_path):
    base = _mk(tmp_path, ".gatekeeper.state",
               [{"id": "ECC-A", "status": "closed", "root_key": "rk-x"}])
    _mk(tmp_path, ".gatekeeper.state.dom1",
        [{"id": "ECC-B", "status": "open", "root_key": "rk-x"}])
    dups = F.cross_domain_dups(str(base))
    assert len(dups) == 1, dups
    assert dups[0]["root_key"] == "rk-x", dups
    assert {m["id"] for m in dups[0]["members"]} == {"ECC-A", "ECC-B"}, dups
    assert {m["status"] for m in dups[0]["members"]} == {"closed", "open"}, dups


def test_cross_domain_single_source_clean(tmp_path):
    base = _mk(tmp_path, ".gatekeeper.state",
               [{"id": "ECC-A", "status": "open", "root_key": "rk-x"}])
    assert F.cross_domain_dups(str(base)) == []


def test_cross_domain_same_source_not_reported(tmp_path):
    """同源内两条同 key **不**算跨域重复（本面只治跨源）。"""
    base = _mk(tmp_path, ".gatekeeper.state",
               [{"id": "ECC-A", "status": "open", "root_key": "rk-x"},
                {"id": "ECC-B", "status": "open", "root_key": "rk-x"}])
    assert F.cross_domain_dups(str(base)) == []


def test_cross_domain_empty_root_key_not_detected(tmp_path):
    """无 key 跨源同场景 ⟹ 不报（机械键缺失 = 未判，非无重复；限制显式文档化）。"""
    base = _mk(tmp_path, ".gatekeeper.state", [{"id": "ECC-A", "status": "closed"}])
    _mk(tmp_path, ".gatekeeper.state.dom1", [{"id": "ECC-B", "status": "open"}])
    assert F.cross_domain_dups(str(base)) == []

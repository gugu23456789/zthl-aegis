#!/usr/bin/env python3
"""审计证据 → finding 台账适配器（E18，2026-10-29）。

闭环验收：`audit_*_result` 里的 `match=false` 必须变成 `source="audit"` 的 finding，
且重跑幂等（root_key 合并）、`dry-run` 零写盘、severity 只升不降。
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import gk_audit_findings as A  # noqa: E402
from gk_finding import load_findings, register  # noqa: E402


def _state(tmp_path, gd=None, findings=None):
    p = tmp_path / "state.json"
    gate = {"ecc_findings": findings or []}
    gate.update(gd or {})
    p.write_text(json.dumps({"gate_data": gate}), encoding="utf-8")
    return str(p)


def _gd_state(**over):
    base = {"audit_state_result": {"state_checks": [], "audit_summary": {}}}
    base.update(over)
    return base


def test_state_check_failure_registers_finding(tmp_path):
    gd = _gd_state(audit_state_result={"state_checks": [
        {"field": "edit_budget", "declared": 8, "replay": 0, "match": False,
         "issues": ["计数器与账本不一致"]},
        {"field": "branch", "declared": "b", "replay": "b", "match": True},
    ]})
    sf = _state(tmp_path, gd)
    out = A.apply_findings(sf, gd)
    assert out["ok"] and out["candidates"] == 1 and out["registered"] == 1
    fs = load_findings(sf)
    assert len(fs) == 1
    f = fs[0]
    assert f["source"] == "audit"
    assert f["status"] == "open"
    assert f["release_state"] == "provisional"
    assert f["severity"] == "high"
    assert f["owner"] == A.DEFAULT_OWNER
    assert f["family"] == "AUDIT-STATE"
    assert f["root_key"] == "audit.state.edit_budget"
    assert "edit_budget" in f["title"]


def test_seal_family_check_is_critical(tmp_path):
    gd = _gd_state(audit_state_result={"state_checks": [
        {"field": "budget_ledger_seal_ok", "match": False},
        {"field": "context_signature", "match": False},
        {"field": "human_resolutions", "match": False},
    ]})
    sf = _state(tmp_path, gd)
    out = A.apply_findings(sf, gd)
    assert out["registered"] == 3
    sev = {f["root_key"]: f["severity"] for f in load_findings(sf)}
    assert sev["audit.state.budget_ledger_seal_ok"] == "critical"
    assert sev["audit.state.context_signature"] == "critical"
    assert sev["audit.state.human_resolutions"] == "medium"


def test_docs_c2_is_high_others_medium(tmp_path):
    gd = {"audit_state_result": {"state_checks": []},
          "audit_docs_result": {"docs_checks": [
              {"doc": "extension-registry.md", "check": "C2 CLI 命令表覆盖",
               "match": False},
              {"doc": "cli-protocol.md", "check": "C1 命令计数", "match": False},
          ], "summary": {"total": 2, "matches": 0, "failures": 2}}}
    sf = _state(tmp_path, gd)
    A.apply_findings(sf, gd)
    sev = {f["root_key"]: f["severity"] for f in load_findings(sf)}
    assert sev["audit.docs.extension-registry.md.C2_CLI_命令表覆盖"] == "high"
    assert sev["audit.docs.cli-protocol.md.C1_命令计数"] == "medium"


def test_rerun_is_idempotent(tmp_path):
    gd = _gd_state(audit_state_result={"state_checks": [
        {"field": "edit_budget", "match": False, "issues": ["x"]}]})
    sf = _state(tmp_path, gd)
    first = A.apply_findings(sf, gd)
    second = A.apply_findings(sf, gd)
    assert first["registered"] == 1 and second["merged"] == 1
    assert second["registered"] == 0
    assert len(load_findings(sf)) == 1


def test_dry_run_writes_nothing(tmp_path):
    gd = _gd_state(audit_state_result={"state_checks": [
        {"field": "edit_budget", "match": False}]})
    sf = _state(tmp_path, gd)
    before = Path(sf).read_text(encoding="utf-8")
    out = A.apply_findings(sf, gd, dry_run=True)
    assert out["dry_run"] is True and out["candidates"] == 1
    assert out["registered"] == 0
    assert Path(sf).read_text(encoding="utf-8") == before
    assert load_findings(sf) == []


def test_severity_never_downgrades_on_merge(tmp_path):
    sf = _state(tmp_path)
    register(sf, "t", "audit", root_key="audit.state.x", severity="critical",
             owner="skill.a")
    register(sf, "t", "audit", root_key="audit.state.x", severity="low",
             owner="skill.b")
    f = load_findings(sf)[0]
    assert f["severity"] == "critical", "严重度只升不降"
    assert f["owner"] == "skill.a", "已有责任域不被覆盖"


def test_register_rejects_invalid_severity_and_owner(tmp_path):
    sf = _state(tmp_path)
    with pytest.raises(ValueError):
        register(sf, "t", "audit", severity="blocker")
    with pytest.raises(ValueError):
        register(sf, "t", "audit", owner="有 空格的责任域")
    assert load_findings(sf) == []


def test_root_key_normalized_and_bounded():
    k = A._root_key("audit", "state", "a field " * 20)
    assert " " not in k and len(k) <= 64
    assert A._root_key("audit", "state", "edit_budget") == "audit.state.edit_budget"
    assert A._root_key("audit", "state", "edit_budget") == \
        A._root_key("audit", "state", "edit_budget")

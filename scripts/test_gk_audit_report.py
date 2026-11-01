#!/usr/bin/env python3
"""审计报告 JSON 侧车（E18/B3，2026-10-29）。

验收：侧车落 `<state>.audit-report.json`（随 state 走，不写死安装目录）、
字段齐备、findings 只带摘要、severity 计数含 unrated、重写原子覆盖。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gk_audit_report as R  # noqa: E402
from gk_finding import register  # noqa: E402


def _state(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"gate_data": {"ecc_findings": []}}), encoding="utf-8")
    return str(p)


def test_write_creates_sibling_sidecar_with_fields(tmp_path):
    sf = _state(tmp_path)
    out = R.write(sf, audit_id="AUDIT-X", audit_type="performance",
                  content_hash="abc123", report_path="/x/ecc-audit-1.md")
    assert out["ok"] and out["schema"] == R.SCHEMA
    path = Path(R.sidecar_path(sf))
    assert path.exists() and path.parent == Path(sf).parent
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["audit_id"] == "AUDIT-X"
    assert doc["audit_type"] == "performance"
    assert doc["content_hash"] == "abc123"
    assert doc["report_path"] == "/x/ecc-audit-1.md"
    assert doc["state_file"] == sf
    assert doc["written_at"].endswith("Z")


def test_findings_summary_and_severity_counts(tmp_path):
    sf = _state(tmp_path)
    register(sf, "a", "audit", root_key="audit.state.a", severity="critical")
    register(sf, "b", "audit", root_key="audit.state.b", severity="critical")
    register(sf, "c", "manual", root_key="audit.state.c")   # 未定级
    out = R.write(sf, audit_id="A", audit_type="compliance")
    assert out["findings"] == 3
    doc = json.loads(Path(R.sidecar_path(sf)).read_text(encoding="utf-8"))
    assert doc["summary"]["total"] == 3
    assert doc["summary"]["by_severity"] == {"critical": 2, "unrated": 1}
    ids = {f["id"] for f in doc["findings"]}
    assert len(ids) == 3 and all(ids)
    # 只带摘要字段（不复制证据正文）
    assert set(doc["findings"][0]) == {"id", "title", "severity", "status", "source"}


def test_read_roundtrip_and_missing(tmp_path):
    sf = _state(tmp_path)
    assert R.read(sf)["ok"] is False
    R.write(sf, audit_id="A", audit_type="performance")
    got = R.read(sf)
    assert got["ok"] and got["report"]["audit_id"] == "A"


def test_rewrite_overwrites_atomically(tmp_path):
    sf = _state(tmp_path)
    R.write(sf, audit_id="OLD", audit_type="performance")
    R.write(sf, audit_id="NEW", audit_type="redteam")
    doc = json.loads(Path(R.sidecar_path(sf)).read_text(encoding="utf-8"))
    assert doc["audit_id"] == "NEW" and doc["audit_type"] == "redteam"
    assert not Path(R.sidecar_path(sf) + ".tmp").exists()

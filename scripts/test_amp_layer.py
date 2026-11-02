#!/usr/bin/env python3
"""AMP 兼容层（`zthl/acp/amp.py` + `amp_bridge.py`）规范符合性测试。

锚：ACPs v2.2.0 `09-ACPs-spec-AMP` §5.1.2 `LogRecord` / §5.1.3 `logId` / §5.2-5.6 Body；
计划 §2.7「六类分文件 + 7 天轮转 + 零服务依赖」。
"""
import json
import os
import sys
import time

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (_ROOT, os.path.join(_ROOT, "scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from zthl.acp import amp, amp_bridge  # noqa: E402

REQUIRED = ("schemaVersion", "timestamp", "aic", "logId", "logType",
            "severityText", "severityNumber", "body", "resource")


@pytest.fixture(autouse=True)
def _amp_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("GK_AMP_DIR", str(tmp_path))
    monkeypatch.delenv("GK_AMP", raising=False)
    monkeypatch.setenv("_AUDIT_KEY_DIR", str(tmp_path / "no-keys"))
    return tmp_path


def _read(path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


# ── LogRecord 结构（spec §5.1.2）──────────────────────────────────────────────
@pytest.mark.parametrize("log_type", list(amp.LOG_TYPES))
def test_log_record_required_fields(log_type):
    rec = amp.build(log_type, {})
    for k in REQUIRED:
        assert k in rec, f"{log_type}: missing {k}"
    assert rec["logType"] == log_type
    assert rec["schemaVersion"] == "1.0.0"
    assert rec["severityNumber"] == 9


def test_unknown_log_type_fails_loud():
    with pytest.raises(ValueError):
        amp.build("application", {})


def test_log_id_is_uuid_v7():
    lid = amp.new_log_id()
    assert len(lid) == 36 and lid[8] == "-" and lid[14] == "7"
    assert lid[19] in "89ab"


def test_trace_span_widths():
    assert len(amp.new_trace_id()) == 32
    assert len(amp.new_span_id()) == 16


def test_aic_default_is_marked_unregistered(monkeypatch):
    monkeypatch.delenv("GK_AIC", raising=False)
    rec = amp.build("access", {})
    assert rec["aic"] == amp.DEFAULT_AIC
    assert rec["attributes"]["zthl.aic.registered"] is False
    monkeypatch.setenv("GK_AIC", "1.2.156.3088.x")
    rec2 = amp.build("access", {})
    assert rec2["aic"] == "1.2.156.3088.x"
    assert "zthl.aic.registered" not in rec2.get("attributes", {})


# ── 分文件 / 关闭 / 轮转（计划 §2.7）──────────────────────────────────────────
def test_six_types_write_separate_files(tmp_path):
    for t in amp.LOG_TYPES:
        assert amp.emit(t, {"n": t}) is not None
    for t in amp.LOG_TYPES:
        p = tmp_path / f"{t}.log"
        assert p.exists(), f"missing {t}.log"
        recs = _read(p)
        assert len(recs) == 1 and recs[0]["logType"] == t


def test_disable_switch():
    os.environ["GK_AMP"] = "0"
    try:
        assert amp.emit("access", {}) is None
    finally:
        del os.environ["GK_AMP"]


def test_rotation_after_retention(tmp_path):
    p = tmp_path / "access.log"
    p.write_text('{"old":1}\n', encoding="utf-8")
    old = time.time() - 8 * 86400
    os.utime(p, (old, old))
    amp.emit("access", {"n": "new"})
    archived = [x.name for x in tmp_path.iterdir() if x.name.startswith("access.log.")]
    assert archived, "expected rotated archive"
    lines = _read(p)
    assert len(lines) == 1 and lines[0]["body"] == {"n": "new"}


def test_no_rotation_when_fresh(tmp_path):
    amp.emit("access", {"n": 1})
    amp.emit("access", {"n": 2})
    assert len(_read(tmp_path / "access.log")) == 2


# ── audit 签名（spec §5.6.1：必须签名；无钥不得冒充）──────────────────────────
def test_audit_unsigned_is_explicitly_marked():
    rec = amp.emit(**amp_bridge.audit({"event": "close", "fid": "ECC-1", "ts": "2026-10-26T00:00:00+00:00"}))
    assert rec["logType"] == "audit"
    assert rec["attributes"]["zthl.integrity"] == "unsigned(no-audit-key)"
    assert "integrity" not in rec


# ── 采集层映射（计划 §2.7 数据源表）───────────────────────────────────────────
def test_access_body_block_mapping():
    kw = amp_bridge.access("RunCommand", "block", 2, "r0.9 windows git write", 12.5)
    assert kw["log_type"] == "access"
    assert kw["body"]["response"]["statusCode"] == 2
    assert kw["body"]["error"]["code"] == 2
    assert kw["body"]["durationMs"] == 12.5
    assert kw["attributes"]["zthl.decision"] == "block"


def test_heartbeat_body_shape():
    kw = amp_bridge.heartbeat({"ok": True, "issues": 1,
                               "checks": [{"field": "key_integrity", "status": "FAIL"}]})
    assert kw["log_type"] == "heartbeat"
    assert set(kw["body"]) <= {"uptimeSeconds"}
    assert kw["attributes"]["zthl.self_check.issues"] == 1
    assert kw["attributes"]["zthl.self_check.nonpass"] == ["key_integrity"]


def test_metrics_aggregates_access_window(tmp_path):
    amp.emit(**amp_bridge.access("Read", "allow", 0, "", 10.0))
    amp.emit(**amp_bridge.access("Write", "block", 2, "x", 30.0))
    kw = amp_bridge.metrics(5)
    win = kw["body"]["windowMetrics"][0]
    assert kw["log_type"] == "metrics"
    assert win["window"] == "PT5M"
    assert win["requestTotal"] == 2
    assert win["successRate"] == 50.0
    assert win["p99LatencyMs"] == 30.0


def test_metrics_empty_window_returns_none():
    assert amp_bridge.metrics(5) is None


def test_system_only_when_non_pass():
    assert amp_bridge.system({"checks": [{"field": "a", "status": "PASS"}]}) is None
    kw = amp_bridge.system({"checks": [{"field": "a", "status": "WARN", "detail": "d"}], "issues": 1})
    assert kw["log_type"] == "system"
    assert kw["body"]["rawBody"][0]["check"] == "a"


def test_message_is_seam():
    assert amp_bridge.message({"topic": "t"}) is None


# ── audit 采集幂等（journal 自然键）──────────────────────────────────────────
def test_collect_audit_is_idempotent(tmp_path):
    state = tmp_path / "st"
    journal = tmp_path / "st.finding-journal.jsonl"
    journal.write_text(
        "\n".join(json.dumps(e) for e in [
            {"ts": "2026-10-26T00:00:00+00:00", "event": "register", "fid": "A"},
            {"ts": "2026-10-26T00:01:00+00:00", "event": "close", "fid": "A"},
        ]) + "\n", encoding="utf-8")
    first = amp_bridge.collect_audit(str(state))
    assert first["added"] == 2
    second = amp_bridge.collect_audit(str(state))
    assert second["added"] == 0 and second["skipped"] == 2
    recs = _read(tmp_path / "audit.log")
    assert [r["body"]["action"]["name"] for r in recs] == ["finding.register", "finding.close"]
    assert recs[1]["body"]["result"]["status"] == "success"


# ── 读面（query）─────────────────────────────────────────────────────────────
def test_query_filters():
    amp.emit(**amp_bridge.access("Read", "allow", 0, "", 1.0))
    amp.emit(**amp_bridge.access("Write", "block", 2, "r", 2.0))
    amp.emit("heartbeat", {})
    assert len(amp.query(limit=10)) == 3
    assert [r["logType"] for r in amp.query("heartbeat")] == ["heartbeat"]
    blocked = amp.query("access", where={"attributes.zthl.decision": "block"})
    assert len(blocked) == 1 and blocked[0]["body"]["request"]["method"] == "Write"
    assert amp.query(since="1h", limit=10)
    assert len(amp.query(limit=1)) == 1

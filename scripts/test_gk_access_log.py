#!/usr/bin/env python3
"""AMP access 记录（hook 进程出口）：allow / block / 关闭 / 落点覆盖。

2026-10-26 起 hook 侧不再自造 jsonl，改为委托 `zthl.acp.amp`（计划 ZH2-H10 / ZH3-H14f）。
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pre_tool_hook as hook  # noqa: E402


def _read(path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def _clean_env(monkeypatch, tmp_path):
    monkeypatch.setenv("GK_AMP_DIR", str(tmp_path))
    monkeypatch.delenv("GK_AMP", raising=False)
    monkeypatch.delenv("GK_ACCESS_LOG", raising=False)


def test_allow_record(tmp_path, monkeypatch):
    _clean_env(monkeypatch, tmp_path)
    hook._amp_access_record("Read", "allow", "", 0)
    recs = _read(tmp_path / "access.log")
    assert len(recs) == 1
    r = recs[0]
    assert r["logType"] == "access"
    assert r["schemaVersion"] == "1.0.0"
    assert r["body"]["request"]["method"] == "Read"
    assert r["body"]["response"]["statusCode"] == 0
    assert r["attributes"]["zthl.decision"] == "allow"
    assert r["body"]["durationMs"] >= 0          # 进程出口耗时（观测面）
    assert "error" not in r["body"]


def test_block_record_carries_reason(tmp_path, monkeypatch):
    _clean_env(monkeypatch, tmp_path)
    hook._amp_access_record("RunCommand", "block", "windows-side git write", 2)
    r = _read(tmp_path / "access.log")[0]
    assert r["attributes"]["zthl.decision"] == "block"
    assert r["severityText"] == "WARN"
    assert r["body"]["response"]["statusCode"] == 2
    assert r["body"]["error"]["message"] == "windows-side git write"


def test_disable_switch(tmp_path, monkeypatch):
    _clean_env(monkeypatch, tmp_path)
    monkeypatch.setenv("GK_ACCESS_LOG", "0")
    hook._amp_access_record("Read", "allow", "", 0)
    assert not (tmp_path / "access.log").exists()


def test_global_amp_switch(tmp_path, monkeypatch):
    _clean_env(monkeypatch, tmp_path)
    monkeypatch.setenv("GK_AMP", "0")
    hook._amp_access_record("Read", "allow", "", 0)
    assert not (tmp_path / "access.log").exists()


def test_dir_override(tmp_path, monkeypatch):
    _clean_env(monkeypatch, tmp_path / "amp")
    hook._amp_access_record("Grep", "allow", "", 0)
    p = tmp_path / "amp" / "access.log"
    assert p.exists()
    assert _read(p)[0]["body"]["request"]["method"] == "Grep"

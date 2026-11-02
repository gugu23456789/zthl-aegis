"""test_gk_cron_model_radar.py — 雷达（0 API）行为臂：基线 / 增量 / 抓取失败。"""
import json
import sys
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gk_cron_model_radar as R  # noqa: E402


def _setup(tmp_path, monkeypatch):
    monkeypatch.setattr(R, "RADAR_DIR", tmp_path / "radar")
    monkeypatch.setattr(R, "STATE", tmp_path / "radar" / "state.json")
    monkeypatch.setattr(R, "EVENTS", tmp_path / "radar" / "events.jsonl")
    monkeypatch.setattr(R, "STATE_FILE", tmp_path / "nonexistent.state")


def _out(capsys):
    return json.loads(capsys.readouterr().out.strip().splitlines()[-1])


def test_baseline_records_state_without_events(tmp_path, monkeypatch, capsys):
    _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(R, "_fetch", lambda *a, **k: [
        {"id": "deepseek-ai/DeepSeek-V3", "lastModified": "2026-01-01T00:00:00Z"}])
    assert R.main() == 0
    out = _out(capsys)
    assert out["baseline"] is True and out["new"] == []
    assert R.STATE.exists()


def test_new_model_emits_event_and_appends(tmp_path, monkeypatch, capsys):
    _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(R, "_fetch", lambda *a, **k: [
        {"id": "deepseek-ai/DeepSeek-V3", "lastModified": "2026-01-01T00:00:00Z"}])
    R.main()
    capsys.readouterr()
    monkeypatch.setattr(R, "_fetch", lambda *a, **k: [
        {"id": "deepseek-ai/DeepSeek-V3", "lastModified": "2026-01-01T00:00:00Z"},
        {"id": "deepseek-ai/DeepSeek-V4", "lastModified": "2026-06-01T00:00:00Z"}])
    assert R.main() == 0
    out = _out(capsys)
    assert [e["model"] for e in out["new"]] == ["deepseek-ai/DeepSeek-V4"]
    lines = R.EVENTS.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1


def test_fetch_failure_is_named_and_nonzero(tmp_path, monkeypatch, capsys):
    _setup(tmp_path, monkeypatch)
    def _boom(*a, **k):
        raise urllib.error.URLError("blocked")
    monkeypatch.setattr(R, "_fetch", _boom)
    assert R.main() == 1
    out = _out(capsys)
    assert out["ok"] is False and out["error"].startswith("fetch_failed")

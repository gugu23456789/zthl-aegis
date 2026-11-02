"""test_gk_audit_cron_run.py — audit-daily 驱动：指纹跳过 / 变更重跑 / 失败告警 / 计时。"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gk_audit_cron_run as R  # noqa: E402


def _skill(tmp_path, ok=True):
    s = tmp_path / "skill"
    s.mkdir()
    marker = tmp_path / "calls"
    body = "#!/usr/bin/env bash\necho x >> %s\n" % marker
    body += "echo '%s'\n" % json.dumps({"ok": ok, "result": {"domain": "x"}})
    cli = s / "gatekeeper-cli.sh"
    cli.write_text(body, encoding="utf-8")
    cli.chmod(0o755)
    state = tmp_path / "state"
    state.write_text("{}", encoding="utf-8")
    return s, state, marker


def _paths(tmp_path):
    return (tmp_path / "cache.json", tmp_path / "alert.json", tmp_path / "audit.log")


def test_first_run_executes_then_skips_when_unchanged(tmp_path):
    s, state, marker = _skill(tmp_path)
    cache, alert, log = _paths(tmp_path)
    r1 = R.run(str(s), ["state", "docs"], 30, cache, alert, log, str(state))
    assert r1["ok"] is True and r1["skipped"] is False
    assert marker.read_text().count("x") == 2
    assert all("sec" in v for v in r1["results"].values())
    r2 = R.run(str(s), ["state", "docs"], 30, cache, alert, log, str(state))
    assert r2["skipped"] is True
    assert marker.read_text().count("x") == 2


def test_state_change_forces_rerun(tmp_path):
    s, state, marker = _skill(tmp_path)
    cache, alert, log = _paths(tmp_path)
    R.run(str(s), ["state"], 30, cache, alert, log, str(state))
    state.write_text('{"changed": 1}', encoding="utf-8")
    r2 = R.run(str(s), ["state"], 30, cache, alert, log, str(state))
    assert r2["skipped"] is False
    assert marker.read_text().count("x") == 2


def test_failure_writes_alert_and_never_skips(tmp_path):
    s, state, marker = _skill(tmp_path, ok=False)
    cache, alert, log = _paths(tmp_path)
    r1 = R.run(str(s), ["state"], 30, cache, alert, log, str(state))
    assert r1["ok"] is False and r1["failed_domains"]
    assert alert.exists()
    r2 = R.run(str(s), ["state"], 30, cache, alert, log, str(state))
    assert r2["skipped"] is False


def test_verdict_matches_legacy_semantics():
    assert R._verdict('{"ok": true}') == "ok"
    assert R._verdict('{"ok": false, "error": "boom"}') == "bad:boom"
    assert R._verdict("not-json") == "bad:unparseable"
    assert R._verdict('{"ok": true, "result": {"error": "x"}}') == "bad:x"

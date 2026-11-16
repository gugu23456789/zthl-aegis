"""T5 seed：cron 作业可重建（2026-11-14）。红先：seed 脚本落刀前本模块 ImportError。"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cron_jobs as CJ   # noqa: E402
import gk_cron_seed as S  # noqa: E402


def _isolate(tmp_path, monkeypatch):
    cron = tmp_path / "cron"
    monkeypatch.setattr(CJ, "JOBS_DIR", str(cron))
    monkeypatch.setattr(CJ, "JOBS_FILE", str(cron / "jobs.json"))
    monkeypatch.setattr(CJ, "OUTPUT_DIR", str(cron / "output"))
    return cron


def test_check_reports_missing(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    rc, rep = S.ensure(apply=False)
    assert rc == 1 and rep["action"] == "missing", rep


def test_apply_creates_job(tmp_path, monkeypatch):
    cron = _isolate(tmp_path, monkeypatch)
    rc, rep = S.ensure(apply=True)
    assert rc == 0 and rep["action"] == "create", rep
    jobs = json.loads((cron / "jobs.json").read_text(encoding="utf-8"))
    assert len(jobs) == 1, jobs
    j = jobs[0]
    assert j["name"] == "audit-model-tick"
    assert j["schedule"] == {"kind": "interval", "minutes": 1}
    assert j["no_agent"] is True and j["enabled"] is True
    assert j["script"].endswith("gk_audit_model_tick.py")
    assert j["next_run_at"], "next_run_at 必须已计算"


def test_apply_is_idempotent(tmp_path, monkeypatch):
    cron = _isolate(tmp_path, monkeypatch)
    S.ensure(apply=True)
    first = json.loads((cron / "jobs.json").read_text(encoding="utf-8"))[0]
    rc, rep = S.ensure(apply=True)
    assert rc == 0 and rep["action"] == "none", rep
    second = json.loads((cron / "jobs.json").read_text(encoding="utf-8"))[0]
    assert second["id"] == first["id"]
    assert second["created_at"] == first["created_at"], "seed 不得重置创建时间"


def test_apply_repairs_script_path(tmp_path, monkeypatch):
    cron = _isolate(tmp_path, monkeypatch)
    S.ensure(apply=True)
    jobs = json.loads((cron / "jobs.json").read_text(encoding="utf-8"))
    jobs[0]["script"] = "/old/path.py"
    (cron / "jobs.json").write_text(json.dumps(jobs), encoding="utf-8")
    rc, rep = S.ensure(apply=True)
    assert rc == 0 and rep["action"] == "update", rep
    fixed = json.loads((cron / "jobs.json").read_text(encoding="utf-8"))[0]
    assert fixed["script"].endswith("gk_audit_model_tick.py")


def test_check_green_after_apply(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    S.ensure(apply=True)
    rc, rep = S.ensure(apply=False)
    assert rc == 0 and rep["action"] == "none", rep

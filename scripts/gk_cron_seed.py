#!/usr/bin/env python3
"""gk_cron_seed.py — 审计署 4B 生命周期 tick 的**可重建注册**（408 T5，2026-11-14）。

问题：`audit-model-tick` 只存在于运行时 `~/.gatekeeper/cron/jobs.json`；换机器 / 清 HOME 后
不会自动重建（T5 只能人工 `cron create` ⟹ 判据不可复现）。本脚本 = 幂等 seed：

  - 缺失 ⟹ 建（id = sha1(name)[:12]、schedule=every 1m、no_agent=True、script 绝对路径）
  - 已存在 ⟹ **只校正** script / schedule / no_agent / enabled；保留 id、created_at、run_count、
    failure_streak、last_run_at（不重置运行统计；schedule 变了才重算 next_run_at）

用法：
  python scripts/gk_cron_seed.py --check   # 只读；缺失/漂移 rc=1
  python scripts/gk_cron_seed.py --apply   # 写入；成功 rc=0
"""
import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cron_jobs as CJ  # noqa: E402

NAME = "audit-model-tick"
SCRIPT = str(Path(__file__).resolve().parent / "gk_audit_model_tick.py")
PROMPT = "审计署 4B 生命周期 tick（确定性作业体，无 API）"
SCHEDULE_EXPR = "every 1m"


def _iso(dt) -> str:
    return dt.isoformat() + "Z" if dt else ""


def _job_id() -> str:
    return hashlib.sha1(NAME.encode("utf-8")).hexdigest()[:12]


def ensure(apply=False):
    """→ `(rc, report)`；rc=0 正常/已修，rc=1 需修（--check），rc=3 脚本不合规。"""
    v = CJ.validate_script_path(SCRIPT)
    if not v.get("ok"):
        return 3, {"ok": False, "action": "invalid-script", "error": v.get("error", "")}

    jobs = CJ.load_jobs()
    if not isinstance(jobs, list):
        jobs = []
    sched = CJ.parse_schedule(SCHEDULE_EXPR)
    idx = next((i for i, j in enumerate(jobs) if j.get("name") == NAME), -1)

    if idx < 0:
        if not apply:
            return 1, {"ok": False, "action": "missing", "script": SCRIPT}
        job = {
            "id": _job_id(), "name": NAME, "prompt": PROMPT,
            "schedule": sched, "schedule_display": SCHEDULE_EXPR,
            "next_run_at": _iso(CJ.compute_next_run(sched)),
            "enabled": True, "state": "scheduled",
            "created_at": _iso(datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)),
            "last_run_at": "", "last_status": "", "last_output_file": "",
            "last_error": "", "last_delivery_error": "",
            "run_count": 0, "failure_streak": 0, "deliver": "local",
            "script": SCRIPT, "no_agent": True,
            "context_from": "", "workdir": "", "repeat": None,
        }
        jobs.append(job)
        CJ.save_jobs(jobs)
        return 0, {"ok": True, "action": "create", "id": job["id"], "script": SCRIPT}

    job = jobs[idx]
    drift = []
    if job.get("script") != SCRIPT:
        drift.append("script")
    if job.get("schedule") != sched:
        drift.append("schedule")
    if job.get("schedule_display") != SCHEDULE_EXPR:
        drift.append("schedule_display")
    if job.get("no_agent") is not True:
        drift.append("no_agent")
    if job.get("enabled") is not True:
        drift.append("enabled")
    if not drift:
        return 0, {"ok": True, "action": "none", "id": job.get("id"), "drift": []}
    if not apply:
        return 1, {"ok": False, "action": "update", "id": job.get("id"), "drift": drift}

    job["script"] = SCRIPT
    job["schedule_display"] = SCHEDULE_EXPR
    job["no_agent"] = True
    job["enabled"] = True
    if "schedule" in drift:
        job["schedule"] = sched
        job["next_run_at"] = _iso(CJ.compute_next_run(sched))
    CJ.save_jobs(jobs)
    return 0, {"ok": True, "action": "update", "id": job.get("id"), "drift": drift}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="审计署 4B tick 作业的可重建注册（幂等 seed）")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true", help="只读；缺失/漂移 rc=1")
    g.add_argument("--apply", action="store_true", help="写入（缺省行为）")
    ns = ap.parse_args(argv)
    rc, rep = ensure(apply=not ns.check)
    print(json.dumps(rep, ensure_ascii=False))
    return rc


if __name__ == "__main__":
    sys.exit(main())

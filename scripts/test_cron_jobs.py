"""test_cron_jobs.py — cron 作业台账（E2 / ECC-03BA0B44DF91）

现场（2026-09-18 沙箱实测）：`gatekeeper-cli.sh cron edit <id> schedule <expr>` 恒失败 ——
CLI 的 edit 分支把 `$value` 当**字符串**塞进 `schedule` 字段，`update_job` 随后
`compute_next_run(schedule)` 立刻 `AttributeError: 'str' object has no attribute 'get'`
⟹ rc=1、job 未改（fail-safe 但**定时表达式无法经 CLI 修改**）。

判据：`update_job(schedule=<expr 字符串>)` 须按 `parse_schedule` 归一为 dict；
非法表达式显式拒绝（不静默写坏账）；dict 形态保持原语义（向后兼容）。
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import cron_jobs


@pytest.fixture
def jobs_env(tmp_path, monkeypatch):
    """隔离作业台账（不触碰生产 `~/.gatekeeper/cron/jobs.json`）。"""
    p = tmp_path / "jobs.json"
    monkeypatch.setattr(cron_jobs, "JOBS_FILE", str(p))
    monkeypatch.setattr(cron_jobs, "_DEFAULT_JOBS_DIR", str(tmp_path))
    return p


@pytest.fixture
def job_id(jobs_env):
    r = cron_jobs.create_job("probe", "probe prompt", "0 18 * * *")
    assert r["ok"] is True, r
    return r["job"]["id"]


def test_seed_is_cron_kind(jobs_env, job_id):
    j = next(x for x in cron_jobs.load_jobs() if x["id"] == job_id)
    assert j["schedule"] == {"kind": "cron", "expr": "0 18 * * *"}


def test_update_job_schedule_accepts_expr_string(jobs_env, job_id):
    """E2 主判据：expr 字符串 → 归一为 {"kind":"cron","expr":...}（此前 AttributeError）。"""
    r = cron_jobs.update_job(job_id, schedule="49 18 * * *")
    assert r["ok"] is True, r
    assert r["job"]["schedule"] == {"kind": "cron", "expr": "49 18 * * *"}


def test_update_job_schedule_string_advances_next_run(jobs_env, job_id):
    before = next(x for x in cron_jobs.load_jobs() if x["id"] == job_id)["next_run_at"]
    r = cron_jobs.update_job(job_id, schedule="49 18 * * *")
    j = next(x for x in cron_jobs.load_jobs() if x["id"] == job_id)
    assert j["schedule"]["expr"] == "49 18 * * *"
    assert j["next_run_at"].endswith("18:49:00Z"), j["next_run_at"]   # 与 tick 相位对齐
    assert j["next_run_at"] != before                                 # 已按新表达式重算
    assert r["job"]["next_run_at"] == j["next_run_at"]


def test_update_job_schedule_interval_string(jobs_env, job_id):
    """`every 2h` 形态 → interval 语义（同一 parse_schedule 单源）。"""
    r = cron_jobs.update_job(job_id, schedule="every 2h")
    assert r["ok"] is True and r["job"]["schedule"] == {"kind": "interval", "minutes": 120}


def test_update_job_schedule_invalid_expr_rejected(jobs_env, job_id):
    """非法表达式 → 显式拒绝，且台账**未被改写**（不静默写坏账）。"""
    before = json.loads(jobs_env.read_text(encoding="utf-8"))
    r = cron_jobs.update_job(job_id, schedule="not a cron")
    assert r["ok"] is False and "invalid schedule" in r["error"]
    assert json.loads(jobs_env.read_text(encoding="utf-8")) == before


def test_update_job_schedule_dict_backward_compatible(jobs_env, job_id):
    r = cron_jobs.update_job(job_id, schedule={"kind": "cron", "expr": "30 4 * * *"})
    assert r["ok"] is True and r["job"]["schedule"]["expr"] == "30 4 * * *"


def test_update_job_schedule_bad_type_rejected(jobs_env, job_id):
    r = cron_jobs.update_job(job_id, schedule=12345)
    assert r["ok"] is False and "schedule" in r["error"]


def test_update_job_schedule_refreshes_display_string(jobs_env, job_id):
    """`schedule_display` 是派生字段 —— 改 schedule 后必须同步（否则台账自相矛盾）。

    实测现场（2026-09-18）：生产 `cron edit … schedule '49 18 * * *'` 后 `schedule.expr` 已变，
    但 `schedule_display` 仍是 `0 18 * * *`（陈旧展示值）。
    """
    cron_jobs.update_job(job_id, schedule="49 18 * * *")
    j = next(x for x in cron_jobs.load_jobs() if x["id"] == job_id)
    assert j["schedule_display"] == "49 18 * * *"


def test_update_job_schedule_refreshes_display_dict(jobs_env, job_id):
    """dict 形态（无原始输入串可回显）→ 按 kind 派生（cron = expr）。"""
    cron_jobs.update_job(job_id, schedule={"kind": "cron", "expr": "30 4 * * *"})
    j = next(x for x in cron_jobs.load_jobs() if x["id"] == job_id)
    assert j["schedule_display"] == "30 4 * * *"


def test_update_job_non_schedule_field_leaves_display_intact(jobs_env, job_id):
    """非 schedule 字段更新不得动 display（防误改展示语义）。"""
    before = next(x for x in cron_jobs.load_jobs() if x["id"] == job_id)["schedule_display"]
    cron_jobs.update_job(job_id, deliver="local")
    j = next(x for x in cron_jobs.load_jobs() if x["id"] == job_id)
    assert j["schedule_display"] == before


class TestJobsChecksumSidecarIsolation:
    """sidecar 必须与 JOBS_FILE **同源**（2026-09-20 实测缺陷，非推测）。

    现场：`_JOBS_CHECKSUM_FILE` 原为**导入期常量**（= 默认 jobs.json + ".sha256"），而本文件的
    `jobs_env` 夹具只 monkeypatch 了 `JOBS_FILE` ⟹ `save_jobs` 把**临时 jobs.json 的哈希写进
    生产 sidecar**，生产 jobs.json 本身却没动 ⟹ 下一次真跑必报
    `checksum mismatch (tampered?) expected=<临时文件哈希> actual=<真文件哈希>`。

    端到端实测（跑一次本文件前后比对生产文件）：
      before: actual=1edbf71b8360 sidecar=1edbf71b8360 一致=True
      after : actual=1edbf71b8360 sidecar=7ff7e390d7c2 一致=False（jobs.json 未动、sidecar 被改）
    ⟹ 报警里的 `expected` 指向一个**已被 pytest 回收的临时文件**的哈希，故凭值无法定位，
    与用户报的 `expected=cb0a38c7c853 actual=5c004883c211` 同型。
    """

    def test_sidecar_written_next_to_jobs_file(self, jobs_env):
        """修复前红：sidecar 被写到导入期常量指向的默认路径，而不是 jobs.json 旁边。"""
        cron_jobs.save_jobs([{"id": "b" * 12, "enabled": True}])
        side = Path(str(jobs_env) + ".sha256")
        assert side.exists(), "sidecar 未写在 jobs.json 旁边（写到了导入期常量指向的路径）"
        assert side.read_text().strip() == cron_jobs._jobs_checksum(str(jobs_env))

    def test_default_sidecar_untouched(self, jobs_env, tmp_path, monkeypatch):
        """修复前红：save_jobs 不得触碰「默认路径」那个 sidecar（它是生产文件）。"""
        sentinel = tmp_path / "prod-sidecar.sha256"
        sentinel.write_text("SENTINEL\n")
        monkeypatch.setattr(cron_jobs, "_JOBS_CHECKSUM_FILE", str(sentinel), raising=False)
        cron_jobs.save_jobs([{"id": "c" * 12, "enabled": True}])
        assert sentinel.read_text().strip() == "SENTINEL", \
            "save_jobs 仍把校验和写进默认路径的 sidecar（跨用例污染生产台账）"

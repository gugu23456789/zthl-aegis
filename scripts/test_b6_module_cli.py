"""B6（RED-MIGRATE-INLINE）：模块自有 CLI 契约测试。

红先顺序：先让这些用例失败（`status/get/prompt/edit` 与三个模块的 `__main__` 尚不存在），
再用模块侧实现转绿 —— 避免「先写实现再补测试」的假绿。
"""
import json
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).parent
sys.path.insert(0, str(SCRIPTS))


def _run(script, args):
    return subprocess.run([sys.executable, str(SCRIPTS / script)] + args,
                          capture_output=True, text=True, encoding="utf-8")


class TestCronCli:
    """`cron_jobs.py` 的只读/失败面动词（不触真 jobs 文件）。"""

    def test_status_json(self):
        p = _run("cron_jobs.py", ["status"])
        assert p.returncode == 0, p
        d = json.loads(p.stdout)
        assert d["ok"] is True and "jobs" in d and "total" in d, d

    def test_get_unknown_id_prints_nothing(self):
        p = _run("cron_jobs.py", ["get", "no-such-job-zzz"])
        assert p.returncode == 0 and p.stdout == "", p

    def test_prompt_unknown_id_prints_empty_line(self):
        p = _run("cron_jobs.py", ["prompt", "no-such-job-zzz"])
        assert p.returncode == 0 and p.stdout == "\n", p

    def test_edit_unknown_ref(self):
        p = _run("cron_jobs.py", ["edit", "no-such-job-zzz", "schedule", "0 9 * * *"])
        assert json.loads(p.stdout) == {"ok": False, "error": "Job not found"}, p


class TestModuleCli:
    def test_suba_max_tier(self):
        from gk_suba_tiers import SUBA_TIERS
        p = _run("gk_suba_tiers.py", ["max-tier"])
        assert p.returncode == 0 and p.stdout.strip() == str(max(SUBA_TIERS)), p

    def test_evidence_summarize_egress(self, tmp_path):
        f = tmp_path / "egress.jsonl"
        f.write_text("", encoding="utf-8")
        p = _run("gk_evidence.py", ["summarize-egress", "--path", str(f)])
        assert p.returncode == 0 and isinstance(json.loads(p.stdout), dict), p

    def test_satellite_reclaim_missing_state(self, tmp_path):
        p = _run("gk_satellite.py", ["reclaim", "--state",
                                     str(tmp_path / "none.json"), "--dry-run"])
        assert p.returncode == 0 and isinstance(json.loads(p.stdout), dict), p

    def test_satellite_backfill_missing_state(self, tmp_path):
        p = _run("gk_satellite.py", ["backfill-ttl", "--state",
                                     str(tmp_path / "none.json"), "--dry-run"])
        assert p.returncode == 0 and isinstance(json.loads(p.stdout), dict), p

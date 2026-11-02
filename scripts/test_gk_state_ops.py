#!/usr/bin/env python3
"""test_gk_state_ops.py — B10d：reflect / resolve 两处 state 语义写。

⚠ 两站按**旧内联原语义**迁移：裸 `json.dump` 覆盖写，**不持 state_lock、
不重算 `_checksum`**（与同目录 `update_state` 的有锁增量路径不同）。
本测试即锁定这一形态，防止后续「顺手改成 update_state」造成行为漂移。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

CLI = Path(__file__).parent / "gk_state_ops.py"


def _run(*args, env=None):
    e = os.environ.copy()
    if env:
        e.update(env)
    return subprocess.run([sys.executable, str(CLI)] + list(args),
                          input="", capture_output=True, text=True,
                          encoding="utf-8", env=e)


class TestReflectPersist:
    def _state(self, tmp_path, obj):
        sf = tmp_path / "s.json"
        sf.write_text(json.dumps(obj), encoding="utf-8")
        return str(sf)

    def test_json_guidance(self, tmp_path):
        st = self._state(tmp_path, {"stage": "R5", "gate_data": {"edit_count": 3},
                                    "keep": True})
        p = _run("reflect-persist", st, "R5", "2026-10-28T10:00:00Z",
                 env={"REFLECT_GUIDANCE": '{"pattern": "repeat"}'})
        assert p.returncode == 0, p
        d = json.loads(Path(st).read_text(encoding="utf-8"))
        assert d["gate_data"]["rejected_patterns"] == {
            "stage": "R5", "analysis": {"pattern": "repeat"},
            "timestamp": "2026-10-28T10:00:00Z", "source": "cmd_reflect"}
        assert d["gate_data"]["needs_analysis"] is False
        assert d["gate_data"]["edit_count"] == 3 and d["keep"] is True
        # 旧式 indent=1 形态
        assert Path(st).read_text(encoding="utf-8").startswith('{\n "')

    def test_non_json_guidance_kept_raw(self, tmp_path):
        st = self._state(tmp_path, {})
        _run("reflect-persist", st, "S", "T", env={"REFLECT_GUIDANCE": "自由文本"})
        d = json.loads(Path(st).read_text(encoding="utf-8"))
        assert d["gate_data"]["rejected_patterns"]["analysis"] == {"text": "自由文本"}

    def test_missing_state_nonzero(self, tmp_path):
        st = str(tmp_path / "no.json")
        p = _run("reflect-persist", st, "S", "T", env={"REFLECT_GUIDANCE": "x"})
        assert p.returncode != 0 and not Path(st).exists()


class TestResolveRecord:
    def _state(self, tmp_path, obj):
        sf = tmp_path / "s.json"
        sf.write_text(json.dumps(obj), encoding="utf-8")
        return str(sf)

    def _reason(self, tmp_path, text):
        rf = tmp_path / "reason.txt"
        rf.write_text(text, encoding="utf-8")
        return str(rf)

    def test_escalate_source(self, tmp_path):
        st = self._state(tmp_path, {"human_resolutions": {"OLD": {"gate": "OLD"}}})
        rf = self._reason(tmp_path, "line1\nline2\n")
        p = _run("resolve-record", st, "G-17", "fix", rf)
        assert p.returncode == 0, p
        out = json.loads(p.stdout)
        assert out["ok"] is True and out["resolution"]["gate"] == "G-17"
        d = json.loads(Path(st).read_text(encoding="utf-8"))
        rec = d["human_resolutions"]["G-17"]
        assert rec["source"] == "escalate" and rec["resolution"] == "fix"
        assert rec["reason"] == "line1\nline2\n"
        assert rec["resolved_at"].endswith("Z")
        assert d["human_resolutions"]["OLD"] == {"gate": "OLD"}

    def test_appeal_source(self, tmp_path):
        st = self._state(tmp_path, {"appeal_records": {"G-9": {}}})
        rf = self._reason(tmp_path, "ok")
        p = _run("resolve-record", st, "G-9", "force_advance", rf)
        assert p.returncode == 0, p
        d = json.loads(Path(st).read_text(encoding="utf-8"))
        assert d["human_resolutions"]["G-9"]["source"] == "appeal"

    def test_missing_reason_nonzero(self, tmp_path):
        st = self._state(tmp_path, {})
        p = _run("resolve-record", st, "G", "fix", str(tmp_path / "no.txt"))
        assert p.returncode != 0
        assert json.loads(Path(st).read_text(encoding="utf-8")) == {}

    def test_missing_state_nonzero(self, tmp_path):
        rf = self._reason(tmp_path, "r")
        assert _run("resolve-record", str(tmp_path / "no.json"), "G", "fix",
                    rf).returncode != 0


class TestCrossfullCopy:
    """B10e：crossfull 隔离副本 state（写副本，父 state 只读由 shell 侧断言保证）。"""

    def _src(self, tmp_path, obj=None, raw=None):
        sf = tmp_path / "src.json"
        sf.write_text(raw if raw is not None else json.dumps(obj), encoding="utf-8")
        return str(sf)

    def test_standing_stage(self, tmp_path):
        src = self._src(tmp_path, {"stage": "R5", "gate_data": {
            "project_type": "standing"}, "keep": 1})
        dst = str(tmp_path / "dst.json")
        p = _run("crossfull-copy", src, dst, "/wt/x")
        assert p.returncode == 0, p
        d = json.loads(Path(dst).read_text(encoding="utf-8"))
        assert d["stage"] == "ECO-AUDIT"
        assert d["worktree"] == "/wt/x" and d["branch"] == "dryrun/crossfull"
        assert d["gate_data"]["project_type"] == "standing" and d["keep"] == 1
        assert Path(dst).read_text(encoding="utf-8").startswith('{\n "'), "indent=1"

    def test_non_standing_stage(self, tmp_path):
        src = self._src(tmp_path, {"gate_data": {"project_type": "service"}})
        dst = str(tmp_path / "dst.json")
        assert _run("crossfull-copy", src, dst, "").returncode == 0
        d = json.loads(Path(dst).read_text(encoding="utf-8"))
        assert d["stage"] == "AUDIT-CROSSR"
        assert "worktree" not in d and "branch" not in d

    def test_missing_source_yields_minimal(self, tmp_path):
        dst = str(tmp_path / "dst.json")
        p = _run("crossfull-copy", str(tmp_path / "no.json"), dst, "/w")
        assert p.returncode == 0, p
        d = json.loads(Path(dst).read_text(encoding="utf-8"))
        assert d == {"worktree": "/w", "branch": "dryrun/crossfull",
                     "stage": "AUDIT-CROSSR"}

    def test_bad_source_yields_minimal(self, tmp_path):
        src = self._src(tmp_path, raw="{broken")
        dst = str(tmp_path / "dst.json")
        assert _run("crossfull-copy", src, dst, "").returncode == 0
        assert json.loads(Path(dst).read_text(encoding="utf-8")) == {"stage": "AUDIT-CROSSR"}

    def test_unwritable_dst_swallowed(self, tmp_path):
        """旧式写盘 `except: pass` ⟹ 失败也 rc=0（调用方另有 P0-2 断言兜底）。"""
        src = self._src(tmp_path, {})
        p = _run("crossfull-copy", src, str(tmp_path / "no" / "d" / "x.json"), "/w")
        assert p.returncode == 0

    def test_non_dict_source_nonzero(self, tmp_path):
        """源根为 list 时旧式 `d.get` 抛 AttributeError ⟹ rc≠0（shell 侧 `|| true`）。"""
        src = self._src(tmp_path, raw="[1,2]")
        assert _run("crossfull-copy", src, str(tmp_path / "d.json"), "").returncode != 0


class TestDiscoverScheduler:
    """B10f：discover 内 scheduler/project_type/target_repo 落库（`_read_state` 读侧）。"""

    def _state(self, tmp_path, obj):
        sf = tmp_path / "s.json"
        sf.write_text(json.dumps(obj), encoding="utf-8")
        return str(sf)

    def test_writes_all_fields(self, tmp_path):
        st = self._state(tmp_path, {"stage": "R5", "gate_data": {"keep": 1}})
        p = _run("discover-scheduler", st, "cosine", "0.001", "0.0001", "1000",
                 "standing", "0", "/repo/x")
        assert p.returncode == 0, p
        d = json.loads(Path(st).read_text(encoding="utf-8"))
        assert d["gate_data"]["scheduler"] == {
            "mode": "cosine", "max_lr": 0.001, "min_lr": 0.0001,
            "total_steps": 1000, "current_step": 0, "current_lr": 0.001}
        assert d["gate_data"]["project_type"] == "standing"
        assert d["gate_data"]["last_release_check"] == 0
        assert d["gate_data"]["keep"] == 1
        assert d["target_repo"] == "/repo/x"

    def test_scientific_notation(self, tmp_path):
        st = self._state(tmp_path, {"gate_data": {}})
        assert _run("discover-scheduler", st, "linear", "1e-3", "1e-4", "10",
                    "service", "7", "").returncode == 0
        d = json.loads(Path(st).read_text(encoding="utf-8"))
        assert d["gate_data"]["scheduler"]["max_lr"] == 0.001
        assert d["gate_data"]["scheduler"]["total_steps"] == 10
        assert d["target_repo"] == ""

    def test_checksum_warning_stripped(self, tmp_path):
        sf = tmp_path / "s.json"
        sf.write_text(json.dumps({"gate_data": {}, "_checksum": "deadbeef"}),
                      encoding="utf-8")
        assert _run("discover-scheduler", sf and str(sf), "m", "1", "0.5", "0", "s",
                    "0", "").returncode == 0
        d = json.loads(Path(sf).read_text(encoding="utf-8"))
        assert "_checksum_warning" not in d

    def test_missing_gate_data_nonzero(self, tmp_path):
        st = self._state(tmp_path, {"stage": "R5"})
        p = _run("discover-scheduler", st, "m", "1", "0.5", "0", "s", "0", "")
        assert p.returncode != 0
        assert json.loads(Path(st).read_text(encoding="utf-8")) == {"stage": "R5"}

    def test_missing_state_nonzero(self, tmp_path):
        assert _run("discover-scheduler", str(tmp_path / "no.json"), "m", "1", "0.5",
                    "0", "s", "0", "").returncode != 0


class TestReleaseCheckRecord:
    """B10f：release-check 回写（setdefault 保留既有时间戳；坏 JSON ⟹ raw 保留）。"""

    def _state(self, tmp_path, obj):
        sf = tmp_path / "s.json"
        sf.write_text(json.dumps(obj), encoding="utf-8")
        return str(sf)

    def test_parse_ok(self, tmp_path):
        st = self._state(tmp_path, {"gate_data": {"last_release_check": 111}})
        p = _run("release-check-record", st,
                 env={"RC_OUT": '{"projects": 8}'})
        assert p.returncode == 0, p
        d = json.loads(Path(st).read_text(encoding="utf-8"))
        assert d["gate_data"]["last_release_check"] == 111
        assert d["gate_data"]["_latest_release_check"] == {"projects": 8}

    def test_default_timestamp_when_missing(self, tmp_path):
        import time
        st = self._state(tmp_path, {"gate_data": {}})
        _run("release-check-record", st, env={"RC_OUT": "{}"})
        d = json.loads(Path(st).read_text(encoding="utf-8"))
        assert abs(d["gate_data"]["last_release_check"] - time.time()) < 60

    def test_bad_json_kept_raw(self, tmp_path):
        st = self._state(tmp_path, {"gate_data": {}})
        p = _run("release-check-record", st, env={"RC_OUT": "x" * 800})
        assert p.returncode == 0, p
        d = json.loads(Path(st).read_text(encoding="utf-8"))
        assert d["gate_data"]["_latest_release_check"] == {"raw": "x" * 500}
        assert "[F-REV-20]" in p.stderr

    def test_missing_state_creates(self, tmp_path):
        st = str(tmp_path / "new.json")
        assert _run("release-check-record", st, env={"RC_OUT": "{}"}).returncode == 0
        assert "_latest_release_check" in json.loads(
            Path(st).read_text(encoding="utf-8"))["gate_data"]

    def test_bad_state_nonzero(self, tmp_path):
        sf = tmp_path / "bad.json"
        sf.write_text("{broken", encoding="utf-8")
        assert _run("release-check-record", str(sf),
                    env={"RC_OUT": "{}"}).returncode != 0


def test_usage_exit_2():
    assert _run().returncode == 2
    assert _run("nope").returncode == 2

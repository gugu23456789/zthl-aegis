#!/usr/bin/env python3
"""test_gk_state_ops.py — B10d：reflect / resolve 两处 state 语义写。

2026-11-02 起五站统一走 `gk_json_utils` 单源写面：
  · 已存在 state ⟹ `update_state`（锁内 RMW + 原子替换 + 重算 `_checksum`）；
  · `crossfull-copy` ⟹ `write_json_file` 原子写副本；
  · `release-check-record` 缺文件 ⟹ 先原子建空 state。
本测试锁定新契约（尤其是 `_checksum` 必须重算、写失败必须 fail-loud）。
"""
import hashlib
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

    def test_checksum_recomputed(self, tmp_path):
        """写后 `_checksum` 必须与 gate_data canon 一致（旧裸写会留下过期 checksum）。"""
        st = self._state(tmp_path, {"gate_data": {}, "_checksum": "deadbeef"})
        p = _run("reflect-persist", st, "S", "T", env={"REFLECT_GUIDANCE": "{}"})
        assert p.returncode == 0, p
        d = json.loads(Path(st).read_text(encoding="utf-8"))
        gate_dump = json.dumps(d["gate_data"], sort_keys=True, ensure_ascii=True)
        assert d["_checksum"] == hashlib.sha256(gate_dump.encode()).hexdigest()[:16]
        assert "_checksum_warning" not in d


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

    def test_concurrent_resolve_keeps_all_gates(self, tmp_path):
        """并发多进程各写不同 gate ⟹ 锁内 RMW 必须全部保留（旧裸写会丢更新）。"""
        st = self._state(tmp_path, {"human_resolutions": {}})
        rf = self._reason(tmp_path, "r")
        gates = ["G1", "G2", "G3", "G4"]
        ps = [subprocess.Popen([sys.executable, str(CLI), "resolve-record", st,
                                gate, "fix", rf],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
              for gate in gates]
        for p in ps:
            out, err = p.communicate()
            assert p.returncode == 0, (out, err)
        d = json.loads(Path(st).read_text(encoding="utf-8"))
        assert set(d["human_resolutions"]) == set(gates)


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
        # 72b95bca（A4 站名归一）已把 standing 副本改到 ECO-VERIFY；旧断言未同步。
        assert d["stage"] == "ECO-VERIFY"
        assert d["worktree"] == "/wt/x" and d["branch"] == "dryrun/crossfull"
        assert d["gate_data"]["project_type"] == "standing" and d["keep"] == 1
        assert len(d["_checksum"]) == 16, "副本必须重算 checksum"
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
        checksum = d.pop("_checksum")
        assert len(checksum) == 16
        assert d == {"worktree": "/w", "branch": "dryrun/crossfull",
                     "stage": "AUDIT-CROSSR"}

    def test_bad_source_yields_minimal(self, tmp_path):
        src = self._src(tmp_path, raw="{broken")
        dst = str(tmp_path / "dst.json")
        assert _run("crossfull-copy", src, dst, "").returncode == 0
        d = json.loads(Path(dst).read_text(encoding="utf-8"))
        checksum = d.pop("_checksum")
        assert len(checksum) == 16
        assert d == {"stage": "AUDIT-CROSSR"}

    def test_unwritable_dst_fails_loud(self, tmp_path):
        """原子写失败必须 fail-loud（旧实现 `except: pass` 会把没写成报成成功）。"""
        src = self._src(tmp_path, {})
        blocker = tmp_path / "blocker"
        blocker.write_text("not a dir", encoding="utf-8")
        p = _run("crossfull-copy", src, str(blocker / "x.json"), "/w")
        assert p.returncode != 0
        assert "[ERROR] crossfull-copy write failed" in p.stderr

    def test_non_dict_source_nonzero(self, tmp_path):
        """源根为 list 时旧式 `d.get` 抛 AttributeError ⟹ rc≠0（shell 侧 `|| true`）。"""
        src = self._src(tmp_path, raw="[1,2]")
        assert _run("crossfull-copy", src, str(tmp_path / "d.json"), "").returncode != 0

    def test_copies_sidecar(self, tmp_path):
        """副本须带上冷索引侧车（否则冷叶丢失 = 读分裂）。"""
        src = self._src(tmp_path, {"gate_data": {}})
        dst = str(tmp_path / "dst.json")
        with open(src + ".satellite-index.jsonl", "w", encoding="utf-8") as f:
            f.write(json.dumps({"op": "put", "batch_id": "b", "arm": "A",
                                "leaf": {"kind": "pipeline"}}) + "\n")
        assert _run("crossfull-copy", src, dst, "").returncode == 0
        assert Path(dst + ".satellite-index.jsonl").is_file()

    def test_removes_stale_sidecar(self, tmp_path):
        """源无侧车 ⟹ 目标残留侧车须清掉（防陈旧冷叶混入）。"""
        src = self._src(tmp_path, {"gate_data": {}})
        dst = str(tmp_path / "dst.json")
        Path(dst + ".satellite-index.jsonl").write_text("stale\n", encoding="utf-8")
        assert _run("crossfull-copy", src, dst, "").returncode == 0
        assert not Path(dst + ".satellite-index.jsonl").exists()


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

#!/usr/bin/env python3
"""红队运行时攻防 · 沙盘**元测试**（E1–E6；408 方案 §7）。

**红先对照**：E1/E3/E4 首轮实现前 `scripts/red_runtime/runner.py` 不存在（ImportError）；
E2/E5/E6 二轮实现前 `run_scenarios` / `recover` / `discard` 不存在（AttributeError）。

元测试锁的是**元层不变量**（先于任何攻击场景，防"场景很花哨但沙箱是假的"）：

  · **E1 限额有效性**：超内存 / 超时的步骤必须**被限额杀掉**（rc≠0 / timed_out），
    且被杀后**无残留子进程**（防"测试把宿主拖死"）。
  · **E2 并发上限**：多场景并行时**子在跑数 ≤ max_parallel**，且**确有并行**（防退化成串行假绿）；
    跑完零残留。并发是无界 OOM 的唯一入口（`gk_hub_scheduler` 文档实测 300 路压测）。
  · **E3 隔离性**：跑完一个场景后**受保护的真实件逐字节不变**（sha256 前后比对）；
    沙盘根不得落在 `/mnt/c`（drvfs / 9p，本会话实测一次 rmtree 让进程 `D` 状态 14 分钟）。
  · **E4 守卫臂（判别力自证）**：同一判定器对「无副作用」给 PASS、对「真违反不变量」给 FAIL
    —— 防判定器恒真（PW-5）。
  · **E5 崩溃恢复**：跑手被 `SIGKILL` 时**已 fsync 的步骤证据仍在**（`recover` 可数），
    半写尾行不得污染；同根**重跑仍拒**（append-only），`discard` 后可在原根重建。
  · **E6 反噬臂（污染不外溢）**：预置伪造 `state.json` / `claims.jsonl` 的根**不得**把毒带进
    受保护真实件；`discard` 可把毒件归档清场，原根恢复可用。

六条都**只用 tmp 沙盘**，不碰真实 state / 账本 / worktree。
"""
import hashlib
import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from red_runtime import runner  # noqa: E402  （红先：模块不存在 ⟹ ImportError）

LIM = {"mem_mb": 256, "timeout_s": 30, "max_proc": 2}


def _sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def _scn(steps, sid="t-meta"):
    return {"id": sid, "kind": "runtime", "steps": steps}


# ── E1 限额有效性 ────────────────────────────────────────────────────────────
class TestE1LimitEnforcement:
    def test_memory_limit_kills_allocation(self, tmp_path):
        """`mem_mb=128` 下的 512MB 分配必须失败（rc≠0），而不是把宿主吃满。"""
        step = {"argv": [sys.executable, "-c", "b = b'x' * (512 * 1024 * 1024)"],
                "invariant": {"kind": "exit_nonzero"}}
        rep = runner.run_scenario(_scn([step]), root=str(tmp_path / "run"),
                                  limits={"mem_mb": 128, "timeout_s": 30, "max_proc": 2})
        st = rep["steps"][0]
        assert st["sandbox"]["enforced"] is True, st
        assert st["rc"] not in (0, None), f"内存上限未生效：rc={st['rc']}"
        assert rep["verdict"] == "PASS", rep

    def test_timeout_killed_and_no_leftover_process(self, tmp_path):
        """`timeout_s=1` 下的 30s 睡眠必须被杀（timed_out），且进程表里**不留残余**。"""
        marker = "GK_RED_RUNTIME_LEFTOVER_" + uuid.uuid4().hex
        code = ("import sys, time\n"
                "sys.argv = ['x', %r]\n"
                "time.sleep(30)\n" % marker)
        step = {"argv": [sys.executable, "-c", code],
                "invariant": {"kind": "timed_out"}}
        rep = runner.run_scenario(_scn([step]), root=str(tmp_path / "run"),
                                  limits={"mem_mb": 256, "timeout_s": 1, "max_proc": 2})
        st = rep["steps"][0]
        assert st["sandbox"]["timed_out"] is True, st
        assert st["rc"] == -1, st
        ps = subprocess.run(["ps", "-eo", "args"], capture_output=True, text=True).stdout
        assert marker not in ps, "超时被杀后仍有残留子进程（沙箱未收口）"
        assert rep["verdict"] == "PASS", rep


# ── E3 隔离性 ────────────────────────────────────────────────────────────────
class TestE3Isolation:
    def test_protected_real_artifacts_unchanged(self, tmp_path):
        """攻击步改写 `STATE_FILE` 时，**真实受保护件**必须逐字节不变；且注入的 STATE_FILE 在沙盘内。"""
        real = tmp_path / "real"
        real.mkdir()
        state = real / "state.json"
        ledger = real / "ledger.jsonl"
        state.write_text('{"stage": "R4", "gate_data": {}}', encoding="utf-8")
        ledger.write_text('{"seq": 1, "amount": 10}\n', encoding="utf-8")
        before = {str(p): _sha(p) for p in (state, ledger)}

        code = ("import os, pathlib\n"
                "pathlib.Path(os.environ['STATE_FILE']).write_text('pwn')\n")
        step = {"argv": [sys.executable, "-c", code],
                "invariant": {"kind": "exit_zero"}}
        rep = runner.run_scenario(_scn([step]), root=str(tmp_path / "run"),
                                  limits=LIM, protected=[str(state), str(ledger)])
        assert rep["verdict"] == "PASS", rep
        assert rep["protected_unchanged"] is True, rep
        after = {str(p): _sha(p) for p in (state, ledger)}
        assert after == before, "真实受保护件被改写（沙盘没隔离住）"
        st = rep["steps"][0]
        assert str(st["env"]["STATE_FILE"]).startswith(str(tmp_path / "run")), st["env"]

    def test_drvfs_root_refused(self, tmp_path):
        """沙盘根落在 `/mnt/c`（drvfs / 9p）必须**拒跑** —— 本会话实测该 FS 上单次 rmtree 可 `D` 14 分钟。"""
        with pytest.raises(ValueError):
            runner.run_scenario(_scn([{"argv": [sys.executable, "-c", "pass"],
                                      "invariant": {"kind": "exit_zero"}}]),
                                root="<home>/.trae/red-runtime-should-refuse",
                                limits=LIM)


# ── E4 守卫臂（判别力自证）──────────────────────────────────────────────────
class TestE4GuardArmDiscriminant:
    def test_guard_arm_passes(self, tmp_path):
        """守卫臂：无副作用的步骤 + 「文件应不存在」不变量 ⟹ PASS（正常流零影响）。"""
        step = {"argv": [sys.executable, "-c", "pass"],
                "invariant": {"kind": "file_absent", "path": "leak.txt"}}
        rep = runner.run_scenario(_scn([step]), root=str(tmp_path / "run"), limits=LIM)
        assert rep["verdict"] == "PASS", rep
        assert not rep["steps"][0]["violations"], rep

    def test_discriminant_fails_on_real_violation(self, tmp_path):
        """判别力：**真的**写出 `leak.txt` ⟹ 必须 FAIL（防判定器恒真）。"""
        code = "open('leak.txt', 'w').write('x')"
        step = {"argv": [sys.executable, "-c", code],
                "invariant": {"kind": "file_absent", "path": "leak.txt"}}
        rep = runner.run_scenario(_scn([step]), root=str(tmp_path / "run"), limits=LIM)
        assert rep["verdict"] == "FAIL", rep
        assert rep["steps"][0]["violations"], "违反不变量却零 violation（判定恒真）"


# ── 公共夹具：带唯一 marker 的子进程（可数 / 可清）────────────────────────────
def _marker_argv(marker, sleep_s=0.0, mb=0):
    code = ("import sys, time\n"
            "sys.argv = ['x', %r]\n" % marker)
    if mb:
        code += "b = b'x' * (%d * 1024 * 1024)\n" % mb
    if sleep_s:
        code += "time.sleep(%r)\n" % sleep_s
    return [sys.executable, "-c", code]


def _marked_pids(marker):
    hits = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open("/proc/%s/cmdline" % pid, "rb") as f:
                if marker.encode() in f.read():
                    hits.append(int(pid))
        except OSError:
            continue
    return hits


def _kill_marked(marker):
    for pid in _marked_pids(marker):
        try:
            os.kill(pid, 9)
        except OSError:
            pass


# ── E2 并发上限 ─────────────────────────────────────────────────────────────
class TestE2BoundedParallelism:
    def test_parallel_runs_capped_and_actually_parallel(self, tmp_path):
        """6 场景 × `max_parallel=3`：子在跑数峰值 ≤3、且 ≥2（防串行假绿）、跑完零残留。"""
        marker = "GK_E2_" + uuid.uuid4().hex
        scns = [{"id": "p%d" % i, "kind": "runtime",
                 "steps": [{"argv": _marker_argv(marker, sleep_s=0.9, mb=32),
                            "invariant": {"kind": "exit_zero"}}]}
                for i in range(6)]
        peak = {"n": 0}
        stop = threading.Event()

        def _sample():
            while not stop.is_set():
                peak["n"] = max(peak["n"], len(_marked_pids(marker)))
                time.sleep(0.05)

        th = threading.Thread(target=_sample, daemon=True)
        th.start()
        try:
            reps = runner.run_scenarios(scns, root_base=str(tmp_path / "runs"), max_parallel=3,
                                        limits={"mem_mb": 128, "timeout_s": 30, "max_proc": 2})
        finally:
            stop.set()
            th.join(timeout=3)
            _kill_marked(marker)
        assert len(reps) == 6 and all(r["verdict"] == "PASS" for r in reps), reps
        assert peak["n"] <= 3, "并发越过上限（峰值 %d > 3）" % peak["n"]
        assert peak["n"] >= 2, "并发退化成串行（峰值 %d）⟹ 并发面无效" % peak["n"]
        assert not _marked_pids(marker), "并行跑完仍有残留子进程"

    def test_parallel_cap_is_hard_rejected(self, tmp_path):
        """超硬上限（`MAX_PARALLEL_CAP`）⟹ **拒跑**而非静默降级。"""
        with pytest.raises(ValueError):
            runner.run_scenarios([{"id": "x", "steps": []}], root_base=str(tmp_path / "r"),
                                 max_parallel=runner.MAX_PARALLEL_CAP + 1)


# ── E5 崩溃恢复 ─────────────────────────────────────────────────────────────
class TestE5CrashRecovery:
    def test_killed_runner_keeps_fsynced_evidence_and_recovers(self, tmp_path):
        """第 2 步长睡时 `SIGKILL` 跑手：第 1 步证据必须仍在；同根重跑仍拒；`discard` 后可重建。"""
        root = tmp_path / "run"
        real = tmp_path / "real"
        real.mkdir()
        st = real / "state.json"
        st.write_text('{"stage": "R3"}', encoding="utf-8")
        before = _sha(st)
        marker = "GK_E5_" + uuid.uuid4().hex

        driver = (
            "import sys\n"
            "sys.path.insert(0, %r)\n"
            "from red_runtime import runner\n"
            "runner.run_scenario({'id': 'crash', 'kind': 'runtime', 'steps': [\n"
            "  {'argv': [sys.executable, '-c', 'pass'], 'invariant': {'kind': 'exit_zero'}},\n"
            "  {'argv': %r, 'invariant': {'kind': 'exit_zero'}}]},\n"
            " root=%r, limits={'mem_mb': 256, 'timeout_s': 60, 'max_proc': 2}, protected=[%r])\n"
            % (str(Path(__file__).parent), _marker_argv(marker, sleep_s=30), str(root), str(st)))
        p = subprocess.Popen([sys.executable, "-c", driver])
        ev = root / "evidence.jsonl"
        try:
            deadline = time.time() + 30
            while time.time() < deadline:
                if ev.exists() and ev.read_text(encoding="utf-8").strip():
                    break
                time.sleep(0.05)
            p.kill()
            p.wait(timeout=10)
            rec = runner.recover(str(root))
            assert rec["completed"] == 1, rec
            assert rec["steps"][0]["index"] == 0, rec
            assert _sha(st) == before, "崩溃前真实受保护件已被改动"
            with pytest.raises(FileExistsError):
                runner.run_scenario(_scn([{"argv": [sys.executable, "-c", "pass"],
                                           "invariant": {"kind": "exit_zero"}}]),
                                    root=str(root), limits=LIM)
            d = runner.discard(str(root))
            assert d["ok"] and d["archived"], d
            assert all(os.path.exists(x) for x in d["archived"]), d
            rep = runner.run_scenario(_scn([{"argv": [sys.executable, "-c", "pass"],
                                             "invariant": {"kind": "exit_zero"}}]),
                                      root=str(root), limits=LIM)
            assert rep["verdict"] == "PASS", rep
        finally:
            _kill_marked(marker)


# ── E6 反噬臂：污染不外溢、可清场 ───────────────────────────────────────────
class TestE6PoisonContainment:
    def test_prepoisoned_root_cannot_leak_into_protected(self, tmp_path):
        """预置伪造 state/claims 的沙盘根：攻击步改写它们 ⟹ 真实受保护件不变；`discard` 清场后可重建。"""
        root = tmp_path / "run"
        root.mkdir()
        (root / "state.json").write_text('{"stage": "R4", "credit": 999999}', encoding="utf-8")
        (root / "claims.jsonl").write_text('{"sid": "evil", "state": "live"}\n', encoding="utf-8")
        real = tmp_path / "real"
        real.mkdir()
        st = real / "state.json"
        st.write_text('{"stage": "R3"}', encoding="utf-8")
        before = _sha(st)

        code = ("import os, pathlib\n"
                "pathlib.Path(os.environ['STATE_FILE']).write_text('{\"stage\": \"R4\", \"credit\": 999999}')\n"
                "pathlib.Path(os.environ['GK_WRITE_CLAIMS_PATH']).write_text('{\"sid\": \"evil\"}\\n')\n")
        rep = runner.run_scenario(_scn([{"argv": [sys.executable, "-c", code],
                                         "invariant": {"kind": "exit_zero"}}]),
                                  root=str(root), limits=LIM, protected=[str(st)])
        assert rep["verdict"] == "PASS", rep
        assert rep["protected_unchanged"] is True, rep
        assert _sha(st) == before, "伪造 state 被写进了真实受保护件（污染外溢）"
        d = runner.discard(str(root))
        assert d["ok"] and d["archived"], d
        assert any("state.json" in x for x in d["archived"]), d
        rep2 = runner.run_scenario(_scn([{"argv": [sys.executable, "-c", "pass"],
                                          "invariant": {"kind": "exit_zero"}}]),
                                   root=str(root), limits=LIM)
        assert rep2["verdict"] == "PASS", rep2

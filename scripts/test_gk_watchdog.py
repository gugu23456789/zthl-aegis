#!/usr/bin/env python3
"""test_gk_watchdog.py — 最小看门狗的三闸判定与整树击杀（2026-11-09）。

纪律：只测**行为**（退出码 + 子进程确实死掉），运行总时长 < 10s；内存闸用纯函数判定，
不伪造系统读数（跨进程无法 monkeypatch）。
"""
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_watchdog as wd  # noqa: E402


# ── 纯函数：三闸优先级与边界 ────────────────────────────────────────────
def test_decide_none_when_all_clear():
    assert wd.decide(10, 5, 4096, 2700, 180, 800) is None


def test_decide_wall_first():
    assert wd.decide(2800, 5, 4096, 2700, 180, 800) == "wall"


def test_decide_idle_needs_log():
    assert wd.decide(10, 200, 4096, 2700, 180, 800) == "idle"
    assert wd.decide(10, 200, 4096, 2700, 180, 800) is not None
    assert wd.decide(10, None, 4096, 2700, 180, 800) is None, "无日志不得判空闲"


def test_decide_low_mem_and_unknown_free():
    assert wd.decide(10, 5, 100, 2700, 180, 800) == "low_mem"
    assert wd.decide(10, 5, None, 2700, 180, 800) is None, "读数失败不得误杀"
    assert wd.decide(10, 5, 100, 2700, 0, 0) is None, "闸关（0）不得杀"


# ── 行为：透传 / 墙钟 / 空闲 ─────────────────────────────────────────────
def _sleep(sec):
    return [sys.executable, "-c", "import time; time.sleep(%s)" % sec]


def test_passthrough_exit_code():
    assert wd.run([sys.executable, "-c", "raise SystemExit(3)"],
                  wall_s=30, idle_s=0, min_free_mb=0, interval_s=0.2) == 3


def test_stdout_is_forwarded(capsys):
    rc = wd.run([sys.executable, "-c", "print('hello-wd')"],
                wall_s=30, idle_s=0, min_free_mb=0, interval_s=0.2)
    assert rc == 0
    assert "hello-wd" in capsys.readouterr().out


def test_wall_timeout_kills_tree():
    t0 = time.monotonic()
    rc = wd.run(_sleep(30), wall_s=1, idle_s=0, min_free_mb=0, interval_s=0.2)
    assert rc == wd.RC_TIMEOUT
    assert time.monotonic() - t0 < 10, "墙钟命中后必须立刻返回，不得等子进程自然结束"


def test_idle_kills_after_quiet_log(tmp_path):
    log = tmp_path / "run.log"
    cmd = [sys.executable, "-c",
           "import time,sys; print('x', flush=True); time.sleep(30)"]
    rc = wd.run(cmd, wall_s=60, idle_s=1, min_free_mb=0, interval_s=0.2,
                log_path=str(log))
    assert rc == wd.RC_KILLED
    assert log.exists() and "x" in log.read_text(encoding="utf-8", errors="replace")


def test_cli_usage_requires_command(capsys):
    assert wd.main([]) == 2
    assert "usage" in capsys.readouterr().err


def test_thresholds_are_single_source():
    """阈值单源（2026-11-09）：`run()` 的签名缺省必须**引用模块常量**，不得二次硬编码。

    accept 侧只在显式设 `ACCEPT_WATCHDOG_*` 时传 `--wall/--idle`；否则一律落到这里。
    """
    import inspect
    sig = inspect.signature(wd.run)
    assert sig.parameters["wall_s"].default == wd.DEFAULT_WALL_S
    assert sig.parameters["idle_s"].default == wd.DEFAULT_IDLE_S
    assert sig.parameters["min_free_mb"].default == wd.DEFAULT_MIN_FREE_MB
    assert sig.parameters["interval_s"].default == wd.DEFAULT_INTERVAL_S
    assert (wd.DEFAULT_WALL_S, wd.DEFAULT_IDLE_S, wd.DEFAULT_MIN_FREE_MB) == (2700.0, 180.0, 800)


def test_cli_parses_flags(monkeypatch):
    seen = {}

    def _fake_run(argv, **kw):
        seen["argv"] = argv
        seen.update(kw)
        return 0

    monkeypatch.setattr(wd, "run", _fake_run)
    rc = wd.main(["--wall", "5", "--idle", "2", "--min-free-mb", "300",
                  "--interval", "0.5", "--log", "/tmp/x.log", "--", "echo", "hi"])
    assert rc == 0
    assert seen["argv"] == ["echo", "hi"]
    assert (seen["wall_s"], seen["idle_s"], seen["min_free_mb"], seen["interval_s"]) == (
        5.0, 2.0, 300, 0.5)

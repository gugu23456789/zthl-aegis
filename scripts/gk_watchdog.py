#!/usr/bin/env python3
"""gk_watchdog.py — **最小**运行期看门狗（墙钟 / 空闲 / 低内存 三闸，命中即整树击杀）。

为什么最小（2026-11-09，用户裁定「不过度设计」）：
  · 不装包（stdlib only）、不常驻、无配置中心；一次运行包一条命令，用完即退。
  · 三闸都只读现成信号：系统时钟、日志 mtime、`gk_hub_scheduler.free_avail_mb()`（单源）。
  · 不做自适应策略 / 不做指标上报 / 不改并发公式 —— 那些由调用方（accept）自己决定。

为什么必须「整树」：Windows 无 fork，pytest → bash.exe/openssl/wsl.exe 是**父子链**，
  只杀 pytest 会留孤儿继续吃内存（408 事故复盘）。POSIX 用 `killpg`，Windows 用
  `taskkill /T /F`。

用法::

  python3 scripts/gk_watchdog.py [--wall 2700] [--idle 180] [--min-free-mb 800] \
      [--interval 15] [--log FILE] -- <cmd...>

退出码：子进程原码透传；墙钟命中 124；空闲/低内存命中 137；参数错误 2。
stdin 固定 DEVNULL（与 `scripts/conftest.py` 同策：不继承悬空管道）。
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gk_hub_scheduler import free_avail_mb  # noqa: E402 — 内存读数单源

RC_TIMEOUT = 124
RC_KILLED = 137

#: 三闸缺省**单源**（2026-11-09，用户质询「看门狗会不会多源漂移」）：accept 只在显式设
#: `ACCEPT_WATCHDOG_*` 时才传 `--wall/--idle`，否则一律用这里；`--min-free-mb` 由 accept
#: 传入 `ACCEPT_MIN_FREE_MB`（与启动前硬闸共用同一变量，避免两套阈值）。
DEFAULT_WALL_S = 2700.0
DEFAULT_IDLE_S = 180.0
DEFAULT_MIN_FREE_MB = 800
DEFAULT_INTERVAL_S = 15.0


def decide(elapsed_s, idle_for_s, free_mb, wall_s, idle_s, min_free_mb):
    """→ 击杀原因（`wall` / `idle` / `low_mem`）或 None。纯函数，便于确定性测试。

    时钟口径：`elapsed_s` 用单调钟（不受系统改时影响）；`idle_for_s` 由**日志 mtime**
    （墙钟）换算，由调用方算好传入。
    """
    if wall_s and wall_s > 0 and elapsed_s > wall_s:
        return "wall"
    if idle_s and idle_s > 0 and idle_for_s is not None and idle_for_s > idle_s:
        return "idle"
    if min_free_mb and min_free_mb > 0 and free_mb is not None and free_mb < min_free_mb:
        return "low_mem"
    return None


def _kill_tree(pid: int) -> None:
    """整树击杀：POSIX `killpg`；Windows `taskkill /T /F`（按父链级联，唯一可靠手段）。"""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                           capture_output=True, timeout=20)
        else:
            import signal
            os.killpg(os.getpgid(pid), signal.SIGKILL)
    except Exception:  # noqa: BLE001 — 边界：进程已退出/无权限 ⟹ 不阻断
        pass


def _pop(args, name, cast):
    if name in args:
        i = args.index(name)
        val = args[i + 1] if i + 1 < len(args) else ""
        del args[i:i + 2]
        try:
            return cast(val)
        except (TypeError, ValueError):
            return None
    return None


def run(argv, wall_s=DEFAULT_WALL_S, idle_s=DEFAULT_IDLE_S,
        min_free_mb=DEFAULT_MIN_FREE_MB, interval_s=DEFAULT_INTERVAL_S, log_path=""):
    """包一条命令跑，返回退出码（子进程码透传；闸命中 124/137）。"""
    env = dict(os.environ)
    flags = 0
    if os.name == "nt":
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, start_new_session=(os.name != "nt"),
                            creationflags=flags)
    logf = None
    if log_path:
        try:
            logf = open(log_path, "ab", buffering=0)
        except OSError:
            logf = None

    def _pump():
        for line in iter(proc.stdout.readline, b""):
            try:
                sys.stdout.buffer.write(line)
                sys.stdout.buffer.flush()
            except Exception:  # noqa: BLE001 — 边界：下游已关闭 ⟹ 继续写日志
                pass
            if logf is not None:
                try:
                    logf.write(line)
                except Exception:  # noqa: BLE001
                    pass
        try:
            proc.stdout.close()
        except Exception:  # noqa: BLE001
            pass

    started = time.monotonic()
    t = threading.Thread(target=_pump, daemon=True)
    t.start()
    reason = None
    elapsed = 0.0
    try:
        while True:
            rc = proc.poll()
            if rc is not None:
                break
            elapsed = time.monotonic() - started
            idle_for = None
            if logf is not None:
                try:
                    idle_for = time.time() - os.stat(log_path).st_mtime
                except OSError:
                    idle_for = None
            reason = decide(elapsed, idle_for, free_avail_mb(), wall_s, idle_s, min_free_mb)
            if reason:
                _kill_tree(proc.pid)
                try:
                    proc.wait(timeout=20)
                except Exception:  # noqa: BLE001
                    pass
                break
            time.sleep(max(0.2, float(interval_s)))
    finally:
        t.join(timeout=5)
        if logf is not None:
            try:
                logf.close()
            except Exception:  # noqa: BLE001
                pass
    if reason:
        print("[watchdog] KILL reason=%s elapsed=%.0fs idle=%ss min_free=%sMB"
              % (reason, elapsed, int(idle_s), min_free_mb), file=sys.stderr, flush=True)
        return RC_TIMEOUT if reason == "wall" else RC_KILLED
    return proc.returncode


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    wall = _pop(args, "--wall", float)
    idle = _pop(args, "--idle", float)
    floor = _pop(args, "--min-free-mb", int)
    every = _pop(args, "--interval", float)
    log = _pop(args, "--log", str)
    if "--" in args:
        args = args[args.index("--") + 1:]
    if not args:
        print("usage: gk_watchdog.py [--wall S] [--idle S] [--min-free-mb M] "
              "[--interval S] [--log FILE] -- <cmd...>", file=sys.stderr)
        return 2
    return run(args,
               wall_s=DEFAULT_WALL_S if wall is None else wall,
               idle_s=DEFAULT_IDLE_S if idle is None else idle,
               min_free_mb=DEFAULT_MIN_FREE_MB if floor is None else floor,
               interval_s=DEFAULT_INTERVAL_S if every is None else every,
               log_path=log or "")


if __name__ == "__main__":
    raise SystemExit(main())

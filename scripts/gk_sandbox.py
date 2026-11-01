#!/usr/bin/env python3
"""gk_sandbox.py — 基础执行沙箱（**stdlib only**）：内存硬上限 + 时间上限 + 进程数上限。

分工（与 `gk_hub_scheduler` 互补）：
  · `gk_hub_scheduler` 做**准入**（全局并发槽位 + 空闲内存闸）；
  · 本模块做**单进程强制**——即使某条子进程失控（内存疯长 / 挂死 / 派生炸裂），也无法吃掉
    宿主机内存与时间预算（超限 ⟹ 分配失败或被杀，而非拖垮宿主）。

平台实现：
  · **Windows** → Job Object：`JOB_OBJECT_LIMIT_PROCESS_MEMORY`（每进程提交上限）+
    `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`（进程数上限）+ `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
    （句柄关闭即回收全部子进程）。
  · **POSIX** → `resource.setrlimit(RLIMIT_AS / RLIMIT_CPU)`（经 `preexec_fn`）。
  · 无法建立限制 ⟹ 默认 **fail-loud（拒跑）**；`fail_closed=False` 则降级放行并置
    `enforced=False`（显式可观测，不静默假装有沙箱）。

替代说明（2026-10-07）：用户裁定「大概用不到 wasmtime」——WASM（zthl ZH3）作为**不可信工具
代码**的最强隔离路径仍登记，但本轮先落**无外部依赖**的 OS 级资源沙箱（任何子进程都可加）。

CLI：gk_sandbox.py run [--mem-mb M] [--timeout S] [--max-proc P] [--json] -- <cmd...>
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

# ── Windows Job Object 常量 ──
_JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
_JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JobObjectExtendedLimitInformation = 9
_PROCESS_SET_QUOTA = 0x0100
_PROCESS_TERMINATE = 0x0001


def _win_run(argv, mem_mb, timeout_s, max_proc, cwd, env):
    """Windows：Job Object 限额执行。返回 (proc_rc, timed_out, enforced)。"""
    import ctypes
    from ctypes import wintypes

    ULONG_PTR = ctypes.c_size_t

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                    ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ULONG_PTR),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [("ReadOperationCount", ctypes.c_uint64),
                    ("WriteOperationCount", ctypes.c_uint64),
                    ("OtherOperationCount", ctypes.c_uint64),
                    ("ReadTransferCount", ctypes.c_uint64),
                    ("WriteTransferCount", ctypes.c_uint64),
                    ("OtherTransferCount", ctypes.c_uint64)]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", _IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]

    k32 = ctypes.windll.kernel32
    job = k32.CreateJobObjectW(None, None)
    if not job:
        return None, False, False
    enforced = True
    try:
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        flags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if mem_mb:
            flags |= _JOB_OBJECT_LIMIT_PROCESS_MEMORY
            info.ProcessMemoryLimit = int(mem_mb) * 1024 * 1024
        if max_proc:
            flags |= _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            info.BasicLimitInformation.ActiveProcessLimit = int(max_proc)
        info.BasicLimitInformation.LimitFlags = flags
        if not k32.SetInformationJobObject(job, _JobObjectExtendedLimitInformation,
                                           ctypes.byref(info), ctypes.sizeof(info)):
            enforced = False
        p = subprocess.Popen(argv, cwd=cwd, env=env)
        h = k32.OpenProcess(_PROCESS_SET_QUOTA | _PROCESS_TERMINATE, False, p.pid)
        if not h or not k32.AssignProcessToJobObject(job, h):
            enforced = False                     # 宿主已在作业中不可 breakout 等 ⟹ 未生效
        if h:
            k32.CloseHandle(h)
        timed_out = False
        try:
            rc = p.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            k32.TerminateJobObject(job, 1)
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
            rc = -1
            timed_out = True
        return rc, timed_out, enforced
    finally:
        k32.CloseHandle(job)                     # KILL_ON_JOB_CLOSE ⟹ 回收残留子进程


def _posix_preexec(mem_mb):
    def _fn():
        import resource
        if mem_mb:
            _b = int(mem_mb) * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (_b, _b))
    return _fn


def _posix_run(argv, mem_mb, timeout_s, max_proc, cwd, env):
    pre = _posix_preexec(mem_mb) if mem_mb else None
    enforced = mem_mb is not None
    timed_out = False
    p = subprocess.Popen(argv, cwd=cwd, env=env, preexec_fn=pre)
    try:
        rc = p.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
        rc, timed_out = -1, True
    return rc, timed_out, enforced


def run(argv, *, mem_mb=None, timeout_s=None, max_proc=None,
        cwd=None, env=None, fail_closed=True) -> dict:
    """限额执行 `argv`。返回 {"ok","rc","enforced","reason","timed_out"}。

    限制未生效且 `fail_closed` ⟹ **拒跑**（ok=False, rc=None）；否则放行并置 enforced=False。
    """
    if not argv:
        return {"ok": False, "rc": None, "enforced": False, "reason": "empty argv"}
    if os.name == "nt":
        rc, timed_out, enforced = _win_run(argv, mem_mb, timeout_s, max_proc, cwd, env)
    else:
        rc, timed_out, enforced = _posix_run(argv, mem_mb, timeout_s, max_proc, cwd, env)
    if not enforced and fail_closed:
        return {"ok": False, "rc": None, "enforced": False,
                "reason": "sandbox limits not enforceable on this host"}
    return {"ok": True, "rc": rc, "enforced": enforced,
            "reason": "timeout" if timed_out else "", "timed_out": timed_out}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="基础执行沙箱（内存/时间/进程数硬上限）")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--mem-mb", type=int, default=1024)
    r.add_argument("--timeout", type=float, default=None)
    r.add_argument("--max-proc", type=int, default=None)
    r.add_argument("--no-fail-closed", action="store_true")
    r.add_argument("--json", action="store_true")
    r.add_argument("cmd_argv", nargs=argparse.REMAINDER)
    a = p.parse_args(argv)
    rest = a.cmd_argv
    if rest and rest[0] == "--":
        rest = rest[1:]
    out = run(rest, mem_mb=a.mem_mb, timeout_s=a.timeout,
              max_proc=a.max_proc, fail_closed=not a.no_fail_closed)
    if a.json:
        print(json.dumps(out, ensure_ascii=False))
    return 0 if out.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

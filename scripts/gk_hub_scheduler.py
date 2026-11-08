#!/usr/bin/env python3
"""gk_hub_scheduler.py — 元数据中枢**基础运行时调度管控**（并发上限 + OOM 闸 + 准入）。

定位（2026-10-07，用户裁定「快速推进」）：卫星/中枢此前只有**静态**上限
（`GK_SUBAGENT_K_MAX=2`）与**无界** shell fan-out（`3×K` 子壳 `& … wait`），**无**运行时
调度 / 背压 / OOM 准入。极端并发压测（300 路）暴露：无管控时并发度不受限 ⟹
  ① 进程数/内存随扇出线性膨胀（**OOM 面**）；
  ② 存储原语在高并发下暴露瞬态失败（`os.replace` 长尾，见 `gk_json_utils.write_json_file`）。
本模块 = **基础**调度：
  · **槽位限流**（跨进程硬上限，默认 64）；
  · **空闲内存下限闸**（准入即拒，非排队）；
  · **受限执行包装** `run`（供 shell fan-out 逐臂包络）。

设计约束：
  · **stdlib only**（禁装包）：POSIX → `fcntl.flock`；Windows → `msvcrt.locking`
    （与 `gk_json_utils.state_lock` 同平台策略）。
  · **跨进程**：N 个槽位文件 `hubslot.000..N-1` 非阻塞锁竞争；占满 ⟹ 超时后 fail-loud
    （`low_slots`），**不静默超发**。
  · **fail-safe 而非 fail-open**：内存读不到 ⟹ **不拦**（宁可放行，避免误伤），但把 `free_mb=None`
    显式回传供观测。
  · 与 state 锁**正交互补**：本闸管**并发度 / 内存准入**；`state_lock` 管**写互斥**。

环境变量：`GK_HUB_MAX_CONCURRENCY`(64) / `GK_HUB_MIN_FREE_MB`(512) / `GK_HUB_SLOTS_ROOT` /
`GK_HUB_ACQUIRE_TIMEOUT_S`(30) / `GK_HUB_WORKERS_RESERVE`(1) / `GK_HUB_WORKERS_CAP`(无)。

CLI：
  status [--json]                              —— 打印上限 / 空闲内存 / 槽位占用
  workers [--n N] [--cap N]                    —— **s5.5** 自适应并发度（核数/内存→worker），供 bash/其它模块查询
  run [--max-concurrency N] [--min-free-mb M] [--timeout S] -- <cmd...>
                                               —— 取得槽位 + 过内存闸后执行 <cmd>；放行失败 → exit 75
"""
from __future__ import annotations

import contextlib
import os
import sys
import tempfile
import time

try:  # POSIX
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None
try:  # Windows
    import msvcrt
except ImportError:  # pragma: no cover - POSIX
    msvcrt = None

SLOT_PREFIX = "hubslot."


# ────────────────────────── 参数（env 单源） ──────────────────────────
def max_concurrency() -> int:
    """并发硬上限（默认 64）。非法/非正 ⟹ 回落默认（不静默放大）。"""
    try:
        n = int(os.environ.get("GK_HUB_MAX_CONCURRENCY", "64"))
    except (TypeError, ValueError):
        return 64
    return n if n > 0 else 64


def min_free_mb() -> int:
    """准入空闲内存下限（MB，默认 512）。0 ⟹ 不设下限。非法 ⟹ 回落默认。"""
    try:
        n = int(os.environ.get("GK_HUB_MIN_FREE_MB", "512"))
    except (TypeError, ValueError):
        return 512
    return n if n >= 0 else 512


def acquire_timeout_s() -> float:
    try:
        return max(0.0, float(os.environ.get("GK_HUB_ACQUIRE_TIMEOUT_S", "30")))
    except (TypeError, ValueError):
        return 30.0


def slots_root() -> str:
    """槽位根目录（跨进程共享）。默认落在系统临时目录（与 state 生命周期解耦）。"""
    r = os.environ.get("GK_HUB_SLOTS_ROOT") or os.path.join(tempfile.gettempdir(),
                                                            ".gatekeeper-hub-slots")
    return r


# ────────────────────────── 空闲内存探测（fail-safe None） ──────────────────────────
def free_avail_mb():
    """当前**可用物理内存** MB；探测失败 ⟹ None（不判低内存，宁可放行）。"""
    try:
        if os.name == "nt":
            import ctypes

            class _MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong),
                            ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong),
                            ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong),
                            ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

            ms = _MEMORYSTATUSEX()
            ms.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms)):
                return None
            return int(ms.ullAvailPhys // (1024 * 1024))
        with open("/proc/meminfo", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except Exception:  # noqa: BLE001 — 边界：探测失败即 None（放行）
        return None
    return None


# ────────────────────────── 硬件自适应并发度（s5.5 全仓**单源**）──────────────────────────
def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, ""))
    except (TypeError, ValueError):
        return default


def _env_min_free_mb() -> int:
    """`min_free_mb` 参数缺省值（不遮蔽：经本名调模块级 `min_free_mb()` 单一源）。"""
    return min_free_mb()


def visible_cpus() -> int:
    """本进程**可见**核数：优先 CPU affinity / cgroup（容器/绑核下 `os.cpu_count()` 报**宿主全核**
    ⟹ 过度订阅），退化 `os.cpu_count()`；Windows 无 affinity ⟹ 自动回落。探测失败保守给 1。"""
    try:
        return len(os.sched_getaffinity(0))       # Linux/容器：尊重 cpuset/cgroup
    except Exception:  # noqa: BLE001 — 边界：探测失败即回落（含 Windows 无该 attr）
        pass
    try:
        return os.cpu_count() or 1
    except Exception:  # noqa: BLE001
        return 1


def adaptive_workers(n: int, cap: int = None, reserve: int = None,
                     min_free_mb: int = None, cpus: int = None,
                     subprocess_factor: int = 0) -> int:
    """按**可见核数** + 空闲内存下限自适应当前并发度（stdlib only，保底 1，**不放大**）。

    全仓**单源**（s5.5）：MoA 检测器 / 相位探针 `--jobs` / 审计 `ThreadPoolExecutor` /
    accept·redfirst / gitnexus 增量分析 / subagent 扇出一律挂此，**禁各自再算并发度**（第二实现）。

    · 核数 = `cpus` 或 `visible_cpus()`（affinity/cgroup 感知），减 `reserve`（默认 1，留 1 核给主控）；
    · 上限不超过待办数 `n`，再被 `cap`（或 `GK_HUB_WORKERS_CAP`）收紧；
    · `min_free_mb`（默认走既有 `GK_HUB_MIN_FREE_MB`）>0 且空闲内存可读且低于阈值 ⟹ 压到 1
      （与槽位/内存准入闸**同向**）；`min_free_mb=0` ⟹ 关内存闸。
    `reserve`/`cap` 缺省走 env 单源（`GK_HUB_WORKERS_RESERVE` / `GK_HUB_WORKERS_CAP`）——**无硬编码**。

    `subprocess_factor`（2026-11-08，408-research 公式 + 实机校正）：该批次每用例派生的**峰值
    外部子进程数** f（纯 python=0；每用例 1 次 bash=1；WSL+openssl 重活=3）。**f>0 才启用**
    安全并发公式，f=0 保持原行为（向后兼容）：
        r = min(4, max(1, 可见核//4))            # OS 保留按切片比例缩放（16→4，5→1）
        W = min( 2·max(1, 可见核-r)/max(1,f),    # I/O 超订 ×2；第 1 个子进程按阻塞 I/O 计
                 0.6·空闲MB/(180+60f),           # 单 worker 峰值 RSS 180+60f MB，留 40% 垫
                 80/(1+f),                       # Windows 进程预算硬顶（>600 进程即换页）
                 cap或8, todo )
    校正依据（2026-11-08 实机验证，WSL：processors=5 / memory=5GB，visible=5 / free≈4.5GB）：
      408 原式 `(C-4)/(1+f)` 在该切片给出 f=1 → 1、f=2 → 1，与实测反证——重活四文件
      n=1 59.0s / n=2 53.0s / n=4 49.5s / n=6 46.6s（plateau≈4–6），全量 n=8 211s / n=12 206s。
      两处修正：(a) 4 核 OS 保留是**宿主级**预留，WSL/cgroup 切片里再扣一次属双算 ⟹ 按 C//4
      缩放；(b) 第 1 个外部子进程通常阻塞在管道/文件 I/O，不占满 CPU ⟹ 核项除数用 max(1,f)
      （f≥2 才线性计入 CPU）。校正后本机 f=1 → 8、f=2 → 4、f=3 → 2（内存/进程项仍在收紧）；
      16 核宿主 f=1..3 均被 8 令牌封顶。
    """
    if reserve is None:
        reserve = _env_int("GK_HUB_WORKERS_RESERVE", 1)
    if cap is None:
        cap = _env_int("GK_HUB_WORKERS_CAP", 0) or None
    if min_free_mb is None:
        min_free_mb = _env_min_free_mb()
    try:
        ncpu = int(cpus) if cpus is not None else visible_cpus()
    except Exception:  # noqa: BLE001
        ncpu = 1
    ncpu = max(1, ncpu)
    try:
        todo = max(1, int(n))
    except Exception:  # noqa: BLE001
        todo = 1
    _f = max(0, int(subprocess_factor or 0))
    if _f > 0:
        # 408 校正式：核/内存/进程三项取小，再被 cap（缺省 8 = 机器级并发令牌）与 todo 收紧。
        _r = min(4, max(1, ncpu // 4))          # OS 保留核按切片比例缩放（16→4，5→1）
        w = (2 * max(1, ncpu - _r)) // max(1, _f)   # I/O 超订 ×2；f=1 首个外部进程按阻塞计
        fm = free_avail_mb()
        if fm is not None:
            w = min(w, max(1, int(0.6 * float(fm) / (180 + 60 * _f))))
        w = min(w, max(1, 80 // (1 + _f)))
        w = min(w, todo)
        w = min(w, 8 if cap is None else max(1, int(cap)))
        return max(1, w)
    w = max(1, ncpu - max(0, int(reserve)))
    w = min(w, todo)
    if cap is not None:
        try:
            w = min(w, max(1, int(cap)))
        except Exception:  # noqa: BLE001
            pass
    if min_free_mb and int(min_free_mb) > 0:
        fm = free_avail_mb()
        if fm is not None and fm < int(min_free_mb):
            w = 1
    return w


# ────────────────────────── 槽位锁（跨进程） ──────────────────────────
def _slot_path(root: str, idx: int) -> str:
    return os.path.join(root, "%s%03d" % (SLOT_PREFIX, idx))


def _try_lock(fd: int) -> bool:
    """非阻塞取排他锁；成功 True，被占 False（真无锁原语 ⟹ 恒 True，退化不拦）。"""
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        if msvcrt is not None:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
    except OSError:
        return False
    return True


def try_acquire(root: str, n: int, timeout_s: float):
    """在 `n` 个槽位里抢一个；成功 → (fd, idx)；超时 → None（不静默超发）。"""
    os.makedirs(root, exist_ok=True)
    deadline = time.monotonic() + max(0.0, timeout_s)
    while True:
        for i in range(n):
            fd = os.open(_slot_path(root, i), os.O_CREAT | os.O_RDWR, 0o644)
            if _try_lock(fd):
                return fd, i
            os.close(fd)
        if time.monotonic() >= deadline:
            return None
        time.sleep(0.02)


def release(fd: int) -> None:
    """释放槽位（close 即释放 flock/locking；异常安全）。"""
    with contextlib.suppress(OSError):
        os.close(fd)


# ────────────────────────── 准入 + 上下文 ──────────────────────────
def admit(root: str = None, max_c: int = None, min_mb: int = None,
          timeout_s: float = None) -> dict:
    """准入判定（内存闸 → 槽位闸）。返回 {"ok", ...}；失败附 reason（不静默）。"""
    root = root or slots_root()
    max_c = max_concurrency() if max_c is None else max_c
    min_mb = min_free_mb() if min_mb is None else min_mb
    timeout_s = acquire_timeout_s() if timeout_s is None else timeout_s
    fm = free_avail_mb()
    if fm is not None and min_mb > 0 and fm < min_mb:
        return {"ok": False, "reason": "low_memory", "free_mb": fm, "min_free_mb": min_mb}
    got = try_acquire(root, max_c, timeout_s)
    if got is None:
        return {"ok": False, "reason": "low_slots", "max_concurrency": max_c,
                "timeout_s": timeout_s}
    fd, idx = got
    return {"ok": True, "fd": fd, "slot": idx, "free_mb": fm, "max_concurrency": max_c}


@contextlib.contextmanager
def gate(root: str = None, max_c: int = None, min_mb: int = None, timeout_s: float = None):
    """`with gate():` 持槽；准入失败 ⟹ 抛 `HubGateDenied`（fail-loud）。"""
    res = admit(root, max_c, min_mb, timeout_s)
    if not res.get("ok"):
        raise HubGateDenied(res)
    try:
        yield res
    finally:
        release(res["fd"])


class HubGateDenied(RuntimeError):
    def __init__(self, res: dict):
        super().__init__("hub gate denied: %s" % res.get("reason"))
        self.result = res


def status(root: str = None) -> dict:
    """只读体检：上限 / 空闲内存 / 当前占用槽位数。"""
    root = root or slots_root()
    n = max_concurrency()
    occupied = 0
    if os.path.isdir(root):
        for i in range(n):
            p = _slot_path(root, i)
            if not os.path.exists(p):
                continue
            fd = os.open(p, os.O_CREAT | os.O_RDWR, 0o644)
            if _try_lock(fd):
                os.close(fd)          # 空槽：立即放
            else:
                occupied += 1
                os.close(fd)
    return {"max_concurrency": n, "min_free_mb": min_free_mb(),
            "free_mb": free_avail_mb(), "occupied": occupied, "slots_root": root}


# ────────────────────────── CLI ──────────────────────────
def _pop_opt(args: list, name: str):
    if name in args:
        i = args.index(name)
        val = args[i + 1] if i + 1 < len(args) else ""
        del args[i:i + 2]
        return val
    return None


def main(argv: list) -> int:
    import json
    if not argv:
        print(__doc__.splitlines()[0])
        return 1
    cmd, rest = argv[0], argv[1:]
    if cmd == "status":
        print(json.dumps(status(), ensure_ascii=False, indent=2))
        return 0
    if cmd == "workers":
        # s5.5：供 bash / gitnexus / subagent / accept·redfirst 查询**自适应并发度**（单一源）。
        _n, _c = _pop_opt(rest, "--n"), _pop_opt(rest, "--cap")
        try:
            nn = int(_n) if _n else 0
        except (TypeError, ValueError):
            nn = 0
        try:
            cc = int(_c) if _c else None
        except (TypeError, ValueError):
            cc = None
        print(json.dumps({"workers": adaptive_workers(nn, cap=cc),
                          "visible_cpus": visible_cpus()}))
        return 0
    if cmd == "run":
        mc = _pop_opt(rest, "--max-concurrency")
        mm = _pop_opt(rest, "--min-free-mb")
        to = _pop_opt(rest, "--timeout")
        if "" in rest:
            rest = rest[rest.index("") + 1:]      # 丢 `--` 前的空串分隔
        if rest and rest[0] == "--":
            rest = rest[1:]
        if not rest:
            print(json.dumps({"ok": False, "error": "run 需要 -- <cmd...>"}))
            return 2
        res = admit(max_c=int(mc) if mc else None,
                    min_mb=int(mm) if mm else None,
                    timeout_s=float(to) if to else None)
        if not res.get("ok"):
            print(json.dumps({"ok": False, **{k: v for k, v in res.items() if k != "fd"}}))
            return 75                                   # EX_TEMPFAIL：可重试
        # A 接线（2026-10-16，owner 裁定「沙箱面向所有 subagent」「全接」）：准入(hub) → 单进程
        #   强制(gk_sandbox) **合体**——`run` 是 shell fan-out 逐臂的包络点。分工严守 docstring：
        #   本模块做**并发/内存准入**，gk_sandbox 做**单进程 mem/time/proc 硬上限**（互补、禁第二实现）。
        #   逃生舱 `GK_SANDBOX_OFF=1` ⟹ 裸 subprocess（与 HEAD 逐字一致，零回归）。
        #   开关：GK_SANDBOX_MEM_MB(2048) / GK_SANDBOX_TIMEOUT_S(不限) / GK_SANDBOX_MAX_PROC(不限) /
        #        GK_SANDBOX_FAIL_OPEN=1（不可建限时降级放行；默认 fail-loud 拒跑）。
        try:
            import gk_sandbox as _sb
        except Exception:  # noqa: BLE001 — 边界：模块不可用 ⟹ 回退裸执行（fail-safe）
            _sb = None
        if _sb is None or os.environ.get("GK_SANDBOX_OFF") == "1":
            import subprocess
            try:
                return subprocess.call(rest)
            finally:
                release(res["fd"])
        try:
            _r = _sb.run(rest,
                         mem_mb=int(os.environ.get("GK_SANDBOX_MEM_MB", "2048") or 0) or None,
                         timeout_s=float(os.environ["GK_SANDBOX_TIMEOUT_S"])
                         if os.environ.get("GK_SANDBOX_TIMEOUT_S") else None,
                         max_proc=int(os.environ.get("GK_SANDBOX_MAX_PROC", "0") or 0) or None,
                         fail_closed=os.environ.get("GK_SANDBOX_FAIL_OPEN") != "1")
        finally:
            release(res["fd"])
        _rc = _r.get("rc")
        return (int(_rc) if _rc is not None else 75)
    print(json.dumps({"ok": False, "error": "usage: status | run -- <cmd...>"}))
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

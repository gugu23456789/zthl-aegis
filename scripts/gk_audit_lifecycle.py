#!/usr/bin/env python3
"""gk_audit_lifecycle.py — 审计署 4B 决策模型自适应启停（408 计划 T1/T2，2026-11-12）
=====================================================================================
把两条进程（`llama-server` :8081 + `startlux_decide serve` :8090）当作一个模型单元，
用状态机 `cold → warming → warm → draining → cold` 管理；资源读数**只**复用
`scripts/gk_hub_scheduler.py` 的既有符号（禁第二套探针）。

设计正本：`docs/analysis/2026-11-12-audit-model-adaptive-lifecycle-408.md` §2–§6 / §9–§10。
首版边界：
  - 只做需求 / 内存 / 显存三闸；CPU 压力闸与电池闸**不产生**（`HOLD_CPU_BUSY`/
    `HOLD_ON_BATTERY` 为后置码，`decide()` 永不产出）。
  - in-flight 唯一事实源 = `inflight_leases[]`（逐条 TTL 过期，不整批清零）。
  - PID 校验 = pid + 进程启动时间双键（防 PID 复用误杀）。
  - **启动器口径（2026-11-16 裁定）**：生产路径 = **外部 launcher**（sidecar `launcher=external`）；
    模块内 `_default_spawn` **unsupported**（fail-loud `START_UNSUPPORTED`）—— 它拉起的子进程
    随宿主 Windows Job Object 被清杀（408 §9.2）。启停命令 env 仅保留读取口径；
    未配置 ⟹ 具名 `START_CMD_UNSET`，不猜路径。

CLI::
  python3 gk_audit_lifecycle.py status [--json]
  python3 gk_audit_lifecycle.py decide [--json]
  python3 gk_audit_lifecycle.py tick [--json]
  python3 gk_audit_lifecycle.py start|stop [--json]
  python3 gk_audit_lifecycle.py lease --kind raises|monitor|sweep [--pid N] [--ttl S]
"""
import argparse
import contextlib
import json
import os
import shlex
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SIDECAR_DEFAULT = REPO / ".gatekeeper.audit_lifecycle.json"

STATES = ("cold", "warming", "warm", "draining")
FIRST_CUT_REASONS = {
    "OK_NEED_HOT", "OK_NEED_MONITOR", "HOLD_IDLE_TTL", "HOLD_LOW_MEM",
    "HOLD_LOW_VRAM", "HOLD_NO_READING", "NO_GPU_DEGRADED", "STOP_TTL_EXPIRED",
    "FORCE_ON", "FORCE_OFF", "PORT_TAKEN", "WARMING_BUSY", "START_TIMEOUT",
    "STOP_FAILED", "DRAIN_TIMEOUT", "LEASE_EXPIRED",
}
# 实现期新增（计划 §2 封闭枚举的同步项；测试表覆盖）：
#   BACKOFF（退避中）/ START_CMD_UNSET（未配启停命令）/ STOP_DRAINED（排空完成）/
#   SIDECAR_CORRUPT（sidecar 不可解析）/ START_FAILED（spawn 异常）/
#   START_UNSUPPORTED（模块内 spawn 已停用，须外部 launcher；2026-11-16 裁定）。
EXTRA_REASONS = {"BACKOFF", "START_CMD_UNSET", "STOP_DRAINED", "SIDECAR_CORRUPT", "START_FAILED",
                 "START_UNSUPPORTED", "HOLD_ON_BATTERY"}
REASONS = FIRST_CUT_REASONS | EXTRA_REASONS


# ────────────────────────── env 单源 ──────────────────────────
def _env_float(name: str, default: float) -> float:
    try:
        return max(0.0, float(os.environ.get(name, str(default))))
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def idle_ttl_s() -> float:
    return _env_float("GK_AUDIT_MODEL_IDLE_TTL_S", 600.0)


def tick_s() -> float:
    return _env_float("GK_AUDIT_MODEL_TICK_S", 60.0)


def lease_ttl_s() -> float:
    return _env_float("GK_AUDIT_MODEL_INFLIGHT_LEASE_TTL_S", 120.0)


def drain_timeout_s() -> float:
    return _env_float("GK_AUDIT_MODEL_DRAIN_TIMEOUT_S", 120.0)


def start_timeout_s() -> float:
    return _env_float("GK_AUDIT_MODEL_START_TIMEOUT_S", 90.0)


def backoff_max_s() -> float:
    return _env_float("GK_AUDIT_MODEL_BACKOFF_MAX_S", 300.0)


def vram_headroom() -> float:
    return _env_float("GK_AUDIT_MODEL_VRAM_HEADROOM", 1.2)


def min_battery_pct():
    """电池闸阈值；**未设置 ⟹ None**（不读电池、不产生 HOLD_ON_BATTERY，零副作用）。"""
    raw = str(os.environ.get("GK_AUDIT_MODEL_MIN_BATTERY_PCT", "")).strip()
    if not raw:
        return None
    try:
        v = int(float(raw))
    except (TypeError, ValueError):
        return None
    return v if 0 <= v <= 100 else None


def battery_status() -> dict:
    """Windows 电池读数（kernel32 GetSystemPowerStatus，ctypes，<1ms、零依赖）。

    非 Windows（WSL）⟹ `{"ok": False, "error": "NON_WINDOWS"}` ⟹ 调用方**不得**据此拦截
    （否则测试环境全 HOLD）。失败同样 fail-open，只记录 error。
    """
    if os.name != "nt":
        return {"ok": False, "error": "NON_WINDOWS"}
    try:
        import ctypes

        class _SPS(ctypes.Structure):
            _fields_ = [("ACLineStatus", ctypes.c_ubyte),
                        ("BatteryFlag", ctypes.c_ubyte),
                        ("BatteryLifePercent", ctypes.c_ubyte),
                        ("SystemStatusFlag", ctypes.c_ubyte),
                        ("BatteryLifeTime", ctypes.c_ulong),
                        ("BatteryFullLifeTime", ctypes.c_ulong)]

        st = _SPS()
        if not ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(st)):
            return {"ok": False, "error": "API_FAILED"}
        on_ac = None if st.ACLineStatus == 255 else bool(st.ACLineStatus)
        pct = None if st.BatteryLifePercent == 255 else int(st.BatteryLifePercent)
        return {"ok": True, "on_ac": on_ac, "pct": pct}
    except Exception as e:  # noqa: BLE001 — 读数失败不得改变控制面
        return {"ok": False, "error": type(e).__name__}


_CPU_LAST = None


def cpu_percent():
    """CPU 占用百分比（**仅观测**；`decide()` 不消费 ⟹ 不产生 HOLD_CPU_BUSY）。

    首次调用无基线 ⟹ None。Windows 走 GetSystemTimes 差分；POSIX 走 /proc/stat 差分。
    """
    global _CPU_LAST
    try:
        if os.name == "nt":
            import ctypes

            class _FT(ctypes.Structure):
                _fields_ = [("lo", ctypes.c_ulong), ("hi", ctypes.c_ulong)]

            idle, kern, user = _FT(), _FT(), _FT()
            if not ctypes.windll.kernel32.GetSystemTimes(
                    ctypes.byref(idle), ctypes.byref(kern), ctypes.byref(user)):
                return None

            def _v(x):
                return (x.hi << 32) | x.lo

            cur = (_v(idle), _v(kern), _v(user))
        else:
            with open("/proc/stat", encoding="utf-8") as f:
                vals = [int(x) for x in f.readline().split()[1:]]
            cur = (vals[3] + (vals[4] if len(vals) > 4 else 0), sum(vals))
        prev, _CPU_LAST = _CPU_LAST, cur
        if prev is None:
            return None
        di, dt = cur[0] - prev[0], cur[1] - prev[1]
        return None if dt <= 0 else round(max(0.0, min(100.0, 100.0 * (1.0 - di / dt))), 1)
    except Exception:  # noqa: BLE001
        return None


def mode() -> str:
    m = str(os.environ.get("GK_AUDIT_MODEL_LIFECYCLE", "auto")).strip().lower()
    return m if m in ("auto", "force-on", "force-off") else "auto"


def llama_port() -> int:
    return _env_int("GK_AUDIT_MODEL_LLAMA_PORT", 8081)


def serve_port() -> int:
    return _env_int("GK_AUDIT_MODEL_SERVE_PORT", 8090)


def llama_cmd() -> str:
    return str(os.environ.get("GK_AUDIT_MODEL_LLAMA_CMD", "")).strip()


def serve_cmd() -> str:
    return str(os.environ.get("GK_AUDIT_MODEL_SERVE_CMD", "")).strip()


# ────────────────────────── sidecar（原子写） ──────────────────────────
def default_state(now: float | None = None) -> dict:
    return {
        "schema": 1, "state": "cold",
        "launcher": "external",
        "pids": {"llama": 0, "serve": 0},
        "proc_start_time": {"llama": "", "serve": ""},
        "reserved": {"mb": 0, "vram_mb": 0, "expires_at": 0},
        "last_request_at": 0.0,
        "inflight_leases": [],
        "backoff": {"attempts": 0, "next_retry_at": 0.0},
        "reason": "HOLD_IDLE_TTL",
        "updated_at": float(now if now is not None else time.time()),
    }


def _merge_defaults(raw: dict) -> dict:
    st = default_state()
    if not isinstance(raw, dict):
        return st
    for k, v in raw.items():
        if k in st and isinstance(st[k], dict) and isinstance(v, dict):
            st[k].update(v)
        else:
            st[k] = v
    if st.get("state") not in STATES:
        st["state"] = "cold"
    if not isinstance(st.get("inflight_leases"), list):
        st["inflight_leases"] = []
    return st


def load_state(path=None) -> dict:
    p = Path(path or SIDECAR_DEFAULT)
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default_state()
    except Exception:
        st = default_state()
        st["reason"] = "SIDECAR_CORRUPT"
        return st
    return _merge_defaults(raw)


def save_state(st: dict, path=None) -> None:
    p = Path(path or SIDECAR_DEFAULT)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp.%d" % os.getpid())
    tmp.write_text(json.dumps(st, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    os.replace(str(tmp), str(p))


def reserved_claim(path=None, now: float | None = None) -> dict:
    """只读：warming 期预留（`reserved`）的**当前有效值**。**绝不写盘**。

    408 ⑦（2026-11-16）：`reserved` 此前是死字段（无消费方）。读侧（accept 启动闸）需要
    在不持有写权时也能安全取值 ⟹ 本函数只 `load_state`；过期 / 缺失 / 坏值一律归零并标
    `active=False`。**过期回收仍归写者**（`_start_unit` / `_stop_unit`），本函数不改 sidecar。
    """
    st = load_state(path)
    now = float(now if now is not None else time.time())
    r = st.get("reserved") if isinstance(st.get("reserved"), dict) else {}

    def _int(key: str) -> int:
        try:
            return max(0, int(r.get(key) or 0))
        except (TypeError, ValueError):
            return 0

    try:
        exp = float(r.get("expires_at") or 0)
    except (TypeError, ValueError):
        exp = 0.0
    mb, vram = _int("mb"), _int("vram_mb")
    if exp <= now or (mb <= 0 and vram <= 0):
        return {"mb": 0, "vram_mb": 0, "expires_at": 0, "active": False}
    return {"mb": mb, "vram_mb": vram, "expires_at": exp, "active": True}


@contextlib.contextmanager
def locked(path=None):
    """侧车互斥（跨进程）。忙 ⟹ `WARMING_BUSY`（调用方具名返回，不启动第二套）。"""
    p = Path(path or SIDECAR_DEFAULT)
    p.parent.mkdir(parents=True, exist_ok=True)
    lock = p.with_name(p.name + ".lock")
    fh = open(lock, "a+")
    try:
        if os.name == "nt":
            import msvcrt
            try:
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                raise TimeoutError("busy")
        else:
            import fcntl
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise TimeoutError("busy")
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except Exception:  # noqa: BLE001
            pass
        fh.close()


# ────────────────────────── 进程双键 / 端口 / health ──────────────────────────
def _pid_alive(pid: int) -> bool:
    if not pid or pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes
            k = ctypes.windll.kernel32
            h = k.OpenProcess(0x1000 | 0x00100000, False, int(pid))
            if not h:
                return False
            try:
                code = wintypes.DWORD()
                if not k.GetExitCodeProcess(h, ctypes.byref(code)):
                    return False
                return int(code.value) == 259  # STILL_ACTIVE
            finally:
                k.CloseHandle(h)
        except Exception:  # noqa: BLE001
            return False
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:  # noqa: BLE001
        return False
    # 僵尸不算活（父进程未 wait 时 kill(0) 仍成功）
    try:
        stat = Path("/proc/%d/stat" % int(pid)).read_text(encoding="utf-8", errors="replace")
        return stat.rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return True


def proc_start_time(pid: int) -> str:
    """PID 复用防护的**第二键**：Linux `/proc/<pid>/stat` field 22；Windows 创建时间。"""
    if not pid or pid <= 0:
        return ""
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes
            k = ctypes.windll.kernel32
            h = k.OpenProcess(0x1000, False, int(pid))
            if not h:
                return ""
            try:
                c = wintypes.FILETIME()
                e = wintypes.FILETIME()
                kt = wintypes.FILETIME()
                ut = wintypes.FILETIME()
                if not k.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e),
                                         ctypes.byref(kt), ctypes.byref(ut)):
                    return ""
                return str((int(c.dwHighDateTime) << 32) | int(c.dwLowDateTime))
            finally:
                k.CloseHandle(h)
        except Exception:  # noqa: BLE001
            return ""
    try:
        stat = Path("/proc/%d/stat" % int(pid)).read_text(encoding="utf-8", errors="replace")
        rest = stat.rsplit(")", 1)[1].split()
        return rest[19] if len(rest) > 19 else ""
    except OSError:
        return ""


def unit_pid(st: dict, kind: str) -> int:
    try:
        return int((st.get("pids") or {}).get(kind) or 0)
    except (TypeError, ValueError):
        return 0


def unit_alive(st: dict, kind: str) -> bool:
    pid = unit_pid(st, kind)
    if not pid or not _pid_alive(pid):
        return False
    want = str((st.get("proc_start_time") or {}).get(kind) or "")
    got = proc_start_time(pid)
    return (not want) or (not got) or want == got


def port_listening(port: int, timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def _default_probe(port: int, timeout: float = 2.0) -> dict:
    try:
        with urllib.request.urlopen(
                "http://127.0.0.1:%d/health" % int(port), timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        return {"ok": True, "data": data}
    except Exception as e:  # noqa: BLE001 — 边界：不可达即 not ok
        return {"ok": False, "error": type(e).__name__}


class SpawnUnsupported(RuntimeError):
    """默认 in-process spawn 不受支持：子进程随宿主 Job Object 被清杀（408 §9.2）。"""


def _popen_spawn(cmd: str):
    """底层 spawn 实现（2026-11-16 起**只作测试注入**；生产默认见 `_default_spawn`）。"""
    argv = shlex.split(cmd, posix=(os.name != "nt"))
    if not argv:
        raise ValueError("empty command")
    kw = {}
    if os.name == "nt":
        kw["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kw["start_new_session"] = True
    return subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)


def _default_spawn(cmd: str):
    """生产默认 = **不支持**（fail-loud）；外部 launcher 是唯一受支持路径。"""
    raise SpawnUnsupported(
        "START_UNSUPPORTED: in-process spawn is unsupported (child dies with host job object); "
        "start llama/serve with an external launcher (408 §9.2)")


# 测试注入点（生产不替换；测试须显式注入 `_popen_spawn`）
SPAWN = _default_spawn
PROBE = _default_probe
SLEEP = time.sleep


# ────────────────────────── 资源读数（单源 = gk_hub_scheduler） ──────────────────────────
def readings() -> dict:
    try:
        import gk_hub_scheduler as H  # 与 accept/subagent 并发闸共用同一读数源
        gpu = H.gpu_admit()
        return {"ok": True, "free_mb": H.free_avail_mb(), "min_free_mb": H.min_free_mb(),
                "gpu": gpu, "cpus": H.visible_cpus(),
                "max_concurrency": H.max_concurrency(),
                "adaptive_workers": H.adaptive_workers(1),
                "battery": battery_status(), "cpu_pct": cpu_percent()}
    except Exception as e:  # noqa: BLE001 — 读数不可用 ⟹ 保守不启（HOLD_NO_READING）
        return {"ok": False, "error": type(e).__name__}


# ────────────────────────── 租约 ──────────────────────────
def live_leases(st: dict, now: float | None = None) -> list:
    now = float(now if now is not None else time.time())
    out = []
    for lease in (st.get("inflight_leases") or []):
        try:
            if float(lease.get("expires_at") or 0) > now:
                out.append(lease)
        except (TypeError, ValueError):
            continue
    return out


def prune_leases(st: dict, now: float | None = None) -> int:
    """逐条回收过期租约（**不整批清零**）；返回移除条数。"""
    now = float(now if now is not None else time.time())
    keep, dropped = [], 0
    for lease in (st.get("inflight_leases") or []):
        try:
            if float(lease.get("expires_at") or 0) > now:
                keep.append(lease)
            else:
                dropped += 1
        except (TypeError, ValueError):
            dropped += 1
    st["inflight_leases"] = keep
    if dropped:
        st["reason"] = "LEASE_EXPIRED"
    return dropped


def add_lease(kind: str, owner_pid: int = 0, ttl_s: float | None = None, path=None) -> dict:
    kind = str(kind or "").strip()
    if kind not in ("raises", "monitor", "sweep"):
        return {"ok": False, "error": "LEASE_KIND_INVALID", "kind": kind}
    with locked(path):
        st = load_state(path)
        prune_leases(st)
        now = time.time()
        lid = "%s:%d:%d" % (kind, int(owner_pid or 0), time.time_ns())
        st.setdefault("inflight_leases", []).append({
            "id": lid, "kind": kind, "owner_pid": int(owner_pid or 0),
            "expires_at": now + float(ttl_s if ttl_s is not None else lease_ttl_s()),
        })
        st["last_request_at"] = now
        st["updated_at"] = now
        save_state(st, path)
    return {"ok": True, "kind": kind, "lease_id": lid,
            "leases": len(st["inflight_leases"])}


def drop_lease(lease_id: str, path=None) -> dict:
    """精确撤销一条租约（按 id；T3/T4 请求完成后立即回收，不靠 TTL 等待）。"""
    with locked(path):
        st = load_state(path)
        leases = st.get("inflight_leases") or []
        kept = [x for x in leases if str(x.get("id") or "") != str(lease_id or "")]
        st["inflight_leases"] = kept
        st["updated_at"] = time.time()
        save_state(st, path)
    return {"ok": True, "dropped": len(leases) - len(kept)}


def wiring_enabled() -> bool:
    """T3/T4 接线只有在**启停命令已配置**时才生效；未配置 ⟹ advisory（不阻断既有测试/旧部署）。"""
    return bool(llama_cmd() and serve_cmd())


def ensure(kind: str, owner_pid: int = 0, ttl_s: float | None = None, path=None) -> dict:
    """T3/T4 单源接线：加租约 → tick（走三闸）→ 等 warm；失败撤销租约并具名回报。

    未配置启停命令 ⟹ `{ok: true, advisory: "lifecycle_unconfigured", lease_id: ""}`
    （调用方继续既有行为，不伪造“已管理”）。
    """
    if not wiring_enabled():
        return {"ok": True, "advisory": "lifecycle_unconfigured", "lease_id": ""}
    st = load_state(path)
    if st.get("state") == "draining":
        return {"ok": False, "error": "DRAINING"}
    lease = add_lease(kind, owner_pid, ttl_s, path)
    if not lease.get("ok"):
        return lease
    lid = lease.get("lease_id") or ""
    deadline = time.time() + start_timeout_s() + drain_timeout_s()
    last = {}
    while time.time() < deadline:
        last = tick(path)
        if last.get("ok") and last.get("state") == "warm":
            return {"ok": True, "state": "warm", "lease_id": lid, "tick": last}
        if (not last.get("ok")) or last.get("reason") in (
                "HOLD_LOW_MEM", "HOLD_LOW_VRAM", "HOLD_NO_READING", "NO_GPU_DEGRADED",
                "BACKOFF", "PORT_TAKEN", "START_TIMEOUT", "START_CMD_UNSET", "START_FAILED",
                "START_UNSUPPORTED"):
            break
        SLEEP(0.5)
    if lid:
        drop_lease(lid, path)
    return {"ok": False, "error": last.get("error") or last.get("reason") or "NOT_WARM",
            "tick": last}


# ────────────────────────── 策略纯函数（E7 矩阵） ──────────────────────────
def decide(st: dict, rd: dict | None = None, *, now: float | None = None,
           leases: list | None = None) -> dict:
    """表驱动纯函数：返回 `{action, target, reason}`；**不写 state**。"""
    now = float(now if now is not None else time.time())
    rd = readings() if rd is None else rd
    leases = live_leases(st, now) if leases is None else list(leases)
    state = str(st.get("state") or "cold")
    m = mode()
    reason_demand = "OK_NEED_MONITOR" if any(
        str(x.get("kind")) == "monitor" for x in leases) else "OK_NEED_HOT"

    def hold(reason: str) -> dict:
        return {"action": "hold", "target": state, "reason": reason}

    def stop(reason: str) -> dict:
        return {"action": "stop", "target": "cold", "reason": reason}

    if m == "force-off":
        return stop("FORCE_OFF") if state in ("warm", "warming", "draining") else hold("FORCE_OFF")

    if state == "warm":
        if leases:
            return hold(reason_demand)
        last = float(st.get("last_request_at") or 0)
        if now - last >= idle_ttl_s():
            return {"action": "drain", "target": "draining", "reason": "STOP_TTL_EXPIRED"}
        return hold("HOLD_IDLE_TTL")

    if state == "warming":
        if now - float(st.get("updated_at") or 0) > start_timeout_s():
            return stop("START_TIMEOUT")
        return hold("WARMING_BUSY")

    if state == "draining":
        if leases:
            return hold(reason_demand)
        if now - float(st.get("updated_at") or 0) > drain_timeout_s():
            return stop("DRAIN_TIMEOUT")
        return stop("STOP_DRAINED")

    # cold
    demand = bool(leases) or m == "force-on"
    if not demand:
        return hold("HOLD_IDLE_TTL")
    if now < float((st.get("backoff") or {}).get("next_retry_at") or 0):
        return hold("BACKOFF")
    gpu = (rd or {}).get("gpu") or {}
    if m == "force-on":
        if gpu.get("reason") == "low_vram":
            return hold("HOLD_LOW_VRAM")
        return {"action": "start", "target": "warming", "reason": "FORCE_ON"}
    cap = min_battery_pct()
    bat = (rd or {}).get("battery") or {}
    if (cap is not None and bat.get("ok") and bat.get("on_ac") is False
            and bat.get("pct") is not None and int(bat["pct"]) <= cap):
        return hold("HOLD_ON_BATTERY")
    if not rd or not rd.get("ok"):
        return hold("HOLD_NO_READING")
    if gpu.get("reason") == "no_gpu":
        return hold("NO_GPU_DEGRADED")
    if gpu.get("reason") == "low_vram":
        return hold("HOLD_LOW_VRAM")
    free_mb, floor = rd.get("free_mb"), rd.get("min_free_mb")
    if free_mb is None:
        return hold("HOLD_NO_READING")
    if floor and int(free_mb) < int(floor):
        return hold("HOLD_LOW_MEM")
    return {"action": "start", "target": "warming", "reason": reason_demand}


# ────────────────────────── 启停实现 ──────────────────────────
def _terminate(pid: int, timeout: float = 5.0) -> bool:
    """先 SIGTERM（进程组）→ 等 → SIGKILL；返回是否已消失。"""
    if not pid or not _pid_alive(pid):
        return True
    try:
        if os.name != "nt":
            try:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
            except OSError:
                os.kill(pid, signal.SIGTERM)
        else:
            os.kill(pid, signal.SIGTERM)
    except OSError:
        pass
    deadline = time.time() + max(0.1, timeout)
    while time.time() < deadline:
        if not _pid_alive(pid):
            return True
        SLEEP(0.1)
    try:
        if os.name != "nt":
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except OSError:
                os.kill(pid, signal.SIGKILL)
        else:
            subprocess.run(["taskkill", "/PID", str(int(pid)), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           check=False)
    except Exception:  # noqa: BLE001
        pass
    for _ in range(20):
        if not _pid_alive(pid):
            return True
        SLEEP(0.1)
    return not _pid_alive(pid)


def _spawn_unit(st: dict, kind: str, cmd: str) -> dict:
    if not cmd:
        return {"ok": False, "error": "START_CMD_UNSET", "kind": kind}
    try:
        proc = SPAWN(cmd)
    except SpawnUnsupported:
        return {"ok": False, "error": "START_UNSUPPORTED", "kind": kind,
                "detail": "external_launcher_required"}
    except Exception as e:  # noqa: BLE001 — spawn 异常具名回报
        return {"ok": False, "error": "START_FAILED", "kind": kind,
                "detail": type(e).__name__}
    pid = int(getattr(proc, "pid", 0) or 0)
    st.setdefault("pids", {})[kind] = pid
    st.setdefault("proc_start_time", {})[kind] = proc_start_time(pid)
    return {"ok": True, "kind": kind, "pid": pid}


def _start_unit(st: dict, path=None, *, force_reason: str = "") -> dict:
    now = time.time()
    # 端口占用：非我方进程 ⟹ fail-loud，不 spawn
    for port, kind in ((llama_port(), "llama"), (serve_port(), "serve")):
        if port_listening(port) and not unit_alive(st, kind):
            st["reason"] = "PORT_TAKEN"
            st["updated_at"] = now
            save_state(st, path)
            return {"ok": False, "error": "PORT_TAKEN", "port": port, "kind": kind}
    st["state"] = "warming"
    st["reason"] = force_reason or "OK_NEED_HOT"
    st["updated_at"] = now
    st["reserved"] = {"mb": 1024, "vram_mb": 0, "expires_at": now + start_timeout_s()}
    save_state(st, path)
    r1 = _spawn_unit(st, "llama", llama_cmd())
    if not r1.get("ok"):
        st["state"], st["reason"] = "cold", r1.get("error") or "START_FAILED"
        # 2026-11-16（408 ⑦）：失败路径必须**清零预留** —— 原实现留下 1024MB 幽灵预留
        #   直到 `start_timeout_s()`（~90s）；生产默认 spawn=unsupported 时每次尝试都会误拒 accept。
        st["reserved"] = {"mb": 0, "vram_mb": 0, "expires_at": 0}
        st["updated_at"] = time.time()
        save_state(st, path)
        return {"ok": False, "error": st["reason"], "step": "llama"}
    r2 = _spawn_unit(st, "serve", serve_cmd())
    save_state(st, path)
    if not r2.get("ok"):
        _terminate(unit_pid(st, "llama"))
        st["pids"] = {"llama": 0, "serve": 0}
        st["proc_start_time"] = {"llama": "", "serve": ""}
        st["state"], st["reason"] = "cold", r2.get("error") or "START_FAILED"
        st["reserved"] = {"mb": 0, "vram_mb": 0, "expires_at": 0}   # 408 ⑦：同上，不留幽灵预留
        st["updated_at"] = time.time()
        save_state(st, path)
        return {"ok": False, "error": st["reason"], "step": "serve"}
    # 等 health ready（超时 ⟹ 反序停 + backoff）
    deadline = now + start_timeout_s()
    last = {}
    while time.time() < deadline:
        last = PROBE(serve_port())
        if last.get("ok"):
            st["state"] = "warm"
            st["reason"] = force_reason or "OK_NEED_HOT"
            st["last_request_at"] = time.time()
            st["reserved"] = {"mb": 0, "vram_mb": 0, "expires_at": 0}
            st["backoff"] = {"attempts": 0, "next_retry_at": 0.0}
            st["updated_at"] = time.time()
            save_state(st, path)
            return {"ok": True, "state": "warm", "reason": st["reason"],
                    "pids": dict(st["pids"]), "health": last.get("data")}
        SLEEP(min(0.5, max(0.05, deadline - time.time())))
    _terminate(unit_pid(st, "serve"))
    _terminate(unit_pid(st, "llama"))
    attempts = int((st.get("backoff") or {}).get("attempts") or 0) + 1
    st["pids"] = {"llama": 0, "serve": 0}
    st["proc_start_time"] = {"llama": "", "serve": ""}
    st["state"], st["reason"] = "cold", "START_TIMEOUT"
    st["backoff"] = {"attempts": attempts,
                     "next_retry_at": time.time() + min(backoff_max_s(), 2 ** attempts)}
    st["reserved"] = {"mb": 0, "vram_mb": 0, "expires_at": 0}
    st["updated_at"] = time.time()
    save_state(st, path)
    return {"ok": False, "error": "START_TIMEOUT", "health": last}


def _stop_unit(st: dict, reason: str, path=None) -> dict:
    st["state"] = "draining"
    st["updated_at"] = time.time()
    save_state(st, path)
    ok_serve = _terminate(unit_pid(st, "serve"))
    ok_llama = _terminate(unit_pid(st, "llama"))
    st["pids"] = {"llama": 0, "serve": 0}
    st["proc_start_time"] = {"llama": "", "serve": ""}
    st["reserved"] = {"mb": 0, "vram_mb": 0, "expires_at": 0}
    st["state"] = "cold"
    st["reason"] = reason if (ok_serve and ok_llama) else "STOP_FAILED"
    st["updated_at"] = time.time()
    save_state(st, path)
    return {"ok": bool(ok_serve and ok_llama), "state": st["state"],
            "reason": st["reason"], "stopped": {"serve": ok_serve, "llama": ok_llama}}


def _reconcile(st: dict) -> dict:
    """把 sidecar 与实际进程对齐（只改内存；调用方决定是否落盘）。"""
    if st.get("state") in ("warm", "warming", "draining"):
        alive = {k: unit_alive(st, k) for k in ("llama", "serve")}
        if st["state"] == "warm" and not all(alive.values()):
            st["state"], st["reason"] = "draining", "STOP_FAILED"
        elif st["state"] == "warming" and not any(alive.values()):
            st["state"], st["reason"] = "cold", "START_TIMEOUT"
        st["_alive"] = alive
    else:
        st["_alive"] = {"llama": False, "serve": False}
    return st


# ────────────────────────── 对外动作 ──────────────────────────
def status(path=None) -> dict:
    st = _reconcile(load_state(path))
    rd = readings()
    now = time.time()
    return {"ok": True, "state": st.get("state"), "reason": st.get("reason"),
            "launcher": st.get("launcher", "external"),
            "pids": st.get("pids"), "alive": st.get("_alive"),
            "leases": len(live_leases(st, now)),
            "last_request_at": st.get("last_request_at"),
            "backoff": st.get("backoff"), "reserved": st.get("reserved"),
            "readings": rd, "sidecar": str(Path(path or SIDECAR_DEFAULT)),
            "updated_at": st.get("updated_at")}


def tick(path=None) -> dict:
    try:
        with locked(path):
            st = load_state(path)
            st = _reconcile(st)
            now = time.time()
            dropped = prune_leases(st, now)
            leases = live_leases(st, now)
            rd = readings()
            d = decide(st, rd, now=now, leases=leases)
            if leases and st.get("state") == "warm":
                st["last_request_at"] = now
            if d["action"] == "start":
                res = _start_unit(st, path)
            elif d["action"] in ("drain", "stop"):
                # drain 只在租约清零后由 decide 返回；直接排空收口
                res = _stop_unit(st, d["reason"], path)
            else:
                st["reason"] = d["reason"]
                st["updated_at"] = now
                save_state(st, path)
                res = {"ok": True, "state": st["state"], "reason": d["reason"]}
            res.update({"decision": d, "dropped_leases": dropped,
                        "leases": len(leases)})
            return res
    except TimeoutError:
        return {"ok": False, "error": "WARMING_BUSY", "reason": "WARMING_BUSY"}


def start(path=None, *, force: bool = False) -> dict:
    try:
        with locked(path):
            st = load_state(path)
            st = _reconcile(st)
            if st.get("state") in ("warm", "warming") and not force:
                return {"ok": False, "error": "WARMING_BUSY",
                        "state": st.get("state"), "pids": st.get("pids")}
            if st.get("state") == "draining" and not force:
                return {"ok": False, "error": "WARMING_BUSY", "state": "draining"}
            return _start_unit(st, path, force_reason="FORCE_ON")
    except TimeoutError:
        return {"ok": False, "error": "WARMING_BUSY", "reason": "WARMING_BUSY"}


def stop(path=None) -> dict:
    try:
        with locked(path):
            st = load_state(path)
            return _stop_unit(st, "FORCE_OFF", path)
    except TimeoutError:
        return {"ok": False, "error": "WARMING_BUSY", "reason": "WARMING_BUSY"}


# ────────────────────────── CLI ──────────────────────────
def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="审计署 4B 模型自适应启停（408 T1/T2）")
    p.add_argument("cmd", choices=("status", "decide", "tick", "start", "stop", "lease"))
    p.add_argument("--sidecar", default="", help="sidecar 路径（默认 <repo>/.gatekeeper.audit_lifecycle.json）")
    p.add_argument("--json", action="store_true", help="JSON 输出（缺省即 JSON）")
    p.add_argument("--kind", default="", help="lease --kind raises|monitor|sweep")
    p.add_argument("--pid", type=int, default=0, help="lease --pid（owner）")
    p.add_argument("--ttl", type=float, default=None, help="lease --ttl 秒")
    p.add_argument("--force", action="store_true", help="start 强制（已 warm 也重启）")
    ns = p.parse_args(argv)
    path = ns.sidecar or None
    if ns.cmd == "status":
        out = status(path)
    elif ns.cmd == "decide":
        st = _reconcile(load_state(path))
        out = decide(st, readings(), leases=live_leases(st))
        # 决策是**成功输出**（hold/stop/start 都是有效判决），不是失败；CLI rc 必须 0。
        out = {"ok": True, **out}
    elif ns.cmd == "tick":
        out = tick(path)
    elif ns.cmd == "start":
        out = start(path, force=ns.force)
    elif ns.cmd == "stop":
        out = stop(path)
    else:
        out = add_lease(ns.kind, ns.pid, ns.ttl, path)
    print(json.dumps(out, ensure_ascii=False))
    if not out.get("ok"):
        return 4 if out.get("error") == "WARMING_BUSY" else 3
    return 0


if __name__ == "__main__":
    sys.exit(main())

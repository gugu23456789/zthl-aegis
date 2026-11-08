#!/usr/bin/env python3
"""gk_hub_scheduler 回归：跨进程槽位限流 / 内存闸 / 准入 fail-loud / 释放语义。

隔离：所有用例经 `GK_HUB_SLOTS_ROOT` 指向 tmp_path，**禁止**污染系统临时槽位目录。
"""
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_hub_scheduler as hs  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_slots(tmp_path, monkeypatch):
    monkeypatch.setenv("GK_HUB_SLOTS_ROOT", str(tmp_path / "slots"))
    yield


# ── 参数单源 ──────────────────────────────────────────────────────────
def test_max_concurrency_default_64(monkeypatch):
    monkeypatch.delenv("GK_HUB_MAX_CONCURRENCY", raising=False)
    assert hs.max_concurrency() == 64


def test_max_concurrency_env_and_invalid(monkeypatch):
    monkeypatch.setenv("GK_HUB_MAX_CONCURRENCY", "8")
    assert hs.max_concurrency() == 8
    for bad in ("0", "-3", "abc", ""):
        monkeypatch.setenv("GK_HUB_MAX_CONCURRENCY", bad)
        assert hs.max_concurrency() == 64, bad


def test_min_free_mb_default_512(monkeypatch):
    monkeypatch.delenv("GK_HUB_MIN_FREE_MB", raising=False)
    assert hs.min_free_mb() == 512


def test_free_avail_mb_is_positive_int_or_none():
    v = hs.free_avail_mb()
    assert v is None or (isinstance(v, int) and v > 0)


# ── 硬件自适应并发度（s5.5：全仓**单源**，中枢拥有）─────────────────────
def test_visible_cpus_affinity_aware(monkeypatch):
    """容器/绑核下 affinity 可见核数**优先**于 os.cpu_count（防按宿主全核过度订阅 → OOM/排队）。"""
    monkeypatch.setattr(hs.os, "sched_getaffinity", lambda pid: {0, 1, 2}, raising=False)
    monkeypatch.setattr(hs.os, "cpu_count", lambda: 64)
    assert hs.visible_cpus() == 3


def test_visible_cpus_fallback_to_cpu_count(monkeypatch):
    monkeypatch.setattr(hs.os, "sched_getaffinity", None, raising=False)  # 探测异常 → 回落
    monkeypatch.setattr(hs.os, "cpu_count", lambda: 8)
    assert hs.visible_cpus() == 8


def test_adaptive_workers_env_single_source(monkeypatch):
    """reserve/cap 均 env 单源（换设备不靠改代码）——无硬编码。"""
    monkeypatch.setattr(hs, "visible_cpus", lambda: 16)
    monkeypatch.setattr(hs, "free_avail_mb", lambda: 10 ** 9)   # 内存不设限
    monkeypatch.setenv("GK_HUB_WORKERS_RESERVE", "4")
    monkeypatch.delenv("GK_HUB_WORKERS_CAP", raising=False)
    assert hs.adaptive_workers(100) == 12
    monkeypatch.setenv("GK_HUB_WORKERS_CAP", "5")
    assert hs.adaptive_workers(100) == 5


def test_adaptive_workers_memory_floor_clamps(monkeypatch):
    monkeypatch.setattr(hs, "visible_cpus", lambda: 16)
    monkeypatch.setattr(hs, "free_avail_mb", lambda: 100)
    assert hs.adaptive_workers(100, min_free_mb=512) == 1
    assert hs.adaptive_workers(100, min_free_mb=0) == 15       # 下限 0 ⟹ 不设内存闸


def test_adaptive_workers_floor_and_todo_clamp(monkeypatch):
    monkeypatch.setattr(hs, "visible_cpus", lambda: 1)
    monkeypatch.setattr(hs, "free_avail_mb", lambda: 10 ** 9)
    assert hs.adaptive_workers(100) == 1        # 保底 1
    assert hs.adaptive_workers(0) == 1
    monkeypatch.setattr(hs, "visible_cpus", lambda: 16)
    assert hs.adaptive_workers(3) == 3          # 不超过待办数


def test_adaptive_workers_subprocess_formula(monkeypatch):
    """408 公式（f>0）：W = min( (核-4)/(1+f), 0.6R/(180+60f), 80/(1+f), cap/8, todo )。

    实测锚（本机 16 核 / 6.5GB，重活四文件）：n=1 59.0s / n=2 53.0s / n=4 49.5s /
    n=6 46.6s ⟹ plateau≈4；f=2 在 16 核推出 4，与实测吻合。f=0 必须保持旧口径。
    """
    monkeypatch.delenv("GK_HUB_WORKERS_CAP", raising=False)
    monkeypatch.setattr(hs, "visible_cpus", lambda: 16)
    monkeypatch.setattr(hs, "free_avail_mb", lambda: 6656)
    assert hs.adaptive_workers(1000, subprocess_factor=2) == 4, \
        "16 核 / 6.5GB / f=2 ⟹ 4（核项 (16-4)/3=4 先于内存项 13 生效，对齐实测 plateau）"

    monkeypatch.setattr(hs, "free_avail_mb", lambda: 10 ** 9)
    assert hs.adaptive_workers(1000, subprocess_factor=3) == 3      # (16-4)/4
    assert hs.adaptive_workers(1000, subprocess_factor=1) == 6      # (16-4)/2
    monkeypatch.setattr(hs, "visible_cpus", lambda: 8)
    assert hs.adaptive_workers(1000, subprocess_factor=1) == 2      # (8-4)/2

    # 内存项单独生效：0.6R/(180+60f) 把 16 核压到 1（R=600MB, f=2 ⟹ 360/300=1.2）
    monkeypatch.setattr(hs, "visible_cpus", lambda: 16)
    monkeypatch.setattr(hs, "free_avail_mb", lambda: 600)
    assert hs.adaptive_workers(1000, subprocess_factor=2) == 1

    # 进程预算硬顶 80/(1+f)：超大核数下 f=40 ⟹ 1（Windows >600 进程即换页）
    monkeypatch.setattr(hs, "visible_cpus", lambda: 100000)
    monkeypatch.setattr(hs, "free_avail_mb", lambda: 10 ** 9)
    assert hs.adaptive_workers(1000, subprocess_factor=40) == 1

    # cap 与 todo 仍能收紧（cap 显式传入优先于缺省 8）
    monkeypatch.setattr(hs, "visible_cpus", lambda: 16)
    assert hs.adaptive_workers(1000, cap=4, subprocess_factor=1) == 4
    assert hs.adaptive_workers(3, subprocess_factor=1) == 3


def test_adaptive_workers_f_zero_keeps_legacy(monkeypatch):
    """f=0（纯 python 批）必须与旧口径逐位一致（向后兼容，不改既有调度）。"""
    monkeypatch.delenv("GK_HUB_WORKERS_CAP", raising=False)
    monkeypatch.setenv("GK_HUB_WORKERS_RESERVE", "1")
    monkeypatch.setattr(hs, "visible_cpus", lambda: 16)
    monkeypatch.setattr(hs, "free_avail_mb", lambda: 10 ** 9)
    assert hs.adaptive_workers(100) == 15
    assert hs.adaptive_workers(100, subprocess_factor=0) == 15
    assert hs.adaptive_workers(100, subprocess_factor=-1) == 15   # 负值视同未启用


# ── 槽位限流（跨 fd / 跨线程） ─────────────────────────────────────────
def test_slot_cap_enforced():
    root = hs.slots_root()
    a = hs.try_acquire(root, 2, 0.0)
    b = hs.try_acquire(root, 2, 0.0)
    c = hs.try_acquire(root, 2, 0.0)
    assert a and b and c is None, "第 3 个不得拿到槽位（硬上限）"
    hs.release(a[0])
    hs.release(b[0])


def test_release_frees_slot():
    root = hs.slots_root()
    a = hs.try_acquire(root, 1, 0.0)
    assert a is not None
    assert hs.try_acquire(root, 1, 0.0) is None
    hs.release(a[0])
    b = hs.try_acquire(root, 1, 0.0)
    assert b is not None
    hs.release(b[0])


def test_concurrency_never_exceeds_cap_under_threads():
    root = hs.slots_root()
    cap = 4
    live = {"now": 0, "peak": 0}
    lock = threading.Lock()
    gate_ok = threading.Semaphore(0)
    start = threading.Event()

    def worker():
        start.wait()
        got = hs.try_acquire(root, cap, 5.0)
        assert got is not None, "5s 内应能抢到槽位"
        with lock:
            live["now"] += 1
            live["peak"] = max(live["peak"], live["now"])
        time.sleep(0.05)
        with lock:
            live["now"] -= 1
        hs.release(got[0])
        gate_ok.release()

    ts = [threading.Thread(target=worker) for _ in range(20)]
    for t in ts:
        t.start()
    start.set()
    for t in ts:
        t.join()
    assert live["peak"] <= cap, "峰值并发 %d 超过上限 %d" % (live["peak"], cap)
    assert live["peak"] > 1, "并发未真正发生（用例退化）"


# ── 准入（内存闸 → 槽位闸） ────────────────────────────────────────────
def test_admit_low_memory_fail_loud(monkeypatch):
    monkeypatch.setattr(hs, "free_avail_mb", lambda: 100)
    r = hs.admit(min_mb=512, timeout_s=0.0)
    assert r["ok"] is False and r["reason"] == "low_memory" and r["free_mb"] == 100


def test_admit_memory_none_does_not_block(monkeypatch):
    monkeypatch.setattr(hs, "free_avail_mb", lambda: None)
    r = hs.admit(max_c=1, min_mb=512, timeout_s=0.0)
    assert r["ok"] is True and r["free_mb"] is None
    hs.release(r["fd"])


def test_admit_low_slots_fail_loud():
    root = hs.slots_root()
    a = hs.try_acquire(root, 1, 0.0)
    assert a is not None
    r = hs.admit(root, max_c=1, min_mb=0, timeout_s=0.0)
    assert r["ok"] is False and r["reason"] == "low_slots"
    hs.release(a[0])


def test_gate_releases_on_exception():
    root = hs.slots_root()
    with pytest.raises(RuntimeError):
        with hs.gate(root, max_c=1, min_mb=0, timeout_s=0.0):
            raise RuntimeError("boom")
    got = hs.try_acquire(root, 1, 0.0)      # 异常后槽位必须已释放
    assert got is not None
    hs.release(got[0])


def test_gate_denied_raises_with_reason(monkeypatch):
    monkeypatch.setattr(hs, "free_avail_mb", lambda: 1)
    with pytest.raises(hs.HubGateDenied) as e:
        with hs.gate(min_mb=512, timeout_s=0.0):
            pass
    assert e.value.result["reason"] == "low_memory"


# ── 只读体检 + CLI ────────────────────────────────────────────────────
def test_status_shape():
    s = hs.status()
    assert s["max_concurrency"] >= 1
    assert set(s) >= {"max_concurrency", "min_free_mb", "free_mb", "occupied", "slots_root"}


def test_cli_status_rc0(capsys):
    assert hs.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "max_concurrency" in out


def test_cli_run_denied_tempfail(monkeypatch, capsys):
    monkeypatch.setattr(hs, "free_avail_mb", lambda: 1)
    rc = hs.main(["run", "--min-free-mb", "512", "--", sys.executable, "-c", "print(1)"])
    assert rc == 75, "放行失败须 EX_TEMPFAIL（可重试），非 0"

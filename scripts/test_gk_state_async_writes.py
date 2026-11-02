#!/usr/bin/env python3
"""test_gk_state_async_writes.py — A2（2026-10-28）落刀锁：锁观测 + 异步单写者

A2 裁定两句各对应一组臂：
  · 「state lock timeout=0 命中**不可**当无瓶颈证据（BLOCK 路径吞异常）」
    ⟹ 锁统计必须把**每次**取锁/超时（含 timeout=0）记账，不管调用方是否吞掉异常。
  · 「写路径保持单写者但**异步化**」
    ⟹ 单写者队列：串行、保序、调用方不阻塞、退出 flush、失败不静默。
"""
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import gk_json_utils as J  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_stats():
    J.reset_state_lock_stats()
    yield
    J.reset_state_lock_stats()
    try:
        J.flush_state_writes(timeout=5.0, strict=False)
    except Exception:
        pass


# ─── 锁观测 ────────────────────────────────────────────────────────────────

def test_stats_counts_acquire_and_reentrant(tmp_path):
    p = tmp_path / "s.json"
    with J.state_lock(p):
        with J.state_lock(p):      # 可重入 ⟹ 只加深度
            pass
    st = J.state_lock_stats()
    assert st["acquired"] == 1
    assert st["reentrant"] == 1
    assert st["timeouts"] == 0


def test_stats_counts_timeout_even_when_swallowed(tmp_path):
    """BLOCK 路径吞 TimeoutError ⟹ 计数仍须 +1（否则「0 命中」可被伪造）。"""
    if J.fcntl is None:
        pytest.skip("需要 fcntl（POSIX）来构造外部持锁")
    p = tmp_path / "s.json"
    lf = J.state_lock_path(str(p))
    os.makedirs(os.path.dirname(lf) or ".", exist_ok=True)
    fd = os.open(lf, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        J.fcntl.flock(fd, J.fcntl.LOCK_EX)      # 同进程不同 fd ⟹ 另一把锁描述符，会互斥
        try:
            with J.state_lock(p, timeout=0.0):
                pass
        except TimeoutError:
            pass                                # 模拟 BLOCK 路径吞异常
    finally:
        os.close(fd)
    st = J.state_lock_stats()
    assert st["timeouts"] == 1, "超时未记账 ⟹ 吞异常的 BLOCK 路径不可观测"
    assert st["last_timeout_s"] == 0.0
    assert st["last_timeout_path"].endswith("s.json")


# ─── 异步单写者 ────────────────────────────────────────────────────────────

def test_dump_state_async_flushes(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"a": 1}), encoding="utf-8")
    J.dump_state_async(p, {"a": 2})
    r = J.flush_state_writes(timeout=10.0)
    assert r["pending"] == 0 and r["error_count"] == 0
    assert json.loads(p.read_text(encoding="utf-8"))["a"] == 2


def test_submit_preserves_order(tmp_path):
    p = tmp_path / "log.jsonl"
    p.write_text("", encoding="utf-8")

    def _append(i):
        def _fn():
            with open(p, "a", encoding="utf-8") as f:
                f.write("%d\n" % i)
        return _fn

    for i in range(6):
        J.submit_state_write(p, _append(i))
    J.flush_state_writes(timeout=10.0)
    assert p.read_text(encoding="utf-8").split() == [str(i) for i in range(6)]


def test_flush_surfaces_error_fail_loud(tmp_path):
    def _boom():
        raise ValueError("disk on fire")

    J.submit_state_write(tmp_path / "x.json", _boom)
    r = J.flush_state_writes(timeout=10.0, strict=False)
    assert r["error_count"] == 1 and "disk on fire" in r["errors"][0]["error"]
    # 取走即清空 ⟹ 下一次 flush 不再重复报同一错误
    assert J.flush_state_writes(timeout=5.0, strict=False)["error_count"] == 0


def test_flush_strict_raises_on_error(tmp_path):
    J.submit_state_write(tmp_path / "y.json", lambda: (_ for _ in ()).throw(OSError("nope")))
    with pytest.raises(RuntimeError):
        J.flush_state_writes(timeout=10.0, strict=True)


def test_submit_is_nonblocking(tmp_path):
    """调用方不等待落盘：submit 返回后队列/写者可仍在跑（用慢任务证明）。"""
    import time
    p = tmp_path / "slow.json"
    J.submit_state_write(p, lambda: time.sleep(0.4))
    t0 = time.monotonic()
    J.submit_state_write(p, lambda: time.sleep(0.4))
    assert time.monotonic() - t0 < 0.3, "submit 被落盘阻塞"
    J.flush_state_writes(timeout=10.0)


# ─── 生产接线：sniffnet 遥测走异步通道 ────────────────────────────────────

def test_sniffnet_ingest_goes_through_queue(tmp_path, monkeypatch):
    import sniffnet_webhook as SW

    st = tmp_path / "state.json"
    st.write_text(json.dumps({"gate_data": {}}), encoding="utf-8")
    monkeypatch.setattr(SW, "STATE_FILE", str(st))
    SW.submit_state_write(str(st), lambda: SW._ingest_alert(
        {"timestamp": "t", "source": "sniffnet", "type": "x", "data": {}}))
    J.flush_state_writes(timeout=10.0)
    d = json.loads(st.read_text(encoding="utf-8"))
    assert d["gate_data"]["_sniffnet_alerts"][0]["source"] == "sniffnet"

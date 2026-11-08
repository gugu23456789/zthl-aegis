#!/usr/bin/env python3
"""test_gk_state_wal.py — M1 WAL 正确性（追加 / 重放 / 修复 / checkpoint / 失败语义）。

只测**行为契约**，不绑定记录字段以外的实现细节：
  · 逻辑写只追加 WAL，读侧 = checkpoint + replay（语义等价于整份读写）；
  · 尾部半行（崩溃常态）被忽略；下一次写先修复再追加；
  · checkpoint 后 WAL 截断，state 文件即最新完整 JSON；
  · WAL 写失败 **fail-loud**，不得静默降级为整份写；
  · 进程退出时把本进程留下的记录折回 state（bash/外部 raw 读取的既有契约）。
"""
import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import gk_json_utils as J  # noqa: E402
import gk_state_wal as W  # noqa: E402


def _mk(tmp_path) -> str:
    p = tmp_path / "s.json"
    d = {"stage": "T", "gate_data": {"n": 0, "items": []}}
    d["_checksum"] = J._state_checksum(d)
    assert J.dump_state(str(p), d)
    return str(p)


def _bump(d):
    gd = d.setdefault("gate_data", {})
    gd["n"] = int(gd.get("n", 0) or 0) + 1


@pytest.fixture(autouse=True)
def _clean_caches():
    W.shutdown_timer()
    W._TOUCHED.clear()
    W._CHECKPOINT_CACHE.clear()
    W._GC_LAST.clear()
    W._LAST_WRITE.clear()
    for fd in list(W._READ_FD.values()) + list(W._APPEND_FD.values()):
        try:
            os.close(fd)
        except OSError:
            pass
    W._READ_FD.clear()
    W._APPEND_FD.clear()
    W._WAL_REAL.clear()
    yield
    W.shutdown_timer()
    W._TOUCHED.clear()


def test_append_then_replay_matches_memory(tmp_path):
    p = _mk(tmp_path)
    for _ in range(5):
        r = J.update_state(p, _bump)
        assert r.get("ok"), r
    # 未到 checkpoint 阈值 ⟹ 磁盘 state 还是旧快照
    assert J.read_json_file(p)["gate_data"]["n"] == 0
    d = J.read_state_file(p)
    assert d["gate_data"]["n"] == 5
    assert d["_wal_seq"] == 5
    assert d["_checksum"] == J._state_checksum(d)


def test_diff_apply_extend_and_del():
    old = {"gate_data": {"items": [1, 2], "gone": 1}}
    new = {"gate_data": {"items": [1, 2, 3]}}
    ops = W.diff(old, new, [])
    assert any(o["op"] == "extend" for o in ops)
    assert any(o["op"] == "del" for o in ops)
    assert W.apply_ops(copy.deepcopy(old), ops) == new


def test_torn_tail_ignored_then_repaired(tmp_path):
    p = _mk(tmp_path)
    assert J.update_state(p, _bump).get("ok")
    with open(p + W.WAL_SUFFIX, "a", encoding="utf-8") as f:
        f.write('{"seq": 2, "pid": 1, "ts": "x", "ops": [')
    d = J.read_state_file(p)
    assert d["gate_data"]["n"] == 1
    assert d.get("_wal_warning"), "尾部坏行必须显式告警，不得当无事发生"
    r = J.update_state(p, _bump)                 # 先 checkpoint 修复，再追加
    assert r.get("ok"), r
    assert r["data"]["gate_data"]["n"] == 2
    assert not J.read_state_file(p).get("_wal_warning")


def test_checkpoint_truncates_wal(tmp_path, monkeypatch):
    monkeypatch.setattr(W, "CHECKPOINT_RECORDS", 3)
    p = _mk(tmp_path)
    for _ in range(3):
        assert J.update_state(p, _bump).get("ok")
    raw = J.read_json_file(p)
    assert raw["gate_data"]["n"] == 3
    assert raw["_wal_seq"] == 3
    assert os.path.getsize(p + W.WAL_SUFFIX) == 0
    assert J.read_state_file(p)["gate_data"]["n"] == 3


def test_age_bound_triggers_checkpoint(tmp_path, monkeypatch):
    """长驻进程：最老未 checkpoint 记录超龄 ⟹ 下一次写顺手整份落盘（陈旧上限）。"""
    monkeypatch.setattr(W, "CHECKPOINT_MAX_AGE_S", -1.0)   # 任何既有记录都算超龄
    p = _mk(tmp_path)
    assert J.update_state(p, _bump).get("ok")
    assert os.path.getsize(p + W.WAL_SUFFIX) > 0           # 首次写：无既有记录 ⟹ 只追加
    assert J.update_state(p, _bump).get("ok")              # 第二次写：触发超龄 checkpoint
    assert os.path.getsize(p + W.WAL_SUFFIX) == 0
    raw = J.read_json_file(p)
    assert raw["gate_data"]["n"] == 2 and raw["_wal_seq"] == 2


def test_wal_write_failure_is_loud_and_no_full_write(tmp_path, monkeypatch):
    p = _mk(tmp_path)
    before = Path(p).read_bytes()

    def _boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(W, "append_record", _boom)
    r = J.update_state(p, lambda d: d["gate_data"].__setitem__("n", 9))
    assert "wal_write_failed" in (r.get("error") or "")
    assert Path(p).read_bytes() == before, "WAL 失败不得静默降级为整份写"


def test_flush_pending_writes_full_state(tmp_path):
    p = _mk(tmp_path)
    assert J.update_state(p, _bump).get("ok")
    r = W.flush_pending(p)
    assert r.get("ok") and r.get("flushed"), r
    raw = J.read_json_file(p)
    assert raw["gate_data"]["n"] == 1
    assert raw["_wal_seq"] == 1
    assert raw["_checksum"] == J._state_checksum(raw)
    assert os.path.getsize(p + W.WAL_SUFFIX) == 0
    st = os.stat(p).st_mtime_ns
    assert W.flush_pending(p).get("flushed") is False   # 无本进程记录 ⟹ 零写盘
    assert os.stat(p).st_mtime_ns == st


def test_concurrent_processes_no_lost_update_and_exit_flush(tmp_path):
    p = _mk(tmp_path)
    n_proc, n_ops = 8, 5
    child = (
        "import os,sys\n"
        "sys.path.insert(0, os.environ['GK_SCRIPTS'])\n"
        "import gk_json_utils as J\n"
        "def bump(d):\n"
        "    gd = d.setdefault('gate_data', {})\n"
        "    gd['n'] = int(gd.get('n', 0) or 0) + 1\n"
        "for _ in range(int(os.environ['GK_OPS'])):\n"
        "    r = J.update_state(os.environ['GK_STATE'], bump)\n"
        "    sys.exit(0) if not r.get('ok') else None\n"
    )
    env = dict(os.environ, GK_SCRIPTS=str(HERE), GK_STATE=p,
               GK_OPS=str(n_ops), PYTHONPATH=str(HERE))
    ps = [subprocess.Popen([sys.executable, "-c", child], env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
          for _ in range(n_proc)]
    for q in ps:
        _, err = q.communicate(timeout=180)
        assert q.returncode == 0, err.decode("utf-8", "replace")[:400]
    d = J.read_state_file(p)
    assert d["gate_data"]["n"] == n_proc * n_ops, "并发 update_state 丢更新"
    # 每个子进程退出时把自己的记录折回 state ⟹ 最后一个退出者应留下完整磁盘快照
    raw = J.read_json_file(p)
    assert raw["gate_data"]["n"] == n_proc * n_ops, "退出 flush 未把 WAL 折回 state"
    assert raw["_checksum"] == J._state_checksum(raw)


# ── S2：checkpoint 周期化 + .tmp 残留回收（M1b + M4）─────────────────────────
def test_stale_tmp_reclaimed_fresh_tmp_kept(tmp_path):
    """超过宽限期的 `.tmp` 在下一次写时被回收；新鲜 tmp 不动（可能仍在写）。"""
    import time
    p = _mk(tmp_path)
    stale = Path(p + ".deadbeef.tmp")
    stale.write_text("{ broken", encoding="utf-8")
    old = time.time() - 3600
    os.utime(str(stale), (old, old))
    fresh = Path(p + ".cafe.tmp")
    fresh.write_text("{ broken", encoding="utf-8")
    assert J.update_state(p, _bump).get("ok")
    assert not stale.exists(), "陈旧 .tmp 未回收 ⟹ 崩溃残留永久堆积"
    assert fresh.exists(), "新鲜 .tmp 被误删（可能正在写）"


def test_gc_tmp_returns_count_and_respects_grace(tmp_path):
    import time
    p = _mk(tmp_path)
    a = Path(p + ".a.tmp")
    b = Path(p + ".b.tmp")
    a.write_text("x", encoding="utf-8")
    b.write_text("x", encoding="utf-8")
    old = time.time() - 100
    os.utime(str(a), (old, old))
    n = W.gc_tmp(p, grace_s=10.0)
    assert n == 1 and not a.exists() and b.exists()


def test_idle_process_checkpoints_without_further_write(tmp_path, monkeypatch):
    """长驻进程写出后完全 idle：后台 tick 必须把超龄 WAL 折回 state。"""
    import time
    monkeypatch.setattr(W, "IDLE_CHECKPOINT_AGE_S", 0.0)
    monkeypatch.setattr(W, "IDLE_TICK_S", 0.05)
    p = _mk(tmp_path)
    assert J.update_state(p, _bump).get("ok")
    assert os.path.getsize(p + W.WAL_SUFFIX) > 0
    deadline = time.time() + 5.0
    while time.time() < deadline and os.path.getsize(p + W.WAL_SUFFIX) > 0:
        time.sleep(0.02)
    assert os.path.getsize(p + W.WAL_SUFFIX) == 0, "idle 进程未周期 checkpoint"
    raw = J.read_json_file(p)
    assert raw["gate_data"]["n"] == 1 and raw["_wal_seq"] == 1


def test_checkpoint_if_stale_noop_without_records(tmp_path):
    p = _mk(tmp_path)
    st = os.stat(p).st_mtime_ns
    r = W.checkpoint_if_stale(p)
    assert r.get("ok") and r.get("flushed") is False
    assert os.stat(p).st_mtime_ns == st

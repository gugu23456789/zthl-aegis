#!/usr/bin/env python3
"""§18.2 判据 c1 红先臂：cron per-state 维度（2026-10-04）。

缺陷（遗漏②）：`cron_scheduler.py` 仅全局 `.tick.lock`、**0 处** `STATE_FILE` ⟹ 无 per-state
维度。卫星随路由命中的 `STATE_FILE` 落盘时，cron 无法按域隔离 / 复用（α1「复用 cron」不成立）。

修法：调度器经**单一事实源**解析 per-state `STATE_FILE` —— ① 锁文件按 state 派生（不同域可并
发 tick）② 导出 `STATE_FILE` 进 job 子进程 env（job 操作落在正确账）。

臂（HEAD 必红：`STATE_FILE` / `_lock_file_path` / `_job_env` 均不存在）：
  · `source_references_state_file`        静态：源码含 `STATE_FILE`
  · `resolve_state_file_honors_env`       行为：env `STATE_FILE` 优先
  · `lock_path_is_per_state`              行为：两 state → 不同锁路径；相同 → 相同
  · `lock_path_falls_back_without_state`  行为：无 state → 全局 `LOCK_FILE`（零回归）
  · `job_env_injects_state_file`          行为：`_job_env` 注入 `STATE_FILE` 且保留原键
  · `job_env_no_state_no_inject`          负臂：无 state 不注入（防误塞空值）
  · `acquire_lock_uses_per_state_path`    行为：`_acquire_lock` 走 per-state 路径
"""
import os
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import cron_scheduler as CS  # noqa: E402


def test_source_references_state_file():
    src = (SCRIPTS / "cron_scheduler.py").read_text(encoding="utf-8")
    assert "STATE_FILE" in src, "c1：cron_scheduler.py 须引用 STATE_FILE（per-state 维度）"


def test_resolve_state_file_honors_env(monkeypatch):
    monkeypatch.setenv("STATE_FILE", "/tmp/.gatekeeper.state.x")
    assert CS._resolve_state_file() == "/tmp/.gatekeeper.state.x"


def test_lock_path_is_per_state(monkeypatch):
    monkeypatch.setattr(CS, "_resolve_state_file", lambda: "/a/.gatekeeper.state")
    a = CS._lock_file_path()
    monkeypatch.setattr(CS, "_resolve_state_file", lambda: "/b/.gatekeeper.state")
    b = CS._lock_file_path()
    monkeypatch.setattr(CS, "_resolve_state_file", lambda: "/a/.gatekeeper.state")
    assert CS._lock_file_path() == a, "同一 state ⟹ 锁路径须稳定（互斥保真）"
    assert a != b, "c1：不同 state 须派生不同锁路径（per-state）"
    assert os.path.dirname(a) == os.path.dirname(CS.LOCK_FILE)


def test_lock_path_falls_back_without_state(monkeypatch):
    monkeypatch.setattr(CS, "_resolve_state_file", lambda: "")
    assert CS._lock_file_path() == CS.LOCK_FILE, "无 state ⟹ 回退全局锁（零回归）"


def test_job_env_injects_state_file(monkeypatch):
    monkeypatch.setattr(CS, "_resolve_state_file", lambda: "/a/.gatekeeper.state")
    env = CS._job_env({"FOO": "1"})
    assert env["STATE_FILE"] == "/a/.gatekeeper.state"
    assert env["FOO"] == "1", "注入须保留原 env 键"


def test_job_env_no_state_no_inject(monkeypatch):
    monkeypatch.setattr(CS, "_resolve_state_file", lambda: "")
    assert "STATE_FILE" not in CS._job_env({"FOO": "1"}), "无 state 不注入（防误塞空值）"


def test_acquire_lock_uses_per_state_path(monkeypatch, tmp_path):
    lp = tmp_path / ".tick.abcd.lock"
    monkeypatch.setattr(CS, "_lock_file_path", lambda: str(lp))
    fd = CS._acquire_lock()
    try:
        assert lp.exists(), "c1：_acquire_lock 须走 per-state 锁路径"
    finally:
        CS._release_lock(fd)

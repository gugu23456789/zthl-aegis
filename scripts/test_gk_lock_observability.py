# -*- coding: utf-8 -*-
"""序④-A 联动面：BLOCK 路径 state 写失败的**可观测性**（red-first，`arm-lockobs`）。

病象（组3 G3a 实测 + v4①）：`pre_tool_hook._record_block_intent` 的 `except Exception: pass`
把 **state 锁获取失败**（`state_lock` 抛 `TimeoutError`）静默吞掉；且 `rec` 在 `with state_lock`
**块内**赋值 ⟹ 抛错时 `rec` 仍为 `None` ⟹ 块尾 `if rec is not None: _record_block_persistent(rec)`
**亦不写** ⟹ 该路径上 ring 与持久源**双丢**，BLOCK 意图整体无痕。

⟹ 后果：「0 命中」**不能**排除静默超时 ⟹ A4「base lock 串行可接受」只能**待补测**。
修法 = 该失败须落一条**独立可观测**记录（与 block 误报率分母**分账**，不污染 Q3 分母）。

红先对照：HEAD 版 `except Exception: pass`（无任何落点）⟹ 本臂必红。
"""
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import pre_tool_hook as h  # noqa: E402


@pytest.fixture()
def sandbox(monkeypatch, tmp_path):
    """隔离沙箱：STATE_FILE 指向 tmp 副本（防写穿真 state），`_CALL_*` 置为块意图形态。"""
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {}}), encoding="utf-8")
    monkeypatch.setattr(h, "STATE_FILE", st)
    monkeypatch.setattr(h, "_CALL_IN_SCOPE", True)
    monkeypatch.setattr(h, "_CALL_TOOL", "RunCommand")
    monkeypatch.setattr(h, "_CALL_KIND", "block")
    monkeypatch.setattr(h, "_CALL_TARGET", "")
    monkeypatch.setattr(h, "_CALL_CMD", "")
    monkeypatch.setattr(h, "_CALL_REASON", "")
    return st


def test_lock_timeout_is_observable(sandbox, monkeypatch):
    """臂（红先 · 行为）：`state_lock` 抛 `TimeoutError` ⟹ 须落**独立可观测**记录。"""
    def _timeout(path, *a, **k):
        raise TimeoutError("state lock timeout (0.0s)")

    monkeypatch.setattr(h, "state_lock", _timeout)
    h._CALL_TARGET = "/tmp/gk_lockobs"
    h._record_block_intent()

    obs = h._persistent_block_dir(str(sandbox)) / "lock-timeout.jsonl"
    assert obs.exists(), (
        "state 锁超时无独立可观测落点（被 `except Exception: pass` 静默吞）"
        "⟹ base lock 争用不可观测、「0 命中 ≠ 无超时」不成立")
    lines = [ln for ln in obs.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert lines, "lock-timeout.jsonl 存在但为空"
    rec = json.loads(lines[-1])
    assert rec.get("err") == "TimeoutError", f"记录未标失败类型: {rec}"
    assert "ts" in rec, f"记录缺 ts: {rec}"
    # 分账：失败**不得**污染 block 误报率分母（Q3）
    assert h._persistent_block_count(str(sandbox)) == 0, (
        "锁超时被误记为 block ⟹ 污染误报率分母")


def test_lock_failure_does_not_break_block_semantics(sandbox, monkeypatch):
    """负臂：可观测落点自身失败时**不得**改变 `_record_block_intent` 的 fail-quiet 契约
    （BLOCK 语义由 hook 的 exit 2 保证，审计副产品失败不升权、不抛）。"""
    monkeypatch.setattr(h, "state_lock",
                        lambda path, *a, **k: (_ for _ in ()).throw(TimeoutError("t")))
    monkeypatch.setattr(h, "_persistent_block_dir",
                        lambda state_path="": __import__("pathlib").Path("/proc/gk_lockobs_none"))
    try:
        h._record_block_intent()
    except Exception as e:  # pragma: no cover
        pytest.fail("fail-quiet 契约被破坏: %r" % e)


# ─── 取锁预算可注入（2026-11-05 bench-nightly 归因）────────────────────────────
def test_env_lock_timeout_override(monkeypatch):
    """`GK_STATE_LOCK_TIMEOUT` 覆盖取锁预算；非法/非正一律回落默认（不许关掉超时）。"""
    from gk_json_utils import LOCK_TIMEOUT, _env_lock_timeout

    monkeypatch.delenv("GK_STATE_LOCK_TIMEOUT", raising=False)
    assert _env_lock_timeout() == LOCK_TIMEOUT

    monkeypatch.setenv("GK_STATE_LOCK_TIMEOUT", "30")
    assert _env_lock_timeout() == 30.0
    monkeypatch.setenv("GK_STATE_LOCK_TIMEOUT", "7.5")
    assert _env_lock_timeout() == 7.5

    for bad in ("", "abc", "0", "-1", "None"):
        monkeypatch.setenv("GK_STATE_LOCK_TIMEOUT", bad)
        assert _env_lock_timeout() == LOCK_TIMEOUT, "非法值 %r 必须回落默认" % bad


def test_explicit_timeout_beats_env(monkeypatch, tmp_path):
    """显式传值（含 `timeout=0` 试探）优先于 env —— 观测口径不得被基准的放宽带走。"""
    import subprocess
    from gk_json_utils import state_lock, state_lock_stats, reset_state_lock_stats

    path = str(tmp_path / "s.json")
    monkeypatch.setenv("GK_STATE_LOCK_TIMEOUT", "30")
    # 子进程持锁 2s：确保主进程必然撞锁（与 env 的 30s 预算形成对照）
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import sys,time;sys.path.insert(0,%r);import gk_json_utils as g;"
         "lk=g.state_lock(%r);lk.__enter__();print('locked',flush=True);time.sleep(2)"
         % (HERE, path)],
        stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "locked"
        reset_state_lock_stats()
        with pytest.raises(TimeoutError):
            with state_lock(path, timeout=0):
                pass
        assert state_lock_stats()["last_timeout_s"] == 0.0, "显式 timeout=0 未生效"
    finally:
        holder.kill()
        holder.wait(timeout=10)

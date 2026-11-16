"""T5：60s tick 作业体（gk_audit_model_tick）—— rc/reason 落日志 + sidecar 前进（2026-11-13）。

红先形态：本模块落刀前不存在 ⟹ ImportError。
判据取自 408 计划 §9 T5：`cron_scheduler --once` 后 sidecar `updated_at` 前进；本层单测只验
作业体本身（不拉起真模型、不注册真 cron）。
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_audit_lifecycle as LC   # noqa: E402
import gk_audit_model_tick as T  # noqa: E402


def _cold_sidecar(tmp_path):
    p = tmp_path / ".gatekeeper.audit_lifecycle.json"
    return str(p)


def test_tick_advances_sidecar_and_logs(tmp_path, monkeypatch):
    """一次 tick 必须：① sidecar 存在且 updated_at 前进；② 日志追加一行 rc/reason。"""
    monkeypatch.delenv("GK_AUDIT_MODEL_LLAMA_CMD", raising=False)
    monkeypatch.delenv("GK_AUDIT_MODEL_SERVE_CMD", raising=False)
    side = _cold_sidecar(tmp_path)
    log = str(tmp_path / "tick.log")
    before = LC.load_state(side).get("updated_at") or 0
    rc, res = T.tick_once(side, log)
    assert rc in (0, 3, 4), res
    st = LC.load_state(side)
    assert st.get("updated_at", 0) > before, "sidecar updated_at 未前进（T5 判据）"
    lines = [ln for ln in open(log, encoding="utf-8").read().splitlines() if ln.strip()]
    assert len(lines) == 1, lines
    rec = json.loads(lines[0])
    assert set(rec) >= {"ts", "rc", "state", "reason"}, rec
    assert rec["reason"], "reason 不得为空（否则事后无法回答『为什么没启停』）"


def test_two_ticks_append_two_lines(tmp_path, monkeypatch):
    monkeypatch.delenv("GK_AUDIT_MODEL_LLAMA_CMD", raising=False)
    monkeypatch.delenv("GK_AUDIT_MODEL_SERVE_CMD", raising=False)
    side = _cold_sidecar(tmp_path)
    log = str(tmp_path / "tick.log")
    T.tick_once(side, log)
    T.tick_once(side, log)
    lines = [ln for ln in open(log, encoding="utf-8").read().splitlines() if ln.strip()]
    assert len(lines) == 2, "日志必须**追加**（不是覆盖）"


def test_log_failure_does_not_change_rc(tmp_path, monkeypatch):
    """日志不可写 ⟹ tick 结果不变（观测面失败不得变成控制面失败）。"""
    monkeypatch.delenv("GK_AUDIT_MODEL_LLAMA_CMD", raising=False)
    monkeypatch.delenv("GK_AUDIT_MODEL_SERVE_CMD", raising=False)
    side = _cold_sidecar(tmp_path)
    rc, res = T.tick_once(side, "/proc/nonexistent-dir/x.log")
    assert rc in (0, 3, 4) and res, (rc, res)

"""T3/T4 接线：sweep 每条 raise / monitor 每次 --api 各持一条生命周期租约（2026-11-12）。

判据：
  ① 未配置启停命令 ⟹ `ensure` 返回 `lifecycle_unconfigured` advisory（旧部署/单测零回归）；
  ② 配置后 `ensure` 真起模型单元并返回 lease_id；请求结束 `drop_lease` 精确回收；
  ③ sweep 失败/成功都撤租约，且不因生命周期不可用而**伪造** outcome。
"""
import json
import os
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_audit_lifecycle as LC  # noqa: E402
import gk_audit_outcome as AO  # noqa: E402
import gk_monitor_decision as MD  # noqa: E402


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_ensure_unconfigured_is_advisory(monkeypatch):
    monkeypatch.delenv("GK_AUDIT_MODEL_LLAMA_CMD", raising=False)
    monkeypatch.delenv("GK_AUDIT_MODEL_SERVE_CMD", raising=False)
    r = LC.ensure("monitor")
    assert r["ok"] is True and r["advisory"] == "lifecycle_unconfigured"
    assert r["lease_id"] == ""


def test_ensure_configured_starts_and_lease_roundtrip(tmp_path, monkeypatch):
    import shlex
    llama, serve = _free_port(), _free_port()
    sleeper = Path(tmp_path) / "sleeper.py"
    sleeper.write_text("import time; time.sleep(60)\n", encoding="utf-8")
    cmd = "%s %s" % (shlex.quote(sys.executable), shlex.quote(str(sleeper)))
    monkeypatch.setenv("GK_AUDIT_MODEL_LLAMA_CMD", cmd)
    monkeypatch.setenv("GK_AUDIT_MODEL_SERVE_CMD", cmd)
    monkeypatch.setenv("GK_AUDIT_MODEL_LLAMA_PORT", str(llama))
    monkeypatch.setenv("GK_AUDIT_MODEL_SERVE_PORT", str(serve))
    monkeypatch.setenv("GK_AUDIT_MODEL_START_TIMEOUT_S", "5")
    monkeypatch.setattr(LC, "PROBE", lambda port, timeout=2.0: {"ok": True, "data": {}})
    # 2026-11-16：生产默认 spawn 已标 unsupported ⟹ 本臂显式注入底层实现
    monkeypatch.setattr(LC, "SPAWN", LC._popen_spawn)
    side = Path(tmp_path) / "life.json"
    r = LC.ensure("raises", owner_pid=os.getpid(), ttl_s=30, path=side)
    assert r.get("ok") and r.get("state") == "warm" and r.get("lease_id"), r
    st = LC.load_state(side)
    assert any(x.get("id") == r["lease_id"] for x in st.get("inflight_leases") or []), st
    LC.drop_lease(r["lease_id"], side)
    st2 = LC.load_state(side)
    assert not any(x.get("id") == r["lease_id"] for x in st2.get("inflight_leases") or []), st2
    LC.stop(side)


def test_t3_sweep_acquires_raises_lease(monkeypatch):
    calls = {"ensure": [], "drop": []}
    monkeypatch.setattr(LC, "ensure", lambda kind, owner_pid=0, ttl_s=None, path=None: (
        calls["ensure"].append((kind, ttl_s)) or
        {"ok": True, "state": "warm", "lease_id": "L-raises"}))
    monkeypatch.setattr(LC, "drop_lease", lambda lid, path=None: calls["drop"].append(lid))
    monkeypatch.setattr(AO.CL, "read_records",
                        lambda _s: ([{"id": "r1", "kind": "raise"}], None))
    monkeypatch.setattr(AO, "produce",
                        lambda *a, **k: {"ok": True, "decision": "success"})
    out = AO.sweep("dummy.state", endpoint="http://127.0.0.1:9", limit=1)
    assert out["ok"] and out["results"][0]["ok"], out
    assert calls["ensure"] and calls["ensure"][0][0] == "raises", calls
    assert calls["drop"] == ["L-raises"], calls


def test_t3_sweep_lifecycle_failure_is_named(monkeypatch):
    monkeypatch.setattr(LC, "ensure",
                        lambda *a, **k: {"ok": False, "error": "HOLD_LOW_MEM"})
    monkeypatch.setattr(AO.CL, "read_records",
                        lambda _s: ([{"id": "r1", "kind": "raise"}], None))
    called = {"n": 0}
    monkeypatch.setattr(AO, "produce", lambda *a, **k: called.__setitem__("n", 1))
    out = AO.sweep("dummy.state", endpoint="http://127.0.0.1:9", limit=1)
    assert out["results"][0]["ok"] is False
    assert "HOLD_LOW_MEM" in out["results"][0]["error"], out
    assert called["n"] == 0, "生命周期不可用仍调用了 produce（伪造风险）"


def test_t4_monitor_acquires_monitor_lease(monkeypatch):
    calls = {"ensure": [], "drop": []}
    monkeypatch.setattr(LC, "ensure", lambda kind, owner_pid=0, ttl_s=None, path=None: (
        calls["ensure"].append(kind) or
        {"ok": True, "state": "warm", "lease_id": "L-mon"}))
    monkeypatch.setattr(LC, "drop_lease", lambda lid, path=None: calls["drop"].append(lid))
    monkeypatch.setattr(AO, "_post_json", lambda url, body, timeout=30.0: {
        "answers": {MD.QUESTION_ID: {"choice": "pass", "confidence": 0.9}}})
    r = MD.run("STAGE_3", endpoint="http://127.0.0.1:9")
    assert r.get("ok") and r.get("verdict") == "PASS", r
    assert calls["ensure"] == ["monitor"], calls
    assert calls["drop"] == ["L-mon"], calls

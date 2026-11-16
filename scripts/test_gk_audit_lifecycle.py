"""E1–E8：审计署 4B 决策模型自适应启停（408 计划 §7，2026-11-12 红先）。

真实件：sidecar 原子写 / 跨进程 flock / PID+start_time 双键 / 真进程 SIGTERM→SIGKILL /
端口占用。测试只替换**启停命令**（假 llama/serve 睡进程）与 **health 探针**（E8 用真探针）。
"""
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_audit_lifecycle as L  # noqa: E402

SLEEPER = "import time; time.sleep(60)\n"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _env(monkeypatch, tmp_path):
    import shlex
    llama, serve = _free_port(), _free_port()
    sleeper = Path(tmp_path) / "sleeper.py"
    sleeper.write_text(SLEEPER, encoding="utf-8")
    cmd = "%s %s" % (shlex.quote(sys.executable), shlex.quote(str(sleeper)))
    monkeypatch.setenv("GK_AUDIT_MODEL_LLAMA_CMD", cmd)
    monkeypatch.setenv("GK_AUDIT_MODEL_SERVE_CMD", cmd)
    monkeypatch.setenv("GK_AUDIT_MODEL_LLAMA_PORT", str(llama))
    monkeypatch.setenv("GK_AUDIT_MODEL_SERVE_PORT", str(serve))
    monkeypatch.setenv("GK_AUDIT_MODEL_IDLE_TTL_S", "1")
    monkeypatch.setenv("GK_AUDIT_MODEL_INFLIGHT_LEASE_TTL_S", "5")
    monkeypatch.setenv("GK_AUDIT_MODEL_START_TIMEOUT_S", "5")
    monkeypatch.setenv("GK_AUDIT_MODEL_DRAIN_TIMEOUT_S", "1")
    monkeypatch.setenv("GK_AUDIT_MODEL_LIFECYCLE", "auto")
    monkeypatch.setattr(L, "PROBE", lambda port, timeout=2.0: {
        "ok": True, "data": {"model": "StartLux-4B-AutoThink"}})
    # 2026-11-16：生产默认 spawn 已标 unsupported ⟹ 生命周期臂显式注入底层实现
    monkeypatch.setattr(L, "SPAWN", L._popen_spawn)
    return Path(tmp_path) / "life.json", llama, serve


def _start(side):
    out = L.start(side)
    assert out.get("ok"), out
    return out


def _cleanup(side):
    try:
        L.stop(side)
    except Exception:  # noqa: BLE001
        pass


def _rd(**kw):
    base = {"ok": True, "free_mb": 8192, "min_free_mb": 512,
            "gpu": {"ok": True, "gpu": {"free_mb": 7000}, "reason": ""},
            "cpus": 8, "max_concurrency": 64, "adaptive_workers": 1}
    base.update(kw)
    return base


def _lease(now, kind="raises", ttl=60):
    return [{"kind": kind, "owner_pid": 0, "expires_at": now + ttl}]


# ── E7：策略纯函数矩阵（9+ 用例）──────────────────────────────────────────
def test_e7_decide_matrix(monkeypatch):
    now = 1000.0
    cold = L.default_state(now)
    warm = L.default_state(now)
    warm["state"] = "warm"
    warm["last_request_at"] = now - 10 ** 6
    warming = L.default_state(now)
    warming["state"] = "warming"
    warming["updated_at"] = now - 100
    draining = L.default_state(now)
    draining["state"] = "draining"
    draining["updated_at"] = now - 100
    backoff = L.default_state(now)
    backoff["backoff"]["next_retry_at"] = now + 100

    cases = [
        ("cold_no_demand", cold, _rd(), [], "HOLD_IDLE_TTL"),
        ("cold_low_mem", cold, _rd(free_mb=100), _lease(now), "HOLD_LOW_MEM"),
        ("cold_no_reading", cold, {"ok": False}, _lease(now), "HOLD_NO_READING"),
        ("cold_no_gpu", cold, _rd(gpu={"ok": False, "reason": "no_gpu"}), _lease(now),
         "NO_GPU_DEGRADED"),
        ("cold_low_vram", cold, _rd(gpu={"ok": False, "reason": "low_vram"}), _lease(now),
         "HOLD_LOW_VRAM"),
        ("cold_backoff", backoff, _rd(), _lease(now), "BACKOFF"),
        ("warm_lease", warm, _rd(), _lease(now), "OK_NEED_HOT"),
        ("warm_ttl", warm, _rd(), [], "STOP_TTL_EXPIRED"),
        ("warming_timeout", warming, _rd(), _lease(now), "START_TIMEOUT"),
        ("draining_empty", draining, _rd(), [], "STOP_DRAINED"),
        ("cold_demand_ok", cold, _rd(), _lease(now), "OK_NEED_HOT"),
    ]
    for name, st, rd, leases, reason in cases:
        d = L.decide(st, rd, now=now, leases=leases)
        assert d["reason"] == reason, (name, d)
        assert d["reason"] in L.REASONS, (name, d["reason"])
        assert d["reason"] != "HOLD_CPU_BUSY", name  # E3 静态判据


def test_e3_force_on_off(monkeypatch):
    now = 1000.0
    cold = L.default_state(now)
    warm = L.default_state(now)
    warm["state"] = "warm"
    monkeypatch.setenv("GK_AUDIT_MODEL_LIFECYCLE", "force-on")
    d = L.decide(cold, _rd(free_mb=1), now=now, leases=[])
    assert d["action"] == "start" and d["reason"] == "FORCE_ON", d
    monkeypatch.setenv("GK_AUDIT_MODEL_LIFECYCLE", "force-off")
    d = L.decide(warm, _rd(), now=now, leases=[])
    assert d["action"] == "stop" and d["reason"] == "FORCE_OFF", d
    monkeypatch.setenv("GK_AUDIT_MODEL_LIFECYCLE", "auto")


# ── E1：读数单源（静态 + 100 次对拍）────────────────────────────────────────
def test_e1_readings_single_source(tmp_path, monkeypatch):
    src = Path(L.__file__).read_text(encoding="utf-8")
    assert "import gk_hub_scheduler" in src
    for sym in ("free_avail_mb", "min_free_mb", "gpu_admit", "visible_cpus",
                "max_concurrency", "adaptive_workers"):
        assert sym in src, sym
    import gk_hub_scheduler as H
    monkeypatch.setattr(H, "free_avail_mb", lambda: 4321)
    monkeypatch.setattr(H, "min_free_mb", lambda: 512)
    monkeypatch.setattr(H, "gpu_admit", lambda: {"ok": True, "reason": "", "gpu": {}})
    monkeypatch.setattr(H, "visible_cpus", lambda: 6)
    monkeypatch.setattr(H, "max_concurrency", lambda: 32)
    monkeypatch.setattr(H, "adaptive_workers", lambda n: 2)
    side = Path(tmp_path) / "life.json"
    for _ in range(100):
        out = L.status(side)["readings"]
        assert out["free_mb"] == 4321 and out["min_free_mb"] == 512
        assert out["cpus"] == 6 and out["max_concurrency"] == 32
        assert out["adaptive_workers"] == 2


# ── E2：空闲 TTL 到点停（真进程，5/5）──────────────────────────────────────
def test_e2_idle_ttl_stops(tmp_path, monkeypatch):
    side, _llama, _serve = _env(monkeypatch, tmp_path)
    for _ in range(5):
        _start(side)
        st = L.load_state(side)
        st["last_request_at"] = time.time() - 10
        L.save_state(st, side)
        out = L.tick(side)
        assert out["decision"]["reason"] == "STOP_TTL_EXPIRED", out
        st2 = L.load_state(side)
        assert st2["state"] == "cold" and st2["reason"] == "STOP_TTL_EXPIRED", st2
        assert st2["pids"] == {"llama": 0, "serve": 0}, st2
    _cleanup(side)


# ── E4：in-flight 不杀（3/3）+ 租约过期后停 ─────────────────────────────────
def test_e4_inflight_does_not_kill(tmp_path, monkeypatch):
    side, _llama, _serve = _env(monkeypatch, tmp_path)
    _start(side)
    try:
        for _ in range(3):
            st = L.load_state(side)
            st["last_request_at"] = time.time() - 10
            L.save_state(st, side)
            L.add_lease("monitor", owner_pid=os.getpid(), ttl_s=60, path=side)
            out = L.tick(side)
            assert out["decision"]["action"] == "hold", out
            assert out["decision"]["reason"] == "OK_NEED_MONITOR", out
            st2 = L.load_state(side)
            assert st2["state"] == "warm", st2
            assert L.unit_alive(st2, "llama") and L.unit_alive(st2, "serve"), st2
            # 清掉租约，进入下一轮
            st2["inflight_leases"] = []
            L.save_state(st2, side)
        # 过期租约 ⟹ 逐条回收 ⟹ 下一 tick 停
        st = L.load_state(side)
        st["inflight_leases"] = [{"kind": "monitor", "owner_pid": os.getpid(),
                                  "expires_at": time.time() - 1}]
        st["last_request_at"] = time.time() - 10
        L.save_state(st, side)
        out = L.tick(side)
        assert out["dropped_leases"] == 1, out
        assert out["decision"]["reason"] == "STOP_TTL_EXPIRED", out
        assert L.load_state(side)["state"] == "cold"
    finally:
        _cleanup(side)


# ── E5：端口占用 fail-loud（3/3）──────────────────────────────────────────
def test_e5_port_taken(tmp_path, monkeypatch):
    side, _llama, serve = _env(monkeypatch, tmp_path)
    for _ in range(3):
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", serve))
            s.listen(1)
            out = L.start(side)
            assert out.get("ok") is False and out.get("error") == "PORT_TAKEN", out
            assert L.load_state(side)["pids"] == {"llama": 0, "serve": 0}
            assert L.load_state(side)["reason"] == "PORT_TAKEN"


# ── E6：双实例（锁忙 = WARMING_BUSY，5/5）──────────────────────────────────
def test_e6_double_instance(tmp_path, monkeypatch):
    side, _llama, _serve = _env(monkeypatch, tmp_path)
    for _ in range(5):
        ready, release = threading.Event(), threading.Event()

        def holder():
            with L.locked(side):
                ready.set()
                release.wait(5)

        t = threading.Thread(target=holder)
        t.start()
        assert ready.wait(5)
        out = L.start(side)
        assert out.get("error") == "WARMING_BUSY", out
        release.set()
        t.join(5)
        out2 = L.start(side)
        assert out2.get("ok") and out2.get("state") == "warm", out2
        _cleanup(side)


# ── E8：真 health 端到端（服务未起 ⟹ BLOCKED，不冒充 PASS）──────────────────
def test_decide_cli_is_success(tmp_path, monkeypatch):
    """`decide` 是有效判决输出（hold 不是失败）⟹ rc=0，禁被 CLI 当错误。"""
    side = Path(tmp_path) / "life.json"
    monkeypatch.setattr(L, "readings", lambda: _rd())
    assert L.main(["decide", "--sidecar", str(side)]) == 0


def test_e8_live_health():
    port = int(os.environ.get("GK_AUDIT_MODEL_SERVE_PORT", "8090"))
    r = L._default_probe(port)
    if not r.get("ok"):
        pytest.skip("E8 BLOCKED: 127.0.0.1:%d/health 不可达（%s）；需先起 llama-server + startlux serve"
                    % (port, r.get("error")))
    model = str((r.get("data") or {}).get("model") or "")
    assert "StartLux" in model, r


# ── 启动器口径（2026-11-16 裁定）：默认 spawn = unsupported ─────────────────
def test_default_spawn_is_unsupported():
    """生产默认 spawn 必 fail-loud（子进程随宿主 Job Object 被清杀，408 §9.2）。"""
    with pytest.raises(L.SpawnUnsupported):
        L._default_spawn("echo hi")


def test_spawn_unit_reports_start_unsupported(tmp_path, monkeypatch):
    monkeypatch.setattr(L, "SPAWN", L._default_spawn)
    st = L.default_state()
    r = L._spawn_unit(st, "llama", "echo hi")
    assert r.get("ok") is False and r.get("error") == "START_UNSUPPORTED", r
    assert r.get("detail") == "external_launcher_required", r
    assert st["pids"]["llama"] == 0, st
    assert st["proc_start_time"]["llama"] == "", st


def test_start_with_configured_cmd_fails_loud(tmp_path, monkeypatch):
    """即使配了启停命令，模块也不 spawn（必须外部 launcher）⟹ cold + 具名 reason。"""
    side = Path(tmp_path) / "life.json"
    monkeypatch.setenv("GK_AUDIT_MODEL_LLAMA_CMD", "echo llama")
    monkeypatch.setenv("GK_AUDIT_MODEL_SERVE_CMD", "echo serve")
    monkeypatch.setenv("GK_AUDIT_MODEL_LLAMA_PORT", str(_free_port()))
    monkeypatch.setenv("GK_AUDIT_MODEL_SERVE_PORT", str(_free_port()))
    out = L.start(side)
    assert out.get("ok") is False and out.get("error") == "START_UNSUPPORTED", out
    st = L.load_state(side)
    assert st["state"] == "cold" and st["reason"] == "START_UNSUPPORTED", st
    assert st["pids"] == {"llama": 0, "serve": 0}, st


def test_default_state_declares_external_launcher():
    assert L.default_state()["launcher"] == "external"
    assert "START_UNSUPPORTED" in L.REASONS


def test_status_reports_external_launcher(tmp_path, monkeypatch):
    """`status` 必须显式暴露 launcher 口径（外部 launcher = 唯一受支持路径）。"""
    side = Path(tmp_path) / "life.json"
    monkeypatch.setattr(L, "readings", lambda: _rd())
    out = L.status(side)
    assert out.get("launcher") == "external", out


# ── 408 ⑦（2026-11-16）：预留租约**只读** claim + 失败路径不留幽灵预留 ──────────
# 病象：`reserved` 只在 warming 期间非零，但 `_start_unit` 的两条失败分支
# （llama/serve 启动失败）**不清零** ⟹ 生产默认 spawn=unsupported 时每次尝试都
# 留下 1024MB 幽灵预留直到 `start_timeout_s()`（~90s），会误拒 accept 启动闸。
def test_reserved_claim_未过期时返回预留(tmp_path):
    side = Path(tmp_path) / "life.json"
    now = 1000.0
    L.save_state({"reserved": {"mb": 512, "vram_mb": 0, "expires_at": now + 30}}, side)
    c = L.reserved_claim(side, now=now)
    assert c == {"mb": 512, "vram_mb": 0, "expires_at": now + 30, "active": True}, c


def test_reserved_claim_过期归零且不写盘(tmp_path):
    side = Path(tmp_path) / "life.json"
    now = 1000.0
    L.save_state({"reserved": {"mb": 512, "vram_mb": 0, "expires_at": now + 30}}, side)
    body = side.read_text(encoding="utf-8")
    c = L.reserved_claim(side, now=now + 31)
    assert c["mb"] == 0 and c["vram_mb"] == 0 and c["active"] is False, c
    assert side.read_text(encoding="utf-8") == body, "claim 只读，不得改写 sidecar"


def test_reserved_claim_缺失不创建文件(tmp_path):
    side = Path(tmp_path) / "absent.json"
    c = L.reserved_claim(side)
    assert c["mb"] == 0 and c["active"] is False, c
    assert not side.exists(), "只读 claim 不得创建 sidecar"


def test_start_unsupported_不留幽灵预留(tmp_path, monkeypatch):
    """红先臂：warming 前写入的 reserved 在启动失败后必须归零。"""
    side = Path(tmp_path) / "life.json"
    monkeypatch.setenv("GK_AUDIT_MODEL_LLAMA_CMD", "echo llama")
    monkeypatch.setenv("GK_AUDIT_MODEL_SERVE_CMD", "echo serve")
    monkeypatch.setenv("GK_AUDIT_MODEL_LLAMA_PORT", str(_free_port()))
    monkeypatch.setenv("GK_AUDIT_MODEL_SERVE_PORT", str(_free_port()))
    out = L.start(side)
    assert out.get("ok") is False, out
    st = L.load_state(side)
    assert st["reserved"]["mb"] == 0, st["reserved"]
    assert st["reserved"]["expires_at"] == 0, st["reserved"]
    assert L.reserved_claim(side)["active"] is False

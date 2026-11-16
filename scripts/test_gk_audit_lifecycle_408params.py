"""408 ②③⑪ 落地臂（2026-11-14）。

- ② 电池闸：阈值未设 ⟹ 不生效；低于阈值且离电 ⟹ HOLD_ON_BATTERY；未知读数 fail-open。
- ③ cpu_pct：只观测；decide() 输出不随其变化（负臂）。
- ⑪ 断言分区：列数 = max(5, max(coverage_target))。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_audit_lifecycle as L      # noqa: E402
import gk_moa_aggregate as A       # noqa: E402

_ENV_KEYS = ("GK_AUDIT_MODEL_IDLE_TTL_S", "GK_AUDIT_MODEL_TICK_S",
             "GK_AUDIT_MODEL_INFLIGHT_LEASE_TTL_S", "GK_AUDIT_MODEL_DRAIN_TIMEOUT_S",
             "GK_AUDIT_MODEL_BACKOFF_MAX_S", "GK_AUDIT_MODEL_VRAM_HEADROOM",
             "GK_AUDIT_MODEL_MIN_BATTERY_PCT", "GK_AUDIT_MODEL_LIFECYCLE")


def _clean(monkeypatch):
    for k in _ENV_KEYS:
        monkeypatch.delenv(k, raising=False)


def _rd(battery=None, cpu=7.5):
    return {"ok": True, "free_mb": 8192, "min_free_mb": 512,
            "gpu": {"ok": True, "reason": "ok"},
            "battery": battery if battery is not None else {"ok": False, "error": "NON_WINDOWS"},
            "cpu_pct": cpu}


def _cold():
    st = L.default_state(now=100.0)
    st.update({"state": "cold", "updated_at": 100.0,
               "backoff": {"attempts": 0, "next_retry_at": 0.0}})
    return st


def _lease():
    return [{"id": "l1", "kind": "raises", "expires_at": 200.0}]


def test_defaults_match_plan(monkeypatch):
    """①④⑤⑥⑧⑩：默认值必须与 §10 表一致（防静默漂移）。"""
    _clean(monkeypatch)
    assert L.idle_ttl_s() == 600.0
    assert L.tick_s() == 60.0
    assert L.lease_ttl_s() == 120.0
    assert L.drain_timeout_s() == 120.0
    assert L.backoff_max_s() == 300.0
    assert L.vram_headroom() == 1.2
    assert L.min_battery_pct() is None, "阈值未设必须为 None（不生效）"


def test_battery_gate_holds_when_low_and_on_battery(monkeypatch):
    _clean(monkeypatch)
    monkeypatch.setenv("GK_AUDIT_MODEL_MIN_BATTERY_PCT", "20")
    out = L.decide(_cold(), _rd({"ok": True, "on_ac": False, "pct": 15}),
                   leases=_lease(), now=100.0)
    assert out["action"] == "hold" and out["reason"] == "HOLD_ON_BATTERY", out


def test_battery_gate_allows_on_ac(monkeypatch):
    _clean(monkeypatch)
    monkeypatch.setenv("GK_AUDIT_MODEL_MIN_BATTERY_PCT", "20")
    out = L.decide(_cold(), _rd({"ok": True, "on_ac": True, "pct": 15}),
                   leases=_lease(), now=100.0)
    assert out["action"] == "start", out


def test_battery_gate_disabled_when_threshold_unset(monkeypatch):
    _clean(monkeypatch)
    out = L.decide(_cold(), _rd({"ok": True, "on_ac": False, "pct": 3}),
                   leases=_lease(), now=100.0)
    assert out["action"] == "start", out


def test_battery_unknown_fails_open(monkeypatch):
    _clean(monkeypatch)
    monkeypatch.setenv("GK_AUDIT_MODEL_MIN_BATTERY_PCT", "20")
    out = L.decide(_cold(), _rd({"ok": False, "error": "NON_WINDOWS"}),
                   leases=_lease(), now=100.0)
    assert out["action"] == "start", out


def test_force_on_bypasses_battery(monkeypatch):
    """force-on 按计划「除 low_vram 外全放行」⟹ 电池不得拦。"""
    _clean(monkeypatch)
    monkeypatch.setenv("GK_AUDIT_MODEL_MIN_BATTERY_PCT", "20")
    monkeypatch.setenv("GK_AUDIT_MODEL_LIFECYCLE", "force-on")
    out = L.decide(_cold(), _rd({"ok": True, "on_ac": False, "pct": 5}),
                   leases=[], now=100.0)
    assert out["action"] == "start" and out["reason"] == "FORCE_ON", out


def test_cpu_pct_is_not_consumed_by_decide(monkeypatch):
    """③ 负臂：CPU 99% 与 0% 的决策必须完全一致（只观测，不做闸）。"""
    _clean(monkeypatch)
    a = L.decide(_cold(), _rd(cpu=0.0), leases=_lease(), now=100.0)
    b = L.decide(_cold(), _rd(cpu=99.9), leases=_lease(), now=100.0)
    assert a == b, (a, b)
    assert a["action"] == "start"


def test_cpu_percent_returns_none_or_number():
    v = L.cpu_percent()
    assert v is None or (0.0 <= v <= 100.0), v


def test_assertion_n_follows_coverage_target():
    assert A.assertion_n([1, 2, 3, 4, 5, 6]) == 6
    assert A.assertion_n([1, 2, 3]) == 5, "少于 5 时保持向后兼容"
    assert A.assertion_n([]) == 5
    assert A.assertion_n(None) == 5


def test_assertion_metrics_exposes_sixth_column():
    refs = [{"assertions": [{"id": i, "verdict": "support"} for i in range(1, 7)]}]
    m = A.assertion_metrics(refs, n_assertions=A.assertion_n([1, 2, 3, 4, 5, 6]))
    assert set(m["per_assertion"]) == {"1", "2", "3", "4", "5", "6"}, m

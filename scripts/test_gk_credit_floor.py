#!/usr/bin/env python3
"""N 门（信用分下限）+ 基线单源 —— 防「credit-baseline vs econ_enabled_at」双源漂移。

单源规则：credit 签名基线权威；`econ_enabled_at` 仅 legacy 回退；两者不一致 ⟹ drift；
基线验签失败 ⟹ fail-closed（不回退 legacy）。无基线 ⟹ 只 advisory，禁止按绝对值判。
"""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_advance as A  # noqa: E402
import gk_audit_outcome as O  # noqa: E402
import gk_credit_ledger as CL  # noqa: E402
import gk_econ_baseline as EB  # noqa: E402


def _state(tmp_path, econ=""):
    st = tmp_path / "s.json"
    gd = {"sprint_contract": {"scope": "x"}}
    if econ:
        gd["econ_enabled_at"] = econ
    d = {"r_phase": "R1", "stage": "STAGE_3", "branch": "feature/r1", "worktree": "/tmp/wt",
         "gate_data": gd, "monitor_scores": {}, "history": []}
    d["_checksum"] = hashlib.sha256(json.dumps(gd, sort_keys=True).encode()).hexdigest()[:16]
    st.write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(st)


def _ok_env():
    return {"worktree_exists": True, "wt_registered": True, "uncommitted": "",
            "stash_count": 0, "ci_trigger": 1, "detect_changes": 0,
            "diff_files": "src/main.cc", "plan_backup_exists": True,
            "merge_check": True, "gn_up_to_date": True, "gn_stale": 0, "edit_used": 0}


# ── 基线单源解析 ───────────────────────────────────────────────────────────
class TestBaselineResolver:
    def test_credit_baseline_is_authoritative(self, tmp_path):
        st = _state(tmp_path)
        r = EB.resolve(st, credit_reader=lambda _: {
            "present": True, "ok": True, "cutoff_ts": "2026-10-01T00:00:00Z", "cutoff_id": "x"})
        assert r["source"] == "credit_baseline" and r["ok"] is True
        assert r["drift"] is False and r["ts"] == "2026-10-01T00:00:00Z"

    def test_drift_is_detected_not_silently_picked(self, tmp_path):
        st = _state(tmp_path, econ="2026-09-01T00:00:00Z")
        r = EB.resolve(st, credit_reader=lambda _: {
            "present": True, "ok": True, "cutoff_ts": "2026-10-01T00:00:00Z", "cutoff_id": "x"})
        assert r["drift"] is True and r["ok"] is False and r["reason"] == "baseline_drift"

    def test_invalid_baseline_fails_closed_without_legacy_fallback(self, tmp_path):
        st = _state(tmp_path, econ="2026-09-01T00:00:00Z")
        r = EB.resolve(st, credit_reader=lambda _: {
            "present": True, "ok": False, "reason": "digest_mismatch"})
        assert r["ok"] is False and r["ts"] == "" and r["source"] == "credit_baseline"

    def test_legacy_fallback_when_credit_baseline_absent(self, tmp_path):
        st = _state(tmp_path, econ="2026-09-01T00:00:00Z")
        r = EB.resolve(st, credit_reader=lambda _: {"present": False, "ok": False})
        assert r["source"] == "gate_data.econ_enabled_at" and r["ok"] is True

    def test_no_baseline_at_all(self, tmp_path):
        st = _state(tmp_path)
        r = EB.resolve(st, credit_reader=lambda _: {"present": False, "ok": False})
        assert r["source"] == "none" and r["reason"] == "baseline_missing"


# ── Δ 只从基线之后取（绝不退化成绝对值）──────────────────────────────────
def test_delta_since_uses_cutoff_id(tmp_path):
    st = _state(tmp_path)
    first = CL.append(st, "raise", reason="seed")
    assert first.get("ok"), first
    CL.append(st, "fail", ref="r1", reason="audit", model_version="m", temperature=0.0, seed=1)
    assert CL.delta_since(st, cutoff_id=first["record"]["id"]) == -15


def test_delta_since_none_without_baseline(tmp_path):
    st = _state(tmp_path)
    CL.append(st, "fail", ref="r1", reason="x", model_version="m", temperature=0.0, seed=1)
    assert CL.delta_since(st) is None, "无基线不得回退成绝对值"


# ── advance：默认 advisory，显式 env 才阻断 ────────────────────────────────
def _run(sf):
    return A._run(sf, "STAGE_4", force=False, dry_run=False, env=_ok_env(),
                  monitor_json={"score": 0.9, "verdict": "PASS", "mode": "local"},
                  cc={}, remote="", skill_dir=str(Path(sf).parent))


def _patch_floor(monkeypatch, delta=-15, drift=False):
    monkeypatch.setattr(EB, "resolve", lambda sf, credit_reader=None: {
        "source": "credit_baseline", "ok": not drift, "drift": drift,
        "ts": "2026-10-01T00:00:00Z", "cutoff_id": "x",
        "reason": "baseline_drift" if drift else "ok"})
    monkeypatch.setattr(CL, "delta_since", lambda *a, **k: delta)


def test_advance_credit_floor_is_advisory_by_default(tmp_path, monkeypatch):
    _patch_floor(monkeypatch, delta=-15)
    sf = _state(tmp_path)
    r = _run(sf)
    assert r.get("allowed") is True, r
    gd = json.load(open(sf, encoding="utf-8"))["gate_data"]
    assert gd["credit_score_delta"] == -15
    assert gd["credit_advisories"][-1]["code"] == "CREDIT_FLOOR_HIT"


def test_advance_credit_floor_enforced_by_env(tmp_path, monkeypatch):
    _patch_floor(monkeypatch, delta=-15)
    monkeypatch.setenv("GK_CREDIT_FLOOR_ENFORCE", "1")
    r = _run(_state(tmp_path))
    assert r.get("error") == "CREDIT_FLOOR_HIT" and r.get("allowed") is False


def test_advance_records_baseline_drift(tmp_path, monkeypatch):
    _patch_floor(monkeypatch, delta=0, drift=True)
    sf = _state(tmp_path)
    assert _run(sf).get("allowed") is True
    gd = json.load(open(sf, encoding="utf-8"))["gate_data"]
    assert gd["credit_advisories"][-1]["code"] == "ECON_BASELINE_DRIFT"


# ── ③ success(+5) 触发面：sweep（未配 endpoint 只 advisory）──────────────
def test_sweep_without_endpoint_only_advisory(tmp_path):
    st = _state(tmp_path)
    CL.append(st, "raise", reason="seed")
    out = O.sweep(st)
    assert out.get("ok") is True and out.get("advisory") == "endpoint_unset"
    assert out.get("pending") == 1


def test_sweep_skips_resolved_and_attempts_pending(tmp_path, monkeypatch):
    st = _state(tmp_path)
    a = CL.append(st, "raise", reason="a")
    b = CL.append(st, "raise", reason="b")
    CL.append(st, "fail", ref=a["record"]["id"], reason="x",
              model_version="m", temperature=0.0, seed=1)
    seen = []
    monkeypatch.setattr(O, "produce",
                        lambda *args, **kw: seen.append(args[1]) or {"ok": True, "decision": "success"})
    out = O.sweep(st, endpoint="http://example")
    assert seen == [b["record"]["id"]], "已审计 raise 不得重复产出（一债一票）"
    assert out.get("attempted") == 1

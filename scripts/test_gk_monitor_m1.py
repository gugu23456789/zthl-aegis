#!/usr/bin/env python3
"""M1 分权（owner 2026-10-31 签 §9.3）—— 负臂 N1–N4。

不变量：**审计侧只测量、不直接 BLOCK**；阻断只能来自额度银行的确定性二次确认。
  N1  `--api` 低分且无银行动作 ⟹ 放行 + finding 落账
  N2  写 N 条 advisory ⟹ 熵不变、不产 `appeal_required`
  N3  `state-patch` 改 `monitor_scores`（top / nested / fragment）一律拒
  N4  静态：`_monitor_eval` 零 `allowed=False` / 零 `appeal_required` 写点；审计模块零 `appeal_required`
"""
import hashlib
import inspect
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_advance as A  # noqa: E402
import gk_state_patch as gsp  # noqa: E402


def _cs(gate_data):
    return hashlib.sha256(json.dumps(gate_data, sort_keys=True).encode()).hexdigest()[:16]


def _write_state(path, stage, gate_data=None):
    d = {"r_phase": "R1", "stage": stage, "branch": "feature/r1", "worktree": "/tmp/wt",
         "gate_data": gate_data or {}, "monitor_scores": {}, "history": []}
    d["_checksum"] = _cs(d["gate_data"])
    path.write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(path)


def _ok_env():
    return {"worktree_exists": True, "wt_registered": True, "uncommitted": "",
            "stash_count": 0, "ci_trigger": 1, "detect_changes": 0,
            "diff_files": "src/main.cc", "plan_backup_exists": True,
            "merge_check": True, "gn_up_to_date": True, "gn_stale": 0, "edit_used": 0}


# ── N1：--api LLM 低分 = advisory，不得作终局否决键 ─────────────────────────
def test_n1_api_low_score_passes_with_finding(tmp_path):
    sf = _write_state(tmp_path / "s.json", "STAGE_3",
                      gate_data={"sprint_contract": {"scope": "x"}})
    r = A._run(sf, "STAGE_4", force=False, dry_run=False, env=_ok_env(),
               monitor_json={"score": 0.3, "verdict": "FAIL", "mode": "api"},
               cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("allowed") is True, r
    d = json.load(open(sf, encoding="utf-8"))
    gd = d["gate_data"]
    assert any(h.get("advisory") == "monitor_low_score" and h.get("mode") == "api"
               for h in gd.get("monitor_history") or []), "finding 未落账"
    assert not (gd.get("rejected_edits") or []), "advisory 不得进被拒缓冲（防熵回流）"
    assert "appeal_required" not in gd


# ── N2：advisory 不改熵、不产 appeal_required ──────────────────────────────
def test_n2_advisories_do_not_change_entropy():
    from gk_gate_entropy import compute_entropy_from_dict
    d = {"gate_data": {}}
    before = compute_entropy_from_dict(d, "STAGE_2")
    for _ in range(5):
        A._monitor_eval(d, "STAGE_2", "STAGE_3",
                        {"score": 0.1, "mode": "api"}, force=False, dry_run=False)
    assert compute_entropy_from_dict(d, "STAGE_2") == before == 0.0
    assert "appeal_required" not in d["gate_data"]


def test_n2_historical_monitor_rows_do_not_feed_entropy():
    """历史 state 里的 `source=monitor` 行也不得经熵门回流成二次 BLOCK。"""
    from gk_gate_entropy import compute_entropy_from_dict
    d = {"gate_data": {"rejected_edits": [{"source": "monitor", "score": 0.1}] * 5}}
    assert compute_entropy_from_dict(d, "STAGE_2") == 0.0


# ── N3：被审方不得自造/抹除测量 ────────────────────────────────────────────
class TestN3MonitorScoresDenied:
    def _state(self, tmp_path):
        p = tmp_path / "state.json"
        p.write_text(json.dumps({"gate_data": {}, "monitor_scores": {}}), encoding="utf-8")
        return str(p)

    def test_set_top_denied(self, tmp_path):
        out = gsp.cmd_set_top(self._state(tmp_path), "monitor_scores", '{"X":{}}')
        assert out["ok"] is False and "monitor_scores" in out["error"]

    def test_set_nested_denied(self, tmp_path):
        out = gsp.cmd_set_nested(self._state(tmp_path),
                                 "gate_data.monitor_scores.STAGE_1", '{"score":1.0}')
        assert out["ok"] is False

    def test_nested_top_form_denied(self, tmp_path):
        out = gsp.cmd_set_nested(self._state(tmp_path),
                                 "monitor_scores.STAGE_1", '{"score":1.0}')
        assert out["ok"] is False

    def test_update_gate_data_fragment_denied(self, tmp_path):
        out = gsp.cmd_update_gate_data(self._state(tmp_path),
                                       json.dumps({"monitor_scores": {"STAGE_1": {}}}))
        assert out["ok"] is False


# ── N4：静态判据（审计侧零阻断写点）────────────────────────────────────────
def test_n4_measurement_has_no_block_writes():
    src = inspect.getsource(A._monitor_eval)
    assert '"allowed": False' not in src
    assert "appeal_required" not in src
    assert "rejected_edits" not in src

    bank = inspect.getsource(A._bank_monitor_gate)
    assert '"allowed": False' in bank
    assert A.BANK_MONITOR_BLOCKED in bank


def test_n4_audit_module_writes_no_appeal_required():
    import gk_audit_state
    src = Path(gk_audit_state.__file__).read_text(encoding="utf-8")
    assert "appeal_required" not in src, "审计侧不得写阻断源"


# ── §9.4 缺口①：封印失效时 advance 必须具名 fail-loud（不按 0 放行）──────────
def test_advance_fails_loud_on_ledger_seal_invalid(tmp_path):
    sf = _write_state(tmp_path / "s.json", "STAGE_3",
                      gate_data={"sprint_contract": {"scope": "x"}})
    # 直接写账本但不补封印 ⟹ 读侧必须 RAISE_LEDGER_SEAL_INVALID
    Path(str(sf) + ".budget-log.jsonl").write_text(
        json.dumps({"ts": "2026-10-31T00:00:00Z", "kind": "raise",
                    "from_max": 1, "to_max": 2}) + "\n", encoding="utf-8")
    r = A._run(sf, "STAGE_4", force=False, dry_run=False, env=_ok_env(),
               monitor_json={"score": 0.9, "verdict": "PASS", "mode": "local"},
               cc={}, remote="", skill_dir=str(tmp_path))
    assert r.get("error") == "RAISE_LEDGER_SEAL_INVALID", r
    assert r.get("allowed") is False and r.get("ok") is False

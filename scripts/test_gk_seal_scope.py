#!/usr/bin/env python3
"""RED-SCOPE-02 红先臂：密封分**完整性哈希**（`gk_seal`，2026-11-12）。

病象：`gate_data._sealed_agent_score` 只有 `score`/`verdicts`/`conclusion`，无完整性字段
⟹ 任何能写 state 的路径都能静默改盲评结论，adjudicate / appeal / mediation 无法判别。
红队 `red_scope` 原判据仅「有无 `hash` 键」——有键即可伪造，不判内容。

修法：
  · 写侧 `gk_seal.apply()`（monitor 落库前盖戳：规范化 SHA256，除 `hash` 外全字段参与）
  · 读侧 `gk_seal.verify()`：无戳 = 未密封、戳不符 = 已篡改（两种都在 `red_scope` 报 SCOPE-02）
  · 审计 D10 同口径验戳（`gk_audit_state` sealed_agent_score）
"""
import json
import sys
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import gk_seal  # noqa: E402


# ─────────────────────────── 纯函数面 ───────────────────────────

def test_digest_ignores_key_order_and_whitespace():
    a = {"score": 0.9, "verdicts": {"F1": "PASS"}}
    b = {"verdicts": {"F1": "PASS"}, "score": 0.9}
    assert gk_seal.digest(a) == gk_seal.digest(b)
    assert gk_seal.digest(a).startswith("sha256:")


def test_apply_then_verify():
    seal = {"score": 0.9, "verdicts": {"F1": "PASS"}, "conclusion": "ok"}
    gk_seal.apply(seal)
    assert seal["hash"].startswith("sha256:")
    assert gk_seal.verify(seal) is True


def test_verify_detects_content_change():
    seal = gk_seal.apply({"score": 0.9, "verdicts": {"F1": "PASS"}, "conclusion": "ok"})
    seal["score"] = 0.1  # 篡改
    assert gk_seal.verify(seal) is False


def test_verify_false_without_hash_or_non_dict():
    assert gk_seal.verify({"score": 0.9}) is False
    assert gk_seal.verify(None) is False
    assert gk_seal.verify("x") is False


def test_hash_field_not_self_referential():
    """`hash` 自身不参与摘要 ⟹ 重复盖戳结果稳定。"""
    seal = {"score": 0.5}
    h1 = gk_seal.apply(seal)["hash"]
    h2 = gk_seal.apply(seal)["hash"]
    assert h1 == h2


# ─────────────────────────── 红队面（red_scope）───────────────────────────

def _write(tmp_path, gd):
    import hashlib
    d = {"r_phase": "R1", "stage": "ECO-EDIT", "gate_data": gd, "monitor_scores": {},
         "history": []}
    d["_checksum"] = hashlib.sha256(
        json.dumps(gd, sort_keys=True).encode()).hexdigest()[:16]
    sf = tmp_path / ".gatekeeper.state"
    sf.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(sf)


def _scope(sf):
    import _red_attacks
    with patch("_red_attacks.STATE_FILE", sf):
        return [f["id"] for f in _red_attacks.red_scope()]


def test_red_scope_flags_unsigned_seal(tmp_path):
    sf = _write(tmp_path, {"_sealed_agent_score": {"score": 0.9, "verdicts": {},
                                                   "conclusion": "x"}})
    assert "RED-SCOPE-02" in _scope(sf)


def test_red_scope_flags_tampered_seal(tmp_path):
    """有 hash 但内容被改 ⟹ 仍须报（原判据只看键存在，可伪造）。"""
    seal = gk_seal.apply({"score": 0.9, "verdicts": {}, "conclusion": "x"})
    seal["conclusion"] = "被改后的结论"
    sf = _write(tmp_path, {"_sealed_agent_score": seal})
    assert "RED-SCOPE-02" in _scope(sf)


def test_red_scope_accepts_sealed(tmp_path):
    seal = gk_seal.apply({"score": 0.9, "verdicts": {}, "conclusion": "x"})
    sf = _write(tmp_path, {"_sealed_agent_score": seal})
    assert "RED-SCOPE-02" not in _scope(sf)


# ─────────── RED-SCOPE-03：推进流须写重放明细（判据与保全同批对表）───────────

def test_red_scope_scope03_accepts_eco_completions_only(tmp_path):
    """有 `eco_completions` 转移记录 ⟹ 不是「无可重放」（`_advance_log` 曾因流不对称缺失）。"""
    sf = _write(tmp_path, {"eco_completions": {"ECO-EDIT": {
        "completed_at": "2026-11-09T10:15:19", "transitioned_to": "ECO-VERIFY"}}})
    assert "RED-SCOPE-03" not in _scope(sf)


def test_red_scope_scope03_fires_when_no_history_at_all(tmp_path):
    sf = _write(tmp_path, {})
    assert "RED-SCOPE-03" in _scope(sf)


# ─────────── 审计面（D10 sealed_agent_score 验戳）───────────

def test_audit_d10_hash_mismatch_fails(tmp_path):
    import gk_audit_state
    import gk_state
    seal = gk_seal.apply({"score": 0.9, "verdicts": {"F1": "PASS"}, "conclusion": "x"})
    seal["score"] = 0.2
    sp = str(tmp_path / ".gatekeeper.state")
    gk_state._write_state({"gate_data": {"_sealed_agent_score": seal},
                           "monitor_scores": {}, "history": [], "appeal_records": {},
                           "human_resolutions": {}, "achievements": {}}, sp)
    out = gk_audit_state.check_state_file(sp, skill_dir=str(tmp_path))
    chk = next(c for c in out["state_checks"] if c["field"] == "sealed_agent_score")
    assert chk["match"] is False and any("hash_mismatch" in i for i in chk["issues"]), chk


def test_audit_d10_valid_seal_matches(tmp_path):
    import gk_audit_state
    import gk_state
    seal = gk_seal.apply({"score": 0.9, "verdicts": {"F1": "PASS"}, "conclusion": "x"})
    sp = str(tmp_path / ".gatekeeper.state")
    gk_state._write_state({"gate_data": {"_sealed_agent_score": seal},
                           "monitor_scores": {}, "history": [], "appeal_records": {},
                           "human_resolutions": {}, "achievements": {}}, sp)
    out = gk_audit_state.check_state_file(sp, skill_dir=str(tmp_path))
    chk = next(c for c in out["state_checks"] if c["field"] == "sealed_agent_score")
    assert chk["match"] is True, chk


# ─────────── discover 保全：`_advance_log` 不再被抹掉 ───────────

def test_carry_over_keeps_advance_log():
    from gk_discover_carry import carry_over
    old = {"gate_data": {"_advance_log": [{"to_stage": "ECO-EDIT", "all_ok": True}]}}
    new = {"gate_data": {}}
    carry_over(old, new)
    assert new["gate_data"]["_advance_log"] == old["gate_data"]["_advance_log"]

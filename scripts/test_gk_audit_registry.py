#!/usr/bin/env python3
"""B3b 审计署登记（sidecar + auto 双读）行为臂（2026-10-28）。

覆盖：
  · 登记写入 / 幂等 / 封印校验；
  · 双读 auto 语义：缺失不拦、存在则摘要与封印双校验；
  · 消费侧接线：`gk_node_guard.audit_all_recorded(gd, state_file)` 随登记翻转。
"""
import json

import gk_audit_registry as R
import gk_node_guard as G

EVIDENCE = {"audit_state_result": {"state_checks": [{"field": "x", "match": True}]},
            "audit_docs_result": {"docs_checks": [{"doc": "d", "match": True}]}}


def _state(tmp_path, gd=None):
    st = tmp_path / "probe.state"
    st.write_text(json.dumps({"gate_data": dict(gd if gd is not None else EVIDENCE)}),
                  encoding="utf-8")
    return str(st)


def test_domains_single_source_with_node_guard():
    assert R.DEFAULT_DOMAINS == G._AUDIT_PRODUCED_EVIDENCE_KEYS


def test_register_then_dual_read_ok(tmp_path):
    st = _state(tmp_path)
    out = R.register(st, source="test")
    assert out["ok"] and out["entry"]["domains"].keys() == set(EVIDENCE), out
    assert R._logical_path(st).exists() and R._seal_path(st).exists()
    dr = R.dual_read(st, EVIDENCE)
    assert dr["required"] is True and dr["ok"] is True and dr["absent"] is False, dr
    assert R.verify(st)["ok"] is True


def test_register_idempotent(tmp_path):
    st = _state(tmp_path)
    assert R.register(st)["ok"]
    again = R.register(st)
    assert again.get("skipped") == "unchanged", again
    assert len(R._logical_path(st).read_text(encoding="utf-8").splitlines()) == 1


def test_register_without_evidence_skips(tmp_path):
    st = _state(tmp_path, gd={})
    out = R.register(st)
    assert out.get("skipped") == "no_evidence" and not R._logical_path(st).exists()


def test_absent_registry_auto_passes(tmp_path):
    st = _state(tmp_path)
    dr = R.dual_read(st, EVIDENCE)
    assert dr["absent"] is True and dr["required"] is False and dr["ok"] is True, dr


def test_tampered_evidence_digest_mismatch(tmp_path):
    st = _state(tmp_path)
    assert R.register(st)["ok"]
    tampered = json.loads(json.dumps(EVIDENCE))
    tampered["audit_state_result"]["state_checks"][0]["match"] = False
    dr = R.dual_read(st, tampered)
    assert dr["ok"] is False and "digest_mismatch:audit_state_result" in dr["mismatch"], dr


def test_evidence_removed_after_register(tmp_path):
    st = _state(tmp_path)
    assert R.register(st)["ok"]
    dr = R.dual_read(st, {"audit_state_result": EVIDENCE["audit_state_result"]})
    assert dr["ok"] is False and "evidence_missing:audit_docs_result" in dr["mismatch"], dr


def test_new_domain_after_register_is_unregistered(tmp_path):
    st = _state(tmp_path, gd={"audit_state_result": EVIDENCE["audit_state_result"]})
    assert R.register(st)["ok"]
    dr = R.dual_read(st, EVIDENCE)       # 新增的 docs 域未登记
    assert dr["ok"] is False and "unregistered:audit_docs_result" in dr["mismatch"], dr
    _state(tmp_path, gd=EVIDENCE)        # 真跑 audit --docs 后 state 才有 docs 域
    assert R.register(st)["ok"]          # 补登记后一致
    assert R.dual_read(st, EVIDENCE)["ok"] is True


def test_bad_seal_fails_closed(tmp_path):
    st = _state(tmp_path)
    assert R.register(st)["ok"]
    R._seal_path(st).write_text('{"mode":"sha256","sha256":"deadbeef"}', encoding="utf-8")
    dr = R.dual_read(st, EVIDENCE)
    assert dr["ok"] is False and dr["reason"].startswith("seal_bad"), dr


def test_node_guard_audit_all_recorded_dual_read(tmp_path):
    st = _state(tmp_path)
    assert G.audit_all_recorded(EVIDENCE, st) is True       # 无登记（auto）→ 放行
    assert R.register(st)["ok"]
    assert G.audit_all_recorded(EVIDENCE, st) is True       # 登记一致 → 放行
    tampered = json.loads(json.dumps(EVIDENCE))
    tampered["audit_docs_result"]["docs_checks"][0]["match"] = False
    assert G.audit_all_recorded(tampered, st) is False      # 摘要不符 → 拒
    assert G.audit_all_recorded(tampered) is True           # 不传 state_file = 旧语义


def test_review_exit_gate_dual_read_mismatch(tmp_path):
    st = _state(tmp_path)
    assert R.register(st)["ok"]
    gd = json.loads(json.dumps(EVIDENCE))
    gd.update({"reviews": [{"round": 1}, {"round": 2}], "red_actions": [{"hit": 1}]})
    tampered = json.loads(json.dumps(gd))
    tampered["audit_state_result"]["state_checks"][0]["match"] = False
    ok_res = G.review_exit_gate("ECO-DOC", gd, st)
    bad_res = G.review_exit_gate("ECO-DOC", tampered, st)
    if ok_res["round_log"]["status"] == "ready":
        assert ok_res["audit_all"] is True, ok_res
    assert bad_res["audit_all"] is False, bad_res
    assert any("登录" in m or "登记" in m for m in bad_res["missing"]), bad_res


def test_cli_register_and_dual_read(tmp_path, capsys):
    st = _state(tmp_path)
    assert R.main(["register", "--state", st]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True
    assert R.main(["dual-read", "--state", st]) == 0
    dr = json.loads(capsys.readouterr().out)
    assert dr["ok"] is True and dr["required"] is True

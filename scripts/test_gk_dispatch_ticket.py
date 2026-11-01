#!/usr/bin/env python3
"""test_gk_dispatch_ticket.py — 方案 B（Task 默认拒绝 + 单次票据）红先臂。

用户裁定（2026-10-27）：「按方案 B 执行完整闭包，先部署票据签发和校验机制」。
本文件把三件事钉成可回归事实：
  ① 签发/校验语义（HMAC 绑定 sha+exp+session、单次消费、过期、篡改、重放）；
  ② 票据字段 `gate_data.dispatch_tickets` 不得经 state-patch 三写面整份替换（防重置 used_at）；
  ③ hook 的 Gate 0 行为（无票 ⟹ 拒；有票且 sha 匹配 ⟹ 放行；二次使用 ⟹ 拒；关键词只告警）。

红先语义：本文件在 `gk_dispatch_ticket.py` 落地前 import 即失败（AttributeError/ImportError）。
"""
import json
import sys
import time
from pathlib import Path  # noqa: F401 — 供 `_report` 与后续臂使用

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import gk_dispatch_ticket as DT  # noqa: E402
import gk_state  # noqa: E402
import gk_state_patch as SP  # noqa: E402
import pre_tool_hook  # noqa: E402

_KEY_HEX = "a" * 64


@pytest.fixture()
def state_file(tmp_path, monkeypatch):
    """隔离 state + 单源密钥（env 供给；KEY_FILE 指空防仓内真钥干扰）。"""
    monkeypatch.setenv("GATEKEEPER_HMAC_KEY", _KEY_HEX)
    monkeypatch.delenv("GK_JOURNAL_KEY", raising=False)
    monkeypatch.setattr(DT, "KEY_FILE", tmp_path / "no-such-key")
    p = tmp_path / "state.json"
    gk_state._write_state({"gate_data": {}, "current": {}}, str(p))
    return p


# ── ① 签发 / 校验语义 ────────────────────────────────────────────────────────
def test_issue_records_signed_ticket(state_file):
    out = DT.issue(str(state_file), "do the thing", ttl=120, session="sess-1", node="N1")
    assert out["ok"] is True, out
    assert out["ticket"].count(".") == 1
    assert out["sha"] == DT.query_sha("do the thing")
    d = json.loads(state_file.read_text(encoding="utf-8"))
    lst = d["gate_data"]["dispatch_tickets"]
    assert len(lst) == 1
    rec = lst[0]
    assert rec["sha"] == out["sha"] and rec["session"] == "sess-1"
    assert rec["node"] == "N1" and rec["used_at"] is None
    assert len(rec["sig"]) == 64


def test_verify_ok_then_replay_blocked(state_file):
    out = DT.issue(str(state_file), "query-A", session="s")
    v1 = DT.verify(str(state_file), out["ticket"], "query-A", session="s")
    assert v1["ok"] is True and v1["reason"] == "ok", v1
    v2 = DT.verify(str(state_file), out["ticket"], "query-A", session="s")
    assert v2["ok"] is False and v2["reason"] == "used", v2


def test_verify_sha_mismatch(state_file):
    out = DT.issue(str(state_file), "query-A", session="s")
    v = DT.verify(str(state_file), out["ticket"], "query-B", session="s")
    assert v["ok"] is False and v["reason"] == "sha_mismatch", v


def test_verify_expired(state_file, monkeypatch):
    out = DT.issue(str(state_file), "query-A", session="s", ttl=1)
    real = DT._now
    monkeypatch.setattr(DT, "_now", lambda: real() + 5)
    v = DT.verify(str(state_file), out["ticket"], "query-A", session="s")
    assert v["ok"] is False and v["reason"] == "expired", v


def test_verify_tampered_signature(state_file):
    out = DT.issue(str(state_file), "query-A", session="s")
    nonce, sig = out["ticket"].split(".")
    bad = nonce + "." + ("0" if sig[0] != "0" else "1") + sig[1:]
    v = DT.verify(str(state_file), bad, "query-A", session="s")
    assert v["ok"] is False and v["reason"] == "bad_sig", v


def test_verify_unknown_ticket(state_file):
    v = DT.verify(str(state_file), "deadbeef." + "0" * 64, "query-A")
    assert v["ok"] is False and v["reason"] == "unknown_ticket", v


def test_verify_no_ticket(state_file):
    v = DT.verify(str(state_file), "", "query-A")
    assert v["ok"] is False and v["reason"] == "no_ticket", v


def test_verify_embedded_ticket_line(state_file):
    out = DT.issue(str(state_file), "query-A", session="s")
    q = "query-A\nGK-TICKET:%s\n" % out["ticket"]
    v = DT.verify(str(state_file), "", q, session="s")
    assert v["ok"] is True, v


def test_verify_crlf_and_trailing_ws_are_canonical(state_file):
    out = DT.issue(str(state_file), "line1\nline2", session="s")
    v = DT.verify(str(state_file), out["ticket"], "  line1\r\nline2\r\n", session="s")
    assert v["ok"] is True, v


def test_verify_cross_session_not_bricked(state_file):
    """session 不参与签名/相等校验（两侧身份链不同源，见模块 docstring）。

    实证：CLI 侧 `gk_session_identity.derive` = worktree token（`state-trim-lines`），
    hook 侧 Task 无 file_path ⟹ 载荷 sid（24-hex）⟹ 若做相等校验，**所有**合法票据恒 BLOCK。
    """
    out = DT.issue(str(state_file), "query-A", session="issuer-sess")
    v = DT.verify(str(state_file), out["ticket"], "query-A", session="caller-sess")
    assert v["ok"] is True, v
    rec = json.loads(state_file.read_text(encoding="utf-8"))["gate_data"]["dispatch_tickets"][0]
    assert rec["session"] == "issuer-sess" and rec["used_by"] == "caller-sess"


def test_issue_ttl_bounds(state_file):
    assert DT.issue(str(state_file), "q", ttl=0)["ok"] is False
    assert DT.issue(str(state_file), "q", ttl=DT.MAX_TTL + 1)["ok"] is False
    assert DT.issue(str(state_file), "q", ttl="not-a-number")["ok"] is False


def test_issue_without_key_fails_closed(state_file, monkeypatch):
    monkeypatch.delenv("GATEKEEPER_HMAC_KEY", raising=False)
    monkeypatch.delenv("GK_JOURNAL_KEY", raising=False)
    out = DT.issue(str(state_file), "q")
    assert out["ok"] is False and out["error"] == "no_hmac_key", out
    v = DT.verify(str(state_file), "a.b", "q")
    assert v["ok"] is False and v["reason"] == "no_hmac_key", v


def test_verify_rejects_tampered_state(state_file):
    """直写 state（不重算 `_checksum`）⟹ 拒：否则可把 used_at 抹回 null 绕过单次语义。"""
    out = DT.issue(str(state_file), "query-A")
    d = json.loads(state_file.read_text(encoding="utf-8"))
    d["gate_data"]["note"] = "tampered"          # 直写，不重算 checksum
    state_file.write_text(json.dumps(d), encoding="utf-8")
    v = DT.verify(str(state_file), out["ticket"], "query-A")
    assert v["ok"] is False and v["reason"] == "state_tampered", v


def test_issue_rejects_tampered_state(state_file):
    d = json.loads(state_file.read_text(encoding="utf-8"))
    d["gate_data"]["note"] = "tampered"
    state_file.write_text(json.dumps(d), encoding="utf-8")
    assert DT.issue(str(state_file), "q")["error"] == "state_tampered"


def test_issue_keeps_consumed_tickets_for_reconciliation(state_file):
    """已消费票据保留 `USED_RETENTION`（B 对账窗口）；未过期未消费的同样保留。"""
    out = DT.issue(str(state_file), "q1")
    assert DT.verify(str(state_file), out["ticket"], "q1")["ok"] is True
    DT.issue(str(state_file), "q2")
    lst = json.loads(state_file.read_text(encoding="utf-8"))["gate_data"]["dispatch_tickets"]
    assert [r["sha"] for r in lst] == [DT.query_sha("q1"), DT.query_sha("q2")], lst
    assert lst[0]["used_at"] and lst[1]["used_at"] is None


def test_issue_prunes_expired_unused(state_file, monkeypatch):
    DT.issue(str(state_file), "q_old", ttl=1)
    real = DT._now
    monkeypatch.setattr(DT, "_now", lambda: real() + 5)
    DT.issue(str(state_file), "q_new")
    lst = json.loads(state_file.read_text(encoding="utf-8"))["gate_data"]["dispatch_tickets"]
    assert [r["sha"] for r in lst] == [DT.query_sha("q_new")], lst


# ── ①b B（授权 → 产物）：报告登记 ────────────────────────────────────────────
def _report(state_file, name="r.md"):
    p = Path(str(state_file)).parent / name
    p.write_text("# report\n", encoding="utf-8")
    return str(p)


def test_record_report_binds_consumed_ticket(state_file):
    out = DT.issue(str(state_file), "q", session="s")
    assert DT.verify(str(state_file), out["ticket"], "q", session="s")["ok"] is True
    rep = _report(state_file)
    r = DT.record_report(str(state_file), rep, session="s")
    assert r["ok"] is True and r["bound"] is True and r["nonce"] == out["nonce"], r
    rec = json.loads(state_file.read_text(encoding="utf-8"))["gate_data"]["dispatch_tickets"][0]
    assert rec["report_file"] == rep and rec["report_origin"] == "cli"


def test_record_report_is_idempotent(state_file):
    rep = _report(state_file)
    first = DT.record_report(str(state_file), rep)
    second = DT.record_report(str(state_file), rep)
    assert first["ok"] and second["ok"]
    assert second["bound"] is False and second["note"] == "already-recorded", second
    lst = json.loads(state_file.read_text(encoding="utf-8"))["gate_data"]["dispatch_tickets"]
    assert len(lst) == 1, lst


def test_record_report_self_records_without_ticket(state_file):
    """CLI 直调 `monitor --subagent` 不经 Task 票据 ⟹ 自记账（origin=report）。"""
    rep = _report(state_file)
    r = DT.record_report(str(state_file), rep, session="s")
    assert r["ok"] is True and r["bound"] is False, r
    rec = json.loads(state_file.read_text(encoding="utf-8"))["gate_data"]["dispatch_tickets"][0]
    assert rec["origin"] == "report" and rec["report_file"] == rep
    assert rec["used_at"] and rec["used_by"] == "s"


def test_record_report_requires_key(state_file, monkeypatch):
    monkeypatch.delenv("GATEKEEPER_HMAC_KEY", raising=False)
    monkeypatch.delenv("GK_JOURNAL_KEY", raising=False)
    r = DT.record_report(str(state_file), _report(state_file))
    assert r["ok"] is False and r["error"] == "no_hmac_key", r


def test_record_report_rejects_tampered_state(state_file):
    d = json.loads(state_file.read_text(encoding="utf-8"))
    d["gate_data"]["note"] = "tampered"
    state_file.write_text(json.dumps(d), encoding="utf-8")
    r = DT.record_report(str(state_file), _report(state_file))
    assert r["ok"] is False and r["error"] == "state_tampered", r


# ── ② 票据键的写面保护（防重置 used_at ⟹ 重放）────────────────────────────────
def test_update_gate_data_refuses_dispatch_tickets(state_file):
    out = SP.cmd_update_gate_data(str(state_file), '{"dispatch_tickets": []}')
    assert out["ok"] is False and "dispatch_tickets" in out["error"], out


def test_set_nested_refuses_dispatch_tickets(state_file):
    err = SP._path_denied(["gate_data", "dispatch_tickets"])
    assert "票据" in err, err


# ── ③ hook Gate 0 行为 ───────────────────────────────────────────────────────
@pytest.fixture()
def hook_state(state_file, monkeypatch):
    monkeypatch.setattr(pre_tool_hook, "STATE_FILE", state_file)
    return state_file


def test_hook_blocks_task_without_ticket(hook_state):
    deny = pre_tool_hook._task_dispatch_gate("Task", {"query": "随便什么任务"}, "s")
    assert "no_ticket" in deny, deny


def test_hook_allows_task_with_matching_ticket(hook_state):
    out = DT.issue(str(hook_state), "do it", session="s")
    q = "do it\nGK-TICKET:%s" % out["ticket"]
    assert pre_tool_hook._task_dispatch_gate("Task", {"query": q}, "s") == ""


def test_hook_second_use_is_blocked(hook_state):
    out = DT.issue(str(hook_state), "do it", session="s")
    q = "do it\nGK-TICKET:%s" % out["ticket"]
    assert pre_tool_hook._task_dispatch_gate("Task", {"query": q}, "s") == ""
    deny = pre_tool_hook._task_dispatch_gate("Task", {"query": q}, "s")
    assert "used" in deny, deny


def test_hook_keyword_hit_only_warns(hook_state):
    """关键词命中 ⟹ 仍需票据；但**有票即放行**（旧行为是无条件 BLOCK）。"""
    q = "请质询这个计划 gatekeeper plan-refinement"
    assert "no_ticket" in pre_tool_hook._task_dispatch_gate("Task", {"query": q}, "s")
    out = DT.issue(str(hook_state), q, session="s")
    assert pre_tool_hook._task_dispatch_gate(
        "Task", {"query": q + "\nGK-TICKET:" + out["ticket"]}, "s") == ""


def test_hook_ignores_non_task_tools(hook_state):
    assert pre_tool_hook._task_dispatch_gate("RunCommand", {"command": "ls"}, "s") == ""


def test_hook_allows_out_of_governance(tmp_path, monkeypatch):
    monkeypatch.setattr(pre_tool_hook, "STATE_FILE", tmp_path / "absent-state.json")
    assert pre_tool_hook._task_dispatch_gate("Task", {"query": "x"}, "") == ""

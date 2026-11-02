#!/usr/bin/env python3
"""D6a 离线回放报告的行为臂（2026-10-28，审计署 §27.2）。

纪律：报告只读（不写账本 / state / 封印）、单源复用 `reconcile`、`chain` 取封印实况、
不宣称 §17.3 ① 解锁。负臂 = 未审债仍出报告但 `ok=False`。
"""
import hashlib
import json

import gk_credit_ledger as L


def _seed(tmp_path, with_outcome=True):
    st = tmp_path / "probe.state"
    st.write_text(json.dumps({"note": "d6a"}), encoding="utf-8")
    r = L.append(str(st), "raise", source="code-fix")
    assert r["ok"], r
    rid = r["record"]["id"]
    if with_outcome:
        o = L.append(str(st), "success", source="code-fix", ref=rid,
                     model_version="m", temperature=0.0, seed=1)
        assert o["ok"], o
    return str(st), rid


def test_replay_report_happy_path_is_readonly(tmp_path):
    st, _ = _seed(tmp_path)
    lp = L._logical_path(st)
    before = lp.read_bytes()
    rep = L.replay_report(st)
    assert rep["ok"] is True, rep
    assert rep["schema"] == L.REPLAY_SCHEMA
    assert rep["chain"] in ("legacy", "verified"), rep
    assert rep["ledger_sha256"] == hashlib.sha256(before).hexdigest()
    assert lp.read_bytes() == before, "报告不得改写账本（只读纪律）"
    art = json.loads(open(rep["report_path"], encoding="utf-8").read())
    assert art["schema"] == L.REPLAY_SCHEMA
    assert art["reconcile"]["unreconciled"] == []
    assert art["state_file"] == rep["state_file"]


def test_replay_report_unreconciled_still_emits_artifact(tmp_path):
    st, rid = _seed(tmp_path, with_outcome=False)
    rep = L.replay_report(st)
    assert rep["ok"] is False
    assert rep["reconcile"]["unreconciled"] == [rid]
    assert json.loads(open(rep["report_path"], encoding="utf-8").read())["ok"] is False


def test_replay_report_require_seal_boundary(tmp_path):
    st, _ = _seed(tmp_path)
    L._seal_path(st).unlink()
    assert L.replay_report(st, require_seal=True)["ok"] is False
    assert L.replay_report(st, require_seal=False)["ok"] is True


def test_cli_replay_report(tmp_path, capsys):
    st, _ = _seed(tmp_path)
    rc = L.main(["replay-report", "--state", st])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and out["ok"] is True, out
    assert out["report_path"].endswith(".replay-report.json")

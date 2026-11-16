#!/usr/bin/env python3
"""D6a 离线回放报告红先臂（2026-11-16）。

判据：artifact 必须带 schema / ledger 路径 / sha256 / `chain="legacy"` / `require_seal`，
且判定只来自 `gk_credit_ledger.reconcile`（禁第二实现）。缺账本 ⟹ 具名失败。
"""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_audit_replay as R  # noqa: E402
import gk_credit_ledger as CL  # noqa: E402


def _mk(tmp_path, rows):
    st = tmp_path / "s.json"
    st.write_text(json.dumps({"gate_data": {}}, ensure_ascii=False), encoding="utf-8", newline="\n")
    led = Path(str(st) + CL.SUFFIX)
    led.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows),
                   encoding="utf-8", newline="\n")
    return str(st)


def _outcome(ref):
    return {"ts": "2026-11-16T00:00:01Z", "kind": "success", "ref": ref, "delta": 5,
            "model_version": "m", "temperature": 0.0, "seed": 1}


def _raise(rid):
    return {"ts": "2026-11-16T00:00:00Z", "id": rid, "kind": "raise", "delta": 0,
            "source": "state_patch"}


def test_replay_artifact_carries_schema_sha_and_legacy_chain(tmp_path, capsys):
    st = _mk(tmp_path, [_raise("r1"), _outcome("r1")])
    out = tmp_path / "artifact.json"
    assert R.main(["--state", st, "--out", str(out)]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["ok"] is True, body
    art = json.loads(out.read_text(encoding="utf-8"))
    assert art["schema"] == "d6a-replay-1"
    assert art["chain"] == "legacy" and art["require_seal"] is True
    assert art["ledger_path"] == str(Path(str(st) + CL.SUFFIX))
    assert art["ledger_sha256"] == hashlib.sha256(
        Path(str(st) + CL.SUFFIX).read_bytes()).hexdigest()
    assert art["raises"] == 1 and art["audited"] == 1 and art["unreconciled"] == []


def test_replay_reports_unreconciled_debt(tmp_path):
    st = _mk(tmp_path, [_raise("r1"), _raise("r2"), _outcome("r1")])
    art = R.replay(st)
    assert art["ok"] is True, art
    assert art["unreconciled"] == ["r2"], art
    assert art["verdict"] != "ok", art


def test_replay_missing_ledger_fails_loud(tmp_path, capsys):
    st = tmp_path / "s.json"
    st.write_text(json.dumps({"gate_data": {}}), encoding="utf-8", newline="\n")
    rc = R.main(["--state", str(st), "--out", str(tmp_path / "a.json")])
    body = json.loads(capsys.readouterr().out)
    assert rc == 1 and body.get("error") == "ledger_missing", body
    assert not (tmp_path / "a.json").exists(), "失败不得落 artifact"


def test_replay_bad_seal_surfaces_not_silent(tmp_path):
    st = _mk(tmp_path, [_raise("r1")])
    Path(str(st) + CL.SEAL_SUFFIX).write_text("not-a-seal\n", encoding="utf-8")
    art = R.replay(st)
    assert art["ok"] is True, art
    assert art["verdict"] == "debt_or_integrity", art
    assert art["seal"], art

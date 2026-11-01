"""test_gk_opcap_baseline.py — 判据5「判定式载体」红先臂（四环：写 / 读 / 比对 / 阈值）。

缺口（审计署 §23.2 / §26.4）：`gk_opcap_export` 只产读数；**基线本体与判定式零实现**
（`x4` 已随上游 v47/v48 删除、`x3` 零载体）⟹ 判据5 无法机检、禁判 PASS。

本切片只落**载体**，不造合成基线：
  · 写：`write()` 现场导出 + `seq`/`prev` 封印链（复用 D3a）；
  · 读：`read()` 真验签 + 链校验（可 `require_chain`）；
  · 比对：`compare()` 逐轴（x3 / x4 / x8）给 `ok|regressed|unavailable`；
  · 阈值：`finalize()` + `gate()` —— **FAIL > INCOMPLETE > PASS**；
    缺载体轴 / 样本不足（< 20）一律 `INCOMPLETE`，**绝不**假绿。
"""
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import gk_opcap_baseline as OB  # noqa: E402


@pytest.fixture()
def keys(tmp_path):
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    d = tmp_path / "keys"
    d.mkdir()
    priv = Ed25519PrivateKey.generate()
    (d / "audit_ed25519.pem").write_bytes(priv.private_bytes(
        ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    (d / "audit_ed25519.pub").write_bytes(priv.public_key().public_bytes(
        ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))
    return str(d)


def _finding(i, hours, status="closed"):
    created = "2026-10-01T00:00:00Z"
    closed = "2026-10-01T%02d:00:00Z" % hours
    rec = {"id": "ECC-%012X" % i, "status": status, "created_at": created}
    if status in ("fixed", "closed"):
        rec["verified_at"] = closed
    return rec


def _mk(tmp_path, name, findings, events):
    st = tmp_path / (name + ".state")
    st.write_text(json.dumps({"gate_data": {"ecc_findings": findings}}, ensure_ascii=False),
                  encoding="utf-8", newline="\n")
    bl = Path(str(st) + ".budget-log.jsonl")
    bl.write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events),
                  encoding="utf-8", newline="\n")
    return str(st)


def _fix(i):
    return {"ts": "2026-10-02T00:00:00Z", "kind": "raise", "source": "code-fix",
            "to_max": 24, "reason": "grant for ECC-%012X" % i}


def _twenty(hours):
    return ([_finding(i, hours) for i in range(1, 21)], [_fix(i) for i in range(1, 21)])


def _baseline(tmp_path, keys, findings, events, name="base"):
    st = _mk(tmp_path, name, findings, events)
    out = str(tmp_path / (name + ".opcap-baseline.json"))
    r = OB.write(st, out=out, key_dir=keys, reason="arm")
    assert r["ok"] is True, r
    return st, out


# ── ① 写 → 读：基线与封印链可复算 ───────────────────────────────────────────
def test_write_read_roundtrip_with_seal_and_chain(tmp_path, keys):
    findings, events = _twenty(2)
    st, out = _baseline(tmp_path, keys, findings, events)
    assert Path(out).exists()
    assert Path(out + ".seal").exists()
    assert Path(out + ".seal" + ".seal-chain.jsonl").exists()
    got = OB.read(out, key_dir=keys, require_chain=True)
    assert got["ok"] is True, got
    assert got["record"]["metrics"]["x8"]["median_hours"] == 2.0, got
    assert got["record"]["metrics"]["x3"]["status"] == "no_carrier", got
    assert got["record"]["metrics"]["x4"]["status"] == "removed_upstream", got


# ── ② 读环 fail-closed：基线被改 ⟹ digest_mismatch ─────────────────────────
def test_read_rejects_tampered_baseline(tmp_path, keys):
    findings, events = _twenty(2)
    _, out = _baseline(tmp_path, keys, findings, events)
    rec = json.loads(Path(out).read_text(encoding="utf-8"))
    rec["metrics"]["x8"]["median_hours"] = 0.0
    Path(out).write_text(json.dumps(rec, ensure_ascii=False) + "\n", encoding="utf-8")
    got = OB.read(out, key_dir=keys)
    assert got["ok"] is False and "digest_mismatch" in got["error"], got


# ── ③ 阈值环：无基线 ⟹ baseline_missing（禁默认放行）────────────────────────
def test_gate_without_baseline_fails_closed(tmp_path, keys):
    findings, events = _twenty(2)
    st = _mk(tmp_path, "cur", findings, events)
    got = OB.gate(st, str(tmp_path / "nope.json"), key_dir=keys)
    assert got["ok"] is False and got["error"] == "baseline_missing", got


# ── ④ 缺载体轴（x3 / x4）⟹ INCOMPLETE，绝不 PASS ───────────────────────────
def test_gate_is_incomplete_without_x3_x4_carriers(tmp_path, keys):
    findings, events = _twenty(2)
    st, out = _baseline(tmp_path, keys, findings, events)
    got = OB.gate(st, out, key_dir=keys)
    assert got["ok"] is True, got
    assert got["verdict"] == "INCOMPLETE", got
    assert any(r.startswith("x3:") for r in got["reasons"]), got
    assert any(r.startswith("x4:") for r in got["reasons"]), got


# ── ⑤ x8 恶化 ⟹ FAIL（即使 x3/x4 缺载体）──────────────────────────────────
def test_gate_fails_on_x8_regression(tmp_path, keys):
    b_find, b_ev = _twenty(2)
    _, out = _baseline(tmp_path, keys, b_find, b_ev, name="base")
    c_find, c_ev = _twenty(10)
    st = _mk(tmp_path, "cur", c_find, c_ev)
    got = OB.gate(st, out, key_dir=keys)
    assert got["ok"] is True and got["verdict"] == "FAIL", got
    assert got["axes"]["x8"]["status"] == "regressed", got


# ── ⑥ 样本不足（< 20）⟹ INCOMPLETE（insufficient_samples）──────────────────
def test_gate_incomplete_on_insufficient_samples(tmp_path, keys):
    st, out = _baseline(tmp_path, keys, [_finding(1, 2)], [_fix(1)], name="weak")
    got = OB.gate(st, out, key_dir=keys)
    assert got["verdict"] == "INCOMPLETE", got
    assert "insufficient_samples" in got["reasons"], got


# ── ⑦ 阈值优先级：FAIL > INCOMPLETE > PASS ─────────────────────────────────
def test_finalize_priority():
    assert OB.finalize("PASS", weak=False) == "PASS"
    assert OB.finalize("PASS", weak=True) == "INCOMPLETE"
    assert OB.finalize("INCOMPLETE", weak=True) == "INCOMPLETE"
    assert OB.finalize("FAIL", weak=True) == "FAIL"


# ── ⑧ 比对环纯函数：三轴齐全且在阈内 ⟹ PASS；x3 缺 ⟹ INCOMPLETE ───────────
def _metrics(x3="available", x4="available", med=2.0):
    return {
        "x3": {"status": x3, "value": 0.0},
        "x4": {"status": x4, "value": 0.0},
        "x8": {"status": "available", "median_hours": med, "max_hours": med, "n_closed": 20},
    }


def test_compare_passes_only_when_all_axes_comparable_and_within_threshold():
    ok = OB.compare(_metrics(), _metrics(med=2.0), x8_rel_tol=0.0)
    assert ok["verdict"] == "PASS", ok
    bad = OB.compare(_metrics(), _metrics(med=3.0), x8_rel_tol=0.0)
    assert bad["verdict"] == "FAIL" and bad["axes"]["x8"]["status"] == "regressed", bad
    inc = OB.compare(_metrics(x3="no_carrier"), _metrics(x3="no_carrier"))
    assert inc["verdict"] == "INCOMPLETE", inc


# ── ⑨ CLI 三环可用（write / read / gate）───────────────────────────────────
def test_cli_write_read_gate(tmp_path, keys, capsys):
    findings, events = _twenty(2)
    st = _mk(tmp_path, "cli", findings, events)
    out = str(tmp_path / "cli.baseline.json")
    assert OB.main(["write", "--state", st, "--out", out, "--key-dir", keys]) == 0
    w = json.loads(capsys.readouterr().out)
    assert w["ok"] is True, w

    assert OB.main(["read", "--baseline", out, "--key-dir", keys]) == 0
    r = json.loads(capsys.readouterr().out)
    assert r["ok"] is True, r

    assert OB.main(["gate", "--state", st, "--baseline", out, "--key-dir", keys]) == 0
    g = json.loads(capsys.readouterr().out)
    assert g["verdict"] == "INCOMPLETE", g

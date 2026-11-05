"""`gk_key_meta.py`（`cmd_audit --key` 两段内联 heredoc 下沉，2026-11-04）。

覆盖：NIST SP 800-57 状态迁移判定（含 meta 缺失放行）与轮换元数据写回。
"""
import hashlib
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
from gk_key_meta import check_transition, update_meta  # noqa: E402


def test_missing_meta_allows(tmp_path):
    assert check_transition(str(tmp_path / "absent.json"), "context", "active") == "ok"


def test_valid_transition(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"context_ed25519": {"status": "pre-activation"}}), encoding="utf-8")
    assert check_transition(str(p), "context", "active") == "ok"


def test_invalid_transition(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"context_ed25519": {"status": "destroyed"}}), encoding="utf-8")
    out = check_transition(str(p), "context", "active")
    assert out.startswith("INVALID: destroyed -> active"), out


def test_missing_status_defaults_to_pre_activation(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"audit_ed25519": {}}), encoding="utf-8")
    assert check_transition(str(p), "audit", "active") == "ok"


def test_update_meta_writes_fields_and_preserves_others(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"other": {"keep": 1}}), encoding="utf-8")
    pub = tmp_path / "k.pub"
    pub.write_bytes(b"PUBKEY-BYTES")
    fp = hashlib.sha256(b"PUBKEY-BYTES").hexdigest()
    rec = update_meta(str(p), "context", 7, "20261104_120000", str(pub))
    assert rec["status"] == "active"
    assert rec["rotation_days"] == 7
    assert rec["rotated_from"] == "20261104_120000"
    assert rec["fingerprint"] == fp
    saved = json.loads(p.read_text())
    assert saved["other"] == {"keep": 1}
    assert saved["context_ed25519"] == rec
    # expires ≈ now + 7d（容忍 120s 时钟抖动）
    import calendar
    exp = calendar.timegm(time.strptime(rec["expires"], "%Y-%m-%dT%H:%M:%SZ"))
    assert abs(exp - (time.time() + 7 * 86400)) < 120


def test_update_meta_missing_pub_gives_empty_fingerprint(tmp_path):
    p = tmp_path / "m.json"
    rec = update_meta(str(p), "audit", 30, "ts", str(tmp_path / "nope.pub"))
    assert rec["fingerprint"] == ""
    assert os.path.exists(p)


# ── verify_fingerprints（`_verify_key_integrity` heredoc 下沉）──────────────

def _pub(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_fingerprints_missing_meta_passes(tmp_path):
    from gk_key_meta import verify_fingerprints
    assert verify_fingerprints(str(tmp_path / "absent.json"), str(tmp_path)) == 0


def test_fingerprints_match_passes(tmp_path, capsys):
    from gk_key_meta import verify_fingerprints
    _pub(tmp_path, "context_ed25519.pub", b"CTX")
    meta = tmp_path / "m.json"
    meta.write_text(json.dumps({"context_ed25519": {
        "fingerprint": hashlib.sha256(b"CTX").hexdigest()}}), encoding="utf-8")
    assert verify_fingerprints(str(meta), str(tmp_path)) == 0
    assert capsys.readouterr().out == ""


def test_fingerprints_replaced_fails(tmp_path, capsys):
    from gk_key_meta import verify_fingerprints
    _pub(tmp_path, "context_ed25519.pub", b"REPLACED")
    meta = tmp_path / "m.json"
    meta.write_text(json.dumps({"context_ed25519": {
        "fingerprint": hashlib.sha256(b"ORIGINAL").hexdigest()}}), encoding="utf-8")
    assert verify_fingerprints(str(meta), str(tmp_path)) == 1
    assert "tampered:context_ed25519 pubkey replaced" in capsys.readouterr().out


def test_fingerprints_missing_pub_skipped(tmp_path):
    from gk_key_meta import verify_fingerprints
    meta = tmp_path / "m.json"
    meta.write_text(json.dumps({"audit_ed25519": {"fingerprint": "deadbeef"}}), encoding="utf-8")
    assert verify_fingerprints(str(meta), str(tmp_path)) == 0

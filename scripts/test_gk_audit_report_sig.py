"""test_gk_audit_report_sig.py — 侧车签名：签→验 / 篡改→invalid / 无钥→unsigned / 门禁拦 invalid。"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gk_audit_report as AR  # noqa: E402
import gk_audit_registry as REG  # noqa: E402


def _keys(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    d = tmp_path / "keys"
    d.mkdir()
    k = ed25519.Ed25519PrivateKey.generate()
    (d / "audit_ed25519.pem").write_bytes(k.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (d / "audit_ed25519.pub").write_bytes(k.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return d


def _state(tmp_path):
    p = tmp_path / "s.state"
    p.write_text("{}", encoding="utf-8")
    return str(p)


def test_signed_sidecar_verifies(tmp_path):
    kd = _keys(tmp_path)
    st = _state(tmp_path)
    AR.write(st, audit_id="a1", audit_type="state", key_dir=str(kd))
    assert json.loads(Path(AR.sidecar_path(st)).read_text())["signature"]["status"] == "verified"
    assert AR.verify_sidecar(st, key_dir=str(kd))["status"] == "verified"


def test_tampered_sidecar_is_invalid(tmp_path):
    kd = _keys(tmp_path)
    st = _state(tmp_path)
    AR.write(st, audit_id="a1", audit_type="state", key_dir=str(kd))
    p = Path(AR.sidecar_path(st))
    doc = json.loads(p.read_text())
    doc["summary"]["total"] = 99
    p.write_text(json.dumps(doc), encoding="utf-8")
    assert AR.verify_sidecar(st, key_dir=str(kd))["status"] == "invalid"


def test_no_key_is_unsigned_not_blocking(tmp_path):
    st = _state(tmp_path)
    AR.write(st, audit_id="a1", key_dir=str(tmp_path / "nokeys"))
    assert AR.verify_sidecar(st, key_dir=str(tmp_path / "nokeys"))["status"] == "unsigned"


def test_gate_blocks_invalid_report_signature(tmp_path, monkeypatch):
    kd = _keys(tmp_path)
    st = _state(tmp_path)
    AR.write(st, audit_id="a1", key_dir=str(kd))
    p = Path(AR.sidecar_path(st))
    doc = json.loads(p.read_text())
    doc["findings"] = [{"id": "forged"}]
    p.write_text(json.dumps(doc), encoding="utf-8")
    monkeypatch.setattr(REG, "verify", lambda *a, **k: {"ok": True})
    monkeypatch.setattr(REG, "read_entries", lambda *a, **k: ([], ""))
    monkeypatch.setattr(REG, "_latest_by_domain", lambda e: {})
    monkeypatch.setattr(REG, "_logical_path", lambda p: Path(p))
    out = REG.dual_read(st, {}, key_dir=str(kd))
    assert out["ok"] is False
    assert "report_sig_invalid" in out["reason"]

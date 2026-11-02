"""test_gk_crypto_cli.py — B8 红先（2026-10-27，锚 RED-MIGRATE-INLINE）

把 `gatekeeper-cli.sh` 的 5 个 Ed25519 内联块抽成 `gk_crypto_cli.py`：
audit-sign / sign-raw / verify-raw / verify-resolution / set-resolution-sig。
字节契约逐字对齐旧内联（签名对象、JSON 键序、错误串）。
"""
import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).parent
CLI = SCRIPTS / "gk_crypto_cli.py"


def _run(*args, stdin_text=""):
    p = subprocess.run([sys.executable, str(CLI)] + list(args),
                       input=stdin_text, capture_output=True, text=True, encoding="utf-8")
    return p


@pytest.fixture
def keypair(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    priv_f = tmp_path / "ed25519.key"
    pub_f = tmp_path / "ed25519.pub"
    priv_f.write_bytes(priv_pem)
    pub_f.write_bytes(pub_pem)
    return priv, priv_f, pub_f


class TestSignRaw:
    def test_sign_and_verify_roundtrip(self, keypair, tmp_path):
        _, priv_f, pub_f = keypair
        data = tmp_path / "payload.bin"
        raw = b'{"a": 1}\n'
        data.write_bytes(raw)

        p = _run("sign-raw", str(priv_f), str(data))
        assert p.returncode == 0, p
        out = json.loads(p.stdout)
        assert list(out.keys()) == ["sig", "hash"], out
        assert out["hash"] == hashlib.sha256(raw).hexdigest()
        assert len(base64.b64decode(out["sig"])) == 64

        v = _run("verify-raw", str(data), out["sig"], out["hash"], str(pub_f))
        assert v.returncode == 0 and json.loads(v.stdout) == {"ok": True}, v

    def test_verify_hash_mismatch(self, keypair, tmp_path):
        _, priv_f, pub_f = keypair
        data = tmp_path / "payload.bin"
        data.write_bytes(b"abc")
        out = json.loads(_run("sign-raw", str(priv_f), str(data)).stdout)
        v = _run("verify-raw", str(data), out["sig"], "deadbeef", str(pub_f))
        assert v.returncode == 0
        assert json.loads(v.stdout) == {"ok": False, "error": "hash mismatch"}, v

    def test_verify_invalid_signature(self, keypair, tmp_path):
        _, priv_f, pub_f = keypair
        data = tmp_path / "payload.bin"
        data.write_bytes(b"abc")
        out = json.loads(_run("sign-raw", str(priv_f), str(data)).stdout)
        data.write_bytes(b"tampered")
        v = _run("verify-raw", str(data), out["sig"], "", str(pub_f))
        assert v.returncode == 0
        assert json.loads(v.stdout) == {"ok": False, "error": "invalid signature"}, v

    def test_verify_missing_public_key(self, keypair, tmp_path):
        _, priv_f, _ = keypair
        data = tmp_path / "payload.bin"
        data.write_bytes(b"abc")
        out = json.loads(_run("sign-raw", str(priv_f), str(data)).stdout)
        v = _run("verify-raw", str(data), out["sig"], "", str(tmp_path / "nope.pub"))
        assert v.returncode == 0
        assert json.loads(v.stdout) == {"ok": False, "error": "no public key"}, v

    def test_verify_missing_file_nonzero(self, keypair, tmp_path):
        _, _, pub_f = keypair
        v = _run("verify-raw", str(tmp_path / "missing.bin"), "AA==", "", str(pub_f))
        assert v.returncode != 0, v

    def test_sign_missing_key_nonzero(self, tmp_path):
        data = tmp_path / "payload.bin"
        data.write_bytes(b"abc")
        p = _run("sign-raw", str(tmp_path / "nope.key"), str(data))
        assert p.returncode != 0, p


class TestAuditSign:
    def test_audit_sign_shape_and_validity(self, keypair, tmp_path):
        _, priv_f, pub_f = keypair
        data = tmp_path / "payload.bin"
        raw = b'report-body'
        data.write_bytes(raw)
        p = _run("audit-sign", str(priv_f), str(data))
        assert p.returncode == 0, p
        out = json.loads(p.stdout)
        assert list(out.keys()) == ["hash", "signature"], out
        assert out["hash"] == hashlib.sha256(raw).hexdigest()
        v = _run("verify-raw", str(data), out["signature"], out["hash"], str(pub_f))
        assert json.loads(v.stdout) == {"ok": True}, v

    def test_audit_sign_missing_key_nonzero(self, tmp_path):
        data = tmp_path / "payload.bin"
        data.write_bytes(b"abc")
        p = _run("audit-sign", str(tmp_path / "nope.key"), str(data))
        assert p.returncode != 0, p


def _state_with_resolution(tmp_path, rec):
    st = tmp_path / "state.json"
    st.write_text(json.dumps({"human_resolutions": {"G1": rec}}, ensure_ascii=False),
                  encoding="utf-8")
    return st


def _sign_payload(priv, payload: bytes):
    return base64.b64encode(priv.sign(payload)).decode()


class TestVerifyResolution:
    def _rec(self):
        return {"gate": "G1", "source": "escalate", "resolution": "approve", "reason": "ok"}

    def test_ok_no_newline(self, keypair, tmp_path):
        priv, _, pub_f = keypair
        rec = self._rec()
        payload = json.dumps(rec, sort_keys=True).encode()
        rec = dict(rec, ed25519_sig=_sign_payload(priv, payload))
        st = _state_with_resolution(tmp_path, rec)
        p = _run("verify-resolution", str(st), "G1", str(pub_f), str(tmp_path / "ctx.pub"))
        assert p.returncode == 0, p
        out = json.loads(p.stdout)
        assert out["ok"] is True and out["key"] == "audit" and out["gate"] == "G1", out

    def test_ok_legacy_trailing_newline(self, keypair, tmp_path):
        priv, _, pub_f = keypair
        rec = self._rec()
        payload = json.dumps(rec, sort_keys=True).encode() + b"\n"
        rec = dict(rec, ed25519_sig=_sign_payload(priv, payload))
        st = _state_with_resolution(tmp_path, rec)
        p = _run("verify-resolution", str(st), "G1", str(pub_f), str(tmp_path / "ctx.pub"))
        assert json.loads(p.stdout)["ok"] is True, p

    def test_context_legacy_key(self, keypair, tmp_path):
        _, _, audit_pub = keypair
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        cpriv = ed25519.Ed25519PrivateKey.generate()
        ctx_pub = tmp_path / "ctx.pub"
        ctx_pub.write_bytes(cpriv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        rec = self._rec()
        payload = json.dumps(rec, sort_keys=True).encode()
        rec = dict(rec, ed25519_sig=base64.b64encode(cpriv.sign(payload)).decode())
        st = _state_with_resolution(tmp_path, rec)
        p = _run("verify-resolution", str(st), "G1", str(audit_pub), str(ctx_pub))
        out = json.loads(p.stdout)
        assert out["ok"] is True and out["key"] == "context_legacy", out

    def test_missing_sig(self, keypair, tmp_path):
        _, _, pub_f = keypair
        st = _state_with_resolution(tmp_path, self._rec())
        p = _run("verify-resolution", str(st), "G1", str(pub_f), str(tmp_path / "ctx.pub"))
        assert json.loads(p.stdout) == {"ok": False, "error": "missing_sig", "gate": "G1"}, p

    def test_fake_sig_wrong_length(self, keypair, tmp_path):
        _, _, pub_f = keypair
        rec = dict(self._rec(), ed25519_sig=base64.b64encode(b"short").decode())
        st = _state_with_resolution(tmp_path, rec)
        p = _run("verify-resolution", str(st), "G1", str(pub_f), str(tmp_path / "ctx.pub"))
        out = json.loads(p.stdout)
        assert out["ok"] is False and out["error"] == "fake_sig" and out["sig_len"] > 0, out

    def test_invalid_sig(self, keypair, tmp_path):
        priv, _, pub_f = keypair
        rec = dict(self._rec(), ed25519_sig=_sign_payload(priv, b"other payload"))
        st = _state_with_resolution(tmp_path, rec)
        p = _run("verify-resolution", str(st), "G1", str(pub_f), str(tmp_path / "ctx.pub"))
        out = json.loads(p.stdout)
        assert out["ok"] is False and out["error"] == "invalid_sig", out
        assert "dbg_payload" in out, out

    def test_missing_state_nonzero(self, keypair, tmp_path):
        _, _, pub_f = keypair
        p = _run("verify-resolution", str(tmp_path / "none.json"), "G1",
                 str(pub_f), str(tmp_path / "ctx.pub"))
        assert p.returncode != 0, p


class TestSetResolutionSig:
    def test_writes_fields_and_preserves_rest(self, tmp_path):
        st = _state_with_resolution(tmp_path, {"gate": "G1", "resolution": "approve"})
        p = _run("set-resolution-sig", str(st), "G1", "SIGB64", "HASHHEX")
        assert p.returncode == 0, p
        d = json.loads(st.read_text(encoding="utf-8"))
        rec = d["human_resolutions"]["G1"]
        assert rec["ed25519_sig"] == "SIGB64" and rec["ed25519_hash"] == "HASHHEX", rec
        assert rec["resolution"] == "approve", rec

    def test_missing_gate_is_noop(self, tmp_path):
        st = tmp_path / "state.json"
        st.write_text(json.dumps({"human_resolutions": {}}), encoding="utf-8")
        p = _run("set-resolution-sig", str(st), "GX", "S", "H")
        assert p.returncode == 0, p
        d = json.loads(st.read_text(encoding="utf-8"))
        assert d["human_resolutions"] == {}, d

    def test_does_not_touch_checksum(self, tmp_path):
        """旧式裸 `json.dump` 不重算 `_checksum`（保持既有语义，B8 不顺手改行为）。"""
        st = tmp_path / "state.json"
        st.write_text(json.dumps({"_checksum": "SENTINEL",
                                  "human_resolutions": {"G1": {"gate": "G1"}}}),
                      encoding="utf-8")
        _run("set-resolution-sig", str(st), "G1", "S", "H")
        d = json.loads(st.read_text(encoding="utf-8"))
        assert d["_checksum"] == "SENTINEL", d


class TestDispatch:
    def test_unknown_subcommand_exit_2(self):
        p = _run("no-such-verb")
        assert p.returncode == 2, p

    def test_no_arbitrary_function_call(self):
        """拒绝「模块名+函数名」泛化派发（同 B6 纪律）。"""
        p = _run("verify_raw")
        assert p.returncode == 2, p

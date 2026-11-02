#!/usr/bin/env python3
"""身份认证最小切片红先测试（2026-10-31，owner 指令「把身份认证补上」）。

契约（单源 `scripts/gk_agent_identity.py`）：
  · 签名面 = canonical(ecc[去掉 agent_identity/hmac/jwt_token]) + agent_id + pubkey_id
  · 三态 verified | unsigned | invalid；缺失 ⟹ unsigned（不阻断），验不过 ⟹ invalid（untrusted）
  · sink 的 machine_check.agent_identity 必须与本模块同源（禁第二实现）

零 API、零落盘（tmp_path 内自建密钥）。
"""
import sys
from pathlib import Path

import pytest

# 2026-11-02（CI 修复）：`cryptography` 是可选的验收依赖，未装时**跳过本文件**而非
#   收集期 ImportError（后者会让整个 pytest 会话中断，连带其它测试全不跑）。
pytest.importorskip("cryptography", reason="身份认证验签需 cryptography")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import gk_agent_identity as ident  # noqa: E402
import gk_ecc_sink as sink  # noqa: E402


def _keys(tmp_path):
    priv = ed25519.Ed25519PrivateKey.generate()
    key_path = tmp_path / "agent.pem"
    key_path.write_bytes(priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    pid = ident.pubkey_id_of(priv.public_key())
    pub_dir = tmp_path / "agents"
    pub_dir.mkdir()
    (pub_dir / (pid + ".pem")).write_bytes(priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return key_path, pub_dir, pid


def _ecc():
    return {"mode": "subagent", "subagent_id": "sub-1", "nonce": "n",
            "timestamp": "t", "task": "x", "conclusion": "ok", "confidence": "high"}


def test_sign_then_verify(tmp_path):
    key, pub_dir, pid = _keys(tmp_path)
    ecc = _ecc()
    ecc["agent_identity"] = ident.sign_ecc(ecc, str(key))
    assert ecc["agent_identity"]["pubkey_id"] == pid
    assert ecc["agent_identity"]["agent_id"] == "sub-1"
    assert ident.verify_ecc(ecc, str(pub_dir))["status"] == "verified"


def test_tamper_ecc_invalid(tmp_path):
    key, pub_dir, _ = _keys(tmp_path)
    ecc = _ecc()
    ecc["agent_identity"] = ident.sign_ecc(ecc, str(key))
    ecc["conclusion"] = "tampered"
    r = ident.verify_ecc(ecc, str(pub_dir))
    assert r["status"] == "invalid" and r["reason"] == "bad_signature"


def test_agent_id_bound_in_signature(tmp_path):
    """agent_id 在 identity 里、不参与 canonical ⟹ 必须由签名消息单独绑定。"""
    key, pub_dir, _ = _keys(tmp_path)
    ecc = _ecc()
    ecc["agent_identity"] = ident.sign_ecc(ecc, str(key), "agent-A")
    ecc["agent_identity"]["agent_id"] = "agent-B"
    assert ident.verify_ecc(ecc, str(pub_dir))["status"] == "invalid"


def test_missing_identity_is_unsigned(tmp_path):
    assert ident.verify_ecc(_ecc(), str(tmp_path))["status"] == "unsigned"


def test_pubkey_missing_is_invalid(tmp_path):
    key, pub_dir, _ = _keys(tmp_path)
    ecc = _ecc()
    ecc["agent_identity"] = ident.sign_ecc(ecc, str(key))
    for f in pub_dir.iterdir():
        f.unlink()
    r = ident.verify_ecc(ecc, str(pub_dir))
    assert r["status"] == "invalid" and r["reason"] == "pubkey_not_found"


def test_sink_projection_same_source(tmp_path, monkeypatch):
    key, pub_dir, _ = _keys(tmp_path)
    monkeypatch.setenv("GATEKEEPER_AGENT_PUBKEY_DIR", str(pub_dir))
    ecc = _ecc()
    ecc["agent_identity"] = ident.sign_ecc(ecc, str(key))
    entry = sink.bounded_entry(ecc, domain="audit", batch_id="b1", arm="a1")
    assert entry["machine_check"]["agent_identity"]["status"] == "verified"

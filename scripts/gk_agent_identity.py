#!/usr/bin/env python3
"""gk_agent_identity.py — 子代理 ECC 的**身份认证**最小切片（2026-10-31）

问题（现状）：ECC 上只有 HMAC（共享密钥 ⟹ 只能证「未被篡改」，不能证「谁产的」）与随机
`SUBAGENT_ID`（可 env 覆写 ⟹ 不具身份性）。审计/红队报告因此无法绑定到具体代理 principal。

契约（单一事实源 = 本模块；runner 签名 / CLI+sink 验签同源，禁第二实现）：
  · `agent_identity = {agent_id, pubkey_id, alg:"ed25519", sig}`（base64 裸签名）
  · `pubkey_id = sha256(DER SubjectPublicKeyInfo)[:16]`；公钥文件 `<pubkey_dir>/<pubkey_id>.pem`
  · 签名消息 = `canonical(ecc) + b"\n" + agent_id + b"\n" + pubkey_id`
    （`canonical` = 去掉 `agent_identity/hmac/jwt_token` 后的紧凑 JSON、键排序 —— 与 HMAC 的
     插入序口径**无关**，避免两套字节契约互相牵制）
  · 验签三态：`verified | unsigned | invalid`
    - 无 `agent_identity` ⟹ unsigned（**不阻断**：未配置密钥的宿主保持旧行为）
    - 有但畸形 / 公钥缺失 / 验签失败 ⟹ invalid（fail-closed，调用方按 untrusted 处置）
  · 私钥来源：`GATEKEEPER_AGENT_KEY`（PEM 路径）；`GATEKEEPER_AGENT_ID`（缺省 = subagent_id）

CLI:
  gk_agent_identity.py verify --pubkey-dir <dir>    # stdin = ECC JSON → {"status":...}
  gk_agent_identity.py sign --key <pem> [--agent-id ID]   # stdin = ECC JSON → 附带 identity 的 ECC
"""
import argparse
import base64
import hashlib
import json
import os
import sys

_IDENTITY_FIELDS = ("agent_identity", "hmac", "jwt_token")
ALG = "ed25519"


def canonical_bytes(ecc: dict) -> bytes:
    """ECC 的确定性字节面（排除身份/签名自身）。"""
    body = {k: v for k, v in (ecc or {}).items() if k not in _IDENTITY_FIELDS}
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False,
                      sort_keys=True, default=str).encode()


def sig_message(ecc: dict, agent_id: str, pubkey_id: str) -> bytes:
    """签名消息 —— 把 agent_id / pubkey_id 一起绑进签名面（二者本身不参与 canonical）。"""
    return (canonical_bytes(ecc) + b"\n" + str(agent_id).encode()
            + b"\n" + str(pubkey_id).encode())


def pubkey_id_of(public_key) -> str:
    from cryptography.hazmat.primitives import serialization as _s
    der = public_key.public_bytes(_s.Encoding.DER, _s.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:16]


def sign_ecc(ecc: dict, key_path: str, agent_id: str = "") -> dict:
    """就地返回 `agent_identity` dict（不改 ecc）。私钥/库缺失 ⟹ 抛异常，调用方决定降级。"""
    from cryptography.hazmat.primitives import serialization as _s
    with open(key_path, "rb") as f:
        priv = _s.load_pem_private_key(f.read(), password=None)
    pub = priv.public_key()
    pid = pubkey_id_of(pub)
    aid = str(agent_id or ecc.get("subagent_id") or "").strip()
    if not aid:
        raise ValueError("agent_id_empty")
    sig = priv.sign(sig_message(ecc, aid, pid))
    return {"agent_id": aid, "pubkey_id": pid, "alg": ALG,
            "sig": base64.b64encode(sig).decode()}


def _load_pubkey(path: str):
    from cryptography.hazmat.primitives import serialization as _s
    with open(path, "rb") as f:
        return _s.load_pem_public_key(f.read())


def verify_ecc(ecc: dict, pubkey_dir: str = "") -> dict:
    """验签三态。任何异常都归 invalid（不静默放行）。"""
    ident = (ecc or {}).get("agent_identity")
    if not ident:
        return {"status": "unsigned"}
    if not isinstance(ident, dict):
        return {"status": "invalid", "reason": "malformed"}
    aid = str(ident.get("agent_id") or "")
    pid = str(ident.get("pubkey_id") or "")
    sig_b64 = str(ident.get("sig") or "")
    if not (aid and pid and sig_b64):
        return {"status": "invalid", "reason": "missing_fields"}
    if not pubkey_dir:
        return {"status": "invalid", "reason": "pubkey_dir_unset"}
    path = os.path.join(pubkey_dir, pid + ".pem")
    if not os.path.exists(path):
        return {"status": "invalid", "reason": "pubkey_not_found", "pubkey_id": pid}
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization as _s
        pub = _load_pubkey(path)
        # 公钥文件名与内容必须同源（防「换文件冒充」）
        if pubkey_id_of(pub) != pid:
            return {"status": "invalid", "reason": "pubkey_id_mismatch", "pubkey_id": pid}
        sig = base64.b64decode(sig_b64, validate=True)
        pub.verify(sig, sig_message(ecc, aid, pid))
    except InvalidSignature:
        return {"status": "invalid", "reason": "bad_signature", "pubkey_id": pid}
    except Exception as e:  # noqa: BLE001 — 边界：坏 key/坏 base64 一律 invalid
        return {"status": "invalid", "reason": "verify_error:" + type(e).__name__,
                "pubkey_id": pid}
    return {"status": "verified", "agent_id": aid, "pubkey_id": pid}


def attach_identity(ecc: dict, key_path: str = "", agent_id: str = "") -> dict:
    """runner 侧便捷入口：有私钥则签，任何失败 ⟹ 不带 identity（unsigned），绝不阻断输出。"""
    kp = key_path or os.environ.get("GATEKEEPER_AGENT_KEY", "")
    if not kp or not os.path.exists(kp):
        return ecc
    try:
        ecc["agent_identity"] = sign_ecc(ecc, kp,
                                         agent_id or os.environ.get("GATEKEEPER_AGENT_ID", ""))
    except Exception as e:  # noqa: BLE001 — 可选能力：失败降级为 unsigned
        print("[identity] WARN sign skipped: %s: %s" % (type(e).__name__, e), file=sys.stderr)
    return ecc


def _read_stdin_json() -> dict:
    return json.loads(sys.stdin.read() or "{}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="gk_agent_identity.py")
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify")
    v.add_argument("--pubkey-dir", default=os.environ.get("GATEKEEPER_AGENT_PUBKEY_DIR", ""))

    s = sub.add_parser("sign")
    s.add_argument("--key", default=os.environ.get("GATEKEEPER_AGENT_KEY", ""))
    s.add_argument("--agent-id", default=os.environ.get("GATEKEEPER_AGENT_ID", ""))

    ns = p.parse_args(argv)
    if ns.cmd == "verify":
        print(json.dumps(verify_ecc(_read_stdin_json(), ns.pubkey_dir),
                         ensure_ascii=False, separators=(",", ":")))
        return 0
    ecc = _read_stdin_json()
    if not ns.key:
        print(json.dumps({"error": "key_required"}, separators=(",", ":")))
        return 2
    ecc = attach_identity(ecc, ns.key, ns.agent_id)
    print(json.dumps(ecc, ensure_ascii=False, separators=(",", ":"), default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())

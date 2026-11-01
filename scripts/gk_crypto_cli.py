#!/usr/bin/env python3
"""gk_crypto_cli.py — Ed25519 签名 / 验签 CLI（B8，2026-10-27，锚 RED-MIGRATE-INLINE）

从 `gatekeeper-cli.sh` 的 5 个内联块抽出（报告 §2 crypto/签名族）：
  · audit-sign          ← `_audit_sign`（审计报告签名）
  · sign-raw            ← `_sign_raw`（上下文/审计文件签名，key_type 由调用方选路径）
  · verify-raw          ← `_verify_raw`（原始文件验签，含 expected_hash 短路）
  · verify-resolution   ← `_verify_resolution_sig`（human_resolutions 终裁真验签）
  · set-resolution-sig  ← cmd_resolve 的签名回写（裸 json.dump，**不**重算 _checksum）

字节契约**逐字对齐旧内联**：
  · 签名对象 = 文件原始字节；hash = sha256(data).hexdigest()
  · audit-sign / sign-raw / verify-raw 输出紧凑 JSON（无空格）
  · verify-resolution 输出默认分隔符 JSON（`, ` / `: `，与旧 `json.dumps` 一致）
  · verify-resolution 的 payload = `json.dumps(rec, sort_keys=True)`；无尾换行与 legacy 尾换行两形态都试
  · 异常**不吞**（rc≠0）⟹ 调用方原有的 `2>/dev/null || echo '<fallback>'` 语义保持不变

确定性：0 API。拒绝「模块名+函数名」泛化派发（只认显式动词）。
"""
import argparse
import base64
import hashlib
import json
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: F401（保持与旧块同依赖面）


def _load_private(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _load_public(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def _compact(**kw) -> str:
    """紧凑 JSON（`{"k":"v","k2":"v2"}`）—— 对齐旧 `print('{"x":"'+v+'"...}')`。"""
    return json.dumps(kw, separators=(",", ":"), ensure_ascii=False)


def cmd_audit_sign(args) -> int:
    priv = _load_private(args.key)
    with open(args.data, "rb") as f:
        data = f.read()
    h = hashlib.sha256(data).hexdigest()
    sig = base64.b64encode(priv.sign(data)).decode()
    print(_compact(hash=h, signature=sig))
    return 0


def cmd_sign_raw(args) -> int:
    priv = _load_private(args.key)
    with open(args.data, "rb") as f:
        data = f.read()
    h = hashlib.sha256(data).hexdigest()
    sig = base64.b64encode(priv.sign(data)).decode()
    print(_compact(sig=sig, hash=h))
    return 0


def cmd_verify_raw(args) -> int:
    with open(args.data, "rb") as f:
        data = f.read()
    h = hashlib.sha256(data).hexdigest()
    if args.expected_hash and h != args.expected_hash:
        print(_compact(ok=False, error="hash mismatch"))
        return 0
    if not os.path.exists(args.pubkey):
        print(_compact(ok=False, error="no public key"))
        return 0
    try:
        pub = _load_public(args.pubkey)
        pub.verify(base64.b64decode(args.sig), data)
        print(_compact(ok=True))
    except InvalidSignature:
        print(_compact(ok=False, error="invalid signature"))
    except Exception as e:  # noqa: BLE001 — 边界：与旧 `except Exception as e` 同文案
        print(_compact(ok=False, error="verify error: " + str(e)))
    return 0


def cmd_verify_resolution(args) -> int:
    with open(args.state) as f:
        d = json.load(f)
    gate = args.gate
    res = d.get("human_resolutions", {}).get(gate, {})
    sig = res.get("ed25519_sig", "")
    if not sig:
        print(json.dumps({"ok": False, "error": "missing_sig", "gate": gate}))
        return 0
    # 重建签名 payload（排除签名字段自身）；`_dbg` 供签名契约漂移排查
    rec = {k: v for k, v in res.items() if k not in ("ed25519_sig", "ed25519_hash")}
    payload = json.dumps(rec, sort_keys=True).encode()
    dbg = payload[:80].decode("utf-8", "replace")
    # 假签名检测：base64 解码必须恰好 64 字节（Ed25519 签名长度）
    try:
        sig_bin = base64.b64decode(sig, validate=True)
    except Exception:  # noqa: BLE001 — 非法 base64 = 假签名
        print(json.dumps({"ok": False, "error": "fake_sig", "gate": gate,
                          "sig_len": len(sig)}))
        return 0
    if len(sig_bin) != 64:
        print(json.dumps({"ok": False, "error": "fake_sig", "gate": gate,
                          "sig_len": len(sig)}))
        return 0
    # 字节契约：legacy 签名端 `echo > tmp` 带尾换行；新实现无换行 ⟹ 两形态都试
    candidates = [payload, payload + b"\n"]
    for pp, label in ((args.audit_pub, "audit"), (args.context_pub, "context_legacy")):
        if not os.path.exists(pp):
            continue
        try:
            pub = _load_public(pp)
            for data in candidates:
                try:
                    pub.verify(sig_bin, data)
                    print(json.dumps({"ok": True, "key": label, "gate": gate,
                                      "dbg_payload": dbg}))
                    return 0
                except InvalidSignature:
                    continue
        except Exception:  # noqa: BLE001 — 边界：坏公钥 ⟹ 换下一把
            continue
    print(json.dumps({"ok": False, "error": "invalid_sig", "gate": gate,
                      "dbg_payload": dbg}))
    return 0


def cmd_set_resolution_sig(args) -> int:
    """旧式签名回写：**裸** `json.dump`（indent=1，不重算 `_checksum`）。"""
    with open(args.state, encoding="utf-8") as f:
        d = json.load(f)
    r = d.get("human_resolutions", {}).get(args.gate, {})
    r["ed25519_sig"] = args.sig
    r["ed25519_hash"] = args.hash
    with open(args.state, "w", encoding="utf-8", newline="\n") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="gk_crypto_cli.py")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit-sign")
    a.add_argument("key")
    a.add_argument("data")
    a.set_defaults(fn=cmd_audit_sign)

    s = sub.add_parser("sign-raw")
    s.add_argument("key")
    s.add_argument("data")
    s.set_defaults(fn=cmd_sign_raw)

    v = sub.add_parser("verify-raw")
    v.add_argument("data")
    v.add_argument("sig")
    v.add_argument("expected_hash", nargs="?", default="")
    v.add_argument("pubkey", nargs="?", default="")
    v.set_defaults(fn=cmd_verify_raw)

    r = sub.add_parser("verify-resolution")
    r.add_argument("state")
    r.add_argument("gate")
    r.add_argument("audit_pub", nargs="?", default="")
    r.add_argument("context_pub", nargs="?", default="")
    r.set_defaults(fn=cmd_verify_resolution)

    w = sub.add_parser("set-resolution-sig")
    w.add_argument("state")
    w.add_argument("gate")
    w.add_argument("sig")
    w.add_argument("hash")
    w.set_defaults(fn=cmd_set_resolution_sig)

    ns = p.parse_args(argv)
    return ns.fn(ns)


if __name__ == "__main__":
    sys.exit(main())

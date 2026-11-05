#!/usr/bin/env python3
"""密钥元数据（NIST SP 800-57 状态机 + 轮换元数据更新）。

2026-11-04 下沉：原为 `gatekeeper-cli.sh::cmd_audit --key` 内两段内联 heredoc
（706 B + 836 B）。下沉后 shell 只留一行调用，状态机可单测。

子命令
------
check-transition --meta <f> --key-type <t> --new-state <s>
    输出 `ok` 或 `INVALID: <cur> -> <new>`；meta 不存在 ⟹ `ok`（尚未建元数据，放行）。
update-meta --meta <f> --key-type <t> --rotation-days <n> --rotated-from <ts> --pub <path>
    写回 `<key>_ed25519` 条目（created/expires/status/rotated_from/rotation_days/fingerprint）。
"""
import argparse
import hashlib
import json
import os
import sys
import time

# NIST SP 800-57 允许的状态迁移
VALID = {
    "pre-activation": ["active", "deactivated", "destroyed"],
    "active": ["deactivated", "compromised"],
    "deactivated": ["destroyed"],
    "compromised": ["destroyed", "deactivated"],
    "revoked": ["destroyed"],
    "destroyed": [],
}


def check_transition(meta_file: str, key_type: str, new_state: str) -> str:
    if not os.path.exists(meta_file):
        return "ok"  # no meta yet, allow
    with open(meta_file) as f:
        meta = json.load(f)
    current = (meta.get(key_type + "_ed25519") or {}).get("status", "pre-activation")
    if new_state in VALID.get(current, []):
        return "ok"
    return "INVALID: %s -> %s not allowed" % (current, new_state)


def update_meta(meta_file: str, key_type: str, rotation_days: int,
                rotated_from: str, pub_path: str) -> dict:
    expires_sec = time.time() + int(rotation_days) * 86400
    meta = {}
    if os.path.exists(meta_file):
        with open(meta_file) as f:
            meta = json.load(f)
    new_fp = ""
    if pub_path and os.path.exists(pub_path):
        with open(pub_path, "rb") as f:
            new_fp = hashlib.sha256(f.read()).hexdigest()
    meta[key_type + "_ed25519"] = {
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "expires": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_sec)),
        "status": "active",
        "rotated_from": rotated_from,
        "rotation_days": int(rotation_days),
        "fingerprint": new_fp,
    }
    with open(meta_file, "w") as f:
        json.dump(meta, f, indent=2)
    return meta[key_type + "_ed25519"]


def verify_fingerprints(meta_file: str, key_dir: str) -> int:
    """核对 key-meta 记录的指纹与磁盘公钥（原 `_verify_key_integrity` 的 heredoc）。

    返回 0 = 通过 / meta 缺失；1 = 公钥被替换（打印 `tampered:<ktype> pubkey replaced`）。
    """
    if not meta_file or not os.path.exists(meta_file):
        return 0
    with open(meta_file) as f:
        meta = json.load(f)
    for ktype in ("context_ed25519", "audit_ed25519"):
        pub_path = os.path.join(key_dir or "", ktype.replace("_ed25519", "") + "_ed25519.pub")
        if not os.path.exists(pub_path):
            continue
        with open(pub_path, "rb") as f:
            fp = hashlib.sha256(f.read()).hexdigest()
        expected_fp = (meta.get(ktype) or {}).get("fingerprint", "")
        if expected_fp and fp != expected_fp:
            print("tampered:%s pubkey replaced" % ktype)
            return 1
    return 0


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(newline="\n")  # CRLF 净化：$() 捕获不得尾粘 \r
    except Exception:  # noqa: BLE001
        pass
    ap = argparse.ArgumentParser(prog="gk_key_meta.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check-transition")
    c.add_argument("--meta", required=True)
    c.add_argument("--key-type", required=True)
    c.add_argument("--new-state", required=True)
    u = sub.add_parser("update-meta")
    u.add_argument("--meta", required=True)
    u.add_argument("--key-type", required=True)
    u.add_argument("--rotation-days", type=int, default=1)
    u.add_argument("--rotated-from", default="")
    u.add_argument("--pub", default="")
    v = sub.add_parser("verify-fingerprints")
    v.add_argument("--meta", required=True)
    v.add_argument("--key-dir", default="")
    ns = ap.parse_args(argv)
    if ns.cmd == "check-transition":
        print(check_transition(ns.meta, ns.key_type, ns.new_state))
    elif ns.cmd == "update-meta":
        update_meta(ns.meta, ns.key_type, ns.rotation_days, ns.rotated_from, ns.pub)
    else:
        return verify_fingerprints(ns.meta, ns.key_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())

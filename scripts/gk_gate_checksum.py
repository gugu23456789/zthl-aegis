#!/usr/bin/env python3
"""Gate: state 校验和（verify + refresh）。

2026-11-04 下沉：`refresh` 原为 `gatekeeper-cli.sh::_state_checksum_write` 的内联
python 块（741 B），移出后可单测、可静态检查，shell 侧只留一行调用。

Usage:
  python3 gk_gate_checksum.py <state_file>                      # 校验（原契约）
  python3 gk_gate_checksum.py refresh --state <f> [--invoke-epoch <s>]
Exit: verify 0 匹配 / 1 篡改或不可读；refresh 恒 0（拒写只报 JSON + stderr）
"""
import argparse
import hashlib
import json
import os
import sys


def verify_checksum(state_file: str) -> dict:
    """Verify SHA256(gate_data) matches stored _checksum."""
    try:
        with open(state_file) as f:
            d = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"error": "STATE_FILE_UNREADABLE", "file": state_file}

    saved = d.get("_checksum", "")
    gd = json.dumps(d.get("gate_data", {}), sort_keys=True)
    computed = hashlib.sha256(gd.encode()).hexdigest()[:16]

    if saved and saved != computed:
        # D1: BLOCK — do NOT write state on tamper detection
        return {
            "error": "STATE_FILE_TAMPERED",
            "saved": saved,
            "computed": computed,
        }

    return {"ok": True, "checksum": computed}


def refresh_checksum(state_file: str, invoke_epoch: int = 0) -> dict:
    """重算并写回 `_checksum`（等价迁移 `_state_checksum_write` 内联块）。

    判据（逐字保留原语义）：checksum 已相符 ⟹ 零写盘；本次调用**未改动**该 state
    （mtime < 调用起点 − 1s）却失配 ⟹ 视为“洗白”未授权写入，**拒写 + stderr 留痕**；
    其余（含三处合法“直写后补算”）照旧重算。写路径走 `dump_state` + `state_lock`。
    """
    from gk_json_utils import dump_state, state_lock
    try:
        mtime = os.path.getmtime(state_file)
    except OSError:
        return {"ok": False, "action": "unreadable", "error": "STATE_FILE_UNREADABLE"}
    with state_lock(state_file):
        try:
            with open(state_file, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, json.JSONDecodeError):
            return {"ok": False, "action": "unreadable", "error": "STATE_FILE_UNREADABLE"}
        gd = json.dumps(d.get("gate_data", {}), sort_keys=True)
        new = hashlib.sha256(gd.encode()).hexdigest()[:16]
        old = str(d.get("_checksum", "") or "")
        if new == old:
            return {"ok": True, "action": "noop", "checksum": new}
        if invoke_epoch and mtime < invoke_epoch - 1:
            sys.stderr.write(
                "[checksum] REFUSE 洗白未改动的 state（mtime<invoke）: new=%s old=%s\n" % (new, old))
            return {"ok": False, "action": "refused",
                    "error": "CHECKSUM_REFUSE_WASH", "new": new, "old": old}
        d["_checksum"] = new
        dump_state(state_file, d)
    return {"ok": True, "action": "updated", "checksum": new, "previous": old}


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["refresh"]:
        ap = argparse.ArgumentParser(prog="gk_gate_checksum.py refresh")
        ap.add_argument("--state", required=True)
        ap.add_argument("--invoke-epoch", type=int, default=0)
        ns = ap.parse_args(args[1:])
        print(json.dumps(refresh_checksum(ns.state, ns.invoke_epoch), ensure_ascii=False))
        return 0  # 原调用点带 `|| true`：拒写不阻断 CLI
    if not args:
        print(json.dumps({"error": "usage: gk_gate_checksum.py <state_file>"}))
        return 1
    result = verify_checksum(args[0])
    print(json.dumps(result))
    return 1 if "error" in result else 0


if __name__ == "__main__":
    sys.exit(main())

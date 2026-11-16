#!/usr/bin/env python3
"""D6a 离线回放报告（审计署 D6 子项，2026-11-16）。

边界（审计署 §27.2）：
  · **只证「可回放」**——不解锁 §17.3 ①、不关闭 D6；
  · **禁第二实现**：判定只复用 `gk_credit_ledger.reconcile(require_seal=True)`；
  · 除 `--out` 指定 artifact 外**零写**（不写 state / 账本 / 封印 / 索引）。

链口径（必须写死）：既有账本 `chain=legacy`（无 `seq`/`prev`）⟹ 默认**不启用**
`require_chain`，artifact 显式标 `chain="legacy"`，不得据此宣称受 D3a 链保护。

用法:
  python3 scripts/gk_audit_replay.py --state <state> --out <artifact.json> [--key-dir D]
"""
import argparse
import datetime
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_credit_ledger as CL  # noqa: E402 — 读侧单源（禁第二套对账）

SCHEMA = "d6a-replay-1"


def _sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def _ledger(state_file: str) -> Path:
    return Path(str(state_file) + CL.SUFFIX)


def replay(state_file: str, key_dir: str = "", require_seal: bool = True) -> dict:
    """只读回放：单快照对账 + 账本摘要。缺账本 / 是目录 ⟹ 具名失败（不静默）。"""
    led = _ledger(state_file)
    if not led.exists():
        return {"ok": False, "error": "ledger_missing", "ledger": str(led)}
    if led.is_dir():
        return {"ok": False, "error": "ledger_is_dir", "ledger": str(led)}
    before = (led.stat().st_size, led.stat().st_mtime_ns)
    rep = CL.reconcile(state_file, key_dir=key_dir, require_seal=require_seal)
    # 单快照：读中被追加 ⟹ 重读一次（口径同 gk_audit_host.poll_once）
    if (led.stat().st_size, led.stat().st_mtime_ns) != before:
        rep = CL.reconcile(state_file, key_dir=key_dir, require_seal=require_seal)
    return {
        "ok": True,
        "schema": SCHEMA,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "state": str(state_file),
        "ledger_path": str(led),
        "ledger_sha256": _sha256(led),
        "chain": "legacy",
        "require_seal": bool(require_seal),
        "verdict": "ok" if rep.get("ok") else "debt_or_integrity",
        "raises": rep.get("raises"),
        "audited": rep.get("audited"),
        "unreconciled": rep.get("unreconciled") or [],
        "duplicate_refs": rep.get("duplicate_refs") or [],
        "legacy_raises": rep.get("legacy_raises") or [],
        "debt_raises": rep.get("debt_raises") or [],
        "seal": rep.get("seal") or {},
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_audit_replay.py")
    ap.add_argument("--state", required=True)
    ap.add_argument("--out", required=True, help="artifact 落盘路径（唯一写点）")
    ap.add_argument("--key-dir", default="", help="封印验签钥目录（缺省 ⟹ sha256 弱模式）")
    ap.add_argument("--no-require-seal", action="store_true",
                    help="显式放宽：封印缺失不算失败（默认 require_seal=True）")
    ns = ap.parse_args(argv)
    out = replay(ns.state, key_dir=ns.key_dir, require_seal=not ns.no_require_seal)
    if out.get("ok"):
        p = Path(ns.out)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_name(p.name + ".tmp.%d" % os.getpid())
            tmp.write_text(json.dumps(out, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
            os.replace(str(tmp), str(p))
        except OSError as e:
            out = {"ok": False, "error": "artifact_write_failed", "detail": str(e)[:200]}
    print(json.dumps(out, ensure_ascii=False))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())

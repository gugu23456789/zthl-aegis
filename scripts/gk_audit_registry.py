#!/usr/bin/env python3
"""审计署登记 sidecar（B3b 消费者双读，2026-10-28）
================================================================
目的：把「审计证据是否由本署签发」从**单读本 state**升级为**双读**——
本 state 证据 + `<state>.audit-registry.jsonl`（append-only + 封印）摘要一致。

纪律
  · **S1 零搬迁**：证据仍留在被审 state；登记只存 `domain -> sha256(证据)`，不复制正文。
  · **auto 口径**（owner 2026-10-28 裁）：登记文件**存在**则强制一致（摘要不符 / 封印坏 ⟹ 拒）；
    缺失只标 `absent`，不拦（与服务侧封印 D5 的 auto 同口径）。
  · 单源：封印实现复用 `gk_budget_ledger._seal_with_chain` / `verify_seal_at`，禁第二实现。
  · 与 credit-ledger 分离：本文件是**签发登记**，不是额度账本（J1 两本账不混）。
"""
import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from gk_budget_ledger import _seal_with_chain, verify_seal_at  # noqa: E402
from gk_json_utils import read_state_file  # noqa: E402

SCHEMA = "gk-audit-registry/v1"
SUFFIX = ".audit-registry.jsonl"
SEAL_SUFFIX = ".audit-registry.jsonl.seal"
# 与 gk_node_guard._AUDIT_PRODUCED_EVIDENCE_KEYS 同源（漂移由 test_gk_audit_registry 钉死）
DEFAULT_DOMAINS = ("audit_state_result", "audit_docs_result")


def _logical_path(state_file: str) -> Path:
    return Path(str(state_file) + SUFFIX)


def _seal_path(state_file: str) -> Path:
    return Path(str(state_file) + SEAL_SUFFIX)


def _digest(obj) -> str:
    raw = json.dumps(obj, sort_keys=True, ensure_ascii=False,
                     separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _read_state(state_file: str) -> dict:
    # 2026-11-03（M1）：走 WAL-aware 读（checkpoint + `<state>.wal` replay）。
    d = read_state_file(state_file)
    return d if "error" not in d and isinstance(d, dict) else {}


def read_entries(state_file: str) -> tuple:
    """→ (entries, bad)：坏行计入 bad 但不抛（append-only 容错，坏行不参与对账）。"""
    p = _logical_path(state_file)
    if not p.exists():
        return [], 0
    entries, bad = [], 0
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if isinstance(obj, dict) and isinstance(obj.get("domains"), dict):
            entries.append(obj)
        else:
            bad += 1
    return entries, bad


def _latest_by_domain(entries) -> dict:
    latest = {}
    for e in entries:
        for k, v in (e.get("domains") or {}).items():
            latest[str(k)] = str(v)
    return latest


def verify(state_file: str, key_dir: str = "") -> dict:
    return verify_seal_at(_logical_path(state_file), _seal_path(state_file), key_dir)


def register(state_file: str, key_dir: str = "", source: str = "cmd_audit",
             domains=DEFAULT_DOMAINS, batch_id: str = "") -> dict:
    """登记当前证据摘要（幂等：与最新登记一致则 skip，不追加重复行）。"""
    if not state_file:
        return {"ok": False, "error": "no_state_file"}
    gd = _read_state(state_file).get("gate_data") or {}
    if not isinstance(gd, dict):
        return {"ok": False, "error": "gate_data_not_object"}
    digests = {k: _digest(gd[k]) for k in domains if gd.get(k)}
    if not digests:
        return {"ok": True, "skipped": "no_evidence"}
    entries, _ = read_entries(state_file)
    latest = _latest_by_domain(entries)
    if latest and all(latest.get(k) == v for k, v in digests.items()):
        return {"ok": True, "skipped": "unchanged"}
    rec = {"schema": SCHEMA,
           "ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "state_id": Path(state_file).name, "source": str(source or ""),
           "batch_id": str(batch_id or ""), "domains": digests}
    p = _logical_path(state_file)
    try:
        with open(p, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
    except OSError as e:
        return {"ok": False, "error": "append_failed: %s" % e}
    seal, err = _seal_with_chain(_seal_path(state_file), p.read_bytes(), key_dir)
    if err:
        return {"ok": False, "error": err, "entry": rec}
    return {"ok": True, "entry": rec, "seal": {"mode": seal.get("mode"),
                                               "sha256": seal.get("sha256")}}


def dual_read(state_file: str, gd: dict, key_dir: str = "",
              domains=DEFAULT_DOMAINS) -> dict:
    """双读判定：`{"required","ok","absent","reason","mismatch"}`。

    auto：登记缺失 ⟹ required=False / ok=True（不拦）；登记存在 ⟹ 摘要 + 封印双校验。
    """
    out = {"required": False, "ok": True, "absent": True,
           "reason": "registry_absent", "mismatch": []}
    p = _logical_path(state_file) if state_file else None
    if p is None or not p.exists():
        return out
    out["absent"] = False
    seal = verify(state_file, key_dir=key_dir)
    if not seal.get("ok"):
        out.update({"required": True, "ok": False,
                    "reason": "seal_bad: %s" % seal.get("reason", "")})
        return out
    entries, _ = read_entries(state_file)
    latest = _latest_by_domain(entries)
    gd = gd if isinstance(gd, dict) else {}
    cur = {k: _digest(gd[k]) for k in domains if gd.get(k)}
    mism = []
    for k in domains:
        if k in cur and k not in latest:
            mism.append("unregistered:%s" % k)
        elif k in cur and latest[k] != cur[k]:
            mism.append("digest_mismatch:%s" % k)
        elif k not in cur and k in latest:
            mism.append("evidence_missing:%s" % k)
    out.update({"required": True, "ok": not mism,
                "reason": "ok" if not mism else "mismatch", "mismatch": mism})
    # 2026-11-01：报告签名**唯一消费点**（此前签名无门禁读 ⟹ 死代码）。
    # 迁移期语义：无侧车/unsigned ⟹ 不拦（仅透出状态）；**invalid（篡改/摘要不符）⟹ 拦**。
    try:
        import gk_audit_report as _AR
        sig = _AR.verify_sidecar(state_file, key_dir=key_dir)
        out["report_signature"] = sig.get("status", "unknown")
        if sig.get("status") == "invalid":
            out.update({"ok": False, "reason": "report_sig_invalid:%s" % sig.get("reason", "")})
    except Exception:  # noqa: BLE001 — 边界：验签不可用不改变既有判定
        out["report_signature"] = "unavailable"
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_audit_registry.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("register")
    r.add_argument("--state", required=True)
    r.add_argument("--key-dir", default="")
    r.add_argument("--source", default="cmd_audit")
    r.add_argument("--batch-id", default="")
    v = sub.add_parser("verify")
    v.add_argument("--state", required=True)
    v.add_argument("--key-dir", default="")
    d = sub.add_parser("dual-read")
    d.add_argument("--state", required=True)
    d.add_argument("--key-dir", default="")
    ns = ap.parse_args(argv)
    if ns.cmd == "register":
        out = register(ns.state, key_dir=ns.key_dir, source=ns.source,
                       batch_id=ns.batch_id)
    elif ns.cmd == "verify":
        out = verify(ns.state, key_dir=ns.key_dir)
    else:
        gd = _read_state(ns.state).get("gate_data") or {}
        out = dual_read(ns.state, gd, key_dir=ns.key_dir)
    print(json.dumps(out, ensure_ascii=False))
    return 0 if out.get("ok", True) else 1


if __name__ == "__main__":
    sys.exit(main())

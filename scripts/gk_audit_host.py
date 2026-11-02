#!/usr/bin/env python3
"""host α1 Phase A 骨架：只读账本 watch/poll + 诚实分权报告。

判据正本：`docs/plans/2026-10-19-host-alpha1-skeleton-plan.md` §3（H1–H8）。

边界（Phase A）：
  · 零写点：不写账本 / 封印 / state / 卫星片 / 日志 / pid；
  · 零 `outcome` 生产：不调用 `gk_credit_ledger.append` / `seal_now`，不发起网络，
    不 spawn 子进程；
  · `satellite_index` 不写（Phase B 才谈写权）。
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import gk_credit_ledger as CL  # noqa: E402 — 读侧单源（禁第二套对账）

EXIT_OK = 0
EXIT_UNKNOWN = 3


def _proc_status(pid, proc_root=None):
    """读 `/proc/<pid>/status` 的 `Uid` / `PPid`（只读；不可读 ⟹ None）。"""
    root = Path(proc_root) if proc_root else Path("/proc")
    try:
        txt = (root / str(pid) / "status").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    uid = None
    ppid = None
    for line in txt.splitlines():
        if line.startswith("Uid:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    uid = int(parts[1])
                except ValueError:
                    pass
        elif line.startswith("PPid:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    ppid = int(parts[1])
                except ValueError:
                    pass
    return {"uid": uid, "ppid": ppid}


def classify_separation(host_uid, host_ppid, editor_uid, editor_pid):
    """真值表：`absent` / `separated` / `unknown`（矛盾 ⟹ unknown）。"""
    if host_uid is None or editor_uid is None:
        return "unknown", "uid_unavailable"
    is_parent = editor_pid is not None and editor_pid == host_ppid
    if host_uid != editor_uid:
        if is_parent:
            return "unknown", "separated_but_editor_is_parent"
        return "separated", ""
    return "absent", "same_uid"


def host_identity(proc_root=None, editor_pid=None, platform=None):
    """→ (host, separation, reason, editor_is_parent)。

    POSIX 读 `/proc` 实测；Windows（`platform="nt"`）固定 `unknown`。
    `editor_pid` 仅测试注入；生产默认 = `os.getppid()`。
    """
    plat = platform or os.name
    pid = os.getpid()
    ppid = os.getppid()
    if plat == "nt":
        return ({"pid": pid, "uid": None, "ppid": ppid},
                "unknown", "platform_not_posix", "unknown")
    uid = os.getuid() if hasattr(os, "getuid") else None
    own = _proc_status(pid, proc_root)
    if own and own.get("uid") is not None:
        uid = own["uid"]
    ed_pid = editor_pid if editor_pid is not None else ppid
    est = _proc_status(ed_pid, proc_root)
    editor_uid = est.get("uid") if est else None
    is_parent = ed_pid == ppid
    sep, reason = classify_separation(uid, ppid, editor_uid, ed_pid)
    return ({"pid": pid, "uid": uid, "ppid": ppid}, sep, reason, is_parent)


def precheck_ledger(state_file, access_fn=None):
    """host 侧前置判定（禁依赖 reconcile 的 fail-open 空集）。"""
    led = Path(str(state_file) + CL.SUFFIX)
    if not led.exists():
        return "ledger_missing"
    if led.is_dir():
        return "ledger_is_dir"
    access = access_fn or os.access
    if not access(led, os.R_OK):
        return "ledger_unreadable"
    return ""


def _spec(state_file):
    return Path(str(state_file) + CL.SUFFIX)


def poll_once(state_file, proc_root=None, editor_pid=None, platform=None,
              access_fn=None, key_dir=""):
    """单轮只读快照。`ok` = **债口径**（无未审债 + 无重票）；`poll_ok` = 驱动是否成功。

    `integrity_ok` / `verdict`（复审 BLOCK 后新增）：把**封印、坏行、无 id raise、基线有效性**
    纳入判定，避免「债平 = 一切正常」。`verdict ∈ {ok, debt, integrity}`。
    ⚠ B1（2026-10-27）：`ok` 不再并自 `reconcile.ok` —— D5 读侧封印令后者在**坏封印/坏基线**时
    也为 False，会把「篡改」报成「欠债」（审计面误判）。封印/坏行/坏基线现只落 `integrity_ok`。
    """
    err = precheck_ledger(state_file, access_fn)
    if err:
        return {"poll_ok": False, "ok": False, "error": err,
                "state": str(state_file)}

    led = _spec(state_file)
    before = (led.stat().st_size, led.stat().st_mtime_ns)
    rep = CL.reconcile(str(state_file), key_dir=key_dir)
    records, stat = CL.read_records(str(state_file))
    after = (led.stat().st_size, led.stat().st_mtime_ns)
    if before != after:                      # 单快照：变了重读一次
        rep = CL.reconcile(str(state_file), key_dir=key_dir)
        records, stat = CL.read_records(str(state_file))

    if stat.get("count", 0) == 0 and stat.get("bad", 0) > 0:
        return {"poll_ok": False, "ok": False, "error": "all_lines_bad",
                "state": str(state_file), "bad": stat.get("bad", 0)}

    host, sep, sep_reason, is_parent = host_identity(
        proc_root=proc_root, editor_pid=editor_pid, platform=platform)
    seal = CL.verify_seal(str(state_file))
    raises_without_id = sum(
        1 for r in records if r.get("kind") == "raise" and not r.get("id"))
    base = rep.get("baseline") or {}
    base_ok = (not base.get("present")) or bool(base.get("ok"))
    integrity_ok = (bool(stat.get("seal_ok")) and stat.get("bad", 0) == 0
                    and raises_without_id == 0 and base_ok)
    # 债口径：只认未审债 / 重票（`reconcile.ok` 还并了封印与基线 ⟹ 不直接用）
    debt_ok = not (rep.get("unreconciled") or rep.get("duplicate_refs"))
    verdict = ("debt" if not debt_ok
               else ("ok" if integrity_ok else "integrity"))

    return {
        "poll_ok": True,
        "ok": debt_ok,
        "verdict": verdict,
        "integrity_ok": integrity_ok,
        "state": str(state_file),
        "ledger": str(led),
        "raises": rep.get("raises"),
        "audited": rep.get("audited"),
        "pending": len(rep.get("unreconciled") or []),
        "unreconciled": rep.get("unreconciled"),
        "debt_raises": rep.get("debt_raises"),
        "legacy_raises": rep.get("legacy_raises"),
        "bookkeeping": stat.get("bookkeeping", 0),
        "baseline": base,
        "bad": stat.get("bad", 0),
        "lines": stat.get("lines", 0),
        "seal_ok": stat.get("seal_ok"),
        "seal_mode": stat.get("seal_mode", ""),
        "seal_reason": seal.get("reason", ""),
        "raises_without_id": raises_without_id,
        "host": host,
        "separation": sep,
        "separation_reason": sep_reason,
        "editor_is_parent": is_parent,
    }


def _file_sig(path):
    """→ `(exists, size, mtime_ns)`（不可读视作缺失）。"""
    try:
        st = path.stat()
        return (True, st.st_size, st.st_mtime_ns)
    except OSError:
        return (False, 0, 0)


def watch_loop(ns):
    """内联 offset tailing：账本或**基线**签名变化即重读并输出。"""
    state = ns.state
    led = _spec(state)
    base = Path(str(state) + CL.BASELINE_SUFFIX)
    proc_root = ns.proc_root or None
    last_sig = None
    while True:
        led_sig = _file_sig(led)
        if not led_sig[0]:
            print(json.dumps({"poll_ok": False, "ok": False,
                              "error": "ledger_missing", "state": state},
                             ensure_ascii=False), flush=True)
            return EXIT_UNKNOWN
        sig = (led_sig, _file_sig(base))
        if sig != last_sig:
            out = poll_once(state, proc_root=proc_root, editor_pid=ns.editor_pid,
                            key_dir=ns.key_dir)
            if out.get("bad", 0) and out.get("pending", 0) == 0:
                time.sleep(0.02)              # 半行重读一次
                out = poll_once(state, proc_root=proc_root,
                                editor_pid=ns.editor_pid, key_dir=ns.key_dir)
            if out.get("error"):
                print(json.dumps(out, ensure_ascii=False), flush=True)
                return EXIT_UNKNOWN
            print(json.dumps(out, ensure_ascii=False), flush=True)
            last_sig = sig
        time.sleep(max(0.0, float(ns.interval)))


def main(argv=None):
    ap = argparse.ArgumentParser(description="host α1 read-only skeleton (Phase A)")
    ap.add_argument("--state", required=True)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--watch", action="store_true")
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--key-dir", default="")
    ap.add_argument("--proc-root", default="", help="test injection only")
    ap.add_argument("--editor-pid", type=int, default=None,
                    help="test injection only")
    ns = ap.parse_args(argv)
    if ns.watch:
        return watch_loop(ns)
    out = poll_once(ns.state, proc_root=ns.proc_root or None,
                    editor_pid=ns.editor_pid, key_dir=ns.key_dir)
    print(json.dumps(out, ensure_ascii=False), flush=True)
    return EXIT_UNKNOWN if out.get("error") else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

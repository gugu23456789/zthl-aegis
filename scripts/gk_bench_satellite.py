#!/usr/bin/env python3
"""gk_bench_satellite.py — 卫星片/索引 benchmark（P0）。

测什么
======
- `gk_satellite.append`：片写 + 冷索引侧车 + 内联热索引 + 判活锚
- 写放大、p50/p95/p99、吞吐、state/侧车/片体积、并集叶子数
- `gc_index`：删除/溢出成本与前后体积
- `reclaim(dry_run=True)`：过期扫描成本与 `held/live/would` 判定（只读）

用法
====
  python scripts/gk_bench_satellite.py --quick
  python scripts/gk_bench_satellite.py --full --out-dir dist/bench
  python scripts/gk_bench_satellite.py --smoke --json
"""
import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import gk_bench_common as C  # noqa: E402
import gk_json_utils as JU  # noqa: E402
import gk_satellite as SAT  # noqa: E402
import gk_state_patch as SP  # noqa: E402


def _record(i, payload):
    return {"i": int(i), "payload": "x" * int(payload)}


def _record_bytes(records):
    return sum(len(json.dumps(r, ensure_ascii=False).encode("utf-8")) + 1
               for r in records)


def _leaves(state):
    si = SAT.index_entries(state)
    return sum(len(arms) for arms in si.values() if isinstance(arms, dict))


def run_append(kind, n_records, batch_size, payload, state_bytes, old_ts=False):
    tmp = tempfile.mkdtemp(prefix="gk_bench_sat_")
    state = os.path.join(tmp, "state.json")
    actual = C.init_state(state, state_bytes, label="%s-b%d" % (kind, batch_size))
    ts = ""
    if old_ts:
        ts = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    lat, errors = [], []
    logical = 0
    calls = 0
    io0 = C.io_write_bytes()
    t0 = C.now()
    for start in range(0, n_records, batch_size):
        chunk = [_record(i, payload) for i in range(start, min(start + batch_size, n_records))]
        bid = "bench-%05d" % calls
        arm = "a%d" % (calls % 6)
        t = C.now()
        try:
            r = SAT.append(state, kind, chunk, batch_id=bid, arm=arm,
                           ttl_s=(1 if old_ts else 0), ts=ts)
        except Exception as e:  # noqa: BLE001 — benchmark 记录失败
            errors.append("%s: %s" % (type(e).__name__, e))
            break
        dt = C.now() - t
        if not r.get("ok"):
            errors.append(str(r.get("error", "append_failed")))
            break
        lat.append(dt)
        logical += _record_bytes(chunk)
        calls += 1
    wall = C.now() - t0
    io1 = C.io_write_bytes()
    st = C.state_status(state)
    shard_bytes = sum(s["bytes"] for s in SAT.shards(state))
    sidecar_bytes = C.safe_size(SAT.sidecar_path(state))
    io_ok = io0 is not None and io1 is not None
    io_total = max(0, io1 - io0) if io_ok else None
    if io_ok and logical:
        amp, amp_src = io_total / logical, "io_write_bytes"
    elif logical:
        amp, amp_src = (st.get("bytes", 0) + sidecar_bytes + shard_bytes) / logical, "file_sizes_approx"
    else:
        amp, amp_src = None, "none"
    ok = (not errors and st.get("ok") and st.get("seq") == 0
          and lat and _leaves(state) == calls)
    return {
        "scenario": "%s-n%d-b%d-p%d" % (kind, n_records, batch_size, payload),
        "kind": kind,
        "records": n_records,
        "batch_size": batch_size,
        "calls": calls,
        "success_calls": len(lat),
        "wall_s": round(wall, 4),
        "calls_s": round(len(lat) / wall, 2) if wall > 0 else None,
        "latency": C.percentiles(lat),
        "write_amp": (round(amp, 2) if amp is not None else None),
        "write_amp_src": amp_src,
        "io_write_bytes": io_total,
        "logical_payload_bytes": logical,
        "state_bytes": st.get("bytes"),
        "sidecar_bytes": sidecar_bytes,
        "shard_bytes": shard_bytes,
        "leaves": _leaves(state),
        "checksum_ok": st.get("checksum_ok"),
        "errors": errors[:8],
        "ok": bool(ok),
        "state_dir": tmp,
    }


def run_gc(state):
    # 造一个「片不存在」的悬空叶，确保 GC 真的走删除路径，而不是只扫一遍 no-op。
    # history 片在 append 场景中不存在 ⟹ kind=history 会被判 dangling。
    leaf = {"kind": "history", "file": "missing-history.jsonl", "arm": "dangling",
            "records": 0, "bytes": 0, "first_ts": "", "last_ts": "", "ttl_s": 0}
    SP.cmd_set_nested(state, "gate_data.satellite_index.bench-dangling.dangling",
                      json.dumps(leaf, ensure_ascii=False))
    before = C.safe_size(state)
    t0 = C.now()
    r = SAT.gc_index(state, dry_run=False)
    wall = C.now() - t0
    after = C.safe_size(state)
    return {
        "ok": bool(r.get("ok")),
        "wall_s": round(wall, 4),
        "before_bytes": before,
        "after_bytes": after,
        "removed_count": r.get("removed_count"),
        "applied": r.get("applied"),
        "spilled": r.get("spilled"),
        "leaves_after": r.get("leaves_after"),
        "error": r.get("error", ""),
    }


def run_reclaim(kind, n_records, payload, state_bytes=128 * 1024):
    row = run_append(kind, n_records, 1, payload, state_bytes, old_ts=True)
    state = os.path.join(row["state_dir"], "state.json")
    t0 = C.now()
    r = SAT.reclaim(state, dry_run=True)
    wall = C.now() - t0
    return {
        "ok": bool(r.get("ok")),
        "wall_s": round(wall, 4),
        "dry_run": bool(r.get("dry_run")),
        "would_reclaim": len(r.get("would_reclaim") or []),
        "held": len(r.get("held") or []),
        "live": len(r.get("live") or []),
        "shard_reclaimable": len(r.get("shard_reclaimable") or []),
        "state_bytes": C.safe_size(state),
        "append_ok": row["ok"],
    }


def _markdown(result):
    rows = []
    for s in result["scenarios"]:
        lat = s["latency"]
        rows.append([
            s["scenario"], s["kind"], s["records"], s["batch_size"], s["success_calls"],
            s["wall_s"], s["calls_s"], lat.get("p50_ms"), lat.get("p95_ms"),
            lat.get("p99_ms"), s["write_amp"], s["write_amp_src"],
            round(s["state_bytes"] / 1024, 1), round(s["sidecar_bytes"] / 1024, 1),
            round(s["shard_bytes"] / 1024, 1), s["leaves"], s["ok"],
        ])
    md = ["# gk_bench_satellite — %s" % result["mode"], "",
          "真实片/侧车/state 写；写放大按进程级写字节或文件体积近似。", "",
          C.md_table(["scenario", "kind", "records", "batch", "calls", "wall_s",
                      "calls_s", "p50_ms", "p95_ms", "p99_ms", "write_amp",
                      "amp_src", "state_kb", "sidecar_kb", "shard_kb", "leaves", "ok"],
                     rows)]
    grows = [[g["scenario"], g["wall_s"], g["before_bytes"], g["after_bytes"],
              g["removed_count"], g["spilled"], g["ok"]] for g in result["gc"]]
    md += ["", "## GC", "",
           C.md_table(["scenario", "wall_s", "before_bytes", "after_bytes",
                       "removed_count", "spilled", "ok"], grows)]
    rrows = [[r["kind"], r["wall_s"], r["would_reclaim"], r["held"], r["live"],
              r["shard_reclaimable"], r["state_bytes"], r["ok"]] for r in result["reclaim"]]
    md += ["", "## Reclaim (dry-run)", "",
           C.md_table(["kind", "wall_s", "would", "held", "live",
                       "shard_reclaimable", "state_bytes", "ok"], rrows)]
    return "\n".join(md)


def main(argv=None):
    p = argparse.ArgumentParser(prog="gk_bench_satellite.py")
    p.add_argument("--quick", action="store_true")
    p.add_argument("--full", action="store_true")
    p.add_argument("--smoke", action="store_true")
    p.add_argument("--out-dir", default="")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    if a.smoke:
        mode = "smoke"
        cases, payloads, state_bytes = [(20, 1, "finding")], [32], 32 * 1024
        reclaim_n = 10
    elif a.full:
        mode = "full"
        # 3000 条 × batch=1 会让 full 跑到十几分钟；大规模用 batch=100 测吞吐，
        # batch=1 只保留 1000 条测逐条索引成本。
        cases = [(n, b, k) for k in ("finding", "history")
                 for n, b in ((1000, 1), (1000, 100), (3000, 100))]
        payloads, state_bytes, reclaim_n = [1024], 128 * 1024, 50
    else:
        mode = "quick"
        cases = [(n, b, "finding") for n in (100, 300) for b in (1, 10)]
        payloads, state_bytes, reclaim_n = [256], 128 * 1024, 30
    scenarios = []
    for payload in payloads:
        for n, b, kind in cases:
            print("[bench-sat] %s n=%d b=%d p=%d" % (kind, n, b, payload),
                  file=sys.stderr)
            scenarios.append(run_append(kind, n, b, payload, state_bytes))
    gc = []
    for s in scenarios[:2]:
        state = os.path.join(s["state_dir"], "state.json")
        g = run_gc(state)
        g["scenario"] = s["scenario"]
        gc.append(g)
    reclaim = []
    for kind in sorted({k for _, _, k in cases}):
        print("[bench-sat] reclaim %s" % kind, file=sys.stderr)
        reclaim.append(run_reclaim(kind, reclaim_n, payloads[0], state_bytes))
        reclaim[-1]["kind"] = kind
    result = {
        "ok": all(s["ok"] for s in scenarios) and all(g["ok"] for g in gc)
              and all(r["ok"] and r["append_ok"] for r in reclaim),
        "mode": mode,
        "config": {"cases": cases, "payloads": payloads,
                   "state_bytes": state_bytes, "reclaim_records": reclaim_n},
        "scenarios": scenarios,
        "gc": gc,
        "reclaim": reclaim,
    }
    result["markdown"] = _markdown(result)
    if a.out_dir:
        jp, mp = C.write_report(result, a.out_dir, "gk_bench_satellite-" + mode)
        print("[bench-sat] report=%s %s" % (jp, mp), file=sys.stderr)
    if a.json:
        print(json.dumps({k: v for k, v in result.items() if k != "markdown"},
                         ensure_ascii=False))
    else:
        print(result["markdown"])
        print()
        print(json.dumps({k: v for k, v in result.items() if k != "markdown"},
                         ensure_ascii=False))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())

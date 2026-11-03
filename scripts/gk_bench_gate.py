#!/usr/bin/env python3
"""gk_bench_gate.py — gate 元数据写路径 benchmark（P1，下一版本主线）。

测什么
======
- `gk_state._read_state`：冷读延迟
- `gk_state_patch.cmd_set_nested`：定点叶子写（真实 state_lock + 整文件重写）
- `gk_state_patch.cmd_update_gate_data`：gate_data 顶层批量更新（真实写路径）

这些是 gate 每轮都会走的元数据面；与 P0 的 state/satellite 分开，避免把
“状态写放大”和“卫星索引写放大”混成一个数字。

用法：
  python scripts/gk_bench_gate.py --quick
  python scripts/gk_bench_gate.py --full --out-dir dist/bench
  python scripts/gk_bench_gate.py --smoke --json
"""
import argparse
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import gk_bench_common as C  # noqa: E402
import gk_json_utils as JU  # noqa: E402
import gk_state as GS  # noqa: E402
import gk_state_patch as SP  # noqa: E402


def _io_delta(fn):
    io0 = C.io_write_bytes()
    t0 = C.now()
    r = fn()
    t1 = C.now()
    io1 = C.io_write_bytes()
    io = max(0, io1 - io0) if io0 is not None and io1 is not None else None
    return r, (t1 - t0), io


def run_read(state_bytes, ops):
    tmp = tempfile.mkdtemp(prefix="gk_bench_gate_read_")
    state = os.path.join(tmp, "state.json")
    C.init_state(state, state_bytes, label="read")
    lat, errors = [], []
    for _ in range(ops):
        t0 = C.now()
        d = GS._read_state(state)
        t1 = C.now()
        if d.get("error"):
            errors.append(d["error"])
            break
        lat.append(t1 - t0)
    st = C.state_status(state)
    return {
        "scenario": "read-s%d" % state_bytes,
        "op": "read",
        "ops": ops,
        "success": len(lat),
        "latency": C.percentiles(lat),
        "write_amp": None,
        "state_bytes": st.get("bytes"),
        "checksum_ok": st.get("checksum_ok"),
        "errors": errors[:8],
        "ok": bool(not errors and st.get("ok") and len(lat) == ops),
        "state_dir": tmp,
    }


def run_set_nested(state_bytes, payload_bytes, ops):
    tmp = tempfile.mkdtemp(prefix="gk_bench_gate_set_")
    state = os.path.join(tmp, "state.json")
    C.init_state(state, state_bytes, label="set_nested")
    value = "x" * payload_bytes
    value_json = json.dumps(value, ensure_ascii=False)
    lat, ios, errors = [], [], []
    for i in range(ops):
        r, dt, io = _io_delta(lambda: SP.cmd_set_nested(
            state, "gate_data.bench_gate.leaf", value_json))
        if not r.get("ok"):
            errors.append(str(r.get("error", "set_nested_failed")))
            break
        lat.append(dt)
        ios.append(io)
    st = C.state_status(state)
    logical = max(1, len(value_json.encode("utf-8")) * len(lat))
    io_ok = bool(ios) and all(v is not None for v in ios)
    amp = (sum(ios) / logical if io_ok else
           (st.get("bytes", 0) * len(lat) / logical if lat else None))
    return {
        "scenario": "set-nested-s%d-p%d" % (state_bytes, payload_bytes),
        "op": "set_nested",
        "ops": ops,
        "success": len(lat),
        "latency": C.percentiles(lat),
        "write_amp": round(amp, 2) if amp is not None else None,
        "write_amp_src": "io_write_bytes" if io_ok else "state_bytes_approx",
        "state_bytes": st.get("bytes"),
        "checksum_ok": st.get("checksum_ok"),
        "errors": errors[:8],
        "ok": bool(not errors and st.get("ok") and len(lat) == ops),
        "state_dir": tmp,
    }


def run_update_gate_data(state_bytes, payload_bytes, ops):
    tmp = tempfile.mkdtemp(prefix="gk_bench_gate_upd_")
    state = os.path.join(tmp, "state.json")
    C.init_state(state, state_bytes, label="update_gate_data")
    lat, ios, errors = [], [], []
    for i in range(ops):
        frag = json.dumps({"bench_meta": {"seq": i, "payload": "x" * payload_bytes}},
                          ensure_ascii=False)
        r, dt, io = _io_delta(lambda: SP.cmd_update_gate_data(state, frag))
        if not r.get("ok"):
            errors.append(str(r.get("error", "update_gate_data_failed")))
            break
        lat.append(dt)
        ios.append(io)
    st = C.state_status(state)
    logical = max(1, len(frag.encode("utf-8")) * len(lat))
    io_ok = bool(ios) and all(v is not None for v in ios)
    amp = (sum(ios) / logical if io_ok else
           (st.get("bytes", 0) * len(lat) / logical if lat else None))
    return {
        "scenario": "update-gate-data-s%d-p%d" % (state_bytes, payload_bytes),
        "op": "update_gate_data",
        "ops": ops,
        "success": len(lat),
        "latency": C.percentiles(lat),
        "write_amp": round(amp, 2) if amp is not None else None,
        "write_amp_src": "io_write_bytes" if io_ok else "state_bytes_approx",
        "state_bytes": st.get("bytes"),
        "checksum_ok": st.get("checksum_ok"),
        "errors": errors[:8],
        "ok": bool(not errors and st.get("ok") and len(lat) == ops),
        "state_dir": tmp,
    }


def _markdown(result):
    rows = []
    for s in result["scenarios"]:
        lat = s["latency"]
        rows.append([s["scenario"], s["op"], s["ops"], s["success"],
                     lat.get("p50_ms"), lat.get("p95_ms"), lat.get("p99_ms"),
                     s["write_amp"], s.get("write_amp_src"),
                     round((s["state_bytes"] or 0) / 1024, 1), s["ok"]])
    return "\n".join([
        "# gk_bench_gate — %s" % result["mode"], "",
        "真实 `state_lock` + gate 元数据写路径；写放大 = 进程写字节 / 逻辑 JSON。", "",
        C.md_table(["scenario", "op", "ops", "success", "p50_ms", "p95_ms",
                    "p99_ms", "write_amp", "amp_src", "state_kb", "ok"], rows),
    ])


def main(argv=None):
    p = argparse.ArgumentParser(prog="gk_bench_gate.py")
    p.add_argument("--quick", action="store_true")
    p.add_argument("--full", action="store_true")
    p.add_argument("--smoke", action="store_true")
    p.add_argument("--out-dir", default="")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    if a.smoke:
        mode = "smoke"
        state_sizes, payloads, ops = [32 * 1024], [8], 2
    elif a.full:
        mode = "full"
        state_sizes, payloads, ops = [128 * 1024, 512 * 1024], [64, 1024], 30
    else:
        mode = "quick"
        state_sizes, payloads, ops = [128 * 1024], [64], 20
    scenarios = []
    for sb in state_sizes:
        print("[bench-gate] read s=%d" % sb, file=sys.stderr)
        scenarios.append(run_read(sb, ops))
        for pb in payloads:
            print("[bench-gate] set-nested s=%d p=%d" % (sb, pb), file=sys.stderr)
            scenarios.append(run_set_nested(sb, pb, ops))
            print("[bench-gate] update-gate-data s=%d p=%d" % (sb, pb), file=sys.stderr)
            scenarios.append(run_update_gate_data(sb, pb, ops))
    result = {
        "ok": all(s["ok"] for s in scenarios),
        "mode": mode,
        "config": {"state_sizes": state_sizes, "payload_sizes": payloads, "ops": ops},
        "scenarios": scenarios,
    }
    result["markdown"] = _markdown(result)
    if a.out_dir:
        jp, mp = C.write_report(result, a.out_dir, "gk_bench_gate-" + mode)
        print("[bench-gate] report=%s %s" % (jp, mp), file=sys.stderr)
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

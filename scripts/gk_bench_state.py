#!/usr/bin/env python3
"""gk_bench_state.py — state 写路径 benchmark（P0）。

测什么
======
- 单写 / 多进程并发写（真实 `state_lock` + `update_state`）
- 写放大：进程级实际写字节 / 逻辑 payload 字节（Windows IO 计数器；不可用则退化）
- p50/p95/p99 延迟、吞吐、最终 state 大小、checksum
- 崩溃注入：写循环中 `kill`，验证 state 仍可解析、checksum 正确、临时文件残留

用法
====
  python scripts/gk_bench_state.py --quick
  python scripts/gk_bench_state.py --full --out-dir dist/bench
  python scripts/gk_bench_state.py --smoke --json
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import gk_bench_common as C  # noqa: E402
import gk_json_utils as JU  # noqa: E402


def _mutator(payload_size, writer_id):
    def mut(d):
        gd = d.setdefault("gate_data", {})
        b = gd.setdefault("bench", {})
        b["seq"] = int(b.get("seq", 0) or 0) + 1
        # 保留 init_state 的 payload 填充，只写一个 payload_size 的增量字段：
        # 这样 state 体积由初始 filler 决定，而不是被 mutator 缩成 payload 大小。
        b["last"] = "x" * int(payload_size)
        b["writer"] = int(writer_id)
    return mut


def worker_main():
    """子进程：真实 update_state 循环；结果写 JSON。"""
    state = os.environ["GK_BENCH_STATE"]
    ops = int(os.environ.get("GK_BENCH_OPS", "1"))
    payload = int(os.environ.get("GK_BENCH_PAYLOAD", "0"))
    writer = int(os.environ.get("GK_BENCH_WRITER", "0"))
    result_path = os.environ["GK_BENCH_RESULT"]
    mode = os.environ.get("GK_BENCH_MODE", "normal")
    lat, ios, sizes, errors = [], [], [], []
    for _ in range(ops):
        io0 = C.io_write_bytes()
        t0 = C.now()
        try:
            r = JU.update_state(state, _mutator(payload, writer))
        except Exception as e:  # noqa: BLE001 — benchmark 记录失败，不伪装成功
            errors.append("%s: %s" % (type(e).__name__, e))
            break
        t1 = C.now()
        io1 = C.io_write_bytes()
        if not r.get("ok"):
            errors.append(str(r.get("error", "update_failed")))
            break
        lat.append(t1 - t0)
        ios.append((max(0, io1 - io0) if io0 is not None and io1 is not None else None))
        sizes.append(C.safe_size(state))
        if mode == "crash":
            time.sleep(0.001)
    payload_out = {
        "ok": not errors,
        "errors": errors,
        "latencies_s": lat,
        "io_write_bytes": ios,
        "state_bytes": sizes,
        "pid": os.getpid(),
    }
    JU.write_json_file(result_path, payload_out)


def _env(state, ops, payload, writer, result, mode="normal"):
    env = os.environ.copy()
    env.update({
        "GK_BENCH_STATE": state,
        "GK_BENCH_OPS": str(ops),
        "GK_BENCH_PAYLOAD": str(payload),
        "GK_BENCH_WRITER": str(writer),
        "GK_BENCH_RESULT": result,
        "GK_BENCH_MODE": mode,
        "PYTHONPATH": HERE,
        "PYTHONIOENCODING": "utf-8",
    })
    return env


def _spawn(state, ops, payload, writer, result, mode="normal"):
    return subprocess.Popen(
        [sys.executable, os.path.abspath(__file__), "--worker"],
        cwd=HERE,
        env=_env(state, ops, payload, writer, result, mode),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )


def _fmt_amp(v):
    return None if v is None else round(float(v), 2)


def run_scenario(state_bytes, payload_bytes, writers, ops):
    tmp = tempfile.mkdtemp(prefix="gk_bench_state_")
    state = os.path.join(tmp, "state.json")
    actual = C.init_state(state, state_bytes, label="w%d-p%d" % (writers, payload_bytes))
    procs, results = [], []
    t0 = C.now()
    for w in range(writers):
        result = os.path.join(tmp, "result-%d.json" % w)
        results.append(result)
        procs.append(_spawn(state, ops, payload_bytes, w, result))
    stderr = []
    for p in procs:
        try:
            _, err = p.communicate(timeout=180)
        except subprocess.TimeoutExpired:
            p.kill()
            _, err = p.communicate()
            stderr.append("worker timeout")
        if err:
            stderr.append(err.strip()[:300])
    wall = C.now() - t0
    lat, ios, sizes, errors = [], [], [], []
    for path in results:
        if not os.path.isfile(path):
            errors.append("missing result: %s" % os.path.basename(path))
            continue
        r = JU.read_json_file(path)
        if "error" in r:
            errors.append(r["error"])
            continue
        lat.extend(r.get("latencies_s") or [])
        ios.extend(r.get("io_write_bytes") or [])
        sizes.extend(r.get("state_bytes") or [])
        errors.extend(r.get("errors") or [])
    if stderr:
        errors.extend(stderr)
    success = len(lat)
    expected = writers * ops
    st = C.state_status(state)
    io_ok = bool(ios) and all(v is not None for v in ios)
    io_total = sum(ios) if io_ok else None
    logical = max(1, success * payload_bytes)
    if io_ok:
        amp = io_total / logical
        amp_src = "io_write_bytes"
    elif sizes:
        amp = sum(sizes) / logical
        amp_src = "state_bytes_approx"
    else:
        amp = None
        amp_src = "none"
    # 2026-11-06（口径修正）：`write_amp` 原定义 = 写字节 / 逻辑 payload，当 payload ≪ state 时
    #   会得到数百倍，语义上其实是 `state_size / payload`。拆成两个可解释的指标：
    #   · amp_per_payload：写字节 / 逻辑 payload（保留旧口径，`write_amp` 作兼容别名）
    #   · amp_per_state  ：写字节 /（逻辑写次数 × state 字节）≈ 每次全量重写的倍数（期望 ~1–2）
    _sb = int(st.get("bytes") or state_bytes or 0)
    if io_ok and success > 0 and _sb > 0:
        amp_per_state = io_total / float(success * _sb)
    else:
        amp_per_state = None
    ok = (not errors and st.get("ok") and success == expected
          and st.get("seq") == expected)
    return {
        "scenario": "w%d-p%d-s%d" % (writers, payload_bytes, state_bytes),
        "writers": writers,
        "ops_per_worker": ops,
        "total_ops": expected,
        "success_ops": success,
        "wall_s": round(wall, 4),
        "ops_s": round(success / wall, 2) if wall > 0 else None,
        "latency": C.percentiles(lat),
        "amp_per_payload": _fmt_amp(amp),
        "amp_per_state": _fmt_amp(amp_per_state),
        "amp_src": amp_src,
        "write_amp": _fmt_amp(amp),          # 兼容别名（旧 baseline 读此键）
        "write_amp_src": amp_src,
        "io_write_bytes": io_total,
        "logical_payload_bytes": logical,
        "state_bytes": st.get("bytes"),
        "initial_state_bytes": actual,
        "final_seq": st.get("seq"),
        "checksum_ok": st.get("checksum_ok"),
        "tmp_left": st.get("tmp_left"),
        "errors": errors[:8],
        "ok": bool(ok),
        "state_dir": tmp,
    }


def run_crash_trial(trial, state_bytes=128 * 1024, payload_bytes=1024):
    tmp = tempfile.mkdtemp(prefix="gk_bench_crash_")
    state = os.path.join(tmp, "state.json")
    C.init_state(state, state_bytes, label="crash-%d" % trial)
    result = os.path.join(tmp, "result.json")
    proc = _spawn(state, 1000000, payload_bytes, 0, result, mode="crash")
    seq = 0
    deadline = time.time() + 8.0
    while time.time() < deadline:
        st = C.state_status(state)
        seq = int(st.get("seq", 0) or 0)
        if seq >= 3 or proc.poll() is not None:
            break
        time.sleep(0.01)
    time.sleep(0.02)
    proc.kill()
    try:
        proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        pass
    st = C.state_status(state)
    return {
        "trial": trial,
        "seq_before_kill": seq,
        "final_seq": st.get("seq"),
        "checksum_ok": st.get("checksum_ok"),
        "state_bytes": st.get("bytes"),
        "tmp_left": st.get("tmp_left"),
        "ok": bool(st.get("ok") and int(st.get("seq", 0) or 0) >= 1),
        "state_dir": tmp,
    }


def _markdown(result):
    rows = []
    for s in result["scenarios"]:
        lat = s["latency"]
        rows.append([
            s["scenario"], s["writers"], s["ops_per_worker"], s["success_ops"],
            s["wall_s"], s["ops_s"], lat.get("p50_ms"), lat.get("p95_ms"),
            lat.get("p99_ms"), s.get("amp_per_payload"), s.get("amp_per_state"), s["amp_src"],
            round((s["state_bytes"] or 0) / 1024, 1), s["final_seq"], s["ok"],
        ])
    md = ["# gk_bench_state — %s" % result["mode"], "",
          "真实 `state_lock` + `update_state`；amp/payload = 写字节 / 逻辑 payload，"
          "amp/state = 写字节 /（写次数 × state 字节，期望 ~1–2）。", "",
          C.md_table(["scenario", "writers", "ops", "success", "wall_s", "ops_s",
                      "p50_ms", "p95_ms", "p99_ms", "amp/payload", "amp/state", "amp_src",
                      "state_kb", "final_seq", "ok"], rows)]
    if result.get("crash"):
        crows = [[c["trial"], c["seq_before_kill"], c["final_seq"], c["checksum_ok"],
                  c["state_bytes"], c["tmp_left"], c["ok"]] for c in result["crash"]]
        md += ["", "## 崩溃注入", "",
               C.md_table(["trial", "seq_before_kill", "final_seq", "checksum_ok",
                           "state_bytes", "tmp_left", "ok"], crows)]
    return "\n".join(md)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--worker" in argv:
        worker_main()
        return 0
    p = argparse.ArgumentParser(prog="gk_bench_state.py")
    p.add_argument("--quick", action="store_true")
    p.add_argument("--full", action="store_true")
    p.add_argument("--smoke", action="store_true")
    p.add_argument("--no-crash", action="store_true")
    p.add_argument("--crashes", type=int, default=None,
                   help="崩溃注入次数（覆盖挡位默认值；full 默认 20，quick 3）")
    p.add_argument("--out-dir", default="")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    if a.smoke:
        mode = "smoke"
        state_sizes, payloads, writers, ops, crash_trials = [32 * 1024], [128], [1], 2, 0
    elif a.full:
        mode = "full"
        state_sizes, payloads, writers, ops, crash_trials = (
            [128 * 1024, 512 * 1024], [1024, 65536], [1, 8, 32], 30, 20)
    else:
        mode = "quick"
        state_sizes, payloads, writers, ops, crash_trials = (
            [128 * 1024], [1024, 16384], [1, 4], 20, 3)
    if a.no_crash:
        crash_trials = 0
    if a.crashes is not None:
        crash_trials = max(0, int(a.crashes))
    scenarios = []
    for sb in state_sizes:
        for pb in payloads:
            for w in writers:
                print("[bench-state] %s w=%d p=%d s=%d" % (mode, w, pb, sb),
                      file=sys.stderr)
                scenarios.append(run_scenario(sb, pb, w, ops))
    crash = []
    for i in range(crash_trials):
        print("[bench-state] crash trial %d" % (i + 1), file=sys.stderr)
        # 2026-11-06（覆盖缺口修正）：崩溃注入不再固定 128 KB，按 state_sizes 轮转，
        #   full 模式因此会覆盖 512 KB 场景。
        crash.append(run_crash_trial(i + 1, state_bytes=state_sizes[i % len(state_sizes)]))
    result = {
        "ok": all(s["ok"] for s in scenarios) and all(c["ok"] for c in crash),
        "mode": mode,
        "config": {"state_sizes": state_sizes, "payload_sizes": payloads,
                   "writers": writers, "ops_per_worker": ops,
                   "crash_trials": crash_trials},
        "scenarios": scenarios,
        "crash": crash,
    }
    result["markdown"] = _markdown(result)
    if a.out_dir:
        jp, mp = C.write_report(result, a.out_dir, "gk_bench_state-" + mode)
        print("[bench-state] report=%s %s" % (jp, mp), file=sys.stderr)
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

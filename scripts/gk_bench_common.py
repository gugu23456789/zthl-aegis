#!/usr/bin/env python3
"""gk_bench_common.py — benchmark 共用面（真实文件、真实 IO 计数、无 mock）。

仅服务 `gk_bench_state.py` / `gk_bench_satellite.py`：
- `io_write_bytes()`：进程级实际写字节（Windows `GetProcessIoCounters`；Linux `/proc/self/io`）
- `percentiles()`：p50/p95/p99（线性插值）
- `init_state()` / `state_status()` / `jsonl_status()`：benchmark 自校验
- `md_table()` / `write_report()`：JSON + Markdown 输出

不引入任何第三方依赖；不改变运行时行为。
"""
import ctypes
import glob
import json
import math
import os
import statistics
import time
from pathlib import Path


def now():
    return time.perf_counter()


def pct_ms(seconds):
    return round(float(seconds) * 1000.0, 3)


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


def io_write_bytes():
    """当前进程累计写入字节；不可用 ⟹ None（调用方退化为文件体积估算）。"""
    if os.name == "nt":
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.GetCurrentProcess.restype = ctypes.c_void_p
            kernel32.GetProcessIoCounters.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(_IO_COUNTERS)]
            kernel32.GetProcessIoCounters.restype = ctypes.c_int
            counters = _IO_COUNTERS()
            handle = kernel32.GetCurrentProcess()
            if kernel32.GetProcessIoCounters(handle, ctypes.byref(counters)):
                return int(counters.WriteTransferCount)
        except Exception:  # noqa: BLE001 — 边界：无计数器即退化
            return None
        return None
    try:
        with open("/proc/self/io", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("write_bytes:"):
                    return int(line.split()[1])
    except OSError:
        return None
    return None


def percentiles(values):
    vals = sorted(float(v) for v in values if v is not None)
    if not vals:
        return {"count": 0}
    def pick(p):
        if len(vals) == 1:
            return vals[0]
        k = (len(vals) - 1) * p
        lo, hi = math.floor(k), math.ceil(k)
        if lo == hi:
            return vals[int(k)]
        return vals[lo] * (hi - k) + vals[hi] * (k - lo)
    return {
        "count": len(vals),
        "min_ms": pct_ms(vals[0]),
        "p50_ms": pct_ms(pick(0.50)),
        "p95_ms": pct_ms(pick(0.95)),
        "p99_ms": pct_ms(pick(0.99)),
        "max_ms": pct_ms(vals[-1]),
        "mean_ms": pct_ms(statistics.fmean(vals)),
    }


def safe_size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def init_state(path, target_bytes=128 * 1024, label="bench"):
    """创建真实 state（canon 形态），返回实际字节数。

    payload 用 ASCII `x`，不会因 JSON 转义改变体积；目标体积是近似值。
    """
    import gk_json_utils as JU
    target = max(1024, int(target_bytes))
    payload = "x" * max(0, target - 1024)
    data = {
        "stage": "BENCH",
        "gate_data": {
            "project_type": "bench",
            "bench": {"seq": 0, "payload": payload, "writer": 0, "label": label},
        },
    }
    data["_checksum"] = JU._state_checksum(data)
    if not JU.dump_state(path, data):
        raise RuntimeError("init_state failed: %s" % path)
    return safe_size(path)


def state_status(path):
    """校验 state JSON + `_checksum`，返回 seq/字节数/临时残留（WAL-aware）。"""
    import gk_json_utils as JU
    d = JU.read_state_file(path)                  # checkpoint + `<path>.wal` replay
    if "error" in d:
        return {"ok": False, "error": d["error"], "bytes": safe_size(path)}
    got = d.pop("_checksum", None)
    want = JU._state_checksum(d)
    gd = d.get("gate_data") or {}
    b = gd.get("bench") if isinstance(gd.get("bench"), dict) else {}
    return {
        "ok": got == want,
        "checksum": got,
        "checksum_ok": got == want,
        "seq": int(b.get("seq", 0) or 0),
        "bytes": safe_size(path),
        "tmp_left": len(glob.glob(path + ".*.tmp")),
    }


def jsonl_status(path):
    """逐行 JSON 校验（卫星片 / 侧车）；返回行数与首个坏行。"""
    if not os.path.isfile(path):
        return {"exists": False, "lines": 0, "torn": 0, "ok": True}
    lines = 0
    bad = None
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            if not line.strip():
                continue
            lines += 1
            try:
                json.loads(line)
            except Exception as e:  # noqa: BLE001 — 边界：benchmark 自校验
                bad = {"line": i, "error": "%s: %s" % (type(e).__name__, e)}
                break
    return {"exists": True, "lines": lines, "torn": (1 if bad else 0),
            "ok": bad is None, "bad": bad}


def md_table(headers, rows):
    def cell(v):
        if v is None:
            return ""
        return str(v).replace("|", "\\|").replace("\n", " ")
    out = ["| " + " | ".join(cell(h) for h in headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        out.append("| " + " | ".join(cell(v) for v in row) + " |")
    return "\n".join(out)


def write_report(result, out_dir, stem):
    """把 JSON + Markdown 写到 `out_dir`；返回两个路径。"""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    jp = out / (stem + ".json")
    mp = out / (stem + ".md")
    jp.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    md = result.get("markdown") or ""
    mp.write_text(md + "\n", encoding="utf-8")
    return str(jp), str(mp)

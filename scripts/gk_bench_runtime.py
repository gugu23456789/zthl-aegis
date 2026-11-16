#!/usr/bin/env python3
"""gk_bench_runtime.py — 治理热点微基准（路由 / 计划指针 / 速率闸 / 合并闸）。

为什么存在（2026-11-14）
========================
state / satellite / gate 三套 bench 只覆盖**持久化写路径**；2026-11 新增的热点是
「每次工具调用 / 每次派发」都会走的治理面：

  · `gk_route_center.pick_active_worktree` —— 唯一路由链（纯函数，四级优先级）；
  · `pre_tool_hook._pointer_plan_draft`   —— 指针计划定稿门（每次编辑判定一次）；
  · `gk_worktree_pool.rate_guard`         —— 热池派发限流（每次分配记一笔）；
  · `gk_merge_guard.check`                —— 合并前置闸（每次合并全扫，full 才跑）。

这些路径退化不会体现在 state 写放大上，但会直接拖慢日常操作，因此单独成表。
本工具**只读 / 只写临时目录**，不改 state、不碰真池、不执行合并。

口径
====
- 延迟 = 单次调用 wall（perf_counter），取 p50/p95/p99；
- 阈值写在本文件（**不**从基线读，避免自证）；`ok=false` 只看 p95 超阈或调用异常；
- quick 只跑前三条（毫秒级）；full 追加合并闸全扫（秒级）；smoke 用于 CI 冒烟。

用法
====
  python scripts/gk_bench_runtime.py --quick --json
  python scripts/gk_bench_runtime.py --full --out-dir dist/bench
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = Path(HERE).parent
sys.path.insert(0, HERE)

import gk_bench_common as C  # noqa: E402
import gk_route_center as RC  # noqa: E402
import gk_worktree_pool as WP  # noqa: E402
import pre_tool_hook as HK  # noqa: E402

# 阈值（毫秒）：先给宽松上界，只拦「数量级退化」；收紧须有实测依据。
THRESHOLDS = {
    "route-resolve": 5.0,
    "plan-pointer": 100.0,
    "rate-guard": 50.0,
    "merge-guard": 120000.0,
}

_PLAN_STEM = "2026-11-03-next-version-performance-mainline"   # 真实 frozen 计划
_WORKTREES = ["/bench/main", "/bench/wt1", "/bench/wt2", "/bench/wt3",
              "/bench/wt4", "/bench/wt5", "/bench/wt6", "/bench/wt7"]


def _timeit(fn, n):
    lat, errs = [], []
    for _ in range(int(n)):
        t0 = C.now()
        try:
            fn()
        except Exception as e:  # noqa: BLE001 — benchmark 记录失败，不伪装成功
            errs.append("%s: %s" % (type(e).__name__, e))
            break
        lat.append(C.now() - t0)
    return lat, errs


def _row(name, lat, errs, threshold_ms, detail=""):
    p = C.percentiles(lat)
    p95 = p.get("p95_ms")
    ok = not errs and p95 is not None and float(p95) <= float(threshold_ms)
    return {
        "scenario": name,
        "ops": len(lat),
        "latency": p,
        "threshold_ms": threshold_ms,
        "ok": bool(ok),
        "errors": errs[:5],
        "detail": detail,
    }


def run_route(n):
    def call():
        r = RC.pick_active_worktree(state_worktree=_WORKTREES[2], cwd=_WORKTREES[4],
                                    worktrees=_WORKTREES, main_repo=_WORKTREES[0])
        if r.get("source") != "state" or r.get("worktree") != _WORKTREES[2]:
            raise RuntimeError("route 结果不符: %r" % (r,))
    lat, errs = _timeit(call, n)
    return _row("route-resolve", lat, errs, THRESHOLDS["route-resolve"],
                "pick_active_worktree（state 命中）")


def run_plan_pointer(n):
    def call():
        # 真实计划文件存在且 frozen ⟹ 必须返回 False（判据路径 + META 解析）
        if HK._pointer_plan_draft(_PLAN_STEM):
            raise RuntimeError("frozen 计划被误判为 draft")
    lat, errs = _timeit(call, n)
    return _row("plan-pointer", lat, errs, THRESHOLDS["plan-pointer"],
                "pre_tool_hook._pointer_plan_draft")


def run_rate_guard(n):
    tmp = Path(tempfile.mkdtemp(prefix="gk_bench_rate_"))
    base = 1_700_000_000.0

    def call():
        # now 每次跳 1h：窗口内恒为空 ⟹ 走「读 + 追加」完整路径（不触发 limited 短路）
        nonlocal_i = call.i
        r = WP.rate_guard(tmp, "bench-sid", now=base + nonlocal_i * 3600.0)
        call.i += 1
        if r.get("limited"):
            raise RuntimeError("rate_guard 误判 limited: %r" % (r,))
    call.i = 0
    lat, errs = _timeit(call, n)
    return _row("rate-guard", lat, errs, THRESHOLDS["rate-guard"],
                "gk_worktree_pool.rate_guard（临时池根）")


def run_merge_guard():
    """full 专用：对「上一 tag → HEAD」跑一次 pre-merge 闸（只读 git 命令）。"""
    src = ""
    try:
        out = subprocess.check_output(["git", "-C", str(ROOT), "tag", "--sort=-v:refname"],
                                      text=True, stderr=subprocess.DEVNULL)
        tags = [x.strip() for x in out.splitlines() if x.strip()]
        src = tags[0] if tags else ""
    except Exception:  # noqa: BLE001 — 非 git 环境
        src = ""
    if not src:
        return {"scenario": "merge-guard", "ops": 0, "latency": {"count": 0},
                "threshold_ms": THRESHOLDS["merge-guard"], "ok": True,
                "errors": [], "detail": "无 tag（跳过全扫）"}
    import gk_merge_guard as MG
    t0 = C.now()
    errs = []
    try:
        r = MG.check(str(ROOT), src, "HEAD")
        if not r.get("decision"):
            errs.append("merge guard 无 decision: %r" % (r,))
    except Exception as e:  # noqa: BLE001
        errs.append("%s: %s" % (type(e).__name__, e))
    wall_ms = C.pct_ms(C.now() - t0)
    ok = not errs and wall_ms <= float(THRESHOLDS["merge-guard"])
    return {"scenario": "merge-guard", "ops": 1,
            "latency": {"count": 1, "p50_ms": wall_ms, "p95_ms": wall_ms, "p99_ms": wall_ms},
            "threshold_ms": THRESHOLDS["merge-guard"], "ok": bool(ok),
            "errors": errs[:5], "detail": "%s..HEAD 一次全扫" % src}


def _markdown(result):
    rows = [[s["scenario"], s["ops"], s["latency"].get("p50_ms"),
             s["latency"].get("p95_ms"), s["latency"].get("p99_ms"),
             s["threshold_ms"], s["ok"], s["detail"]] for s in result["scenarios"]]
    return "\n".join([
        "# gk_bench_runtime — %s" % result["mode"], "",
        "治理热点（路由 / 计划指针 / 速率闸 / 合并闸）；阈值见 `THRESHOLDS`（毫秒）。", "",
        C.md_table(["scenario", "ops", "p50_ms", "p95_ms", "p99_ms",
                    "threshold_ms", "ok", "detail"], rows),
    ])


def main(argv=None):
    p = argparse.ArgumentParser(prog="gk_bench_runtime.py")
    p.add_argument("--quick", action="store_true")
    p.add_argument("--full", action="store_true")
    p.add_argument("--smoke", action="store_true")
    p.add_argument("--out-dir", default="")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    if a.smoke:
        mode, n_route, n_plan, n_rate, do_merge = "smoke", 5, 3, 5, False
    elif a.full:
        mode, n_route, n_plan, n_rate, do_merge = "full", 5000, 200, 500, True
    else:
        mode, n_route, n_plan, n_rate, do_merge = "quick", 2000, 100, 300, False
    scenarios = [run_route(n_route), run_plan_pointer(n_plan), run_rate_guard(n_rate)]
    if do_merge:
        scenarios.append(run_merge_guard())
    result = {
        "ok": all(s["ok"] for s in scenarios),
        "mode": mode,
        "config": {"route_ops": n_route, "plan_ops": n_plan, "rate_ops": n_rate,
                   "merge_guard": do_merge},
        "scenarios": scenarios,
    }
    result["markdown"] = _markdown(result)
    if a.out_dir:
        jp, mp = C.write_report(result, a.out_dir, "gk_bench_runtime-" + mode)
        print("[bench-runtime] report=%s %s" % (jp, mp), file=sys.stderr)
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

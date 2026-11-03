#!/usr/bin/env python3
"""gk_bench_release.py — 发布门 benchmark（P2，下一版本主线）。

测什么
======
- `gk_doc_release.py --strict --summary` 总耗时（facts + doc-align + claims）
- `gk_ci_security_lint.py --json` 耗时（CI 最小权限/SHA pin/persist/timeout/run 注入）

发布门不是热路径，但它是每次发版必须跑完的串行成本；记录 p50/p95 没意义，
只记录单次 wall、rc、输出规模，作为发布流程基线。

用法：
  python scripts/gk_bench_release.py
  python scripts/gk_bench_release.py --out-dir dist/bench
"""
import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gk_bench_common as C  # noqa: E402


def _one(name, argv):
    t0 = C.now()
    p = subprocess.run([sys.executable] + argv, cwd=HERE, capture_output=True,
                       text=True, timeout=300)
    wall = C.now() - t0
    last = ""
    for line in reversed((p.stdout or "").splitlines()):
        if line.strip().startswith("{"):
            last = line.strip()
            break
    parsed = None
    if last:
        try:
            parsed = json.loads(last)
        except Exception:
            parsed = None
    return {
        "name": name,
        "argv": argv,
        "wall_s": round(wall, 4),
        "rc": p.returncode,
        "stdout_bytes": len((p.stdout or "").encode("utf-8")),
        "stderr_tail": (p.stderr or "")[-400:],
        "json": parsed,
        "ok": p.returncode == 0,
    }


def main(argv=None):
    p = argparse.ArgumentParser(prog="gk_bench_release.py")
    p.add_argument("--out-dir", default="")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    rows = [
        _one("doc-release", ["gk_doc_release.py", "--strict", "--summary"]),
        _one("ci-security-lint", ["gk_ci_security_lint.py", "--json"]),
    ]
    result = {"ok": all(r["ok"] for r in rows), "mode": "release", "results": rows}
    result["markdown"] = "\n".join([
        "# gk_bench_release", "",
        C.md_table(["name", "wall_s", "rc", "stdout_bytes", "ok"],
                   [[r["name"], r["wall_s"], r["rc"], r["stdout_bytes"], r["ok"]]
                    for r in rows]),
    ])
    if a.out_dir:
        jp, mp = C.write_report(result, a.out_dir, "gk_bench_release")
        print("[bench-release] report=%s %s" % (jp, mp), file=sys.stderr)
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

#!/usr/bin/env python3
"""P0 benchmark smoke：真实子进程/文件，不 mock；只验证可运行与自校验。"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _run(script, args):
    p = subprocess.run([sys.executable, os.path.join(HERE, script)] + args,
                       cwd=HERE, capture_output=True, text=True, timeout=180)
    assert p.returncode == 0, "%s rc=%s\nstdout=%s\nstderr=%s" % (
        script, p.returncode, p.stdout[-2000:], p.stderr[-2000:])
    for line in reversed(p.stdout.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            return json.loads(line)
    raise AssertionError("no JSON output from %s" % script)


def test_bench_state_smoke():
    r = _run("gk_bench_state.py", ["--smoke", "--json", "--no-crash"])
    assert r["ok"] is True
    assert r["scenarios"] and all(s["ok"] for s in r["scenarios"])
    assert r["scenarios"][0]["success_ops"] == 2
    assert r["scenarios"][0]["checksum_ok"] is True


def test_bench_satellite_smoke():
    r = _run("gk_bench_satellite.py", ["--smoke", "--json"])
    assert r["ok"] is True
    assert r["scenarios"] and all(s["ok"] for s in r["scenarios"])
    assert r["scenarios"][0]["leaves"] == r["scenarios"][0]["calls"]
    assert r["gc"] and all(g["ok"] for g in r["gc"])
    assert r["reclaim"] and all(x["ok"] for x in r["reclaim"])


def test_bench_gate_smoke():
    r = _run("gk_bench_gate.py", ["--smoke", "--json"])
    assert r["ok"] is True
    assert r["scenarios"] and all(s["ok"] for s in r["scenarios"])
    assert {s["op"] for s in r["scenarios"]} == {"read", "set_nested", "update_gate_data"}

#!/usr/bin/env python3
"""`gk_bench_compare.py` 机检臂（S5）：容差内放行、超容差红、失败/残留硬红、发布门只 WARN。"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_bench_compare as C  # noqa: E402


def _base(amp=1.0, p99=10.0, sat_amp=1.0, gate_amp=1.0, rel=10.0):
    return {"benchmarks": {
        "state": {"scenarios": [{"scenario": "s", "write_amp": amp, "p99_ms": p99,
                                 "success_ops": 10, "total_ops": 10}],
                  "crash": [{"trial": i, "checksum_ok": True, "tmp_left": 0, "ok": True}
                            for i in (1, 2)], "ok": True},
        "satellite": {"scenarios": [{"scenario": "sat", "write_amp": sat_amp, "ok": True}],
                      "ok": True},
        "gate": {"scenarios": [{"scenario": "gate", "write_amp": gate_amp, "ok": True}],
                 "ok": True},
        "release": {"results": [{"name": "doc-release", "wall_s": rel, "ok": True}],
                    "ok": True},
    }}


def _cur(amp=1.0, p99=10.0, sat_amp=1.0, gate_amp=1.0, rel=10.0,
         success=10, total=10, crash_ok=True, tmp=0):
    return {"state": {"scenarios": [{"scenario": "s", "write_amp": amp, "p99_ms": p99,
                                     "success_ops": success, "total_ops": total}],
                      "crash": [{"trial": 1, "checksum_ok": crash_ok, "tmp_left": tmp,
                                 "ok": True}], "ok": True},
            "satellite": {"scenarios": [{"scenario": "sat", "write_amp": sat_amp,
                                         "ok": True}], "ok": True},
            "gate": {"scenarios": [{"scenario": "gate", "write_amp": gate_amp,
                                    "ok": True}], "ok": True},
            "release": {"results": [{"name": "doc-release", "wall_s": rel, "ok": True}],
                        "ok": True}}


def test_within_tolerance_passes():
    r = C.compare(_base(), _cur(amp=1.2, p99=12.0, sat_amp=1.2, gate_amp=1.2),
                  tolerance=1.25)
    assert r["ok"] and not r["violations"], r


def test_over_tolerance_is_violation():
    r = C.compare(_base(), _cur(amp=1.5), tolerance=1.25)
    assert not r["ok"]
    assert any(v["metric"] == "state.write_amp" for v in r["violations"])


def test_failed_ops_is_hard_failure():
    r = C.compare(_base(), _cur(success=9, total=10))
    assert not r["ok"]
    assert any(v["metric"] == "state.failed" for v in r["violations"])


def test_crash_residue_and_checksum():
    r1 = C.compare(_base(), _cur(tmp=2))
    r2 = C.compare(_base(), _cur(crash_ok=False))
    assert not r1["ok"] and not r2["ok"]
    assert any(v["metric"] == "state.crash.tmp_left" for v in r1["violations"])
    assert any(v["metric"] == "state.crash.checksum" for v in r2["violations"])


def test_release_wall_warns_by_default_and_strict_fails():
    a = C.compare(_base(rel=10.0), _cur(rel=20.0))
    b = C.compare(_base(rel=10.0), _cur(rel=20.0), strict_release=True)
    assert a["ok"] and a["warnings"], a
    assert not b["ok"] and b["violations"], b


def test_missing_scenario_is_violation():
    cur = _cur()
    cur["state"]["scenarios"] = []
    r = C.compare(_base(), cur)
    assert not r["ok"]


def test_new_scenario_warns_only():
    cur = _cur()
    cur["satellite"]["scenarios"].append({"scenario": "new", "write_amp": 99, "ok": True})
    r = C.compare(_base(), cur)
    assert r["ok"] and any(w["scenario"] == "new" for w in r["warnings"])


def test_init_baseline_writes_schema(tmp_path):
    cur = _cur()
    files = {}
    for k in ("state", "satellite", "gate", "release"):
        p = tmp_path / (k + ".json")
        p.write_text(json.dumps(cur[k]), encoding="utf-8")
        files[k] = p
    out = tmp_path / "baseline.json"
    rc = C.main(["--init-baseline", str(out),
                 "--state", str(files["state"]),
                 "--satellite", str(files["satellite"]),
                 "--gate", str(files["gate"]),
                 "--release", str(files["release"]), "--json"])
    assert rc == 0
    got = json.loads(out.read_text(encoding="utf-8"))
    assert got["schema"] == "gk-bench-baseline/v1"
    assert got["environment"] and "state" in got["benchmarks"]

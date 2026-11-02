#!/usr/bin/env python3
"""Tests for scripts/gk_audit_memory.py (batch8 R-T6 Phase 4b 补课 2026-08-23).

Covers: history 规模 / calibration trend 判定 / ECC 文件数 / history_entries 摘要.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_audit_memory as gam


def _write_state(data: dict, path: str) -> str:
    import gk_state
    gk_state._write_state(data, path)
    return path


def test_empty_state(tmp_path):
    sp = _write_state({"gate_data": {}, "history": []}, str(tmp_path / "s.json"))
    r = gam.check_memory(sp, str(tmp_path))
    assert r["history_count"] == 0
    assert r["calibration_trend"] == "stable"
    assert r["calibration_samples"] == 0
    assert r["ecc_files_found"] == 0
    assert r["history_entries"] == []


def test_history_entries_summary(tmp_path):
    sp = _write_state({
        "gate_data": {},
        "history": [
            {"r_phase": "R-T5", "best": {"score": 0.8}, "rejection_count": 2},
            {"r_phase": "R-T6", "best": {"score": 0.9}, "rejection_count": 0},
        ],
    }, str(tmp_path / "s.json"))
    r = gam.check_memory(sp, str(tmp_path))
    assert r["history_count"] == 2
    assert r["history_entries"][-1] == {"r_phase": "R-T6", "best_score": 0.9, "rejections": 0}


def test_calibration_trend_degrading(tmp_path):
    cl = [{"divergence": 0.05}, {"divergence": 0.06}, {"divergence": 0.07},
          {"divergence": 0.4}, {"divergence": 0.5}, {"divergence": 0.6}]
    sp = _write_state({"gate_data": {"human_calibration_log": cl}, "history": []},
                      str(tmp_path / "s.json"))
    r = gam.check_memory(sp, str(tmp_path))
    assert r["calibration_trend"] == "degrading"  # 前 3 均值 0.06 vs 后 3 均值 0.5
    assert r["calibration_samples"] == 6


def test_calibration_trend_improving(tmp_path):
    cl = [{"divergence": 0.6}, {"divergence": 0.5}, {"divergence": 0.4},
          {"divergence": 0.06}, {"divergence": 0.05}, {"divergence": 0.04}]
    sp = _write_state({"gate_data": {"human_calibration_log": cl}, "history": []},
                      str(tmp_path / "s.json"))
    r = gam.check_memory(sp, str(tmp_path))
    assert r["calibration_trend"] == "improving"


def test_ecc_files_counted(tmp_path):
    (tmp_path / "references").mkdir()
    for name in ("ecc-finding-a.md", "ecc-finding-b.md", "not-ecc.md"):
        (tmp_path / "references" / name).write_text("x", encoding="utf-8")
    sp = _write_state({"gate_data": {}, "history": []}, str(tmp_path / "s.json"))
    r = gam.check_memory(sp, str(tmp_path))
    assert r["ecc_files_found"] == 2

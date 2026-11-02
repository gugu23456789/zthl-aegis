#!/usr/bin/env python3
"""Gatekeeper Audit — Memory domain (batch8 R-T6 Phase 4b 补课 2026-08-23)
===========================================================================
Migrates `cmd_audit --memory` bash heredoc (gatekeeper-cli.sh L4628-4650) to a
standalone Python module. 原 heredoc 硬编码 `<home>/...` ECC 路径 →
参数化 SKILL_DIR（与 gk_audit_docs.py 同模式）。

Contract (compatible with bash heredoc):
  {"history_count":N,"ecc_files_found":N,
   "calibration_trend":"stable|degrading|improving","calibration_samples":N,
   "history_entries":[{r_phase,best_score,rejections}...]}

Usage:
  STATE_FILE=<s> SKILL_DIR=<d> python3 scripts/gk_audit_memory.py

Exit codes: 0 = OK (JSON on stdout), 1 = error JSON (stderr not swallowed).
"""
import glob
import json
import os
import sys
from pathlib import Path


def check_memory(state_path: str, skill_dir: str) -> dict:
    """Memory domain — history 规模 + 校准趋势 + ECC 文件数."""
    try:
        with open(state_path, encoding="utf-8") as f:
            s = json.load(f)
    except Exception:
        s = {}
    h = s.get("history", [])
    cl = s.get("gate_data", {}).get("human_calibration_log") or []
    divs = [e.get("divergence") for e in cl if e.get("divergence") is not None]

    # Calibration trend: 前 3 vs 后 3 divergence 均值差 > 0.1
    trend = "stable"
    if len(divs) >= 3:
        f3 = sum(divs[:3]) / 3
        l3 = sum(divs[-3:]) / 3
        if l3 > f3 + 0.1:
            trend = "degrading"
        elif l3 < f3 - 0.1:
            trend = "improving"

    ecc = sorted(glob.glob(str(Path(skill_dir) / "references" / "ecc-*.md")))
    return {
        "history_count": len(h),
        "ecc_files_found": len(ecc),
        "calibration_trend": trend,
        "calibration_samples": len(divs),
        "history_entries": [
            {"r_phase": x.get("r_phase"),
             "best_score": x.get("best", {}).get("score"),
             "rejections": x.get("rejection_count", 0)}
            for x in h[-5:]
        ],
    }


def main():
    state_path = os.environ.get("STATE_FILE", "")
    skill_dir = os.environ.get("SKILL_DIR", str(Path(__file__).resolve().parent.parent))
    if not state_path:
        _dir = os.path.dirname(os.path.abspath(__file__))
        if _dir not in sys.path:
            sys.path.insert(0, _dir)
        from gk_state import DEFAULT_STATE_FILE
        state_path = DEFAULT_STATE_FILE
    try:
        print(json.dumps(check_memory(state_path, skill_dir), ensure_ascii=False))
        sys.exit(0)
    except Exception as e:
        err = {"error": str(e), "trace": __import__("traceback").format_exc()}
        print(json.dumps(err, ensure_ascii=False), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

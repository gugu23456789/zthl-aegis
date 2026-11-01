#!/usr/bin/env python3
"""
gk_audit_crossr.py — Cross-R audit analysis (batch8 R-T6 Phase 5, 2026-08-20)
==============================================================================
Migrates `cmd_audit --crossr` bash heredoc core analysis to a standalone
Python module. 0 API calls, deterministic. LLM analysis + git concurrency
scan stay wired at CLI layer (already standalone scripts: subagent_runner.py /
gk_git_concurrency_check.py).

Contract (compatible with bash heredoc L5082-5103):
  {"rejected_count":N,"best_score":...,"best_stage":...,
   "rejection_convergence":"converging|diverging|stable",
   "last_rejections":[...],"history_scores":{...},
   "phase_patterns":{"phase_distribution":[...],"stage_patterns":[...],
                      "recurring_violations":[...]}}   ← Phase 5 新增（跨 phase 模式分析）

Usage:
  python3 scripts/gk_audit_crossr.py [--state-file <f>]
  STATE_FILE env 亦可指定（CLI 调用时传入，避免 heredoc 内嵌路径）。
  GITSCAN env 可选：CLI 侧 gk_git_concurrency_check.py 产物 JSON，合并进输出 git_concurrency。

Exit codes: 0 = OK (JSON on stdout), 1 = error JSON.
2026-08-20: 迁移自 cmd_audit --crossr bash heredoc (L5082-5103)。
  修复点: ① 路径参数化（STATE_FILE env）；② 新增 phase_patterns 跨 phase 分析
  （计划 L1654: "audit --crossr 包含跨 phase 模式分析 (非当前 phase 孤立数据)"）；
  ③ best/history entry 可能缺字段 → `or {}` 加固（原 heredoc 直接崩被 2>/dev/null 吞）。
"""

import json
import os
import sys
from collections import Counter


def _load_state(state_path: str) -> dict:
    """State 读取（优先 gk_state._read_state 带 checksum 警告，缺失降级原生 json）。"""
    if not state_path:
        return {}
    try:
        _script_dir = os.path.dirname(os.path.abspath(__file__))
        if _script_dir not in sys.path:
            sys.path.insert(0, _script_dir)
        from gk_state import _read_state
        s = _read_state(state_path)
        if isinstance(s, dict) and "error" not in s:
            return s
    except Exception:
        pass
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _convergence(rc: list) -> str:
    """迁移自 heredoc: h[-5:] 的 rejection_count，3 样本以上判收敛/发散/稳定。"""
    if len(rc) >= 3:
        if rc[-1] < rc[0]:
            return "converging"
        if rc[-1] > rc[0]:
            return "diverging"
    return "stable"


def analyze_crossr(state_path: str) -> dict:
    """Cross-R analysis — 输出契约与 bash heredoc 一致 + phase_patterns 增值。"""
    s = _load_state(state_path)
    gd = s.get("gate_data", {}) if isinstance(s, dict) else {}
    rej = gd.get("rejected_edits", []) or []
    best = gd.get("best", {}) or {}
    h = s.get("history", []) if isinstance(s, dict) else []

    rc = [x.get("rejection_count", 0) or 0 for x in h[-5:]]
    conv = _convergence(rc)

    # Phase 5 增值: 跨 phase 模式分析（非当前 phase 孤立数据）
    stage_counts = Counter((r.get("stage") or "unknown") for r in rej)
    stage_patterns = [{"stage": st, "count": c} for st, c in stage_counts.most_common(5)]
    viol_counter = Counter(str(v) for r in rej for v in (r.get("violations") or []))
    recurring = [{"violation": v, "count": c} for v, c in viol_counter.most_common(5)]
    phase_distribution = [
        {"r_phase": x.get("r_phase"), "rejection_count": x.get("rejection_count", 0),
         "best_score": (x.get("best") or {}).get("score")}
        for x in h
    ]

    result = {
        "rejected_count": len(rej),
        "best_score": best.get("score"),
        "best_stage": best.get("stage"),
        "rejection_convergence": conv,
        "last_rejections": [
            {"stage": r.get("stage"), "violations": r.get("violations", [])}
            for r in rej[-5:]
        ],
        "history_scores": {(x.get("r_phase")): (x.get("best") or {}).get("score")
                           for x in h[-5:]},
        "phase_patterns": {
            "phase_distribution": phase_distribution,
            "stage_patterns": stage_patterns,
            "recurring_violations": recurring,
        },
    }

    # GITSCAN env 合并（CLI 侧 gk_git_concurrency_check.py 产物；空则注入 {} 保持契约恒有字段）
    gitscan = os.environ.get("GITSCAN", "")
    if gitscan:
        try:
            result["git_concurrency"] = json.loads(gitscan)
        except Exception:
            result["git_concurrency"] = {"raw": gitscan[:200]}
    else:
        result["git_concurrency"] = {}

    # GWSCAN env 合并（2026-09-01 L1 扩展实装：git-workflow 全量检测
    # — gk_git_workflow_check.py 产物；空则注入 {} 保持契约恒有字段）
    gwscan = os.environ.get("GWSCAN", "")
    if gwscan:
        try:
            result["git_workflow"] = json.loads(gwscan)
        except Exception:
            result["git_workflow"] = {"raw": gwscan[:200]}
    else:
        result["git_workflow"] = {}

    return result


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    state_file = os.environ.get("STATE_FILE", "")
    if "--state-file" in args:
        i = args.index("--state-file")
        if i + 1 < len(args):
            state_file = args[i + 1]
    try:
        print(json.dumps(analyze_crossr(state_file)))
    except Exception as e:
        print(json.dumps({"rejected_count": 0, "rejection_convergence": "stable",
                          "error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()

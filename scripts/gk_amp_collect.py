#!/usr/bin/env python3
"""gk_amp_collect.py — AMP 采集入口（`zthl-harness-adapter` 计划 ZH2-H10 / ZH3-H14f）
=====================================================================================

把既有事实源采集为 AMP `LogRecord` 并写入 `~/.zthl/amp/*.log`：

    heartbeat ← `gk_self_check.run_all()`
    metrics   ← `amp/access.log` 窗口汇总
    audit     ← `<state>.finding-journal.jsonl`（幂等：已入账的自然键跳过）
    system    ← 自检 FAIL/WARN（自由格式 body）
    message   ← seam（ZH3-H14d 前不产出）

用法：
    python3 scripts/gk_amp_collect.py                      # 全部可采集类
    python3 scripts/gk_amp_collect.py --types heartbeat,system
    python3 scripts/gk_amp_collect.py --window 5 --dry-run --json

纪律：采集**只读**既有事实源；`--dry-run` 不落盘。AMP 任何异常不阻断（采集侧显式报告）。
"""
import argparse
import json
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(_ROOT), str(_ROOT / "scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from zthl.acp import amp, amp_bridge  # noqa: E402


def _self_check(state_file: str, skill_dir: str):
    """跑一遍自检（心跳/系统类的数据源）。失败 ⟹ `None`（不产出幻影记录）。"""
    try:
        import gk_self_check
        return gk_self_check.run_all(
            state_file,
            skill_dir,
            os.environ.get("_KEY_META", ""),
            os.environ.get("_KEY_INTEGRITY", ""),
            os.environ.get("_AUDIT_KEY_DIR", ""),
        )
    except Exception:
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(description="AMP 采集（六类日志 → ~/.zthl/amp）")
    ap.add_argument("--types", default="heartbeat,metrics,audit,system",
                    help="逗号分隔：heartbeat,metrics,audit,system（message 为 seam）")
    ap.add_argument("--state-file", default=os.environ.get("STATE_FILE", ""))
    ap.add_argument("--skill-dir", default=str(_ROOT))
    ap.add_argument("--window", type=int, default=5, help="metrics 窗口（分钟）")
    ap.add_argument("--dry-run", action="store_true", help="只构造不落盘")
    ap.add_argument("--json", action="store_true", help="JSON 输出")
    args = ap.parse_args(argv)

    types = [t.strip() for t in args.types.split(",") if t.strip()]
    unknown = [t for t in types if t not in amp.LOG_TYPES]
    if unknown:
        print(json.dumps({"ok": False, "error": f"unknown logType: {unknown}"}, ensure_ascii=False))
        return 2

    sc = _self_check(args.state_file, args.skill_dir) if (
        "heartbeat" in types or "system" in types) else None
    out = {"dir": str(amp.amp_dir()), "enabled": amp.enabled(), "types": types}
    built = {}

    if "heartbeat" in types:
        built["heartbeat"] = amp_bridge.heartbeat(sc)
    if "metrics" in types:
        m = amp_bridge.metrics(args.window)
        if m:
            built["metrics"] = m
        else:
            out["metrics_skipped"] = "no access records in window"
    if "system" in types:
        s = amp_bridge.system(sc)
        if s:
            built["system"] = s
        else:
            out["system_skipped"] = "self-check has no FAIL/WARN"
    if args.dry_run:
        out["dry_run"] = True
        out["records"] = built
        if "audit" in types:
            out["audit"] = amp_bridge.collect_audit(args.state_file, dry_run=True)
    else:
        out["written"] = {}
        for t, kw in built.items():
            out["written"][t] = bool(amp.emit(**kw))
        if "audit" in types:
            out["audit"] = amp_bridge.collect_audit(args.state_file)

    print(json.dumps(out, ensure_ascii=False, indent=2) if args.json
          else json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

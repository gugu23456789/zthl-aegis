#!/usr/bin/env python3
"""gk_audit_model_tick.py — 审计署 4B 生命周期 **cron 作业体**（408 T5，2026-11-13）。

契约:
  - 输入: `[--sidecar P] [--log P]`
  - 输出: stdout JSON（= `gk_audit_lifecycle.tick()` 原样）+ 一行 rc/reason 追加到日志
  - 退出码: 0=tick ok；3=tick 失败；4=WARMING_BUSY（并发 tick，属正常拒绝）

单一事实源: 计数/启停/理由枚举全在 `gk_audit_lifecycle.tick()`；本模块**只做**「跑一次 + 落
rc/reason」，不复制任何判据（禁第二套 decide）。日志为单行 JSON（`ts/rc/state/reason`），
与 `cron_scheduler` 的 rc 日志同族 —— 用于事后回答「60s tick 到底跑没跑、为什么没启停」。
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_audit_lifecycle as LC  # noqa: E402

_DEFAULT_LOG = os.path.join(os.path.expanduser("~"), ".gatekeeper", "cron",
                            "audit-model-tick.log")


def tick_once(sidecar=None, log_path=None) -> tuple:
    """跑一次 tick；返回 `(rc, result)`，并把 rc/state/reason 追加进日志（失败不阻断）。"""
    res = LC.tick(sidecar)
    rc = 0 if res.get("ok") else (4 if res.get("error") == "WARMING_BUSY" else 3)
    line = {"ts": round(time.time(), 3), "rc": rc,
            "state": res.get("state") or (res.get("decision") or {}).get("target") or "",
            "reason": res.get("reason") or res.get("error") or ""}
    p = log_path or os.environ.get("GK_AUDIT_TICK_LOG") or _DEFAULT_LOG
    try:
        Path(p).parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(line, ensure_ascii=False) + "\n")
    except OSError:
        pass                      # 日志失败不得改变 tick 结果（观测面 ≠ 控制面）
    return rc, res


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="审计署 4B 生命周期 tick（cron 作业体）")
    ap.add_argument("--sidecar", default="", help="sidecar 路径（缺省 = 技能仓 sidecar）")
    ap.add_argument("--log", default="", help="rc/reason 日志路径（缺省 ~/.gatekeeper/cron/…）")
    ns = ap.parse_args(argv)
    rc, res = tick_once(ns.sidecar or None, ns.log or None)
    print(json.dumps(res, ensure_ascii=False))
    return rc


if __name__ == "__main__":
    sys.exit(main())

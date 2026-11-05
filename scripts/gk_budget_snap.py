#!/usr/bin/env python3
"""预算快照（`gatekeeper-cli.sh::_budget_snap` 内联块下沉，2026-11-04）。

输出契约（单行、空格分隔）：`<domain> <used> <remaining>`；state 不可用 → `- - -`。
`session` 域在条目未建时按扣减点的 `setdefault` 口径预演（max / 0 / max），
否则“新会话首笔扣款”会成为跨域伪差值而被丢弃。

⚠ CRLF：Windows python 的 print 产出 `\\r\\n`，`$()` 只剥尾部 `\\n` ⟹ 三字段串尾粘 `\\r`
污染账单对账 —— 必须显式 `newline="\\n"`（原内联块同款约束，见 test_gk_cli_crlf_strip）。
"""
import json
import os
import sys


def snapshot(state_file: str, session_id: str = "") -> tuple:
    try:
        with open(state_file, encoding="utf-8") as f:
            d = json.load(f)
    except Exception:  # noqa: BLE001 — 损坏/缺失统一降级为不可用
        return ("-", "-", "-")
    eb = (d.get("gate_data") or {}).get("edit_budget") or {}
    if session_id:
        box = (eb.get("sessions") or {}).get(session_id)
        if isinstance(box, dict):
            return ("session", int(box.get("used", 0) or 0),
                    int(box.get("remaining", 0) or 0))
        return ("session", 0, int(eb.get("max", 0) or 0))
    return ("global", int(eb.get("used", 0) or 0), int(eb.get("remaining", 0) or 0))


def main() -> int:
    try:
        sys.stdout.reconfigure(newline="\n")
    except Exception:  # noqa: BLE001 — 非 TextIO stdout（测试替身）时忽略
        pass
    p = os.environ.get("STATE_FILE") or (sys.argv[1] if len(sys.argv) > 1 else "")
    sid = os.environ.get("GK_SESSION_ID") or (sys.argv[2] if len(sys.argv) > 2 else "")
    print("%s %s %s" % snapshot(p, sid))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Gatekeeper CLI balance formatter — avoids heredoc escaping issues.

2026-11-04（单源收敛）：解析**不再原地重写** —— 统一走 `gk_views.parse_balance`，
避免与 `gk_views.cmd_balance` / `gk_balance_audit` 三份解析规则漂移。
输出行格式保持逐字不变（既有消费者/快照基线依赖）；**追加**一行投喂提醒
（仅当用户显式设置 `GK_BALANCE_MIN_CNY` 且余额低于它；文案单源 = `gk_views.topup_reminder`）。
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gk_views import parse_balance, topup_reminder  # noqa: E402


def main() -> int:
    d = json.loads(sys.stdin.read())
    parsed = parse_balance(d)
    for bi in parsed["infos"]:
        cur = bi.get("currency") or "?"
        print(f"Currency: {cur}")
        print(f"  Total: {bi.get('total_balance') or '?'}")
        print(f"  Granted: {bi.get('granted_balance') or '0'}")
        print(f"  Topped-up: {bi.get('topped_up_balance') or '0'}")
    print(f"Available: {(d.get('is_available') if isinstance(d, dict) else None) or False}")
    print("Rate limits: v4-pro=500, v4-flash=2500 (this CLI uses v4-flash)")
    tip = topup_reminder(parsed.get("total"))
    if tip:
        print(tip)
    return 0


if __name__ == "__main__":
    sys.exit(main())

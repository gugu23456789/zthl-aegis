#!/usr/bin/env python3
"""Gatekeeper CLI balance formatter — avoids heredoc escaping issues."""
import sys, json
d = json.loads(sys.stdin.read())
for bi in d.get('balance_infos', []):
    cur = bi.get('currency', '?')
    print(f'Currency: {cur}')
    print(f'  Total: {bi.get("total_balance","?")}')
    print(f'  Granted: {bi.get("granted_balance","0")}')
    print(f'  Topped-up: {bi.get("topped_up_balance","0")}')
print(f'Available: {d.get("is_available",False)}')
print('Rate limits: v4-pro=500, v4-flash=2500 (this CLI uses v4-flash)')

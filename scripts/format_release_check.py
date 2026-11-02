#!/usr/bin/env python3
"""Format release-check JSON output as a readable summary.
Usage: bash gatekeeper-cli.sh release-check | python3 scripts/format_release_check.py"""
import sys, json

d = json.loads(sys.stdin.read())
updates = [p for p in d['projects'] if p['has_update']]
all_ok = len(updates) == 0

print("=== Release Check Report ===")
for p in d['projects']:
    if p['has_update']:
        icon = "⚠️ " if p['category'] == 'direct' else "ℹ️ "
        print(f"{icon}{p['name']:15s} {p['current_version']:>12s} → {p['latest_version']:<12s} ({p['category']})")
    else:
        print(f"  ✓ {p['name']:15s} {p['current_version']:>12s} (current)")

if all_ok:
    print("All projects up to date.")
elif any(p['category'] == 'direct' for p in updates):
    print(f"\n⚠️  {len(updates)} project(s) have updates. Run 'advance ECO-RESEARCH' to analyze impact.")
else:
    print(f"\nℹ️  {len(updates)} reference project(s) have updates.")

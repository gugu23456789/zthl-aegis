#!/bin/bash
# Phase -1: Capture baselines for all safe read-only commands
SKILL_DIR="${SKILL_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CLI="$SKILL_DIR/gatekeeper-cli.sh"
OUT="$SKILL_DIR/scripts/test_baselines"
mkdir -p "$OUT"

echo "Capturing baselines..."

# Safe read-only commands
for cmd in state balance self-check achievements context trace replay; do
  echo "  $cmd..."
  bash "$CLI" "$cmd" 2>/dev/null > "$OUT/baseline_${cmd}.json"
done

# cron (list mode)
echo "  cron..."
bash "$CLI" cron list 2>/dev/null > "$OUT/baseline_cron.json"

# discover
echo "  discover..."
bash "$CLI" discover 2>/dev/null > "$OUT/baseline_discover.json"

echo "Done. Files:"
ls -la "$OUT"/baseline_*.json 2>/dev/null | wc -l

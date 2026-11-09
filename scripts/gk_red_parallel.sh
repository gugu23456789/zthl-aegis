#!/usr/bin/env bash
# gk_red_parallel.sh — 红队确定性**只读站**并发执行器（2026-11-09）
# 只跑 _red_attacks.py 的只读 phase；RED-REPORT / advance 状态推进仍走串行链（防 state 写竞态）。
set -u
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${GK_PY:-python3}"
WORKERS=4
PHASES="scope surface constraints exploit postex hint hook py poison registry ghost coverage diff integrity"
while [ $# -gt 0 ]; do
  case "$1" in
    --workers) WORKERS="${2:-4}"; shift 2 2>/dev/null || shift ;;
    --phases)  PHASES="${2:-}"; shift 2 2>/dev/null || shift ;;
    --help|-h)
      echo "usage: bash scripts/gk_red_parallel.sh [--workers N] [--phases 'p1 p2 ...']"
      echo "只读 phases: $PHASES"
      exit 0 ;;
    *) shift ;;
  esac
done
TMP=$(mktemp -d 2>/dev/null || echo "/tmp/gk-red-parallel.$$")
mkdir -p "$TMP"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT
launch() {
  local phase="$1"
  (
    timeout 180 "$PY" "$SKILL_DIR/scripts/_red_attacks.py" "$phase" \
      > "$TMP/$phase.json" 2> "$TMP/$phase.err"
    echo $? > "$TMP/$phase.rc"
  ) &
}
for phase in $PHASES; do
  launch "$phase"
  while [ "$(jobs -pr | wc -l | tr -d ' ')" -ge "$WORKERS" ]; do
    wait -n 2>/dev/null || break
  done
done
wait
"$PY" - "$TMP" $PHASES <<'PY'
import json, pathlib, sys
tmp = pathlib.Path(sys.argv[1]); phases = sys.argv[2:]
out = {"ok": True, "parallel": True, "phases": {}, "findings": 0, "failed": []}
for p in phases:
    rc_f = tmp / (p + ".rc")
    rc = int(rc_f.read_text().strip() or "1") if rc_f.exists() else 1
    try:
        data = json.loads((tmp / (p + ".json")).read_text(encoding="utf-8"))
    except Exception:
        data = None
    det = data.get("details") if isinstance(data, dict) else None
    n = len(det) if isinstance(det, list) else (
        int(data.get("findings") or 0) if isinstance(data, dict) else 0)
    out["phases"][p] = {"ok": rc == 0 and data is not None, "rc": rc,
                        "findings": n, "data": data}
    out["findings"] += n
    if rc != 0 or data is None:
        out["failed"].append(p)
out["ok"] = not out["failed"]
print(json.dumps(out, ensure_ascii=False))
sys.exit(0 if out["ok"] else 2)
PY

#!/usr/bin/env bash
# run_tests.sh — 测试统一入口（2026-11-13）。
#
# 目标：① 一次全量跑完就给出「真红 / 并行假红」两个清单；② 不制造 wsl.exe 进程风暴；
#      ③ 用最新调度器吃掉「重文件拖尾」，同时把并发压到不触发门禁 watchdog 的水平。
#
# 用法（**在 WSL 内一次调用**；从 Windows 侧只起一个 wsl.exe）：
#   bash scripts/run_tests.sh                      # 全量
#   bash scripts/run_tests.sh scripts/test_x.py    # 子集
#   DIST=worksteal bash scripts/run_tests.sh       # 工作窃取调度（默认 loadfile）
#
# 旋钮：JOBS（默认 = nproc-1，上限 6）/ DIST / OUT / NO_RECHECK=1 / GK_TEST_PY
#
# 为什么默认 loadfile 而不是 worksteal：
#   本仓有大量「同文件内共享模块级状态」的臂（夹具/计数器/临时树），loadfile 保证整文件
#   落同一 worker；worksteal 会把同文件的用例拆到不同 worker（更快，但可能引入新的
#   顺序依赖）。需要压尾延迟时用 DIST=worksteal 显式切换，并用串行复核兜底。
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

# 解释器：必须是**当前平台可运行**且带 pytest。
#   2026-11-13 实测：`py_resolve.sh pytest` 在 WSL 下会先返回主树 `.venv-*/Scripts/python.exe`
#   （Windows 解释器，`_ok_any` 靠 WSL interop 也能过）⟹ pytest 用 Windows 路径语义收集
#   ⟹ `.keys` 报 WinError 1920、`/tmp` 夹具全错。故 POSIX 侧**显式排除** `*.exe`。
case "$(uname -s 2>/dev/null)" in
  MINGW*|MSYS*|CYGWIN*) PLAT="win" ;;
  *) PLAT="wsl" ;;
esac

_has_pytest() { "$1" -c "import pytest, xdist" >/dev/null 2>&1; }

_pick_py() {
  local c
  for c in "${GK_TEST_PY:-}" \
           "$(command -v python3 2>/dev/null || true)" \
           "$(command -v python 2>/dev/null || true)" \
           $(ls /opt/*/bin/python 2>/dev/null || true) \
           "$(bash scripts/py_resolve.sh pytest 2>/dev/null || true)"; do
    [ -n "$c" ] || continue
    if [ "$PLAT" = "wsl" ]; then
      case "$c" in *.exe|*.EXE) continue ;; esac       # Windows 解释器不跑 POSIX 套件
    fi
    _has_pytest "$c" && { printf '%s' "$c"; return 0; }
  done
  return 1
}

PY="$(_pick_py || true)"
[ -n "$PY" ] || PY="python3"

# 验收 CLI / 脚本内裸 python3 的解释器口径：与本次运行保持一致
export ACCEPT_PY="${ACCEPT_PY:-$PY}"
if [ -z "${GK_PY_GLOBS:-}" ]; then
  case "$(uname -s 2>/dev/null)" in
    MINGW*|MSYS*|CYGWIN*) : ;;                       # Windows 侧不启用 /opt 通配
    *) export GK_PY_GLOBS="/opt/*/bin/python" ;;
  esac
fi

NPROC="$(nproc 2>/dev/null || echo 4)"
JOBS="${JOBS:-$(( NPROC > 1 ? NPROC - 1 : 1 ))}"
[ "$JOBS" -gt 6 ] && JOBS=6
DIST="${DIST:-loadfile}"
OUT="${OUT:-/tmp/gk-tests}"
mkdir -p "$OUT"

ARGS=(-q -p no:cacheprovider -n "$JOBS" --dist "$DIST"
      --maxprocesses="$JOBS" --max-worker-restart=0
      --durations=25 --junitxml="$OUT/all.xml")
[ "$#" -gt 0 ] && ARGS+=("$@")

echo "[run_tests] py=$PY jobs=$JOBS dist=$DIST out=$OUT"
"$PY" -m pytest "${ARGS[@]}" 2>&1 | tee "$OUT/all.log"
rc="${PIPESTATUS[0]}"

# 失败清单（并行结果）→ 串行复核：只把「并行红但串行绿」标成假红
grep -E '^FAILED ' "$OUT/all.log" | sed -E 's/^FAILED ([^ ]+).*/\1/' > "$OUT/failed.txt" || true
grep -E '^(FAILED|[0-9]+ (failed|passed))' "$OUT/all.log" | tail -3

if [ "$rc" -ne 0 ] && [ "${NO_RECHECK:-0}" != "1" ] && [ -s "$OUT/failed.txt" ]; then
  echo "[run_tests] 串行复核 $(wc -l < "$OUT/failed.txt") 条（滤并行假红）"
  mapfile -t IDS < "$OUT/failed.txt"
  "$PY" -m pytest -q -p no:cacheprovider --tb=short "${IDS[@]}" 2>&1 | tee "$OUT/recheck.log"
  rc="${PIPESTATUS[0]}"
  echo "[run_tests] 串行复核 rc=$rc（0 = 全部是并行假红；log: $OUT/recheck.log）"
fi

echo "[run_tests] artifacts: $OUT/all.log $OUT/failed.txt ${OUT}/recheck.log"
exit "$rc"

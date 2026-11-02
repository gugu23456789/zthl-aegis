#!/usr/bin/env bash
# run_verify.sh <verify_script.py> [args...] — 验证脚本机器护栏（2026-08-09）
# =============================================================================
# 目的：兜住"验证脚本自身 bug"（本次 verify_check_cfg.py 的 declared 变量覆盖
# 导致误报）。对齐 wasm-pre-check.sh 的 pass()/fail() 分级 + CI failure 日志 dump：
#
#   P1 py_compile      语法检查（对齐 wasm-pre-check P7 file integrity）
#   P2 python 执行     运行验证脚本（对齐 P1 build）
#   P3 机器断言        输出必须含 "=== ALL_PASS ==="（对齐 pass() 哨兵）
#                       防"脚本跑了但断言缺失/断言没生效/误报"——只有明确的 PASS
#                       哨兵才算通过，否则一律 FAIL 并 dump 完整输出
#   P4 交叉验证提示    FAIL 时提示换一种方法验证同一结论（对齐 CI Auto-Fix 诊断）
#
# 验证脚本约定：
#   1) 结尾必须打印 "=== ALL_PASS ==="（全部通过）或 "=== SOME_FAIL ==="（存在失败）
#   2) 每个断言用独立变量名，禁止复用上游变量名（防作用域污染类 bug）
#   3) 关键逻辑必须正/负双路径都测（正向期望 PASS + 负向期望 FAIL 都断言）
#
# 用法：bash run_verify.sh verify_xxx.py      # exit 0 = 通过，2/3/4 = 分级失败
# =============================================================================
set -euo pipefail

SCRIPT="${1:-}"
[ -n "$SCRIPT" ] || { echo "run_verify: missing verify script path" >&2; exit 1; }
shift || true
[ -f "$SCRIPT" ] || { echo "run_verify: script not found: $SCRIPT" >&2; exit 1; }

# P1: 语法
if ! python3 -m py_compile "$SCRIPT" 2>/dev/null; then
  echo "P1_SYNTAX_FAIL: py_compile failed for $SCRIPT" >&2
  exit 2
fi

# P2: 执行（捕获完整输出，含脚本自身 stderr）
RC=0
OUTPUT="$(python3 "$SCRIPT" "$@" 2>&1)" || RC=$?
if [ "$RC" -ne 0 ]; then
  echo "P2_RUN_FAIL: exit=$RC" >&2
  echo "----- verify output -----" >&2
  echo "$OUTPUT" >&2
  echo "-------------------------" >&2
  exit 3
fi

# P3: 机器断言 — 只有明确的 ALL_PASS 哨兵才算通过
if ! echo "$OUTPUT" | rg -q '=== ALL_PASS ==='; then
  echo "P3_ASSERT_FAIL: output missing '=== ALL_PASS ===' (script may have false-passed or missed assertions)" >&2
  echo "----- verify output -----" >&2
  echo "$OUTPUT" >&2
  echo "-------------------------" >&2
  echo "P4_CROSSCHECK_HINT: FAIL 时先怀疑验证脚本自身（变量复用/断言缺失），换一种方法验证同一结论再改生产代码" >&2
  exit 4
fi

echo "$OUTPUT"
echo "=== VERIFY_PASS ==="

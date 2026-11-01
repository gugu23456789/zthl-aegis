#!/bin/bash
# py_resolve.sh — **解释器解析单一事实源**（2026-11-01，替代 CLI 里的 /opt/... 硬编码）。
#
# 用法：bash scripts/py_resolve.sh [any|pytest]
#   输出：选中的解释器路径（stdout，单行）；无可用候选 ⟹ exit 1（调用方自行回落并**留痕**）。
#
# 为什么单独成脚本：解释器是**机器属性**，不能进公开源码。顺序（全部是**发现式**，无绝对硬编码）：
#   1. `GK_PYTHON`        —— 通用显式覆盖（CI / 本机 / 跨 OS 都走这里）
#   2. `SUAGENT_PYTHON`   —— 既有子代理键（向后兼容）
#   3. `ACCEPT_PY`        —— 既有验收键（向后兼容）
#   4. `scripts/_accept_py.local` —— **本机私有** pin（gitignore）；一行路径
#   5. 仓内 `.venv`（POSIX `bin/python*` / Windows `Scripts/python.exe`）
#   6. `GK_PY_GLOBS` 通配（缺省 `/opt/*/bin/python`；`:` 分隔多组）—— 发现式，缺省不存在即跳过
#   7. `scripts/suagent_py311.sh`（仓内包装器）
#   8. `python3` / `python`（PATH）
#
# 需求门：
#   · `any`    = 能执行 `-c 'import sys'`；
#   · `subagent` = 额外要求 `-c 'import openai, agents, pydantic'`（子代理真实依赖；
#     2026-11-01 owner 裁定 B 方案：子代理与 gitnexus 同侧，避免 Linux 解释器 spawn
#     Windows 原生包 ⟹ invalid ELF ⟹ 空壳报告）；
#   · `pytest` = 额外要求 `-c 'import pytest'`（自检测试腿用）。都不满足时**回落**到第一个
#     `any` 可用者（让 check_tests 显式 SKIP 并给出原因，而不是解析失败炸掉）。
#     `subagent` **不回落**：依赖不全即 exit 1，由调用方 fail-closed。
set -uo pipefail

_need="${1:-any}"
# 根目录：只用内建（`dirname` 是外部命令；本脚本可能在 **PATH 受限** 环境被调用/被测）
_self="${BASH_SOURCE[0]}"
case "$_self" in */*) _dir="${_self%/*}" ;; *) _dir="." ;; esac
_root="$(cd "$_dir/.." && pwd)"
_cands=()

_add() { [ -n "${1:-}" ] && _cands+=("$1"); }

_add "${GK_PYTHON:-}"
_add "${SUAGENT_PYTHON:-}"
_add "${ACCEPT_PY:-}"
if [ -f "$_root/scripts/_accept_py.local" ]; then
  _add "$(head -1 "$_root/scripts/_accept_py.local" | tr -d '\r')"
fi
# 仓内 venv 变体（`.venv` / `.venv-accept` / `.venv-*`）：POSIX `bin/` 与 Windows `Scripts/`
#   两种布局都发现。2026-11-01：原只看 `.venv` ⟹ Windows 侧 `.venv-accept` 永不被选中，
#   子代理只能落到 WSL 解释器（混血根源之一）。
for _v in "$_root/.venv" "$_root"/.venv-*; do
  [ -d "$_v" ] || continue
  for _p in "$_v/bin/python" "$_v/bin/python3" "$_v/Scripts/python.exe"; do
    _add "$_p"
  done
done
# 通配发现（缺省 /opt/*/bin/python；多组用 ':' 分隔）
_globs="${GK_PY_GLOBS-/opt/*/bin/python}"   # `-`（非 `:-`）：显式置空 = 关闭通配发现
_oldifs="$IFS"; IFS=':'
for _g in $_globs; do
  IFS="$_oldifs"
  for _p in $_g; do [ -x "$_p" ] && _cands+=("$_p"); done
  IFS=':'
done
IFS="$_oldifs"
_add "$_root/scripts/suagent_py311.sh"
_add "$(command -v python3 2>/dev/null || true)"
_add "$(command -v python 2>/dev/null || true)"

_ok_any()    { [ -x "$1" ] && "$1" -c 'import sys' >/dev/null 2>&1; }
_ok_pytest() { _ok_any "$1" && "$1" -c 'import pytest' >/dev/null 2>&1; }
_ok_subagent() { _ok_any "$1" && "$1" -c 'import openai, agents, pydantic' >/dev/null 2>&1; }

_first_any=""
for _c in "${_cands[@]}"; do
  _ok_any "$_c" || continue
  [ -z "$_first_any" ] && _first_any="$_c"
  case "$_need" in
    pytest)   if _ok_pytest "$_c"; then printf '%s' "$_c"; exit 0; fi ;;
    subagent) if _ok_subagent "$_c"; then printf '%s' "$_c"; exit 0; fi ;;
    *)        printf '%s' "$_c"; exit 0 ;;
  esac
done
if [ "$_need" = "pytest" ] && [ -n "$_first_any" ]; then
  printf '%s' "$_first_any"      # 回落：调用方据 `import pytest` 失败显式 SKIP
  exit 0
fi
exit 1

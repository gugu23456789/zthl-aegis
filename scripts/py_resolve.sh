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
#   6. `GK_PY_GLOBS` 通配（缺省 `/opt/*/bin/python`；多组分隔符 POSIX=`:`、Windows=`;`）—— 发现式，缺省不存在即跳过
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
# 平台覆盖（可选第 2 参）：`win` / `wsl`。**必须可显式给** —— 因为「当前 bash 的 uname」
#   与「调用方所在平台」会不一致：Windows python 的 `subprocess(["bash"])` 在本机命中的是
#   System32 的 WSL 启动器，`uname -s`=Linux ⟹ 自动探测会把**Windows 调用方**判成 wsl
#   ⟹ 挑到 `/opt/...`（Windows 上不存在）。由调用方（`gk_accept_py`，按 `os.name`）显式声明。
_plat_ov="${2:-}"
# 平台判定**前置**（glob 默认值也要按平台收口，不能等 pin 块里才判）
_plat="${_plat_ov:-}"
if [ -z "$_plat" ]; then
  _plat="wsl"
  # 先看 bash 自带 `OSTYPE`：`uname` 是外部命令，PATH 受限时可能根本不在
  # （2026-11-02 Windows CI 实测：PATH 被清空 ⟹ uname 取不到 ⟹ 误判 wsl ⟹
  #  用 ':' 切 Windows 盘符路径，glob 候选被切碎丢失）。
  case "${OSTYPE:-}" in
    msys*|cygwin*|win32*) _plat="win" ;;
    *) case "$(uname -s 2>/dev/null)" in
         MINGW*|MSYS*|CYGWIN*) _plat="win" ;;
       esac ;;
  esac
fi
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
  # 2026-11-02（owner 裁定「Windows 也要能用」）：本机 pin 支持**按平台标记**，不再是单行裸路径。
  #   格式（一行一条，`#` 注释可留）：
  #     win:  C:/…/.venv-accept/Scripts/python.exe     ← Windows（Git Bash / MSYS）
  #     wsl:  /opt/spz-py312/bin/python                ← WSL / Linux
  #     或一条**不带标记**的裸路径 = 通吃（向后兼容旧文件）
  #   为什么必须分平台：原来只有一行 `head -1` ⟹ Windows 上读到 WSL 路径直接返回 ⟹
  #   `_accept_cli.sh` 拿一个不存在的解释器跑 pytest（失败方向还伪装成"环境性红"）。
  #   ⚠ 仍是**本机私有配置**（gitignore），不写死任何路径进仓库。
  _plat="${_plat_ov:-}"
  if [ -z "$_plat" ]; then
    _plat="wsl"
    case "${OSTYPE:-}" in
      msys*|cygwin*|win32*) _plat="win" ;;
      *) case "$(uname -s 2>/dev/null)" in
           MINGW*|MSYS*|CYGWIN*) _plat="win" ;;
         esac ;;
    esac
  fi
  while IFS= read -r _line || [ -n "$_line" ]; do
    _line="${_line%$'\r'}"
    case "$_line" in ''|\#*) continue ;; esac
    case "$_line" in
      win:*|msys:*|wsl:*|linux:*)
        _tag="${_line%%:*}"
        _pv="${_line#*:}"
        # 去前导空格（`win: C:/…` 这种写法很自然；带空格会让 `-x` 判假 ⟹ 候选被静默跳过）
        while :; do case "$_pv" in ' '*) _pv="${_pv# }" ;; *) break ;; esac; done
        case "$_tag" in
          win|msys) [ "$_plat" = "win" ] && _add "$_pv" ;;
          *)        [ "$_plat" = "wsl" ] && _add "$_pv" ;;
        esac ;;
      *) _add "$_line" ;;                     # 旧格式：无标记 = 通吃
    esac
  done < "$_root/scripts/_accept_py.local"
fi
# 仓内 venv 变体（`.venv` / `.venv-accept` / `.venv-*`）：POSIX `bin/` 与 Windows `Scripts/`
#   两种布局都发现。2026-11-01：原只看 `.venv` ⟹ Windows 侧 `.venv-accept` 永不被选中，
#   子代理只能落到 WSL 解释器（混血根源之一）。
# 2026-11-02：**worktree 场景补主树回落**。`.venv*` 在 gitignore 里 ⟹ 不随 worktree 派生 ⟹
#   在 worktree 里只看 `$_root` 会一个都找不到，直接掉到 PATH 的任意 python3（本机实测：
#   掉到 WorkBuddy 的 3.13，缺 cryptography ⟹ 签名崩 ⟹ 被上层报成「上下文过期」）。
#   根 = git `--git-common-dir` 反推主树（worktree 的 `.git` 是文件，公共目录在主树）。
_roots="$_root"
_gcd=$(git -C "$_root" rev-parse --git-common-dir 2>/dev/null || true)
if [ -n "$_gcd" ]; then
  case "$_gcd" in /*) : ;; *) _gcd="$_root/$_gcd" ;; esac
  _mr=$(cd "$(dirname "$_gcd")" 2>/dev/null && pwd) || _mr=""
  if [ -n "$_mr" ] && [ "$_mr" != "$_root" ]; then _roots="$_root
$_mr"; fi
fi
_oldifs_v="$IFS"; IFS='
'
for _rt in $_roots; do
  for _v in "$_rt/.venv" "$_rt"/.venv-*; do
    [ -d "$_v" ] || continue
    for _p in "$_v/bin/python" "$_v/bin/python3" "$_v/Scripts/python.exe"; do
      _add "$_p"
    done
  done
done
IFS="$_oldifs_v"
# 通配发现（缺省 /opt/*/bin/python；多组分隔符 POSIX=':' / Windows=';'）
# 通配发现：**只在 POSIX 侧**用 `/opt/*` 缺省（那是 WSL 时代的产物）；Windows 侧默认**不启用**
#   —— 否则在 WSL bash 下 `/opt/*/bin/python` 会匹配到**与本仓无关**的 `/opt/entropygs/bin/python`
#   之类，把解释器解析到无关虚拟环境（2026-11-02 实测踩到）。`GK_PY_GLOBS` 仍可显式开启。
if [ "$_plat" = "win" ]; then
  _globs="${GK_PY_GLOBS-}"                  # 默认空；显式设了才用
  # Windows 用 `;` 分隔多组：盘符里的 `:` 会被当成分隔符（2026-11-02 CI 实测：
  #   `C:\Users\…\py-good` 被切成 "C" 与 "\Users\…" 两段 ⟹ 候选丢失/串味）。
  _glob_sep=';'
else
  _globs="${GK_PY_GLOBS-/opt/*/bin/python}" # `-`（非 `:-`）：显式置空 = 关闭通配发现
  _glob_sep=':'
fi
_oldifs="$IFS"; IFS="$_glob_sep"
for _g in $_globs; do
  IFS="$_oldifs"
  for _p in $_g; do [ -x "$_p" ] && _cands+=("$_p"); done
  IFS="$_glob_sep"
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

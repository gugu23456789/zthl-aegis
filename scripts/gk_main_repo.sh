#!/usr/bin/env bash
# 主仓路径运行时解析（bash 侧薄壳；单源 = scripts/gk_main_repo.py）。
# 由 gatekeeper-cli.sh 在 STATE_FILE 确定后调用 `_main_repo_resolve`。
# 解析失败 ⟹ 保持空串（依赖主仓的检查 fail-closed）。

_main_repo_resolve() {
  [ -n "${MAIN_REPO_WSL:-}" ] && return 0
  MAIN_REPO_WSL=""; MAIN_REPO_WIN=""   # set -u 下先占位（python 失败 ⟹ 保持空 = fail-closed）
  local _sd
  _sd="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)"
  [ -n "$_sd" ] && [ -f "$_sd/scripts/gk_main_repo.py" ] || return 0
  {
    IFS= read -r MAIN_REPO_WSL
    IFS= read -r MAIN_REPO_WIN
  } < <(STATE_FILE="${STATE_FILE:-}" GK_WORKTREE_CWD="${GK_WORKTREE_CWD:-$PWD}" \
        python3 "$_sd/scripts/gk_main_repo.py" --print-lines 2>/dev/null)
  _MAIN_REPO_WIN_RE="$(printf '%s' "$MAIN_REPO_WIN" | sed 's#/#[\\\\/]#g')"
  _MAIN_REPO_WSL_RE="$(printf '%s' "$MAIN_REPO_WSL" | sed 's#/#[\\\\/]#g')"
  return 0
}

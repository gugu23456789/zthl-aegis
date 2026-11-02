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
  # 2026-11-01（跨平台 ①D 修复 · **CRLF 泄漏根源**）：**剥 CR**。
  #   python 在 Windows 下 stdout 为 **text mode** ⟹ 行尾是 `\r\n`；
  #   bash 的 `read -r` 只剥 `\n`，**不剥 `\r`** ⟹ 读到的值尾带**裸 CR**。
  #   该值随后被拼进 state JSON（gatekeeper-cli.sh 的 state 重建段）⟹
  #   `json.loads` 抛 **`Invalid control character`** ⟹ **整份 state 不可读**
  #   ⟹ 所有读点 `{"error":"json_decode_error"}` ⟹ plan-refinement 入队后 57s 处全线中断。
  #   实测现场：域 state 的 `main_repo` 字段值 = `'\r'`（单个裸 CR，字节 152）。
  #   ⚠ 报错只说"解码失败"，真因是"读入时没剥 \r" —— 真因被伪装（同 真因 A/B 的病征模式）。
  MAIN_REPO_WSL="${MAIN_REPO_WSL//$'\r'/}"
  MAIN_REPO_WIN="${MAIN_REPO_WIN//$'\r'/}"
  _MAIN_REPO_WIN_RE="$(printf '%s' "$MAIN_REPO_WIN" | sed 's#/#[\\\\/]#g')"
  _MAIN_REPO_WSL_RE="$(printf '%s' "$MAIN_REPO_WSL" | sed 's#/#[\\\\/]#g')"
  return 0
}

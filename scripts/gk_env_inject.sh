#!/bin/bash
# gk_env_inject.sh — WSL 侧 API key 环境注入（2026-08-09）
# =============================================================================
# 等价于 wslsh.ps1 的 WSLENV 注入（wslsh 只覆盖走 wslsh 的入口）：
# 任何非 wslsh 入口（hook 直调 wsl / Windows 计划任务 / WSL 终端直跑 / 独立脚本）
# 启动的 WSL 进程，若环境缺 key，从 Windows 注册表拉取并 export 到当前 shell。
# 优先级: 进程环境已有 → 不动；否则注册表 User → Process。
# 用法: source gk_env_inject.sh && _gk_env_inject   （幂等，无副作用）
# =============================================================================

_gk_env_inject() {
  [ -n "${DEEPSEEK_API_KEY:-}" ] && [ -n "${MIMO_API_KEY:-}" ] && return 0

  local _ps_exe=""
  if [ -x "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe" ]; then
    _ps_exe="/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
  elif command -v powershell.exe >/dev/null 2>&1; then
    _ps_exe="powershell.exe"
  fi
  [ -z "$_ps_exe" ] && return 1

  if [ -z "${DEEPSEEK_API_KEY:-}" ]; then
    DEEPSEEK_API_KEY=$("$_ps_exe" -NoProfile -Command '[System.Environment]::GetEnvironmentVariable("DEEPSEEK_API_KEY","User")' 2>/dev/null | tr -d '\r\n ')
    [ -n "$DEEPSEEK_API_KEY" ] && export DEEPSEEK_API_KEY
  fi
  if [ -z "${MIMO_API_KEY:-}" ]; then
    MIMO_API_KEY=$("$_ps_exe" -NoProfile -Command '[System.Environment]::GetEnvironmentVariable("MIMO_API_KEY","User")' 2>/dev/null | tr -d '\r\n ')
    [ -n "$MIMO_API_KEY" ] && export MIMO_API_KEY
  fi
  return 0
}

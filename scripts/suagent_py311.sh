#!/bin/bash
# suagent_py311.sh — subagent 运行环境 launcher：把 /mnt/* 参数转 Windows 形态后 exec python311。
# 2026-09-08 F-REV-1 (ECC-8A07DDAD64ED): python311 装 openai-agents==0.22.0 + openai 3.x，
#   实测 DeepSeek tool_calls 往返正常（turns=2 真实工具执行）；venv 0.17.6 触发 400
#   "insufficient tool messages following tool_calls" 请求体缺陷。subagent 默认环境 = 本 launcher。
# SUAGENT_PYTHON 显式设置时 CLI 优先使用显式值（跳过本 launcher）。
args=()
for a in "$@"; do
  case "$a" in
    /mnt/*) args+=("$(wslpath -w "$a" 2>/dev/null || echo "$a")") ;;
    *) args+=("$a") ;;
  esac
done
# Windows Python 解释器（不写死用户名）：GK_WIN_PYTHON 显式胜，否则按 WSL $USER 推导
PY="${GK_WIN_PYTHON:-/mnt/c/Users/${USER:-$USERNAME}/AppData/Local/Programs/Python/Python311/python.exe}"
exec "$PY" "${args[@]}"

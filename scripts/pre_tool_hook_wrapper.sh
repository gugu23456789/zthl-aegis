#!/bin/bash
# pre_tool_hook_wrapper.sh — WSL 侧 wrapper：让 hook 载荷不经过 PowerShell 解析
# （PS 宿主会展开双引号内 `$`/反引号；PS 5.1 另有 native arg mangling，7.3+ 已修）
# =============================================================================
# Trae hook command 通过 `wsl bash <this>` 调用（hooks.json 全局 catch-all 单入口），
# 避免 `wsl bash -c 'python3 ...'` 在 PowerShell 中的引号被剥离导致 hook 失效。
# stdin JSON 由 wsl 原样透传（不经过 PS 解析）。
# 2026-08-07: light hook（pre_tool_hook_light.sh）已删除 — 只读工具全量走本 python
# 门禁；后续提速方案为常驻 python 服务（一次启动、IPC 复用），替代进程级冷启动。
# 2026-08-09: hook 入口环境注入 — 非 wslsh 启动的 hook 调用同样拿到 API key
# （等价于 wslsh WSLENV 注入的 WSL 侧兜底；hook 当前无 API 需求，为一致性预留）。
source "$(dirname "$0")/gk_env_inject.sh" 2>/dev/null && _gk_env_inject >/dev/null 2>&1
# 解释器单源 = py_resolve.sh（2026-11-01）：不再写死 `python3` —— 开源用户机器上的
# python3 可能缺依赖，解析失败才回落到 GK_PYTHON / python3。
_PY="$(bash "$(dirname "$0")/py_resolve.sh" any 2>/dev/null || true)"
[ -n "$_PY" ] || _PY="${GK_PYTHON:-python3}"
exec "$_PY" "$(dirname "$0")/pre_tool_hook.py"

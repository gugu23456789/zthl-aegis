#!/usr/bin/env bash
# suagent_sandbox.sh — subagent 沙箱包裹器（A 接线 2026-10-16；模式化 2026-11-01）。
#
# 由 `gatekeeper-cli.sh` 的 `_subagent_exec` 调用（单源覆盖全部 runner 调用点）：
#   <本脚本> <subagent_runner.py> <runner 参数...>
#
# 模式（GK_SANDBOX_MODE）：
#   limits（默认）  `gk_sandbox.py run` 限额：mem / 墙钟 / 进程数（**资源限额，非安全边界**）
#   bwrap           只读根 + 可写 worktree/状态 + 私有 /tmp（FS 隔离；网络默认放开，
#                   因为质询/审查需要 LLM API 与网页抓取；GK_SANDBOX_NET=deny 才断网）
#   不可用          fail-loud（exit 2），**不**静默回退；仅 GK_SANDBOX_FAIL_OPEN=1 显式降级
#
# 环境：
#   GK_SANDBOX_SUBAGENT=0 总开关关闭（由 gatekeeper-cli.sh 判定，本脚本不再兜底）
#   GK_SANDBOX_MEM_MB / TIMEOUT_S / MAX_PROC   limits 模式参数
#   GK_SANDBOX_MODE=limits|bwrap              模式选择
#   GK_SANDBOX_NET=allow|deny                 bwrap 模式网络（默认 allow）
set -u
_skill="$(cd "$(dirname "$0")/.." && pwd)"
# 2026-11-01：去硬编码 —— 缺省不再写死某个 venv 绝对路径（公开包在他机必不存在）。
_py="${GK_SUBAGENT_PY_REAL:-$(bash "$_skill/scripts/py_resolve.sh" any 2>/dev/null || echo python3)}"
_mode="${GK_SANDBOX_MODE:-limits}"

case "$_mode" in
  limits)
    exec "$_py" "$_skill/scripts/gk_sandbox.py" run \
      --mem-mb "${GK_SANDBOX_MEM_MB:-2048}" \
      ${GK_SANDBOX_TIMEOUT_S:+--timeout "$GK_SANDBOX_TIMEOUT_S"} \
      ${GK_SANDBOX_MAX_PROC:+--max-proc "$GK_SANDBOX_MAX_PROC"} \
      ${GK_SANDBOX_FAIL_OPEN:+--no-fail-closed} \
      -- "$_py" "$@"
    ;;
  bwrap)
    if ! command -v bwrap >/dev/null 2>&1; then
      if [ "${GK_SANDBOX_FAIL_OPEN:-0}" = "1" ]; then
        echo "WARN[sandbox] bwrap 未安装 → limits 降级（GK_SANDBOX_FAIL_OPEN=1）" >&2
        exec "$_py" "$_skill/scripts/gk_sandbox.py" run \
          --mem-mb "${GK_SANDBOX_MEM_MB:-2048}" --no-fail-closed -- "$_py" "$@"
      fi
      echo '{"ok":false,"error":"SANDBOX_MODE_UNAVAILABLE","mode":"bwrap","hint":"未安装 bubblewrap（本仓不自动安装）；安装后重试，或 GK_SANDBOX_MODE=limits"}' >&2
      exit 2
    fi
    _net="--share-net"
    [ "${GK_SANDBOX_NET:-allow}" = "deny" ] && _net="--unshare-net"
    _home="${HOME:-/root}"
    exec bwrap --die-with-parent --new-session \
      --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
      --bind "$_skill" "$_skill" \
      --ro-bind "$_home" "$_home" \
      --bind-try "$_home/.gatekeeper" "$_home/.gatekeeper" \
      --bind-try "$_home/.gatekeeper.state" "$_home/.gatekeeper.state" \
      --bind-try "$_home/.gitconfig" "$_home/.gitconfig" \
      "$_net" -- "$_py" "$@"
    ;;
  *)
    echo "{\"ok\":false,\"error\":\"SANDBOX_MODE_UNKNOWN\",\"mode\":\"$_mode\",\"hint\":\"合法值: limits|bwrap\"}" >&2
    exit 2
    ;;
esac

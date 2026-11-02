#!/bin/bash
# _push_auth_url.sh — 构造「带凭据」的 git push URL（**纯函数**，无副作用）。
#
# 用法: _push_auth_url <raw_url> <token> [user]
#   ① raw 非 https://（ssh/scp 形态）⟹ **原样透传**（不注入凭据）
#   ② user 非空 ⟹ https://<user>:<token>@<host>/<path>（Gitee/atomgit 系需 user:token）
#   ③ user 为空 ⟹ https://<token>@<host>/<path>（GitHub 系 token-as-username 兼容形态）
#
# 背景（2026-09-28 实测）：gatekeeper-cli.sh 的 cmd_push confirm 原实现**恒**用 token-only 形态，
#   对 atomgit 报 `fatal: could not read Password for 'https://<token>@atomgit.com'`
#   （token 被当成用户名、缺密码）⟹ 直推失败；实测 `https://<user>:<token>@atomgit.com/...` rc=0。
#   故把构造抽为**可单测**的纯函数（测试见 scripts/test_gk_push_auth_url.py），消除「凭据里没用户」缺陷。
_push_auth_url() {
  local raw="$1" token="$2" user="${3:-}"
  case "$raw" in
    https://*) ;;
    *) printf '%s\n' "$raw"; return 0 ;;
  esac
  local rest="${raw#https://}"
  if [ -n "$user" ]; then
    printf 'https://%s:%s@%s\n' "$user" "$token" "$rest"
  else
    printf 'https://%s@%s\n' "$token" "$rest"
  fi
}

# 直接执行（非 source）时按参数运行 —— 供单测 / 命令行复用
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  _push_auth_url "$@"
fi

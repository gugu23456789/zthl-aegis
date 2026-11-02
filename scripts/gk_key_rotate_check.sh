#!/usr/bin/env bash
# Gatekeeper key rotation check — cron no_agent 作业 (2026-08-21 轮转盲区兜底层)
# =================================================================================
# 背景: 轮转盲区 — 原设计过期检测只挂在 cmd_advance，长期不 advance 则错过过期检测
# (context=1d / audit=30d)。CLI 启动级检查 (_key_rotate_if_expired) 覆盖"用了 CLI"的场景；
# 本脚本覆盖"CLI 完全闲置"场景，由 cron 调度器 (cron_scheduler.py --once) 周期触发。
#
# 与 CLI 启动检查同逻辑，幂等: 仅 key-meta 存在且确有密钥过期时才 rotate；
# rotate 后再次调用无事发生。输出 JSON 供 tick.log / wake gate 记录。
#
# Usage: bash scripts/gk_key_rotate_check.sh
# Exit:  0 always (调度器容错)，错误信息进 stdout JSON。
set -u

# 解析 SKILL_DIR: 优先自身目录（scripts/ 上一级），WSL 下 /mnt/c/... 硬编码兜底
_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(dirname "$_SCRIPT_DIR")"
[ -f "$SKILL_DIR/gatekeeper-cli.sh" ] || SKILL_DIR="${HOME:-/root}/.trae/skills/spz-gatekeeper-r-sequence"

KEY_META="${SKILL_DIR}/.keys/key-meta.json"

[ -f "$KEY_META" ] || { echo '{"ok":true,"rotated":[],"reason":"no key-meta"}'; exit 0; }

_expired=$(python3 -c "
import json,datetime
try:
    meta=json.load(open('$KEY_META'))
except Exception:
    print(''); raise SystemExit
now=datetime.datetime.utcnow()
out=[]
for ktype,info in meta.items():
    exp=info.get('expires','')
    if exp:
        try:
            exp_dt=datetime.datetime.fromisoformat(exp.replace('Z',''))
            if now>exp_dt: out.append(ktype)
        except: pass
print(' '.join(out))
" 2>/dev/null)

if [ -z "$_expired" ]; then
  echo '{"ok":true,"rotated":[],"reason":"nothing expired"}'
  exit 0
fi

_rotated=""
for _k in $_expired; do
  _r=$(bash "$SKILL_DIR/gatekeeper-cli.sh" audit --key rotate "$_k" auto 2>/dev/null || true)
  _rotated="${_rotated} ${_k}:${_r}"
done

echo "{\"ok\":true,\"rotated\":\"${_rotated}\"}"
exit 0

#!/usr/bin/env bash
# uninstall.sh — 按 manifest 精确删除 gatekeeper 安装
# 用法: bash uninstall.sh [目标项目路径] [--dest <安装目录>] [--yes] [--force-legacy]
#   未指定路径时从当前目录的 .trae/skills/spz-gatekeeper-r-sequence/ 删除
#   `--dest` 与 install.sh 的 --dest 对称（装到 ~/.claude/skills/<名> 等宿主无关落点也能卸）
#   只删除 .spz-manifest 中记录的文件（v2 只含安装器自己写入的文件），不误删用户文件
#   旧版 manifest（无 manifest-version: 2）可能收录了用户文件 ⟹ 默认拒删，需 --force-legacy
#   `--yes` 跳过交互确认（CI / 自动化用）
#   用户级 `~/.gatekeeper/cron` 与 cron 进程：只报告，不自动删除/杀进程

set -euo pipefail

TARGET="."
DEST_OVERRIDE=""
YES=0
FORCE_LEGACY=0
SKILL_NAME="spz-gatekeeper-r-sequence"

while [ $# -gt 0 ]; do
  case "$1" in
    --dest) DEST_OVERRIDE="${2:-}"; shift 2 ;;
    --yes|-y) YES=1; shift ;;
    --force-legacy) FORCE_LEGACY=1; shift ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) TARGET="$1"; shift ;;
  esac
done

if [ -n "$DEST_OVERRIDE" ]; then
  DEST="$DEST_OVERRIDE"
elif [ -n "${TRAE_ENV:-}" ] && [ "$TRAE_ENV" = "cn" ]; then
  DEST="${TARGET}/.trae-cn/skills/${SKILL_NAME}"
elif [ -d "${TARGET}/.trae-cn/skills/${SKILL_NAME}" ] && [ ! -d "${TARGET}/.trae/skills/${SKILL_NAME}" ]; then
  DEST="${TARGET}/.trae-cn/skills/${SKILL_NAME}"
else
  DEST="${TARGET}/.trae/skills/${SKILL_NAME}"
fi
MANIFEST="${DEST}/.spz-manifest"

# ─── 前置检查 ───
if [ ! -d "$DEST" ]; then
  echo "ERROR: not found: $DEST" >&2
  echo "  提示：非默认落点请用 --dest <安装目录>" >&2
  exit 1
fi
# 归一为绝对路径（下面的 cron 进程精确匹配依赖它）
DEST="$(cd "$DEST" && pwd)"
MANIFEST="${DEST}/.spz-manifest"

if [ ! -f "$MANIFEST" ]; then
  echo "ERROR: manifest not found: $MANIFEST" >&2
  echo "  Cannot safely uninstall without manifest. Remove manually:" >&2
  echo "    rm -rf $DEST" >&2
  exit 1
fi

# ─── manifest 版本门（v1 可能收录了目录内的用户文件 ⟹ 防误删）───
MANIFEST_VERSION="$(sed -n 's/^# manifest-version:[[:space:]]*//p' "$MANIFEST" | head -1)"
if [ "${MANIFEST_VERSION:-}" != "2" ]; then
  echo "WARN: 旧版 manifest（无 manifest-version: 2）——它可能收录了非本仓文件。" >&2
  if [ "$FORCE_LEGACY" != "1" ]; then
    echo "  为防止误删用户文件，已停止。核对清单后再加 --force-legacy 重跑。" >&2
    exit 2
  fi
  echo "  --force-legacy 已给出：继续按清单删除。" >&2
fi

# ─── 读取 manifest 并预演 ───
echo "Uninstalling gatekeeper from ${DEST}..."
removed=0

# ─── 路径遍历保护 (ECC is_valid_manifest_entry) ───
is_valid_entry() {
  local entry="$1"
  case "$entry" in
    ""|/*|~*|*/../*|../*|*/..|..) return 1 ;;
  esac
  return 0
}

echo "Files to remove:"
while IFS= read -r relpath; do
  [ -z "$relpath" ] && continue
  [[ "$relpath" =~ ^# ]] && continue
  if ! is_valid_entry "$relpath"; then
    echo "  SKIP (invalid): $relpath"
    continue
  fi
  full="${DEST}/${relpath}"
  if [ -f "$full" ]; then
    echo "  $relpath"
  fi
done < "$MANIFEST"

if [ "$YES" != "1" ]; then
  read -p "Uninstall gatekeeper from ${DEST}? (y/N) " -n 1 -r
  echo
  [[ ! $REPLY =~ ^[Yy]$ ]] && { echo "Cancelled."; exit 0; }
fi

# ─── 先摘钩子条目（可逆效应；只摘本仓条目，用户条目逐字保留）───
if [ -f "$DEST/scripts/gk_hook_manage.py" ]; then
  HOOK_ARGS=(uninstall --skill-dir "$DEST")
  if [ -n "${GK_HOOKS_JSON:-}" ]; then HOOK_ARGS+=(--hooks "$GK_HOOKS_JSON"); fi
  python3 "$DEST/scripts/gk_hook_manage.py" "${HOOK_ARGS[@]}" || {
    echo "  WARN: 钩子条目未清理（rc=$?）—— 请手工检查用户级 hooks.json（脚本随后继续删文件）" >&2
  }
else
  echo "  WARN: 缺 scripts/gk_hook_manage.py ⟹ 无法自动摘钩子条目，请手工检查 hooks.json" >&2
fi

# ─── cron：只报告，不杀进程、不删用户级目录 ───
CRON_PID=$(pgrep -f "${DEST}/scripts/cron_scheduler.py" 2>/dev/null || true)
if [ -n "$CRON_PID" ]; then
  echo "  NOTE: 本安装的 cron 调度器仍在运行（PID: $CRON_PID）"
  echo "        停止：kill $CRON_PID"
fi
CRON_DIR="$HOME/.gatekeeper/cron"
if [ -d "$CRON_DIR" ]; then
  echo "  NOTE: 未删除用户级任务目录 $CRON_DIR（可能被多个安装共用）"
  echo "        确认无用后手动清理：rm -rf \"$CRON_DIR\""
fi

while IFS= read -r relpath; do
  [ -z "$relpath" ] && continue
  [[ "$relpath" =~ ^# ]] && continue
  is_valid_entry "$relpath" || continue
  full="${DEST}/${relpath}"
  if [ -f "$full" ]; then
    rm -f "$full"
    removed=$((removed + 1))
  fi
done < "$MANIFEST"

# manifest 自身不在清单里 ⟹ 单独删（否则目录永远非空）
rm -f "$MANIFEST"

# ─── 清理空目录（从深到浅） ───
find "$DEST" -type d -empty -delete 2>/dev/null || true

# ─── 如果整个目录空了，删掉 ───
if [ -d "$DEST" ] && [ -z "$(ls -A "$DEST")" ]; then
  rmdir "$DEST"
  echo "  Removed empty directory: ${DEST}"
fi

echo ""
echo "Done. Removed $removed files."

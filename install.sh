#!/usr/bin/env bash
# install.sh — 非破坏性安装 ZTHL Aegis（技能目录名 spz-gatekeeper-r-sequence）
# 用法: bash install.sh [目标项目路径] [--dest <绝对/相对目录>] [--no-hooks]
#                        [--hook-profile safe|full|off] [--force]
#   未指定路径时安装到当前目录；默认落点 = <目标>/.trae/skills/<skill 名>
#   `--dest` = **宿主无关**落点（任意 agent 运行时的技能目录，如 ~/.claude/skills/<名>）；
#     给出即覆盖默认落点，且**不注册 Trae 钩子**（钩子只在 .trae/.trae-cn 落点有意义）
#   已存在的文件**默认不覆盖**（保护用户自定义）；内容不同 ⟹ 报 conflict 并跳过，
#     确认要覆盖时加 `--force`（覆盖前留 `.bak-<UTC>` 时间戳备份）
#   安装后写 .spz-manifest（v2：**只记录本次实际写入的文件**，卸载据此精确删除）
#   默认按**加载安全网**把 PreToolUse 钩子注册到用户级 hooks.json（非破坏合并 +
#   备份 + 回读校验，只摘/加本仓条目）；--no-hooks 跳过；--hook-profile off 摘掉旧条目

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET="."
WITH_HOOKS=1
HOOK_PROFILE="safe"
DEST_OVERRIDE=""
FORCE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --no-hooks) WITH_HOOKS=0; shift ;;
    --hook-profile) HOOK_PROFILE="${2:-safe}"; shift 2 ;;
    --dest) DEST_OVERRIDE="${2:-}"; shift 2 ;;
    --force) FORCE=1; shift ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) TARGET="$1"; shift ;;
  esac
done

SKILL_NAME="spz-gatekeeper-r-sequence"

# .trae-cn 支持 (ECC get_trae_dir pattern)
get_trae_dir() {
    if [ "${TRAE_ENV:-}" = "cn" ]; then
        echo ".trae-cn"
    else
        echo ".trae"
    fi
}
TRAE_DIR="$(get_trae_dir)"
if [ -n "$DEST_OVERRIDE" ]; then
    DEST="$DEST_OVERRIDE"
    WITH_HOOKS=0   # 宿主无关落点无 Trae 钩子语义 ⟹ 显式不注册（不静默写别处 hooks.json）
else
    DEST="${TARGET}/${TRAE_DIR}/skills/${SKILL_NAME}"
fi
MANIFEST="${DEST}/.spz-manifest"

# ─── 前置检查 ───
if [ ! -d "$SCRIPT_DIR" ]; then
  echo "ERROR: source not found: $SCRIPT_DIR" >&2; exit 1
fi
if [ ! -f "$SCRIPT_DIR/gatekeeper-cli.sh" ]; then
  echo "ERROR: gatekeeper-cli.sh not found in $SCRIPT_DIR" >&2; exit 1
fi

# ─── 创建目标目录 ───
mkdir -p "$DEST"

# ─── 复制文件（非破坏性：默认不覆盖；--force 才覆盖并留时间戳备份） ───
copied=0
updated=0
skipped=0
conflicts=0
WROTE=()

copy_managed() {
  local src="$1" dst="$2" rel bak
  rel="${dst#"$DEST"/}"
  if [ -f "$dst" ]; then
    if cmp -s "$src" "$dst"; then
      skipped=$((skipped + 1))
      return 0
    fi
    if [ "$FORCE" != "1" ]; then
      # 保护用户自定义：默认保留磁盘上的版本，只提示如何覆盖
      echo "  conflict (kept): $rel   [--force 覆盖并备份]"
      conflicts=$((conflicts + 1))
      return 0
    fi
    bak="${dst}.bak-$(date -u +%Y%m%dT%H%M%SZ)"
    cp -p "$dst" "$bak"
    cp -p "$src" "$dst"
    echo "  updated: $rel (backup: ${bak#"$DEST"/})"
    WROTE+=("$rel")
    updated=$((updated + 1))
    return 0
  fi
  cp -p "$src" "$dst"
  WROTE+=("$rel")
  copied=$((copied + 1))
}

echo "Installing gatekeeper to ${DEST}..."

# 递归复制目录（逐文件走 copy_managed，保持「默认不覆盖」语义）
copy_tree() {
  local src="$1" dst="$2" f rel
  [ -d "$src" ] || return 0
  while IFS= read -r -d '' f; do
    rel="${f#"$src"/}"
    mkdir -p "$dst/$(dirname "$rel")"
    copy_managed "$f" "$dst/$rel"
  done < <(find "$src" -type f -not -name '*.bak' -not -name '*.bak-*' -not -name '*.pyc' -print0)
}

# 核心文件
for f in gatekeeper-cli.sh AGENTS.md CLAUDE.md SKILL.md install.sh uninstall.sh; do
  [ -f "$SCRIPT_DIR/$f" ] && copy_managed "$SCRIPT_DIR/$f" "$DEST/$f"
done

# scripts/
mkdir -p "$DEST/scripts"
for f in "$SCRIPT_DIR"/scripts/*; do
  [ -f "$f" ] && copy_managed "$f" "$DEST/scripts/$(basename "$f")"
done

# references/（**含子目录**：agent-families 等；原 `[ -f ]` 过滤会把目录整体漏装 ⟹
#   `gk_agent_family` 找不到族定义，coder 档位静默降级。find 递归 + 逐文件 copy_managed）
copy_tree "$SCRIPT_DIR/references" "$DEST/references"

# monitor-schemas/
if [ -d "$SCRIPT_DIR/monitor-schemas" ]; then
  mkdir -p "$DEST/monitor-schemas"
  for f in "$SCRIPT_DIR"/monitor-schemas/*; do
    [ -f "$f" ] && copy_managed "$f" "$DEST/monitor-schemas/$(basename "$f")"
  done
fi

# assets/（运行资产：ECharts 离线渲染；缺它 MoA 报告会**静默**降级为 SVG ⟹ 必须装）
copy_tree "$SCRIPT_DIR/assets" "$DEST/assets"

# ─── Cron 调度器目录 ───
CRON_DIR="$HOME/.gatekeeper/cron"
mkdir -p "$CRON_DIR/output"
echo "  cron dir: $CRON_DIR"

# ─── 检查 croniter 依赖（**不自动安装**：装包属宿主决策，安装器只报缺）───
if ! python3 -c "import croniter" 2>/dev/null; then
  echo "  WARN: python3 缺 croniter ⟹ cron 调度不可用。由你决定安装（例如 pip install croniter）"
fi

# ─── 写 manifest（v2：只记本安装面文件；**并入旧清单**）───
# 2026-11-02 修：原实现只写「本次真正写入」的文件（WROTE）。重复安装时文件都相同 ⟹
#   WROTE 为空 ⟹ manifest 被覆盖成空清单 ⟹ uninstall 一个文件都删不掉（覆盖面丢失）。
#   现口径 = 本次写入 ∪ 旧 manifest 条目（只并 v2；旧版可能含用户文件，拒绝并入）。
PREV=()
if [ -f "$MANIFEST" ] && sed -n 's/^# manifest-version:[[:space:]]*//p' "$MANIFEST" | head -1 | grep -qx '2'; then
  while IFS= read -r _line; do
    case "$_line" in ''|'#'*) continue ;; esac
    PREV+=("$_line")
  done < "$MANIFEST"
fi
{
  echo "# spz-gatekeeper manifest — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# manifest-version: 2"
  echo "# source: $SCRIPT_DIR"
  if [ "${#WROTE[@]}" -gt 0 ]; then printf '%s\n' "${WROTE[@]}"; fi
  if [ "${#PREV[@]}" -gt 0 ]; then printf '%s\n' "${PREV[@]}"; fi
} | sed '/^$/d' | sort -u > "$MANIFEST.tmp"
# 保序：头部三行不被 sort 打散（sort 只作用于条目）
{
  echo "# spz-gatekeeper manifest — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# manifest-version: 2"
  echo "# source: $SCRIPT_DIR"
  grep -v '^#' "$MANIFEST.tmp" || true
} > "$MANIFEST"
rm -f "$MANIFEST.tmp"

# ─── 钩子注册（加载安全网：非破坏合并 + 备份 + 原子写 + 回读校验）───
HOOK_RC=0
if [ "$WITH_HOOKS" = "1" ]; then
  # 2026-11-04（用户：「插件的安装钩子需要自动化更新扩展」）：install → sync。
  # sync = 判漂移（覆盖面不足/命令漂移/超时漂移/重复/未登记）→ 有则改、无则零写入，
  # 使「升级 / 换机 / 改 profile 后重跑 install.sh」自动收敛，不再停在旧注册形态。
  HOOK_ARGS=(sync --skill-dir "$DEST" --profile "$HOOK_PROFILE")
  if [ -n "${GK_HOOKS_JSON:-}" ]; then HOOK_ARGS+=(--hooks "$GK_HOOKS_JSON"); fi
  HOOK_OUT=$(python3 "$DEST/scripts/gk_hook_manage.py" "${HOOK_ARGS[@]}" 2>&1) || HOOK_RC=$?
  echo "  hook: $HOOK_OUT"
  if [ "$HOOK_RC" -eq 0 ]; then
    HOOK_STATUS_ARGS=(status --skill-dir "$DEST" --profile "$HOOK_PROFILE")
    if [ -n "${GK_HOOKS_JSON:-}" ]; then HOOK_STATUS_ARGS+=(--hooks "$GK_HOOKS_JSON"); fi
    echo "  hook verify: $(python3 "$DEST/scripts/gk_hook_manage.py" "${HOOK_STATUS_ARGS[@]}" 2>&1 | tr '\n' ' ')"
  else
    echo "  WARN: 钩子未注册（rc=$HOOK_RC）—— 修好后重跑上面 install 命令；此状态下写入/执行类工具不受门禁保护"
  fi
else
  echo "  hook: skipped (--no-hooks)"
fi

# ─── 汇总 ───
echo ""
echo "Done. Installed to: ${DEST}"
echo "  copied:    $copied new files"
echo "  updated:   $updated overwritten files (--force)"
echo "  unchanged: $skipped files already identical"
echo "  conflicts: $conflicts files kept as-is (re-run with --force to overwrite)"
echo "  manifest:  $MANIFEST"
echo ""
echo "To uninstall: bash ${DEST}/uninstall.sh --dest ${DEST}"

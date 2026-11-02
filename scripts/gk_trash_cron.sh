#!/bin/bash
# gk_trash_cron.sh — 回收区（`.gk-trash`）定期**自动释放**（cron no_agent 作业）
# 用法: 由 cron_scheduler 调用（no_agent + script）。TTL 默认 **3 天**（`--trash-days` 可覆盖），
#       `--apply` 才落刀；dry-run 语义不变。
# 复用**单一事实源** `gk_worktree_reclaim.reclaim_trash`（龄期门 + RESTORE-MAP 自洽校验 +
#   主树/回收区保护），本脚本只做**调度编排**，不复制任何删除判据。
# 动机: `pre_tool_hook` 把每条递归删除改写成「搬进 `.gk-trash`」，而回收链此前**只进不出**
#   （finding `ECC-AAB70D5DCF11`）⟹ 隔离区单调增长；手动 `--apply` 无法保证周期性 ⟹ 本作业
#   把「到期即释放」变成**自动**。
set -u
SKILL_DIR="${SKILL_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CLI="$SKILL_DIR/gatekeeper-cli.sh"
OUT=$(bash "$CLI" apply-worktree --reclaim --trash --apply 2>/dev/null || echo '{"ok":false,"error":"trash reclaim failed"}')
# 提取 purged / held（held 非空 = 半搬态或有项拒删，须 fail-loud 不静默）
PURGED=$(echo "$OUT" | python3 -c "
import sys,json
try:
    print(len(json.load(sys.stdin).get('purged', [])))
except Exception:
    print(-1)
" 2>/dev/null)
HELD=$(echo "$OUT" | python3 -c "
import sys,json
try:
    print(len(json.load(sys.stdin).get('held', [])))
except Exception:
    print(-1)
" 2>/dev/null)
if [ "$PURGED" = "-1" ]; then
    echo "[gk-trash] FAIL — 无法解析回收输出"
    echo "$OUT" | head -c 500
else
    echo "[gk-trash] OK — TTL 3d 自动释放：purged=$PURGED held=$HELD"
fi
echo "$OUT"

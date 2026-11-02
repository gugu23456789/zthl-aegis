#!/bin/bash
# gk_doc_align_cron.sh — 定期文档-代码一致性检查（cron no_agent 作业，2026-08-27）
# 用法: 由 cron_scheduler 调用（no_agent + script）。输出含 doc-align JSON + 状态行。
# 覆盖：连续几轮变更后自动核对 cli-protocol/extension-registry/architecture-overview
# 与代码（_CMD_REG/函数名）漂移；命令名全名化（plan-refinement）漂移兜底。
set -u
SKILL_DIR="${SKILL_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CLI="$SKILL_DIR/gatekeeper-cli.sh"
OUT=$(bash "$CLI" doc-align 2>/dev/null || echo '{"ok":false,"error":"doc-align failed"}')
# 提取 issues 数（0 = 一致）
ISSUES=$(echo "$OUT" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print(d.get('issues', -1))
except Exception:
    print(-1)
" 2>/dev/null)
if [ "$ISSUES" = "0" ]; then
    echo "[doc-align] OK — 文档与代码一致 (issues=0)"
elif [ "$ISSUES" = "-1" ]; then
    echo "[doc-align] FAIL — 无法解析 doc-align 输出"
    echo "$OUT" | head -c 500
else
    echo "[doc-align] DRIFT — issues=$ISSUES，需要 docgen/手动对齐"
fi
echo "$OUT"

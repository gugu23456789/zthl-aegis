#!/usr/bin/env bash
# gk_red_team.sh — 红队 4 API 角色编排（2026-11-09）
# scanner / exploiter / auditor **并发**；reporter 在三人完成后汇总。
# 任务前缀 RED-SCOPE:/RED-EXPLOIT:/RED-POSTEX:/RED-REPORT: 由 CLI L4908-4911 映射到角色。
# 只分析本仓（Gatekeeper）；不对外部项目做渗透。
set -u
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="$SKILL_DIR/gatekeeper-cli.sh"
BATCH="${RED_BATCH:-red-team-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT="${RED_OUT:-$SKILL_DIR/docs/analysis/red-team/$BATCH}"
EPOCH="${RED_BATCH_EPOCH:-$(date +%s)}"
DRY=0
for a in "$@"; do [ "$a" = "--dry-run" ] && DRY=1; done
mkdir -p "$OUT"
SCOPE_TASK='RED-SCOPE: 对本仓（Gatekeeper）做只读攻击面测绘。重点三面：①额度银行计费咽喉/pre_tool_hook linked worktree 认领/edit_budget；②路径归一化（相对 gitdir、大小写、..、Windows↔WSL、兄弟名前缀）；③安全并发（budget-log append+seal、edit-log rotate+append、state-patch+advance）。只读，不改文件，不执行攻击，不分析外部项目。输出：面清单 + 证据文件:行。'
EXPLOIT_TASK='RED-EXPLOIT: 基于本仓 governance-contract.json 与 RED-GOV 向量，构造可复现攻击向量。重点三面：额度银行计费绕过/封印与 CAP；路径归一化形态绕过；budget-log 并发重复 seq。每条给 id/severity/步骤/repro_cmd/证据。只读，不改文件，不执行破坏性动作，不分析外部项目。'
POSTEX_TASK='RED-POSTEX: 对本仓红队攻击链做后期利用评估：哪些向量能组合成真实绕过、哪些被现有防线挡住、哪些是假阳性。重点三面：额度银行、路径归一化、安全并发。只读，不改文件，不分析外部项目。'
run_role() {
  local task="$1" out="$2"
  SUBAGENT_TIER=3 SUBAGENT_TIMEOUT=600 "$CLI" monitor --subagent --batch-epoch "$EPOCH" "$task" \
    > "$out" 2> "$out.err"
  echo $? > "$out.rc"
}
if [ "$DRY" = "1" ]; then
  echo "BATCH=$BATCH OUT=$OUT EPOCH=$EPOCH"
  echo "scanner   -> monitor --subagent RED-SCOPE: ..."
  echo "exploiter -> monitor --subagent RED-EXPLOIT: ..."
  echo "auditor   -> monitor --subagent RED-POSTEX: ..."
  echo "reporter  -> monitor --subagent RED-REPORT: ... (after 3)"
  exit 0
fi
run_role "$SCOPE_TASK" "$OUT/scanner.json" & p1=$!
run_role "$EXPLOIT_TASK" "$OUT/exploiter.json" & p2=$!
run_role "$POSTEX_TASK" "$OUT/auditor.json" & p3=$!
wait $p1 $p2 $p3
PATHS=$(python3 - "$OUT" <<'PY'
import json, pathlib, sys
out = pathlib.Path(sys.argv[1]); paths = []
for f in ("scanner.json", "exploiter.json", "auditor.json"):
    try:
        d = json.loads((out / f).read_text(encoding="utf-8"))
    except Exception:
        continue
    for k in ("report_path", "md_file", "report", "path"):
        v = d.get(k) if isinstance(d, dict) else None
        if isinstance(v, str) and v and v not in paths:
            paths.append(v)
print("; ".join(paths))
PY
)
REPORT_TASK="RED-REPORT: 汇总本批 $BATCH 的三份报告（scanner/exploiter/auditor，batch_epoch=$EPOCH），去重、排序、标注哪些是真实绕过/哪些是假阳性，输出攻击链报告。可用报告路径：${PATHS:-（在 $OUT 与 docs/analysis/subagent/ 下按 batch_epoch 找）}。只读，不分析外部项目。"
run_role "$REPORT_TASK" "$OUT/reporter.json"
echo "{\"ok\":true,\"batch\":\"$BATCH\",\"out\":\"$OUT\",\"reports\":\"$PATHS\"}"

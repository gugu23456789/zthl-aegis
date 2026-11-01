#!/usr/bin/env bash
# 2026-10-19: W2A 金字塔证据共享拓扑（规范下发：三组 × K=2）。
#
# 默认 = L0/L3 pilot（1 计划 × 2 层 × 6 臂 = 12 次臂运行）：
#   L0 = 臂各自检索（不注入证据）；L3 = 全臂并集证据静态注入。
# 全量 = W2A_MODE=full：L0-L3 × 6 臂 + 确定性 D1-D5 缺陷计划 B + gold。
#
# 纪律：
#   · 窄任务先过 C1-C8 机检；派生/正交标志不绿 ⟹ 直接退出，不跑 API。
#   · 专用域 state（不污染 base）；缺失则初始化骨架。
#   · K 缺省 2（K=1 会按 index//K 错标组别）。
#   · 预算/限速由 gk_web_tools 的文件级 token bucket 控（聚合 ≤5 req/s）。
set -u
# 2026-10-29 去硬编码：技能目录/工作目录/域 token 全部由**脚本自身位置 + 环境**推导
# （原为写死的 `/mnt/c/Users/<user>/...agent/session/84044a4e` 与技能路径 ⟹ 换机器/换会话即不可跑）。
SKILL_DIR="${SKILL_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
W2A_WORKTREE="${W2A_WORKTREE:-$SKILL_DIR}"
cd "$W2A_WORKTREE" || exit 2

STATE_DOMAIN="${W2A_STATE_DOMAIN:-skill.2026-10-18-w2a-web-evidence-pyramid-plan}"
STATE_FILE="$SKILL_DIR/.gatekeeper.state.$STATE_DOMAIN"
export STATE_FILE
export GK_ENV_INJECT=1
export SUBAGENT_TIER=2
export GK_NO_CTX_SELFHEAL=1
export GK_ALLOW_STALE_CTX=1
export GK_ALLOW_STALE_BASELINE=1
export GK_GX_ANALYZE_TIMEOUT=30

# 专用域 state：只建骨架，不复制 base 的历史/预算（防跨计划污染）。
if [ ! -f "$STATE_FILE" ]; then
  cat > "$STATE_FILE" <<JSON
{"r_phase":"","stage":"STAGE_0","branch":"${W2A_BRANCH:-agent/session/w2a}","worktree":"$W2A_WORKTREE","main_repo":"${GK_MAIN_REPO:-}","gate_data":{}}
JSON
fi

MODE="${W2A_MODE:-pilot}"              # pilot | full
LEVELS="${W2A_LEVELS:-L0 L3}"          # pilot 缺省只跑 L0/L3
K="${W2A_ARMS_PER_GROUP:-2}"
DRY_RUN="${W2A_DRY_RUN:-0}"            # 1 = 只跑到机检通过（零 API）
# 2026-11-01：解释器改**发现式**（W2A_PY 可覆盖；不写死个人 venv 路径）
PY="${W2A_PY:-$(bash "$(dirname "$0")/py_resolve.sh" pytest 2>/dev/null || echo python3)}"
LOG_PREFIX="${W2A_LOG_PREFIX:-/tmp/w2a-web}"
EV_PREFIX="${W2A_EV_PREFIX:-/tmp/w2a-web-evidence}"
PILOT_PLAN="docs/plans/2026-10-18-w2a-web-pilot-plan.md"
PLAN_B_DIR="docs/analysis/w2a-web-pyramid"
PLAN_B="$PLAN_B_DIR/plan-b-20261019.md"
GOLD_B="$PLAN_B_DIR/plan-b-20261019.gold.json"
NARROW="docs/plans/2026-10-18-w2a-web-narrow-tasks.json"
TASK='请逐条核查本计划的 5 条断言。若上下文已注入共享外部证据，优先使用；未覆盖的断言再用 web_search / web_fetch 补充；禁止使用本地 search。每条给出 verdict=support/refute/abstain、source URL、<=200 字原文片段；不确定就 abstain。最后输出 SOURCES: ...'

TASK_FULL='请逐行审查本计划的步骤链，找出可复核的缺陷（矛盾/悬空依赖/无据断言/依赖倒置/越权），每条给出缺陷 id、原文 clause、source URL 与 verdict=support/refute/abstain；最后输出 SOURCES: ...'

if [ "$MODE" = "full" ]; then
  LEVELS="${W2A_LEVELS:-L0 L1 L2 L3}"
  TASK="$TASK_FULL"
  mkdir -p "$PLAN_B_DIR"
  "$PY" - "$PLAN_B" "$GOLD_B" <<'PY'
import json, sys
sys.path.insert(0, "scripts")
import gk_defect_gen as D
out = D.generate(seed=20261019, k=3, stealth=1)
meta = ("<!-- META\nphases: W2A-WEB-PLAN-B\ntarget_repo: skill\n"
        "project_type: plan\nworktree_needed: false\n"
        "state_domain: skill.2026-10-18-w2a-web-evidence-pyramid-plan\n-->\n\n")
with open(sys.argv[1], "w", encoding="utf-8") as f:
    f.write(meta + out["plan_text"])
with open(sys.argv[2], "w", encoding="utf-8") as f:
    json.dump(out["gold"], f, ensure_ascii=False, indent=2)
print(json.dumps({"seed": out["seed"], "k": out["k"], "codes": out["codes"],
                  "plan": sys.argv[1], "gold": sys.argv[2]}, ensure_ascii=False))
PY
  PLAN="$PLAN_B"
  export GK_ARM_GOLD="$(cat "$GOLD_B")"
else
  PLAN="$PILOT_PLAN"
  # pilot 无 gold：det_F1 必须落 null(reason=no_gold)，不得冒充 0。
  unset GK_ARM_GOLD
fi

# 1) 窄任务登记（K=2 + 构造性 G2 派生）；机检不绿 ⟹ 不跑 API。
REG_LOG=/tmp/w2a-pyramid-register.log
bash ./gatekeeper-cli.sh state-patch --narrow-register "$NARROW" >"$REG_LOG" 2>&1 || {
  echo "narrow register failed:"; tail -n 20 "$REG_LOG"; exit 2
}
"$PY" - "$REG_LOG" <<'PY' || { echo "narrow constraints not green"; tail -n 20 "$REG_LOG"; exit 2; }
import json, sys
o = json.load(open(sys.argv[1], encoding="utf-8"))
ok = bool(o.get("registered")) and o.get("constraints", {}).get("ok")
orth = o.get("constraints", {}).get("orthogonality", {})
der = o.get("derivation", {})
if not (ok and orth.get("covers_disjoint") and orth.get("joint_covers_target")
        and orth.get("text") == "checked" and der.get("mode") == "derived"):
    raise SystemExit(1)
PY

if [ "$DRY_RUN" = "1" ]; then
  echo "DRY-RUN: preflight green (state=$STATE_FILE, K=$K, levels=$LEVELS, mode=$MODE)"
  exit 0
fi

# L1 = scout 广播（1 个官方源）；L2 = curated（3 个官方页）；L3 = union（8 个：官方 + 二手）
L1_URLS='https://api-docs.deepseek.com/guides/search'
L2_URLS='https://api-docs.deepseek.com/guides/search,https://api-docs.deepseek.com/api/search/,https://api-docs.deepseek.com/api/fetch/'
L3_URLS='https://api-docs.deepseek.com/guides/search,https://api-docs.deepseek.com/api/search/,https://api-docs.deepseek.com/api/fetch/,https://runtimewire.com/article/deepseek-search-fetch-api-pricing-liang-wenfeng,https://news.17173.com/content/10172026/160516064.shtml,https://www.gateskills.ai/zh-tw/news/detail/deepseek-to-charge-for-search-and-fetch-calls-starting-november-1-at-5-cny-25016430,https://app.qudong.com/article/526406.html,https://github-wiki-see.page/m/pawaca/dsh-edge/wiki/Web-Access-zh'

for lvl in $LEVELS; do
  EV_ARGS=()
  if [ "$lvl" != "L0" ]; then
    case "$lvl" in
      L1) urls="$L1_URLS" ;;
      L2) urls="$L2_URLS" ;;
      L3) urls="$L3_URLS" ;;
      *) echo "unknown level: $lvl"; exit 2 ;;
    esac
    EV="${EV_PREFIX}-$lvl.json"
    if [ ! -s "$EV" ]; then
      "$PY" scripts/build_w2a_web_evidence.py --urls "$urls" --out "$EV" || {
        echo "$lvl evidence build failed"; exit 2
      }
    fi
    EV_ARGS=(--web-evidence "$EV")
  fi
  echo "=== $lvl (K=$K, mode=$MODE, plan=$PLAN) ==="
  bash ./gatekeeper-cli.sh plan-refinement "$PLAN" --task "$TASK" \
    --arms-per-group "$K" --evidence-sharing "$lvl" "${EV_ARGS[@]}" --run \
    --aggregate-out "${LOG_PREFIX}-$lvl.aggregate.json" \
    > "${LOG_PREFIX}-$lvl.log" 2>&1
  rc=$?
  echo "$lvl RC=$rc"
  tail -n 25 "${LOG_PREFIX}-$lvl.log"
done

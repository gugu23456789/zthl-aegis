"""test_gk_dispatch_budget_single_source.py — CLI subagent 派发链「预算单源化 + role 臂补全」。

背景（实测，非推测）：
  `cmd_monitor` 的 subagent 派发链在 CLI 侧维护了**第二份预算来源** ——
    · `local subagent_max_turns` / `subagent_token_budget` / `subagent_item_budget`
    · 4 个 named-mode 的 max_turns 预设（red-scanner/exploiter/auditor/reporter）
    · free-text 的 task_count 启发式（`subagent_max_turns="${SUAGENT_MAX_TURNS:-$(( task_count * 10 ))}"`）
    · 5 个 role 臂的 token/item 赋值（plan-refinement / scanner|auditor / reporter / exploiter / default）
    · 3 处派发点把三参当 argv 传给 runner
  而 runner 侧 `_bootstrap()` 的 tier 块**覆盖**这份 argv：`args.max_turns = _t["max_turns"]` 无条件；
  token/item 仅在 env `SUBAGENT_TOKEN_BUDGET` / `SUBAGENT_ITEM_BUDGET` **未设**时被覆盖（CLI 从不
  export 这两个 env）⟹ **CLI 侧三参是死参**。端到端实证（2026-09-25）：CLI argv 传
  `--tier 4 --max-turns 10 --token-budget 500000 --item-budget 2000`，runner 产物
  `token_usage = {cap:1000000, item_cap:4000, rounds:28}`（**当时**值；tier4 cap 已于
  2026-09-26 因 `ECC-A2ECF8371F96` 上调为 1,500,000，见 arm53）⟹ 唯一仍生效的是 **tier**
  （`SUBA_TIERS[tier]` = 预算单一事实源）。

  次生缺陷：role `case`（`case "$subagent_role" in`）**无 `coder)` 臂、无 `*)` 兜底臂**
  ⟹ `--role coder`（及任何未登记角色）不命中任何臂 ⟹ `SUBAGENT_TIER` 未设 ⟹ 派发落 `--tier 0`
  ⟹ runner 的 tier 块**整块跳过** ⟹ 已被判死的 CLI 三参反而「复活」为实际预算
  （实测该派发 `cap=100000 / item_cap=375`）—— 单源被彻底破坏。

判据（红先 + 负臂）：
  arm50（红先）：整份 CLI 不得再出现三参族任何字面（3 处 argv 传参 + 5 处 role 赋值 + 声明/预设/启发式）。
  arm52（红先）：role `case` 段必须同时含 `coder)` 臂与 `*)` 兜底臂。
  arm51（**非红**回归臂）：三处派发点仍须传 `--tier "${SUBAGENT_TIER:-0}"`（防「顺手把档位也删掉」
      —— 删掉 tier 才是真的把单源连根拔了）。

安全网 R1：纯**文本不变量**（只读源码；不起子进程、不写盘、不 patch 标准库）。
"""
import re
from pathlib import Path

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"

# 三参族（预算双源在 CLI 侧的全部字面载体）。`subagent_mode_set` **不在**本列 ——
# 它是 **role 推导的输入**（`if $subagent_mode_set; then case "$task" in RED-*:*)`），非预算参数，
# 落刀后**保留**（free-text 启发式删除后它仍被 role 派生读取，故非死变量）。
_DEAD_BUDGET_TOKENS = (
    "--token-budget",
    "--item-budget",
    "subagent_max_turns",
    "subagent_token_budget",
    "subagent_item_budget",
    "SUAGENT_MAX_TURNS",
)

_TIER_CALL = '--tier "${SUBAGENT_TIER:-0}"'


def _src() -> str:
    return CLI.read_text(encoding="utf-8")


def _role_case_seg() -> str:
    """`case "$subagent_role" in` … 首个 `esac` 之间的**代码**段（剥注释）。

    剥注释的理由：臂的判据是「**分支标签**存在」，注释里出现同形字不构成分支；
    不剥则一个「我们是 coder) 车道」的注释就能让臂假绿。
    """
    src = _src()
    i = src.index('case "$subagent_role" in')
    rest = src[i:]
    m = re.search(r"(?m)^[ \t]*esac[ \t]*$", rest)
    seg = rest[: m.end()] if m else rest
    return "\n".join(re.sub(r"#.*$", "", ln) for ln in seg.splitlines())


def test_auditor_arm_is_split_and_not_below_default():
    """2026-10-01（用户裁定「修 auditor 档位错配」）：auditor 须为**独立**臂，且档位 ≥ default。

    背景：原与 scanner 合并为 `scanner|auditor)` = tier2；而 auditor 承载 L2 `--crossrev` /
    后R 五域审计 / RED-POSTEX 三条重审查车道，均需读 gate 区大文件 ⟹ tier2 实测
    `budget_status=hard` 截停分析。从 `_role_case_seg()`（**已剥注释**）取段 ⟹ 防
    「注释里写着 auditor) tier4」的假绿。
    """
    seg = _role_case_seg()
    assert "scanner|auditor)" not in seg, "auditor 仍与 scanner 合臂 ⟹ 重审查面被压到 light 档"
    m = re.search(r"(?m)^[ \t]*auditor\)[ \t]*$", seg)
    assert m, "缺 auditor) 独立臂"
    arm = seg[m.end():seg.index(";;", m.end())]
    tiers = re.findall(r"SUBAGENT_TIER:-(\d+)", arm)
    assert tiers, "auditor 臂未定档位（会落 --tier 0 ⟹ runner 整块跳过 tier 逻辑）"
    dm = re.search(r"(?m)^[ \t]*default\)[ \t]*$", seg)
    assert dm, "缺 default) 臂"
    d_arm = seg[dm.end():seg.index(";;", dm.end())]
    d_tier = int(re.findall(r"SUBAGENT_TIER:-(\d+)", d_arm)[0])
    assert int(tiers[0]) >= d_tier, (
        f"auditor tier={tiers[0]} < default tier={d_tier} ⟹ 审查面预算低于补位面")


def test_scanner_tier_raised_to_3():
    """2026-10-17（owner 裁定「scanner t2→t3，其余保持」）：RED-SCOPE 要读 gate 大文件
    （gatekeeper-cli.sh ~575K 字符）+ state 枚举攻击面，与 auditor 当年抬档理由同构 ⟹
    scanner 档位须 ≥ 3（t2=200k 成本当量会被 `budget_status=hard` 中途截停）。"""
    seg = _role_case_seg()
    m = re.search(r"(?m)^[ \t]*scanner\)[ \t]*$", seg)
    assert m, "缺 scanner) 独立臂"
    arm = seg[m.end():seg.index(";;", m.end())]
    tiers = re.findall(r"SUBAGENT_TIER:-(\d+)", arm)
    assert tiers, "scanner 臂未定档位（会落 --tier 0 ⟹ runner 整块跳过 tier 逻辑）"
    assert int(tiers[0]) >= 3, (
        f"scanner tier={tiers[0]} < 3 ⟹ RED-SCOPE 读 gate 大文件会被 hard 截停")


def test_coder_tier_is_4():
    """2026-10-17：coder（`--code-fix`，工具含 `edit`）档位 = 4（与 default 同档，已最高）。

    背景：coder 派发经 `apply-worktree --code-fix` → `monitor --subagent --role coder`；
    档位错配会让写代码臂被低预算截停（同 auditor 抬档教训）。
    """
    seg = _role_case_seg()
    m = re.search(r"(?m)^[ \t]*coder\)[ \t]*$", seg)
    assert m, "缺 coder) 独立臂"
    arm = seg[m.end():seg.index(";;", m.end())]
    tiers = re.findall(r"SUBAGENT_TIER:-(\d+)", arm)
    assert tiers, "coder 臂未定档位（会落 --tier 0 ⟹ runner 整块跳过 tier 逻辑）"
    assert int(tiers[0]) == 4, f"coder tier={tiers[0]} != 4（应 default 同档）"


def test_arm50_subagent_dispatch_budget_single_source():
    """红先臂：CLI 侧**不得**再持有预算三参 —— 预算单源 = runner `SUBA_TIERS[tier]`。

    红先对照（HEAD 实测**出现次数**，非行数、非推测）：`--token-budget`×3 /
    `--item-budget`×3 / `subagent_max_turns`×9 / `subagent_token_budget`×9 /
    `subagent_item_budget`×9 / `SUAGENT_MAX_TURNS`×2 ⟹ 本臂在落刀前必红。
    """
    src = _src()
    left = {tok: src.count(tok) for tok in _DEAD_BUDGET_TOKENS if src.count(tok)}
    assert not left, (
        "CLI 侧预算三参仍残留（应删：它们被 runner tier 块覆盖 ⟹ 死参，且 tier=0 时反而「复活」"
        "破坏单源）—— 注释里也不得出现这些字面（本臂是**全文字面**判据）：\n"
        + "\n".join(f"  {tok}: {n} 处" for tok, n in left.items()))


def test_arm51_subagent_dispatch_sites_keep_tier():
    """**非红**回归臂：三处派发点仍须传 `--tier`（唯一活着的预算通道）。

    本臂在 HEAD 与落刀后**都应绿** ⟹ 不入选红先集（`shape_k`/`full_k` 不含 arm51），
    它防的是「把死参删干净时顺手把 tier 也删了」。
    """
    src = _src()
    n = src.count(_TIER_CALL)
    assert n == 3, (
        f"三处 subagent 派发点应各传一次 `{_TIER_CALL}`（实测 {n} 处）—— "
        "删死参不得连带删除 tier：tier 是 SUBA_TIERS 单源的**唯一入口**")


def test_arm52_role_case_has_coder_and_fallback_arm():
    """红先臂：role `case` 段必须含 `coder)` 臂 **与** `*)` 兜底臂。

    缺 `coder)` ⟹ `--role coder` 不命中任何臂；缺 `*)` ⟹ 任何未登记角色同样不命中
    ⟹ 两者都使 `SUBAGENT_TIER` 未设 ⟹ `--tier 0` ⟹ runner 跳过 tier 块、CLI 参数「复活」。
    """
    seg = _role_case_seg()
    assert re.search(r"(?m)^[ \t]*coder\)", seg), (
        "role case 缺 `coder)` 臂 ⟹ `--role coder` 不命中任何臂 ⟹ SUBAGENT_TIER 未设 ⟹ tier=0")
    assert re.search(r"(?m)^[ \t]*\*\)", seg), (
        "role case 缺 `*)` 兜底臂 ⟹ 任何未登记角色/roleless 派发落 tier=0 ⟹ 单源破裂")


# ══════════ tier4 质询 cap 覆盖实测成本（`ECC-A2ECF8371F96`）══════════
# ⚠ 读取源订正（2026-10-12，`ECC-D59A6171817B`）：`SUBA_TIERS` 已于 2026-10-08 迁至 `gk_suba_tiers.py`
#   ⟹ 本臂读 `token_budget` 的源 = `gk_suba_tiers.py`（旧家 `subagent_runner.py` 已无该表 ⟹ 恒 FAIL）。
# 红先对照（HEAD 源码，迁移前口径）：`git show HEAD:scripts/subagent_runner.py | grep -c '1500000'`。
TIERS_SRC = Path(__file__).resolve().parent / "gk_suba_tiers.py"


def test_arm53_tier4_cap_covers_measured_cost():
    """红先臂（`ECC-A2ECF8371F96`）：tier4 质询 cap **不得低于本型实测成本**；口径 = **成本当量**。

    现场（2026-09-26 实测本仓）：单臂 plan-refinement 质询 `total_tokens`（= **成本当量**，
    `miss + hit×_PRICE_HIT_RATIO + completion×_PRICE_OUTPUT_RATIO`，见 `_BudgetHooks.on_llm_end`）
    = **1,146,006** 已 > 1,000,000 ⟹ `budget_status=hard` **截停分析** ⟹ 结论可信度受损。
    ⚠ **口径订正**：hook-xenv §15.1 台账列的是 **raw tokens**（= 请求级 `total_tokens` 含缓存重发，
    只作量级参考），而 cap 比的是**成本当量** —— 两者**不可直接比**（`subagent_runner.py` `_BUDGET`
    注释「口径警告…禁止直接比」明令）。原 finding 用 raw 作证据属口径错误，但其结论（cap 偏低）
    由本次成本当量 1,146,006 > 1M 独立坐实。
    """
    src = TIERS_SRC.read_text(encoding="utf-8")
    m = re.search(r'(?m)^\s*4:\s*\{"token_budget":\s*(\d+)', src)
    assert m, "未找到 SUBA_TIERS[4].token_budget（单一事实源结构变了？）"
    cap = int(m.group(1))
    assert cap >= 1_500_000, (
        f"tier4 token_budget={cap} < 1,500,000：实测单臂质询**成本当量** 1,146,006 已触发 hard 截停"
        " ⟹ 硬限低于真实成本中位（口径 = 成本当量，非 raw token）")
    tbl = src[src.index("SUBA_TIERS = {"):src.index("DEFAULT_TIER")]
    assert "成本当量" in tbl, (
        "tier 表须明示 `token_budget` 口径 = **成本当量**（防再次拿 raw token 当口径直接比）")

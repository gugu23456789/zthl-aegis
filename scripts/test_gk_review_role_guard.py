#!/usr/bin/env python3
"""F2 红先臂 —— 质询 subagent 可静默落 default 角色（`ECC-FAB556F786E5`，2026-10-01）。

病象（实测臂 `sub-1790833592-542-3597`，登记于 `docs/plans/2026-09-21-review-runtime-subplan.md`
「序④-C 追加」）：`monitor --subagent "<质询任务>"` 未带 `--role` 时，`subagent_role` 由
`echo "$task" | rg -q "plan-refinement"` 的**自由文本子串**推断；任务串不含该字面
（实测 = 「质询臂A(域化范围)：…」）⟹ 静默落 `default` ⟹ 产出 `verdicts={}` /
`seven_dim_score={}` / `verification` 空壳，却仍被套质询报告模板。

**循环依赖（真根因）**：审查通道门禁 `_review_channel_preflight` 的 arm 条件**就是**
`[ "$subagent_role" = "plan-refinement" ]` ⟹ 门禁只在「已经是质询角色」时举起，
而那个身份由**未校验的自由文本**推断 ⟹ 猜错时门禁根本不 arm。

判据（红先，落刀前 HEAD **必红**）：
  arm1  源中须有 `REVIEW_ROLE_UNSPECIFIED` fail-loud（HEAD 无 → 红）
  arm2  门禁 arm 条件须改为**显式** `role_override`（HEAD 用推断出的 `subagent_role` → 红）
  arm3  守门臂（改前已绿）：RED-* 前缀映射与 `--role` 显式覆盖**不得**被本刀破坏
"""
from pathlib import Path

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def _src() -> str:
    return CLI.read_text(encoding="utf-8")


def test_review_role_unspecified_is_fail_loud():
    """命题①：命中质询子串且**未显式** `--role` ⟹ fail-loud（禁猜进高权通道）。"""
    s = _src()
    assert "REVIEW_ROLE_UNSPECIFIED" in s, (
        "缺 REVIEW_ROLE_UNSPECIFIED ⟹ 质询任务仍可静默落 default 角色（ECC-FAB556F786E5）")


def test_preflight_armed_by_explicit_role_not_inference():
    """命题②：门禁 arm 条件与「推断出的身份」解耦，改由**显式** `role_override` 驱动。"""
    s = _src()
    assert '[ "$role_override" = "plan-refinement" ] || $crossrev_flag' in s, (
        "门禁仍以推断角色（subagent_role）为 arm 条件 ⟹ 循环依赖未除（猜错即门禁不举）")


def test_red_prefix_and_explicit_override_preserved():
    """守门臂：RED-* 四臂映射与显式 `--role` 覆盖两条既有路径不得被本刀破坏。"""
    s = _src()
    for lit in ('RED-SCOPE:*) subagent_role="scanner"',
                'RED-EXPLOIT:*) subagent_role="exploiter"',
                '[ -n "$role_override" ] && subagent_role="$role_override"'):
        assert lit in s, f"既有角色路径被破坏: {lit}"

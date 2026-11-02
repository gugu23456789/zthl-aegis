#!/usr/bin/env python3
"""设计 A/B 红先臂：**族可改面**与「该 finding 的红先臂文件」对齐（2026-09-30）。

来源：用户实测「apply-worktree 经常因为**不包含对应个别测试文件**导致失败」⟹ 裁定 **A+B**
（A = 运行时刻按红先臂登记表并入；B = 族数据静态对齐）。见
`docs/plans/2026-09-28-git-concurrency-lease-declare-plan.md` §14。

**病象**：族 `allowed_paths` 是**静态**清单（每族通常只一个测试文件），而「这个 finding 的臂
写在哪个文件」按 finding 登记在 `references/red-arm-templates.json::finding_arms[].test_file`
⟹ 二者系统性错配 ⟹ coder 落 `gk_agent_edit.apply_edit` 闸② 判 `blocked_by: "allowed_paths"`。

**关键实测约束（本文件钉住的最重要一条）**：族分**两类设计**，A **只对「可改自有测试」型生效**：
  · 可改自有测试型：`allowed_paths` **已含** `test_*.py`（F3b / XENV-FORM / F-MoA-accept-aggregation）
    ⟹ 并入该 finding 的臂文件；
  · **source-only 型**：`allowed_paths` **不含**任何测试文件，模板自陈「**禁止改任何测试文件**
    （红先臂由主 agent 写）—— 你只负责落刀」（F7 / F-cli-dispatch-budget-single-source /
    F-MoA-full-regression）⟹ **一律 no-op**（臂⑥钉住：源字段里没有测试文件的族，A 不得凭
    `forbidden_paths` 缺席就擅自放行 —— 那会**违反其显式设计**）。
"""
import json
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import gk_agent_family as af  # noqa: E402
import gk_red_arm_gen as gen  # noqa: E402
from gk_agent_edit import _within  # noqa: E402  （**同一份**路径判定语义，禁第二实现）

# 取数源（登记表）里的**真**条目（禁自造，否则证不了与生产同一事实源）
F_ACCOUNTING_ARM = "ECC-F6C94D444CC6"     # test_file = scripts/test_gk_edit_budget_metering.py
F_SOURCE_ONLY_ARM = "ECC-8A6560E4FEB6"    # test_file = scripts/test_pre_tool_hook.py
F_FORBIDDEN_ARM = "ECC-F0F0999A3970"      # test_file = scripts/test_gk_state_write_single_entry.py

FAM_TEST_EDITING = "F3b-edit-budget-accounting"
FAM_SOURCE_ONLY = "F7-worktree-route-visibility"


def _allowed_of(fid, fam):
    return af.resolve(fid, family_id=fam)["allowed_paths"]


# ── 臂①（设计 A · 正臂）可改自有测试型 ⟹ 并入该 finding 的臂文件 ───────────────
def test_arm1_extra_added_for_test_editing_family():
    tf = gen.finding_test_file(F_ACCOUNTING_ARM)
    assert tf == "scripts/test_gk_edit_budget_metering.py", f"取数源变了：{tf}"
    fam = af.load_family(FAM_TEST_EDITING)
    assert tf not in (fam.get("allowed_paths") or []), "前提不成立：该文件已在族 allowed_paths"
    out = _allowed_of(F_ACCOUNTING_ARM, FAM_TEST_EDITING)
    assert tf in out, f"设计 A 未并入该 finding 的红先臂文件：{out}"
    # 三面同源：窄任务串的 `allowed_paths:` 行也须带上（否则 coder 被告知的面 ≠ 闸判定面）
    nt = af.resolve(F_ACCOUNTING_ARM, family_id=FAM_TEST_EDITING)["narrow_task"]
    line = [ln for ln in nt.splitlines() if ln.startswith("allowed_paths:")]
    assert line and tf in line[0], f"窄任务串未同步该文件：{line}"


# ── 臂②（设计 A · **负臂**）source-only 族 ⟹ 一律 no-op（不得擅自放行）────────
def test_arm2_extra_skipped_for_source_only_family():
    tf = gen.finding_test_file(F_SOURCE_ONLY_ARM)
    assert tf == "scripts/test_pre_tool_hook.py", f"取数源变了：{tf}"
    fam = af.load_family(FAM_SOURCE_ONLY)
    # 该族**显式** forbids 一堆他族测试，但**不**列自家臂文件 ⟹ 单看 forbidden 判不出 source-only
    assert tf not in (fam.get("forbidden_paths") or []), (
        "前提变了：该族已显式 forbids 自家臂文件（则本臂应改为「forbidden 优先」形态）")
    out = _allowed_of(F_SOURCE_ONLY_ARM, FAM_SOURCE_ONLY)
    assert tf not in out, (
        f"source-only 族被擅自放行测试文件（违反其模板「禁止改任何测试文件」）：{out}")


# ── 臂③（设计 A · 负臂）显式禁忌优先：臂文件在该族 forbidden_paths ⟹ 不并入 ────
def test_arm3_extra_respects_forbidden_paths():
    tf = gen.finding_test_file(F_FORBIDDEN_ARM)
    assert tf == "scripts/test_gk_state_write_single_entry.py", f"取数源变了：{tf}"
    assert tf in (af.load_family(FAM_TEST_EDITING).get("forbidden_paths") or []), (
        "前提变了：F3b 未 forbids 该文件（本臂须换一个真被 forbids 的臂文件）")
    assert tf not in _allowed_of(F_FORBIDDEN_ARM, FAM_TEST_EDITING), (
        "显式 forbidden 被架空（禁改优先于推演）")


# ── 臂④（设计 A）未登记 finding ⟹ no-op（取数失败不得放大面 / 不得阻断）────────
def test_arm4_unknown_finding_is_noop():
    base = af.load_family(FAM_TEST_EDITING).get("allowed_paths")
    assert _allowed_of("ECC-NOT-REGISTERED", FAM_TEST_EDITING) == base


# ── 臂⑤（设计 A · kill switch）`GK_ARM_ALLOWED=0` ⟹ 退回族原值 ───────────────
def test_arm5_kill_switch_disables_augment(tmp_path, monkeypatch):
    monkeypatch.setenv("GK_ARM_ALLOWED", "0")
    base = af.load_family(FAM_TEST_EDITING).get("allowed_paths")
    assert _allowed_of(F_ACCOUNTING_ARM, FAM_TEST_EDITING) == base


# ── 臂⑥（**门本身**）「可改自有测试」判据只看 allowed_paths 有没有 test_*.py ────
def test_arm6_may_edit_tests_uses_structural_signal():
    assert af._family_may_edit_tests(["gatekeeper-cli.sh", "scripts/test_x.py"]) is True
    assert af._family_may_edit_tests(["gatekeeper-cli.sh", "scripts/gk_x.py"]) is False
    assert af._family_may_edit_tests([]) is False
    # 与**真**族数据一致（防「门」与数据漂移）
    assert af._family_may_edit_tests(af.load_family(FAM_TEST_EDITING)["allowed_paths"]) is True
    assert af._family_may_edit_tests(af.load_family(FAM_SOURCE_ONLY)["allowed_paths"]) is False


# ── 臂⑦（设计 B · 数据不变量）可改自有测试族：affected_tests \ forbidden ⊆ allowed ──
def test_arm7_b_data_invariant_for_test_editing_families():
    bad = []
    for fid in af.list_families():
        fam = af.load_family(fid)
        allowed = list(fam.get("allowed_paths") or [])
        if not af._family_may_edit_tests(allowed):
            continue                      # source-only 族不适用（设计如此）
        forb = list(fam.get("forbidden_paths") or [])
        for t in (fam.get("affected_tests") or []):
            if _within(t, forb):
                continue                  # verify-only（显式禁改）⟹ 不进 allowed 面
            if t not in allowed:
                bad.append("%s: affected_tests %s 不在 allowed_paths" % (fid, t))
    assert not bad, "设计 B 数据不变量破（族改不了自己要保绿的测试）：\n  " + "\n  ".join(bad)


# ── 臂⑧（设计 B · 本批实修面）XENV-FORM 三个验收测试都可改 ─────────────────────
def test_arm8_xenv_form_covers_all_its_affected_tests():
    fam = af.load_family("XENV-FORM")
    for t in fam.get("affected_tests") or []:
        assert t in (fam.get("allowed_paths") or []), f"XENV-FORM 仍改不了自己的验收测试：{t}"

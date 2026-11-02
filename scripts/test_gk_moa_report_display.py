#!/usr/bin/env python3
"""§18 残余红先臂：MoA 面 RC3（N2 suspect 泛滥）+ RC4（N3 报告归属塌缩）。

伞：`ECC-5538DD07B709`（`root_key=moa-face`）—— RC3 引用可信度 / RC4 报告呈现。

判据（红先，HEAD 必红）：
  N2（RC3）：`_suspect_flags` 的**内容缺席类**标记（`no_evidence` / `budget_*`）把
    **实质齐备**的 plan-refinement 报告误标 suspect 降权（实测 6/8 质询臂 `budget_hard`、
    1 臂 `no_evidence`）。修法 = 与 `zero_findings` **同源的实质判据** carve-out：
    `_has_substance` 为真 ⟹ 不标 `no_evidence` / `budget_*`（真零实质仍标，负臂钉住）。
  N3（RC4）：`render_md` 只打 `task[:200]`，standing 模板前缀 >200 字符 ⟹ 全部 reference
    任务行**逐字相同**，聚合器无法从报告做归属（F-REV-53 落库去截断在显示面复发）。
    修法 = head+tail 省略显示（保留尾部区分信息）。
"""
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import gk_moa_aggregate as M  # noqa: E402

PLAN = "/p/docs/plans/x-plan.md"
TASK = "plan-refinement: %s — 质询 组1" % PLAN


def _pr_entry():
    """实质住 review 通道的 plan-refinement 报告（findings/evidence 本就空）。"""
    return {
        "subagent_id": "sub-pr-1", "task": TASK, "conclusion": "结论：F1 PASS；F2 PASS。" * 12,
        "evidence": [], "findings": {},
        "challenges": ["F1 范围：设计把第三键当必要 ⟹ WARN"],
        "verdicts": {"F1": "WARN", "F7": "PASS"},
        "kept": ["允许集 worktrees_extra"], "slashed": ["dispatch_worktree 落主 state"],
        "budget_status": "hard",
    }


# ── N2（RC3）：内容缺席类标记不得误标「实质齐备」报告 ────────────────────────

def test_pr_substantive_no_evidence_not_flagged():
    e = _pr_entry()
    flags = M._suspect_flags(e)
    assert "no_evidence" not in flags, (
        f"实质齐备的 plan-refinement 报告（evidence 空属正常形态）被误标 no_evidence：{flags}")


def test_pr_substantive_budget_hard_not_flagged():
    e = _pr_entry()
    e["budget_status"] = "hard"
    flags = M._suspect_flags(e)
    assert "budget_hard" not in flags, (
        f"实质齐备的报告被 budget_hard 误标降权（N2 现场 6/8 臂）：{flags}")


def test_non_substantive_no_evidence_still_flagged():
    """负臂：真零实质 + 无 evidence 仍须标（判据不得放空）。"""
    e = {"subagent_id": "s", "task": TASK, "conclusion": "ok", "evidence": [],
         "findings": {}, "challenges": [], "verdicts": {}, "kept": [], "slashed": [],
         "seven_dim_score": {}}
    flags = M._suspect_flags(e)
    assert "no_evidence" in flags, f"零实质无证据条目漏标 no_evidence：{flags}"


def test_non_substantive_budget_still_flagged():
    """负臂：真零实质 + budget_hard 仍须标。"""
    e = {"subagent_id": "s", "task": TASK, "conclusion": "ok", "evidence": [],
         "findings": {}, "challenges": [], "verdicts": {}, "kept": [], "slashed": [],
         "seven_dim_score": {}, "budget_status": "hard"}
    assert "budget_hard" in M._suspect_flags(e)


def test_evidence_present_no_no_evidence_flag():
    """守卫：有 evidence ⟹ 从不标 no_evidence（零回归）。"""
    e = _pr_entry()
    e["evidence"] = [{"file": "f", "lines": "1", "status": "confirmed"}]
    assert "no_evidence" not in M._suspect_flags(e)


# ── N3（RC4）：任务行须可区分（head+tail，不塌缩为同一 200 字前缀）──────────

_LONG_PREFIX = "plan-refinement: %s — " % PLAN + "说明文字" * 60  # 前缀 > 200 字符


def _state(tmp_path, tasks):
    p = tmp_path / ".gatekeeper.state"
    p.write_text(json.dumps({"gate_data": {"subagent_history": [
        {"subagent_id": "s%d" % i, "task": t, "conclusion": "cc" * 200,
         "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]}
        for i, t in enumerate(tasks)]}}), encoding="utf-8")
    return str(p)


def test_task_display_distinguishes_long_tasks():
    a = M._task_display(_LONG_PREFIX + " A组-区分甲")
    b = M._task_display(_LONG_PREFIX + " B组-区分乙")
    assert a != b, ("超长任务显示塌缩为同一前缀（区分信息在尾部被截）", a, b)
    assert "区分甲" in a and "区分乙" in b, (a, b)


def test_task_display_short_unchanged():
    assert M._task_display("短任务 x") == "短任务 x"


def test_render_md_task_lines_differ(tmp_path):
    sf = _state(tmp_path, [_LONG_PREFIX + " A组-区分甲", _LONG_PREFIX + " B组-区分乙"])
    md = M.render_md(M.aggregate(sf, None, None, plan=PLAN))
    lines = [ln for ln in md.splitlines() if ln.startswith("- 任务:")]
    assert len(lines) == 2 and lines[0] != lines[1], ("两臂任务行逐字相同 ⟹ 归属塌缩", lines)

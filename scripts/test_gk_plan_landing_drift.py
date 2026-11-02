"""test_gk_plan_landing_drift.py — ECC-PLAND 落刀漂移检测器 **红先臂**（主 agent 写）
================================================================================
`check_plan_landing_drift` 尚未实装 ⟹ 本文件对 HEAD **必红**（`getattr` 返 None）。
落刀方（coder）使之转绿后方可验收。族脚手架 = `references/agent-families/F-ECC-PLAND.json`。

契约（设计权威源 = docs/plans/2026-10-04-plan-landing-drift-detector-plan.md §2）：
  `gk_doc_align.check_plan_landing_drift(skill_dir) -> dict`
    {"check": "plan_landing_drift", "status": ..., "items": [{"plan","t_item","target","verdict"}], ...}
  verdict ∈ {landed_stale(high, 目标已存在且含落刀痕) / suspect(low) / ok(不存在)}
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gk_doc_align  # noqa: E402


def _fn():
    return getattr(gk_doc_align, "check_plan_landing_drift", None)


def _mk_plan(repo, name, body):
    d = repo / "docs" / "plans"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text("<!-- META\nphases: R-X\ntarget_repo: skill\n-->\n\n" + body, encoding="utf-8")


def test_landed_stale_is_flagged(tmp_path):
    """① 计划称 §3 T1 新增 + 目标文件已存在且含落刀痕 ⟹ `landed_stale`。"""
    repo = tmp_path
    (repo / "scripts").mkdir()
    (repo / "scripts" / "gk_new_thing.py").write_text(
        "# plandemo DRAFT-8 —— 本文件由该计划落刀\ndef new_symbol():\n    pass\n", encoding="utf-8")
    _mk_plan(repo, "plandemo.md",
             "### T1 新增检测单源\n**文件**：`scripts/gk_new_thing.py`（新增 `new_symbol`）\n")
    fn = _fn()
    assert fn is not None, "check_plan_landing_drift 未实装（红先臂，落刀后须绿）"
    res = fn(str(repo))
    verdicts = [it.get("verdict") for it in res.get("items", [])]
    assert "landed_stale" in verdicts, res


def test_suspect_target_is_low(tmp_path):
    """② 目标文件存在但无落刀痕（无计划 basename/`DRAFT-N` 注释、未定义声明符号）⟹ `suspect`。"""
    repo = tmp_path
    (repo / "scripts").mkdir()
    (repo / "scripts" / "gk_new_thing.py").write_text(
        "def someone_else_symbol():\n    pass\n", encoding="utf-8")
    _mk_plan(repo, "plandemo.md",
             "### T1 新增检测单源\n**文件**：`scripts/gk_new_thing.py`（新增 `new_symbol`）\n")
    fn = _fn()
    assert fn is not None, "check_plan_landing_drift 未实装（红先臂，落刀后须绿）"
    res = fn(str(repo))
    verdicts = [it.get("verdict") for it in res.get("items", [])]
    assert "suspect" in verdicts, res
    assert "landed_stale" not in verdicts, res


def test_absent_target_is_ok(tmp_path):
    """③ 目标文件不存在 ⟹ 不得误报 `landed_stale`。"""
    repo = tmp_path
    _mk_plan(repo, "plandemo.md", "### T1 新增\n**文件**：`scripts/nope_xyz_does_not_exist.py`\n")
    fn = _fn()
    assert fn is not None, "check_plan_landing_drift 未实装（红先臂，落刀后须绿）"
    res = fn(str(repo))
    verdicts = [it.get("verdict") for it in res.get("items", [])]
    assert "landed_stale" not in verdicts, res


def test_unasserted_t2_moves_out_of_drift(tmp_path):
    """④ T2 改口径（行为臂）：含 T2 的夹具 ⟹ T2 **不入** `drifted`、**入** `unasserted`，
    且 `anchors_total`（冻结分母）逐字不变、`tiers` 分级面不丢锚。"""
    docs = tmp_path / "docs" / "plans"
    docs.mkdir(parents=True)
    (tmp_path / "scripts").mkdir()
    body = "# 占位\nx = 1\n" * 5 + "def route():\n    return 'tier'\n"
    (tmp_path / "scripts" / "gk_demo.py").write_text(body, encoding="utf-8")
    # 裸 `path:LINE`（无声明符号绑定）⟹ keyword 漂移属 T2（无断言 content_drift）
    (docs / "p.md").write_text("见 scripts/gk_demo.py:1 的 route 语义。", encoding="utf-8")
    r = gk_doc_align.check_anchor_existence(str(tmp_path))
    assert r["anchors_total"] == 1, r              # 冻结分母逐字不变
    assert r["drifted"] == [], r                   # T2 不入漂移面
    assert len(r["unasserted"]) == 1, r            # T2 入 unasserted
    assert r["unasserted"][0]["verdict"] == "content_drift", r
    assert r["tiers"]["counts"]["total"] == 1, r   # 分级面不丢锚

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


def test_self_target_is_not_stale(tmp_path):
    """⑤ 自引：落刀点 = 计划自身 ⟹ 不得算 `landed_stale`（计划必然提到自己的文件名）。"""
    repo = tmp_path
    _mk_plan(repo, "plandemo.md",
             "| `docs/plans/plandemo.md` | 本计划自身 | — |\n\n"
             "### T1 留痕\n**文件**：`docs/plans/plandemo.md`（追加 DRAFT-2 记录）\n")
    res = _fn()(str(repo))
    assert all(it["verdict"] != "landed_stale" for it in res["items"]), res
    assert res["status"] != "WARN", res


def test_section_exclusion_is_honored(tmp_path):
    """⑥ §3 段级排除（「本版无落刀项」）与表格行同权 ⟹ 不得算落刀点。"""
    repo = tmp_path
    (repo / "scripts").mkdir()
    (repo / "scripts" / "gk_demo.py").write_text("# DRAFT-8\n", encoding="utf-8")
    _mk_plan(repo, "plandemo.md",
             "### T3 锚错防线（既有独立 doc-align；本版无落刀项）\n"
             "**文件**：`scripts/gk_demo.py`\n")
    res = _fn()(str(repo))
    assert all(it["verdict"] != "landed_stale" for it in res["items"]), res
    assert res["status"] != "WARN", res


def test_landed_marker_closes_the_warn(tmp_path):
    """⑦ 合法关单路径：计划行标「✅ 已落刀 <日期>」⟹ verdict=`ok_landed`（不再 landed_stale）。"""
    repo = tmp_path
    (repo / "scripts").mkdir()
    (repo / "scripts" / "gk_new_thing.py").write_text(
        "# plandemo\ndef new_symbol():\n    pass\n", encoding="utf-8")
    _mk_plan(repo, "plandemo.md",
             "## 5. 落刀点表\n\n| 落刀点 | 状态 |\n|:--|:--|\n"
             "| `scripts/gk_new_thing.py` | **✅ 已落刀 2026-10-01** |\n")
    res = _fn()(str(repo))
    verdicts = [it["verdict"] for it in res["items"]]
    assert "ok_landed" in verdicts, res
    assert "landed_stale" not in verdicts, res


def test_draft_marker_ignored_for_docs(tmp_path):
    """⑧ `DRAFT-N` 只算**代码**文件的落刀痕；文档里的沿革叙述（DRAFT-3/4/5）不算。"""
    repo = tmp_path
    (repo / "references").mkdir()
    (repo / "references" / "note.md").write_text(
        "沿革：DRAFT-3 → DRAFT-5 已修。\n", encoding="utf-8")
    _mk_plan(repo, "plandemo.md", "| `references/note.md` | 登记条文 | — |\n")
    res = _fn()(str(repo))
    assert "landed_stale" not in [it["verdict"] for it in res["items"]], res


def test_exclusion_column_does_not_hide_landing_point(tmp_path):
    """⑨ 三列表的**排除面列**（第三格）写「不动」= 声明不改别人的面，**不**代表本行不是落刀点。

    病灶（2026-11-12 实测）：`_plan_excluded` 对整行做关键词过滤 ⟹
    `| gatekeeper-cli.sh（新增 mcp 子命令段） | 统一入口 | **不动** PROTECTED_REGION |`
    被整行跳过 ⟹ 真落刀点变**假阴性**（09-29 的 MCP CLI 入口因此从未被报）。
    """
    repo = tmp_path
    (repo / "scripts").mkdir()
    (repo / "scripts" / "gatekeeper-cli.sh").write_text(
        "# plandemo DRAFT-8\n", encoding="utf-8")
    _mk_plan(repo, "plandemo.md",
             "| 落刀点 | 覆盖 | 排除面（不改） |\n|:--|:--|:--|\n"
             "| `scripts/gatekeeper-cli.sh` | 统一入口 | **不动** 其他任何一行 |\n")
    res = _fn()(str(repo))
    items = [it for it in res["items"] if it["target"] == "scripts/gatekeeper-cli.sh"]
    assert items, res
    assert items[0]["verdict"] == "landed_stale", items


def test_exclusion_cell_still_skips_row(tmp_path):
    """⑩ 守护：两列表的**覆盖列**写「不改」⟹ 该行确为排除面，仍须跳过（不得因修假阴性而回退）。"""
    repo = tmp_path
    (repo / "scripts").mkdir()
    (repo / "scripts" / "gk_demo.py").write_text("# plandemo DRAFT-8\n", encoding="utf-8")
    _mk_plan(repo, "plandemo.md",
             "| 落刀点 | 改动 |\n|:--|:--|\n"
             "| `scripts/gk_demo.py` | **不改** 既有判定 |\n")
    res = _fn()(str(repo))
    assert [it for it in res["items"] if it["target"] == "scripts/gk_demo.py"] == [], res


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

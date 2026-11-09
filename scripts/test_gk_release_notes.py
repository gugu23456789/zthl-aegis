"""test_gk_release_notes.py — 发布说明生成 + 两轮机检的红先臂（2026-11-08）。

背景：v0.9.8.2 手写说明漏掉此前四十余个 commit，且容易把**计划/草案**写成已落地。
本工具把「从 git 历史提取事实」与两道检测固化；本文件锁住四条行为：

  A. `generate`：`docs/` 独占的 commit 归入「计划与内部文档」段（不混进变更）；
     触碰 `docs/plans/` 的 commit 标 `[计划]`。
  B. C1：公开面禁词（内部论文仓路径 / 本机绝对路径）⟹ 违规。
  C. C2：「已完成/已落地」与「计划/草案」同行 ⟹ 违规（计划 ≠ 已实施）。
  D. C3：覆盖缺口只作提示（不阻断），且真跑 git 端到端可用。
"""
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_release_notes as R


def _commit(sha, subject, files):
    public = [f for f in files if not f.startswith("docs/")]
    return {
        "sha": sha, "subject": subject,
        "type": R._split_subject(subject)[0],
        "scope": R._split_subject(subject)[1],
        "text": R._split_subject(subject)[2],
        "files": files, "public_files": public,
        "internal_only": bool(files) and not public,
        "touches_plan": any(f.startswith("docs/plans/") for f in files),
    }


def test_generate_separates_internal_and_marks_plan():
    commits = [
        _commit("aaaa1111", "feat(gate): 新增主树只读闸", ["scripts/pre_tool_hook.py"]),
        _commit("bbbb2222", "docs(plan): gk-sdk/1 落 R21",
                ["docs/plans/sdk.md", "references/sdk.md"]),
        _commit("cccc3333", "docs(analysis): 第五轮复评归档", ["docs/analysis/r5.md"]),
    ]
    text = R.generate(commits, version="v0.9.8.3")
    head, _, tail = text.partition("## 计划与内部文档")
    assert "新增主树只读闸" in head, "公开面变更未进正文"
    assert "`[计划]`" in head, "公开面 commit 若同时动 docs/plans 须标 [计划]"
    assert "第五轮复评归档" in tail and "第五轮复评归档" not in head, \
        "docs 独占 commit 混进了对外变更段"
    assert "不随公开包发布" in tail, "计划段缺发布面说明"


def test_c1_forbidden_token_is_violation():
    text = "# 说明\n\n见 <home>/proj 与 " + "papers/" + "www2027 目录。\n"
    rep = R.check_notes(text, [])
    rules = {v["rule"] for v in rep["violations"]}
    assert "C1" in rules and not rep["ok"], rep


def test_c2_plan_written_as_done_is_violation():
    bad = "# 说明\n\n- SDK 计划已完成 R21 实施。\n"
    rep = R.check_notes(bad, [])
    assert any(v["rule"] == "C2" for v in rep["violations"]), rep
    good = "# 说明\n\n- SDK 计划推进到 R21，复评未收敛，未进入实施。\n"
    assert R.check_notes(good, [])["ok"], "合规表述被误判"


def test_c3_gap_is_advice_not_failure():
    commits = [_commit("dddd4444", "feat(x): 完全没写进说明的变更", ["scripts/a.py"])]
    rep = R.check_notes("# 说明\n\n- 别的变更。\n", commits)
    assert rep["ok"], "C3 不应阻断"
    assert rep["coverage_missing"], "覆盖缺口未被记录"
    assert any("C3" in a for a in rep["advice"])


def test_generate_end_to_end_on_real_repo(tmp_path):
    """真跑 git：建仓 → 两个 commit（一公开一 docs 独占）→ generate 落盘。"""
    repo = tmp_path / "r"
    repo.mkdir()
    g = lambda *a: subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True)
    g("init", "-q", "-b", "main")
    (repo / "a.py").write_text("x", encoding="utf-8")
    g("add", "a.py")
    g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "chore: init")
    root_sha = g("rev-list", "--max-parents=0", "HEAD").stdout.strip()
    (repo / "a.py").write_text("y", encoding="utf-8")
    g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "feat(a): 首条", "-a")
    (repo / "docs" / "plans").mkdir(parents=True)
    (repo / "docs" / "plans" / "p.md").write_text("# p\n", encoding="utf-8")
    g("add", "docs/plans/p.md")
    g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "docs(plan): 计划稿")
    out = tmp_path / "n.md"
    assert R.main(["generate", "--from", root_sha, "--version", "vX", "--out", str(out),
                   "--repo", str(repo)]) == 0
    text = out.read_text(encoding="utf-8")
    assert "首条" in text and "计划稿" in text
    assert "计划与内部文档" in text

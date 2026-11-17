"""test_gk_release_notes.py — 发布说明生成 + 两轮机检的红先臂（2026-11-08）。

背景：v0.9.8.2 手写说明漏掉此前四十余个 commit，且容易把**计划/草案**写成已落地。
本工具把「从 git 历史提取事实」与两道检测固化；本文件锁住四条行为：

  A. `generate`：`docs/` 独占的 commit 归入「计划与内部文档」段（不混进变更）；
     触碰 `docs/plans/` 的 commit 标 `[计划]`。
  B. C1：公开面禁词（内部论文仓路径 / 本机绝对路径）⟹ 违规。
  C. C2：「已完成/已落地」与「计划/草案」同行 ⟹ 违规（计划 ≠ 已实施）。
  D. C3：覆盖缺口只作提示（不阻断），且真跑 git 端到端可用。
"""
import json
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


# ── 2026-11-16：C4 数字回环（说明声明的「N 个提交」必须与 git 实测一致）──────────
def _repo_n_commits(tmp_path, n, tag="v1"):
    """建仓：1 个基线提交 + 打 tag + n 个后续提交。"""
    repo = tmp_path / "r"
    repo.mkdir()
    g = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True,
                                  capture_output=True, text=True)
    g("init", "-q", "-b", "master")
    (repo / "seed.txt").write_text("seed", encoding="utf-8")
    g("add", "seed.txt")
    g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "chore: init")
    g("tag", tag)
    for i in range(n):
        (repo / ("f%d.txt" % i)).write_text(str(i), encoding="utf-8")
        g("add", ".")
        g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "feat: c%d" % i)
    (repo / "docs").mkdir(exist_ok=True)      # 私仓判据：`docs/` 随包 ⟹ C4 生效
    return repo


def test_c4_count_matches_is_clean(tmp_path):
    repo = _repo_n_commits(tmp_path, 3)
    assert R.verify_commit_count("覆盖 3 个提交", "v1", "HEAD", cwd=str(repo)) is None


def test_c4_count_mismatch_blocks(tmp_path):
    """病象复刻：v0.10.0 说明写 171，实测 246 ⟹ 必须判 C4。"""
    repo = _repo_n_commits(tmp_path, 3)
    v = R.verify_commit_count("覆盖 5 个提交", "v1", "HEAD", cwd=str(repo))
    assert v and v["rule"] == "C4" and "说明写 5" in v["detail"], v


def test_c4_cli_exit1_on_mismatch(tmp_path):
    """端到端：check --from <tag> 在数字不符时 rc=1 且打印 C4。"""
    repo = _repo_n_commits(tmp_path, 3)
    notes = tmp_path / "RELEASE-NOTES-v9.9.9.md"
    notes.write_text("# X\n\n> 覆盖 9 个提交\n", encoding="utf-8")
    p = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                     "gk_release_notes.py"),
                        "check", "--notes", str(notes), "--from", "v1", "--repo", str(repo)],
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 1, p.stdout + p.stderr
    assert "C4" in p.stdout


def test_c4_skipped_in_export_tree(tmp_path):
    """公开导出树（无 `docs/`）不跑 C4 —— 镜像仓的提交数不是私有口径。"""
    import shutil
    repo = _repo_n_commits(tmp_path, 3)
    shutil.rmtree(repo / "docs")
    notes = tmp_path / "RELEASE-NOTES-v9.9.9.md"
    notes.write_text("# X\n\n> 覆盖 9 个提交\n", encoding="utf-8")
    p = subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                     "gk_release_notes.py"),
                        "check", "--notes", str(notes), "--from", "v1", "--repo", str(repo)],
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "C4" not in p.stdout


# ── 2026-11-16：三节自动填充（性能红利 / 架构进化 / 安全哲学）+ C5 锚点 ──────────
def _fixture_repo(tmp_path, invariants=None, entrypoint="scripts/gk_demo.py"):
    """登记表 + 基线 + 一个入口脚本（锚点符号写在脚本里）。"""
    repo = tmp_path
    (repo / "references").mkdir(exist_ok=True)
    (repo / "scripts").mkdir(exist_ok=True)
    (repo / "scripts" / "gk_demo.py").write_text("ANCHOR = 1\n", encoding="utf-8")
    (repo / "references" / "bench-baseline.json").write_text(json.dumps({
        "git_head": "deadbeefcafe", "stale_after_commits": 150,
        "benchmarks": {"state": {"scenarios": [{"scenario": "s"}]},
                       "gate": {"scenarios": [{"scenario": "g"}]},
                       "satellite": {"scenarios": []}}}), encoding="utf-8")
    (repo / "references" / "mechanism-registry.json").write_text(json.dumps({
        "schema": "gk-mechanism-registry/1",
        "mechanisms": [{"id": "demo", "title": "演示", "doc": "references/demo.md",
                        "entrypoints": [entrypoint], "cli": [], "tests": []}],
        "security_invariants": invariants if invariants is not None else [{
            "id": "single-entry", "claim": "锚点必须在活代码里",
            "proof": {"file": "scripts/gk_demo.py", "symbol": "ANCHOR"}}],
    }, ensure_ascii=False), encoding="utf-8")
    return repo


def _doc_commit(files):
    return _commit("eeee5555", "docs(ref): 正本补写", files)


def test_perf_section_says_no_change_when_perf_modules_untouched(tmp_path):
    repo = _fixture_repo(tmp_path)
    out = "\n".join(R.section_perf([_doc_commit(["references/demo.md"])], str(repo)))
    assert "无变化" in out and "性能面机制模块" in out, out
    assert "deadbeef" in out, out


def test_perf_section_ignores_non_perf_scripts(tmp_path):
    """文档工具脚本（非性能面）改动不得触发「重采基线」——口径单源 = bench 机制模块表。"""
    repo = _fixture_repo(tmp_path)
    (repo / "scripts" / "gk_demo_other.py").write_text("X = 1\n", encoding="utf-8")
    out = "\n".join(R.section_perf([_doc_commit(["scripts/gk_demo_other.py"])], str(repo)))
    assert "无变化" in out and "重采基线" not in out, out


def test_perf_section_demands_rebaseline_when_scripts_touched(tmp_path):
    repo = _fixture_repo(tmp_path)
    out = "\n".join(R.section_perf([_doc_commit(["scripts/gk_demo.py"])], str(repo)))
    assert "重采基线" in out and "`scripts/gk_demo.py`" in out, out


def test_perf_section_refuses_numbers_without_baseline(tmp_path):
    repo = _fixture_repo(tmp_path)
    (repo / "references" / "bench-baseline.json").unlink()
    out = "\n".join(R.section_perf([], str(repo)))
    assert "不给数字" in out, out


def test_arch_section_names_touched_mechanism(tmp_path):
    repo = _fixture_repo(tmp_path)
    out = "\n".join(R.section_arch([_doc_commit(["scripts/gk_demo.py"])], str(repo)))
    assert "`demo`" in out and "references/demo.md" in out, out


def test_arch_section_says_no_mechanism_change(tmp_path):
    repo = _fixture_repo(tmp_path)
    out = "\n".join(R.section_arch([_doc_commit(["references/demo.md"])], str(repo)))
    assert "无机制面演进" in out, out


def test_security_section_marks_missing_anchor_and_c5_blocks(tmp_path):
    repo = _fixture_repo(tmp_path)
    (repo / "scripts" / "gk_demo.py").write_text("OTHER = 2\n", encoding="utf-8")
    out = "\n".join(R.section_security(str(repo)))
    assert "锚点缺失" in out, out
    bad = R.check_invariant_anchors(out, str(repo))
    assert bad and bad[0]["rule"] == "C5", bad
    # 修复锚点后 C5 放行
    (repo / "scripts" / "gk_demo.py").write_text("ANCHOR = 1\n", encoding="utf-8")
    assert R.check_invariant_anchors(out, str(repo)) == []


def test_c5_real_registry_anchors_all_valid():
    """仓内登记表的不变式锚点必须真实存在（否则本版说明无法自动填充）。"""
    sd = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    text = "\n".join(R.section_security(sd))
    assert "锚点缺失" not in text, text
    assert R.check_invariant_anchors(text, sd) == []

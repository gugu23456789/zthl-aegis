"""合并退化防护（2026-11-13）：旧分支 / 删除文件 / 合并冲突必须在 merge 前 BLOCK。"""
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_merge_guard as G  # noqa: E402


def _git(repo, *args):
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    assert r.returncode == 0, (args, r.stdout, r.stderr)
    return r


def _repo(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-b", "master")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    return repo


def _commit(repo, name, text):
    (Path(repo) / name).write_text(text, encoding="utf-8")
    _git(repo, "add", name)
    _git(repo, "commit", "-m", "add " + name)


def test_safe_diverged_merge(tmp_path):
    repo = _repo(tmp_path)
    _commit(repo, "a.txt", "a\n")
    _git(repo, "checkout", "-b", "feat")
    _commit(repo, "b.txt", "b\n")
    _git(repo, "checkout", "master")
    _commit(repo, "c.txt", "c\n")
    out = G.check(str(repo), "feat", "master")
    assert out["ok"] and out["decision"] == "SAFE", out


def test_source_behind_blocks(tmp_path):
    repo = _repo(tmp_path)
    _commit(repo, "a.txt", "a\n")
    _git(repo, "checkout", "-b", "feat")
    _git(repo, "checkout", "master")
    _commit(repo, "b.txt", "b\n")
    out = G.check(str(repo), "feat", "master")
    assert not out["ok"] and out["reasons"][0]["code"] == "SOURCE_BEHIND_TARGET", out


def test_source_delete_target_file_blocks(tmp_path):
    repo = _repo(tmp_path)
    _commit(repo, "a.txt", "a\n")
    _commit(repo, "b.txt", "b\n")
    _git(repo, "checkout", "-b", "feat")
    _git(repo, "rm", "b.txt")
    _git(repo, "commit", "-m", "delete b")
    out = G.check(str(repo), "feat", "master")
    assert not out["ok"] and out["reasons"][0]["code"] == "MERGE_DELETES_TARGET_FILES", out
    assert out["deleted_by_source"] == ["b.txt"], out


def test_equivalent_only_warns(tmp_path):
    """source 的独有提交在 target 已有等价补丁 ⟹ WARN SOURCE_EQUIVALENT_ONLY（勿 merge）。"""
    repo = _repo(tmp_path)
    _commit(repo, "a.txt", "a\n")
    _git(repo, "checkout", "-b", "feat")
    _commit(repo, "b.txt", "b\n")
    _git(repo, "checkout", "master")
    _commit(repo, "c.txt", "c\n")           # 先加一个 master 独有提交，避免 cherry-pick 同 hash
    _git(repo, "cherry-pick", "feat")       # 同补丁、不同 hash
    out = G.check(str(repo), "feat", "master")
    assert out["ok"] and out["decision"] == "WARN", out
    assert any(r["code"] == "SOURCE_EQUIVALENT_ONLY" for r in out["reasons"]), out


def test_already_merged(tmp_path):
    repo = _repo(tmp_path)
    _commit(repo, "a.txt", "a\n")
    out = G.check(str(repo), "master", "master")
    assert out["ok"] and out["decision"] == "ALREADY_MERGED", out


def test_sim_asymmetry_warns_not_blocks(tmp_path, monkeypatch):
    """2026-11-13 ECC-MERGE-SIM-SYM：仅**单向** merge-file 冲突 ⟹ WARN（不得 BLOCK）。

    实测形态：`ours=master` 方向报冲突，而 `git merge` 实际可自动合并。旧实现据此直接
    BLOCK（假阳性，真仓曾误拦一次）。判据改为双向复算：只有两向都冲突才算真冲突。
    """
    repo = _repo(tmp_path)
    (repo / "a.txt").write_text("l1\nl2\nl3\nl4\nl5\n", encoding="utf-8")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-m", "base")
    _git(repo, "checkout", "-b", "feat")
    (repo / "a.txt").write_text("FEAT1\nl2\nl3\nl4\nl5\n", encoding="utf-8")
    _git(repo, "commit", "-am", "feat edit")
    _git(repo, "checkout", "master")
    (repo / "a.txt").write_text("l1\nl2\nl3\nl4\nMASTER5\n", encoding="utf-8")
    _git(repo, "commit", "-am", "master edit")

    real = G._simulate_merge

    def fake(r, b, ours, theirs, p):
        if p == "a.txt" and ours == "master":
            return "conflict\n", True      # 仅 master 方向假阳性
        return real(r, b, ours, theirs, p)

    monkeypatch.setattr(G, "_simulate_merge", fake)
    out = G.check(str(repo), "feat", "master")
    assert out["ok"] and out["decision"] == "WARN", out
    assert any(x["code"] == "MERGE_SIM_ASYMMETRY" for x in out["reasons"]), out


def test_merge_conflict_blocks(tmp_path):
    repo = _repo(tmp_path)
    _commit(repo, "a.txt", "base\n")
    _git(repo, "checkout", "-b", "feat")
    (repo / "a.txt").write_text("feat\n", encoding="utf-8")
    _git(repo, "commit", "-am", "feat edit")
    _git(repo, "checkout", "master")
    (repo / "a.txt").write_text("master\n", encoding="utf-8")
    _git(repo, "commit", "-am", "master edit")
    out = G.check(str(repo), "feat", "master")
    assert not out["ok"] and out["reasons"][0]["code"] == "MERGE_CONFLICT", out


# ── 2026-11-13 扩展为「标准化合并前置闸」的红先臂 ────────────────────────────────

def test_clean_both_changed_merge_not_blocked(tmp_path):
    """同文件双改但**可干净合并** ⟹ SAFE（回归旧实现的 "changed in both" 假阳性）。

    旧 fallback 把旧 `merge-tree` 的 "changed in both" 当冲突 ⟹ 任何双方都改过同一文件的
    正常合并都被 BLOCK（恒假阳性）。
    """
    repo = _repo(tmp_path)
    (repo / "a.txt").write_text("l1\nl2\nl3\nl4\nl5\n", encoding="utf-8")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-m", "base")
    _git(repo, "checkout", "-b", "feat")
    (repo / "a.txt").write_text("FEAT1\nl2\nl3\nl4\nl5\n", encoding="utf-8")
    _git(repo, "commit", "-am", "feat edit l1")
    _git(repo, "checkout", "master")
    (repo / "a.txt").write_text("l1\nl2\nl3\nl4\nMASTER5\n", encoding="utf-8")
    _git(repo, "commit", "-am", "master edit l5")
    out = G.check(str(repo), "feat", "master")
    assert out["ok"] and out["decision"] == "SAFE", out


def _prot_file(n=6):
    return ("#!/bin/bash\n"
            "# PROTECTED_REGION_START::gate\n"
            + "".join("guard_line_%d\n" % i for i in range(n))
            + "# PROTECTED_REGION_END::gate\necho ok\n")


def test_protected_region_shrink_blocks(tmp_path):
    """合并削弱受保护区 ⟹ BLOCK（门禁自举面被带回旧形态）。"""
    repo = _repo(tmp_path)
    (repo / "g.sh").write_text(_prot_file(6), encoding="utf-8")
    _git(repo, "add", "g.sh")
    _git(repo, "commit", "-m", "base")
    _git(repo, "checkout", "-b", "feat")
    (repo / "g.sh").write_text(_prot_file(3), encoding="utf-8")   # 删掉 3 行守卫
    _git(repo, "commit", "-am", "drop guards")
    _git(repo, "checkout", "master")
    _commit(repo, "other.txt", "x\n")
    out = G.check(str(repo), "feat", "master")
    assert not out["ok"], out
    # git<2.38 会先记一条 MERGE_TREE_FALLBACK（信息项），故按 code 找而非取首条
    r = next(x for x in out["reasons"] if x["code"] == "PROTECTED_REGION_SHRINK")
    assert r["regions"][0]["lost_lines"] == 3, out


def test_facts_rebuild_required_warns(tmp_path):
    """合并触达事实源 ⟹ WARN + next（合并后必须重算 GK-FACTS）。"""
    repo = _repo(tmp_path)
    (repo / "gatekeeper-cli.sh").write_text("echo a\n", encoding="utf-8")
    _git(repo, "add", "gatekeeper-cli.sh")
    _git(repo, "commit", "-m", "base")
    _git(repo, "checkout", "-b", "feat")
    (repo / "gatekeeper-cli.sh").write_text("echo a\necho b\n", encoding="utf-8")
    _git(repo, "commit", "-am", "cli change")
    _git(repo, "checkout", "master")
    _commit(repo, "other.txt", "x\n")
    out = G.check(str(repo), "feat", "master")
    assert out["ok"] and out["decision"] == "WARN", out
    r = next(x for x in out["reasons"] if x["code"] == "FACTS_REBUILD_REQUIRED")
    assert "gk_docgen_facts.py --write" in r["next"], r


def test_staged_deletions_block(tmp_path):
    """merge 进行中带暂存删除 ⟹ BLOCK（否则 merge 提交把它们写进历史）。

    实测事故：本仓 792 条 `docs/analysis/**` 暂存删除差点被一次 merge 提交带走。
    """
    repo = _repo(tmp_path)
    _commit(repo, "a.txt", "a\n")
    _commit(repo, "b.txt", "b\n")
    _git(repo, "rm", "--cached", "b.txt")
    out = G.check_staged_merge(str(repo))
    assert not out["ok"] and out["reasons"][0]["code"] == "STAGED_DELETIONS", out
    assert out["reasons"][0]["count"] == 1 and out["reasons"][0]["next"], out


def test_staged_deletions_allow_override(tmp_path):
    """显式 `--allow-index-deletions` ⟹ 放行但降级 WARN（留痕，不静默）。"""
    repo = _repo(tmp_path)
    _commit(repo, "a.txt", "a\n")
    _commit(repo, "b.txt", "b\n")
    _git(repo, "rm", "--cached", "b.txt")
    out = G.check_staged_merge(str(repo), allow_index_deletions=True)
    assert out["ok"] and out["decision"] == "WARN", out
    assert any(r["code"] == "STAGED_DELETIONS_ALLOWED" for r in out["reasons"]), out


def test_staged_protected_shrink_blocks(tmp_path):
    """merge 进行中把受保护区改小 ⟹ BLOCK。"""
    repo = _repo(tmp_path)
    (repo / "g.sh").write_text(_prot_file(5), encoding="utf-8")
    _git(repo, "add", "g.sh")
    _git(repo, "commit", "-m", "base")
    (repo / "g.sh").write_text(_prot_file(2), encoding="utf-8")
    out = G.check_staged_merge(str(repo))
    assert not out["ok"] and out["reasons"][0]["code"] == "PROTECTED_REGION_SHRINK", out


def test_staged_clean_passes(tmp_path):
    repo = _repo(tmp_path)
    _commit(repo, "a.txt", "a\n")
    out = G.check_staged_merge(str(repo))
    assert out["ok"] and out["decision"] == "SAFE", out


def test_staged_rename_not_treated_as_drop(tmp_path):
    """归档/移动 = git rename ⟹ 旧路径消失不算「丢路径」，闸② 必须放行。

    实测（2026-11-13）：779 份报告归档为 rename，merge 被
    MERGE_TREE_DROPS_TARGET_PATHS 假阳性挡死。
    """
    repo = _repo(tmp_path)
    _commit(repo, "a.txt", "a\n")
    (repo / "arch").mkdir()
    _git(repo, "mv", "a.txt", "arch/a.txt")
    out = G.check_staged_merge(str(repo))
    assert out["ok"], out
    assert out["dropped_paths"] == [], out
    assert "a.txt" in out.get("staged_renames", []), out


def test_every_block_carries_next(tmp_path):
    """所有 BLOCK 必须带**可执行** next（流程引导，不靠手工拼 git）。"""
    repo = _repo(tmp_path)
    _commit(repo, "a.txt", "a\n")
    _git(repo, "checkout", "-b", "feat")
    _git(repo, "checkout", "master")
    _commit(repo, "b.txt", "b\n")
    out = G.check(str(repo), "feat", "master")            # SOURCE_BEHIND_TARGET
    assert not out["ok"]
    for r in out["reasons"]:
        assert r.get("next"), r


# ── 2026-11-13 R0.24：路径归一 + 缺省主仓（防"对着 worktree 自己判已合并"的假绿）────────

def test_norm_repo_identity_and_no_guess(tmp_path):
    """可进得去的路径原样返回；进不去的**不猜**（由下游 fail-loud）。"""
    repo = _repo(tmp_path)
    assert G.norm_repo(str(repo)) == str(repo)
    assert G.norm_repo("/definitely/not/a/repo-xyz") == "/definitely/not/a/repo-xyz"


def test_default_repo_resolves_git_repo():
    """`--repo` 缺省必须解析到**装主分支的主工作树**（不是调用方 cwd）。"""
    d = G._default_repo()
    r = subprocess.run(["git", "-C", d, "rev-parse", "--git-dir"],
                       capture_output=True, text=True)
    assert r.returncode == 0, (d, r.stderr)
    assert "/worktrees/" not in d, "缺省仓不得是某个 worktree：%s" % d


def test_source_deletions_declared_warns(tmp_path):
    """source 的**预期清理**必须可显式声明：默认 BLOCK，声明后 WARN 且逐条留痕。"""
    repo = _repo(tmp_path)
    _commit(repo, "a.txt", "a\n")
    _commit(repo, "b.txt", "b\n")
    _git(repo, "checkout", "-b", "feat")
    _git(repo, "rm", "b.txt")
    _git(repo, "commit", "-m", "rm b")
    out = G.check(str(repo), "feat", "master")
    assert not out["ok"] and out["reasons"][0]["code"] == "MERGE_DELETES_TARGET_FILES", out
    out2 = G.check(str(repo), "feat", "master", allow_source_deletions=True)
    assert out2["ok"] and out2["decision"] == "WARN", out2
    assert any(r["code"] == "SOURCE_DELETIONS_DECLARED" for r in out2["reasons"]), out2

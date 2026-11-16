"""`gk_merge_cli.py --cleanup-source-remote`：合并前置闸的**对偶闸**（方案 A，2026-11-14）。

缺口：合并侧有 R0.24 闸①/闸② + 票据，但「删源远端分支」此前是裸 `git push --delete`。
本闸 = 归档（可恢复）→ 判据（保护分支 / 远端 / 检出态）→ 删除 → `ls-remote` 校验；
预检失败**连合并都不做**（fail-fast），全部在同一把单队列锁内。

臂：
  A1 正常收口（归档 ref == 源 tip；远端分支消失；verified）
  A2 关闭 flag（远端分支保留；零回归）
  A3 保护分支 / 目标同名（BLOCK 且不合并）
  A4 远端已无该分支（幂等：不删、仍归档、verified）
  A5 远端名不存在（BLOCK；不合并）
  A6 dry-run（只预检 planned=True；不合并、不删除）
"""
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import gk_merge_cli as M  # noqa: E402


def _git(repo, *args):
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    assert r.returncode == 0, "git %s failed: %s" % (" ".join(args), r.stderr)
    return r.stdout.strip()


def _mk(tmp_path):
    """最小仓 + 裸远端 + 源分支 feature/x（master 为干净基线）。"""
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=str(repo), check=True, capture_output=True)
    _git(repo, "checkout", "-b", "master")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "init")
    _git(repo, "remote", "add", "origin", str(remote))
    _git(repo, "push", "-u", "origin", "master")
    _git(repo, "checkout", "-b", "feature/x")
    (repo / "b.txt").write_text("b\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "feat")
    _git(repo, "push", "-u", "origin", "feature/x")
    _git(repo, "checkout", "master")
    return repo, remote


def _remote_heads(repo):
    return _git(repo, "ls-remote", "--heads", "origin")


@pytest.fixture()
def sandbox(tmp_path):
    return _mk(tmp_path)


def test_a1_cleanup_archives_and_deletes(sandbox):
    repo, _ = sandbox
    src_sha = _git(repo, "rev-parse", "feature/x")
    rc, out = M.run("feature/x", "master", str(repo), cleanup_source_remote=True)
    assert rc == 0 and out["decision"] == "MERGED", out
    sc = out["source_cleanup"]
    assert sc["ok"] and sc["deleted"] and sc["verified"], sc
    assert sc["archived_ref"].startswith("refs/gk-archive/merged/feature/x/"), sc
    assert _git(repo, "rev-parse", sc["archived_ref"]) == src_sha
    assert "refs/heads/feature/x" not in _remote_heads(repo)


def test_a2_flag_off_keeps_remote_branch(sandbox):
    repo, _ = sandbox
    rc, out = M.run("feature/x", "master", str(repo))
    assert rc == 0 and out["decision"] == "MERGED", out
    assert "source_cleanup" not in out
    assert "refs/heads/feature/x" in _remote_heads(repo)


def test_a3_protected_branch_pool_prefix_blocks(sandbox):
    repo, _ = sandbox
    _git(repo, "checkout", "-b", "gk-pool/9")
    (repo / "c.txt").write_text("c\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "pool")
    _git(repo, "push", "-u", "origin", "gk-pool/9")
    _git(repo, "checkout", "master")
    before = _git(repo, "rev-parse", "master")

    rc, out = M.run("gk-pool/9", "master", str(repo), cleanup_source_remote=True)
    assert rc == 3 and out["code"] == "SOURCE_CLEANUP_PROTECTED", out
    # 预检失败 ⟹ 连合并都不做
    assert _git(repo, "rev-parse", "master") == before
    assert "refs/heads/gk-pool/9" in _remote_heads(repo)


def test_a4_remote_branch_already_gone_is_idempotent(sandbox):
    repo, _ = sandbox
    _git(repo, "push", "origin", "--delete", "feature/x")
    rc, out = M.run("feature/x", "master", str(repo), cleanup_source_remote=True)
    assert rc == 0 and out["decision"] == "MERGED", out
    sc = out["source_cleanup"]
    assert sc["ok"] and sc["deleted"] is False and sc["verified"] is True, sc
    assert sc["archived_ref"]


def test_a5_missing_remote_blocks(sandbox):
    repo, _ = sandbox
    before = _git(repo, "rev-parse", "master")
    rc, out = M.run("feature/x", "master", str(repo),
                    cleanup_source_remote=True, remote="no-such-remote")
    assert rc == 3 and out["code"] == "SOURCE_CLEANUP_NO_REMOTE", out
    assert _git(repo, "rev-parse", "master") == before


def test_a6_dry_run_reports_plan_only(sandbox):
    repo, _ = sandbox
    before = _git(repo, "rev-parse", "master")
    rc, out = M.run("feature/x", "master", str(repo), dry_run=True,
                    cleanup_source_remote=True)
    assert rc == 0 and out["decision"] == "DRY_RUN", out
    assert out["source_cleanup"]["planned"] is True, out
    assert out["source_cleanup"]["remote_exists"] is True
    assert _git(repo, "rev-parse", "master") == before
    assert "refs/heads/feature/x" in _remote_heads(repo)

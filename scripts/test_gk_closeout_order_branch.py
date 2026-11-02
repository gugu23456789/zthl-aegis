"""B 接线红先臂（2026-10-16，owner 裁定「accept → close → 回收」+「回收含 worktree→分支」）。

  · **B-1** `--close-out`：关单**前移**到 reclaim **之前**（关单须在 worktree/分支仍在时完成）；
        逃生舱 `GK_CLOSEOUT_NO_CLOSE=1` 退回「只产 next」（零回归）。
  · **B-2** `gk_worktree_reclaim.py`：新增**分支回收**（`--branches`，判据 `_is_merged_clean`，
        未并入/有残留 ⟹ fail-closed 保留并入 `branch_guarded`）。

HEAD 必红：两处接线在 HEAD 均不存在（`branch_reclaim`/`branch_removed` 未定义 ⟹ 形态臂红、
行为臂因 `branch_guarded` 缺键而红）。
"""
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_worktree_reclaim as wr

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def _git(repo, *a):
    return subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True)


@pytest.fixture()
def repo_clean_wt(tmp_path):
    """真 git 仓 + 一个**干净且已并入**的 worktree（其分支 == 基线 HEAD）。"""
    repo = tmp_path / "main"
    repo.mkdir()
    _git(str(repo), "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("x", encoding="utf-8")
    _git(str(repo), "add", "a.txt")
    _git(str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")
    root = tmp_path / "wts"
    root.mkdir()
    wt = root / "wtc"
    _git(str(repo), "worktree", "add", "-q", "-b", "feat_clean", str(wt))
    return str(repo), str(root), str(wt)


@pytest.fixture()
def repo_dirty_wt(tmp_path):
    """真 git 仓 + 一个**有未提交残留**的 worktree（⟹ 未并入/不干净）。"""
    repo = tmp_path / "main"
    repo.mkdir()
    _git(str(repo), "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("x", encoding="utf-8")
    _git(str(repo), "add", "a.txt")
    _git(str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")
    root = tmp_path / "wts"
    root.mkdir()
    wt = root / "wtd"
    _git(str(repo), "worktree", "add", "-q", "-b", "feat_dirty", str(wt))
    (wt / "new_file.txt").write_text("残留", encoding="utf-8")
    return str(repo), str(root), str(wt)


# ── B-1 ────────────────────────────────────────────────────────────────────────
def test_arm_b1_close_comes_before_reclaim_in_closeout_block():
    """机检：`--close-out` 块内 `cmd_finding close` 必须出现在 `gk_worktree_reclaim.py` **之前**。"""
    cli = _read("gatekeeper-cli.sh")
    i = cli.index("--close-out，2026-10-16")
    block = cli[i:i + 7000]
    assert "cmd_finding close" in block, "B-1 未接：close-out 块内无关单调用"
    a = block.index("cmd_finding close")
    b = block.index("gk_worktree_reclaim.py")
    assert a < b, "B-1 时序错：关单未前移到回收之前"
    assert "GK_CLOSEOUT_NO_CLOSE" in block, "B-1 缺逃生舱 GK_CLOSEOUT_NO_CLOSE"


# ── B-2 ────────────────────────────────────────────────────────────────────────
def test_arm_b2_module_declares_branch_reclaim():
    """机检：模块须有 `branch_reclaim` 参数 + `--branches` + 两留痕键。"""
    src = _read("scripts/gk_worktree_reclaim.py")
    assert "branch_reclaim" in src, "B-2 未接：缺 branch_reclaim 参数"
    assert '"--branches"' in src, "B-2 未接：缺 --branches CLI 面"
    assert 'report["branch_removed"] = []' in src, "B-2 缺 branch_removed 初始化"
    assert 'report["branch_guarded"] = []' in src, "B-2 缺 branch_guarded 初始化"


def test_arm_b2_merged_clean_branch_is_deleted(repo_clean_wt):
    """真跑（正臂）：已并入且干净 ⟹ 分支回收。"""
    repo, root, wt = repo_clean_wt
    r = wr.reclaim(repo, root, apply=True, trash=os.path.join(root, "trash"),
                   only=[wt], branch_reclaim=True)
    assert "feat_clean" in (r.get("branch_removed") or []), ("已并入且干净的分支未回收", r)
    assert not _git(repo, "branch", "--list", "feat_clean").stdout.strip(), "分支仍在"


def test_arm_b2_dirty_branch_is_guarded_kept(repo_dirty_wt):
    """真跑（负臂）：有残留/未并入 ⟹ **fail-closed 保留**，进 branch_guarded（不误删）。"""
    repo, root, wt = repo_dirty_wt
    r = wr.reclaim(repo, root, apply=True, trash=os.path.join(root, "trash"),
                   only=[wt], branch_reclaim=True)
    assert "feat_dirty" in (r.get("branch_guarded") or []), ("残留分支未 guarded", r)
    assert _git(repo, "branch", "--list", "feat_dirty").stdout.strip(), "未合并分支被误删！"


def test_arm_b2_opt_in_default_keeps_branch(repo_clean_wt):
    """真跑（opt-in）：未传 `--branches` ⟹ 分支回收为零（与 HEAD 行为一致）。"""
    repo, root, wt = repo_clean_wt
    r = wr.reclaim(repo, root, apply=True, trash=os.path.join(root, "trash"), only=[wt])
    assert not (r.get("branch_removed") or []), "非 opt-in 竟然回收了分支"
    assert _git(repo, "branch", "--list", "feat_clean").stdout.strip(), "非 opt-in 分支被删"

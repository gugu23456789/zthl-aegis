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


def test_arm_b2_cli_forwards_branches_in_multi_flag_form():
    """2026-11-08 实测缺口：`apply-worktree --reclaim --branches` 在**第二解析循环**里
    被 unknown arg 拒绝（usage 也没有该 flag）⟹ 回收链的标准用法打不通。本条锁两处。"""
    cli = _read("gatekeeper-cli.sh")
    assert cli.count('--branches) reclaim_branches="1"') >= 2, \
        "apply-worktree 解析只接了一处 --branches（多 flag 形态仍会 unknown arg）"
    assert "[--path <dir>]... [--branches] [--all-branches] [--apply] [--all]" in cli, \
        "usage 未登记 --branches/--all-branches（且 --path 未标注可重复）"


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


# ── B-3（2026-11-08，owner 裁定「合并回收所有工作区分支」）──────────────────────────
#   病象：worktree 面只回收其挂载分支；长期残留的「已并入 / patch 等价」分支**无回收通路**，
#   而门禁 R0.17 已拦裸 `git branch -d|-D` ⟹ 标准通道必须覆盖，否则通道干不了活。
def _branches(repo):
    return _git(repo, "branch", "--list", "--format=%(refname:short)").stdout.split()


@pytest.fixture()
def repo_loose_branches(tmp_path):
    """main + 三类游离分支：已并入 / patch 等价（cherry 全 `-`） / 独有提交。"""
    repo = tmp_path / "main"
    repo.mkdir()
    _git(str(repo), "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("x", encoding="utf-8")
    _git(str(repo), "add", "a.txt")
    _git(str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")
    _git(str(repo), "branch", "feat_merged")                       # 已并入（== main）
    _git(str(repo), "checkout", "-q", "-b", "feat_applied")        # patch 等价：本支提交后
    (repo / "b.txt").write_text("y", encoding="utf-8")
    _git(str(repo), "add", "b.txt")
    _git(str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "add-b")
    _git(str(repo), "checkout", "-q", "main")
    _git(str(repo), "cherry-pick", "--no-commit", "feat_applied")  # 同补丁落到 main（不同 sha）
    _git(str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "add-b-main")
    _git(str(repo), "checkout", "-q", "-b", "feat_unique")
    (repo / "c.txt").write_text("z", encoding="utf-8")
    _git(str(repo), "add", "c.txt")
    _git(str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "add-c")
    _git(str(repo), "checkout", "-q", "main")
    return str(repo)


def test_arm_b3_dry_run_reports_without_deleting(repo_loose_branches):
    """dry-run（零写）：只报 would_remove；分支一个不少。"""
    repo = repo_loose_branches
    r = wr.sweep_loose_branches(repo, repo, apply=False)
    assert {"feat_merged", "feat_applied"} <= set(r["would_remove"]), r
    assert r["guarded"] == ["feat_unique"], r
    assert "main" in r["checked_out"], r
    for b in ("feat_merged", "feat_applied", "feat_unique"):
        assert _git(repo, "branch", "--list", b).stdout.strip(), "dry-run 竟然删了分支 " + b


def test_arm_b3_apply_deletes_merged_and_applied_keeps_unique(repo_loose_branches):
    """真跑：已并入 + patch 等价 ⟹ 回收；独有提交 ⟹ fail-closed 保留并留痕。"""
    repo = repo_loose_branches
    r = wr.sweep_loose_branches(repo, repo, apply=True)
    assert {"feat_merged", "feat_applied"} <= set(r["removed"]), r
    assert r["guarded"] == ["feat_unique"], r
    left = set(_branches(repo))
    assert "feat_unique" in left and "main" in left, "误删：独有分支/主分支被回收"
    assert "feat_merged" not in left and "feat_applied" not in left, "应删未删"


def test_arm_b3_reclaim_wires_all_branches_dry_run(repo_loose_branches):
    """接线：`reclaim(all_branches=True)` 的 dry-run 须把游离面透到四个分键。"""
    repo = repo_loose_branches
    r = wr.reclaim(repo, "", apply=False, all_branches=True)
    assert {"feat_merged", "feat_applied"} <= set(r["loose_branch_would_remove"]), r
    assert r["loose_branch_guarded"] == ["feat_unique"], r
    assert r["loose_branch_removed"] == [], "dry-run 竟有已删项"


def test_arm_b3_cli_forwards_all_branches_and_repeated_path():
    """机检：CLI 两处解析循环都认 `--all-branches`；`--path` 须累积为数组并逐条透传。"""
    cli = _read("gatekeeper-cli.sh")
    assert cli.count('--all-branches) reclaim_all_branches="1"') >= 2, \
        "apply-worktree 解析只接了一处 --all-branches（多 flag 形态会 unknown arg）"
    assert '[--path <dir>]... [--branches] [--all-branches]' in cli, "usage 未登记新 flag"
    assert 'reclaim_paths+=("${2:-}")' in cli, "--path 未累积（第二条会覆盖第一条）"
    assert 'for _rp in "${reclaim_paths[@]}"' in cli, "多 --path 未逐条透传"
    assert '[ "$reclaim_all_branches" = "1" ] && _rc_args+=(--all-branches)' in cli, \
        "reclaim 未透传 --all-branches"

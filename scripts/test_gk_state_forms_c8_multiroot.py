"""c8 红先臂：`gk_state_forms` **扩多根**（加性）—— worktree 内域 state 可见（§18.2 #8 / 遗漏④）。

HEAD 必红：`iter_live_states(skill_dir)` **只扫传入根**（无 `extra_roots`）⟹ `TypeError`；
且无 `worktree_state_roots` 辅助 ⟹ `AttributeError`。

判据（`2026-09-28-git-concurrency-lease-declare-plan.md` §18.2 #8）：域 state 建在 worktree 内时
`audit --state` 活体盘点须命中；扩根**加性**（原单根行为为其子集）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_state_forms as gsf


def _mk(p, body='{"stage":"IDLE"}'):
    p.write_text(body, encoding="utf-8")


def test_c8_multi_root_hits_worktree_domain_state(tmp_path):
    skill = tmp_path / "skill"
    skill.mkdir()
    _mk(skill / ".gatekeeper.state")
    wt = tmp_path / "wt"
    wt.mkdir()
    _mk(wt / ".gatekeeper.state.myrepo.plan")
    single = list(gsf.iter_live_states(str(skill)))
    assert all(str(wt) not in p for p in single), "单根不应含 worktree（原行为）"
    multi = list(gsf.iter_live_states(str(skill), extra_roots=[str(wt)]))
    assert any(p.endswith(".gatekeeper.state.myrepo.plan") for p in multi), \
        "多根未命中 worktree 内域 state（c8 未落）：%r" % (multi,)
    assert str(skill / ".gatekeeper.state") in multi, "扩根须**加性**（单根为其子集）"


def test_c8_helper_finds_worktree_state_roots(tmp_path):
    """辅助 `worktree_state_roots`：从 skill_dir 派生 worktree 盘点根（标准布局）。"""
    parent = tmp_path / ".trae"
    skill = parent / "skills" / "myskill"
    skill.mkdir(parents=True)
    _mk(skill / ".gatekeeper.state")
    wt = parent / "worktrees" / "myskill" / "agent" / "session" / "abc"
    wt.mkdir(parents=True)
    _mk(wt / ".gatekeeper.state")
    roots = gsf.worktree_state_roots(str(skill))
    assert str(wt) in roots, roots


def test_c8_helper_depth_bound_default(tmp_path):
    """2026-10-31 perf：默认深度上限 3 —— depth 2/3 命中，depth 4 不再无界遍历。"""
    parent = tmp_path / ".trae"
    skill = parent / "skills" / "myskill"
    skill.mkdir(parents=True)
    base = parent / "worktrees" / "myskill"
    d2 = base / "feature" / "x"
    d3 = base / "agent" / "task" / "run"
    d4 = d3 / "deep"
    for d in (d2, d3, d4):
        d.mkdir(parents=True)
        _mk(d / ".gatekeeper.state")
    roots = gsf.worktree_state_roots(str(skill))
    assert str(d2) in roots and str(d3) in roots
    assert str(d4) not in roots, "默认深度上限 3（depth 4 只在显式放宽时命中）"


def test_c8_helper_depth_can_be_widened(tmp_path, monkeypatch):
    """安全阀：`GK_WT_STATE_MAX_DEPTH=4` 时 depth 4 的 state 仍可见（深布局可显式恢复）。"""
    parent = tmp_path / ".trae"
    skill = parent / "skills" / "myskill"
    skill.mkdir(parents=True)
    d4 = parent / "worktrees" / "myskill" / "agent" / "task" / "run" / "deep"
    d4.mkdir(parents=True)
    _mk(d4 / ".gatekeeper.state")
    monkeypatch.setenv("GK_WT_STATE_MAX_DEPTH", "4")
    assert str(d4) in gsf.worktree_state_roots(str(skill))

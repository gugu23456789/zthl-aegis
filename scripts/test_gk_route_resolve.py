"""P0-b 路由链（2026-11-13）：`pick_active_worktree` 四级优先级的红先臂。

事故背景：`reclaim` 删树后 `state.worktree` 仍指向该路径 ⟹ 写面永远落空（Edit 静默无输出）。
本组把「唯一路由链」压成纯函数，先红后绿：

    ① state.worktree —— **必须存在且在 worktrees 列表内**，否则视为失效（本次事故的判据）
    ② cwd 精确命中已注册工作树（realpath）
    ③ 未过期的池槽租约（且其 path 在列表内）
    ④ 主树（只读模式）

纪律：缓存/状态不得当事实源 —— `worktrees` 列表（来自 `git worktree list`）是权威。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_route_center as R  # noqa: E402

MAIN = "/repo/main"
WT_A = "/wt/slot-0"
WT_B = "/wt/slot-1"


def _pick(**kw):
    return R.pick_active_worktree(**kw)


def test_state_route_wins_when_alive():
    """① state 指向**存在**的树 ⟹ 采用，source=state。"""
    out = _pick(state_worktree=WT_A, cwd=WT_B, worktrees=[MAIN, WT_A, WT_B], main_repo=MAIN)
    assert out["ok"] and out["source"] == "state" and out["worktree"] == WT_A, out
    assert out["read_only"] is False


def test_dangling_state_falls_through_to_cwd():
    """本次事故形态：state 指向**已删**的树 ⟹ 不得采用，落 ② cwd。"""
    out = _pick(state_worktree="/wt/gone", cwd=WT_B, worktrees=[MAIN, WT_B], main_repo=MAIN)
    assert out["ok"] and out["source"] == "cwd" and out["worktree"] == WT_B, out
    assert out.get("stale_state") == "/wt/gone", out


def test_cwd_outside_worktrees_uses_lease():
    """② cwd 不在任何树内（工作区根的空壳目录）⟹ 落 ③ 有效租约。"""
    lease = {"path": WT_A, "expires_at": 10 ** 12}
    out = _pick(state_worktree="", cwd="/empty/workspace", worktrees=[MAIN, WT_A],
                lease=lease, main_repo=MAIN)
    assert out["ok"] and out["source"] == "lease" and out["worktree"] == WT_A, out


def test_expired_lease_is_ignored():
    """③ 租约过期 ⟹ 视为无主，落 ④ 主树（只读）。"""
    lease = {"path": WT_A, "expires_at": 1}
    out = _pick(state_worktree="", cwd="/empty", worktrees=[MAIN, WT_A],
                lease=lease, main_repo=MAIN, now=10 ** 6)
    assert out["ok"] and out["source"] == "main" and out["read_only"] is True, out


def test_no_route_is_fail_loud():
    """四级全空 ⟹ **FAIL-LOUD**（不得静默退回 cwd，否则又是悬空）。"""
    out = _pick(state_worktree="", cwd="/empty", worktrees=[], lease=None, main_repo="")
    assert out["ok"] is False and out["reason"] == "NO_ROUTE", out


def test_state_pointing_at_main_is_read_only():
    """state 指向主树 ⟹ 允许但标记 read_only（主树只读语义由下游闸执行）。"""
    out = _pick(state_worktree=MAIN, cwd="", worktrees=[MAIN], main_repo=MAIN)
    assert out["ok"] and out["source"] == "state" and out["read_only"] is True, out

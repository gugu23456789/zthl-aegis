#!/usr/bin/env python3
"""worktree 回收「路径过滤」红先臂（2026-10-01）。

**病象（本会话实测）**：`apply-worktree --reclaim --apply` **无按路径过滤** ——
dry-run 会把**并发会话**的 worktree（实测 `agent/session/b3f2421a`）与历史会话 worktree
一并列入 `WOULD-REMOVE`。回收器的语义是「本仓**全部** agent worktree」，而**并发多会话**是
常态 ⟹ 一次 `--apply` 会删掉别人正在用的工作区。本刀只加**过滤器**，不改默认语义。

**红先对照（HEAD 源码）**：
  `git show HEAD:scripts/gk_worktree_reclaim.py | grep -c 'only'` → **0**（无 `only` 形参）
  `git show HEAD:scripts/gk_worktree_reclaim.py | grep -c -- '--path'` → **0**（main 不认 `--path`）
  `git show HEAD:gatekeeper-cli.sh | grep -c 'path_arg.*_rc_args'` → **0**（CLI 不透传）
⟹ 下列臂在 HEAD 上必红。
"""
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_worktree_reclaim as wr  # noqa: E402


def _git(repo, *a):
    return subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True)


@pytest.fixture()
def repo_two_wt(tmp_path):
    """真 git 仓 + **两个** worktree（模拟「本会话」与「并发会话」）。"""
    repo = tmp_path / "main"
    repo.mkdir()
    _git(str(repo), "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("x", encoding="utf-8")
    _git(str(repo), "add", "a.txt")
    _git(str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")
    root = tmp_path / "wts"
    root.mkdir()
    mine = root / "mine"
    peer = root / "peer"
    _git(str(repo), "worktree", "add", "-q", "-b", "mine", str(mine))
    _git(str(repo), "worktree", "add", "-q", "-b", "peer", str(peer))
    return str(repo), str(root), str(mine), str(peer)


def _paths(seq):
    return {os.path.abspath(p) for p in seq}


def test_reclaim_only_restricts_candidates(repo_two_wt):
    """行为臂①：`only=[A]` ⟹ **只有 A** 进候选（items），B 进 `skipped`（**不动并发会话**）。

    HEAD：`reclaim()` 无 `only` 形参 ⟹ TypeError ⟹ 红。
    """
    repo, root, mine, peer = repo_two_wt
    r = wr.reclaim(repo, root, apply=False, only=[mine])
    assert os.path.abspath(mine) in _paths(i["path"] for i in r["items"]), "指定路径未进候选"
    assert os.path.abspath(peer) in _paths(r["skipped"]), "非指定路径未进 skipped ⟹ 有被删风险"
    assert os.path.abspath(peer) not in _paths(i["path"] for i in r["items"]), "非指定路径仍进候选"
    assert os.path.abspath(mine) not in _paths(r["skipped"]), "指定路径被误 skip"


def test_reclaim_without_only_keeps_full_scope(repo_two_wt):
    """守门臂：**不传 `only`** ⟹ 语义不变（A、B 均在候选内）。过滤器是 **opt-in**。"""
    repo, root, mine, peer = repo_two_wt
    r = wr.reclaim(repo, root, apply=False)
    cand = _paths(i["path"] for i in r["items"])
    assert os.path.abspath(mine) in cand and os.path.abspath(peer) in cand, \
        "未传 only 时收窄了范围 ⟹ 破坏既有全量语义"


def test_main_accepts_repeated_path_flag(repo_two_wt, capsys):
    """行为臂②：`main([... --path A])` 须被认（HEAD 报 `unknown arg: --path` ⟹ 红）。"""
    repo, root, mine, peer = repo_two_wt
    rc = wr.main(["--repo", repo, "--root", root, "--path", mine])
    out = capsys.readouterr().out.strip().splitlines()[-1]
    rep = json.loads(out)
    assert rc == 0 and rep.get("ok") is True, rep
    assert os.path.abspath(peer) in _paths(rep["skipped"]), "CLI 面 `--path` 未生效"


def test_cli_forwards_path_arg_into_reclaim():
    """形态臂：CLI 的 reclaim 分支须把 `--path` 透传进脚本调用（单一入口，不另起实现）。"""
    cli = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "gatekeeper-cli.sh")
    src = open(cli, encoding="utf-8").read()
    seg = src[src.index("cmd_apply_worktree() {"):]
    assert '_rc_args+=(--path "$path_arg")' in seg, "CLI 未把 --path 透传给回收器"

#!/usr/bin/env python3
"""直推 main 的「显式授权三选一」+ stage 作用域 —— 集成修复臂（2026-11-03）。

**现场**（实测，非推测）：git-workflow 的 `push push` 委托 `gatekeeper push confirm` 时被
`Direct push to 'main' blocked. This repo uses PR workflow` 拦下 —— 但该仓历史全部是直推
main（本地 10 个未推提交即证据），且它的推送根本不处在门禁仓的 R-phase 内。三处缺陷：
  ① main 判定不区分目标仓（本仓策略套到旁路仓），错误文案硬写 “uses PR workflow”；
  ② 调用方无透传授权位（只能绕到 gatekeeper CLI 敲 auth-main）；
  ③ stage 闸对**任意** --repo 生效 ⟹ 门禁 IDLE 时旁路仓永远推不上去。

覆盖（离线可跑）：
  · `test_blocked_without_authorization`  —— 无授权 ⟹ 拒推，hint 三选一齐全；
  · `test_allow_main_flag_passes`         —— `--allow-main` 放行（真推到本地裸仓）；
  · `test_allow_main_env_passes`          —— `GK_PUSH_ALLOW_MAIN=<repo>` 放行；
  · `test_stage_gate_scoped_to_own_repo`  —— stage=IDLE 时**旁路仓**照常推（原实现必红）；
  · `test_stage_gate_still_applies_to_own_repo` —— 守卫臂：本门禁仓仍被 stage 闸拦住。

离线构造：origin 与 `--push-url` 均指**本地裸仓**（`_push_auth_url` 对非 https 原样透传），
`GITHUB_TOKEN` 伪值 ⟹ 不触网；`STATE_FILE` 注入。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI = SKILL_DIR / "gatekeeper-cli.sh"
sys.path.insert(0, str(SCRIPT_DIR))


def _git(repo, *a):
    return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True)


def _cli(*args, env=None):
    e = dict(os.environ)
    e.pop("GK_PUSH_ALLOW_MAIN", None)
    e.pop("GK_MAIN_REPO", None)
    if env:
        e.update(env)
    return subprocess.run(["bash", str(CLI), *args], capture_output=True, text=True,
                          env=e, timeout=120)


def _mk_repo(tmp_path, branch="main", stage="R1"):
    bare = tmp_path / "bare.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
    repo = tmp_path / "rp"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", branch)
    (repo / "a.txt").write_text("x", encoding="utf-8")
    _git(repo, "add", "a.txt")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")
    _git(repo, "remote", "add", "origin", str(bare))
    st = tmp_path / "state.json"
    st.write_text(json.dumps({"stage": stage, "gate_data": {}}), encoding="utf-8")
    return str(repo), str(bare), str(st)


def _confirm(repo, bare, state, extra=(), env=None):
    e = {"STATE_FILE": state, "GITHUB_TOKEN": "fake-token"}
    if env:
        e.update(env)
    args = ["push", "confirm", "--repo", repo, "--branch", "main",
            "--remote", "origin", "--push-url", bare, *extra]
    return json.loads(_cli(*args, env=e).stdout)


def test_blocked_without_authorization(tmp_path):
    """无任何授权 ⟹ 拒推；hint 必须给出三条可操作路径（原实现只提 auth-main，且文案错误归因）。"""
    repo, bare, st = _mk_repo(tmp_path)
    d = _confirm(repo, bare, st)
    assert d.get("ok") is False, d
    assert d.get("error") == "Direct push to 'main' blocked by policy", d
    hint = d.get("hint") or ""
    for token in ("auth-main", "--allow-main", "GK_PUSH_ALLOW_MAIN"):
        assert token in hint, f"hint 缺 {token}：{hint}"


def test_allow_main_flag_passes(tmp_path):
    """`--allow-main` 是显式透传位 ⟹ 必须放行并真的推到本地裸仓。"""
    repo, bare, st = _mk_repo(tmp_path)
    d = _confirm(repo, bare, st, extra=("--allow-main",))
    assert d.get("ok") is True and d.get("phase") == "confirm", d
    assert _git(repo, "rev-parse", "refs/remotes/origin/main").returncode == 0


def test_allow_main_env_passes(tmp_path):
    """env 允许集按**仓库路径**命中 ⟹ 放行（不写盘、不改远端配置）。"""
    repo, bare, st = _mk_repo(tmp_path)
    d = _confirm(repo, bare, st, env={"GK_PUSH_ALLOW_MAIN": repo})
    assert d.get("ok") is True, d


def test_stage_gate_scoped_to_own_repo(tmp_path):
    """stage=IDLE 时**旁路仓**照常推：原实现对任意 --repo 都要求活跃 R-phase ⟹ 本臂必红。"""
    repo, bare, st = _mk_repo(tmp_path, stage="IDLE")
    d = _confirm(repo, bare, st, extra=("--allow-main",))
    assert d.get("ok") is True, d
    assert "R-phase" not in (d.get("error") or ""), d


def test_stage_gate_still_applies_to_own_repo(tmp_path):
    """守卫臂：`GK_MAIN_REPO` 指向的目标仓 = 本门禁仓时，stage 闸**仍然生效**（不许改宽）。"""
    repo, bare, st = _mk_repo(tmp_path, stage="IDLE")
    d = _confirm(repo, bare, st, extra=("--allow-main",), env={"GK_MAIN_REPO": repo})
    assert d.get("ok") is False, d
    assert "requires active R-phase" in (d.get("error") or ""), d

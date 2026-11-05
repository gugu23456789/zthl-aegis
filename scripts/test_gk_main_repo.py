#!/usr/bin/env python3
"""主仓路径运行时解析（2026-10-31 开源前置）—— 优先级与安全臂。"""
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_main_repo as MR  # noqa: E402


def _canon(p) -> str:
    """被测模块的规范形态 = 正斜杠（`_abs`/`_to_win` 显式归一）⟹ 断言按它比。"""
    return str(p).replace("\\", "/")


def test_env_absolute_wins(tmp_path):
    d = tmp_path / "repo"
    d.mkdir()
    r = MR.resolve(env={"GK_MAIN_REPO": str(d)})
    assert r["ok"] is True and r["source"] == "env" and r["wsl"] == _canon(d)


def test_relative_env_is_rejected(tmp_path):
    r = MR.resolve(env={"GK_MAIN_REPO": "../evil"}, cwd=str(tmp_path))
    assert "evil" not in r["wsl"], "相对路径不得被接受（防 scope 重定向）"


def test_state_target_repo(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    st = tmp_path / "s.json"
    st.write_text(json.dumps({"target_repo": str(repo), "gate_data": {}}), encoding="utf-8")
    r = MR.resolve(state_file=str(st), env={})
    assert r["ok"] and r["source"] == "state.target_repo" and r["wsl"] == _canon(repo)


def test_meta_target_repo_fallback(tmp_path):
    repo = tmp_path / "m"
    repo.mkdir()
    plan = tmp_path / "p.md"
    plan.write_text("<!-- META\ntarget_repo: %s\n-->\n" % repo, encoding="utf-8")
    st = tmp_path / "s.json"
    st.write_text(json.dumps({"gate_data": {"plan": str(plan)}}), encoding="utf-8")
    r = MR.resolve(state_file=str(st), env={})
    assert r["ok"] and r["source"] == "meta.target_repo" and r["wsl"] == _canon(repo)


def test_git_fallback(tmp_path):
    repo = tmp_path / "g"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    r = MR.resolve(cwd=str(repo), env={})
    assert r["ok"] and r["source"] == "git"
    assert os.path.realpath(r["wsl"]) == os.path.realpath(str(repo))


def test_unresolved_is_named_error(tmp_path):
    r = MR.resolve(state_file=str(tmp_path / "none.json"), cwd=str(tmp_path), env={})
    assert r["ok"] is False and r["error"] == "MAIN_REPO_UNRESOLVED" and r["wsl"] == ""

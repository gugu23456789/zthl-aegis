#!/usr/bin/env python3
"""Gate R0.15（主树 git 写硬拦）红先测试。

背景（2026-10-26 实证）：写面门禁只覆盖 EDIT_TOOLS；`wsl git -C <主树> commit|merge` 走
RunCommand ⟹ worktree 归属 / edit_budget / Gate 3 全不执行 ⟹ 整条写面门禁被绕过。
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pre_tool_hook as hook  # noqa: E402

# 合成主树路径（不含 `/worktrees/`），与测试运行位置（可能在 worktree 内）解耦
MAIN = "<home>/.trae/skills/spz-gatekeeper-r-sequence"
WT = "<home>/.trae/worktrees/spz-gatekeeper-r-sequence/feature/x"


@pytest.fixture(autouse=True)
def _fake_main(monkeypatch):
    # 用**字符串**注入：Windows 上 `Path("/mnt/...")` 会被规范化成 `\\mnt\\...`，与 WSL 形态不一致
    monkeypatch.setattr(hook, "SKILL_DIR", MAIN)


def test_block_subdir_of_main_tree():
    assert hook._git_main_tree_write(f"wsl git -C {MAIN}/docs commit -m x")


def test_block_commit_on_main_tree():
    hit = hook._git_main_tree_write(f"wsl git -C {MAIN} commit -m 'x'")
    assert hit and "main-tree git write" in hit[0]
    assert "worktree" in hit[1]


def test_allow_merge_ritual():
    """merge 是既有落地仪式（设计 §11.3-3 单队列 merge）⟹ 不得拦（拦了就断正路）。"""
    assert hook._git_main_tree_write(f"wsl git -C {MAIN} merge --no-ff feature/x") is None


def test_block_cd_form_uses_effective_cwd():
    """`cd <主树> && git commit`（无 -C）：hook 的 cwd 常滞留主目录 ⟹ 必须看命令内 cd。"""
    cmd = f"wslsh -c 'cd {MAIN} && git commit -m x'"
    assert hook._git_main_tree_write(cmd, "c:/Users/HP")


def test_allow_worktree_target():
    wt = MAIN + "/../worktrees/spz-gatekeeper-r-sequence/feature/x"
    assert hook._git_main_tree_write(f"wsl git -C {wt} commit -m x") is None


def test_allow_read_only_subcommands():
    assert hook._git_main_tree_write(f"git -C {MAIN} status") is None
    assert hook._git_main_tree_write(f"git -C {MAIN} log --oneline -3") is None
    assert hook._git_main_tree_write(f"git -C {MAIN} diff") is None


def test_allow_push_and_fetch():
    """push/fetch 不改工作区/branch ⟹ 不在本门范围（发布路径不应被误伤）。"""
    assert hook._git_main_tree_write(f"wsl git -C {MAIN} push origin master") is None
    assert hook._git_main_tree_write(f"wsl git -C {MAIN} fetch origin") is None


def test_escape_hatch():
    assert hook._git_main_tree_write(
        f"GK_ALLOW_MAIN_GIT_WRITE=1 wsl git -C {MAIN} commit -m x") is None


def test_allow_unrelated_repo():
    assert hook._git_main_tree_write("wsl git -C <home>/some-other-repo commit -m x") is None


def test_quoted_literal_not_blocked():
    assert hook._git_main_tree_write(f"echo 'git -C {MAIN} commit'") is None


def test_chained_cd_uses_nearest_preceding():
    """一条命令里先 worktree 提交、再 cd 主树读：前段不得被后段的 cd 误判（2026-10-26 实测踩中）。"""
    cmd = f"wslsh -c 'cd {WT} && git add -A && git commit -m x && cd {MAIN} && git status'"
    assert hook._git_main_tree_write(cmd, "c:/Users/HP") is None


def test_chained_cd_blocks_only_the_main_segment():
    cmd = f"wslsh -c 'cd {WT} && git status && cd {MAIN} && git commit -m x'"
    hit = hook._git_main_tree_write(cmd, "c:/Users/HP")
    assert hit and "main-tree git write" in hit[0]


def test_gate_name_follows_blue_fat_fish_family():
    """命名族一致性（owner 2026-10-26 指令）：R0.15 与 R0.6/R0.7/R0.12/R0.13 同族。"""
    assert hook.BLUE_FAT_FISH_MAIN_GIT_GATE_NAME == "蓝色大肥鱼与主树之间不得不说的故事"
    names = [hook.BLUE_FAT_FISH_GATE_NAME, hook.BLUE_FAT_FISH_WSL_GATE_NAME,
             hook.BLUE_FAT_FISH_ALIAS_GATE_NAME, hook.BLUE_FAT_FISH_POSIX_GATE_NAME,
             hook.BLUE_FAT_FISH_MAIN_GIT_GATE_NAME]
    assert all(n.startswith("蓝色大肥鱼与") and n.endswith("不得不说的故事") for n in names)

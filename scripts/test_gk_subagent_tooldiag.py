"""子代理工具诊断可观测性红先臂（ECC-7A3BF1148812 / ECC-128772BC3F1D）。

两臂对 HEAD **必红**：
  ① `read_gk_file` 须支持**显式读根** —— 否则 worktree coder 无读自身副本通路
     （read 根恒 SKILL_DIR ⟹ read 根 != edit 根 = 幽灵锚）。落点 `scripts/subagent_runner.py`。
  ② `apply_edit` 回包须含 `resolved`(绝对) / `redirected`(junction) —— 否则 junction 真因不可辨
     （edit 先 realpath 再调 guard-edit ⟹ guard 永不报 JUNCTION_REDIRECT）。落点 `scripts/gk_agent_edit.py`。

隔离：复用 `test_gk_agent_edit` 的 worktree fixture 与门禁 stub；read 臂隔离 SKILL_DIR + 角色。
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import subagent_runner as sr  # noqa: E402
import gk_agent_edit as ae  # noqa: E402

# 复用既有 fixture/常量（禁二次硬编码；见 test_gk_agent_edit）
from test_gk_agent_edit import FAM, _gates_ok, wt as wt_fixture  # noqa: E402,F401


def test_read_gk_file_honors_explicit_root(tmp_path, monkeypatch):
    """① ECC-7A3BF1148812 红先：`read_gk_file` 第 3 参 `root` 须可指定读根。

    HEAD：签名 `(path, offset)` ⟹ 传第 3 位置参 = TypeError ⟹ RED。
    落刀后：`root=<worktree>` 读到 worktree 副本；缺省仍读 SKILL_DIR（向后兼容）。
    """
    monkeypatch.setattr(sr, "_CFG", types.SimpleNamespace(tier=3, mode="crossrev"))
    monkeypatch.setenv("SUBAGENT_ROLE", "auditor")
    skill = tmp_path / "skill"
    wt = tmp_path / "worktree"
    for r, body in ((skill, "SKILL_COPY"), (wt, "WORKTREE_COPY")):
        (r / "scripts").mkdir(parents=True)
        (r / "scripts" / "x.py").write_text(body, encoding="utf-8")
    monkeypatch.setattr(sr, "SKILL_DIR", str(skill))
    read = sr.TOOL_REGISTRY["read"].__wrapped__
    # 缺省根 = SKILL_DIR（既有语义逐字不变）
    assert read("scripts/x.py", 0) == "SKILL_COPY"
    # 显式根 = worktree ⟹ 读本工作树副本（HEAD 在此 TypeError ⟹ 红）
    assert read("scripts/x.py", 0, str(wt)) == "WORKTREE_COPY"


def test_apply_edit_surfaces_resolved_and_redirected(wt_fixture, monkeypatch):
    """② ECC-128772BC3F1D 红先：`apply_edit` 回包须含 `resolved` / `redirected`。

    HEAD：回包仅 {ok, blocked_by, detail} ⟹ 无 resolved/redirected ⟹ RED。
    落刀后：`old_str_not_found` 的 detail 亦带 size，且 resolved 指向 worktree 内绝对路径。
    """
    _gates_ok(monkeypatch)
    r = ae.apply_edit(wt_fixture, "gatekeeper-cli.sh", "NOPE\n", "X\n", FAM, used=0, allowed=3)
    assert r["ok"] is False and r["blocked_by"] == "old_str_not_found"
    assert r["resolved"].endswith(os.path.join("gatekeeper-cli.sh"))
    assert r["redirected"] is False
    assert "size=" in r["detail"]


def test_read_gk_file_normalizes_root(tmp_path, monkeypatch):
    """③ 硬化臂：`read_gk_file` 的 `root` 须先归一（`_native_root` + `normpath`）再进 `_read_common`。

    HEAD：root 未归一 ⟹ 带冗余片段（`sub/..`）的 root 在 `full.startswith(root)` 处误报 traversal；
    且 Windows 宿主下 WSL 形态 root（`/mnt/c/...`）恒被误判（与兄弟 `read_repo_file` 的 F-REV-26 同源）。
    落刀后：root 先归一到宿主形态 ⟹ 两种形态均可读。**本臂宿主无关**（posix/nt 在 HEAD 均红）。
    """
    monkeypatch.setattr(sr, "_CFG", types.SimpleNamespace(tier=3, mode="crossrev"))
    monkeypatch.setenv("SUBAGENT_ROLE", "auditor")
    skill = tmp_path / "skill"
    wt = tmp_path / "worktree"
    for r, body in ((skill, "SKILL_COPY"), (wt, "WORKTREE_COPY")):
        (r / "scripts").mkdir(parents=True)
        (r / "scripts" / "x.py").write_text(body, encoding="utf-8")
    monkeypatch.setattr(sr, "SKILL_DIR", str(skill))
    read = sr.TOOL_REGISTRY["read"].__wrapped__
    # 冗余片段 root：归一后 == wt；HEAD 下 startswith 误判 ⟹ PermissionError ⟹ 红
    weird = os.path.join(str(wt), "sub", "..")
    assert read("scripts/x.py", 0, weird) == "WORKTREE_COPY"

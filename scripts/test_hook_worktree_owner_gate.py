"""hook 归属闸接线臂（Gate 3c / R0.22，2026-11-10，红先）。

事故：并发会话把产物写进本会话 worktree 并混进本会话 commit（`99aed8c2`）。
判据本体在 `gk_worktree_owner`（已有独立臂）；本文件只钉**接线**：
  · Gate 3c 位于 Gate 3（写面）之后、Gate 8（技能自维护）之前；
  · R0.22 在「治理范围内」「范围外」两个 RunCommand 分支**同挂**（只挂一支 = 门禁有、实际不生效）；
  · `_worktree_owner_gate` / `_git_foreign_worktree_write` 的放行与拦截行为。
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import gk_worktree_owner as W  # noqa: E402
import pre_tool_hook as H  # noqa: E402

SRC = (Path(__file__).parent / "pre_tool_hook.py").read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    """hook 日志不落盘（测试不改仓内日志）。"""
    monkeypatch.setattr(H, "_log_hook", lambda *a, **k: None)


def _wt(tmp_path: Path, rel: str = "wts/repo/agent/session/me", claim_ids=None):
    """带真实 gitdir 的 linked worktree（认领文件要真能落盘）。"""
    wt = tmp_path.joinpath(*rel.split("/"))
    wt.mkdir(parents=True, exist_ok=True)
    gd = tmp_path / "gitdirs" / ("gd-" + wt.name)
    gd.mkdir(parents=True, exist_ok=True)
    (wt / ".git").write_text("gitdir: %s\n" % gd, encoding="utf-8")
    f = wt / "x.py"
    f.write_text("x", encoding="utf-8")
    if claim_ids:
        W.claim(str(wt), claim_ids)
    return wt, str(f)


def test_gate3c_blocks_foreign_session(tmp_path, monkeypatch):
    monkeypatch.setenv("GK_WORKTREE_ROOTS", str(tmp_path / "wts"))
    _, f = _wt(tmp_path, claim_ids=["owner-A"])
    out = H._worktree_owner_gate(f, ["intruder-B"])
    assert out, "别人的 worktree 未被 Gate 3c 拦下"
    assert "WORKTREE_OWNERSHIP_VIOLATION" in out[0], out


def test_gate3c_allows_owner(tmp_path, monkeypatch):
    monkeypatch.setenv("GK_WORKTREE_ROOTS", str(tmp_path / "wts"))
    _, f = _wt(tmp_path, claim_ids=["owner-A"])
    assert H._worktree_owner_gate(f, ["owner-A"]) is None


def test_gate3c_ignores_main_checkout(tmp_path, monkeypatch):
    """主检出根（`.git` 是目录）不归本闸管（主树另有只读闸）。"""
    monkeypatch.setenv("GK_WORKTREE_ROOTS", str(tmp_path / "wts"))
    main = tmp_path / "wts" / "repo"
    main.mkdir(parents=True)
    (main / ".git").mkdir()
    f = main / "x.py"
    f.write_text("x", encoding="utf-8")
    assert H._worktree_owner_gate(str(f), ["intruder"]) is None


def test_r022_blocks_commit_in_foreign_worktree(tmp_path, monkeypatch):
    monkeypatch.setenv("GK_WORKTREE_ROOTS", str(tmp_path / "wts"))
    wt, _ = _wt(tmp_path, claim_ids=["owner-A"])
    out = H._git_foreign_worktree_write("git -C %s commit -m x" % wt, "", ["intruder-B"])
    assert out, "别人的 worktree 内的 commit 未被 R0.22 拦下"
    assert "foreign-worktree" in out[0], out


def test_r022_allows_own_worktree_and_read_commands(tmp_path, monkeypatch):
    monkeypatch.setenv("GK_WORKTREE_ROOTS", str(tmp_path / "wts"))
    wt, _ = _wt(tmp_path, claim_ids=["owner-A"])
    assert H._git_foreign_worktree_write("git -C %s commit -m x" % wt, "", ["owner-A"]) is None
    assert H._git_foreign_worktree_write("git -C %s status" % wt, "", ["intruder-B"]) is None


def test_r022_escape_hatch(tmp_path, monkeypatch):
    monkeypatch.setenv("GK_WORKTREE_ROOTS", str(tmp_path / "wts"))
    wt, _ = _wt(tmp_path, claim_ids=["owner-A"])
    cmd = "GK_ALLOW_FOREIGN_WT=1 git -C %s commit -m x" % wt
    assert H._git_foreign_worktree_write(cmd, "", ["intruder-B"]) is None


def test_wiring_shape():
    """源码形态：Gate 3c 在 Gate 3 之后 / Gate 8 之前；R0.22 两支同挂。"""
    i_active = SRC.index("if not _in_active_surface(resolved, state):")
    i_3c = SRC.index("_ow = _worktree_owner_gate(resolved, _caller_ids)")
    i_g8 = SRC.index("g8 = _gate8_skill_self_maintenance(cwd, file_path, state)")
    assert i_active < i_3c < i_g8, (i_active, i_3c, i_g8)
    assert SRC.count("_git_foreign_worktree_write(command, cwd, _caller_ids)") == 2, \
        "R0.22 必须同时挂在「范围内」与「范围外」两个 RunCommand 分支"

#!/usr/bin/env python3
"""test_gk_receive_check.py — `gk_receive_check` 判别臂 ①–⑲（计划 §3-T4，红先）。

臂清单（与 §3-T4 逐字对齐）：
  ① diff 空 ⟹ clean:true, rc=0
  ② diff 非空 ⟹ surface_review:true, rc=1
  ③ ahead-not-divergent（wt=master+1）⟹ ancestor:'ff', divergent:false
  ④ 真分叉 ⟹ divergent:true, rc=2
  ⑤ alive=false（越界/不存在）⟹ rc=2
  ⑥ 重命名（git mv）⟹ surface_review:true
  ⑦ stale（wt 落后）⟹ rc=1, 非 divergent
  ⑧ GK_RECEIVE_CHECK=0 ⟹ skipped:true, rc=1（**不**报 clean）
  ⑨ 不可判（master ref 不可解）⟹ rc=3
  ⑩ env 非法值 ⟹ rc=3（§2.3）
  ⑪ ancestry state=='unknown' ⟹ rc=3（§2.3；**分支锁**，真值面见 ⑱）
  ⑫ ancestry hint==128 ⟹ rc=3（§2.3；**分支锁**，真值面见 ⑱）
  ⑬ `_DIFF_FILTER` 含 git 状态全集 ACDMRTUXB ⟹ §2.2-2 覆盖锁（DRAFT-16）
  ⑭ `hook_live_from` 派生失败 / wrapper 缺席 ⟹ rc=3（§2.3；覆盖锁）
  ⑮ `expected_worktrees` 异常（state 合法非对象 JSON）⟹ rc=3（§2.3；覆盖锁）
  ⑯ `wt_sha` 不可解 ⟹ rc=3（§2.3；monkeypatch 覆盖锁）
  ⑰ `diff` 不可判 ⟹ rc=3（§2.3；monkeypatch 覆盖锁）
  ⑱ **真 git 128 集成臂**（非 monkeypatch）：分离仓 B 的 HEAD 不在主仓 A 对象库 ⟹ `--is-ancestor` 真返 128 ⟹ rc=3（DRAFT-16 P2 收口）
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_receive_check as grc  # noqa: E402


def _git(cwd, *args):
    r = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise AssertionError(f"git {args} failed rc={r.returncode}: {r.stderr}")
    return r


def _mk_env(tmp_path):
    """夹具前置：真仓 + master(A) + 活体 wrapper（供 hook_live_from 派生）。"""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / "f.txt").write_text("A\n", encoding="utf-8")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-q", "-m", "A")
    _git(repo, "branch", "-M", "master")
    skill = tmp_path / "skill"
    (skill / "scripts").mkdir(parents=True)
    (skill / "scripts" / "pre_tool_hook_wrapper.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    return repo, skill


def _add_wt(repo, path, branch):
    _git(repo, "worktree", "add", "-q", "-b", branch, str(path))
    return path


def _commit_file(repo_or_wt, name, content, msg):
    (Path(repo_or_wt) / name).write_text(content, encoding="utf-8")
    _git(repo_or_wt, "add", name)
    _git(repo_or_wt, "commit", "-q", "-m", msg)


def _check(wt, repo, skill, master="master"):
    return grc.check(str(wt), str(repo), "", str(skill), master)


def test_arm1_clean_diff_empty(tmp_path):
    repo, skill = _mk_env(tmp_path)
    wt = _add_wt(repo, tmp_path / "wt1", "b1")           # 与 master 同点 ⟹ ff + 空 diff
    o = _check(wt, repo, skill)
    assert o["receive_check"] is True
    assert o["clean"] is True and o["rc"] == 0
    assert o["diff_empty"] is True and o["surface_review"] is False


def test_arm2_nonempty_diff_surface_review(tmp_path):
    repo, skill = _mk_env(tmp_path)
    wt = _add_wt(repo, tmp_path / "wt2", "b2")
    _commit_file(wt, "g.txt", "B\n", "B")                # wt 领先 master
    o = _check(wt, repo, skill)
    assert o["rc"] == 1 and o["surface_review"] is True
    assert o["clean"] is False and o["diff_empty"] is False


def test_arm3_ahead_not_divergent(tmp_path):
    repo, skill = _mk_env(tmp_path)
    wt = _add_wt(repo, tmp_path / "wt3", "b3")
    _commit_file(wt, "g.txt", "B\n", "B")
    o = _check(wt, repo, skill)
    assert o["ancestor"] == "ff" and o["divergent"] is False


def test_arm4_divergent(tmp_path):
    repo, skill = _mk_env(tmp_path)
    wt = _add_wt(repo, tmp_path / "wt4", "b4")
    _commit_file(repo, "m.txt", "M\n", "M")              # master 前进
    _commit_file(wt, "w.txt", "W\n", "W")                # wt 另起
    o = _check(wt, repo, skill)
    assert o["divergent"] is True and o["rc"] == 2


def test_arm5_absent_out_of_bounds(tmp_path):
    repo, skill = _mk_env(tmp_path)
    stray = tmp_path / "stray"
    stray.mkdir()                                        # 目录存在但非注册 worktree
    o = _check(stray, repo, skill)
    assert o["rc"] == 2 and o["alive"] is False
    o2 = _check(tmp_path / "nope", repo, skill)          # 不存在
    assert o2["rc"] == 2


def test_arm6_rename_surface_review(tmp_path):
    repo, skill = _mk_env(tmp_path)
    wt = _add_wt(repo, tmp_path / "wt6", "b6")
    _git(wt, "mv", "f.txt", "renamed.txt")
    _git(wt, "commit", "-q", "-m", "rename")
    o = _check(wt, repo, skill)
    assert o["rc"] == 1 and o["surface_review"] is True
    assert any(f.startswith("R") for f in o["files"])


def test_arm7_stale(tmp_path):
    repo, skill = _mk_env(tmp_path)
    wt = _add_wt(repo, tmp_path / "wt7", "b7")
    _commit_file(repo, "m.txt", "M\n", "M")              # master 前进 ⟹ wt 落后
    o = _check(wt, repo, skill)
    assert o["stale"] is True and o["rc"] == 1
    assert o["divergent"] is False


def test_arm8_skip(tmp_path, monkeypatch):
    repo, skill = _mk_env(tmp_path)
    wt = _add_wt(repo, tmp_path / "wt8", "b8")
    monkeypatch.setenv("GK_RECEIVE_CHECK", "0")
    o = _check(wt, repo, skill)
    assert o["skipped"] is True and o["rc"] == 1
    assert o["clean"] is False


def test_arm9_undecidable_master(tmp_path):
    repo, skill = _mk_env(tmp_path)
    wt = _add_wt(repo, tmp_path / "wt9", "b9")
    o = _check(wt, repo, skill, master="no-such-ref")     # master 不可解 ⟹ 不可判
    assert o["rc"] == 3


def test_hook_live_from_derived_not_hardcoded(tmp_path):
    """§2.1：`hook_live_from` 须**运行时派生**且等值测试侧独立期望（防硬编码）。"""
    repo, skill = _mk_env(tmp_path)
    wt = _add_wt(repo, tmp_path / "wth", "bh")
    exp = os.path.join(str(skill), "scripts", "pre_tool_hook_wrapper.sh")
    o = _check(wt, repo, skill)
    assert o["hook_live_from"] == exp


def test_arm_env_invalid_is_rc3(tmp_path, monkeypatch):
    """env 非法值（非 "0"）⟹ rc=3（§2.3 不可判态；**红先**：当前 `gk_receive_check.py:119` 仅判 `== "0"`）。"""
    repo, skill = _mk_env(tmp_path)
    wt = _add_wt(repo, tmp_path / "wtx", "bx")
    monkeypatch.setenv("GK_RECEIVE_CHECK", "banana")
    o = _check(wt, repo, skill)
    assert o["rc"] == 3


def test_hook_live_from_reflects_given_skill_not_main(tmp_path):
    """§2.1 **真判别**：传**副本** skill_dir ⟹ `hook_live_from` 须指向副本、**不得**冒充主树（防硬编码恒过）。"""
    repo, skill = _mk_env(tmp_path)
    wt = _add_wt(repo, tmp_path / "wth2", "bh2")
    alt = tmp_path / "alt_skill"
    (alt / "scripts").mkdir(parents=True)
    (alt / "scripts" / "pre_tool_hook_wrapper.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    o = _check(wt, repo, alt)
    assert o["hook_live_from"] == os.path.join(str(alt), "scripts", "pre_tool_hook_wrapper.sh")
    assert str(skill) not in o["hook_live_from"]


# ── §13 残余补齐：ancestry 不可判两分支（原「有实现、无臂」⟹ 覆盖锁）──────────────
def test_arm_ancestry_state_unknown_is_rc3(tmp_path, monkeypatch):
    """⑪ §2.3 不可判：`classify_ancestor` 返 `state == "unknown"` ⟹ rc=3 fail-loud。

    **分支锁**（非真值面）：真码中 `unknown` 恒伴 `hint==128`（`classify_ancestor` 两处 128 均
    `return "unknown", 128`）⟹ `("unknown", 0)` 组合**构造上不可达**，本臂仅锁
    `hint == 128 or state == "unknown"` 的 **OR 子句**；**真 128 值面**由 ⑱（分离仓集成臂）覆盖。
    负臂对照：同点仓**未** patch 时 rc≠3（防"恒判不可判"的假锁）。
    """
    repo, skill = _mk_env(tmp_path)
    wt = _add_wt(repo, tmp_path / "wt11a", "b11a")
    assert _check(wt, repo, skill)["rc"] != 3            # 负臂：正常判定不得误报到 rc=3
    monkeypatch.setattr(grc, "classify_ancestor", lambda *a, **k: ("unknown", 0))
    o = _check(wt, repo, skill)
    assert o["rc"] == 3 and "ancestry" in o["reason"]


def test_arm_ancestry_hint128_is_rc3(tmp_path, monkeypatch):
    """⑫ §2.3 不可判：`classify_ancestor` 返 `hint == 128` ⟹ rc=3。

    **分支锁**：`--is-ancestor` 的 **128** 是 git「无法判定」退出码（≠ 0=祖先 / 1=非祖先）——
    真码中它与 `state=='unknown'` **同生** ⟹ 本臂用 `("ff", 128)` 把 `hint` 子句与 `state`
    子句**区分**锁死（仅 monkeypatch 可分离）；**真 git 128 值面**由 ⑱ 覆盖。
    """
    repo, skill = _mk_env(tmp_path)
    wt = _add_wt(repo, tmp_path / "wt12a", "b12a")
    monkeypatch.setattr(grc, "classify_ancestor", lambda *a, **k: ("ff", 128))
    o = _check(wt, repo, skill)
    assert o["rc"] == 3 and "ancestry" in o["reason"]


# ── DRAFT-16 P0 收口：§2.2-2 filter 全集 + §2.3 rc=3 产者补齐（原「有实现、无表行、无臂」）──
def test_arm13_diff_filter_covers_full_status_set():
    """⑬ §2.2-2 覆盖锁：`_DIFF_FILTER` 须含 git 状态**全集** ACDMRTUXB。

    X（unknown）/ B（broken）在干净夹具里**不可构造** ⟹ 本臂是**常量锁**（非行为臂），
    如实标注；行为面由 ②/⑥（M/R）与 symlink（T）覆盖。
    """
    assert set("ACDMRTUXB") <= set(grc._DIFF_FILTER)


def test_arm14_hook_live_from_missing_is_rc3(tmp_path):
    """⑭ §2.3 rc=3 产者：`hook_live_from` 派生失败 / wrapper 缺席 ⟹ rc=3（原无表行、无臂）。"""
    repo, skill = _mk_env(tmp_path)
    wt = _add_wt(repo, tmp_path / "wt14a", "b14a")
    nohook = tmp_path / "nohook"
    (nohook / "scripts").mkdir(parents=True)              # 无 wrapper ⟹ 派生目标缺席
    o = grc.check(str(wt), str(repo), "", str(nohook), "master")
    assert o["rc"] == 3 and "hook_live_from" in o["reason"]
    assert _check(wt, repo, skill)["rc"] != 3             # 负臂：wrapper 在位不得误报


def test_arm15_expected_worktrees_broken_state_is_rc3(tmp_path):
    """⑮ §2.3 rc=3 产者：state 为**合法非对象 JSON** ⟹ `expected_worktrees` 抛 ⟹ rc=3。

    可达性实证：`gk_write_claims._state_worktrees_extra` 只捕 `(OSError, ValueError)`，
    故 `json.load("123") -> int` 后 `d.get` 的 `AttributeError` **不被吞** ⟹ 上抛 ⟹ rc=3。
    （即 §12.9-Q1「源码不可达」删行理由不成立。）
    """
    repo, skill = _mk_env(tmp_path)
    wt = _add_wt(repo, tmp_path / "wt15a", "b15a")
    bad = tmp_path / "bad.state"
    bad.write_text("123\n", encoding="utf-8")
    o = grc.check(str(wt), str(repo), str(bad), str(skill), "master")
    assert o["rc"] == 3 and "expected_worktrees" in o["reason"]


def test_arm16_wt_sha_unresolvable_is_rc3(tmp_path, monkeypatch):
    """⑯ §2.3 rc=3 产者：`wt_sha` 不可解（worktree HEAD 不可解析）⟹ rc=3（monkeypatch 覆盖锁）。"""
    repo, skill = _mk_env(tmp_path)
    wt = _add_wt(repo, tmp_path / "wt16a", "b16a")
    real = grc._rev_parse
    monkeypatch.setattr(grc, "_rev_parse",
                        lambda rp, ref: None if ref == "HEAD" else real(rp, ref))
    o = _check(wt, repo, skill)
    assert o["rc"] == 3 and "wt_sha" in o["reason"]


def test_arm17_diff_undecidable_is_rc3(tmp_path, monkeypatch):
    """⑰ §2.3 rc=3 产者：`diff` 不可判（git diff 非零退出）⟹ rc=3（monkeypatch 覆盖锁）。"""
    repo, skill = _mk_env(tmp_path)
    wt = _add_wt(repo, tmp_path / "wt17a", "b17a")
    monkeypatch.setattr(grc, "diff_status", lambda *a, **k: (None, []))
    o = _check(wt, repo, skill)
    assert o["rc"] == 3 and "diff 不可判" in o["reason"]


# ── DRAFT-16 P2 收口：真 git 128 集成臂（非 monkeypatch；真值面覆盖 ⑪/⑫ 两子句出口）──
def test_arm18_ancestry_real_git128_is_rc3(tmp_path):
    """⑱ §2.3 rc=3 产者：**真 git 128 集成臂**（非 monkeypatch）。

    构造（不 patch）：A = 主仓；B = **独立 git 仓**（非 `git worktree add` ⟹ 其 commit 不进 A 的
    对象库）；`state.worktrees_extra=[B]` ⟹ `expected_worktrees` 纳入 B（否则先撞「越界 rc=2」）。
    于是 `classify_ancestor(A, <A.master>, <B.HEAD>)` 在 A 内跑 `merge-base --is-ancestor`，
    B.HEAD 不是 A 的合法对象 ⟹ git **真返 128** ⟹ rc=3。真码中该 128 与 `state=='unknown'`
    同生 ⟹ 本臂同时覆盖 ⑪（state 子句）与 ⑫（hint 子句）的**可观测出口**。
    """
    repo, skill = _mk_env(tmp_path)                    # A：主仓（master 有提交）
    wt = tmp_path / "wt18b"                            # B：独立仓（非 linked worktree）
    wt.mkdir()
    _git(wt, "init", "-q")
    _git(wt, "config", "user.email", "t@t")
    _git(wt, "config", "user.name", "t")
    (wt / "g.txt").write_text("B\n", encoding="utf-8")
    _git(wt, "add", "g.txt")
    _git(wt, "commit", "-q", "-m", "B")
    state = tmp_path / "st18.json"
    state.write_text(json.dumps({"worktrees_extra": [str(wt)]}), encoding="utf-8")
    o = grc.check(str(wt), str(repo), str(state), str(skill), "master")
    assert o["rc"] == 3 and "ancestry" in o["reason"]


def test_arm19_main_propagates_rc_to_exit_code(tmp_path):
    """⑲ §2.3/P2 收口：`main()` 须把 rc（0/1/2/3）**传导到进程退出码**。

    病象：原 `main` 恒 `return 0` ⟹ rc=3（fail-loud）只存 JSON 字段，shell 调用方按退出码
    判读时**看不见**不可判。复用 ⑱ 真 128 场景：`main(argv)` 返回 **3**（修复前必返 0 ⟹ 红）。
    """
    repo, skill = _mk_env(tmp_path)
    wt = tmp_path / "wt19b"
    wt.mkdir()
    _git(wt, "init", "-q")
    _git(wt, "config", "user.email", "t@t")
    _git(wt, "config", "user.name", "t")
    (wt / "g.txt").write_text("B\n", encoding="utf-8")
    _git(wt, "add", "g.txt")
    _git(wt, "commit", "-q", "-m", "B")
    state = tmp_path / "st19.json"
    state.write_text(json.dumps({"worktrees_extra": [str(wt)]}), encoding="utf-8")
    rc = grc.main(["--wt", str(wt), "--main-repo", str(repo),
                   "--state-file", str(state), "--skill-dir", str(skill)])
    assert rc == 3

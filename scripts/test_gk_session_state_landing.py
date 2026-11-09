"""序④-A v5：会话副本 state 治理落刀（red-first）。

落刀面（`gatekeeper-cli.sh` `cmd_apply_worktree --session`）：
  · 废副本 —— 不再 `cp` base state 到 worktree、不再对副本 `set-top worktree/branch`、
    不再重置副本预算（甲 = 单 state + `edit_budget.sessions.<sid>` 分片）。
  · 改「幂等归档 + bind 承接 + 归主树 state」；归档 helper 落 **python 侧**
    （`gk_state_patch.cmd_session_state_archive`，可测 —— 禁 bash 内联不可测实现）。

红先对照：HEAD 版 `--session` 分支含 `cp "$_s_st" "$_s_state"` / `set-top "$_s_state" worktree`
（`git show HEAD:gatekeeper-cli.sh` 可复核），且 HEAD 版 `gk_state_patch.py` **无**
`cmd_session_state_archive` ⟹ 本文件全部臂在 HEAD 上必红。
"""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_state  # noqa: E402
import gk_state_patch as sp  # noqa: E402


def _cli_session_seg():
    """`cmd_apply_worktree` 的 `--session` 分支源码段（形态臂落点）。"""
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "gatekeeper-cli.sh")
    src = open(p, encoding="utf-8").read()
    i = src.index('if [ -n "$session" ]; then')
    j = src.index("\n  fi", i)
    return src[i:j]


# ── 形态臂（gatekeeper-cli.sh 源码切片）──────────────────────────────────────
def test_s1_no_copy_no_settop():
    """负臂：废副本 —— cp / 对副本 set-top worktree·branch 必须全部缺席。"""
    seg = _cli_session_seg()
    assert 'cp "$_s_st" "$_s_state"' not in seg, "仍在 cp 副本 state（甲：废副本）"
    assert 'set-top "$_s_state" worktree' not in seg, "仍对副本 set-top worktree"
    assert 'set-top "$_s_state" branch' not in seg, "仍对副本 set-top branch"


def test_s2_binds_worktrees_extra():
    """bind 承接：经唯一写通路 `worktrees-extra ... bind` 把 worktree 登记进主 state。"""
    seg = _cli_session_seg()
    assert "worktrees-extra" in seg and " bind " in seg, \
        "未走唯一写通路 bind worktrees_extra（A1 归属承重面缺失）"


def test_s3_archives_before_delete():
    """幂等归档 helper 被调用；命名族（.jsonl 后缀）在 python 侧单源，禁 bash 内写死。"""
    seg = _cli_session_seg()
    assert "session-state-archive" in seg, "未调用幂等归档 helper"
    assert "session-state-archive.jsonl" not in seg, \
        "旁挂文件名在 bash 侧写死 ⟹ 命名族非单源（G2b）"


def test_s4_note_is_truthful():
    """清除虚假 note（ECC-B9395FC8E23C）：『就近 .gatekeeper.state』**自动**治理 不成立。"""
    seg = _cli_session_seg()
    assert "就近 .gatekeeper.state" not in seg, "虚假 note 未清除（ECC-B9395FC8E23C）"
    assert "主树 state" in seg, "note 未改为可信语义（归主树 state）"


def test_s5_state_file_is_base():
    """回包 `state_file` 必须 = **base** state（不再是副本路径）；旧 `_s_state` 变量应消失。"""
    seg = _cli_session_seg()
    assert "_s_state" not in seg, "旧副本变量 `_s_state` 仍在使用（废副本未净）"
    # 回包经 `gk_json.py build` 构造 ⟹ 判据落在 builder 实参（不再有手写 JSON 字面量）。
    assert 'state_file="$_s_st"' in seg, "state_file 未指向 base state"


# ── 行为臂（python 侧 helper）────────────────────────────────────────────────
def test_archive_helper_diff_archives_and_removes(tmp_path):
    base = tmp_path / "base.state"
    base.write_text('{"a":1}', encoding="utf-8")
    wt = tmp_path / "wt.state"
    wt.write_text('{"a":1,"x":2}', encoding="utf-8")
    out = sp.cmd_session_state_archive(str(base), str(wt), session="s1", worktree="/w1")
    assert out["ok"] and out["present"] and out["archived"] is True and out["removed"] is True
    assert not wt.exists(), "有 diff 的副本未删除"
    arch = tmp_path / "base.state.session-state-archive.jsonl"
    assert arch.exists(), "有 diff 未落旁挂（须先归档后删）"
    rec = json.loads(arch.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert rec["session"] == "s1" and rec["worktree"] == "/w1"
    assert rec["state_sha256"] and rec["bytes"] == len('{"a":1,"x":2}')
    assert base64.b64decode(rec["content_b64"]).decode("utf-8") == '{"a":1,"x":2}', \
        "旁挂内容不可逐字节复原（「可核对」判据缺失）"


def test_archive_helper_identical_deletes_only(tmp_path):
    base = tmp_path / "base.state"
    base.write_text('{"a":1}', encoding="utf-8")
    wt = tmp_path / "wt.state"
    wt.write_text('{"a":1}', encoding="utf-8")
    out = sp.cmd_session_state_archive(str(base), str(wt), session="s2")
    assert out["ok"] and out["present"] and out["archived"] is False and out["removed"] is True
    assert not wt.exists(), "无 diff 的副本未删除"
    assert not (tmp_path / "base.state.session-state-archive.jsonl").exists(), \
        "无 diff 竟也落旁挂（A5：有 diff 才归档）"


def test_archive_helper_absent_noop(tmp_path):
    base = tmp_path / "base.state"
    base.write_text('{"a":1}', encoding="utf-8")
    out = sp.cmd_session_state_archive(str(base), str(tmp_path / "nope.state"), session="s3")
    assert out["ok"] and out["present"] is False and out["removed"] is False
    assert not (tmp_path / "base.state.session-state-archive.jsonl").exists()


def test_archive_helper_dry_run_no_write(tmp_path):
    base = tmp_path / "base.state"
    base.write_text('{"a":1}', encoding="utf-8")
    wt = tmp_path / "wt.state"
    wt.write_text('{"a":2}', encoding="utf-8")
    out = sp.cmd_session_state_archive(str(base), str(wt), session="s4", dry_run=True)
    assert out["ok"] and out["archived"] is True and out["dry_run"] is True
    assert wt.exists(), "dry_run 竟删了副本"
    assert not (tmp_path / "base.state.session-state-archive.jsonl").exists(), \
        "dry_run 竟写了旁挂"


def test_bind_worktrees_extra_idempotent(tmp_path):
    st = tmp_path / "s.json"
    gk_state._write_state({"gate_data": {}}, str(st))
    a = sp.cmd_worktrees_extra(str(st), "bind", "/w/x")
    assert a["ok"] and a["changed"] is True, "首次 bind 未生效"
    b = sp.cmd_worktrees_extra(str(st), "bind", "/w/x")
    assert b["ok"] and b["changed"] is False, "重复 bind 非幂等（应 changed:false 零写盘）"

"""gk_worktree_owner 归属臂（2026-11-10，红先）。

事故：并发会话把产物写进本会话 worktree 并混入本会话 commit（`99aed8c2`）。
判据：**worktree 路径派生 token = 该 worktree 的唯一身份**（派生单源 = gk_session_identity）；
写者身份必须等于目标 worktree 的 token，否则 BLOCK。身份不可判定 ⟹ fail-open（显式）。

红先对照：`scripts/gk_worktree_owner.py` 尚不存在 ⟹ 本文件对 HEAD 必红（ImportError）。
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_worktree_owner as W  # noqa: E402


def _tree(base: Path, rel: str, dot_git: str = "file") -> Path:
    """建一棵假 worktree：`dot_git=file` = linked worktree；`dir` = 主检出根。"""
    p = base.joinpath(*rel.split("/"))
    p.mkdir(parents=True, exist_ok=True)
    if dot_git == "file":
        (p / ".git").write_text("gitdir: /nonexistent/.git/worktrees/x\n", encoding="utf-8")
    else:
        (p / ".git").mkdir(exist_ok=True)
    return p


def _file(p: Path, name: str = "x.txt") -> str:
    f = p / name
    f.write_text("x", encoding="utf-8")
    return str(f)


ROOTS_OF = lambda base: [str(base / "wts")]  # noqa: E731


def test_locate_worktree_owner_from_agent_layout(tmp_path):
    wt = _tree(tmp_path, "wts/repo/agent/session/abc123")
    loc = W.locate(_file(wt), roots=ROOTS_OF(tmp_path))
    assert loc["kind"] == "worktree", loc
    assert loc["owner"] == "abc123", loc
    assert loc["worktree"].endswith("agent/session/abc123"), loc


def test_locate_pool_slot_has_distinct_token(tmp_path):
    """池槽 `<repo>/_pool/<repo>/slot-N` ⟹ token=`slot-N`（否则同池各槽共用一个身份）。"""
    s1 = _tree(tmp_path, "wts/repo/_pool/repo/slot-1")
    s2 = _tree(tmp_path, "wts/repo/_pool/repo/slot-2")
    a = W.locate(_file(s1), roots=ROOTS_OF(tmp_path))
    b = W.locate(_file(s2), roots=ROOTS_OF(tmp_path))
    assert a["owner"] == "slot-1", a
    assert b["owner"] == "slot-2", b


def test_owner_may_write_own_worktree(tmp_path):
    wt = _tree(tmp_path, "wts/repo/agent/session/me")
    out = W.check(_file(wt), ["me"], roots=ROOTS_OF(tmp_path))
    assert out["ok"] is True and out["decision"] == "allow", out
    assert out["reason"] == "owner_match", out


def test_foreign_session_is_blocked(tmp_path):
    """负臂：别人的 worktree 必须 BLOCK（这正是并发产物串味的入口）。"""
    wt = _tree(tmp_path, "wts/repo/agent/session/other")
    out = W.check(str(wt / "scripts"), ["me"], roots=ROOTS_OF(tmp_path))
    assert out["ok"] is False, out
    assert out["error"] == "WORKTREE_OWNERSHIP_VIOLATION", out
    assert "other" in out["reason"] and "me" in out["reason"], out


def test_identity_unknown_fails_open(tmp_path):
    """调用方给不出任何身份 ⟹ 不拦（手工排障 / 非 Trae 宿主；显式 reason 可审计）。"""
    wt = _tree(tmp_path, "wts/repo/agent/session/other")
    out = W.check(_file(wt), [], roots=ROOTS_OF(tmp_path))
    assert out["ok"] is True and out["reason"] == "caller_identity_unknown", out


def test_main_checkout_is_not_ownership_gated(tmp_path):
    """主检出根（`.git` 是目录）⟹ owner 空、不据此拦截（主树另有只读闸）。"""
    main = _tree(tmp_path, "skills/repo", dot_git="dir")
    out = W.check(_file(main), ["me"], roots=ROOTS_OF(tmp_path))
    assert out["kind"] == "main", out
    assert out["ok"] is True and out["owner"] == "", out


def test_path_outside_dev_worktrees_is_unknown(tmp_path):
    main = _tree(tmp_path, "elsewhere/repo", dot_git="dir")
    loc = W.locate(_file(main), roots=ROOTS_OF(tmp_path))
    assert loc["kind"] == "main", loc
    bare = tmp_path / "plain"
    bare.mkdir()
    assert W.locate(str(bare), roots=ROOTS_OF(tmp_path))["kind"] == "unknown"


def test_relative_path_is_absolutized(tmp_path, monkeypatch):
    """`locate('.')` 必须按 cwd 绝对化（否则恒 `not_in_dev_worktree_tree` ⟹ 闸形同虚设）。"""
    wt = _tree(tmp_path, "wts/repo/agent/session/me")
    monkeypatch.chdir(wt)
    loc = W.locate(".", roots=ROOTS_OF(tmp_path))
    assert loc["kind"] == "worktree" and loc["owner"] == "me", loc


def test_edit_renews_pool_lease_throttled(tmp_path):
    """**编辑即续期**：活跃会话的槽位不得被 TTL 扫走；但按 `ttl/2` 节流（热路径不落盘）。

    病象：`acquire` 只写一次 `ts_epoch` ⟹ 任何超过 TTL 的活跃会话都会被 sweep 当成「崩溃」清场。
    """
    import json as _json
    import time as _time

    wt = _linked(tmp_path, "wts/repo/_pool/repo/slot-1")
    lp = wt.parent / "slot-1.lease.json"
    old = _time.time() - 1000
    lp.write_text(_json.dumps({"slot": 1, "sid": "payload-lease", "state": "leased",
                               "ts_epoch": old, "ttl_s": 100}), encoding="utf-8")
    f = _file(wt)
    out = W.check(f, ["payload-lease"], roots=ROOTS_OF(tmp_path), autoclaim=False)
    assert out["ok"] is True, out
    assert (out.get("lease_renewed") or {}).get("renewed") is True, out
    assert _json.loads(lp.read_text(encoding="utf-8"))["ts_epoch"] > old

    again = W.check(f, ["payload-lease"], roots=ROOTS_OF(tmp_path), autoclaim=False)
    assert again["ok"] is True and "lease_renewed" not in again, "续期未按 ttl/2 节流"


def test_renew_refuses_foreign_identity(tmp_path):
    """负臂：外人既不能写槽，也不能替槽续期（否则能把别人的槽“焊死”）。"""
    import json as _json
    import time as _time

    wt = _linked(tmp_path, "wts/repo/_pool/repo/slot-1")
    lp = wt.parent / "slot-1.lease.json"
    old = _time.time() - 1000
    lp.write_text(_json.dumps({"slot": 1, "sid": "payload-lease", "state": "leased",
                               "ts_epoch": old, "ttl_s": 100}), encoding="utf-8")
    r = W.renew_pool_lease(str(wt), ["intruder"])
    assert r.get("ok") is False and r.get("error") == "NOT_OWNER", r
    assert _json.loads(lp.read_text(encoding="utf-8"))["ts_epoch"] == old


def test_caller_id_from_cwd(tmp_path):
    mine = _tree(tmp_path, "wts/repo/agent/session/me")
    other = _tree(tmp_path, "wts/repo/agent/session/other")
    assert W.caller_id(str(mine / "scripts"), roots=ROOTS_OF(tmp_path)) == "me"
    assert W.caller_id(str(other), roots=ROOTS_OF(tmp_path)) == "other"
    assert W.caller_id(str(tmp_path), roots=ROOTS_OF(tmp_path)) == ""


def _linked(tmp_path: Path, rel: str, gitdir: str = "gd") -> Path:
    """带**真实** gitdir 目录的 linked worktree（认领文件要真能落盘）。"""
    wt = _tree(tmp_path, rel)
    gd = tmp_path / "gitdirs" / gitdir
    gd.mkdir(parents=True, exist_ok=True)
    (wt / ".git").write_text("gitdir: %s\n" % gd, encoding="utf-8")
    return wt


def test_claim_first_writer_wins_and_blocks_others(tmp_path):
    """首写认领：认领者（载荷 sid）持续可写；**外人即使路径 token 相同也无法接管**。"""
    wt = _linked(tmp_path, "wts/repo/agent/session/me")
    f = _file(wt)
    first = W.check(f, ["payload-A", "me"], roots=ROOTS_OF(tmp_path))
    assert first["ok"] is True and first["reason"] == "owner_match", first
    assert W.read_claim(str(wt))["ids"] == ["payload-A", "me"], W.read_claim(str(wt))

    second = W.check(f, ["payload-B"], roots=ROOTS_OF(tmp_path))
    assert second["ok"] is False, second
    assert second["error"] == "WORKTREE_OWNERSHIP_VIOLATION", second
    assert W.check(f, ["payload-A"], roots=ROOTS_OF(tmp_path))["ok"] is True


def test_expired_claim_is_reclaimable(tmp_path):
    """认领带 TTL（单源 = gk_git_lease.claim_ttl_s）：过期后可由新会话认领（防永久占坑）。"""
    import json

    wt = _linked(tmp_path, "wts/repo/agent/session/me")
    f = _file(wt)
    W.claim(str(wt), ["old"])
    p = W.claim_path(str(wt))
    data = json.loads(p.read_text(encoding="utf-8"))
    data["ts_epoch"] = float(data["ts_epoch"]) - 10 ** 6
    p.write_text(json.dumps(data), encoding="utf-8")

    out = W.check(f, ["me"], roots=ROOTS_OF(tmp_path))
    assert out["ok"] is True and out["reason"] == "owner_match", out
    assert W.read_claim(str(wt))["ids"] == ["me"], W.read_claim(str(wt))


def test_pool_slot_lease_sid_is_accepted(tmp_path):
    """池槽：租约 sid 与槽名同为合法身份（槽被租给哪个会话，哪个会话就能写）。"""
    import json

    wt = _linked(tmp_path, "wts/repo/_pool/repo/slot-1")
    (wt.parent / "slot-1.lease.json").write_text(
        json.dumps({"slot": 1, "sid": "payload-lease", "state": "leased"}), encoding="utf-8")
    f = _file(wt)
    # autoclaim=False：本臂只判「租约 sid / 槽名是否都属于 owner 集」，不落认领（否则第二条会被首写认领挡住）
    assert W.check(f, ["payload-lease"], roots=ROOTS_OF(tmp_path), autoclaim=False)["ok"] is True
    assert W.check(f, ["slot-1"], roots=ROOTS_OF(tmp_path), autoclaim=False)["ok"] is True

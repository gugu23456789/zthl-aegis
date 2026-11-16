"""会话身份与 worktree 归属隔离（2026-11-12，红先）。

事故（本会话实测）：两个 chat 同时写 `agent/session/396aa76b`。
根因三层：
  ① `caller_identities` 会采纳**别人**写进单槽 `.gatekeeper.session` 的 sid 与别名 token；
  ② `check()` 把**目标路径 token** 当 owner 身份，外人只要派生出该 token 即可通过；
  ③ `_SESSION_ID` 优先取目标路径 token ⟹ 会话身份被路径身份覆盖。

本文件钉住三条修复判据：
  - 路径 token 不能给外来会话「救场」（有会话级 id 时必须匹配它）；
  - 外来 marker/alias 不得进入本会话身份候选；
  - 会话身份优先级 = env > 宿主 payload sid > worktree token（仅兜底）。
"""
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_worktree_owner as W  # noqa: E402
import pre_tool_hook as H  # noqa: E402

ROOTS = lambda base: [str(base / "wts")]  # noqa: E731


def _linked(tmp_path: Path, rel: str) -> Path:
    wt = tmp_path.joinpath(*rel.split("/"))
    wt.mkdir(parents=True, exist_ok=True)
    gd = tmp_path / "gitdirs" / ("gd-" + wt.name)
    gd.mkdir(parents=True, exist_ok=True)
    (wt / ".git").write_text("gitdir: %s\n" % gd, encoding="utf-8")
    return wt


def _file(wt: Path) -> str:
    f = wt / "x.py"
    f.write_text("x", encoding="utf-8")
    return str(f)


def test_path_token_cannot_rescue_foreign_session(tmp_path):
    """主判据：认领里有 `payload-A` + 路径 token `me`，外来 `payload-B` 即使带 `me` 也必须 BLOCK。"""
    wt = _linked(tmp_path, "wts/repo/agent/session/me")
    f = _file(wt)
    W.claim(str(wt), ["payload-A", "me"])
    out = W.check(f, ["payload-B", "me"], roots=ROOTS(tmp_path))
    assert out["ok"] is False, out
    assert out["error"] == "WORKTREE_OWNERSHIP_VIOLATION", out
    assert W.check(f, ["payload-A"], roots=ROOTS(tmp_path))["ok"] is True


def test_claim_records_allocated_sid(tmp_path):
    """`gk-owner.json` 须记 `allocated_sid`（会话轮换告警的锚，不是第二个事实源）。"""
    wt = _linked(tmp_path, "wts/repo/agent/session/me")
    W.claim(str(wt), ["payload-A", "me"])
    cl = W.read_claim(str(wt))
    assert cl.get("allocated_sid") == "payload-A", cl


def test_sid_rotation_is_flagged_but_allowed(tmp_path):
    """宿主 sid 轮换（分配 sid 已不在，但新 sid 已在 ids 里）⟹ 放行 + `sid_rotated` 显式告警。"""
    wt = _linked(tmp_path, "wts/repo/agent/session/me")
    f = _file(wt)
    W.claim(str(wt), ["allocated-A", "new-B", "me"])
    out = W.check(f, ["new-B"], roots=ROOTS(tmp_path))
    assert out["ok"] is True and out.get("sid_rotated") is True, out


def test_allocated_sid_reads_fresh_claim(tmp_path):
    """CLI 身份首选 = 新鲜认领的 `allocated_sid`；过期 ⟹ 空（回落 legacy 链）。"""
    import json

    wt = _linked(tmp_path, "wts/repo/agent/session/me")
    W.claim(str(wt), ["payload-A", "me"])
    assert W.allocated_sid(str(wt)) == "payload-A"

    p = W.claim_path(str(wt))
    data = json.loads(p.read_text(encoding="utf-8"))
    data["ts_epoch"] = float(data["ts_epoch"]) - 10 ** 6
    p.write_text(json.dumps(data), encoding="utf-8")
    assert W.allocated_sid(str(wt)) == ""


def _marker(sd: Path, sid: str, cwd: str, alias: str = "") -> None:
    """模拟 hook 的写侧：单槽 + 本 sid 分片（2026-11-12 后的真实形态）。"""
    sd.mkdir(parents=True, exist_ok=True)
    line = "%s\t%d\tEdit\t%s\n" % (sid, int(time.time()), cwd)
    (sd / ".gatekeeper.session").write_text(line, encoding="utf-8")
    (sd / (".gatekeeper.session." + sid)).write_text(line, encoding="utf-8")
    if alias:
        (sd / (".gatekeeper.session.alias." + sid)).write_text(alias + "\n", encoding="utf-8")


def test_caller_identities_ignore_foreign_marker_and_alias(tmp_path):
    """单槽被别的会话覆盖 ⟹ 本会话（payload=bbbb2222）不得采纳 aaaa1111 及其别名 token。"""
    sd = tmp_path / "skill"
    cwd = str(tmp_path / "workspace")
    os.makedirs(cwd, exist_ok=True)
    _marker(sd, "aaaa1111", cwd, alias="target-token")
    ids = W.caller_identities(cwd, extra=("bbbb2222",), session_dir=str(sd))
    assert "aaaa1111" not in ids, ids
    assert "target-token" not in ids, ids
    assert "bbbb2222" in ids, ids


def test_caller_identities_accept_own_marker_alias(tmp_path):
    """同源 marker（sid 与 payload 一致）⟹ 仍采纳其别名（保留 T6 记账链路）。"""
    sd = tmp_path / "skill"
    cwd = str(tmp_path / "workspace")
    os.makedirs(cwd, exist_ok=True)
    _marker(sd, "bbbb2222", cwd, alias="token-b")
    ids = W.caller_identities(cwd, extra=("bbbb2222",), session_dir=str(sd))
    assert "bbbb2222" in ids and "token-b" in ids, ids


def test_marker_candidates_ambiguous_then_stale(tmp_path):
    """分片读面：同 cwd 两个新鲜分片 ⟹ ambiguous（不猜）；旧分片过期后 ⟹ 唯一候选。"""
    sd = tmp_path / "skill"
    cwd = str(tmp_path / "workspace")
    os.makedirs(cwd, exist_ok=True)
    now = time.time()
    _marker(sd, "aaaa1111", cwd)
    (sd / ".gatekeeper.session.bbbb2222").write_text(
        "bbbb2222\t%d\tEdit\t%s\n" % (now, cwd), encoding="utf-8")

    r = W.marker_candidates(str(sd), cwd, ttl_s=1800, now=now)
    assert r["ambiguous"] is True and r["sid"] == "", r
    assert {x["sid"] for x in r["candidates"]} == {"aaaa1111", "bbbb2222"}, r

    (sd / ".gatekeeper.session.bbbb2222").write_text(
        "bbbb2222\t%d\tEdit\t%s\n" % (now - 10 ** 5, cwd), encoding="utf-8")
    r2 = W.marker_candidates(str(sd), cwd, ttl_s=1800, now=now)
    assert r2["sid"] == "aaaa1111" and not r2["ambiguous"], r2


def test_marker_candidates_legacy_global_and_cwd_mismatch(tmp_path):
    """无分片才回落单槽；cwd 不同源的分片不得入选。"""
    sd = tmp_path / "skill"
    cwd = str(tmp_path / "workspace")
    other = str(tmp_path / "other")
    os.makedirs(cwd, exist_ok=True)
    os.makedirs(other, exist_ok=True)
    sd.mkdir(parents=True, exist_ok=True)
    now = time.time()

    (sd / ".gatekeeper.session").write_text(
        "cccc3333\t%d\tEdit\t%s\n" % (now, cwd), encoding="utf-8")
    legacy = W.marker_candidates(str(sd), cwd, ttl_s=1800, now=now)
    assert legacy["source"] == "legacy_global" and legacy["sid"] == "cccc3333", legacy

    (sd / ".gatekeeper.session.dddd4444").write_text(
        "dddd4444\t%d\tEdit\t%s\n" % (now, other), encoding="utf-8")
    r = W.marker_candidates(str(sd), cwd, ttl_s=1800, now=now)
    assert r["sid"] == "", r  # 分片 cwd 不同源；且分片存在 ⟹ 不回落单槽


def test_marker_cli_ambiguous_rc3(tmp_path):
    """CLI 契约：多候选 ⟹ stdout 空 + rc=3（shell 侧据此告警/回落）。"""
    import subprocess

    sd = tmp_path / "skill"
    cwd = str(tmp_path / "workspace")
    os.makedirs(cwd, exist_ok=True)
    now = int(time.time())
    for sid in ("aaaa1111", "bbbb2222"):
        (sd / (".gatekeeper.session." + sid)).parent.mkdir(parents=True, exist_ok=True)
        (sd / (".gatekeeper.session." + sid)).write_text(
            "%s\t%d\tEdit\t%s\n" % (sid, now, cwd), encoding="utf-8")
    r = subprocess.run([sys.executable, str(Path(__file__).parent / "gk_worktree_owner.py"),
                        "marker", "--dir", str(sd), "--cwd", cwd, "--ttl", "1800"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 3, (r.returncode, r.stdout, r.stderr)
    assert r.stdout.strip() == "", r.stdout
    assert "ambiguous" in r.stderr, r.stderr


def test_resolve_session_id_priority():
    """身份优先级：env > 宿主 payload sid > 目标 worktree token（仅无宿主身份时兜底）。"""
    assert H.resolve_session_id("env-A", "payload-B", "me") == "env-A"
    assert H.resolve_session_id("", "payload-B", "me") == "payload-B"
    assert H.resolve_session_id("", "", "me") == "me"

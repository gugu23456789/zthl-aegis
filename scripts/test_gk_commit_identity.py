"""gk_commit_identity 提交身份臂（2026-11-10，红先）。

事故：并发产物混进本会话 commit，而 `git log` 上无从分辨（全局 author 全会话一致）。
判据：① author = `agent/<sid> <sid>@gatekeeper.local`；② trailer `Session:` / `Worktree:`；
③ 提交后 `verify` 必须与本树身份一致（不一致 ⟹ fail-loud）。

红先对照：`scripts/gk_commit_identity.py` 尚不存在 ⟹ 本文件对 HEAD 必红（ImportError）。
"""
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_commit_identity as C  # noqa: E402


def _repo(tmp_path: Path) -> str:
    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "-C", str(r), "init", "-q", "-b", "master"], check=True)
    (r / "a.txt").write_text("x", encoding="utf-8")
    subprocess.run(["git", "-C", str(r), "add", "a.txt"], check=True)
    subprocess.run(["git", "-C", str(r), "-c", "user.name=t", "-c", "user.email=t@t",
                    "commit", "-qm", "init"], check=True)
    return str(r)


def test_identity_uses_given_sid():
    ident = C.identity("/tmp/x", sid="abc123")
    assert ident["sid"] == "abc123", ident
    assert ident["author_name"] == "agent/abc123", ident
    assert ident["author_email"] == "abc123@gatekeeper.local", ident
    assert ident["trailers"]["Session"] == "abc123", ident


def test_decorate_appends_and_is_idempotent():
    ident = C.identity("/tmp/x", sid="abc123")
    once = C.decorate("feat: 主题\n\n正文", ident)
    twice = C.decorate(once, ident)
    assert once == twice, "重复装饰叠加了 trailer（非幂等）"
    assert once.startswith("feat: 主题\n\n正文"), once
    assert once.rstrip().endswith("Worktree: /tmp/x"), once
    assert C.parse(once)["Session"] == "abc123"


def test_decorate_replaces_stale_trailer():
    ident = C.identity("/tmp/x", sid="new")
    msg = "主题\n\nSession: old\nWorktree: /elsewhere\n"
    out = C.decorate(msg, ident)
    tr = C.parse(out)
    assert tr["Session"] == "new" and tr["Worktree"] == "/tmp/x", out
    assert out.count("Session:") == 1, out


def test_parse_takes_last_occurrence():
    assert C.parse("x\nSession: a\nSession: b\n")["Session"] == "b"


def test_verify_passes_on_matching_commit(tmp_path):
    repo = _repo(tmp_path)
    ident = C.identity(repo, sid="abc123")
    msg = C.decorate("feat: 提交", ident)
    mf = tmp_path / "m.txt"
    mf.write_text(msg, encoding="utf-8")
    subprocess.run(["git", "-C", repo, "-c", "user.name=" + ident["author_name"],
                    "-c", "user.email=" + ident["author_email"],
                    "commit", "--allow-empty", "-q", "-F", str(mf)], check=True)
    out = C.verify(repo, "HEAD", sid="abc123")
    assert out["ok"] is True, out
    assert out["trailers"]["Session"] == "abc123", out


def test_verify_flags_foreign_author(tmp_path):
    """负臂：author 不是本会话身份 ⟹ 必须报不一致（这正是「串味」的可机检形态）。"""
    repo = _repo(tmp_path)
    mf = tmp_path / "m.txt"
    mf.write_text("feat: 借来的提交\n\nSession: someone-else\nWorktree: /elsewhere\n",
                  encoding="utf-8")
    subprocess.run(["git", "-C", repo, "-c", "user.name=gugu", "-c", "user.email=g@u",
                    "commit", "--allow-empty", "-q", "-F", str(mf)], check=True)
    out = C.verify(repo, "HEAD", sid="abc123")
    assert out["ok"] is False, out
    joined = " | ".join(out["mismatch"])
    assert "Session" in joined and "author" in joined, out


def test_sanitized_env_strips_git_ident_keys():
    """env 伪造面（2026-11-11 实测）：`GIT_AUTHOR_*` 优先级高于 `-c user.name` ⟹ 必须能清。

    提交面两侧同源：Python = `sanitized_env`，shell = `cmd_commit` 的 `env -u`（下一条臂钉）。
    """
    base = {"PATH": "/bin", "GIT_AUTHOR_NAME": "agent/victim",
            "GIT_AUTHOR_EMAIL": "victim@gk", "GIT_COMMITTER_NAME": "x",
            "GIT_COMMITTER_EMAIL": "x@x", "KEEP": "1"}
    env = C.sanitized_env(base)
    for k in C.GIT_IDENT_ENV:
        assert k not in env, (k, env)
    assert env == {"PATH": "/bin", "KEEP": "1"}, env


def test_cli_commit_wiring_clears_git_ident_env():
    """接线臂：`cmd_commit` 的两个提交分支都必须 `env -u GIT_AUTHOR_NAME`（清一侧漏另一侧 = 半修）。"""
    src = (Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    assert src.count("env -u GIT_AUTHOR_NAME") == 2, "两个提交分支都要清 env（实得 %d 处）" % \
        src.count("env -u GIT_AUTHOR_NAME")
    assert "GIT_COMMITTER_EMAIL" in src


def test_cli_decorate_msg_file(tmp_path):
    repo = _repo(tmp_path)
    mf = tmp_path / "msg.txt"
    mf.write_text("feat: x\n", encoding="utf-8")
    rc = C.main(["decorate", "--repo", repo, "--sid", "abc123", "--msg-file", str(mf)])
    assert rc == 0
    tr = C.parse(mf.read_text(encoding="utf-8"))
    assert tr["Session"] == "abc123", tr

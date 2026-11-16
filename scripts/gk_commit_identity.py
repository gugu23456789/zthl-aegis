#!/usr/bin/env python3
"""gk_commit_identity.py — 提交身份（worktree + session 双键，2026-11-10）。

事故（2026-11-10，实证）：并发产物（`references/comment-template.md`）混进本会话的提交
（`99aed8c2`），而 `git log` 上**无从分辨**——author 是本机全局身份
（`gugu23456789@users.noreply.github.com`），所有会话、所有 worktree 全一样。事后只能靠人肉
回忆哪段是谁的 ⟹ 归因成本极高。

本模块给提交面加两件**可机检**的东西（判据单源，不重复 `gk_session_identity` 的派生）：
  ① **author/committer** = `agent/<sid> <sid>@gatekeeper.local` ⟹ 每棵 worktree 独立身份；
  ② message 尾部 trailer `Session: <sid>` / `Worktree: <worktree>`（幂等：重跑不会叠加）。
`verify` 在提交后复核 trailer/author 与**实际** repo 是否一致；不一致 ⟹ fail-loud（历史已写，
处置 = `git reset --soft HEAD^` 重提，**禁 amend**）。

用法:
  identity --repo <r> [--sid s]                   # → {sid, worktree, author_name, author_email}
  decorate --repo <r> --msg-file <f> [--sid s]    # 原地追加/刷新 trailer
  verify   --repo <r> [--rev HEAD] [--sid s]      # 校验已有提交
Exit: 0 = 一致；1 = 不一致；2 = 参数/环境错。
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_session_identity as gsi  # noqa: E402  （身份派生单源）
import gk_worktree_owner as own    # noqa: E402  （worktree 路径单源）

TRAILER_RE = re.compile(r"^(Session|Worktree):\s*(.*)$")
_KEYS = ("Session", "Worktree")
# git 语义：这四组 env 的优先级**高于** `-c user.name/user.email` ⟹ 不清掉就能用环境变量
# 伪造提交身份（2026-11-11 场景 `commit-identity-forge-01` 实测踩中正控假阴）。
GIT_IDENT_ENV = ("GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL",
                 "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL")


def sanitized_env(base=None) -> dict:
    """去掉 `GIT_AUTHOR_*` / `GIT_COMMITTER_*` 的环境副本（提交面**必须**用它）。

    判据单源：CLI 的 `cmd_commit` 用 `env -u` 做同一件事（shell 侧），本函数供
    Python 侧/场景探针使用 —— 两侧语义必须一致，改一侧须同批改另一侧。
    """
    env = dict(os.environ if base is None else base)
    for k in GIT_IDENT_ENV:
        env.pop(k, None)
    return env


def _norm(p) -> str:
    return str(p or "").replace("\\", "/").rstrip("/")


def _git(repo: str, *args: str):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)


def resolve_sid(repo: str, sid: str = "") -> str:
    """身份链：显式 `--sid` > env `GK_SESSION_ID` > 该 repo 路径派生 token。"""
    for cand in (sid, os.environ.get("GK_SESSION_ID", "")):
        s = str(cand or "").strip()
        if gsi.is_valid_token(s):
            return s
    tok = gsi.derive(str(repo or "")).get("token") or ""
    return tok if gsi.is_valid_token(tok) else ""


def identity(repo: str, sid: str = "") -> dict:
    """提交身份三件套（author 名/邮箱 + 两条 trailer）。"""
    s = resolve_sid(repo, sid)
    wt = _norm(gsi.derive(str(repo or "")).get("worktree") or own.worktree_root(repo) or repo)
    return {"ok": True, "repo": _norm(repo), "sid": s, "worktree": wt,
            "author_name": ("agent/" + s) if s else "",
            "author_email": (s + "@gatekeeper.local") if s else "",
            "trailers": ({"Session": s, "Worktree": wt} if s else {"Worktree": wt})}


def strip_trailers(msg: str) -> str:
    """去掉尾部的 `Session:` / `Worktree:` 行（幂等装饰的前提）。"""
    lines = str(msg or "").replace("\r\n", "\n").split("\n")
    while lines and (not lines[-1].strip() or TRAILER_RE.match(lines[-1].strip())):
        lines.pop()
    return "\n".join(lines).rstrip()


def decorate(msg: str, ident: dict) -> str:
    """正文 + 规范化 trailer 块（正文里的旧 trailer 一律先剥掉 ⟹ 不叠加）。"""
    body = strip_trailers(msg)
    tr = ident.get("trailers") or {}
    tail = "\n".join("%s: %s" % (k, tr[k]) for k in _KEYS if tr.get(k))
    return (body + "\n\n" + tail + "\n") if body else (tail + "\n")


def parse(msg: str) -> dict:
    """message 里的 trailer（同名取**最后**一条；缺 ⟹ 不出现该键）。"""
    out = {}
    for ln in str(msg or "").replace("\r\n", "\n").split("\n"):
        m = TRAILER_RE.match(ln.strip())
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def verify(repo: str, rev: str = "HEAD", sid: str = "") -> dict:
    """提交后复核：author/trailer 必须与本树身份一致（不一致 ⟹ fail-loud）。"""
    r = _git(repo, "log", "-1", "--format=%an%x00%ae%x00%B", rev)
    if r.returncode != 0:
        return {"ok": False, "error": "GIT_LOG_FAILED", "detail": (r.stderr or "").strip()[:300]}
    parts = (r.stdout or "").split("\x00", 2)
    if len(parts) < 3:
        return {"ok": False, "error": "GIT_LOG_UNPARSEABLE", "detail": (r.stdout or "")[:200]}
    name, email, body = parts[0].strip(), parts[1].strip(), parts[2]
    want = identity(repo, sid)
    tr = parse(body)
    mismatch = []
    if want["sid"]:
        if tr.get("Session") != want["sid"]:
            mismatch.append("trailer Session=%r ≠ %r" % (tr.get("Session"), want["sid"]))
        if name != want["author_name"] or email != want["author_email"]:
            mismatch.append("author %r <%s> ≠ %r <%s>"
                            % (name, email, want["author_name"], want["author_email"]))
    if tr.get("Worktree") and tr["Worktree"] != want["worktree"]:
        mismatch.append("trailer Worktree=%r ≠ %r" % (tr.get("Worktree"), want["worktree"]))
    return {"ok": not mismatch, "rev": rev, "commit": (_git(repo, "rev-parse", "--short", rev).stdout or "").strip(),
            "author": {"name": name, "email": email}, "trailers": tr,
            "expect": {"sid": want["sid"], "worktree": want["worktree"],
                       "author_name": want["author_name"], "author_email": want["author_email"]},
            "mismatch": mismatch}


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: identity|decorate|verify --repo <r> [--sid s] [--msg-file f] [--rev r]")
        return 2
    cmd, repo, sid, msg_file, rev = argv[0], "", "", "", "HEAD"
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--repo" and i + 1 < len(argv):
            repo, i = argv[i + 1], i + 2
        elif a == "--sid" and i + 1 < len(argv):
            sid, i = argv[i + 1], i + 2
        elif a == "--msg-file" and i + 1 < len(argv):
            msg_file, i = argv[i + 1], i + 2
        elif a == "--rev" and i + 1 < len(argv):
            rev, i = argv[i + 1], i + 2
        else:
            print(json.dumps({"ok": False, "error": "unknown arg: %r" % a}, ensure_ascii=False))
            return 2
    if not repo:
        print(json.dumps({"ok": False, "error": "--repo required"}, ensure_ascii=False))
        return 2
    try:
        if cmd == "identity":
            print(json.dumps(identity(repo, sid), ensure_ascii=False))
            return 0
        if cmd == "decorate":
            if not msg_file:
                print(json.dumps({"ok": False, "error": "--msg-file required"}, ensure_ascii=False))
                return 2
            ident = identity(repo, sid)
            raw = Path(msg_file).read_text(encoding="utf-8")
            out = decorate(raw, ident)
            Path(msg_file).write_text(out, encoding="utf-8")
            print(json.dumps({"ok": True, "sid": ident["sid"],
                              "worktree": ident["worktree"], "message": out},
                             ensure_ascii=False))
            return 0
        if cmd == "verify":
            out = verify(repo, rev, sid)
            print(json.dumps(out, ensure_ascii=False))
            return 0 if out.get("ok") else 1
        print(json.dumps({"ok": False, "error": "unknown cmd: %r" % cmd}, ensure_ascii=False))
        return 2
    except Exception as e:  # noqa: BLE001 — CLI 边界 fail-loud
        print(json.dumps({"ok": False, "error": "%s: %s" % (type(e).__name__, e)},
                         ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

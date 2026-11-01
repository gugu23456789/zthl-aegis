#!/usr/bin/env python3
"""会话身份解析单源（平台无关兜底）—— finding ECC-AB2FA16E9133。

身份 token = 会话所绑 git worktree 的稳定标识（不依赖任何宿主 hook API ⟹ 平台无关）。
本模块**只产 token**；消费在启动块（`gatekeeper-cli.sh`）/ hook（`pre_tool_hook.py`）/
元数据中枢（`gk_route_center` / `gk_state_route`）/ 额度银行（`edit_budget.sessions.<token>`）。

解析链（Q1a：name 优先 + 路径哈希兜底）：
  0. 调用方已给身份（env `GK_SESSION_ID` / 宿主 payload `session_id`）⟹ **不经本模块**（调用方短路）
  1. path ∈ 开发 worktree 树（`DEV_WORKTREE_ROOTS/<repo>/…`）：
     (a) `<repo>/agent/session/<leaf>` 或 `<repo>/agent/<family>/<leaf>`（2 段布局）→ token=`<leaf>`（name）
     (b) 其它 2 段布局 → token=`<leaf>`（name）
     (c) 更奇形态 → token=`w` + sha8(worktree 绝对路径)（hash）
  2. 不在 worktree 树（主树 / 未知）→ token=""（回落全局/默认，零回归）

单源约束：`DEV_WORKTREE_ROOTS` / `_norm` 从 `gk_state_route` 复用（**禁第二实现**）。
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gk_state_route import DEV_WORKTREE_ROOTS, _norm  # noqa: E402  单源复用

# token 须为文件系统安全（用于 `.gatekeeper.plan.<token>` 等文件名）
_TOKEN_OK = re.compile(r"^[0-9A-Za-z_][0-9A-Za-z_-]*$")


def is_valid_token(tok: str) -> bool:
    return bool(tok) and bool(_TOKEN_OK.match(tok))


def _sha8(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:8]


def derive(path: str) -> dict:
    """由路径派生会话身份 token。

    返回 `{token, source, worktree, repo, reason}`；无 token 时 `token=""`。
    `source` ∈ {`, `name`, `hash`}`。
    """
    out = {"token": "", "source": "", "worktree": "", "repo": "", "reason": ""}
    if not path:
        out["reason"] = "no_path"
        return out
    # 归一 + 小写比对（对齐 gk_state_route 的 worktree 根匹配口径）
    np = _norm(path)
    npl = np.lower()
    root = ""
    for r in DEV_WORKTREE_ROOTS:
        rn = _norm(r).lower()
        rn = rn if rn.endswith("/") else rn + "/"
        if npl == rn.rstrip("/") or npl.startswith(rn):
            root = rn
            break
    if not root:
        out["reason"] = "not_in_dev_worktree_tree"
        return out
    segs = [s for s in np[len(root):].split("/") if s]
    if not segs:
        out["reason"] = "empty_rest"
        return out
    repo = segs[0]
    out["repo"] = repo
    # `<repo>/agent/<family>/<leaf>`（apply-worktree 布局）→ token = leaf = segs[3]（name 优先）
    if len(segs) >= 4 and segs[1] == "agent":
        out.update({"token": segs[3], "source": "name",
                    "worktree": root + "/".join(segs[:4]), "reason": "agent_route_name"})
        return out
    # 其它 2 段布局 `<repo>/<a>/<leaf>` → token = leaf = segs[2]
    if len(segs) >= 3:
        out.update({"token": segs[2], "source": "name",
                    "worktree": root + "/".join(segs[:3]), "reason": "two_seg_name"})
        return out
    # 更奇形态 → 路径哈希兜底
    wt = root + "/".join(segs[:2]) if len(segs) >= 2 else (root + repo)
    out.update({"token": "w" + _sha8(wt), "source": "hash", "worktree": wt, "reason": "hash_fallback"})
    return out


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: gk_session_identity.py derive --path <p> [--json]")
        return 2
    if argv[0] == "derive":
        path = ""
        as_json = False
        i = 1
        while i < len(argv):
            if argv[i] == "--path" and i + 1 < len(argv):
                path = argv[i + 1]
                i += 2
                continue
            if argv[i] == "--json":
                as_json = True
                i += 1
                continue
            i += 1
        r = derive(path)
        if not is_valid_token(r["token"]):
            r["token"] = ""
        if as_json:
            print(json.dumps(r, ensure_ascii=False))
        else:
            print(r["token"])
        return 0
    print("unknown command", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

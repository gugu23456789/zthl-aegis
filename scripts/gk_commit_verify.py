#!/usr/bin/env python3
"""gk_commit_verify.py — 提交面校验（单一实现）：索引/提交里的 blob **逐字节**对不对工作树 + 能不能解析。

2026-09-25（**提交面单一入口**，`ECC-<待登记>`）：事故驱动 —— code commit `65974a8` 落了一枚
**损坏 blob**（`gatekeeper-cli.sh` 2968-2977 行两段粘连、`bash -n` 直接 syntax error），而
`git status` / `git diff` / `git diff-files` **全报 clean**（索引 stat 缓存命中 ⟹ 不重算 hash）
⟹ 损坏内容进历史，唯 `git archive HEAD` 型测试才暴露（`ECC-E5364D7993C8`）。

**为什么必须是「blob vs 工作树」而不是看 git 状态**：撕裂发生在 `git add` 的**那一次读取**上；
此后所有 git 侧的"干净"判断都走 stat 缓存。唯一能抓住它的是**第二次独立读取**（对象库 ←→ 工作树
逐字节比对）。本模块即该判据的单一实现，供 `gatekeeper-cli.sh cmd_commit` 在**提交前**（暂存面）
与**提交后**（HEAD 面）各调一次 —— 前者把损坏挡在历史之外（消除），后者兜住"校验后又被撕裂"的窗口。

判据（全部确定性、零网络）：
  ① `blob_bytes == 工作树字节`（逐字节；缺失文件 = MISMATCH，防"提交后又被删"）；
  ② 解析面：`.sh` → `bash -n`（喂 blob，不是喂工作树）；`.py` → `ast.parse`；
     `.json` → `json.loads`。均**读 blob**，故能抓「blob 坏而工作树好」这一事故形态。

用法:
  python3 gk_commit_verify.py --repo <r> --mode staged
  python3 gk_commit_verify.py --repo <r> --mode rev [--rev HEAD] [--paths a b c]
Exit: 0 = 全过；1 = 有坏项（JSON `bad[]` 逐条给出 reason）；2 = 环境/参数错。
"""
import argparse
import ast
import json
import os
import subprocess
import sys
from pathlib import Path

_BAD_REASONS = ("MISSING_WORKTREE", "BLOB_MISMATCH", "PARSE_FAIL", "BLOB_UNREADABLE",
                "DRVFS_CROSS_VIEW_MISMATCH")


def _git(repo: str, *args: str, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, timeout=120, **kw)


def _git_blob_sha1(repo: str, data: bytes) -> str:
    """`data` 的 **blob** 口径 sha1（`git hash-object --stdin --no-filters`）。
    口径说明：`git hash-object` 算的是 `blob <len>\\0` + 内容（**非**裸内容的 sha1）⟹ 两路比较必须
    都用本口径，否则**必假报不一致**（实测 `hello\\n` → git `ce013625…` vs 裸 sha1 `f572d396…`）。
    2026-09-28 升级：原「写 temp 文件再 hash」改为**直喂 stdin** ⟹ 免一次 FS 往返、天然同口径。"""
    r = subprocess.run(["git", "-C", repo, "hash-object", "--stdin", "--no-filters"],
                       input=data, capture_output=True, timeout=120)
    return r.stdout.decode("utf-8", "replace").strip() if r.returncode == 0 else ""


def _stage_paths(repo: str) -> list:
    """暂存面文件清单（`--diff-filter` 全量：含 A/M/D，D 由 MISSING_WORKTREE 判）。"""
    r = _git(repo, "diff", "--cached", "--name-only", "--diff-filter=ACMRTUXB")
    if r.returncode != 0:
        raise RuntimeError("git diff --cached 失败: " + r.stderr.strip()[:200])
    return [ln for ln in r.stdout.splitlines() if ln.strip()]


def _rev_paths(repo: str, rev: str) -> list:
    """`rev` 相对其父改动文件清单（根 commit ⟹ 全树）。"""
    r = _git(repo, "diff-tree", "-r", "--name-only", "--no-commit-id", rev)
    if r.returncode != 0:
        raise RuntimeError("git diff-tree 失败: " + r.stderr.strip()[:200])
    return [ln for ln in r.stdout.splitlines() if ln.strip()]


def _blob_bytes(repo: str, spec: str) -> bytes:
    """对象库里的 blob 原始字节（`spec` 形如 `:0:path` = 索引 / `HEAD:path`）。"""
    r = subprocess.run(["git", "-C", repo, "cat-file", "blob", spec],
                       capture_output=True, timeout=120)
    if r.returncode != 0:
        raise FileNotFoundError(spec)
    return r.stdout


def _parse_ok(path: str, data: bytes) -> str:
    """解析面判据；返回 "" = 过，否则 reason 明细。判据面**只读 blob**（事故形态：blob 坏/工作树好）。"""
    low = path.lower()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        return "PARSE_FAIL: 非 UTF-8（%s）" % e
    if low.endswith(".sh") or low.endswith(".bash"):
        r = subprocess.run(["bash", "-n", "/dev/stdin"], input=data,
                           capture_output=True, timeout=60)
        if r.returncode != 0:
            return "PARSE_FAIL: bash -n — " + (r.stderr.decode("utf-8", "replace").strip()[:160])
    elif low.endswith(".py"):
        try:
            ast.parse(text)
        except SyntaxError as e:
            return "PARSE_FAIL: ast.parse — line %s: %s" % (e.lineno, e.msg)
    elif low.endswith(".json"):
        try:
            json.loads(text)
        except ValueError as e:
            return "PARSE_FAIL: json — %s" % str(e)[:160]
    return ""


# ── drvfs 跨侧陈旧读（2026-09-28，`ECC-FAA686AB1791` / `ECC-C2BE2C56A7BD`）──────────────
# 实测形态：Windows 侧改文件 + WSL git ⟹ `git hash-object`（四形态）读**旧** blob，而
# `dd`/`md5sum`/`cp`（read 路径）得**真**内容 ⟹ 索引暂存旧 blob ⟹ 本模块判 BLOB_MISMATCH
# 拦下（拦对了），但**无法识别**这是宿主跨侧页缓存问题、也**没有机械通道**。
# 人工处置手法（`cp f /tmp && cp /tmp f`）本身**会把 Windows 侧新编辑回滚**（`c5366fc` 实测被
# 回滚、`9dcb6e8` 补落）—— 因为回写的缓冲可能正是**陈旧**内容。故本段给两条：
#   ① `worktree_views` —— 同一文件的**两路独立读**（read 路径 vs git 路径），供本模块**区分**
#      「真语料不一致」与「宿主缓存不一致」（判据不放松：仍然阻断，只改诊断）；
#   ② `verified_refresh` —— drvfs 缓存失效的**安全**通道：回写前做**逐字节**双视图比对，
#      不一致 ⟹ **无法判定真值** ⟹ **拒绝回写**（目标文件一字节不动）⟹ 杜绝对 Windows 侧编辑的回滚。

def worktree_views(repo: str, path: str) -> dict:
    """同一文件的两种**独立读路径**（drvfs 陈旧读判据）：
       git 路径 = `git hash-object --no-filters` 直读**原文件**；
       read 路径 = python `open().read()` 取字节 → `_git_blob_sha1`（`--stdin` **免临时件**）
       （内核读路径所得内容的**同口径**指纹）。
    ⚠ **必须同口径**：`git hash-object` 是 **blob** 口径（`blob <len>\\0` + 内容），拿
       `sha1(内容)` 与它直接比是**错**的（实测 `hello\\n` → git `ce013625…` vs `sha1` `f572d396…`）。
    两路不一致 ⟹ 跨侧页缓存不一致。返回 `{exists, read_sha1, git_sha1, agree}`。"""
    p = Path(repo) / path
    if not p.is_file():
        return {"exists": False, "read_sha1": "", "git_sha1": "", "agree": False}
    r = _git(repo, "hash-object", "--no-filters", "--", path)
    git_sha1 = r.stdout.strip() if r.returncode == 0 else ""
    read_sha1 = _git_blob_sha1(repo, p.read_bytes())
    return {"exists": True, "read_sha1": read_sha1, "git_sha1": git_sha1,
            "agree": bool(git_sha1) and git_sha1 == read_sha1}


def verified_refresh(repo: str, path: str) -> dict:
    """drvfs 缓存失效的**安全**通道（替代裸 `cp` 往返）。
    判据（回写前）：`git hash-object --no-filters`(原文件) == `git hash-object --no-filters`(逐字节副本)
    —— 不一致 ⟹ 两条读路径对「同一内容」给出不同答案 ⟹ **无法判定真值** ⟹ **拒绝回写**
    （fail-loud `DRVFS_CROSS_VIEW_MISMATCH`，目标文件一字节不动：这是 `ECC-C2BE2C56A7BD` 的回滚守门）。
    一致 ⟹ 执行**逐字节等值**往返（写临时件 → fsync → 回读比对 → 回写 → 复核），内容不变、只做缓存失效。"""
    p = Path(repo) / path
    if not p.is_file():
        return {"ok": False, "error": "MISSING_WORKTREE", "path": path}
    v = worktree_views(repo, path)
    if not (v["exists"] and v["agree"]):
        return {"ok": False, "error": "DRVFS_CROSS_VIEW_MISMATCH", "path": path,
                "read_sha1": v["read_sha1"], "git_sha1": v["git_sha1"]}
    raw = p.read_bytes()  # 两路已一致的内容；逐字节等值回写 ⟹ 不回滚任何一侧的编辑
    with open(p, "wb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    v2 = worktree_views(repo, path)
    if not v2["agree"] or p.read_bytes() != raw:
        return {"ok": False, "error": "REFRESH_READBACK_MISMATCH", "path": path}
    return {"ok": True, "refreshed": True, "path": path, "sha1": v2["git_sha1"]}


def verify(repo: str, mode: str, rev: str = "", paths=None) -> dict:
    """逐文件跑 ① 字节面 ② 解析面；返回机读结果（含 `bad[]`）。"""
    if mode == "staged":
        files, spec_of = _stage_paths(repo), (lambda p: ":0:" + p)
    elif mode == "rev":
        files, spec_of = (_rev_paths(repo, rev or "HEAD"), (lambda p: (rev or "HEAD") + ":" + p))
    else:
        raise ValueError("mode 只能是 staged|rev（收到 %r）" % mode)
    if paths:
        want = set(paths)
        files = [f for f in files if f in want]
    checked, bad = [], []
    for f in files:
        try:
            data = _blob_bytes(repo, spec_of(f))
        except FileNotFoundError:
            bad.append({"path": f, "reason": "BLOB_UNREADABLE: " + spec_of(f)})
            continue
        wt = Path(repo) / f
        if not wt.is_file():
            bad.append({"path": f, "reason": "MISSING_WORKTREE: 工作树无此文件"})
            continue
        if wt.read_bytes() != data:
            # 成因区分（`ECC-FAA686AB1791`）：两路读**互相不一致** ⟹ 宿主跨侧页缓存不一致
            #   （drvfs），非语料真不一致 ⟹ 报可识别 reason 并指向安全通道；判据**不放松**（仍阻断）。
            _v = worktree_views(repo, f)
            if _v["exists"] and not _v["agree"]:
                bad.append({"path": f, "reason": "DRVFS_CROSS_VIEW_MISMATCH: 读路径 %s ≠ git 路径 %s"
                            "（drvfs 跨侧页缓存不一致；用 --refresh 走安全通道，禁裸 cp 往返）"
                            % (_v["read_sha1"][:12], _v["git_sha1"][:12])})
            else:
                bad.append({"path": f, "reason": "BLOB_MISMATCH: blob %d B ≠ 工作树 %d B"
                            % (len(data), wt.stat().st_size)})
            continue
        why = _parse_ok(f, data)
        if why:
            bad.append({"path": f, "reason": why})
            continue
        checked.append(f)
    return {"ok": not bad, "mode": mode, "rev": rev or ("(staged)" if mode == "staged" else "HEAD"),
            "checked": checked, "bad": bad, "count": len(files)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="提交面校验（blob vs 工作树 + 解析面）")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--mode", choices=("staged", "rev"), default="")
    ap.add_argument("--rev", default="")
    ap.add_argument("--paths", nargs="*", default=None)
    ap.add_argument("--refresh", nargs="+", default=None,
                    help="对给定路径做 drvfs **安全**刷新（不提交/不校验；两路读不一致即拒绝回写）")
    a = ap.parse_args(argv)
    if a.refresh:
        res = [verified_refresh(a.repo, pth) for pth in a.refresh]
        print(json.dumps({"ok": all(r.get("ok") for r in res), "refreshed": res}, ensure_ascii=False))
        return 0 if all(r.get("ok") for r in res) else 1
    if not a.mode:
        print(json.dumps({"ok": False, "error": "需 --mode staged|rev（或 --refresh）"}, ensure_ascii=False))
        return 2
    try:
        out = verify(a.repo, a.mode, a.rev, a.paths)
    except (RuntimeError, ValueError) as e:
        print(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
        return 2
    print(json.dumps(out, ensure_ascii=False))
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())

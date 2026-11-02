#!/usr/bin/env python3
"""gk_git_concurrency_check.py — git 并发抢锁检测器（2026-08-15）

检测 Windows/WSL git 并发操作风险，供 `audit --crossr` 交叉审查调用（追加审查项）。
背景: 8/15 回收站出现 .git/index + refs/heads/master + 大量 index.lock（Windows 进程
显式删除，POSIX unlink 不进回收站）+ git config 含 vscode-merge-base（VS Code git 痕迹）
→ Windows git 与 WSL git 并发抢锁的实锤。

检测项:
  1. repo_healthy     : HEAD 可解析 + rev-list 正常
  2. stuck_locks      : .git/*.lock 残留且 mtime 超 10 分钟（正常锁应瞬时消失）
  3. windows_git_trace: git config 含 vscode-merge-base（VS Code/Trae 内嵌 git 操作痕迹）
  4. dense_commit     : reflog 近 60 分钟内 >6 commit 且最小间隔 <30s（密集提交=并发窗口高风险）
  5. fsck             : git fsck --no-dangling 无 missing/corrupt
  6. index            : git diff --cached 为空（index==HEAD 树）

输出: JSON {ok, repo, checks, concurrency_detected, recommendation}
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

_LOCK_AGE_THRESHOLD_S = 600      # 锁残留 10 分钟 = stuck
_DENSE_WINDOW_S = 3600           # 检测窗口 60 分钟
_DENSE_MAX_COMMITS = 6           # 窗口内 commit 上限
_DENSE_MIN_GAP_S = 30            # 最小间隔阈值


def _git(repo: str, *args: str, timeout: int = 10) -> tuple[int, str, str]:
    try:
        r = subprocess.run(["git", "-C", repo, *args],
                           capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:  # git 缺失/超时 → 不可用
        return -1, "", str(e)


def _parse_ref_date(s: str) -> datetime:
    """解析 reflog --date=iso 的 'YYYY-MM-DD HH:MM:SS +0800'（Python 3.11 需补冒号）。"""
    s = s.strip()
    m = re.match(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s*([+-]\d{2}):?(\d{2})?", s)
    if m:
        base, off_hh, off_mm = m.group(1), m.group(2), m.group(3) or "00"
        return datetime.fromisoformat(base + off_hh + ":" + off_mm)
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def check_repo_healthy(repo: str) -> dict:
    rc, out, _ = _git(repo, "rev-parse", "HEAD")
    if rc != 0:
        return {"status": "warn", "reason": "HEAD unresolvable"}
    rc2, cnt, _ = _git(repo, "rev-list", "--count", "HEAD")
    return {"status": "ok", "head": out.strip()[:12], "commits": cnt.strip()}


def check_stuck_locks(repo: str) -> dict:
    git_dir = Path(repo) / ".git"
    if not git_dir.exists():
        return {"status": "skip", "reason": "no .git dir"}
    locks = []
    now = time.time()
    for p in sorted(git_dir.glob("*.lock")):
        age = now - p.stat().st_mtime
        if age > _LOCK_AGE_THRESHOLD_S:
            locks.append({"name": p.name, "age_s": round(age)})
    return {"status": "ok" if not locks else "warn", "stuck_locks": locks}


def check_windows_git_trace(repo: str) -> dict:
    rc, out, _ = _git(repo, "config", "--list", "--local")
    if rc != 0:
        return {"status": "skip", "reason": "config read failed"}
    # vscode-merge-base = VS Code/Trae 内嵌 git 集成写回的 config 项
    trace = [l for l in out.splitlines() if "vscode-merge-base" in l]
    return {"status": "warn" if trace else "ok", "trace": trace}


def check_dense_commit(repo: str) -> dict:
    rc, out, _ = _git(repo, "reflog", "--date=iso", "-200")
    if rc != 0:
        return {"status": "skip", "reason": "reflog failed"}
    times = []
    for line in out.splitlines():
        m = re.search(r"@\{([^}]+)\}: commit:", line)
        if m:
            try:
                times.append(_parse_ref_date(m.group(1)).timestamp())
            except (ValueError, TypeError):
                continue
    now = time.time()
    recent = sorted((t for t in times if now - t <= _DENSE_WINDOW_S), reverse=True)
    if len(recent) <= _DENSE_MAX_COMMITS:
        return {"status": "ok", "recent_commits": len(recent)}
    gaps = [recent[i] - recent[i + 1] for i in range(len(recent) - 1)]
    min_gap = min(gaps) if gaps else 0
    dense = min_gap < _DENSE_MIN_GAP_S
    return {"status": "warn" if dense else "ok",
            "recent_commits": len(recent), "min_gap_s": round(min_gap, 1), "dense": dense}


def check_fsck(repo: str) -> dict:
    rc, out, _ = _git(repo, "fsck", "--no-dangling")
    issues = [l for l in out.splitlines() if l.strip() and "dangling" not in l]
    return {"status": "ok" if rc == 0 and not issues else "warn", "issues": issues[:5]}


def check_index(repo: str) -> dict:
    rc, out, _ = _git(repo, "diff", "--cached", "--stat")
    return {"status": "ok" if rc == 0 and not out.strip() else "warn",
            "staged_changes": out.strip()}


def worktree_fingerprint(repo: str) -> dict:
    """**工作树一致性指纹**（2026-09-28，`ECC-130ECB1ABCA4`）。

    给「并发编辑下 L2 读到半写/撕裂快照」提供**可机检判据**：对 dirty 集合
    （`git status --porcelain=v1 -z --untracked-files=all`）逐文件取 `git hash-object --no-filters`
    （**blob 口径**，与 `gk_commit_verify` 同口径）后聚合 sha256。

    **用法（判据，不是结论）**：调用方在 LLM 车道**前后各取一次** —— 两次不等 ⟹ 该段工作树被
    **并发改动** ⟹ L2/后R 的结果可能是**半写/撕裂**读的产物（本仓自认最坏的"假绿"，§隔离段注记
    同款教训）⟹ 须**显式告警**并标该步 `WARN`，**不得**静默判 OK。两次相等 ⟹ 该段**无**并发
    写入证据（`clean:true`）。

    **只读**：不写文件、不动 index（`git status` 不刷 index；`hash-object` 默认不写对象库）。
    """
    rc, out, _ = _git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    tokens = [t for t in (out or "").split("\0") if t] if rc == 0 else []
    files, h = [], hashlib.sha256()
    for tok in sorted(tokens):
        # `-z` 形态：有状态前缀的为路径项（`XY <path>`）；rename/copy 的**源路径**紧随其后无前缀
        path = tok[3:] if re.match(r"^[ MADRCU?!]{1,2} ", tok) else tok
        rc2, blob, _ = _git(repo, "hash-object", "--no-filters", "--", path)
        blob = blob.strip() if rc2 == 0 else "?"
        files.append({"path": path, "blob": blob[:12]})
        h.update(("%s\0%s\0" % (path, blob)).encode("utf-8", "replace"))
    return {"ok": rc == 0, "repo": repo, "dirty_count": len(files),
            "fingerprint": h.hexdigest()[:16], "files": files}


def main(argv=None) -> None:
    av = list(sys.argv[1:] if argv is None else argv)
    if av and av[0] == "--ws-fingerprint":
        # 工作树一致性指纹（crossfull LLM 车道前后对拍用；只读，见 worktree_fingerprint docstring）
        print(json.dumps(worktree_fingerprint(av[1] if len(av) > 1 else os.getcwd()),
                         ensure_ascii=False))
        return
    repo = av[0] if av else os.getcwd()
    checks = {
        "repo_healthy": check_repo_healthy(repo),
        "stuck_locks": check_stuck_locks(repo),
        "windows_git_trace": check_windows_git_trace(repo),
        "dense_commit": check_dense_commit(repo),
        "fsck": check_fsck(repo),
        "index": check_index(repo),
    }
    flagged = [k for k, v in checks.items() if v.get("status") == "warn"]
    if not flagged:
        rec = "OK: no concurrency evidence"
    else:
        rec = ("CONCURRENCY RISK: " + ", ".join(flagged)
               + " — 统一 WSL git 操作(`wsl git -C <path>`); 若 windows_git_trace 命中, "
                 "检查 VS Code/Trae git 集成是否与 WSL git 并发; stuck_locks 可用 "
                 "`rm .git/*.lock` 清理(先确认无 git 进程运行)")
    print(json.dumps({"ok": not flagged, "repo": repo, "checks": checks,
                      "concurrency_detected": bool(flagged),
                      "recommendation": rec}, ensure_ascii=False))


if __name__ == "__main__":
    main()

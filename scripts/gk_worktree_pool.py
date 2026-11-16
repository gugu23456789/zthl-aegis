#!/usr/bin/env python3
"""gk_worktree_pool.py — worktree **热池**（派发 ms 级）。

病象（2026-11-10 实测）：派发一棵会话 worktree 要物化 2052 个 tracked 文件到 drvfs（9p）——
`git archive | tar -x` 到 ext4 4.4s / 到 `/mnt/c` **31.1s** ⟹ `apply-worktree --session` **34.4s**。
用户口径：派发须 **ms 级**（>1min 不可接受）。

热池做法：预建 K 个 slot（各是真 worktree，检出于 `gk-pool/<n>`，基于基线）。
  · **派发** = 在既有树上 `git checkout -B <session-branch> <baseline>`（树相同 ⟹ 不写文件）；
  · **回收** = 清回基线（reset/clean）+ 切回 `gk-pool/<n>` + 租约归池。

归属（E2 并发）：每槽一个 **O_EXCL claim 文件**（`slot-N.claim`）——创建成功即拥有，
不存在"两个会话拿到同一槽"的窗口；池满 ⟹ 立即 `POOL_EXHAUSTED`（**不**静默新建树）。

TTL 自动回收（E5）：`slot-N.lease.json` 带 `ts/ttl_s`。进程崩溃 / 忘记 release 时 claim 仍在，
`sweep()` 见到 `ts+ttl_s < now` 即收回（清理 → 归池），不依赖 release 被调用。

毒不外溢（E6）：**交付前**统一清理（`checkout -B` + `reset --hard` + `clean -ffd`：
丢弃 tracked 改动、删未跟踪毒件、伪造 state/claims 一并清除）；归还时同样清一次，
使下一个会话看不到上一个会话的任何残留。

与既有 TTL 面同源：租约 TTL 默认 `GK_POOL_TTL_S`（7200s）；既有 claims TTL
（`gk_git_lease.claim_ttl_s`）仍是"谁在写"的判据，二者分工不重叠。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

DEFAULT_SIZE = 3
MAX_SIZE = 8            # 硬上限：`--pool-size 10000` 会物化 10000 棵 worktree（磁盘/注册表打爆）
DEFAULT_TTL_S = 7200
POOL_DIRNAME = "_pool"
# 自动化流程引导（单源）：**所有**入口（CLI `--session` / `--pool-*` / 中枢
# `apply_worktree` / 模块直调）都必须带回同一份 next，禁让 agent 自己拼命令。
GUIDE_NOTE = ("热池派发：槽位复用，不物化文件。改动只在该 worktree 内 → commit"
              "（身份由 gk_commit_identity 落）→ 主树 `merge --no-ff` → push；"
              "归还走 `apply-worktree --reclaim`（池槽 = POOL-RELEASED，不删目录）。")
GUIDE_NEXT = "改 → 测试 → commit → 主树 merge --no-ff → push；归还 apply-worktree --reclaim"
GUIDE_STATUS = ("三态读法：leased=已被会话占用；free=可派发；expired=true ⟹ 下次 sweep 回收"
                "（回收前先归档）。权威判据见本模块 docstring，禁按目录名猜。")
# 池满（2026-11-16）：`full=true` 是**显式标记**，不是让调用方自己算 `free==0` ——
#   `free==0` 可能因 size=0（池未建）或全部 expired 而出现，语义完全不同。
GUIDE_FULL = ("池已满：派发会**回落冷建**（物化全量文件，drvfs 实测 ~34s）。"
              "可等他人归还 / TTL sweep 后重试，或 `--pool-ensure --pool-size N` 扩容"
              "（硬上限 %d）。expired=true 的槽无需等 TTL 到期 —— `--pool-sweep` 即可收回。"
              % MAX_SIZE)
# per-sid 派发限流（2026-11-11「让攻击不划算」）：抢槽/归还抖动会把池打爆 ⟹ 窗口内计数。
# 幂等复用（同 sid 同分支）在限流之前返回 ⟹ 不消耗配额；只对**真分配**计数。
RATE_LIMIT_DEFAULT = 20
RATE_WINDOW_S_DEFAULT = 300


def _pnorm(p) -> str:
    return str(p or "").replace("\\", "/").rstrip("/")


def root_allowed(worktrees_root) -> bool:
    """池根必须在 `DEV_WORKTREE_ROOTS` 白名单内（**堵** `--root /tmp/evil` 把 worktree 建到
    莫名其妙地方的入口）。排障逃生：`GK_POOL_ALLOW_ANY_ROOT=1`（只给测试/人工，不给 agent）。"""
    if os.environ.get("GK_POOL_ALLOW_ANY_ROOT") == "1":
        return True
    try:
        from gk_state_route import DEV_WORKTREE_ROOTS   # 延迟导入：不拖慢热路径启动
    except Exception:  # noqa: BLE001
        return False
    r = _pnorm(os.path.abspath(str(worktrees_root))).lower()
    return any(r == _pnorm(x).lower() or r.startswith(_pnorm(x).lower() + "/")
               for x in DEV_WORKTREE_ROOTS)


# 池只派发**会话分支**：主分支 / 池分支被占 = 直接破坏主树或池自身
_PROTECTED_BRANCHES = ("master", "main", "trunk", "develop", "HEAD")


def _git(repo, *args, timeout=180):
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True, timeout=timeout)


def _now() -> float:
    return time.time()


def _ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def pool_dir(main_repo, worktrees_root) -> Path:
    """池根：`<worktrees_root>/_pool/<repo-name>`（**不在** repo 子树内 ⟹ 不被孤儿扫描当残留）。

    `main_repo` **先绝对化**：`--repo .` 这类相对形态会让 `Path(".").name` 变成 `""`/`.`，
    池根退化成 `<root>/_pool`（实测 size=0 空转）。
    """
    return Path(worktrees_root) / POOL_DIRNAME / Path(os.path.abspath(str(main_repo))).name


def _slot_path(pd: Path, i: int) -> Path:
    return pd / ("slot-%d" % i)


def _claim_path(pd: Path, i: int) -> Path:
    return pd / ("slot-%d.claim" % i)


def _lease_path(pd: Path, i: int) -> Path:
    return pd / ("slot-%d.lease.json" % i)


def _read_json(p: Path, default=None):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _write_json(p: Path, data: dict) -> None:
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, p)


def _branch_exists(main_repo, branch: str) -> bool:
    return _git(main_repo, "show-ref", "--verify", "--quiet",
                "refs/heads/" + branch).returncode == 0


# ─── refs 文件层（**0 git 子进程**）：drvfs 实测 git 子进程 105–1270ms/次，文件读 3–8ms/次 ───
_HEX40 = re.compile(r"^[0-9a-f]{40}$")


def _read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _write_atomic(p: Path, text: str) -> bool:
    """临时件 + `os.replace`（与 `_write_json` 同款；**不** fsync ⟹ 保持热路径 ms 级）。"""
    tmp = p.with_name(p.name + ".gk-tmp")
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, p)
        return True
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        return False


def _gitdir_of(worktree) -> Path:
    """worktree 的 gitdir（读 `.git` 文件；linked worktree 形如 `<main>/.git/worktrees/<name>`）。"""
    dot = Path(str(worktree)) / ".git"
    if dot.is_dir():
        return dot
    raw = _read_text(dot).strip()
    if not raw.startswith("gitdir:"):
        return Path()
    p = raw[len("gitdir:"):].strip()
    q = Path(p) if p else Path()
    if not p:
        return Path()
    return q if q.is_absolute() else (Path(str(worktree)) / q).resolve()


def _common_dir(gitdir: Path) -> Path:
    """refs/objects 的共享目录：`<common>/.git/worktrees/<name>` ⟹ `<common>/.git`。"""
    if gitdir.parent.name == "worktrees" and gitdir.parent.parent.name == ".git":
        return gitdir.parent.parent
    return gitdir


def _head_ref(gitdir: Path) -> str:
    line = _read_text(gitdir / "HEAD").strip()
    return line[4:].strip() if line.startswith("ref:") else ""


def _resolve_ref(common: Path, ref: str) -> str:
    """松引用优先，其次 `packed-refs`（松引用天然遮蔽 packed 条目）。"""
    first = (_read_text(common / ref).strip().split() or [""])[0]
    if _HEX40.match(first):
        return first
    for ln in _read_text(common / "packed-refs").splitlines():
        if not ln or ln.startswith(("#", "^")):
            continue
        parts = ln.split()
        if len(parts) == 2 and parts[1] == ref and _HEX40.match(parts[0]):
            return parts[0]
    return ""


def _resolve_rev(gitdir: Path, rev: str) -> str:
    """`HEAD` / 分支名 / 全 ref / 40 位 sha ⟹ commit oid（**只读文件**）。"""
    common = _common_dir(gitdir)
    rev = str(rev or "").strip()
    if _HEX40.match(rev):
        return rev
    if rev in ("", "HEAD", "@"):
        hr = _head_ref(gitdir)
        if hr:
            return _resolve_ref(common, hr)
        raw = _read_text(gitdir / "HEAD").strip()
        return raw if _HEX40.match(raw) else ""
    if rev.startswith("refs/"):
        return _resolve_ref(common, rev)
    return _resolve_ref(common, "refs/heads/" + rev)


def slot_branch(worktree) -> str:
    """槽当前分支名（**0 子进程**：读 `gitdir/HEAD`）；detached ⟹ `""`。

    单源给 `gk_route_center.resolve_worktree` 用：池槽目录名恒 `slot-N`，**推不出**真分支名
    （租出后 HEAD 指向 `agent/session/<sha8>`），必须读真实 HEAD —— 禁按路径猜。
    """
    gd = _gitdir_of(worktree)
    if not gd:
        return ""
    ref = _head_ref(gd)
    return ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else ""


def _fast_switch(sp: Path, main_repo, branch: str, baseline: str) -> bool:
    """**0 子进程**派发：纯 refs 文件读写（提交相同 ⟹ 树相同 ⟹ 不写 2052 个文件）。

    三条前置（任一不满足 ⟹ `False`，调用方走 git 慢路径并统一清场）：
      ① 槽 HEAD 解析出的 commit == 基线 commit（否则是脏槽 / 漂移，先清再用 —— E6）；
      ② 目标分支**尚不存在**（已存在 ⟹ 交 git 判「是否已在别处检出」并保留该分支既有提交；
         这是 `checkout -B` 会**重置**既有分支的旧坑）；
      ③ gitdir 可解析（非标准布局 ⟹ 回退）。
    reflog 不在此写：切换不产生内容变更，提交时 git 自行写 HEAD reflog。
    """
    gd, mgd = _gitdir_of(sp), _gitdir_of(main_repo)
    if not gd or not mgd:
        return False
    common = _common_dir(gd)
    base_oid = _resolve_rev(mgd, baseline)
    hr = _head_ref(gd)
    if not base_oid or not hr:
        return False
    if _resolve_ref(common, hr) != base_oid:
        return False
    tgt = "refs/heads/" + branch
    if _resolve_ref(common, tgt):
        return False
    return (_write_atomic(common / tgt, base_oid + "\n")
            and _write_atomic(gd / "HEAD", "ref: " + tgt + "\n"))


def ensure_pool(main_repo, worktrees_root, size: int = DEFAULT_SIZE,
                baseline: str = "HEAD") -> dict:
    """建齐 K 个 slot（已存在则复用）。**冷路径**：允许秒级；派发热路径不经过这里。"""
    try:
        size = int(size)
    except (TypeError, ValueError):
        return {"ok": False, "error": "BAD_SIZE", "size": str(size)}
    if size < 1 or size > MAX_SIZE:
        return {"ok": False, "error": "BAD_SIZE", "size": size, "max": MAX_SIZE,
                "note": "池大小限 1..%d（每槽 = 一棵真 worktree）" % MAX_SIZE}
    pd = pool_dir(main_repo, worktrees_root)
    pd.mkdir(parents=True, exist_ok=True)
    slots = []
    for i in range(int(size)):
        sp = _slot_path(pd, i)
        br = "gk-pool/%d" % i
        if not (sp / ".git").exists():
            if _branch_exists(main_repo, br):
                r = _git(main_repo, "worktree", "add", "-q", str(sp), br)
            else:
                r = _git(main_repo, "worktree", "add", "-q", "-b", br, str(sp), baseline)
            if r.returncode != 0:
                return {"ok": False, "error": "POOL_PROVISION_FAILED",
                        "detail": (r.stderr or r.stdout).strip()[:400], "slot": i}
        lp = _lease_path(pd, i)
        if not lp.exists():
            _write_json(lp, {"slot": i, "path": str(sp), "branch": br, "state": "free",
                             "sid": "", "session_branch": "", "ts": "", "ttl_s": 0,
                             "clean": True})
        slots.append({"slot": i, "path": str(sp), "branch": br})
    return {"ok": True, "pool": str(pd), "slots": slots,
            "note": "冷建一次即够；之后派发走热槽（refs 切换，不物化文件）",
            "next": "bash gatekeeper-cli.sh apply-worktree --pool-status"}


def _clean_slot(main_repo, sp: Path, pool_branch: str, baseline: str) -> dict:
    """把槽位**物理清回基线**（交付前 / 归还前 / sweep 时统一走这里）。"""
    r1 = _git(sp, "checkout", "-q", "-B", pool_branch, baseline)
    r2 = _git(sp, "reset", "--hard", "-q", baseline)
    r3 = _git(sp, "clean", "-ffd", "-q")
    ok = r1.returncode == 0 and r2.returncode == 0 and r3.returncode == 0
    return {"ok": ok,
            "detail": "" if ok else (r1.stderr or r2.stderr or r3.stderr).strip()[:300]}


def _lease_state(pd: Path, i: int) -> dict:
    lease = _read_json(_lease_path(pd, i), {}) or {}
    claimed = _claim_path(pd, i).exists()
    expired = False
    if claimed:
        try:
            expired = _now() > float(lease.get("ts_epoch") or 0) + float(lease.get("ttl_s") or 0)
        except (TypeError, ValueError):
            expired = True
        if not lease:
            expired = True
    return {"slot": i, "claimed": claimed, "expired": expired, "lease": lease}


def status(main_repo, worktrees_root) -> dict:
    pd = pool_dir(main_repo, worktrees_root)
    slots = []
    if pd.is_dir():
        for lp in sorted(pd.glob("slot-*.lease.json")):
            try:
                i = int(lp.name.split(".")[0].split("-")[1])
            except (IndexError, ValueError):
                continue
            st = _lease_state(pd, i)
            slots.append({"slot": i, "path": st["lease"].get("path", str(_slot_path(pd, i))),
                          "branch": st["lease"].get("branch", "gk-pool/%d" % i),
                          "state": "leased" if st["claimed"] else "free",
                          "sid": st["lease"].get("sid", ""),
                          "ts": st["lease"].get("ts", ""),
                          "expired": st["expired"]})
    leased = sum(1 for s in slots if s["state"] == "leased")
    # `full` 只表示「全部槽都被占」；池未建（size=0）**不是满**（那是 NO_POOL，另一码事）。
    full = bool(slots) and leased >= len(slots)
    expired = [s["slot"] for s in slots if s.get("expired")]
    out = {"ok": True, "pool": str(pd), "size": len(slots), "leased": leased,
           "free": len(slots) - leased, "full": full, "slots": slots,
           "note": GUIDE_STATUS + ("｜" + GUIDE_FULL if full else "")}
    if full:
        # 满时给**可执行**降级路径（禁让 agent 自己拼命令）：有 expired 槽 ⟹ sweep 立即可收；
        # 无 expired ⟹ 只能等归还或扩容。
        out["degraded"] = "cold-build"
        out["next"] = (("bash gatekeeper-cli.sh apply-worktree --pool-sweep"
                        "   # %d 个槽已过 TTL，收回后立即可派" % len(expired))
                       if expired else
                       ("等他人归还 / TTL 到期；或 bash gatekeeper-cli.sh apply-worktree"
                        " --pool-ensure --pool-size N 扩容（当前 %d，硬上限 %d）"
                        % (len(slots), MAX_SIZE)))
    return out


def _rate_cfg() -> tuple[int, int]:
    """限流参数（env 仅给测试/运维逃生；默认 20 次 / 300s）。"""
    def _i(name, default):
        try:
            return max(1, int(os.environ.get(name, default)))
        except (TypeError, ValueError):
            return default
    return (_i("GK_POOL_RATE_LIMIT", RATE_LIMIT_DEFAULT),
            _i("GK_POOL_RATE_WINDOW_S", RATE_WINDOW_S_DEFAULT))


def _rate_file(pd: Path, sid: str) -> Path:
    """per-sid 计数文件（在池根 `_rate/` 下；不进 slot 命名空间 ⟹ 不干扰三态判定）。"""
    h = hashlib.sha256(str(sid or "").encode("utf-8", "replace")).hexdigest()[:16]
    return pd / "_rate" / (h + ".jsonl")


def rate_guard(pd: Path, sid: str, now: float | None = None) -> dict:
    """窗口内派发计数（**只对真分配调用**；超限 ⟹ `limited=True`，不碰任何槽位）。

    实现：文件尾追加一行时间戳；读侧按窗口过滤（decay 同 `gk_threat` 口径）。
    超 4×limit 才压缩，保证文件有界。
    """
    limit, window = _rate_cfg()
    now = time.time() if now is None else float(now)
    p = _rate_file(pd, sid)
    ts: list[float] = []
    try:
        for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                v = float(ln.strip())
            except ValueError:
                continue
            if now - window < v <= now:
                ts.append(v)
    except OSError:
        pass
    if len(ts) >= limit:
        return {"limited": True, "count": len(ts), "limit": limit, "window_s": window}
    ts.append(now)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write("%.3f\n" % now)
        if len(ts) > limit * 4:
            _write_atomic(p, "".join("%.3f\n" % t for t in ts))
    except OSError:
        pass          # 计数面失败不拦派发（限流是成本控制，不是正确性判据）
    return {"limited": False, "count": len(ts), "limit": limit, "window_s": window}


def acquire(main_repo, worktrees_root, sid: str, branch: str,
            baseline: str = "HEAD", ttl_s: int = DEFAULT_TTL_S) -> dict:
    """抢一个热槽并交付（**热路径**：只做 refs 切换，不物化文件）。"""
    sid = str(sid or "").strip()
    branch = str(branch or "").strip()
    # 归属靠租约 sid；空 sid = 无主槽（任何人可写）⟹ 直接拒
    if not sid:
        return {"ok": False, "error": "SID_REQUIRED",
                "note": "acquire 必须带会话 sid（租约归属与编辑续期都靠它）"}
    if not branch or branch in _PROTECTED_BRANCHES or branch.startswith("gk-pool/"):
        return {"ok": False, "error": "BRANCH_PROTECTED", "branch": branch,
                "note": "池只派发会话分支（agent/… / feature/… / standing/…）；主分支与池分支不可被占"}
    pd = pool_dir(main_repo, worktrees_root)
    if not pd.is_dir():
        return {"ok": False, "error": "NO_POOL", "pool": str(pd),
                "note": "池未建 ⟹ 派发会回落冷建（物化全量文件，drvfs 实测 ~34s）",
                "next": "bash gatekeeper-cli.sh apply-worktree --pool-ensure"}   # 一次性，之后 ms 级
    try:
        ttl_s = int(os.environ.get("GK_POOL_TTL_S", ttl_s) or ttl_s)
    except (TypeError, ValueError):
        pass
    # **一 sid 一槽**（2026-11-11 扩展场景 `pool-double-lease-01`）：已有**新鲜**租约时
    #   同分支 ⟹ 幂等回同一槽（重复调 apply-worktree 不该吃第二个槽）；换分支 ⟹ 拒。
    #   不变量：池容量不被同一会话悄悄翻倍占用。
    for lp in sorted(pd.glob("slot-*.lease.json")):
        try:
            i = int(lp.name.split(".")[0].split("-")[1])
        except (IndexError, ValueError):
            continue
        st = _lease_state(pd, i)
        lease = st.get("lease") or {}
        if not st["claimed"] or st["expired"] or str(lease.get("sid") or "") != sid:
            continue
        if str(lease.get("session_branch") or "") == branch:
            return {"ok": True, "slot": i, "worktree": str(_slot_path(pd, i)),
                    "branch": branch, "pool_branch": "gk-pool/%d" % i,
                    "reused": True, "idempotent": True, "ttl_s": lease.get("ttl_s"),
                    "note": GUIDE_NOTE, "next": GUIDE_NEXT}
        return {"ok": False, "error": "SID_ALREADY_LEASED", "slot": i,
                "branch": lease.get("session_branch"), "requested": branch,
                "note": "同一会话已有在租槽位；禁一 sid 占两槽（先 release 或复用原槽）"}
    # **per-sid 限流**（2026-11-11）：只对「真分配」计数（幂等复用已在上方返回 ⟹ 不吃配额）。
    # 目的 = 抢槽/归还抖动（acquire→release→acquire…）不能把池容量与派发面打爆。
    _rl = rate_guard(pd, sid)
    if _rl.get("limited"):
        return {"ok": False, "error": "RATE_LIMITED", "sid": sid,
                "limit": _rl["limit"], "window_s": _rl["window_s"], "count": _rl["count"],
                "note": "同一会话派发过于频繁（窗口内已达上限）；等窗口滑动，或复用已在租槽位"}
    tried = []
    for lp in sorted(pd.glob("slot-*.lease.json")):
        try:
            i = int(lp.name.split(".")[0].split("-")[1])
        except (IndexError, ValueError):
            continue
        cp = _claim_path(pd, i)
        try:
            fd = os.open(str(cp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            st = _lease_state(pd, i)
            tried.append({"slot": i, "state": "busy", "expired": st["expired"]})
            continue
        os.close(fd)
        sp = _slot_path(pd, i)
        pool_branch = "gk-pool/%d" % i
        prev_uses = int((_read_json(_lease_path(pd, i), {}) or {}).get("uses", 0))
        # **热路径（0 子进程）**：槽在基线 + 目标分支不存在 ⟹ 纯 refs 文件切换（实测 ~50ms）。
        # 任一前置不满足（脏槽 / 分支已存在 / 非标准 gitdir）⟹ 慢路径：**先清回基线**再切
        #   （E6：脏槽不得交付；`git checkout -B` 能"带脏"成功，故不能只靠它失败兜底）。
        switched = _fast_switch(sp, main_repo, branch, baseline)
        if not switched:
            chk = _clean_slot(main_repo, sp, pool_branch, baseline)
            hand = None
            if chk["ok"]:
                # 既有分支 ⟹ 平切（**保留**该分支提交；`-B` 会重置成基线 = 旧坑）
                if _branch_exists(main_repo, branch):
                    hand = _git(sp, "checkout", "-q", branch)
                else:
                    hand = _git(sp, "checkout", "-q", "-B", branch, baseline)
            if hand is None or hand.returncode != 0:
                try:
                    cp.unlink()
                except OSError:
                    pass
                detail = chk.get("detail") or ((hand.stderr or "").strip()[:300] if hand else "")
                return {"ok": False, "error": "POOL_SLOT_UNUSABLE", "slot": i,
                        "detail": detail}
        _write_json(_lease_path(pd, i), {
            "slot": i, "path": str(sp), "branch": pool_branch,
            "state": "leased", "sid": sid, "session_branch": branch,
            "ts": _ts(), "ts_epoch": _now(), "ttl_s": ttl_s, "clean": True,
            "uses": prev_uses + 1,
        })
        return {"ok": True, "slot": i, "worktree": str(sp), "branch": branch,
                "pool_branch": pool_branch, "reused": prev_uses > 0, "ttl_s": ttl_s,
                "note": GUIDE_NOTE, "next": GUIDE_NEXT}
    _exp = [t["slot"] for t in tried if t.get("expired")]
    return {"ok": False, "error": "POOL_EXHAUSTED", "pool": str(pd), "slots": tried,
            # 显式标记（2026-11-16）：调用方据此判断「是否降级冷建」，不必自己算 free==0。
            "full": True, "degraded": "cold-build", "expired": _exp,
            "note": "池满不静默新建树（否则派发重新退化为 34s 冷建）；" + GUIDE_FULL,
            "next": ("bash gatekeeper-cli.sh apply-worktree --pool-sweep"
                     "   # %d 个槽已过 TTL" % len(_exp)) if _exp else
                    "等他人归还或 TTL 到期；确需扩容走 apply-worktree --pool-ensure --pool-size N"}


def release(main_repo, worktrees_root, worktree, baseline: str = "HEAD") -> dict:
    """归还槽位：清回基线 + 切回池分支 + 释放 claim（下一个会话拿到的是干净树）。"""
    pd = pool_dir(main_repo, worktrees_root)
    target = os.path.abspath(str(worktree))
    for lp in sorted(pd.glob("slot-*.lease.json")):
        try:
            i = int(lp.name.split(".")[0].split("-")[1])
        except (IndexError, ValueError):
            continue
        sp = _slot_path(pd, i)
        if os.path.abspath(str(sp)) != target:
            continue
        pool_branch = "gk-pool/%d" % i
        prev = _read_json(lp, {}) or {}
        # 归还同样**先归档**：`_clean_slot` 会丢弃未提交改动（误 release 不该等于删档）。
        arc = _archive_slot(sp, pd, i)
        if not arc.get("ok"):
            return {"ok": False, "error": "ARCHIVE_FAILED", "slot": i,
                    "detail": arc.get("detail")}
        chk = _clean_slot(main_repo, sp, pool_branch, baseline)
        if not chk["ok"]:
            return {"ok": False, "error": "RELEASE_CLEAN_FAILED", "slot": i,
                    "detail": chk.get("detail")}
        _write_json(lp, {"slot": i, "path": str(sp), "branch": pool_branch,
                         "state": "free", "sid": "", "session_branch": "",
                         "ts": "", "ts_epoch": 0, "ttl_s": 0, "clean": True,
                         "uses": int(prev.get("uses", 0))})
        try:
            _claim_path(pd, i).unlink()
        except OSError:
            pass
        return {"ok": True, "slot": i, "worktree": str(sp), "freed": True,
                "archived": arc if arc.get("archived") else None}
    return {"ok": False, "error": "NOT_A_SLOT", "worktree": str(worktree)}


def _archive_slot(sp: Path, pd: Path, i: int) -> dict:
    """**清理前先归档**（与 `gk_worktree_reclaim` 的「归档前置不可跳过」同原则）。

    病象：TTL 到期 ⟹ 清理 = `reset --hard` + `clean -ffd` ⟹ 槽里**未提交的工作会被静默销毁**。
    回收链早已把「先归档再删」定为硬约束（`ECC-35AC08DA96F0`），热池不能开倒车。故：
      · `changes.diff` = `git diff HEAD`（tracked 改动全文）；
      · `untracked/<rel>` = 未跟踪文件**逐字节副本**；
      · `status.txt` = `git status --porcelain -z` 明细（含删除/重命名，便于人工还原）。
    落点 `<pool>/archive/slot-<n>-<UTC>/`（池根下，**不在**任何 worktree 内 ⟹ 不被清场误删）。
    """
    out = pd / "archive" / ("slot-%d-%s" % (i, time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())))
    st = _git(sp, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    if st.returncode != 0:
        return {"ok": False, "error": "STATUS_FAILED", "detail": (st.stderr or "").strip()[:300]}
    entries = [t for t in (st.stdout or "").split("\0") if t]
    if not entries:
        return {"ok": True, "archived": False}
    try:
        out.mkdir(parents=True, exist_ok=True)
        (out / "changes.diff").write_text((_git(sp, "diff", "HEAD").stdout or ""),
                                          encoding="utf-8")
        (out / "status.txt").write_text("\n".join(entries), encoding="utf-8")
        copied = []
        for tok in entries:
            if not tok.startswith("?? "):
                continue
            rel = tok[3:]
            src = Path(sp) / rel
            if src.is_file():
                dst = out / "untracked" / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
                copied.append(rel)
    except OSError as e:
        return {"ok": False, "error": "ARCHIVE_FAILED", "detail": str(e)[:300]}
    return {"ok": True, "archived": True, "dir": str(out), "untracked": copied}


def sweep(main_repo, worktrees_root, baseline: str = "HEAD", archive: bool = True) -> dict:
    """TTL 自动回收：`ts+ttl_s < now` 的 claim 一律收回（清理 → 归池）。"""
    pd = pool_dir(main_repo, worktrees_root)
    reclaimed, kept, failed, archived = [], [], [], []
    if not pd.is_dir():
        return {"ok": True, "reclaimed": 0, "kept": 0, "failed": 0, "archived": []}
    for lp in sorted(pd.glob("slot-*.lease.json")):
        try:
            i = int(lp.name.split(".")[0].split("-")[1])
        except (IndexError, ValueError):
            continue
        st = _lease_state(pd, i)
        if not st["claimed"]:
            continue
        if not st["expired"]:
            kept.append(i)
            continue
        sp = _slot_path(pd, i)
        pool_branch = "gk-pool/%d" % i
        prev = _read_json(lp, {}) or {}
        # **归档前置**（2026-11-10）：脏槽清理会销毁未提交工作 ⟹ 先落 archive，归档失败即**拒清**。
        if archive:
            arc = _archive_slot(sp, pd, i)
            if not arc.get("ok"):
                failed.append({"slot": i, "detail": arc.get("detail"), "error": arc.get("error")})
                continue
            if arc.get("archived"):
                archived.append({"slot": i, **arc})
        else:
            arc = {"ok": True, "archived": False}
        chk = _clean_slot(main_repo, sp, pool_branch, baseline)
        if not chk["ok"]:
            failed.append({"slot": i, "detail": chk.get("detail")})
            continue
        _write_json(lp, {"slot": i, "path": str(sp), "branch": pool_branch,
                         "state": "free", "sid": "", "session_branch": "",
                         "ts": "", "ts_epoch": 0, "ttl_s": 0, "clean": True,
                         "uses": int(prev.get("uses", 0))})
        try:
            _claim_path(pd, i).unlink()
        except OSError:
            pass
        reclaimed.append(i)
    return {"ok": not failed, "reclaimed": len(reclaimed), "kept": len(kept),
            "failed": len(failed), "archived": archived,
            "slots": {"reclaimed": reclaimed, "kept": kept, "failed": failed}}


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(description="worktree 热池（派发 ms 级）")
    p.add_argument("--repo", required=True)
    p.add_argument("--root", required=True)
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("ensure")
    e.add_argument("--size", type=int, default=DEFAULT_SIZE)
    e.add_argument("--baseline", default="HEAD")
    a = sub.add_parser("acquire")
    a.add_argument("--sid", required=True)
    a.add_argument("--branch", required=True)
    a.add_argument("--baseline", default="HEAD")
    r = sub.add_parser("release")
    r.add_argument("--worktree", required=True)
    r.add_argument("--baseline", default="HEAD")
    s = sub.add_parser("sweep")
    s.add_argument("--baseline", default="HEAD")
    sub.add_parser("status")
    ns = p.parse_args(argv)
    # 池根白名单（堵 `--root /tmp/evil` 把 worktree 建到莫名其妙的地方）
    if not root_allowed(ns.root):
        print(json.dumps({"ok": False, "error": "ROOT_NOT_ALLOWED", "root": str(ns.root),
                          "note": "池根必须在 DEV_WORKTREE_ROOTS 白名单内（单源 = gk_state_route）",
                          "next": "用 bash gatekeeper-cli.sh apply-worktree --pool-*（根由 route-root 给出）"},
                         ensure_ascii=False))
        return 2
    if ns.cmd == "ensure":
        out = ensure_pool(ns.repo, ns.root, ns.size, ns.baseline)
    elif ns.cmd == "acquire":
        out = acquire(ns.repo, ns.root, ns.sid, ns.branch, ns.baseline)
    elif ns.cmd == "release":
        out = release(ns.repo, ns.root, ns.worktree, ns.baseline)
    elif ns.cmd == "sweep":
        out = sweep(ns.repo, ns.root, ns.baseline)
    else:
        out = status(ns.repo, ns.root)
    print(json.dumps(out, ensure_ascii=False))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())

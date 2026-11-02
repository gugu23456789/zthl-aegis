#!/usr/bin/env python3
"""repo 级 git 写 lease —— 锁语义**唯一实现**（R-CONC-GIT 一期 · 设计 L，2026-09-30）。

来源：`docs/plans/2026-09-28-git-concurrency-lease-declare-plan.md` §2（设计 L）/ §7（kill switch）/ §8（反例）。

载体：`<repo>/.git/gk-git-write.lease`
  ⚠ 后缀是 `.lease` **而非** `.lock` —— §8 反例明列：「新 lease 文件**不得**被
  `gk_git_concurrency_check.check_stuck_locks` 的 `.git/*.lock` glob 命中」（否则超龄 lease
  会被误判为 git 内部 `stuck_lock`，产假告警）。原计划 §2 写作 `gk-git-write.lock`，
  本批订正为 `.lease`（改动面最小：不动既有检测器）。

协议（正本，禁第二实现）：
  · **创建者** = 调用方（`cmd_commit`）在临界段前**自己创建**（`O_CREAT|O_EXCL`，写 pid/sid/host/ts）；
  · **释放点** = 临界段正常结束（含异常路径）；
  · **超时语义** = 年龄 < TTL 且持有进程活 ⟹ **活锁 fail-loud 不抢**（抢活锁 = 与真在跑的写相撞）；
    超期 或 持有进程已亡 ⟹ **孤儿**，**归档（非删除）**到回收站单源 `gk_route_center.trash_dir` 后放行。

**TTL 单源（治 §9-ASSUMPTION-3「双 TTL 静默失效」）**：lease 的判活/归档阈值 = `claim_ttl_s()`
（`GK_CLAIM_TTL_S`，默认 3600）—— 与设计 D 的 write-claims 台账**同源**，故「长编辑会话」不会
因 lease 用短 grace(120s) 被判孤儿而**静默失去互斥**。
  ⚠ `GK_COMMIT_LOCK_GRACE`(=120) 仍只是**既有 `index.lock` preflight** 的阈值，**语义保持不变**。

kill switch：`GK_GIT_LEASE=0` ⟹ 调用方（`cmd_commit`）**完全跳过** lease（应急；不删实现）。
"""
import argparse
import json
import os
import socket
import shutil
import subprocess
import sys
import time
from pathlib import Path

LEASE_NAME = "gk-git-write.lease"
CLAIM_TTL_DEFAULT = 3600
GRACE_DEFAULT = 120
_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"


# ─────────────────────────── 阈值（单源）───────────────────────────
def claim_ttl_s() -> int:
    """claim/lease 共用的 TTL 源（设计 D 的 `gk_write_claims` 亦读本函数 ⟹ 单源）。"""
    try:
        return int(os.environ.get("GK_CLAIM_TTL_S") or CLAIM_TTL_DEFAULT)
    except (TypeError, ValueError):
        return CLAIM_TTL_DEFAULT


def lease_grace_s() -> int:
    """既有 `index.lock` preflight 的阈值（`GK_COMMIT_LOCK_GRACE`；语义**保持不变**）。"""
    try:
        return int(os.environ.get("GK_COMMIT_LOCK_GRACE") or GRACE_DEFAULT)
    except (TypeError, ValueError):
        return GRACE_DEFAULT


# ─────────────────────────── 工具 ───────────────────────────
def _git_dirs(repo: str) -> tuple:
    """→ `(git_dir, common_dir)`（**worktree 支持**；2026-09-30 修 `ECC-B42D0F9B136C`）。

    git worktree 下 `<repo>/.git` 是**文件**（`gitdir: <主仓>/.git/worktrees/<n>`）而非目录 ⟹
    原 `lease_path` 假设目录 ⟹ `acquire` 在 worktree 恒 `LEASE_HELD: 非 git 仓`（**而主工作流就是 worktree**）。
    权威解析走 `git rev-parse --git-dir/--git-common-dir`；git 不可用时回退按 `.git` 文件解析。
    """
    try:
        out = subprocess.run(["git", "-C", repo, "rev-parse", "--git-dir", "--git-common-dir"],
                             capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            lines = [l.strip() for l in out.stdout.splitlines() if l.strip()]
            if len(lines) >= 2:
                gd = lines[0] if os.path.isabs(lines[0]) else os.path.join(repo, lines[0])
                cd_ = lines[1] if os.path.isabs(lines[1]) else os.path.join(repo, lines[1])
                gd, cd_ = os.path.realpath(gd), os.path.realpath(cd_)
                if os.path.isdir(gd):
                    return (gd, cd_ if os.path.isdir(cd_) else gd)
    except (OSError, subprocess.SubprocessError):
        pass
    p = Path(repo) / ".git"
    if p.is_dir():
        return (str(p), str(p))
    if p.is_file():
        try:
            txt = p.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return (str(p), str(p))
        if txt.startswith("gitdir:"):
            gd = txt.split("gitdir:", 1)[1].strip()
            if not os.path.isabs(gd):
                gd = str((p.parent / gd).resolve())
            cm = Path(gd) / "commondir"
            if cm.is_file():
                try:
                    c = cm.read_text(encoding="utf-8").strip()
                    cd_ = c if os.path.isabs(c) else str((Path(gd) / c).resolve())
                    return (os.path.realpath(gd), os.path.realpath(cd_))
                except OSError:
                    pass
            return (os.path.realpath(gd), os.path.realpath(gd))
    return (str(p), str(p))


def lease_path(repo: str) -> str:
    """lease 落 **common** git dir（repo 级 = 跨 worktree 共享）；worktree 下 `.git` 是文件 ⟹ 先解析。"""
    return os.path.join(_git_dirs(repo)[1], LEASE_NAME)


def _ts_now() -> str:
    return time.strftime(_TS_FMT, time.gmtime())


def _parse_ts(ts) -> float:
    try:
        return time.mktime(time.strptime(str(ts), _TS_FMT)) - time.timezone
    except (TypeError, ValueError):
        return None


def _age_s(rec: dict):
    t = _parse_ts((rec or {}).get("ts"))
    return None if t is None else max(0.0, time.time() - t)


def _pid_alive(pid) -> bool:
    try:
        p = int(pid)
    except (TypeError, ValueError):
        return False
    if p <= 0:
        return False
    if os.path.isdir("/proc/%d" % p):
        return True
    try:
        os.kill(p, 0)          # 非 Linux（无 /proc）时的兜底
        return True
    except OSError:
        return False


def _trash_dir() -> str:
    d = os.environ.get("GK_TRASH_DIR")
    if d:
        return d
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import gk_route_center as r  # noqa: E402
        return str(r.trash_dir(str(Path(__file__).resolve().parent.parent)))
    except Exception:
        return str(Path(__file__).resolve().parent.parent.parent / ".gk-trash")


def _archive(path: str, trash_dir: str = None) -> str:
    """孤儿锁**归档（非删除）**；返回归档落点（失败 ⟹ `None`）。命名对齐既有 `index.lock.stale-*`。"""
    if not os.path.exists(path):
        return None
    tr = trash_dir or _trash_dir()
    try:
        os.makedirs(tr, exist_ok=True)
    except OSError:
        return None
    stamp = time.strftime("%Y%m%dT%H%M%S")
    dst = os.path.join(tr, "%s.stale-%s" % (os.path.basename(path), stamp))
    if os.path.exists(dst):
        dst = "%s-%d" % (dst, os.getpid())
    try:
        # ⚠ 必须容**跨设备**：仓在 /tmp（Linux fs）而回收站在 /mnt/c（drvfs）时 `os.replace`
        #   会报 `Invalid cross-device link`（实测）⟹ 用 `shutil.move`（自动退化为 copy+unlink）。
        shutil.move(path, dst)
        return dst
    except (OSError, shutil.Error):
        return None


# ─────────────────────────── 获取 / 释放 ───────────────────────────
def acquire(repo: str, sid: str = "", pid: int = None, trash_dir: str = None) -> dict:
    """临界段前**自己创建**锁；活锁 fail-loud（不抢）、孤儿归档后放行。"""
    _gd, _cd = _git_dirs(repo)
    if not os.path.isdir(_cd):
        return {"ok": False, "lock": "",
                "error": "LEASE_HELD: 非 git 仓，无 `.git` / common dir：%s" % os.path.abspath(repo)}
    p = os.path.join(_cd, LEASE_NAME)
    pid = os.getpid() if pid is None else pid
    ttl = claim_ttl_s()
    archived = None
    if os.path.exists(p):
        rec = {}
        try:
            rec = json.loads(Path(p).read_text(encoding="utf-8")) or {}
        except Exception:
            rec = {}
        age = _age_s(rec)
        holder = rec.get("pid")
        if age is None or age < ttl:
            if age is None or _pid_alive(holder):
                return {"ok": False, "lock": p,
                        "error": ("LEASE_HELD: %s 年龄 %ss < GK_CLAIM_TTL_S=%ss 且持有进程(pid=%s)活 "
                                  "⟹ 不抢锁，稍后重试" % (p, age, ttl, holder))}
        archived = _archive(p, trash_dir)
        if archived is None:
            return {"ok": False, "lock": p, "error": "LEASE_HELD: 孤儿锁存在且无法归档: %s" % p}
    rec = {"pid": pid, "sid": sid, "host": socket.gethostname(),
           "ts": _ts_now(), "repo": os.path.abspath(repo)}
    try:
        fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        return {"ok": False, "lock": p, "error": "LEASE_HELD: 竞争写者已抢先创建（O_EXCL）"}
    except OSError as e:
        return {"ok": False, "lock": p, "error": "LEASE_HELD: 创建失败 %s" % e}
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(rec, ensure_ascii=False))
    return {"ok": True, "lock": p, "archived": archived, "ttl_s": ttl}


def release(lock_path: str) -> dict:
    """释放**自己创建**的锁（归档只用于孤儿；正常释放 = 删除本体，否则会阻塞后续写者）。"""
    if not lock_path or not os.path.exists(lock_path):
        return {"ok": True, "released": False, "lock": lock_path or ""}
    try:
        os.remove(lock_path)
        return {"ok": True, "released": True, "lock": lock_path}
    except OSError as e:
        return {"ok": False, "released": False, "lock": lock_path, "error": str(e)}


# ─────────────────────────── 既有 `index.lock` preflight（逐字保持）───────────────────────────
def _live_git_on(repo_real: str) -> bool:
    """**只认名为 `git` 的进程**，再看其 cwd/cmdline 是否指向本仓（对齐既有 bash 实现）。"""
    try:
        pids = subprocess.run(["pgrep", "-x", "git"], capture_output=True, text=True,
                              timeout=10).stdout.split()
    except (OSError, subprocess.SubprocessError):
        return False
    for pid in pids:
        try:
            cl = Path("/proc/%s/cmdline" % pid).read_bytes().replace(b"\0", b" ").decode(
                "utf-8", "replace")
        except OSError:
            cl = ""
        try:
            cw = os.path.realpath("/proc/%s/cwd" % pid)
        except OSError:
            cw = ""
        if repo_real and repo_real in (cl + "|" + cw):
            return True
    return False


def preflight(repo: str, trash_dir: str = None):
    """既有 `_gk_commit_lock_preflight` 的语义迁移（**行为逐字保持、不新增拒绝**）。

    返回 `(rc, stdout_str, stderr_str)`；调用方只负责原样打印与 `return rc`。
    ⚠ `trash_dir` 由**调用方**按自己的 `$SKILL_DIR` 传入（回收站是「谁的技能根就归谁」）——
    否则沙箱对照臂（`test_gk_commit_guard.py`）会因回收落点错位而假红（实测）。
    """
    rp = os.path.realpath(repo)
    # worktree 下 `index.lock` 落在**本 worktree 自己的** git dir（非 common）⟹ 先解析（ECC-B42D0F9B136C）。
    lk = os.path.join(_git_dirs(repo)[0], "index.lock")
    if not os.path.exists(lk):
        return 0, "", ""
    now = int(time.time())
    try:
        mt = int(os.stat(lk).st_mtime)
    except OSError:
        mt = now
    age = now - mt
    grace = lease_grace_s()
    if age < grace:
        return 1, json.dumps({"ok": False, "error": (
            "COMMIT_LOCK_HELD: %s 年龄 %ss < GK_COMMIT_LOCK_GRACE=%ss（可能真在跑）⟹ 不抢锁，稍后重试"
            % (lk, age, grace))}, ensure_ascii=False), ""
    if _live_git_on(rp):
        return 1, json.dumps({"ok": False, "error": (
            "COMMIT_LOCK_HELD: 检测到 git 进程正操作 %s ⟹ 不抢锁（活锁）" % rp)},
            ensure_ascii=False), ""
    dst = _archive(lk, trash_dir)
    if dst:
        return 0, "", "WARN[commit]: 孤儿锁已归档（非删除）: %s\n" % dst
    return 1, json.dumps({"ok": False, "error": (
        "COMMIT_LOCK_HELD: 锁存在且无法归档: %s" % lk)}, ensure_ascii=False), ""


# ─────────────────────────── 合并结果硬校验（§15.7 一期）───────────────────────────
def _git_out(repo: str, *args: str):
    """→ `(rc, stdout)`；git 不可用/超时 ⟹ `(None, "")`。"""
    try:
        r = subprocess.run(["git", "-C", repo] + list(args),
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None, ""
    return r.returncode, r.stdout


def verify_merge_result(repo: str, ours: str, theirs: str, result: str = None) -> dict:
    """**合并结果硬校验**（治「空合并」；§15.6 病象 / §15.7 一期）。

    判据（确定性；由 §15.6 反例标定）：
      · **空合并**：`diff --name-only <ours> <result>` 为空 **且** `diff --name-only <ours> <theirs>`
        非空 ⟹ 结果 tree == ours，被并分支的变更**全丢**；
      · **丢文件**：`diff --name-status <theirs> <result>` 含 `D`（分支有、结果无）。

    `result` 缺省 `HEAD`。返回 `{"ok", "verdict", "empty_merge", "dropped", "detail"}`，
    `verdict ∈ ok | empty_merge | dropped_files | unavailable`。
    ⚠ **不静默放行**：git 不可用 / 参数不可解 ⟹ `ok=False, verdict=unavailable`（fail-loud）。
    """
    res = result or "HEAD"
    rc_o, out_o = _git_out(repo, "diff", "--name-only", ours, res)
    rc_t, out_t = _git_out(repo, "diff", "--name-only", ours, theirs)
    if rc_o is None or rc_t is None or rc_o != 0 or rc_t != 0:
        return {"ok": False, "verdict": "unavailable", "empty_merge": False, "dropped": [],
                "error": ("VERIFY_UNAVAILABLE: git 不可用或参数不可解 "
                          "(repo=%s ours=%s theirs=%s result=%s)" % (repo, ours, theirs, res))}
    ours_diff = [l for l in out_o.splitlines() if l.strip()]
    theirs_diff = [l for l in out_t.splitlines() if l.strip()]
    rc_s, out_s = _git_out(repo, "diff", "--name-status", theirs, res)
    dropped = []
    if rc_s == 0:
        for line in out_s.splitlines():
            parts = [x for x in line.split("\t") if x != ""]
            if len(parts) >= 2 and parts[0][:1] == "D":      # 仅 D（rename 记 R*，不算丢）
                dropped.append(parts[1])
    if (not ours_diff) and theirs_diff:
        return {"ok": False, "verdict": "empty_merge", "empty_merge": True, "dropped": dropped,
                "detail": ("空合并：结果 tree == ours(%s)；被并 %s 有 %d 项变更未纳入"
                           % (ours, theirs, len(theirs_diff)))}
    if dropped:
        return {"ok": False, "verdict": "dropped_files", "empty_merge": False, "dropped": dropped,
                "detail": ("被并分支有 %d 个文件未出现在结果中：%s"
                           % (len(dropped), ", ".join(dropped[:10])))}
    return {"ok": True, "verdict": "ok", "empty_merge": False, "dropped": [],
            "detail": "合并结果已纳入被并分支变更（ours→result %d 项）" % len(ours_diff)}


# ─────────────────────────── CLI ───────────────────────────
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_git_lease.py", add_help=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("acquire"); a.add_argument("repo"); a.add_argument("--sid", default="")
    a.add_argument("--trash", default=None)
    r = sub.add_parser("release"); r.add_argument("--lock", required=True)
    p = sub.add_parser("preflight"); p.add_argument("repo"); p.add_argument("--trash", default=None)
    v = sub.add_parser("verify-merge")
    v.add_argument("repo"); v.add_argument("--ours", required=True)
    v.add_argument("--theirs", required=True); v.add_argument("--result", default=None)
    ns = ap.parse_args(argv)

    if ns.cmd == "acquire":
        out = acquire(ns.repo, sid=ns.sid, trash_dir=ns.trash)
        print(json.dumps(out, ensure_ascii=False))
        return 0 if out.get("ok") else 1
    if ns.cmd == "release":
        out = release(ns.lock)
        print(json.dumps(out, ensure_ascii=False))
        return 0 if out.get("ok") else 1
    if ns.cmd == "verify-merge":
        out = verify_merge_result(ns.repo, ns.ours, ns.theirs, ns.result)
        print(json.dumps(out, ensure_ascii=False))
        return 0 if out.get("ok") else 1
    rc, out, err = preflight(ns.repo, trash_dir=ns.trash)
    if out:
        print(out)
    if err:
        sys.stderr.write(err)
    return rc


if __name__ == "__main__":
    sys.exit(main())

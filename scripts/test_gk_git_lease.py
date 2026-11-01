#!/usr/bin/env python3
"""设计 L 红先臂：repo 级 git 写 lease（`scripts/gk_git_lease.py`）。

来源：`docs/plans/2026-09-28-git-concurrency-lease-declare-plan.md` §2（设计 L）+ §8（反例表）+ §9 `[ASSUMPTION-3]`。

**缺口（G2）**：`commit` 有 preflight、但 `merge`/`push` 无写锁，且跨 worktree 的**写互斥**无单源实现。

**锁语义（本文件钉住）**：
  ① 空闲仓 ⟹ `acquire` 成功，锁文件记录 `pid`/`sid`/`host`/`ts`；
  ② **活锁不抢**（年龄 < TTL 且持有进程活）⟹ `LEASE_HELD` fail-loud，**且不动**原锁（防与真在跑的写相撞）；
  ③ **孤儿归档**（超期或持有进程已亡）⟹ 移到回收站（**归档非删除**）后放行；
  ④ `release` 后可再次 `acquire`；
  ⑤ **反例**：锁文件**不得**被 `gk_git_concurrency_check.check_stuck_locks` 的 `.git/*.lock` glob 命中
     （否则超龄 lease 会被误判为 git 内部 stuck_lock）；
  ⑥ **双 TTL 单源**：lease 的判活/归档阈值 == claim TTL 源（`gk_git_lease.claim_ttl_s()`；
     `GK_CLAIM_TTL_S` 默认 3600）—— 治「长编辑会话超短 grace 被判孤儿 ⟹ 互斥静默失效」。
     ⚠ `GK_COMMIT_LOCK_GRACE`(=120) 仍是**既有 `index.lock` preflight** 的阈值，**语义保持不变**；
  ⑦ `preflight` 对无锁仓**零输出 rc=0**（既有 `test_gk_commit_guard.py` 为逐字保持的对照网）。

⚠ 文件后缀 `.lease`（**非** `.lock`）是**刻意**的：见反例⑤。原计划 §2 写作 `gk-git-write.lock`，
本批订正为 `.lease`（改动面最小：不动既有检测器）。
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import gk_git_lease as L  # noqa: E402

LEASE_NAME = "gk-git-write.lease"


def _mk_repo(tmp_path: Path) -> Path:
    """真 `.git` 仓（`acquire` 要写 `<repo>/.git/`，且反例⑤要能跑既有检测器）。"""
    rp = (tmp_path / "repo").resolve()
    rp.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(rp)], capture_output=True, text=True, timeout=60)
    return rp


def _lock(rp: Path) -> Path:
    return rp / ".git" / LEASE_NAME


# ── 臂① 空闲仓 ⟹ 获取成功 + 记录字段齐 ─────────────────────────────────────
def test_arm1_acquire_on_free_repo(tmp_path):
    rp = _mk_repo(tmp_path)
    r = L.acquire(str(rp), sid="deadbeef" * 3)
    assert r.get("ok") is True, f"空闲仓获取失败：{r}"
    p = Path(r["lock"])
    assert p.exists(), f"锁文件未创建：{p}"
    rec = json.loads(p.read_text(encoding="utf-8"))
    for k in ("pid", "sid", "host", "ts"):
        assert k in rec, f"锁记录缺字段 `{k}`：{rec}"
    assert rec["pid"] == os.getpid(), f"pid 非持有者：{rec}"


# ── 臂② 活锁 fail-loud ⟹ 不抢、原锁逐字不变 ─────────────────────────────────
def test_arm2_live_lease_fails_loud_without_stealing(tmp_path):
    rp = _mk_repo(tmp_path)
    first = L.acquire(str(rp), sid="aaaa")
    assert first.get("ok") is True, first
    before = _lock(rp).read_text(encoding="utf-8")
    second = L.acquire(str(rp), sid="bbbb")
    assert second.get("ok") is False, f"**抢锁**：活锁竟然放行第二个持有者：{second}"
    assert "LEASE_HELD" in (second.get("error") or ""), f"错误码口径错：{second}"
    assert _lock(rp).read_text(encoding="utf-8") == before, "活锁被改动（应逐字不动）"


# ── 臂③ 孤儿 ⟹ 归档（非删除）后放行 ────────────────────────────────────────
def test_arm3_orphan_is_archived_not_deleted(tmp_path):
    rp = _mk_repo(tmp_path)
    p = _lock(rp)
    stale = {"pid": 999999, "sid": "gone", "host": "x",
             "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 10 ** 6))}
    p.write_text(json.dumps(stale), encoding="utf-8", newline="\n")
    r = L.acquire(str(rp), sid="cccc")
    assert r.get("ok") is True, f"孤儿锁未归档放行：{r}"
    assert r.get("archived"), f"未回报归档落点：{r}"
    assert Path(r["archived"]).exists(), f"归档目标不存在（= 删除而非归档）：{r}"
    assert not p.exists() or json.loads(p.read_text(encoding="utf-8"))["sid"] == "cccc", \
        "旧锁未被归档而残留"


# ── 臂④ release 后可再获取 ─────────────────────────────────────────────────
def test_arm4_release_then_acquire(tmp_path):
    rp = _mk_repo(tmp_path)
    r1 = L.acquire(str(rp), sid="dddd")
    assert r1.get("ok") is True, r1
    rel = L.release(lock_path=r1["lock"])
    assert rel.get("ok") is True and rel.get("released") is True, f"释放失败：{rel}"
    assert not Path(r1["lock"]).exists(), "释放后锁文件仍在"
    assert L.acquire(str(rp), sid="eeee").get("ok") is True, "释放后仍无法获取"


# ── 臂⑤ 反例：锁文件名不被既有 `*.lock` glob 命中 ──────────────────────────
def test_arm5_lock_name_not_caught_by_stuck_locks(tmp_path):
    rp = _mk_repo(tmp_path)
    assert L.acquire(str(rp), sid="ffff").get("ok") is True
    import gk_git_concurrency_check as cc
    res = cc.check_stuck_locks(str(rp))
    names = [x.get("name") for x in (res.get("stuck_locks") or [])]
    assert LEASE_NAME not in names, (
        f"lease 被误判为 git 内部 stuck_lock（超龄即假告警）：{res}")
    assert LEASE_NAME.endswith(".lease") or not LEASE_NAME.endswith(".lock"), (
        "lease 文件名不得以 `.lock` 结尾（会被 `.git/*.lock` glob 命中）")


# ── 臂⑥ 双 TTL 单源：归档阈值 == claim TTL 源 ───────────────────────────────
def test_arm6_orphan_threshold_is_claim_ttl_single_source(tmp_path, monkeypatch):
    rp = _mk_repo(tmp_path)
    rec = {"pid": os.getpid(), "sid": "self", "host": "x",
           "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 2))}
    _lock(rp).write_text(json.dumps(rec), encoding="utf-8", newline="\n")
    monkeypatch.delenv("GK_CLAIM_TTL_S", raising=False)
    assert L.claim_ttl_s() == 3600, f"claim TTL 缺省值应为 3600：{L.claim_ttl_s()}"
    assert L.acquire(str(rp), sid="x").get("ok") is False, \
        "年龄 2s < 缺省 TTL 3600 ⟹ 持有进程活，须 fail-loud"
    monkeypatch.setenv("GK_CLAIM_TTL_S", "1")
    assert L.claim_ttl_s() == 1
    assert L.acquire(str(rp), sid="x").get("ok") is True, \
        "TTL 降到 1s 后同一年龄的锁须判孤儿（证明归档阈值**同源**于 claim TTL）"


# ── 臂⑦ preflight：无锁仓零输出 rc=0 ───────────────────────────────────────
def test_arm7_preflight_clean_repo_is_silent(tmp_path):
    rp = _mk_repo(tmp_path)
    rc, out, err = L.preflight(str(rp))
    assert rc == 0, f"无锁仓 preflight 应放行：rc={rc} out={out} err={err}"
    assert out.strip() == "", f"无锁仓不应有输出：{out!r}"


# ── 臂⑧–⑩ 真 CLI 接线（复用 `test_gk_commit_guard.py` 沙箱契约，避免第二份 harness）──
def _cli_sb(sb: Path, args: str, env_prefix: str = "", timeout: int = 300):
    """真 CLI（沙箱技能根）；`env_prefix` 形如 `GK_GIT_LEASE=0`。"""
    from test_gk_commit_guard import _wsl
    return subprocess.run(
        ["bash", "-lc", 'cd "%s" && %s bash gatekeeper-cli.sh %s' % (_wsl(sb), env_prefix, args)],
        capture_output=True, text=True, timeout=timeout)


def test_arm8_cli_commit_takes_and_releases_lease(tmp_path):
    """臂⑧：真 `commit` 须**获取** lease 并在成功出口**释放**（临界段不留锁）。"""
    from test_gk_commit_guard import _mk_skillroot, _mk_repo, _last_json, _wsl
    sb = _mk_skillroot(tmp_path)
    rp = _mk_repo(tmp_path)
    subprocess.run(["bash", "-lc", 'printf "echo two\\n" > "%s/two.sh"' % _wsl(rp)],
                   capture_output=True, text=True, timeout=60)
    r = _cli_sb(sb, 'commit --repo "%s" --add two.sh -m "lease arm8"' % _wsl(rp))
    out = r.stdout + r.stderr
    d = _last_json(out)
    assert d.get("ok") is True, f"commit 失败：{out[:500]}"
    assert not (rp / ".git" / LEASE_NAME).exists(), "成功出口未释放 lease（会阻塞后续写者）"


def test_arm9_cli_kill_switch_skips_lease(tmp_path):
    """臂⑨（反例「误伤非 git 会话」）：`GK_GIT_LEASE=0` ⟹ **不创建** lease（应急旁路）。"""
    from test_gk_commit_guard import _mk_skillroot, _mk_repo, _last_json, _wsl
    sb = _mk_skillroot(tmp_path)
    rp = _mk_repo(tmp_path)
    subprocess.run(["bash", "-lc", 'printf "echo three\\n" > "%s/three.sh"' % _wsl(rp)],
                   capture_output=True, text=True, timeout=60)
    r = _cli_sb(sb, 'commit --repo "%s" --add three.sh -m "lease arm9"' % _wsl(rp),
                env_prefix="GK_GIT_LEASE=0")
    out = r.stdout + r.stderr
    assert _last_json(out).get("ok") is True, f"kill switch 下提交失败：{out[:500]}"
    assert not (rp / ".git" / LEASE_NAME).exists(), "kill switch 未生效（仍创建了 lease）"


def test_arm10_cli_live_lease_fails_loud_without_stealing(tmp_path):
    """臂⑩：活 lease 在场 ⟹ `commit` fail-loud `LEASE_HELD`，且**不抢**（原锁逐字不变）。"""
    from test_gk_commit_guard import _mk_skillroot, _mk_repo, _wsl
    sb = _mk_skillroot(tmp_path)
    rp = _mk_repo(tmp_path)
    subprocess.run(["bash", "-lc", 'printf "echo four\\n" > "%s/four.sh"' % _wsl(rp)],
                   capture_output=True, text=True, timeout=60)
    held = L.acquire(str(rp), sid="other")
    assert held.get("ok") is True, held
    before = _lock(rp).read_text(encoding="utf-8")
    r = _cli_sb(sb, 'commit --repo "%s" --add four.sh -m "lease arm10"' % _wsl(rp))
    out = r.stdout + r.stderr
    assert "LEASE_HELD" in out, f"活锁未 fail-loud：{out[:500]}"
    assert _lock(rp).read_text(encoding="utf-8") == before, "活锁被抢/被改（应与真在跑的写相撞）"


# ── 臂⑪–⑬ worktree 支持（ECC-B42D0F9B136C 修复的红先面）─────────────────────────
def _mk_worktree(tmp_path: Path) -> tuple:
    """真 git **worktree**（`<wt>/.git` 是**文件** ⟹ 旧实现恒判「非 git 仓」）。"""
    main = _mk_repo(tmp_path)
    subprocess.run(["git", "-C", str(main), "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "--allow-empty", "-q", "-m", "init"],
                   capture_output=True, text=True, timeout=60)
    wt = (tmp_path / "wt").resolve()
    subprocess.run(["git", "-C", str(main), "worktree", "add", "-q", "-b", "wtb", str(wt)],
                   capture_output=True, text=True, timeout=60)
    return main, wt


def _wt_gitdir(wt: Path) -> Path:
    gd = subprocess.run(["git", "-C", str(wt), "rev-parse", "--git-dir"],
                        capture_output=True, text=True, timeout=60).stdout.strip()
    return Path(gd if os.path.isabs(gd) else os.path.join(str(wt), gd))


def test_arm11_lease_works_in_git_worktree(tmp_path):
    """臂⑪（**红先**，修 `ECC-B42D0F9B136C`）：worktree 下 `acquire` 须成功（旧实现恒 `LEASE_HELD`）。"""
    main, wt = _mk_worktree(tmp_path)
    assert (wt / ".git").is_file(), "夹具失效：worktree 的 `.git` 应为文件"
    r = L.acquire(str(wt), sid="deadbeef" * 3)
    assert r.get("ok") is True, f"worktree 下 acquire 失败（worktree 支持缺失）：{r}"
    assert Path(r["lock"]).parent == (main / ".git").resolve(), \
        f"lease 未落 **common** dir（repo 级）：{r['lock']}（预期 {(main / '.git')}）"


def test_arm12_preflight_finds_worktree_index_lock(tmp_path):
    """臂⑫（**红先**）：worktree 的 `index.lock` 在**本 worktree 的** git dir ⟹ preflight 须命中并归档孤儿。"""
    main, wt = _mk_worktree(tmp_path)
    lock = _wt_gitdir(wt) / "index.lock"
    lock.write_text("", encoding="utf-8")
    old = time.time() - 100000                      # 远超 grace ⟹ 判孤儿
    os.utime(lock, (old, old))
    rc, out, err = L.preflight(str(wt), trash_dir=str(tmp_path / "trash"))
    assert rc == 0, f"孤儿 index.lock 未放行：rc={rc} out={out}"
    assert not lock.exists(), "孤儿锁未被归档（worktree 的 index.lock 未被找到 ⟹ 旧路径假设失效）"
    assert (tmp_path / "trash").exists(), "归档落点未创建"


def test_arm13_live_lock_blocks_preflight_in_worktree(tmp_path):
    """臂⑬（守卫）：worktree 下**活锁**仍须 fail-loud（不抢）。"""
    main, wt = _mk_worktree(tmp_path)
    lock = _wt_gitdir(wt) / "index.lock"
    lock.write_text("", encoding="utf-8")            # 新鲜 mtime ⟹ 年龄 < grace
    rc, out, err = L.preflight(str(wt), trash_dir=str(tmp_path / "trash"))
    assert rc == 1 and "COMMIT_LOCK_HELD" in out, f"活锁未 fail-loud：rc={rc} out={out}"


# ── 臂⑭–⑯ 合并结果硬校验（§15.7 一期；治「空合并」静默丢批次）──────────────────
def _g(rp: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(rp)] + list(args),
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"git {' '.join(args)} 失败：{r.stderr}"
    return r.stdout.strip()


def _mk_merge_fixture(tmp_path: Path) -> tuple:
    """基线仓 + `feature` 分支（加 `feat.txt`）；返回 `(repo, ours, theirs)`。"""
    rp = _mk_repo(tmp_path)
    _g(rp, "config", "user.email", "t@t")
    _g(rp, "config", "user.name", "t")
    (rp / "base.txt").write_text("b\n", encoding="utf-8", newline="\n")
    _g(rp, "add", "base.txt")
    _g(rp, "commit", "-q", "-m", "base")
    ours = _g(rp, "rev-parse", "HEAD")
    _g(rp, "checkout", "-q", "-b", "feature")
    (rp / "feat.txt").write_text("f\n", encoding="utf-8", newline="\n")
    _g(rp, "add", "feat.txt")
    _g(rp, "commit", "-q", "-m", "feat")
    theirs = _g(rp, "rev-parse", "HEAD")
    _g(rp, "checkout", "-q", "-")                    # 回到 ours 所在分支
    return rp, ours, theirs


def test_arm14_verify_merge_result_passes_on_real_merge(tmp_path):
    """臂⑭（正例）：真合并 ⟹ 放行，且无丢文件。"""
    rp, ours, theirs = _mk_merge_fixture(tmp_path)
    _g(rp, "merge", "-q", "--no-ff", "-m", "m", "feature")
    r = L.verify_merge_result(str(rp), ours, theirs)
    assert r.get("ok") is True, f"真合并被误判：{r}"
    assert r.get("empty_merge") is False and not r.get("dropped"), r


def test_arm15_verify_merge_result_detects_empty_merge(tmp_path):
    """臂⑮（**红先**，§15.6 病象复现）：结果 tree == ours 而分支有变更 ⟹ 判「空合并」。

    手法 = `commit-tree <ours 的 tree> -p ours -p theirs` 造出「双亲齐、tree 却是 ours」的合并提交
    —— 正是孤儿 `index.lock` 致 `git merge` 未写索引后 `git commit` 记录下来的形态。
    """
    rp, ours, theirs = _mk_merge_fixture(tmp_path)
    tree = _g(rp, "rev-parse", "HEAD^{tree}")        # ours 的 tree
    fake = _g(rp, "commit-tree", tree, "-p", ours, "-p", theirs, "-m", "fake empty merge")
    r = L.verify_merge_result(str(rp), ours, theirs, fake)
    assert r.get("ok") is False, f"空合并未被检出（正是 §15.6 的病象）：{r}"
    assert r.get("empty_merge") is True, r
    assert r.get("verdict") == "empty_merge", r


def test_arm16_verify_merge_result_detects_dropped_file(tmp_path):
    """臂⑯（**红先**）：合并确有纳入、但分支的某文件在结果中缺失（状态 `D`）⟹ 判「丢文件」。

    夹具须让 `ours→result` **非空**（另加 `extra.txt`），否则会被误归为「空合并」分支。
    """
    rp, ours, theirs = _mk_merge_fixture(tmp_path)
    _g(rp, "merge", "-q", "--no-ff", "-m", "m", "feature")
    _g(rp, "rm", "-q", "feat.txt")
    (rp / "extra.txt").write_text("e\n", encoding="utf-8", newline="\n")
    _g(rp, "add", "extra.txt")
    _g(rp, "commit", "-q", "-m", "drop feat + add extra")
    r = L.verify_merge_result(str(rp), ours, theirs)
    assert r.get("ok") is False, f"丢文件未被检出：{r}"
    assert r.get("verdict") == "dropped_files", r
    assert "feat.txt" in (r.get("dropped") or []), r

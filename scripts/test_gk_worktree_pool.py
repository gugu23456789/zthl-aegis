#!/usr/bin/env python3
"""worktree 热池（派发 ms 级）—— 红先臂集。

**病象（2026-11-10 实测）**：派发一棵会话 worktree 要物化 2052 个 tracked 文件到 drvfs（9p）：
`git archive | tar -x` 到 ext4 **4.4s** / 到 `/mnt/c` **31.1s** ⟹ `apply-worktree --session` **34.4s**。
回收端另有 claims 逐条 realpath（已修，327s→5s）。用户口径：派发须 **ms 级**，>1min 不可接受。

**热池**：预建 K 个 slot（各是真 worktree，检出于 `gk-pool/<n>`）。派发 = 在已有树上
`git checkout -B agent/session/<sid> <baseline>`（树相同 ⟹ **不写文件**）；回收 = 清回基线 +
`gk-pool/<n>`，租约归池。归属用 **O_EXCL claim 文件**（原子），TTL 作废（进程崩溃 / 忘了 release）。

**红先对照**：`scripts/gk_worktree_pool.py` 尚不存在 ⟹ 本文件对 HEAD 必红（ImportError）。
"""
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import gk_worktree_pool as P  # noqa: E402  （红先：模块不存在 ⟹ ImportError）

WARM_MS = 1500          # 「ms 级」判据（含 python 内 git 子进程一次往返的宽松上限）


def _git(repo, *a):
    return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True)


@pytest.fixture()
def fixture_repo(tmp_path):
    """真 git 仓 + 空 worktree 根（池 slot 之后由 ensure_pool 建）。"""
    repo = tmp_path / "main"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "master")
    (repo / "a.txt").write_text("x", encoding="utf-8")
    (repo / "b.txt").write_text("y", encoding="utf-8")
    _git(repo, "add", "a.txt", "b.txt")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")
    root = tmp_path / "wts"
    root.mkdir()
    return str(repo), str(root)


def _slots(repo, root):
    st = P.status(str(repo), str(root))
    return st["slots"]


# ── 池供给与派发延迟 ────────────────────────────────────────────────────────
class TestWarmAcquireLatency:
    def test_ensure_pool_and_second_acquire_is_ms(self, fixture_repo):
        """冷建池不计时；**第二次**派发必须走热槽（< WARM_MS）且复用同一棵树。"""
        repo, root = fixture_repo
        rep = P.ensure_pool(repo, root, size=2, baseline="HEAD")
        assert rep["ok"] and len(rep["slots"]) == 2, rep

        a1 = P.acquire(repo, root, sid="s1", branch="agent/session/s1", baseline="HEAD")
        assert a1["ok"] and a1["reused"] is False, a1
        assert P.release(repo, root, a1["worktree"], baseline="HEAD")["ok"]

        t0 = time.time()
        a2 = P.acquire(repo, root, sid="s2", branch="agent/session/s2", baseline="HEAD")
        dt = (time.time() - t0) * 1000
        assert a2["ok"], a2
        assert a2["worktree"] == a1["worktree"], "热槽未复用（又建了新树 ⟹ 派发仍慢）"
        assert dt < WARM_MS, "热池派发 %.0fms ≥ %dms（未达 ms 级）" % (dt, WARM_MS)
        P.release(repo, root, a2["worktree"], baseline="HEAD")

    def test_hot_dispatch_spawns_no_git_subprocess(self, fixture_repo, monkeypatch):
        """热派发**不得**起任何 git 子进程（drvfs 实测 105–1270ms/次 ⟹ 5 次即秒级）。

        判据与环境无关：把 `_git` 换成爆炸桩，热派发仍须成功 —— 这条臂比"看墙钟"更硬。
        """
        repo, root = fixture_repo
        P.ensure_pool(repo, root, size=1, baseline="HEAD")
        a = P.acquire(repo, root, sid="s0", branch="agent/session/s0", baseline="HEAD")
        assert a["ok"]
        assert P.release(repo, root, a["worktree"], baseline="HEAD")["ok"]

        def _boom(*_a, **_k):
            raise AssertionError("热路径起了 git 子进程: %r" % (_a,))

        monkeypatch.setattr(P, "_git", _boom)
        t0 = time.time()
        b = P.acquire(repo, root, sid="s1", branch="agent/session/s1", baseline="HEAD")
        dt = (time.time() - t0) * 1000
        assert b["ok"], b
        assert b["slot"] == a["slot"], "热槽未复用"
        assert dt < 500, "0 子进程热派发仍 %.0fms（应远低于 500ms）" % dt

    def test_released_slot_is_clean_for_next_session(self, fixture_repo):
        """归还后槽位必须**回到基线**（下一个会话看不到上一个的改动）。"""
        repo, root = fixture_repo
        P.ensure_pool(repo, root, size=1, baseline="HEAD")
        a = P.acquire(repo, root, sid="s1", branch="agent/session/s1", baseline="HEAD")
        assert a["ok"]
        ws = Path(a["worktree"])
        (ws / "a.txt").write_text("session-1 的改动", encoding="utf-8")
        (ws / "leak.txt").write_text("残留", encoding="utf-8")
        assert P.release(repo, root, str(ws), baseline="HEAD")["ok"]
        assert (ws / "a.txt").read_text(encoding="utf-8") == "x", "归还未回基线"
        assert not (ws / "leak.txt").exists(), "归还后仍留未跟踪残留（下一会话会看到）"


# ── E2：有界并发 ────────────────────────────────────────────────────────────
class TestE2PoolBoundedConcurrency:
    def test_concurrent_acquire_distinct_slots_and_exhausted_fails_fast(self, fixture_repo):
        """池 2 槽、4 路并发：恰好 2 个成功且槽位互异，其余 **快速** POOL_EXHAUSTED（不新建树）。"""
        repo, root = fixture_repo
        P.ensure_pool(repo, root, size=2, baseline="HEAD")
        out, lock = [], threading.Lock()

        def _grab(i):
            r = P.acquire(repo, root, sid="c%d" % i, branch="agent/session/c%d" % i,
                          baseline="HEAD")
            with lock:
                out.append(r)

        t0 = time.time()
        ths = [threading.Thread(target=_grab, args=(i,)) for i in range(4)]
        [t.start() for t in ths]
        [t.join() for t in ths]
        dt = (time.time() - t0) * 1000
        oks = [r for r in out if r.get("ok")]
        bad = [r for r in out if not r.get("ok")]
        assert len(oks) == 2, out
        assert {os.path.abspath(r["worktree"]) for r in oks}.__len__() == 2, "两路拿到同一槽"
        assert all(r.get("error") == "POOL_EXHAUSTED" for r in bad), bad
        assert dt < 3 * WARM_MS, "池满时未快速失败（%.0fms）" % dt
        for r in oks:
            P.release(repo, root, r["worktree"], baseline="HEAD")


# ── E5：崩溃 / TTL 自动回收 ─────────────────────────────────────────────────
class TestE5StaleLeaseByTtl:
    def test_expired_claim_is_swept_and_slot_reusable(self, fixture_repo):
        """模拟崩溃（acquire 后不 release）：TTL 到期后 `sweep` 必须收回槽位并可再派发。"""
        repo, root = fixture_repo
        P.ensure_pool(repo, root, size=1, baseline="HEAD")
        a = P.acquire(repo, root, sid="crash", branch="agent/session/crash",
                      baseline="HEAD", ttl_s=0)
        assert a["ok"], a
        b = P.acquire(repo, root, sid="next", branch="agent/session/next", baseline="HEAD")
        assert not b.get("ok") and b.get("error") == "POOL_EXHAUSTED", b
        sw = P.sweep(repo, root, baseline="HEAD")
        assert sw["reclaimed"] >= 1, sw
        c = P.acquire(repo, root, sid="next", branch="agent/session/next", baseline="HEAD")
        assert c["ok"], c
        P.release(repo, root, c["worktree"], baseline="HEAD")


# ── E6：毒不外溢（脏槽先清再交付）───────────────────────────────────────────
class TestE6PoisonedSlotReset:
    def test_poisoned_slot_reset_before_handover(self, fixture_repo):
        """槽位被写脏（未跟踪毒文件 + 改 tracked + 伪造 state）且在租约中被遗弃 ⟹ 交付前必须清干净。"""
        repo, root = fixture_repo
        P.ensure_pool(repo, root, size=1, baseline="HEAD")
        a = P.acquire(repo, root, sid="evil", branch="agent/session/evil",
                      baseline="HEAD", ttl_s=0)
        ws = Path(a["worktree"])
        (ws / "poison.txt").write_text("毒", encoding="utf-8")
        (ws / "a.txt").write_text("被篡改", encoding="utf-8")
        (ws / "state.json").write_text('{"stage": "R4", "credit": 999999}', encoding="utf-8")

        P.sweep(repo, root, baseline="HEAD")
        b = P.acquire(repo, root, sid="victim", branch="agent/session/victim", baseline="HEAD")
        assert b["ok"], b
        ws2 = Path(b["worktree"])
        assert not (ws2 / "poison.txt").exists(), "毒文件跨会话外溢"
        assert not (ws2 / "state.json").exists(), "伪造 state 跨会话外溢"
        assert (ws2 / "a.txt").read_text(encoding="utf-8") == "x", "tracked 文件未回基线"
        P.release(repo, root, str(ws2), baseline="HEAD")

    def test_dirty_slot_is_archived_before_clean(self, fixture_repo):
        """清理前**先归档**：`reset --hard` + `clean -ffd` 会销毁未提交工作 ⟹ 必须先落 diff/副本。"""
        repo, root = fixture_repo
        P.ensure_pool(repo, root, size=1, baseline="HEAD")
        a = P.acquire(repo, root, sid="crash", branch="agent/session/crash",
                      baseline="HEAD", ttl_s=0)
        ws = Path(a["worktree"])
        (ws / "a.txt").write_text("未提交的 tracked 改动", encoding="utf-8")
        (ws / "wip.txt").write_text("未提交的新文件", encoding="utf-8")
        sw = P.sweep(repo, root, baseline="HEAD")
        assert sw["archived"], sw
        arc = Path(sw["archived"][0]["dir"])
        assert "未提交的 tracked 改动" in (arc / "changes.diff").read_text(encoding="utf-8")
        assert (arc / "untracked" / "wip.txt").read_text(encoding="utf-8") == "未提交的新文件"


# ── 状态面 ──────────────────────────────────────────────────────────────────
def test_reclaim_from_session_worktree_resolves_pool_by_main_repo(fixture_repo, tmp_path):
    """池目录名 = **主仓名**：从会话 worktree 调 reclaim 也必须扫到池。

    病象（2026-11-10 实测）：CLI 的 `--repo "$SKILL_DIR"` 在 worktree 内是 `<sid>` ⟹
    `pool_dir` 算成 `_pool/<sid>`（不存在）⟹ sweep 静默空转（kept=0）⟹ TTL 回收「机制在、不生效」。
    """
    repo, root = fixture_repo
    P.ensure_pool(repo, root, size=1, baseline="HEAD")
    a = P.acquire(repo, root, sid="s1", branch="agent/session/s1", baseline="HEAD", ttl_s=7200)
    assert a["ok"], a
    wt = tmp_path / "session-wt"
    _git(repo, "worktree", "add", "-q", "-b", "agent/session/sess", str(wt), "HEAD")
    import gk_worktree_reclaim as R
    rep = R.reclaim(str(wt), root, apply=False)
    assert rep["pool_sweep"].get("kept", 0) >= 1, rep.get("pool_sweep")


def test_status_reports_slot_and_lease(fixture_repo):
    repo, root = fixture_repo
    P.ensure_pool(repo, root, size=2, baseline="HEAD")
    a = P.acquire(repo, root, sid="s1", branch="agent/session/s1", baseline="HEAD")
    st = P.status(repo, root)
    assert st["size"] == 2 and st["leased"] == 1 and st["free"] == 1, st
    leased = [s for s in st["slots"] if s["state"] == "leased"]
    assert leased and leased[0]["sid"] == "s1", st
    P.release(repo, root, a["worktree"], baseline="HEAD")


# ── 入口防呆 + 自动化流程引导（2026-11-11）─────────────────────────────────
# 病象：池模块 CLI 的 `--root` 任意 ⟹ `--root /tmp/evil ensure` 会把 worktree 建到
#   莫名其妙的地方；`--sid ""` 会造出无主槽（任何人可写）；且直调入口无 next 引导 ⟹
#   agent 只能手工拼命令（踩错根/踩错分支）。
def test_cli_refuses_root_outside_whitelist(fixture_repo, monkeypatch, capsys):
    repo, root = fixture_repo
    monkeypatch.delenv("GK_POOL_ALLOW_ANY_ROOT", raising=False)
    rc = P.main(["--repo", repo, "--root", "/tmp/not-a-dev-root", "status"])
    assert rc == 2
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["error"] == "ROOT_NOT_ALLOWED", out
    assert out.get("next"), "拒绝时必须给自动化引导（禁让 agent 自己猜）"


def test_cli_escape_hatch_allows_any_root(fixture_repo, monkeypatch, capsys):
    """逃生舱：显式 `GK_POOL_ALLOW_ANY_ROOT=1`（测试/人工）才放开白名单。"""
    repo, root = fixture_repo
    monkeypatch.setenv("GK_POOL_ALLOW_ANY_ROOT", "1")
    P.main(["--repo", repo, "--root", root, "status"])
    assert "ROOT_NOT_ALLOWED" not in capsys.readouterr().out


def test_acquire_requires_sid(fixture_repo):
    repo, root = fixture_repo
    P.ensure_pool(repo, root, size=1, baseline="HEAD")
    r = P.acquire(repo, root, sid="", branch="agent/session/x", baseline="HEAD")
    assert r.get("ok") is False and r.get("error") == "SID_REQUIRED", r


def test_acquire_refuses_protected_branch(fixture_repo):
    """池只派发会话分支：主分支 / 池分支被占 ⟹ 直接拒（否则等于把主树或池自身交出去）。"""
    repo, root = fixture_repo
    P.ensure_pool(repo, root, size=1, baseline="HEAD")
    for br in ("master", "main", "gk-pool/0"):
        r = P.acquire(repo, root, sid="s1", branch=br, baseline="HEAD")
        assert r.get("error") == "BRANCH_PROTECTED", (br, r)


def test_ensure_pool_rejects_absurd_size(fixture_repo):
    """池大小硬上限：`--pool-size 10000` 会物化 10000 棵真 worktree ⟹ 直接拒（不静默截断）。"""
    repo, root = fixture_repo
    for bad in (0, -1, P.MAX_SIZE + 1, 10000):
        r = P.ensure_pool(repo, root, size=bad, baseline="HEAD")
        assert r.get("ok") is False and r.get("error") == "BAD_SIZE", (bad, r)


# ── 池满显式标记（2026-11-16）────────────────────────────────────────────────
def test_status_full_flag_and_degraded_next(fixture_repo):
    """`full` 是显式标记：占用满 ⟹ true + 降级路径；未建池（size=0）**不算满**。"""
    repo, root = fixture_repo
    empty = P.status(repo, root)
    assert empty.get("ok") and empty.get("full") is False, empty
    assert not empty.get("degraded"), "未建池不该报降级"

    P.ensure_pool(repo, root, size=1, baseline="HEAD")
    a = P.acquire(repo, root, sid="s1", branch="agent/session/s1", baseline="HEAD")
    st = P.status(repo, root)
    assert st["full"] is True and st["free"] == 0 and st["leased"] == 1, st
    assert st.get("degraded") == "cold-build", st
    assert st.get("next"), "满时**必须**给可执行降级路径（禁让 agent 自己拼命令）"
    assert "pool-sweep" in st["next"] or "--pool-ensure" in st["next"], st
    P.release(repo, root, a["worktree"], baseline="HEAD")
    assert P.status(repo, root)["full"] is False


def test_status_full_prefers_sweep_when_expired(fixture_repo):
    """满 + 有过期租约 ⟹ next 指向 `--pool-sweep`（不必等归还或扩容）。"""
    repo, root = fixture_repo
    P.ensure_pool(repo, root, size=1, baseline="HEAD")
    P.acquire(repo, root, sid="s1", branch="agent/session/s1", baseline="HEAD")
    lp = Path(P.pool_dir(repo, root)) / "slot-0.lease.json"
    d = json.loads(lp.read_text(encoding="utf-8"))
    d["ts_epoch"] = 1.0          # 远古 ⟹ expired
    d["ttl_s"] = 1
    lp.write_text(json.dumps(d), encoding="utf-8")
    st = P.status(repo, root)
    assert st["full"] is True and st["slots"][0]["expired"] is True, st
    assert "pool-sweep" in st["next"], st


def test_acquire_exhausted_marks_full_and_degraded(fixture_repo):
    """抢空 ⟹ POOL_EXHAUSTED 且带 `full`/`degraded`/`next`（调用方无须自己推降级）。"""
    repo, root = fixture_repo
    P.ensure_pool(repo, root, size=1, baseline="HEAD")
    a = P.acquire(repo, root, sid="s1", branch="agent/session/s1", baseline="HEAD")
    assert a.get("ok"), a
    r = P.acquire(repo, root, sid="s2", branch="agent/session/s2", baseline="HEAD")
    assert r.get("error") == "POOL_EXHAUSTED", r
    assert r.get("full") is True and r.get("degraded") == "cold-build", r
    assert r.get("next"), r
    P.release(repo, root, a["worktree"], baseline="HEAD")


def test_acquire_is_idempotent_per_sid(fixture_repo):
    """**一 sid 一槽**（2026-11-11）：同 sid 同分支重复 acquire ⟹ 回原槽，不占第二个槽。"""
    repo, root = fixture_repo
    P.ensure_pool(repo, root, size=2, baseline="HEAD")
    a = P.acquire(repo, root, sid="dup", branch="agent/session/dup", baseline="HEAD")
    b = P.acquire(repo, root, sid="dup", branch="agent/session/dup", baseline="HEAD")
    assert a.get("ok") and b.get("ok"), (a, b)
    assert b["slot"] == a["slot"] and b.get("idempotent") is True, b
    assert P.status(repo, root)["leased"] == 1, "重复 acquire 泄漏了槽位"
    P.release(repo, root, b["worktree"], baseline="HEAD")


def test_acquire_rejects_second_branch_for_same_sid(fixture_repo):
    """同 sid 换分支 ⟹ SID_ALREADY_LEASED；别的 sid 仍能拿另一槽（池容不被误锁）。"""
    repo, root = fixture_repo
    P.ensure_pool(repo, root, size=2, baseline="HEAD")
    a = P.acquire(repo, root, sid="dup", branch="agent/session/dup", baseline="HEAD")
    c = P.acquire(repo, root, sid="dup", branch="agent/session/dup2", baseline="HEAD")
    assert c.get("error") == "SID_ALREADY_LEASED", c
    d = P.acquire(repo, root, sid="other", branch="agent/session/other", baseline="HEAD")
    assert d.get("ok") and d["slot"] != a["slot"], d
    P.release(repo, root, a["worktree"], baseline="HEAD")
    P.release(repo, root, d["worktree"], baseline="HEAD")


def test_acquire_carries_automation_guidance(fixture_repo):
    """派发/状态回包必须带 `note`/`next`（自动化流程引导单一来源）。"""
    repo, root = fixture_repo
    ensure = P.ensure_pool(repo, root, size=1, baseline="HEAD")
    assert ensure.get("note") and ensure.get("next"), ensure
    a = P.acquire(repo, root, sid="s1", branch="agent/session/s1", baseline="HEAD")
    assert a.get("note") and a.get("next"), a
    assert "merge --no-ff" in a["next"], a
    st = P.status(repo, root)
    assert st.get("note"), st
    P.release(repo, root, a["worktree"], baseline="HEAD")


# ── per-sid 派发限流（2026-11-11「让攻击不划算」）────────────────────────────
def test_acquire_rate_limited_per_sid(fixture_repo, monkeypatch):
    """acquire→release 抖动超限 ⟹ RATE_LIMITED；**不消耗槽位**，也不连坐别的 sid。"""
    repo, root = fixture_repo
    monkeypatch.setenv("GK_POOL_RATE_LIMIT", "1")
    monkeypatch.setenv("GK_POOL_RATE_WINDOW_S", "600")
    P.ensure_pool(repo, root, size=2, baseline="HEAD")
    a = P.acquire(repo, root, sid="flap", branch="agent/session/a", baseline="HEAD")
    assert a.get("ok"), a
    assert P.release(repo, root, a["worktree"], baseline="HEAD")["ok"]
    b = P.acquire(repo, root, sid="flap", branch="agent/session/b", baseline="HEAD")
    assert b.get("error") == "RATE_LIMITED", b
    assert b.get("limit") == 1 and b.get("window_s") == 600, b
    assert P.status(repo, root)["leased"] == 0, "限流把槽位也消耗了"
    # 正控：别的 sid 不受影响（限流 per-sid，不是全局闸）
    c = P.acquire(repo, root, sid="other", branch="agent/session/c", baseline="HEAD")
    assert c.get("ok"), c
    P.release(repo, root, c["worktree"], baseline="HEAD")


def test_rate_limit_does_not_count_idempotent_reuse(fixture_repo, monkeypatch):
    """幂等复用（同 sid 同分支）不吃配额：只有**真分配**计数。"""
    repo, root = fixture_repo
    monkeypatch.setenv("GK_POOL_RATE_LIMIT", "2")
    monkeypatch.setenv("GK_POOL_RATE_WINDOW_S", "600")
    P.ensure_pool(repo, root, size=1, baseline="HEAD")
    a = P.acquire(repo, root, sid="s", branch="agent/session/s", baseline="HEAD")
    assert a.get("ok"), a
    for _ in range(3):        # 复用不计数
        again = P.acquire(repo, root, sid="s", branch="agent/session/s", baseline="HEAD")
        assert again.get("ok") and again.get("idempotent"), again
    assert P.release(repo, root, a["worktree"], baseline="HEAD")["ok"]
    b = P.acquire(repo, root, sid="s", branch="agent/session/s2", baseline="HEAD")
    assert b.get("ok"), b          # 第 2 次真分配（额度 = 2）
    assert P.release(repo, root, b["worktree"], baseline="HEAD")["ok"]
    c = P.acquire(repo, root, sid="s", branch="agent/session/s3", baseline="HEAD")
    assert c.get("error") == "RATE_LIMITED", c

#!/usr/bin/env python3
"""red_runtime.scenarios — 场景层**剧本**（6 条，2026-11-11）。

分工：`runner.py` 提供 E1 限额 / E3 隔离 / E4 判别力的**执行面**；本文件只提供**剧本**。
每条剧本 = 一个探针：在 `/tmp` 沙盘根里造最小现场 → 施加攻击 → **防住才 exit 0**
（防不住 / 崩溃 ⟹ 非零 ⟹ runner 的不变量 `exit_zero` 判 FAIL，禁「异常当 PASS」）。

登记：`references/red-vectors.json` 的 `kind:"runtime"` 条目与本文件 `SCENARIOS` **一一对应**
（双向差集为空），由 `scripts/test_red_runtime_scenarios.py` 机检。

用法（runner 调）:
    python3 scripts/red_runtime/scenarios.py --probe <id> --root <沙盘根>
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))   # scripts/
import gk_commit_identity as ci          # noqa: E402
import gk_worktree_owner as own          # noqa: E402
import gk_worktree_pool as pool          # noqa: E402
import gk_worktree_reclaim as reclaim    # noqa: E402

GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}

SCENARIOS = [
    {"id": "wt-share-poison-01",
     "title": "跨会话 worktree 写入（并发产物串味）",
     "probe": "wt_share_poison"},
    {"id": "hook-ownership-bypass-01",
     "title": "伪造路径 token / 别名冒充 worktree 主人",
     "probe": "hook_ownership_bypass"},
    {"id": "commit-identity-forge-01",
     "title": "手写 trailer + 他人 author 冒充提交身份",
     "probe": "commit_identity_forge"},
    {"id": "pool-slot-race-01",
     "title": "多路并发抢热池槽位",
     "probe": "pool_slot_race"},
    {"id": "pool-dirty-sweep-01",
     "title": "脏槽 TTL 到期被 sweep（未提交工作不得静默销毁）",
     "probe": "pool_dirty_sweep"},
    {"id": "reclaim-master-lock-01",
     "title": "主树 detach 后主分支被误回收",
     "probe": "reclaim_master_lock"},
    {"id": "pool-lease-renew-01",
     "title": "活跃会话槽位被 TTL 误收（编辑续期）",
     "probe": "pool_lease_renew"},
    {"id": "pool-crossproc-race-01",
     "title": "跨进程并发抢槽（O_EXCL 是否真原子）",
     "probe": "pool_crossproc_race"},
    {"id": "hook-session-forge-01",
     "title": "真 hook 端到端：伪造载荷 session_id 写入他人 worktree",
     "probe": "hook_session_forge"},
    {"id": "pool-double-lease-01",
     "title": "一 sid 一槽（重复 acquire 不得吃第二槽）",
     "probe": "pool_double_lease"},
    {"id": "canary-deception-01",
     "title": "诱饵面：假 state/claims/池槽/凭据 + 非 owner 单行拒绝",
     "probe": "canary_deception"},
    {"id": "threat-quarantine-01",
     "title": "违约台账：窗口计数隔离 + 单行零信息拒绝 + decay",
     "probe": "threat_quarantine"},
    {"id": "pool-rate-limit-01",
     "title": "per-sid 派发限流（抢槽抖动打爆池）",
     "probe": "pool_rate_limit"},
    {"id": "monitor-rotation-01",
     "title": "monitor 事件驱动 + 诱饵旋转门（无信号零调用）",
     "probe": "monitor_rotation"},
]


# ─── 基础设施 ────────────────────────────────────────────────────────────────
_GIT_IDENT_KEYS = ("GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL",
                   "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL")


def _git(repo, *a, ident: bool = True):
    """跑一条 git。

    `ident=False` ⟹ **清掉** `GIT_AUTHOR_*`/`GIT_COMMITTER_*`：这两组 env 的优先级**高于**
    `-c user.name/user.email`（git 语义），不清掉会让「按机制落身份」的正控提交被 env 覆盖，
    把合法的正控判成 FAIL（实测踩中）。
    """
    env = dict(os.environ)
    if ident:
        env.update(GIT_ENV)
    else:
        for k in _GIT_IDENT_KEYS:
            env.pop(k, None)
    return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, env=env)


def _mk_repo(base: Path) -> Path:
    repo = base / "repo"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "master")
    (repo / "a.txt").write_text("x", encoding="utf-8")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-qm", "init")
    return repo


def _mk_session_wt(repo: Path, root: Path, sid: str) -> Path:
    """造 `<root>/<repo>/agent/session/<sid>` 形态的 linked worktree（归属判据认这种布局）。"""
    wt = root / repo.name / "agent" / "session" / sid
    wt.parent.mkdir(parents=True, exist_ok=True)
    r = _git(repo, "worktree", "add", "-q", "-b", "agent/session/" + sid, str(wt), "HEAD")
    if r.returncode != 0:
        raise RuntimeError("worktree add failed: " + (r.stderr or "").strip()[:200])
    return wt


def _fail(*why) -> int:
    print(json.dumps({"verdict": "FAIL", "why": [str(w) for w in why]}, ensure_ascii=False))
    return 1


def _ok(note: str) -> int:
    print(json.dumps({"verdict": "PASS", "note": note}, ensure_ascii=False))
    return 0


# ─── 1. 跨会话 worktree 写入 ─────────────────────────────────────────────────
def probe_wt_share_poison(root: Path) -> int:
    repo = _mk_repo(root)
    wt_root = root / "wts"
    wt_a = _mk_session_wt(repo, wt_root, "aaaa")
    target = wt_a / "poison.txt"
    roots = [str(wt_root)]

    blocked = own.check(str(target), ["bbbb"], roots=roots)
    if blocked.get("decision") != "block":
        return _fail("外人写入未被拦截", blocked)
    if blocked.get("error") != "WORKTREE_OWNERSHIP_VIOLATION":
        return _fail("错误码不符", blocked)
    # 防住 ⟹ 没有文件落地；A 的树与历史都不含 B 的产物
    if target.exists():
        return _fail("毒文件已落盘")
    st = _git(wt_a, "status", "--porcelain").stdout.strip()
    if st:
        return _fail("A 的 worktree 不干净", st)
    hist = _git(wt_a, "log", "--name-only", "--pretty=format:").stdout
    if "poison.txt" in hist:
        return _fail("A 的提交历史混入 B 的文件")
    # 正控：主人写入必须放行（防判定器恒真）
    allowed = own.check(str(target), ["aaaa"], roots=roots, autoclaim=False)
    if allowed.get("decision") != "allow":
        return _fail("主人被误拦（判定器恒假）", allowed)
    return _ok("block + 无落盘 + 主人放行")


# ─── 2. 伪造身份冒充 ────────────────────────────────────────────────────────
def probe_hook_ownership_bypass(root: Path) -> int:
    repo = _mk_repo(root)
    wt_root = root / "wts"
    wt_a = _mk_session_wt(repo, wt_root, "aaaa")
    target = str(wt_a / "x.txt")
    roots = [str(wt_root)]

    own.claim(str(wt_a), ["AAAA"], force=True)
    # 攻击 = 同时伪造「路径 token」与自己的载荷 id（别名被污染的真实形态）
    forged = own.check(target, ["BBBB", "aaaa"], roots=roots)
    if forged.get("decision") != "block":
        return _fail("伪造路径 token 穿过了认领", forged)
    if (own.read_claim(str(wt_a)) or {}).get("ids") != ["AAAA"]:
        return _fail("认领被覆写", own.read_claim(str(wt_a)))
    # 正控：认领者本人可写
    if own.check(target, ["AAAA"], roots=roots).get("decision") != "allow":
        return _fail("认领者被误拦")
    return _ok("认领优先于路径 token，且不可被覆写")


# ─── 3. 提交身份伪造 ────────────────────────────────────────────────────────
def probe_commit_identity_forge(root: Path) -> int:
    repo = _mk_repo(root)
    _git(repo, "-c", "user.name=gugu", "-c", "user.email=g@u",
         "commit", "--allow-empty", "-q", "-m",
         "feat: 借来的提交\n\nSession: victim\nWorktree: /elsewhere")
    bad = ci.verify(str(repo), "HEAD", sid="attacker")
    if bad.get("ok") is not False:
        return _fail("伪造提交未被识别", bad)
    joined = " | ".join(bad.get("mismatch") or [])
    if "Session" not in joined or "author" not in joined:
        return _fail("mismatch 缺项", joined)

    # 正控：按机制落身份 ⟹ 必须 ok=true
    ident = ci.identity(str(repo), sid="attacker")
    mf = root / "msg.txt"
    mf.write_text(ci.decorate("feat: 合法提交", ident), encoding="utf-8")
    _git(repo, "-c", "user.name=" + ident["author_name"],
         "-c", "user.email=" + ident["author_email"],
         "commit", "--allow-empty", "-q", "-F", str(mf), ident=False)
    good = ci.verify(str(repo), "HEAD", sid="attacker")
    if good.get("ok") is not True:
        return _fail("合法身份被误判（判定器恒假）", good)

    # ── 3b env 伪造（`GIT_AUTHOR_*` 优先级**高于** `-c user.name`，2026-11-11 实测）──
    #   a) 不清 env：即使 `-c` 写对，author 仍被环境变量覆盖 ⟹ verify 必须 FAIL（事后必被抓）；
    #   b) `ci.sanitized_env` 清掉四键后再提交 ⟹ author 正确 ⟹ verify PASS（修复面生效）。
    forged = dict(os.environ)
    forged.update({"GIT_AUTHOR_NAME": "agent/victim", "GIT_AUTHOR_EMAIL": "victim@gk"})
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=" + ident["author_name"],
                    "-c", "user.email=" + ident["author_email"],
                    "commit", "--allow-empty", "-q", "-m", "feat: env-forge"],
                   capture_output=True, env=forged)
    env_bad = ci.verify(str(repo), "HEAD", sid="attacker")
    if env_bad.get("ok") is not False:
        return _fail("env 伪造 author 未被识别", env_bad)

    mf2 = root / "msg2.txt"
    mf2.write_text(ci.decorate("feat: env-clean", ident), encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=" + ident["author_name"],
                    "-c", "user.email=" + ident["author_email"],
                    "commit", "--allow-empty", "-q", "-F", str(mf2)],
                   capture_output=True, env=ci.sanitized_env(forged))
    env_good = ci.verify(str(repo), "HEAD", sid="attacker")
    if env_good.get("ok") is not True:
        return _fail("清 env 后仍落不了正确身份（修复面无效）", env_good)
    return _ok("伪造 mismatch + 合法 ok + env 伪造可抓 + 清 env 后生效")


# ─── 4. 池槽并发抢占 + 入口防呆（2026-11-11 覆盖当前热池）─────────────────────
def probe_pool_slot_race(root: Path) -> int:
    repo = _mk_repo(root)
    wt_root = root / "wts"
    wt_root.mkdir(parents=True, exist_ok=True)
    # ── 4a 入口防呆：**先于抢槽**（这些入口不该消耗槽位、不该覆盖已有租约）──
    os.environ.pop("GK_POOL_ALLOW_ANY_ROOT", None)
    if pool.root_allowed("/tmp/evil-pool"):
        return _fail("非白名单池根未被拒（worktree 会被建到莫名地方）")
    if not pool.root_allowed(str(wt_root)) and not pool.root_allowed(
            "<home>/.trae/worktrees"):
        return _fail("白名单判定恒假（连真实根都拒）")
    bad = pool.ensure_pool(str(repo), str(wt_root), size=pool.MAX_SIZE + 1, baseline="HEAD")
    if bad.get("error") != "BAD_SIZE":
        return _fail("池大小无上限", bad)
    z = pool.acquire(str(repo), str(wt_root), sid="", branch="agent/session/z", baseline="HEAD")
    if z.get("error") != "SID_REQUIRED":
        return _fail("空 sid 可抢槽（无主槽 = 任何人可写）", z)
    for br in ("master", "gk-pool/0"):
        b = pool.acquire(str(repo), str(wt_root), sid="s1", branch=br, baseline="HEAD")
        if b.get("error") != "BRANCH_PROTECTED":
            return _fail("主分支/池分支可被占：%s" % br, b)

    # ── 4b 中枢默认走池（opt-out）：默认 True，`GK_WT_POOL_HUB=0` 才关 ──
    import gk_route_center as _rc
    _prev = os.environ.pop("GK_WT_POOL_HUB", None)
    try:
        if _rc._pool_hub_enabled() is not True:
            return _fail("中枢热池未默认开（新派发仍走 34s 冷建）")
        os.environ["GK_WT_POOL_HUB"] = "0"
        if _rc._pool_hub_enabled() is not False:
            return _fail("GK_WT_POOL_HUB=0 未能关闭中枢热池")
    finally:
        os.environ.pop("GK_WT_POOL_HUB", None)
        if _prev is not None:
            os.environ["GK_WT_POOL_HUB"] = _prev

    rep = pool.ensure_pool(str(repo), str(wt_root), size=2, baseline="HEAD")
    if not rep.get("ok"):
        return _fail("建池失败", rep)
    if not (rep.get("note") and rep.get("next")):
        return _fail("建池回包缺自动化引导", rep)

    out, lock = [], threading.Lock()

    def _grab(i):
        r = pool.acquire(str(repo), str(wt_root), sid="r%d" % i,
                         branch="agent/session/r%d" % i, baseline="HEAD")
        with lock:
            out.append(r)

    ths = [threading.Thread(target=_grab, args=(i,)) for i in range(4)]
    [t.start() for t in ths]
    [t.join() for t in ths]
    oks = [r for r in out if r.get("ok")]
    badr = [r for r in out if not r.get("ok")]
    if len(oks) != 2:
        return _fail("成功数 != 槽数", [r.get("error") for r in out])
    if len({r["worktree"] for r in oks}) != 2:
        return _fail("两路拿到同一槽")
    if any(r.get("error") != "POOL_EXHAUSTED" for r in badr):
        return _fail("失败原因不是 POOL_EXHAUSTED", badr)
    if not all(r.get("note") and r.get("next") for r in oks):
        return _fail("派发回包缺自动化引导", oks)
    n = len([ln for ln in _git(repo, "worktree", "list", "--porcelain").stdout.splitlines()
             if ln.startswith("worktree ")])
    if n != 3:      # 主树 + 2 槽（池满时不得偷偷新建树）
        return _fail("worktree 数量 %d != 3（池满仍新建树）" % n)
    for r in oks:
        pool.release(str(repo), str(wt_root), r["worktree"], baseline="HEAD")
    return _ok("入口防呆 4 项 + 2 成功/槽互异/其余 POOL_EXHAUSTED + 引导齐备")


# ─── 5. 脏槽 TTL 清场（归档前置）─────────────────────────────────────────────
def probe_pool_dirty_sweep(root: Path) -> int:
    repo = _mk_repo(root)
    wt_root = root / "wts"
    wt_root.mkdir(parents=True, exist_ok=True)
    if not pool.ensure_pool(str(repo), str(wt_root), size=1, baseline="HEAD").get("ok"):
        return _fail("建池失败")
    a = pool.acquire(str(repo), str(wt_root), sid="crash", branch="agent/session/crash",
                     baseline="HEAD", ttl_s=0)
    if not a.get("ok"):
        return _fail("抢槽失败", a)
    ws = Path(a["worktree"])
    (ws / "a.txt").write_text("未提交的 tracked 改动", encoding="utf-8")
    (ws / "wip.txt").write_text("未提交的新文件", encoding="utf-8")

    sw = pool.sweep(str(repo), str(wt_root), baseline="HEAD")
    if not sw.get("archived"):
        return _fail("清场未归档（未提交工作被静默销毁）", sw)
    arc = Path(sw["archived"][0]["dir"])
    diff = (arc / "changes.diff").read_text(encoding="utf-8")
    if "未提交的 tracked 改动" not in diff:
        return _fail("diff 归档内容缺失")
    if not (arc / "untracked" / "wip.txt").exists():
        return _fail("未跟踪文件未归档")

    b = pool.acquire(str(repo), str(wt_root), sid="next", branch="agent/session/next",
                     baseline="HEAD")
    if not b.get("ok"):
        return _fail("清场后不可再派发", b)
    ws2 = Path(b["worktree"])
    if (ws2 / "wip.txt").exists():
        return _fail("残留跨会话外溢")
    if (ws2 / "a.txt").read_text(encoding="utf-8") != "x":
        return _fail("tracked 文件未回基线")
    # 状态面必须带自动化引导（三态读法），否则 agent 只能按目录名猜
    st = pool.status(str(repo), str(wt_root))
    if not st.get("note"):
        return _fail("status 回包缺自动化引导", st)
    pool.release(str(repo), str(wt_root), str(ws2), baseline="HEAD")
    return _ok("归档 diff + 未跟踪副本 + 清后可复用 + status 带引导")


# ─── 6. 主分支锁定 ──────────────────────────────────────────────────────────
def probe_reclaim_master_lock(root: Path) -> int:
    repo = _mk_repo(root)
    _git(repo, "branch", "topic-merged", "HEAD")
    _git(repo, "branch", "gk-pool/9", "HEAD")

    rep = reclaim.sweep_loose_branches(str(repo), str(repo), apply=False)
    if "topic-merged" not in rep["would_remove"]:
        return _fail("普通已并分支未进回收面（判定器失效）", rep)
    if "gk-pool/9" not in rep["protected"]:
        return _fail("池分支未受保护", rep)
    if "master" not in rep["protected"]:
        return _fail("主分支未受保护", rep)

    _git(repo, "checkout", "-q", "--detach", "HEAD")
    rep2 = reclaim.sweep_loose_branches(str(repo), str(repo), apply=False)
    if set(rep2["would_remove"]) & set(reclaim.PROTECTED_BRANCHES):
        return _fail("主树 detach 后主分支进了删除面", rep2)
    if [b for b in rep2["would_remove"] if b.startswith("gk-pool/")]:
        return _fail("池分支进了删除面", rep2)
    # 判据本体（不只走 sweep）：主分支/池分支必须恒受保护
    for b in ("master", "main", "trunk", "develop", "gk-pool/3"):
        if not reclaim.is_protected_branch(b):
            return _fail("保护判据漏了 %s" % b)
    return _ok("protected + 删除面不含受保护分支 + 判据本体覆盖 master/main/trunk/develop/gk-pool/*")


# ─── 7. 编辑即续期（活跃会话不被 TTL 误收）──────────────────────────────────
def probe_pool_lease_renew(root: Path) -> int:
    repo = _mk_repo(root)
    wt_root = root / "wts"
    wt_root.mkdir(parents=True, exist_ok=True)
    if not pool.ensure_pool(str(repo), str(wt_root), size=1, baseline="HEAD").get("ok"):
        return _fail("建池失败")
    a = pool.acquire(str(repo), str(wt_root), sid="me", branch="agent/session/me",
                     baseline="HEAD", ttl_s=100)
    if not a.get("ok"):
        return _fail("抢槽失败", a)
    ws = Path(a["worktree"])
    lp = ws.parent / (ws.name + ".lease.json")

    def _age(sec):
        d = json.loads(lp.read_text(encoding="utf-8"))
        d["ts_epoch"] = time.time() - sec
        lp.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")

    # 7a 活跃会话：已过 ttl/2 ⟹ 编辑（check）必须续期，且 sweep 不得收
    _age(60)
    f = ws / "x.txt"
    f.write_text("x", encoding="utf-8")
    r = own.check(str(f), ["me"], roots=[str(wt_root)], autoclaim=False)
    if r.get("decision") != "allow" or not (r.get("lease_renewed") or {}).get("renewed"):
        return _fail("编辑未续期（活跃会话会被 TTL 当崩溃）", r)
    if pool.sweep(str(repo), str(wt_root), baseline="HEAD").get("reclaimed"):
        return _fail("活跃会话槽位被 TTL 误收")

    # 7b 节流：ttl/2 内不得重复落盘
    r2 = own.check(str(f), ["me"], roots=[str(wt_root)], autoclaim=False)
    if "lease_renewed" in r2:
        return _fail("续期未按 ttl/2 节流（每次编辑都落盘）", r2)

    # 7c 外人不能替别人的槽续期（否则可把别人的槽“焊死”）
    _age(60)
    before = json.loads(lp.read_text(encoding="utf-8"))["ts_epoch"]
    rr = own.renew_pool_lease(str(ws), ["intruder"])
    if rr.get("error") != "NOT_OWNER":
        return _fail("外人可替别人的槽续期", rr)
    if json.loads(lp.read_text(encoding="utf-8"))["ts_epoch"] != before:
        return _fail("外人续期改动了租约")

    # 7d 真崩溃（过期且无人续）仍必须被收 —— 机制不能退化成“永不回收”
    _age(1000)
    if not pool.sweep(str(repo), str(wt_root), baseline="HEAD").get("reclaimed"):
        return _fail("过期槽未被回收（TTL 形同虚设）")
    return _ok("活跃续期 + ttl/2 节流 + 外人拒续 + 真过期仍回收")


# ─── 8. 跨进程并发抢槽（O_EXCL 原子性）──────────────────────────────────────
def probe_pool_crossproc_race(root: Path) -> int:
    repo = _mk_repo(root)
    wt_root = root / "wts"
    wt_root.mkdir(parents=True, exist_ok=True)
    if not pool.ensure_pool(str(repo), str(wt_root), size=2, baseline="HEAD").get("ok"):
        return _fail("建池失败")
    scripts = str(Path(__file__).resolve().parents[1])
    code = ("import json,sys;sys.path.insert(0,%r);import gk_worktree_pool as p;"
            "print(json.dumps(p.acquire(%r,%r,sid=sys.argv[1],branch=sys.argv[2],baseline='HEAD')))"
            % (scripts, str(repo), str(wt_root)))
    procs = [subprocess.Popen([sys.executable, "-c", code, "c%d" % i, "agent/session/c%d" % i],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                              env=dict(os.environ)) for i in range(4)]
    outs = []
    for pr in procs:
        o, e = pr.communicate(timeout=120)
        try:
            outs.append(json.loads((o or "").strip().splitlines()[-1]))
        except Exception:  # noqa: BLE001 — 子进程崩了就是没防住/没跑起来，必须报
            outs.append({"ok": False, "error": "BAD_OUTPUT",
                         "raw": (o or "")[:200], "stderr": (e or "")[:200]})
    oks = [r for r in outs if r.get("ok")]
    bad = [r for r in outs if not r.get("ok")]
    if len(oks) != 2:
        return _fail("跨进程成功数 != 槽数", [r.get("error") for r in outs])
    if len({r["worktree"] for r in oks}) != 2:
        return _fail("跨进程两路拿到同一槽")
    if any(r.get("error") != "POOL_EXHAUSTED" for r in bad):
        return _fail("失败原因不是 POOL_EXHAUSTED", bad)
    n = len([ln for ln in _git(repo, "worktree", "list", "--porcelain").stdout.splitlines()
             if ln.startswith("worktree ")])
    if n != 3:
        return _fail("worktree 数量 %d != 3（跨进程池满仍新建树）" % n)
    for r in oks:
        pool.release(str(repo), str(wt_root), r["worktree"], baseline="HEAD")
    return _ok("跨进程 2 成功 / 槽互异 / 其余 POOL_EXHAUSTED / 无新树")


# ─── 9. 真 hook 端到端：伪造载荷 session_id ─────────────────────────────────
def probe_hook_session_forge(root: Path) -> int:
    """跑**真实** `pre_tool_hook.py`（stdin 喂 hook payload），而不是直接调判据函数。

    E3（沙盘根必须 /tmp）与 hook 的 scope 解析天然冲突：`/tmp` 目标默认 scope_out ⟹
    钩子会在 Gate 3c 之前放行，测什么都是绿的。故在沙盘内放一份**就近 state**
    （`.gatekeeper.state` 的 `worktree` = 受害者），让 hook 走真实的 Gate 2/3/3c。
    """
    repo = _mk_repo(root)
    wt_root = root / "wts"
    # sid 必须是**纯 hex 8–64 位**（`gk_worktree_owner._SID_RE`，2026-11-13 收紧）：
    #   非 hex 标签会被身份解析丢弃 ⟹ 主人正控也会被归属闸拦（判定器恒假）。
    victim_sid, attacker_sid = "a1b2c3d4", "deadbeef"
    victim = _mk_session_wt(repo, wt_root, victim_sid)
    f = victim / "x.txt"
    f.write_text("x", encoding="utf-8")
    own.claim(str(victim), [victim_sid], force=True)
    st = wt_root / repo.name / ".gatekeeper.state"
    st.write_text(json.dumps({
        "stage": "T1", "phase": "P1",
        # hook 读的是**顶层** `worktree`（`state.get("worktree")`，见 pre_tool_hook.py）；
        # `worktrees_extra` 同层 ⟹ Gate 2/3 才会真正执行到 Gate 3c。
        "worktree": str(victim), "worktrees_extra": [str(victim)],
        "gate_data": {"edit_budget": {"max": 99, "sessions": {}}},
    }, ensure_ascii=False), encoding="utf-8")

    hook = str(Path(__file__).resolve().parents[1] / "pre_tool_hook.py")

    def _run(sid: str):
        payload = {"tool_name": "Edit", "file_path": str(f), "cwd": str(root),
                   "session_id": sid, "tool_input": {"file_path": str(f)}}
        env = ci.sanitized_env(dict(os.environ))
        env["STATE_FILE"] = str(st)
        env.pop("GK_SESSION_ID", None)
        return subprocess.run([sys.executable, hook], input=json.dumps(payload),
                              capture_output=True, text=True, env=env, timeout=180)

    bad = _run(attacker_sid)
    out = (bad.stdout or "") + (bad.stderr or "")
    if "WORKTREE_OWNERSHIP_VIOLATION" not in out:
        return _fail("伪造 session_id 未被归属闸拦（真 hook 路径）",
                     {"rc": bad.returncode, "out": out[:500]})
    if bad.returncode != 2:
        return _fail("归属 BLOCK 退出码应为 2", bad.returncode)
    good = _run(victim_sid)
    gout = (good.stdout or "") + (good.stderr or "")
    if "WORKTREE_OWNERSHIP_VIOLATION" in gout:
        return _fail("主人也被归属闸误拦（判定器恒假）", gout[:500])
    return _ok("真 hook：伪造 payload ⟹ Gate 3c BLOCK(rc=2)；主人不被归属闸拦")


# ─── 10. 一 sid 一槽（重复 acquire 不得吃第二槽）─────────────────────────────
def probe_pool_double_lease(root: Path) -> int:
    repo = _mk_repo(root)
    wt_root = root / "wts"
    wt_root.mkdir(parents=True, exist_ok=True)
    if not pool.ensure_pool(str(repo), str(wt_root), size=2, baseline="HEAD").get("ok"):
        return _fail("建池失败")
    a = pool.acquire(str(repo), str(wt_root), sid="dup", branch="agent/session/dup",
                     baseline="HEAD")
    if not a.get("ok"):
        return _fail("首次抢槽失败", a)
    # 10a 同 sid 同分支 ⟹ 幂等回同一槽（不占第二槽）
    b = pool.acquire(str(repo), str(wt_root), sid="dup", branch="agent/session/dup",
                     baseline="HEAD")
    if not b.get("ok") or b.get("slot") != a.get("slot") or not b.get("idempotent"):
        return _fail("重复 acquire 未幂等（吃了第二个槽）", b)
    # 10b 同 sid 换分支 ⟹ 必须拒（禁一 sid 占两槽）
    c = pool.acquire(str(repo), str(wt_root), sid="dup", branch="agent/session/dup2",
                     baseline="HEAD")
    if c.get("error") != "SID_ALREADY_LEASED":
        return _fail("同 sid 换分支仍拿到第二个槽", c)
    st = pool.status(str(repo), str(wt_root))
    if st.get("leased") != 1:
        return _fail("池内租约数 != 1（重复 acquire 泄漏槽位）", st)
    # 10c 别的 sid 仍能拿另一槽（池容没被误锁）
    d = pool.acquire(str(repo), str(wt_root), sid="other", branch="agent/session/other",
                     baseline="HEAD")
    if not d.get("ok") or d.get("slot") == a.get("slot"):
        return _fail("他人拿不到另一槽", d)
    pool.release(str(repo), str(wt_root), b["worktree"], baseline="HEAD")
    pool.release(str(repo), str(wt_root), d["worktree"], baseline="HEAD")
    return _ok("同分支幂等回原槽 + 换分支拒 + 他人仍可拿另一槽")


# ─── 11. 诱饵面（假信息只在自己仓内；非 owner 命中 ⟹ 单行零信息拒绝）──────────
def probe_canary_deception(root: Path) -> int:
    """三类诱饵（假 state/claims、假池槽、假 token/密钥）+ 真 hook 端到端拒绝。"""
    import gk_canary as canary
    import gk_threat as threat

    repo = _mk_repo(root)
    state = root / ".gatekeeper.state"
    state.write_text("{}", encoding="utf-8")
    st = str(state)
    inst = canary.install(str(repo), owner_sid="owner")
    if not inst.get("ok"):
        return _fail("诱饵部署失败", inst)

    d = repo / ".gatekeeper-canary"
    fake_state = json.loads((d / "state.json").read_text(encoding="utf-8"))
    if int(fake_state.get("credit_balance") or 0) != 999999:
        return _fail("假 state 缺 credit_balance=999999", fake_state)
    if not (d / "claims.json").is_file():
        return _fail("假 claims 缺失")
    if not (d / "pool" / "slot-99" / ".git").is_file():
        return _fail("假池槽缺失")
    if list((d / "pool").rglob("*lease*")) or list((d / "pool").rglob("*claim*")):
        return _fail("假池槽带了 lease/claim（会被当成可派发）")
    if not (d / ".env").is_file() or not (d / "id_rsa").is_file():
        return _fail("假 token/密钥缺失")

    # 判定既不能漏（绝对/相对路径都算接触），也不能恒真（无关命令不命中）
    if not canary.check_access(str(d / "state.json"), cwd=str(repo)).get("hit"):
        return _fail("绝对路径未命中诱饵")
    if not canary.check_access("cat .gatekeeper-canary/.env", cwd=str(repo)).get("hit"):
        return _fail("相对路径未命中诱饵")
    if canary.check_access("pytest -q scripts/", cwd=str(repo)).get("hit"):
        return _fail("判定器恒真（无关文本也命中）")

    hook = str(Path(__file__).resolve().parents[1] / "pre_tool_hook.py")

    def _run(sid: str, path: Path):
        payload = {"tool_name": "Read", "tool_input": {"file_path": str(path)},
                   "cwd": str(root), "session_id": sid}
        env = ci.sanitized_env(dict(os.environ))
        env["STATE_FILE"] = st
        env.pop("GK_SESSION_ID", None)
        return subprocess.run([sys.executable, hook], input=json.dumps(payload),
                              capture_output=True, text=True, env=env, timeout=180)

    bad = _run("attacker", d / "state.json")
    err = (bad.stderr or "").strip()
    lines = [ln for ln in err.splitlines() if ln.strip()]
    if bad.returncode != 2:
        return _fail("诱饵访问未被拒（真 hook）", {"rc": bad.returncode, "err": err[:300]})
    if len(lines) != 1 or lines[0] != threat.SINGLE_LINE:
        return _fail("拒绝面不是「单行零信息」", lines[:5])
    if ".gatekeeper-canary" in err or str(repo) in err or "worktree" in err:
        return _fail("拒绝面泄漏内部路径/面")
    # 一次访问**只记一笔**（目录前缀 + 具体文件命中同一诱饵面，不得一次算两笔）
    if threat.status("attacker", state=st)["count"] != 1:
        return _fail("一次访问的违约笔数 != 1（阈值会被放大）",
                     threat.status("attacker", state=st))

    # 正控：owner 访问诱饵不记违约，也不被单行拒绝（否则防御方无法巡检）
    own = _run("owner", d / "state.json")
    if threat.status("owner", state=st)["count"] != 0:
        return _fail("owner 被记违约")
    if threat.SINGLE_LINE in ((own.stderr or "") + (own.stdout or "")):
        return _fail("owner 也被单行拒绝（豁免失效）")
    return _ok("三类诱饵落盘 + O(1) 判定 + 真 hook 单行零信息拒绝 + owner 豁免")


# ─── 12. 隔离（窗口计数 ⟹ 一切工具调用只回一行；decay 自动解封）──────────────
def probe_threat_quarantine(root: Path) -> int:
    import gk_threat as threat

    repo = _mk_repo(root)
    state = root / ".gatekeeper.state"
    state.write_text("{}", encoding="utf-8")
    st = str(state)
    for _ in range(3):
        threat.record("attacker", "canary_hit", detail="probe", state=st)
    chk = threat.check("attacker", state=st)
    if not chk.get("denied") or chk.get("line") != threat.SINGLE_LINE:
        return _fail("3 次违约未隔离", chk)
    # decay：窗口外的旧违约不参与判级（文件只增不改，读侧过滤）
    now = time.time()
    for _ in range(3):
        threat.record("stale", "canary_hit", state=st, now=now - threat.window_s() - 60)
    if threat.check("stale", state=st, now=now)["denied"]:
        return _fail("窗口外旧违约仍在判级（decay 失效）")

    hook = str(Path(__file__).resolve().parents[1] / "pre_tool_hook.py")
    benign = repo / "benign.txt"

    def _run(sid: str):
        payload = {"tool_name": "Write",
                   "tool_input": {"file_path": str(benign), "content": "x"},
                   "cwd": str(root), "session_id": sid}
        env = ci.sanitized_env(dict(os.environ))
        env["STATE_FILE"] = st
        env.pop("GK_SESSION_ID", None)
        return subprocess.run([sys.executable, hook], input=json.dumps(payload),
                              capture_output=True, text=True, env=env, timeout=180)

    # 目标**不是**诱饵：隔离面必须独立生效（与诱饵判定解耦）
    bad = _run("attacker")
    err = (bad.stderr or "").strip()
    lines = [ln for ln in err.splitlines() if ln.strip()]
    if bad.returncode != 2:
        return _fail("被隔离后仍能调工具", {"rc": bad.returncode, "err": err[:300]})
    if len(lines) != 1 or lines[0] != threat.SINGLE_LINE:
        return _fail("隔离拒绝面不是单行零信息", lines[:5])
    if "stage=" in err or "worktree=" in err or str(repo) in err:
        return _fail("隔离拒绝面泄漏 state/路径")
    if benign.exists():
        return _fail("被隔离方仍写入成功")

    # 正控：未被隔离的会话不得被这层拦
    good = _run("innocent")
    if threat.SINGLE_LINE in ((good.stderr or "") + (good.stdout or "")):
        return _fail("无辜会话被隔离面误拦（判定器恒真）")
    return _ok("3 次违约 ⟹ 隔离；窗口外旧账不判级；任意目标只回一行；无辜会话不受影响")


# ─── 13. per-sid 派发限流（acquire/release 抖动与抢槽）──────────────────────
def probe_pool_rate_limit(root: Path) -> int:
    repo = _mk_repo(root)
    wt_root = root / "wts"
    wt_root.mkdir(parents=True, exist_ok=True)
    os.environ["GK_POOL_ALLOW_ANY_ROOT"] = "1"
    os.environ["GK_POOL_RATE_LIMIT"] = "1"
    os.environ["GK_POOL_RATE_WINDOW_S"] = "600"
    try:
        if not pool.ensure_pool(str(repo), str(wt_root), size=2, baseline="HEAD").get("ok"):
            return _fail("建池失败")
        a = pool.acquire(str(repo), str(wt_root), sid="flap",
                         branch="agent/session/r1", baseline="HEAD")
        if not a.get("ok"):
            return _fail("首次派发失败", a)
        if not pool.release(str(repo), str(wt_root), a["worktree"], baseline="HEAD").get("ok"):
            return _fail("归还失败")
        b = pool.acquire(str(repo), str(wt_root), sid="flap",
                         branch="agent/session/r2", baseline="HEAD")
        if b.get("error") != "RATE_LIMITED":
            return _fail("窗口内抖动未被限流", b)
        if pool.status(str(repo), str(wt_root)).get("leased") != 0:
            return _fail("限流消耗了槽位")
        # 正控：别的 sid 不受影响（限流 per-sid，不是全局闸）
        c = pool.acquire(str(repo), str(wt_root), sid="other",
                         branch="agent/session/r3", baseline="HEAD")
        if not c.get("ok"):
            return _fail("别人的派发被连坐", c)
        pool.release(str(repo), str(wt_root), c["worktree"], baseline="HEAD")

        # decay：把计数时间戳改成窗口外 ⟹ 应立刻解封（否则 = 一次性拉黑）
        pd = pool.pool_dir(str(repo), str(wt_root))
        rf = pool._rate_file(pd, "flap")
        rf.write_text("%.3f\n" % (time.time() - 7200), encoding="utf-8")
        d = pool.acquire(str(repo), str(wt_root), sid="flap",
                         branch="agent/session/r4", baseline="HEAD")
        if not d.get("ok"):
            return _fail("窗口滑动后仍被永久限流", d)
        pool.release(str(repo), str(wt_root), d["worktree"], baseline="HEAD")
    finally:
        os.environ.pop("GK_POOL_RATE_LIMIT", None)
        os.environ.pop("GK_POOL_RATE_WINDOW_S", None)
        os.environ.pop("GK_POOL_ALLOW_ANY_ROOT", None)
    return _ok("窗口内抖动 RATE_LIMITED + 不耗槽 + 不连坐 + 窗口滑动自动解封")


# ─── 14. monitor 事件驱动 + 旋转门（无信号零调用；信号 ⟹ triage + 轮转）──────
def probe_monitor_rotation(root: Path) -> int:
    """证明 monitor 不再"闲置"：无信号零激活；命中信号 ⟹ 分档 + 诱饵换代（旧地图仍暴露）。"""
    import gk_canary as canary
    import gk_monitor_rotation as monitor
    import gk_threat as threat

    repo = _mk_repo(root)
    state = root / ".gatekeeper.state"
    state.write_text("{}", encoding="utf-8")
    st = str(state)
    canary.install(str(repo), owner_sid="owner")
    old = repo / ".gatekeeper-canary" / "state.json"

    # 14a 无信号 ⟹ 零激活 / 零 API（monitor 闲置时不得烧 token）
    idle = monitor.run(repo=str(repo), state=st, endpoint="")
    if idle.get("activated"):
        return _fail("无信号也激活了 monitor（闲置面仍在烧）", idle)
    if idle.get("api_calls") != 0:
        return _fail("无信号也调了 LLM", idle)

    # 14b 3 次诱饵命中 ⟹ 中等级信号 ⟹ triage + 轮转（首命中不等预热）
    for _ in range(3):
        threat.record("attacker", "canary_hit", detail="probe", state=st)
    out = monitor.run(repo=str(repo), state=st, endpoint="")
    if not out.get("activated") or int(out.get("level") or 0) < 2:
        return _fail("信号未激活/未达中等级", out)
    if out.get("api_calls") != 0:
        return _fail("endpoint 未配仍调了 LLM", out)
    rot = out.get("rotation") or {}
    if not rot.get("rotated") or int(rot.get("generation") or 0) != 2:
        return _fail("中等级信号未触发诱饵轮转（旋转门没转）", rot)
    if not old.is_file():
        return _fail("退役诱饵被删（旧地图不再暴露）")
    if not canary.check_access(str(old), cwd=str(repo)).get("hit"):
        return _fail("退役诱饵不再参与判定")
    new = repo / str(rot.get("active_dir") or "") / "state.json"
    if not new.is_file() or not canary.check_access(str(new), cwd=str(repo)).get("hit"):
        return _fail("新世代诱饵未生效", {"dir": rot.get("active_dir")})

    # 14c 同批信号只消费一次（游标）；审计行必须落盘
    again = monitor.run(repo=str(repo), state=st, endpoint="")
    if again.get("activated"):
        return _fail("游标未推进（同批信号会反复烧 monitor）", again)
    log = Path(st + ".threat.monitor.jsonl")
    if not log.is_file() or not log.read_text(encoding="utf-8").strip():
        return _fail("激活无审计行")
    return _ok("无信号零激活 + 信号分档 + 诱饵换代（退役仍暴露）+ 游标只消费一次")


_PROBES = {
    "wt-share-poison-01": probe_wt_share_poison,
    "hook-ownership-bypass-01": probe_hook_ownership_bypass,
    "commit-identity-forge-01": probe_commit_identity_forge,
    "pool-slot-race-01": probe_pool_slot_race,
    "pool-dirty-sweep-01": probe_pool_dirty_sweep,
    "reclaim-master-lock-01": probe_reclaim_master_lock,
    "pool-lease-renew-01": probe_pool_lease_renew,
    "pool-crossproc-race-01": probe_pool_crossproc_race,
    "hook-session-forge-01": probe_hook_session_forge,
    "pool-double-lease-01": probe_pool_double_lease,
    "canary-deception-01": probe_canary_deception,
    "threat-quarantine-01": probe_threat_quarantine,
    "pool-rate-limit-01": probe_pool_rate_limit,
    "monitor-rotation-01": probe_monitor_rotation,
}


def build(sid: str, root: str) -> dict:
    """给 `runner.run_scenario` 的场景 dict（argv 指向本文件 + 探针 id）。"""
    return {"id": sid, "kind": "runtime",
            "steps": [{"argv": [sys.executable, str(Path(__file__).resolve()),
                                "--probe", sid, "--root", root],
                       "invariant": {"kind": "exit_zero"}}]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", required=True)
    ap.add_argument("--root", required=True)
    a = ap.parse_args(argv)
    fn = _PROBES.get(a.probe)
    if not fn:
        return _fail("unknown probe: " + a.probe)
    root = Path(a.root)
    # E3：沙盘根必须在 /tmp（本机 drvfs 上 rmtree 会 D 状态挂死）
    if not str(root).startswith("/tmp/"):
        return _fail("sandbox root 必须在 /tmp: " + str(root))
    root.mkdir(parents=True, exist_ok=True)
    return fn(root)


if __name__ == "__main__":
    raise SystemExit(main())

"""worktree 回收链 `apply-worktree --reclaim`（finding `ECC-35AC08DA96F0`）红先臂集。

**红先对照（HEAD 源码，本仓惯例）**：
  `git show HEAD:gatekeeper-cli.sh | grep -c -- '--reclaim'` → **0**
  `git show HEAD:scripts/gk_worktree_reclaim.py` → **不存在**
⟹ 下列形态臂 / 行为臂在 HEAD 上必红。

**本轮新增（隔离区回收 / 归因判据，findings `ECC-AAB70D5DCF11` / `ECC-82CC385C121E` /
`ECC-070771766647`）红先对照**：
  `git show HEAD:scripts/gk_worktree_reclaim.py | grep -c 'def reclaim_trash'` → **0**
  `git show HEAD:scripts/gk_worktree_reclaim.py | grep -c 'def _trash_dir'`    → **0**
  `git show HEAD:scripts/gk_route_center.py    | grep -c 'def trash_dir'`     → **0**
  `git show HEAD:scripts/gk_worktree_reclaim.py | grep -c 'TMP_OWN_RULE'`     → **0**
  `git show HEAD:gatekeeper-cli.sh | grep -c -- '--trash'`                    → **0**
"""
import os
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_worktree_reclaim as wr


def _git(repo, *a):
    return subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True)


def test_orphan_scan_is_scoped_and_depth_bounded(tmp_path, monkeypatch):
    """2026-10-23（红先，实测 180s 挂死）：孤儿扫描必须**收窄到本仓子树**且**限深 ≤2**。

    现场：`root` = 共享 worktree 根（跨仓库 parent，实测 7+ 棵 worktree × node_modules/.git），
    旧实现对它做**无界** `os.walk` ⟹ `apply-worktree --reclaim` 单次 >180s，把
    `test_gk_edit_budget_metering` 的 5 臂挂死（faulthandler 栈停在 `os.walk`）。
    判据三条（缺一即红）：
      ① `<root>/<repo>/<branch>/.git` 须被发现（自有子树，深度 1）；
      ② `<root>/<repo>/<branch>/deep/.git` 不得被认领（深度 2 不下钻）；
      ③ `<root>/<other-repo>/<branch>/.git` 不得被本仓认领（他仓越界）。
    ⚠ claim 闸另行独立（`gk_write_claims`，本机实测单次 5.8s 且 `/tmp` 全局 claim 会命中
      任意临时路径）⟹ 本臂关掉该闸，只测**扫描面**（单一变量）。
    """
    monkeypatch.setenv("GK_RECLAIM_CLAIM_GUARD", "0")
    root = tmp_path / "wts"
    repo = tmp_path / "skill"                     # basename 决定自有子树名
    (root / "skill" / "br1").mkdir(parents=True)
    (root / "skill" / "br1" / ".git").write_text("gitdir: x\n", encoding="utf-8")
    (root / "skill" / "br2" / "deep").mkdir(parents=True)
    (root / "skill" / "br2" / "deep" / ".git").write_text("gitdir: y\n", encoding="utf-8")
    (root / "other-repo" / "br3").mkdir(parents=True)
    (root / "other-repo" / "br3" / ".git").write_text("gitdir: z\n", encoding="utf-8")
    repo.mkdir()

    t0 = time.time()
    rep = wr.reclaim(str(repo), str(root))
    elapsed = time.time() - t0
    found = {os.path.abspath(i["path"]) for i in rep["items"]}
    assert os.path.abspath(str(root / "skill" / "br1")) in found, rep["items"]
    assert os.path.abspath(str(root / "skill" / "br2" / "deep")) not in found, rep["items"]
    assert not any("other-repo" in p for p in found), rep["items"]
    assert elapsed < 10, "孤儿扫描疑似无界（elapsed=%.1fs）" % elapsed


def test_depth2_route_worktree_found_and_age_gated(tmp_path, monkeypatch):
    """2026-10-31（红先，实测 31 个断链 worktree 静默堆积）：route 布局是**两段**。

    现场：`<root>/<repo>/feature/<name>`（agent 同构，单源 `gk_route_center.WORKTREE_ROUTES`
    的 `*/feature/*`、`*/agent/*/*`）位于**深度 2**，而孤儿扫描限深 1 ⟹ `git worktree prune`
    清掉元数据后，这些树既不在 `git worktree list`、又不是空壳、也不是孤儿 state ⟹ 三面全盲
    （实测 19 个断链 + 1 个 499M `.orphan-moved`）。
    判据：
      ① 深度 2、`feature/<name>` 形态、`.git` 指向不存在 gitdir、**超龄** ⟹ 必须进候选（broken 标记）；
      ② 同形态但**未超龄**（< `GK_RECLAIM_UNREG_DAYS`）⟹ 不进（防把正在 `worktree add` 的半成品回收）；
      ③ 非 route 前缀的深度 2 目录（`br2/deep`）⟹ 仍不认领（既有红先臂 `depth_bounded` 语义零回归）。
    """
    monkeypatch.setenv("GK_RECLAIM_CLAIM_GUARD", "0")
    monkeypatch.delenv("GK_RECLAIM_UNREG_DAYS", raising=False)
    root = tmp_path / "wts"
    repo = tmp_path / "skill"
    repo.mkdir()
    stale = root / "skill" / "feature" / "stale-tree"
    stale.mkdir(parents=True)
    (stale / ".git").write_text("gitdir: /nonexistent/git/worktrees/stale-tree\n", encoding="utf-8")
    (stale / "keep.txt").write_text("未回收内容", encoding="utf-8")
    fresh = root / "skill" / "feature" / "fresh-tree"
    fresh.mkdir(parents=True)
    (fresh / ".git").write_text("gitdir: /nonexistent/git/worktrees/fresh-tree\n", encoding="utf-8")
    (fresh / "a.txt").write_text("x", encoding="utf-8")
    off = time.time() - 8 * 86400
    os.utime(stale, (off, off))
    os.utime(stale / ".git", (off, off))

    rep = wr.reclaim(str(repo), str(root))
    found = {os.path.abspath(i["path"]): i for i in rep["items"]}
    assert os.path.abspath(str(stale)) in found, rep["items"]
    assert found[os.path.abspath(str(stale))]["unregistered"] is True
    assert found[os.path.abspath(str(stale))]["broken"] is True
    assert os.path.abspath(str(fresh)) not in found, "未超龄的未注册树不得进候选（防回收半成品）"


def test_depth2_stale_tree_apply_archives_then_removes(tmp_path, monkeypatch):
    """同族的 `--apply` 臂：断链树的内容必须**先归档再删**（禁静默丢工作）。"""
    monkeypatch.setenv("GK_RECLAIM_CLAIM_GUARD", "0")
    root = tmp_path / "wts"
    repo = tmp_path / "skill"
    repo.mkdir()
    stale = root / "skill" / "agent" / "F-demo" / "abc12345"
    stale.mkdir(parents=True)
    (stale / ".git").write_text("gitdir: /nonexistent/git/worktrees/abc12345\n", encoding="utf-8")
    (stale / "only_here.txt").write_text("未回收内容", encoding="utf-8")
    off = time.time() - 9 * 86400
    os.utime(stale, (off, off))
    os.utime(stale / ".git", (off, off))
    trash = tmp_path / "trash"

    rep = wr.reclaim(str(repo), str(root), apply=True, only=[str(stale)],
                     trash=str(trash))
    assert os.path.abspath(str(stale)) in {os.path.abspath(p) for p in rep["removed"]}, rep
    assert not stale.exists()
    archived = [p for p in rep["archived"]]
    assert archived, "无归档落点 ⟹ 违反归档前置"
    assert any("only_here.txt" in os.path.join(dp, f)
               for dp, _dn, fn in os.walk(str(trash)) for f in fn), rep


@pytest.fixture()
def repo_wt(tmp_path):
    """真 git 仓 + 一个真 worktree（含**未提交新文件** = 待归档内容）。"""
    repo = tmp_path / "main"
    repo.mkdir()
    _git(str(repo), "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("x", encoding="utf-8")
    _git(str(repo), "add", "a.txt")
    _git(str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")
    root = tmp_path / "wts"
    root.mkdir()
    wt = root / "wt1"
    _git(str(repo), "worktree", "add", "-q", "-b", "feat", str(wt))
    (wt / "new_file.txt").write_text("未回收内容", encoding="utf-8")
    return str(repo), str(root), str(wt)


def test_cli_wires_reclaim_in_both_case_slots():
    """形态臂：`--reclaim` 必须在**两个** case 位注册。

    `--batch` 的教训（`test_batch_flag_and_k_max_default_are_present`）：只加 `while` 里那
    一处会漏 —— 函数开头的**首个位置** case 会把 `--reclaim` 当 finding 吃掉并 `shift 2`。
    """
    cli = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "gatekeeper-cli.sh")
    src = open(cli, encoding="utf-8").read()
    seg = src[src.index("cmd_apply_worktree() {"):]
    assert seg.count("--reclaim)") >= 2, "`--reclaim` 未在两个 case 位均注册"
    assert "gk_worktree_reclaim.py" in seg, "未委托单一事实源脚本（疑第二实现）"


def test_main_repo_is_never_reclaimed(repo_wt):
    """**硬臂（实测缺陷回归）**：主 worktree 永不进回收面。

    现场（2026-09-24 首版即踩）：从 worktree 内调用时 `--repo` = 那个 worktree，而排除判据
    只用 `--repo` ⟹ **主树**（`worktree list` 首条）被列为 `WOULD-REMOVE` ⟹ `--apply` 会删主树。
    """
    repo, root, wt = repo_wt
    r = wr.reclaim(wt, root, apply=False)     # 故意拿 **worktree** 当 `--repo`（复现首版现场）
    skipped = [os.path.abspath(p) for p in r["skipped"]]
    assert os.path.abspath(repo) in skipped, "主 worktree 未进 skipped ⟹ 有被删风险"


def test_claim_guarded_reports_fix_and_hint(repo_wt, tmp_path, monkeypatch):
    """ECC-B141333BBA20：live claim ⟹ 拒删且**给可操作 fix**（+ 顶层 hint）。

    前坑：`--unbind` 只清 `state.worktrees_extra[]`、**不**释放 claim（claim 在 gk_write_claims
    台账）⟹ guard 项此前只回 `sids`、无指引，用户在 TTL 3600s 内以为"回收失败"却不知下一步。
    """
    repo, root, wt = repo_wt
    ledger = tmp_path / "claims.jsonl"
    monkeypatch.setenv("GK_WRITE_CLAIMS_PATH", str(ledger))
    monkeypatch.delenv("GK_RECLAIM_CLAIM_GUARD", raising=False)
    import gk_write_claims as wc
    assert wc.append(None, sid="t9", worktree=wt, source="test").get("ok"), "夹具：claim 未登记"
    r = wr.reclaim(repo, root, apply=False, trash=os.path.join(root, "trash"))
    guarded = [g for g in (r.get("claim_guarded") or [])
               if os.path.abspath(g["path"]) == os.path.abspath(wt)]
    assert guarded, "live claim 未进 claim_guarded ⟹ 护并发闸失效"
    assert guarded[0].get("fix"), "claim_guarded 缺 fix（无操作指引 = 原缺陷）"
    assert "release" in guarded[0]["fix"], "fix 未指向 gk_write_claims release"
    assert "release" in (r.get("hint") or ""), "缺顶层 hint"


def test_full_sweep_apply_refused_without_authorization(repo_wt, monkeypatch):
    """**红先**（finding `ECC-2B04C5B10464`）：全量 `--apply`（无 `--path`）在**未显式授权**时
    必须**拒绝（零写）**。

    现场：一次未带 `--path` 的 `--apply` 全量扫把 3 个**在用**会话 worktree 一并删档（白名单原为
    **opt-in** ⟹ 全量零门槛）。HEAD 必红（现状直接开删）。
    """
    repo, root, wt = repo_wt
    monkeypatch.delenv("GK_RECLAIM_ALLOW_FULL", raising=False)
    monkeypatch.delenv("GK_RECLAIM_CLAIM_GUARD", raising=False)
    trash = os.path.join(root, "trash")
    r = wr.reclaim(repo, root, apply=True, trash=trash)
    assert r["ok"] is False and r.get("error") == "FULL_SWEEP_REFUSED", r
    assert os.path.isdir(wt), "未授权全量回收竟删了 worktree（零写契约破）"
    assert not os.path.isdir(trash), "未授权全量回收竟写了归档"


def test_expired_unreleased_claim_is_held(repo_wt, tmp_path, monkeypatch):
    """**红先**（finding `ECC-2B04C5B10464`）：claim **过期但未 release** ⟹ 仍 held（**过期 ≠ 可删**）。

    现场：`claims_for_worktree` 是 **live-only** ⟹ 长任务超 `claim_ttl_s`（3600s）后回收前置闸
    **fail-open**（实测末条 live claim 已过期 12m43s 的在用 worktree 被全量删档）。HEAD 必红。
    """
    import gk_write_claims as wc
    repo, root, wt = repo_wt
    monkeypatch.setenv("GK_WRITE_CLAIMS_PATH", str(tmp_path / "claims.jsonl"))
    monkeypatch.delenv("GK_RECLAIM_CLAIM_GUARD", raising=False)
    monkeypatch.setenv("GK_RECLAIM_ALLOW_FULL", "1")   # 隔离 #1：本臂只验 claim 判据（#2）
    old = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 10000))
    assert wc.append(None, sid="exp", worktree=wt, source="test",
                     ttl_s=3600, ts=old).get("ok"), "夹具：claim 未登记"
    assert not wc.claims_for_worktree(None, wt), "前置：claim 应已过期（live 面须回空）"
    assert wc.unreleased_claims_for_worktree(None, wt), "前置：应为未 release"
    trash = os.path.join(root, "trash")
    r = wr.reclaim(repo, root, apply=True, trash=trash)
    assert os.path.isdir(wt), "过期未 release 的 claim 未护住 worktree（「过期 ≠ 可删」未落）"
    guarded = [g for g in (r.get("claim_guarded") or [])
               if os.path.abspath(g["path"]) == os.path.abspath(wt)]
    assert guarded and "release" in guarded[0].get("fix", ""), r


def test_release_then_full_sweep_reclaims(repo_wt, tmp_path, monkeypatch):
    """**守臂**：显式 `release` 后，全量回收（已授权）可正常收掉该 worktree（闭环不卡死）。"""
    import gk_write_claims as wc
    repo, root, wt = repo_wt
    monkeypatch.setenv("GK_WRITE_CLAIMS_PATH", str(tmp_path / "claims.jsonl"))
    monkeypatch.delenv("GK_RECLAIM_CLAIM_GUARD", raising=False)
    monkeypatch.setenv("GK_RECLAIM_ALLOW_FULL", "1")
    assert wc.append(None, sid="rel", worktree=wt, source="test").get("ok"), "夹具：claim 未登记"
    assert wc.release(None, sid="rel", worktree=wt).get("ok"), "夹具：release 失败"
    trash = os.path.join(root, "trash")
    r = wr.reclaim(repo, root, apply=True, trash=trash)
    assert r["ok"] is True and not os.path.isdir(wt), "release 后仍无法回收（闭环卡死）"


def test_t13_narrow_path_autoreleases_claim(repo_wt, tmp_path, monkeypatch):
    """T13（n4 §19）：`--path` **窄面**（`only`）回收 ⟹ **自动释放**该 worktree 的 live claim
    （显式指名 = 会话已终结意图），不再被 D-a 闸拒；**宽面回收仍保闸**（对照
    `test_claim_guarded_reports_fix_and_hint`）。HEAD 必红（未自动释放 ⟹ `claim_guarded` 非空）。
    """
    repo, root, wt = repo_wt
    ledger = tmp_path / "claims.jsonl"
    monkeypatch.setenv("GK_WRITE_CLAIMS_PATH", str(ledger))
    monkeypatch.delenv("GK_RECLAIM_CLAIM_GUARD", raising=False)
    import gk_write_claims as wc
    assert wc.append(None, sid="t13", worktree=wt, source="test").get("ok"), "夹具：claim 未登记"
    r = wr.reclaim(repo, root, apply=True, only=[wt],
                   trash=os.path.join(root, "trash"))
    guarded = [g for g in (r.get("claim_guarded") or [])
               if os.path.abspath(g["path"]) == os.path.abspath(wt)]
    assert not guarded, "窄面回收仍被 claim 闸拒 ⟹ 未自动释放（T13 未落）"
    assert r.get("claim_autoreleased"), "缺 claim_autoreleased 留痕（释放面未报）"
    assert not wc.claims_for_worktree(None, wt), "claim 未真正 released"


def test_t13_dryrun_does_not_release_claim(repo_wt, tmp_path, monkeypatch):
    """T13 缺陷 `ECC-5406400DA6BD`：**dry-run**（`apply=False`）须守 reclaim 自述的「零写」契约 ——
    窄面回收只**预告**将释放，**绝不**落 claim 台账（否则一次预览 `--reclaim --path X`（默认
    dry-run）即误释放 X 的 live claim，可撞并发会话在用的工作区）。HEAD 必红（现状未 gate
    `apply` ⟹ `release` 被调，claim 变 released）。
    """
    repo, root, wt = repo_wt
    ledger = tmp_path / "claims.jsonl"
    monkeypatch.setenv("GK_WRITE_CLAIMS_PATH", str(ledger))
    monkeypatch.delenv("GK_RECLAIM_CLAIM_GUARD", raising=False)
    import gk_write_claims as wc
    assert wc.append(None, sid="t13dry", worktree=wt, source="test").get("ok"), "夹具：claim 未登记"
    r = wr.reclaim(repo, root, apply=False, only=[wt],
                   trash=os.path.join(root, "trash"))
    assert wc.claims_for_worktree(None, wt), "dry-run 释放了 live claim ⟹ 破「零写」契约"
    prev = [g for g in (r.get("claim_autoreleased") or [])
            if os.path.abspath(g.get("path", "")) == os.path.abspath(wt)]
    assert prev and prev[0].get("would_release"), "dry-run 未预告将释放（静默）"


def test_dry_run_reports_pending_but_writes_nothing(repo_wt):
    """默认 dry-run：报出待归档内容，且**零写操作**（worktree 仍在、无归档目录）。"""
    repo, root, wt = repo_wt
    trash = os.path.join(root, "trash")
    r = wr.reclaim(repo, root, apply=False, trash=trash)
    assert r["dry_run"] is True
    item = next(i for i in r["items"] if os.path.abspath(i["path"]) == os.path.abspath(wt))
    assert item["pending"] >= 1, "dry-run 未报出未回收内容 ⟹ 归档前置形同虚设"
    assert os.path.isdir(wt), "dry-run 竟删了 worktree"
    assert not os.path.isdir(trash), "dry-run 竟写了归档"


def test_apply_archives_before_removing(repo_wt, monkeypatch):
    """核心行为：有未提交内容 ⟹ **先归档、再删**；归档内容与源逐字一致。

    `ECC-2B04C5B10464`：全量 `--apply`（无 `--path`）现须**显式授权**
    （`GK_RECLAIM_ALLOW_FULL=1`，CLI 侧 `--all`）⟹ 本臂显式置位。
    """
    monkeypatch.setenv("GK_RECLAIM_ALLOW_FULL", "1")
    repo, root, wt = repo_wt
    trash = os.path.join(root, "trash")
    r = wr.reclaim(repo, root, apply=True, trash=trash)
    assert r["ok"] is True and r["archived"], "未产生归档"
    hits = [os.path.join(d, f)
            for d, _s, fs in os.walk(trash) for f in fs if f == "new_file.txt"]
    assert hits, "未提交文件未被归档 ⟹ 违反「归档前置」"
    assert open(hits[0], encoding="utf-8").read() == "未回收内容"
    assert not os.path.isdir(wt), "归档成功后 wt 应被回收"


def test_dead_registration_falls_back_to_diff(tmp_path):
    """判别力臂：git 注册失效时**不得**信 `status` 的空输出（假 0）—— 必须走 diff 兜底。

    现场：`standing/mimo-v26-output-probe` 的 `.git` 指向已删 gitdir ⟹ `git status` 静默返回空
    ⟹ 手工扫描一度判「干净」（假 0），实际有 2 项未回收工作（含 `m1_ladder.jsonl` 新文件）。
    """
    repo = tmp_path / "main"
    repo.mkdir()
    _git(str(repo), "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("x", encoding="utf-8")
    _git(str(repo), "add", "a.txt")
    _git(str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")
    wt = tmp_path / "orphan"
    wt.mkdir()
    (wt / ".git").write_text("gitdir: /nonexistent/gone\n", encoding="utf-8")
    (wt / "orphan_new.txt").write_text("孤儿内容", encoding="utf-8")
    st = wr.worktree_state(str(wt), str(repo))
    assert st.get("fallback") == "diff", "失效注册未走 diff 兜底 ⟹ 会假 0 漏掉未回收内容"
    assert any("orphan_new.txt" in e for e in st["entries"]), f"兜底未报出孤儿内容：{st}"


# ══════════ `/tmp` 回收（**共享区纪律**，2026-09-24 用户裁定「3 是不是更好」）══════════
def _mk_tmpdir(root, name, content="x", age_days=0.0):
    """造一个可控龄期的 `/tmp` 风格条目（目录 + 内含一个文件）。"""
    import time as _t
    p = root / name
    p.mkdir()
    (p / "f.txt").write_text(content, encoding="utf-8")
    if age_days:
        old = _t.time() - age_days * 86400
        os.utime(p, (old, old))
        os.utime(p / "f.txt", (old, old))
    return p


def test_tmp_scan_requires_both_own_prefix_and_age(tmp_path):
    """**判别力臂**：`/tmp` 是**全局共享**区 ⟹ 判据必须**双条件**。

    三个条目分别击穿三种错误实现：
      `gk-tamper-old`  —— 本仓前缀 **且** 超龄 ⟹ **应报**（正例）；
      `other-tool-old` —— 超龄但**非本仓可归因** ⟹ 不报（只按龄期 ⟹ 误删别人的）；
      `gk-tamper-new`  —— 本仓前缀但**新** ⟹ 不报（只按前缀 ⟹ 误删并发测试的活目录）。
    """
    _mk_tmpdir(tmp_path, "gk-tamper-old", age_days=30)
    _mk_tmpdir(tmp_path, "other-tool-old", age_days=30)
    _mk_tmpdir(tmp_path, "gk-tamper-new", age_days=0)
    got = [i["name"] for i in wr.scan_tmp(str(tmp_path), days=7)]
    assert got == ["gk-tamper-old"], f"双条件判据失效（共享区会被误删）：{got}"


def test_tmp_never_whitelist_wins(tmp_path):
    """在用白名单**最高优先**：即便同时命中「本仓前缀 + 超龄」也绝不进报告。"""
    _mk_tmpdir(tmp_path, "gk-redfirst-cache", age_days=99)
    _mk_tmpdir(tmp_path, "gk-tamper-old", age_days=30)
    got = [i["name"] for i in wr.scan_tmp(str(tmp_path), days=7)]
    assert "gk-redfirst-cache" not in got, "在用白名单被击穿 ⟹ 会删正在用的红先缓存"
    assert got == ["gk-tamper-old"]


def test_tmp_dry_run_writes_nothing(tmp_path):
    p = _mk_tmpdir(tmp_path, "gk-tamper-old", age_days=30)
    r = wr.reclaim_tmp(tmp_dir=str(tmp_path), days=7, apply=False)
    assert r["dry_run"] is True and r["total"] == 1 and r["freed_bytes"] > 0
    assert p.is_dir(), "dry-run 竟删了目录"


def test_tmp_apply_archives_before_remove(tmp_path):
    """核心行为：**先归档、再删**；归档内容与源逐字一致。"""
    p = _mk_tmpdir(tmp_path, "gk-tamper-old", content="待归档", age_days=30)
    trash = str(tmp_path / "trash")
    r = wr.reclaim_tmp(tmp_dir=str(tmp_path), days=7, apply=True, trash=trash)
    assert r["ok"] is True and r["archived"], "未产生归档"
    hits = [os.path.join(d, f) for d, _s, fs in os.walk(trash) for f in fs if f == "f.txt"]
    assert hits, "未提交内容未被归档 ⟹ 违反「归档前置」"
    assert open(hits[0], encoding="utf-8").read() == "待归档"
    assert not p.exists(), "归档成功后应被回收"


def test_tmp_archive_dest_is_outside_tmpdir(tmp_path, monkeypatch):
    """**硬臂（`--apply` 实测缺陷回归，dry-run 查不出的那类）**：归档落点**不得**在 tmp_dir 内。

    现场（2026-09-24 首跑）：默认落点 `tmp_dir/.gk-tmp-trash` ⟹「copy 到 trash + 删源」后
    `/tmp` 总占用**纹丝不动**（实测 1334MB → 1334MB）⟹ 用户要的「腾空间」完全没达成，
    白多一层目录。此臂锁死「默认落点必须在 tmp_dir 之外」。
    """
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(wr.os.path, "expanduser",
                        lambda p: str(fake_home) if p == "~" else p)
    work = tmp_path / "tmpdir"
    work.mkdir()
    _mk_tmpdir(work, "gk-tamper-x", age_days=30)
    r = wr.reclaim_tmp(tmp_dir=str(work), days=7, apply=True)   # 不传 trash ⟹ 走默认落点
    assert r["archived"], "未归档"
    for a in r["archived"]:
        assert not os.path.abspath(a).startswith(os.path.abspath(str(work)) + os.sep), \
            f"归档落点在 tmp_dir 内 ⟹ 腾不出空间：{a}"


def test_tmp_cli_wires_flag():
    """形态臂：CLI 必须注册 `--tmp`（**两个** case 位）+ `--tmp-days` + 子模式调用。"""
    cli = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "gatekeeper-cli.sh")
    src = open(cli, encoding="utf-8").read()
    seg = src[src.index("cmd_apply_worktree() {"):]
    assert seg.count("--tmp)") >= 2, "`--tmp` 未在两个 case 位均注册"
    assert "--tmp-days)" in seg, "`--tmp-days` 未注册"
    assert "tmp --days" in seg, "未把 `/tmp` 子模式接进脚本调用"


# ══════════ 归因判据改形态（finding `ECC-070771766647`）══════════
def test_tmp_ownership_rule_covers_gk_prefix_names(tmp_path):
    """**判别力臂**：本仓产物一律 `gk` 起头（`gk-` / `gk_`）⟹ 判据必须**按命名约定**收，
    而不是手列清单 —— 初版 11 项手列清单漏了**本仓自己的** `gk_worker_*`
    （CLI `mktemp /tmp/gk_worker_XXXXXX.pid`）、`gk_commit_*`、`gk_subagent_dbg.log`，
    手列清单于是成了「覆盖面的天花板」，`--reclaim --tmp` 永远扫不到这些残留。
    """
    _mk_tmpdir(tmp_path, "gk_worker_abc123.pid", age_days=30)
    _mk_tmpdir(tmp_path, "gk_commit_999.txt", age_days=30)
    _mk_tmpdir(tmp_path, "gk_subagent_dbg.log", age_days=30)
    got = {i["name"] for i in wr.scan_tmp(str(tmp_path), days=7)}
    assert got == {"gk_worker_abc123.pid", "gk_commit_999.txt", "gk_subagent_dbg.log"}, \
        f"命名约定判据未生效（本仓残留扫不到）：{sorted(got)}"


def test_tmp_unattributable_names_are_deliberately_excluded(tmp_path):
    """**决策锁定臂**（HEAD 上即绿 —— 锁的是**刻意不拦**的决定，不是新行为）。

    共享区里**不可归因**的名字一律不收，宁可漏也不误删别人的东西：
      · `ci_logs` 虽是本仓 `ci-diagnose fetch` 的落点，但名字**太泛**（任何 CI 工具都可能用）；
      · `wt` / `x` / `a.txt` 只是文档与测试夹具里的**举例**路径，并非真实产物。
    """
    for n in ("ci_logs", "wt", "x", "a.txt"):
        _mk_tmpdir(tmp_path, n, age_days=99)
    got = [i["name"] for i in wr.scan_tmp(str(tmp_path), days=7)]
    assert got == [], f"不可归因的名字被收进清理面（会误删别人的东西）：{got}"


# ══════════ 隔离区回收（**单向门的另一半**，finding `ECC-AAB70D5DCF11`）══════════
def _mk_trash_entry(root, name, content="x", age_days=0.0, restore_map=None):
    """造一个可控龄期的隔离区条目（可选 `RESTORE-MAP.tsv`）。"""
    import time as _t
    p = root / name
    p.mkdir()
    (p / "f.txt").write_text(content, encoding="utf-8")
    if restore_map is not None:
        (p / "RESTORE-MAP.tsv").write_text(restore_map, encoding="utf-8")
    if age_days:
        old = _t.time() - age_days * 86400
        os.utime(p, (old, old))
        os.utime(p / "f.txt", (old, old))
    return p


def test_trash_purge_requires_age(tmp_path):
    """判别力臂：回收区回收**受龄期门**约束 —— 未超龄的条目可能是**并发会话**正在写的。"""
    _mk_trash_entry(tmp_path, "old-entry", age_days=30)
    _mk_trash_entry(tmp_path, "fresh-entry", age_days=0)
    got = [i["name"] for i in wr.scan_trash(str(tmp_path), days=7)]
    assert got == ["old-entry"], f"龄期门失效（会删并发会话正在写的条目）：{got}"


def test_trash_dry_run_purges_nothing(tmp_path):
    p = _mk_trash_entry(tmp_path, "old-entry", age_days=30)
    r = wr.reclaim_trash(str(tmp_path), days=7, apply=False)
    assert r["dry_run"] is True and r["total"] == 1 and r["freed_bytes"] > 0
    assert p.is_dir(), "dry-run 竟删了隔离区条目"


def test_trash_apply_purges(tmp_path):
    """核心行为：`--apply` 才真删 —— 补上「删除永远无法完成」缺的那一半。"""
    p = _mk_trash_entry(tmp_path, "old-entry", content="待清", age_days=30)
    r = wr.reclaim_trash(str(tmp_path), days=7, apply=True)
    assert r["ok"] is True and r["purged"], "未删任何条目 ⟹ 隔离区仍只增不减"
    assert not p.exists(), "apply 后条目仍在"


def test_trash_holds_entry_with_incomplete_restore_map(tmp_path):
    """**硬臂**：`RESTORE-MAP.tsv` 左列的名字在目录内**必须存在**；缺项 = 搬移半途停了
    ⟹ **拒删**（fail-loud）—— 否则「可逆」这个承诺是假的。

    同时锁住**粒度**：同目录里另一个自洽条目该照删（一处失据不该让整批放过）。
    """
    bad = _mk_trash_entry(tmp_path, "half-moved", age_days=30,
                          restore_map="f.txt\t/tmp/f.txt\ngone.txt\t/tmp/gone.txt\n")
    good = _mk_trash_entry(tmp_path, "ok-entry", age_days=30)
    r = wr.reclaim_trash(str(tmp_path), days=7, apply=True)
    assert r["ok"] is False, "半搬态未 fail-loud"
    held = [os.path.abspath(x) for x in r["held"]]
    assert os.path.abspath(str(bad)) in held, "半搬态未进 held"
    assert bad.is_dir(), "半搬态被删了 ⟹ 丢数据"
    assert not good.exists(), "自洽条目应照删（一处失据不该整批放过）"


def test_trash_anchor_is_single_source(tmp_path):
    """**硬臂（finding `ECC-82CC385C121E`）**：回收区落点只有**一个**公式 ——
    **技能仓的祖父目录** + `/.gk-trash`。

    现场：hook 取 `SKILL_DIR.parent.parent`（= `.trae/.gk-trash`），而 reclaim 取
    `dirname(main_repo)` ⟹ CLI 接线算成 `.trae/skills/.gk-trash`（实测**不存在**）、
    从 worktree 内调用又算成 `…/feature/.gk-trash` ⟹ 同一回收区**多处落点**。
    本臂同时锁「脚本侧落点」与「单源函数」，两者**不一致即双源复发**。
    """
    skill = tmp_path / "skills" / "spz-gatekeeper-r-sequence"
    skill.mkdir(parents=True)
    want = os.path.join(str(tmp_path), ".gk-trash")          # 祖父目录 = tmp_path
    assert wr._trash_dir(str(skill)) == want, "reclaim 侧落点不是「技能仓祖父」⟹ 与 hook 双源"
    import gk_route_center as rc
    assert rc.trash_dir(str(skill)) == want, "单源函数与 reclaim 侧不一致 ⟹ 仍是双源"


def test_trash_anchor_is_invariant_across_worktrees(repo_wt):
    """**硬臂**：从 **worktree 内**调用与从**主树**调用，回收区落点必须**逐字相同**。

    现场（finding `ECC-82CC385C121E`）：CLI 在 worktree 内跑时会算出
    `.trae/worktrees/spz-gatekeeper-r-sequence/.gk-trash` —— 又一个「第二落点」，
    而且**灰而不显**：那里通常是空的 ⟹ 报告 `total: 0` 会被**误读成「已经干净」**。
    归一手法 = `_main_worktree`（git 权威视图，不猜父目录层数），与 `_git_workflow_entry` 同。
    """
    repo, _root, wt = repo_wt
    assert wr._trash_dir(wt) == wr._trash_dir(repo), \
        "worktree 内调用算出另一个落点 ⟹ 会「扫到 0 项」而被误读成「已清理」"


def test_trash_cli_wires_flag():
    """形态臂：CLI 必须注册 `--trash`（**两个** case 位）+ `--trash-days` + 子模式调用。"""
    cli = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "gatekeeper-cli.sh")
    src = open(cli, encoding="utf-8").read()
    seg = src[src.index("cmd_apply_worktree() {"):]
    assert seg.count("--trash)") >= 2, "`--trash` 未在两个 case 位均注册"
    assert "--trash-days)" in seg, "`--trash-days` 未注册"
    assert "trash --repo" in seg, "未把隔离区子模式接进脚本调用"


# ══════════ 目录层残留（RC6，findings `ECC-D03CE3E6CBC9` / `ECC-35AC08DA96F0`）══════════
# **红先对照（HEAD 源码）**：`git show HEAD:scripts/gk_worktree_reclaim.py | grep -c 'scan_residue'`
#   → **0**（候选集只能来自 `git worktree list`）⟹ 下列两条行为臂在 HEAD 上必红
#   （`residue` 键缺失；实测 `--reclaim` dry-run 报 `total:1, items:[]` 而残留仍在）。
def _mk_plain_repo(p):
    """建一个只有一次提交的真 git 仓（无 worktree）——RC6 臂只需「主树 + root」。"""
    p.mkdir()
    _git(str(p), "init", "-q", "-b", "main")
    (p / "a.txt").write_text("x", encoding="utf-8")
    _git(str(p), "add", "a.txt")
    _git(str(p), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")
    return str(p)


def test_rc6_shell_dir_residue_reported_and_reclaimed(tmp_path, monkeypatch):
    """RC6 行为臂（**空壳目录**，finding `ECC-D03CE3E6CBC9`）：`root` 下的未登记空壳目录
    （`git worktree list` 看不到、无 `.git`、递归无任何文件）必须被 `reclaim` **报出**。

    现场（2026-09-26 实测）：`--reclaim` dry-run 报 `total:1, items:[]`（只认主树），而 worktree
    根下仍有空壳目录（`agent/<family>`）——用户手工清过 7 个但**无人守**，会再生。
    `--apply` 才清（dry-run 零写操作）。
    """
    repo = _mk_plain_repo(tmp_path / "main")
    root = tmp_path / "wts"
    own = root / "main"                             # 自有子树 = <root>/<repo 名>（与 CLI 布局同）
    shell = own / "agent" / "F-x"
    shell.mkdir(parents=True)                       # 空壳（只装空目录）
    dry = wr.reclaim(repo, str(root), apply=False)
    paths = {os.path.abspath(i["path"]) for i in dry.get("residue", [])}
    assert os.path.abspath(str(own / "agent")) in paths, \
        f"未报出目录层空壳残留 ⟹ dry-run 会漏（git worktree list 看不到这一层）: {sorted(paths)}"
    assert dry["dry_run"] is True and shell.is_dir(), "dry-run 竟删了空壳目录"
    monkeypatch.setenv("GK_RECLAIM_ALLOW_FULL", "1")   # ECC-2B04C5B10464：全量 --apply 须显式授权
    wr.reclaim(repo, str(root), apply=True)
    assert not (own / "agent").exists(), "apply 未回收空壳目录"


def test_rc6_orphan_state_residue_reported_and_archived(tmp_path, monkeypatch):
    """RC6 行为臂（**孤儿 state**，finding `ECC-35AC08DA96F0`）：`root/dryrun/crossfull-*.state`
    (+`.lock`)（`audit --crossfull --isolate` 的独立 state）不在任何 worktree 面 ⟹ 必须被报出；
    `--apply` **先归档（内容逐字一致）再删**。

    实测残留：`dryrun/` 4 组 `.state`+`.lock`（2026-09-13×3 + 09-25×1），从未被任何回收面覆盖。
    """
    repo = _mk_plain_repo(tmp_path / "main")
    root = tmp_path / "wts"
    dr = root / "main" / "dryrun"                   # 自有子树 <root>/<repo 名>/dryrun
    dr.mkdir(parents=True)
    sf = dr / "crossfull-20260913-111748.state"
    sf.write_text('{"ok":true}', encoding="utf-8")
    (dr / "crossfull-20260913-111748.state.lock").write_text("", encoding="utf-8")
    trash = tmp_path / "trash"
    dry = wr.reclaim(repo, str(root), apply=False, trash=str(trash))
    got = {os.path.abspath(i["path"]) for i in dry.get("residue", [])}
    assert os.path.abspath(str(sf)) in got, \
        f"未报出孤儿 state ⟹ 该残留永远不被回收: {sorted(got)}"
    assert not trash.exists(), "dry-run 竟写了归档"
    monkeypatch.setenv("GK_RECLAIM_ALLOW_FULL", "1")   # ECC-2B04C5B10464：全量 --apply 须显式授权
    wr.reclaim(repo, str(root), apply=True, trash=str(trash))
    assert not sf.exists(), "apply 未回收孤儿 state"
    hits = [os.path.join(d, f) for d, _s, fs in os.walk(str(trash)) for f in fs
            if f == "crossfull-20260913-111748.state"]
    assert hits and open(hits[0], encoding="utf-8").read() == '{"ok":true}', \
        "孤儿 state 未**先归档** ⟹ 丢数据（违反「归档前置」）"


def test_rc6_residue_scan_never_touches_sibling_repo(repo_wt):
    """RC6 **负臂**（非红回归臂，**不入选**红先集）：`root` 是**跨仓库共享** parent
    （`GATEKEEPER_WORKTREE_ROOT`）⟹ 绝不越界到他仓目录；但**收窄不得过度**（自有子树内该收还得收）。

    现场（2026-09-26 实测）：首版未收窄 ⟹ `spz2glb` / `spz_gatekeeper_project` /
    `spz-gatekeeper-agent-worktree-consolidation` 三者**齐被误报** `empty_dir`，`--apply` 会越权删他仓。
    """
    repo, root, wt = repo_wt
    own = os.path.join(root, "main")                        # 自有子树 = <root>/<repo 名>（repo_wt 仓名=main）
    os.makedirs(os.path.join(own, "agent"), exist_ok=True)  # 自有子树内的空壳（应被收）
    other = os.path.join(root, "other-project")
    os.makedirs(other, exist_ok=True)                        # 他仓（空）⟹ 绝不能被当本仓残留
    r = wr.reclaim(repo, root, apply=False)
    res = {os.path.abspath(i["path"]) for i in r["residue"]}
    assert os.path.abspath(other) not in res, \
        "越界到他仓目录 ⟹ `--apply` 会删别的仓库（共享 parent 纪律）"
    assert os.path.abspath(os.path.join(own, "agent")) in res, \
        "自有子树内的空壳未收 ⟹ 收窄过度（RC6 又变漏检）"
    for p in (repo, wt):
        assert os.path.abspath(p) not in res, f"已登记树被误当残留：{p}"

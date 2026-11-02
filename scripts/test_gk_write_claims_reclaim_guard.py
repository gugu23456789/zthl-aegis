#!/usr/bin/env python3
"""R-CONC-GIT §16 一期红先臂：路径归一 + live 抗 anomaly 遮蔽 + 回收前置闸。

finding: ECC-71EBE521D5A5（claims 僵尸 live）/ ECC-B4E1D1A84999（worktree 无 claim 盲区）。
落刀点: scripts/gk_write_claims.py（P1 路径归一 / P3 live 抗遮蔽 / claims_for_worktree）
        + scripts/gk_worktree_reclaim.py（D-a 回收前置闸 / D-b① 回收后 release）。

红先（实现前本文件须见红）：臂①②③ 逻辑红；臂④ 结构性红（源码无 guard 接线）。
"""
import json
import os
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import gk_write_claims as C  # noqa: E402

SID_A = "aaaa1111aaaa1111aaaa1111"


def _repo(tmp_path):
    rp = tmp_path / "repo"
    rp.mkdir()
    return rp


# ── 臂① 路径两形态必命中：claim 绝对 worktree 目录 vs changed 仓库相对 ⟹ ok 面零 anomaly ──
def test_arm1_registered_in_scope_zero_anomaly(tmp_path):
    rp = _repo(tmp_path)
    wt = rp / "wt-dir"
    wt.mkdir()
    C.append(str(rp), sid=SID_A, worktree=str(wt), source="dispatch", paths=[str(wt)])
    r = C.reconcile(str(rp), changed_paths=["scripts/foo.py"], sid=SID_A)
    assert r.get("anomalies") == [], (
        "已登记 + 范围内提交仍报 anomaly（路径未归一）: %r" % (r.get("anomalies"),))


# ── 臂② anomaly 行不得洗掉同 sid 的 live（保护方向反转）──
def test_arm2_anomaly_row_does_not_mask_live(tmp_path):
    rp = _repo(tmp_path)
    C.append(str(rp), sid=SID_A, worktree="/x/wt", source="dispatch", paths=["/x/wt"])
    C.reconcile(str(rp), changed_paths=["oops.py"], sid=SID_A)   # 落一条 anomaly（同 sid）
    got = [c.get("sid") for c in C.live(str(rp))]
    assert SID_A in got, "anomaly 行把同 sid 的 live 洗掉了（保护方向反转）: %r" % (got,)


# ── 臂③ claims_for_worktree：按 worktree 判活（两形态命中 / 未声明回空）──
def test_arm3_claims_for_worktree_both_forms(tmp_path):
    rp = _repo(tmp_path)
    wt = rp / "wt-dir"
    wt.mkdir()
    C.append(str(rp), sid=SID_A, worktree=str(wt), source="dispatch", paths=[str(wt)])
    assert [c.get("sid") for c in C.claims_for_worktree(str(rp), str(wt))] == [SID_A], \
        "声明该 worktree 时未命中"
    assert C.claims_for_worktree(str(rp), str(rp / "other")) == [], "未声明却命中"


# ── 臂③b（红先·ECC-2B04C5B10464）`unreleased_claims_for_worktree`：**过期 ≠ 可删** ──
def test_arm3b_unreleased_claims_includes_expired(tmp_path):
    rp = _repo(tmp_path)
    wt = rp / "wt-dir"
    wt.mkdir()
    old = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 10000))
    C.append(str(rp), sid=SID_A, worktree=str(wt), source="dispatch", paths=[str(wt)],
             ttl_s=3600, ts=old)
    assert C.claims_for_worktree(str(rp), str(wt)) == [], "前置：live 面应已过期（回空）"
    assert [c.get("sid") for c in C.unreleased_claims_for_worktree(str(rp), str(wt))] == [SID_A], \
        "过期未 release 的 claim 未计入（「过期 ≠ 可删」未落 ⟹ 回收闸仍 fail-open）"
    C.release(str(rp), sid=SID_A, worktree=str(wt))
    assert C.unreleased_claims_for_worktree(str(rp), str(wt)) == [], \
        "release 后仍报未 release（闭环不成立）"


# ── 臂④ 结构性：回收链已接 guard + 回收后 release（D-a / D-b①）──
def test_arm4_reclaim_wired_to_claims(tmp_path):
    src = (SCRIPT_DIR / "gk_worktree_reclaim.py").read_text(encoding="utf-8")
    assert "unreleased_claims_for_worktree" in src, (
        "回收链未接 claims 判据（D-a 缺）—— ECC-2B04C5B10464 起判据改**含过期**的 "
        "unreleased_claims_for_worktree（live-only 会被 TTL 架空 ⟹ fail-open）")
    assert "GK_RECLAIM_CLAIM_GUARD" in src, "回收链无 GK_RECLAIM_CLAIM_GUARD 开关"
    assert "release" in src, "回收后未 release（D-b① 缺）"


# ── 臂⑤ P2 账本单源：`_default_repo` 走 `git worktree list` 首项（非脚本所在树）──
def test_arm5_default_repo_single_source_via_git(tmp_path, monkeypatch):
    fake_main = str(tmp_path / "MAIN")
    fake_scripts = tmp_path / "wt" / "scripts"
    fake_scripts.mkdir(parents=True)
    monkeypatch.setattr(C, "_SCRIPT_DIR", fake_scripts)
    monkeypatch.setattr(C, "_DEFAULT_REPO_CACHE", [])

    class _R:
        stdout = "worktree %s\nHEAD deadbeef\n" % fake_main

    monkeypatch.setattr(C.subprocess, "run", lambda *a, **k: _R())
    assert C._default_repo() == fake_main, "未走 `git worktree list` 首项单源（P2 未落）"


# ── 臂⑥ P4 续期：`renewed` 刷新 ts ⟹ 过期后重新 live ──
def test_arm6_renew_refreshes_ttl(tmp_path):
    rp = _repo(tmp_path)
    wt = rp / "wt"
    wt.mkdir()
    old = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 10000))
    C.append(str(rp), sid=SID_A, worktree=str(wt), source="dispatch", paths=[str(wt)],
             ttl_s=3600, ts=old)
    assert [c.get("sid") for c in C.live(str(rp))] == [], "旧 ts 应已过期（前置不成立）"
    C.renew(str(rp), sid=SID_A, worktree=str(wt))
    assert SID_A in [c.get("sid") for c in C.live(str(rp))], "renew 未刷新 ts（P4 未落）"


# ── 臂⑦ D-c① 僵尸：live claim 的目录已不存在 ──
def test_arm7_zombie_live_claim_whose_dir_gone(tmp_path):
    rp = _repo(tmp_path)
    C.append(str(rp), sid=SID_A, worktree=str(rp / "gone"), source="dispatch",
             paths=[str(rp / "gone")])
    r = C.reconcile(str(rp), changed_paths=[], sid=SID_A)
    assert any(a.get("kind") == "zombie" for a in r["anomalies"]), r["anomalies"]


# ── 臂⑧ D-c② 盲区：期望集内未 claim ⟹ blind_spot；已 claim 不报 ──
def test_arm8_blind_spot_expected_unclaimed(tmp_path):
    rp = _repo(tmp_path)
    claimed = rp / "wt-a"
    claimed.mkdir()
    C.append(str(rp), sid=SID_A, worktree=str(claimed), source="dispatch", paths=[str(claimed)])
    unclaimed = rp / "wt-b"
    unclaimed.mkdir()
    r = C.reconcile(str(rp), changed_paths=[], sid=SID_A,
                    expected_worktrees=[str(claimed), str(unclaimed)])
    bs = [a for a in r["anomalies"] if a.get("kind") == "blind_spot"]
    assert bs, "期望集内未 claim 未报盲区"
    assert all("wt-b" in a.get("worktree", "") for a in bs), ("已 claim 不应报盲区", bs)


# ── 臂⑨ D-c② 开关：`GK_CLAIM_ANOMALY=0` ⟹ 返回仍报、台账不落 anomaly 行 ──
def test_arm9_anomaly_switch_suppresses_ledger(tmp_path, monkeypatch):
    rp = _repo(tmp_path)
    C.append(str(rp), sid=SID_A, worktree=str(rp / "gone"), source="dispatch",
             paths=[str(rp / "gone")])
    monkeypatch.setenv("GK_CLAIM_ANOMALY", "0")
    r = C.reconcile(str(rp), changed_paths=[], sid=SID_A)
    assert any(a.get("kind") == "zombie" for a in r["anomalies"]), "返回仍应如实报"
    assert not any(x.get("state") == "anomaly" for x in C.read_all(str(rp))), \
        "开关=0 时不得落 anomaly 行"


# ── 臂⑩ D-c② 去重/上限：同类误报封顶 ──
def test_arm10_anomaly_dedup_cap(tmp_path):
    rp = _repo(tmp_path)
    exp = []
    for i in range(50):
        d = rp / ("w%03d" % i)
        d.mkdir()
        exp.append(str(d))
    C.append(str(rp), sid=SID_A, worktree=str(rp / "w000"), source="dispatch",
             paths=[str(rp / "w000")])
    r = C.reconcile(str(rp), changed_paths=[], sid=SID_A, expected_worktrees=exp)
    bs = [a for a in r["anomalies"] if a.get("kind") == "blind_spot"]
    assert len(bs) == C._ANOMALY_CAP, ("应封顶到 _ANOMALY_CAP", len(bs))


# ── 臂⑪ 双宿主归一：`C:\…` 与 `/mnt/c/…` 落同一坐标 ──
def test_arm11_canon_dual_host_forms_equal():
    assert C._canon("<home>\\.trae") == C._canon("<home>/.trae"), \
        "双宿主两形态未归一（P1 判据①未真覆盖）"


# ── 臂⑫ 接线：`renew` 已接 CLI（提交前续期）+ `moa-aggregate` 已透传 `--plan` ──
def test_arm12_cli_wiring_renew_and_moa_plan():
    cli = (SCRIPT_DIR.parent / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    assert "gk_write_claims.py\" renew" in cli, "renew 零调用点（P4 未接线）"
    assert "_gk_claim_renew \"${1:-}\"" in cli, "_gk_claim_reconcile 未调用 renew"
    assert "args+=(--plan " in cli, "moa-aggregate 未透传 --plan（§18 CLI 接线缺）"


# ── 臂⑬（红先·round-4 CRITICAL）renew 不得擦空 worktree/paths ⟹ 否则 D-a 回收闸 fail-open ──
def test_arm13_renew_preserves_worktree_and_paths(tmp_path):
    rp = _repo(tmp_path)
    wt = rp / "wt-dir"
    wt.mkdir()
    C.append(str(rp), sid=SID_A, worktree=str(wt), source="dispatch", paths=[str(wt)])
    assert [c.get("sid") for c in C.claims_for_worktree(str(rp), str(wt))] == [SID_A]
    C.renew(str(rp), sid=SID_A, source="reconcile")   # 生产路径：只传 sid/source（不带 worktree/paths）
    guard = [c.get("sid") for c in C.claims_for_worktree(str(rp), str(wt))]
    assert guard == [SID_A], (
        "renew 擦空 worktree/paths ⟹ claims_for_worktree 回空 ⟹ D-a 回收前置闸 fail-open: %r" % (guard,))
    r = C.reconcile(str(rp), changed_paths=["scripts/foo.py"], sid=SID_A)
    assert r.get("anomalies") == [], ("renew 后对账恒落 anomaly（declared 被擦空）", r.get("anomalies"))


# ── 臂⑭（红先）renew 只续**已登记**会话：无 live/renewed 前驱 ⟹ no-op（禁凭空造 claim）──
def test_arm14_renew_noop_without_prior_claim(tmp_path):
    rp = _repo(tmp_path)
    out = C.renew(str(rp), sid=SID_A, source="reconcile")
    assert out.get("noop") is True, "未登记会话 renew 应 no-op（否则凭空造 claim 顶掉 unregistered_writer）"
    assert C.read_all(str(rp)) == [], "no-op 不得追加行"
    assert [c.get("sid") for c in C.live(str(rp))] == [], "no-op 不得造出 live"


def _win_form(posix: str) -> str:
    """`/mnt/<d>/...` ⟹ `<D>:\\...`（造跨宿主形态用；非 `/mnt/` 则原样返回）。"""
    if posix.startswith("/mnt/") and len(posix) > 6 and posix[5] != "/":
        return posix[5].upper() + ":" + posix[6:].replace("/", "\\")
    return posix


# ── 臂⑮（红先·round-4）D-c① 僵尸须过 `_host_norm`：跨宿主**存在**的 worktree 不得误报 ──
def test_arm15_zombie_cross_host_existing_not_reported(tmp_path):
    rp = _repo(tmp_path)
    win = _win_form(str(SCRIPT_DIR.parent))   # 技能根（Windows 盘符形态），该目录确实存在
    assert win.startswith("C:") or win.startswith("/"), ("前置：未造出盘符形态", win)
    C.append(str(rp), sid=SID_A, worktree=win, source="dispatch", paths=[win])
    r = C.reconcile(str(rp), changed_paths=[], sid=SID_A)
    z = [a for a in r["anomalies"] if a.get("kind") == "zombie"]
    assert z == [], ("跨宿主存在的 worktree 被误报 zombie（僵尸判据未过 _host_norm）", z)


# ── 臂⑮b（守卫）跨宿主**缺失**的 worktree 仍须报 zombie（防修法过度抑制）──
def test_arm15b_zombie_cross_host_missing_still_reported(tmp_path):
    rp = _repo(tmp_path)
    win = _win_form(str(SCRIPT_DIR.parent)) + "\\__no_such_dir_zzz__"
    C.append(str(rp), sid=SID_A, worktree=win, source="dispatch", paths=[win])
    r = C.reconcile(str(rp), changed_paths=[], sid=SID_A)
    assert any(a.get("kind") == "zombie" for a in r["anomalies"]), \
        "缺失的跨宿主目录应仍报 zombie（不得过度抑制）"


# ── 臂⑯（红先·round-4 D-c②）期望集派生：`worktrees_extra ∪ git list` − 主树 ──
def test_arm16_expected_worktrees_derives_and_excludes_main(tmp_path, monkeypatch):
    rp = _repo(tmp_path)
    st = tmp_path / "state.json"
    extra = rp / "wt-extra"
    extra.mkdir()
    listed = rp / "wt-listed"
    listed.mkdir()
    st.write_text(json.dumps({"worktrees_extra": [str(extra), str(rp)]}), encoding="utf-8")
    monkeypatch.setattr(C, "_git_worktree_paths", lambda repo=None: [str(rp), str(listed)])
    got = C.expected_worktrees(str(rp), str(st))
    names = sorted(os.path.basename(p) for p in got)
    assert "wt-extra" in names and "wt-listed" in names, ("期望集须含 extra ∪ list", got)
    assert C._canon(str(rp), str(rp)) not in [C._canon(p, str(rp)) for p in got], \
        ("主树不得入期望集", got)


# ── 臂⑰（红先·round-4 D-c②）盲区行为：未 claim 者报、主树不报 ──
def test_arm17_blind_spot_reports_unclaimed_not_main(tmp_path, monkeypatch):
    rp = _repo(tmp_path)
    st = tmp_path / "state.json"
    unclaimed = rp / "wt-x"
    unclaimed.mkdir()
    st.write_text(json.dumps({"worktrees_extra": [str(unclaimed)]}), encoding="utf-8")
    monkeypatch.setattr(C, "_git_worktree_paths", lambda repo=None: [str(rp)])
    exp = C.expected_worktrees(str(rp), str(st))
    r = C.reconcile(str(rp), changed_paths=[], sid="", expected_worktrees=exp)
    bs = [a for a in r["anomalies"] if a.get("kind") == "blind_spot"]
    assert any("wt-x" in a.get("worktree", "") for a in bs), ("未 claim 者须报盲区", r["anomalies"])
    assert not any(C._canon(a.get("worktree", ""), str(rp)) == C._canon(str(rp), str(rp)) for a in bs), \
        ("主树不得报盲区", bs)


# ── 臂⑱（红先·round-4 D-c②）生产接线：`_gk_claim_reconcile` 传期望集派生 ──
def test_arm18_reconcile_cli_wired_expected_auto():
    cli = (SCRIPT_DIR.parent / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    assert "--expected-auto" in cli, "reconcile 生产调用点未接期望集派生（D-c② 生产不可达）"
    py = (SCRIPT_DIR / "gk_write_claims.py").read_text(encoding="utf-8")
    assert "def expected_worktrees(" in py, "缺期望集派生单源 expected_worktrees"
    assert "--expected-auto" in py, "reconcile 子命令未接 --expected-auto"


# ── 臂⑲（红先·#2 键同源）登记键≠对账键，但同 worktree ⟹ 命中（不报 unregistered_writer）──
def test_arm19_reconcile_keyed_by_worktree_not_sid(tmp_path):
    rp = _repo(tmp_path)
    wt = rp / "wt-dir"
    wt.mkdir()
    C.append(str(rp), sid=SID_A, worktree=str(wt), source="session", paths=[str(wt)])
    # 提交时身份 = 另一会话（GK_SESSION_ID 形态），与登记 sid **不同**
    r = C.reconcile(str(rp), changed_paths=["scripts/foo.py"],
                    sid="bbbb2222bbbb2222bbbb2222", worktree=str(wt))
    assert r.get("anomalies") == [], (
        "登记键≠对账键但同 worktree 仍报 anomaly（未按 worktree 同源）: %r"
        % (r.get("anomalies"),))


# ── 臂⑳（红先·#2）out_of_scope 生产可达：同 worktree 命中后越界路径须报 ──
def test_arm20_out_of_scope_reachable(tmp_path):
    rp = _repo(tmp_path)
    wt = rp / "wt-dir"
    (wt / "scripts").mkdir(parents=True)
    C.append(str(rp), sid=SID_A, worktree=str(wt), source="session",
             paths=[str(wt / "scripts")])
    r = C.reconcile(str(rp), changed_paths=["docs/other.md"],
                    sid="bbbb2222bbbb2222bbbb2222", worktree=str(wt))
    kinds = [a.get("kind") for a in r.get("anomalies", [])]
    assert "out_of_scope" in kinds, "越界路径未报 out_of_scope（生产不可达）: %r" % (r,)


# ── 臂㉑（守卫）该 worktree 真无 claim ⟹ 仍须报 unregistered_writer（防修法过度抑制）──
def test_arm21_unregistered_writer_when_no_claim_for_worktree(tmp_path):
    rp = _repo(tmp_path)
    wt = rp / "wt-dir"
    wt.mkdir()
    r = C.reconcile(str(rp), changed_paths=["scripts/foo.py"], sid=SID_A,
                    worktree=str(wt))
    kinds = [a.get("kind") for a in r.get("anomalies", [])]
    assert "unregistered_writer" in kinds, "真无 claim 却未报 unregistered_writer: %r" % (r,)


# ── 臂㉒（结构性·#2）生产接线：`_gk_claim_reconcile` 传 `--worktree` + 提交点传 $repo ──
def test_arm22_reconcile_cli_wires_worktree():
    cli = (SCRIPT_DIR.parent / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    seg = cli[cli.find("_gk_claim_reconcile() {"):]
    seg = seg[:seg.find("\n}")]
    assert "--worktree" in seg, "reconcile 生产调用点未传 --worktree（键未同源）"
    assert '_gk_claim_reconcile "${GK_SESSION_ID:-}" "${_staged%,}" "$repo"' in cli, \
        "提交点未把 repo 作 worktree 传入（键未同源）"


# ── 臂㉓（红先·#3）跨调用去重：同类 anomaly 多次 reconcile 只落一行 ──
def test_arm23_anomaly_cross_call_dedup(tmp_path):
    rp = _repo(tmp_path)
    for _ in range(3):
        C.reconcile(str(rp), changed_paths=["docs/x.md"], sid=SID_A)
    anoms = [r for r in C.read_all(str(rp)) if r.get("state") == "anomaly"]
    assert len(anoms) == 1, "同类 anomaly 跨调用重复落行: %r" % (anoms,)


# ── 臂㉔（红先·#3）轮转：最旧 anomaly 归档到 .archive.jsonl，非 anomaly 行保留 ──
def test_arm24_rotate_archives_oldest_anomalies(tmp_path):
    rp = _repo(tmp_path)
    C.append(str(rp), sid=SID_A, worktree="/x/live", source="s", paths=["/x/live"])
    for i in range(5):
        C._append_line(str(rp), {"sid": SID_A, "worktree": "", "family": "", "source": "reconcile",
                                 "paths": [], "ts": "2026-01-01T00:00:00Z", "ttl_s": 0,
                                 "state": "anomaly", "anomaly": {"kind": "k%d" % i}})
    out = C.rotate(str(rp), keep_anomaly=2)
    assert out.get("rotated") == 3, out
    rows = C.read_all(str(rp))
    assert sum(1 for r in rows if r.get("state") == "anomaly") == 2, rows
    assert any(r.get("state") == "live" for r in rows), "非 anomaly 行被误删"
    arc = Path(C.claims_path(str(rp)) + ".archive.jsonl")
    assert arc.exists(), "未生成归档"
    arch = [json.loads(l) for l in arc.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(arch) == 3, arch


# ── 臂㉕（红先·#4）心跳：按 worktree 续期 + 节流（新鲜 ⟹ 不再落行）──
def test_arm25_heartbeat_renews_and_throttles(tmp_path):
    rp = _repo(tmp_path)
    wt = rp / "wt-dir"
    wt.mkdir()
    C.append(str(rp), sid=SID_A, worktree=str(wt), source="session", paths=[str(wt)])
    n0 = len(C.read_all(str(rp)))
    C.heartbeat(str(rp), worktree=str(wt), frac=0.0)
    rows = C.read_all(str(rp))
    assert len(rows) == n0 + 1 and rows[-1].get("state") == "renewed", rows[-1]
    assert rows[-1].get("worktree") and rows[-1].get("paths"), "心跳续期擦空 worktree/paths"
    n1 = len(rows)
    C.heartbeat(str(rp), worktree=str(wt), frac=0.5)
    assert len(C.read_all(str(rp))) == n1, "心跳未节流（台账随编辑膨胀）"


# ── 臂㉖（结构性·#4）接线：heartbeat 子命令 + 挂 pre_tool_check 编辑分支 ──
def test_arm26_heartbeat_wired(tmp_path):
    cli = (SCRIPT_DIR.parent / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    assert "_gk_claim_heartbeat() {" in cli, "无 _gk_claim_heartbeat 接线函数"
    assert '_gk_claim_heartbeat "$SKILL_DIR"' in cli, "pre_tool_check 未挂心跳（判活仍只在提交路径）"

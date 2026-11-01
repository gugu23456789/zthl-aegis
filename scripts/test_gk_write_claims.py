#!/usr/bin/env python3
"""设计 D 红先臂：运行时刻 declare —— **区外 append-only write-claims 台账**（`scripts/gk_write_claims.py`）。

来源：`docs/plans/2026-09-28-git-concurrency-lease-declare-plan.md` §3（设计 D）+ §8（反例）+ §9。

**缺口（G1/G3）**：`gate_data.allowed_paths` 是族定义里的**静态清单**（同一批内判 disjoint），
**跨批 / 非派发会话不可见** ⟹「谁正在写哪些路径」无运行时刻实例。

**落点（治质询 F4/F5 三面皆中）**：台账存**区外 append-only** `<repo>/.gatekeeper.write-claims.jsonl`
（与 `.finding-journal.jsonl` / `.session-state-archive.jsonl` 同族命名）。**弃用** `state.gate_data.write_claims[]`：
① `discover` 归档并清空 `gate_data` ⟹ 台账被静默清空后**一切重叠检测读空账 = 假绿**；
② `cmd_apply_worktree` 的 code-fix 路径 `cp` 出 worktree state 副本 ⟹ 单源前提不成立；
③ `state-patch` 走 `gate_data` 顶层键整体 update ⟹ last-writer-wins 丢单。

**本文件钉住的判据**：
  ① **append-only**：`release` 是**追加**同 `sid` 的终态行，**禁原地改写**（旧行逐字不变、行数只增）；
  ② **抗 discover 清空**：台账与 `state` 解耦 ⟹ `gate_data` 被清空后台账**仍在且内容不变**；
  ③ **重叠只 WARN 不阻断**（对齐 Loom「lease warns, never blocks」）：`overlap` 非空而 `blocked` 恒 `False`；
  ④ **TTL 单源**：条目 `ttl_s` == `gk_git_lease.claim_ttl_s()`（治 §9-ASSUMPTION-3 双 TTL 静默失效）；
  ⑤ **写后对账**：未登记写者 / 越出声明路径 ⟹ 落 anomaly（「会话永不登记」**有成本**，治 G1「只换措辞」）；
  ⑥ **best-effort**：登记失败（路径不可写）**不得抛**，返回 `ok:False` + `error` 供调用方留痕。
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
import gk_write_claims as C  # noqa: E402

SID_A = "aaaa1111aaaa1111aaaa1111"
SID_B = "bbbb2222bbbb2222bbbb2222"


def _repo(tmp_path: Path) -> Path:
    rp = (tmp_path / "repo").resolve()
    rp.mkdir(parents=True, exist_ok=True)
    (rp / ".git").mkdir(exist_ok=True)
    return rp


def _lines(rp: Path) -> list:
    p = Path(C.claims_path(str(rp)))
    if not p.exists():
        return []
    return [ln for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]


# ── 臂① append-only：release 是追加、旧行逐字不变 ───────────────────────────
def test_arm1_release_appends_never_rewrites(tmp_path):
    rp = _repo(tmp_path)
    C.append(str(rp), sid=SID_A, source="dispatch", paths=["src"])
    before = _lines(rp)
    assert len(before) == 1, before
    r = C.release(str(rp), sid=SID_A)
    assert r.get("ok") is True, r
    after = _lines(rp)
    assert len(after) == 2, f"release 未**追加**终态行：{after}"
    assert after[0] == before[0], "旧行被**原地改写**（append-only 破）"
    assert json.loads(after[-1]).get("state") == "released", after[-1]


# ── 臂② 抗 discover：台账与 state 解耦 ⟹ gate_data 清空后仍不变 ─────────────
def test_arm2_survives_state_purge(tmp_path):
    rp = _repo(tmp_path)
    st = rp / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {"write_claims": [{"sid": SID_A}]}}),
                  encoding="utf-8", newline="\n")
    C.append(str(rp), sid=SID_A, source="dispatch", paths=["a.sh"])
    snap = _lines(rp)
    # 模拟 `discover` 归档并**清空 gate_data**
    st.write_text(json.dumps({"gate_data": {}}), encoding="utf-8", newline="\n")
    assert _lines(rp) == snap, "`discover` 清空 gate_data 后台账被连带清空（落点错）"
    assert json.loads(snap[0]).get("sid") == SID_A


# ── 臂③ 重叠只 WARN、不阻断 ────────────────────────────────────────────────
def test_arm3_overlap_warns_never_blocks(tmp_path):
    rp = _repo(tmp_path)
    C.append(str(rp), sid=SID_A, source="dispatch", paths=["scripts/gatekeeper-cli.sh"])
    C.append(str(rp), sid=SID_B, source="self", paths=["scripts"])
    r = C.overlap(str(rp), paths=["scripts/gatekeeper-cli.sh"], sid=SID_B)
    assert r.get("blocked") is False, f"重叠被做成 BLOCK（反例：不得再添一道拦人的门）：{r}"
    assert r.get("overlap"), f"重叠未检出（超集/前缀口径）：{r}"
    assert any(o.get("a") == SID_B and o.get("b") == SID_A for o in r["overlap"]), r["overlap"]


# ── 臂④ 终态行生效：live 排除已 released 的 sid，但历史行仍在 ────────────────
def test_arm4_released_sid_excluded_from_live(tmp_path):
    rp = _repo(tmp_path)
    C.append(str(rp), sid=SID_A, source="dispatch", paths=["x"])
    C.append(str(rp), sid=SID_B, source="dispatch", paths=["y"])
    C.release(str(rp), sid=SID_A)
    ids = [c.get("sid") for c in C.live(str(rp))]
    assert SID_A not in ids and SID_B in ids, f"live 未按终态行过滤：{ids}"
    assert len(_lines(rp)) == 3, "release 抹掉了历史行（append-only 破）"


# ── 臂⑤⑥ TTL 单源 + 过期失效 ──────────────────────────────────────────────
def test_arm5_ttl_single_source_and_expiry(tmp_path, monkeypatch):
    rp = _repo(tmp_path)
    monkeypatch.delenv("GK_CLAIM_TTL_S", raising=False)
    C.append(str(rp), sid=SID_A, source="dispatch", paths=["a"])
    rec = json.loads(_lines(rp)[0])
    assert rec.get("ttl_s") == L.claim_ttl_s() == 3600, (
        f"`ttl_s` 与 `gk_git_lease.claim_ttl_s()` **不同源**：{rec.get('ttl_s')}")
    assert [c["sid"] for c in C.live(str(rp))] == [SID_A]
    # 单源对 env 敏感：TTL 降到 1s 后**新写**的条目须记 1
    monkeypatch.setenv("GK_CLAIM_TTL_S", "1")
    C.append(str(rp), sid=SID_B, source="dispatch", paths=["b"])
    assert json.loads(_lines(rp)[-1]).get("ttl_s") == 1, "`ttl_s` 未随单源 TTL 变化"
    # 过期：`ts + ttl_s` 之外 ⟹ 不计入 live（ttl_s 是**条目自持**的判活窗口）
    p = Path(C.claims_path(str(rp)))
    rec["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 30))
    rec["ttl_s"] = 1
    p.write_text(json.dumps(rec, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    assert C.live(str(rp)) == [], "超过 `ts + ttl_s` 的 claim 仍在 live（TTL 未生效）"


# ── 臂⑦ 写后对账：未登记写者 / 越出声明范围 ⟹ anomaly ───────────────────────
def test_arm6_reconcile_flags_unregistered_and_out_of_scope(tmp_path):
    rp = _repo(tmp_path)
    r = C.reconcile(str(rp), changed_paths=["scripts/foo.py"], sid="nosuch")
    assert any(a.get("kind") == "unregistered_writer" for a in r.get("anomalies") or []), (
        f"未登记写者未被对账抓到（G1「只换措辞」）：{r}")
    C.append(str(rp), sid=SID_A, source="self", paths=["scripts/foo.py"])
    r2 = C.reconcile(str(rp), changed_paths=["scripts/foo.py", "scripts/bar.py"], sid=SID_A)
    assert any(a.get("kind") == "out_of_scope" for a in r2.get("anomalies") or []), (
        f"越出声明路径未被抓到：{r2}")


# ── 臂⑧ best-effort：登记失败不抛、回 ok:False ─────────────────────────────
def test_arm7_append_is_best_effort(tmp_path):
    bad = tmp_path / "nope" / "deep"
    r = C.append(str(bad), sid=SID_A, source="dispatch", paths=["a"])
    assert r.get("ok") is False and r.get("error"), f"登记失败未回可留痕的错误：{r}"


# ── 臂⑨ 真 CLI：`cmd_commit` 写后对账 ⟹ 未登记写者落 `anomaly`（**且不阻断提交**）──
def test_arm8_cli_commit_reconcile_records_anomaly(tmp_path):
    """真 CLI 提交面：`GK_SESSION_ID` 未登记 ⟹ 复盘落一条 `state=anomaly` 行，且**提交仍成功**。"""
    from test_gk_commit_guard import _mk_skillroot, _mk_repo, _last_json, _wsl
    sb = _mk_skillroot(tmp_path)
    rp = _mk_repo(tmp_path)
    subprocess.run(["bash", "-lc", 'printf "echo z\\n" > "%s/z.sh"' % _wsl(rp)],
                   capture_output=True, text=True, timeout=60)
    r = subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh commit --repo "%s" --add z.sh -m "wc arm9"'
         % (_wsl(sb), _wsl(rp))],
        capture_output=True, text=True, timeout=300)
    out = r.stdout + r.stderr
    assert _last_json(out).get("ok") is True, f"对账**阻断**了提交（应只 WARN）：{out[:500]}"
    led = Path(sb) / ".gatekeeper.write-claims.jsonl"
    assert led.exists(), f"提交面未写对账台账（落点 = 沙箱技能根）：{out[:300]}"
    recs = [json.loads(x) for x in led.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert any(x.get("state") == "anomaly"
               and (x.get("anomaly") or {}).get("kind") == "unregistered_writer" for x in recs), (
        f"未登记写者未被对账抓到（G1「只换措辞」）：{recs}")


# ── 臂⑦ D-b② 谓词对账（§17-4 A 步①，report-only，**零写**） ─────────────────
_MISS = object()


def _write_state_file(rp: Path, name: str, worktree=_MISS) -> str:
    """写一个状态文件；`worktree` 缺省 = **键缺失**（空值三态之一）。"""
    d = {"gate_data": {"project_type": "standard"}}
    if worktree is not _MISS:
        d["worktree"] = worktree
    p = rp / name
    p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8", newline="\n")
    return str(p)


def test_arm7_db2_gap_when_state_worktree_unclaimed(tmp_path):
    """§17-4 红先：live `state.worktree=X` 且**无** live claim(X) ⟹ 计 gap（谓词 ∃ 破）。"""
    rp = _repo(tmp_path)
    wt = str((tmp_path / "wt-x").resolve())
    sf = _write_state_file(rp, ".gatekeeper.state", wt)
    r = C.state_claim_gaps(str(rp), state_files=[sf])
    assert r.get("ok") is False and r.get("count") == 1, r
    assert r["gaps"][0]["worktree"] == wt and r["gaps"][0]["state_file"] == sf, r


def test_arm7_db2_no_gap_when_claim_live(tmp_path):
    """§17-4：live `state.worktree=X` **且**存在 live claim(X) ⟹ 零 gap。"""
    rp = _repo(tmp_path)
    wt = str((tmp_path / "wt-y").resolve())
    C.append(str(rp), sid=SID_A, source="dispatch", worktree=wt, paths=[wt])
    sf = _write_state_file(rp, ".gatekeeper.state", wt)
    r = C.state_claim_gaps(str(rp), state_files=[sf])
    assert r.get("ok") is True and r.get("count") == 0, r


def test_arm7_db2_empty_tristate_no_constraint(tmp_path):
    """§17-4：空值三态（键缺失 / null / ""）⟹ 无约束（不计 checked、不算 gap）。"""
    rp = _repo(tmp_path)
    files = [
        _write_state_file(rp, ".gatekeeper.state.miss"),
        _write_state_file(rp, ".gatekeeper.state.null", None),
        _write_state_file(rp, ".gatekeeper.state.empty", ""),
    ]
    r = C.state_claim_gaps(str(rp), state_files=files)
    assert r.get("checked") == 0 and r.get("count") == 0, r


# ── 臂⑧ D-b② 写面写点同步（§17-4 A 步②，fail-soft / sid-gated / 主树排除）─────
def test_arm8_sync_appends_when_sid_and_nonmain(tmp_path):
    """非主树 worktree + 有 sid ⟹ 登记一条 live claim（谓词 ∃ 侧）。"""
    rp = _repo(tmp_path)
    wt = str((tmp_path / "wt-sync").resolve())
    r = C.sync_state_worktree(str(rp), worktree=wt, sid=SID_A)
    assert r.get("ok") is True and not r.get("noop"), r
    live = [c for c in C.live(str(rp)) if c.get("sid") == SID_A]
    # [ECC-F24156A47BEB] 台账**存储**经 `_norm` 归一为 posix 形态（跨宿主单源）⟹ 断言须同源归一，
    #   否则 Windows 宿主上 `str(Path)` 的反斜杠与存储值永不相等（误红）。
    assert live and live[-1].get("worktree") == C._norm(wt), live


def test_arm8_sync_noop_without_sid(tmp_path):
    """无 sid（sid-less）⟹ no-op，**零写台账**（防 sid-less 噪声行）。"""
    rp = _repo(tmp_path)
    wt = str((tmp_path / "wt-nosid").resolve())
    r = C.sync_state_worktree(str(rp), worktree=wt, sid="")
    assert r.get("noop") is True and _lines(rp) == [], r


def test_arm8_sync_noop_main_tree(tmp_path):
    """`state.worktree == repo 自身`（主树）⟹ no-op（对齐 `expected_worktrees` 排除主树惯例）。"""
    rp = _repo(tmp_path)
    r = C.sync_state_worktree(str(rp), worktree=str(rp), sid=SID_A)
    assert r.get("noop") is True and _lines(rp) == [], r


def test_arm8_sync_idempotent(tmp_path):
    """同 sid 同 worktree 已有 live claim ⟹ 再次同步 no-op（防台账膨胀）。"""
    rp = _repo(tmp_path)
    wt = str((tmp_path / "wt-idem").resolve())
    C.sync_state_worktree(str(rp), worktree=wt, sid=SID_A)
    n1 = len(_lines(rp))
    r = C.sync_state_worktree(str(rp), worktree=wt, sid=SID_A)
    assert r.get("noop") is True and len(_lines(rp)) == n1, (r, _lines(rp))


def test_arm8_gaps_exclude_main_tree(tmp_path):
    """步① 谓词：`state.worktree == repo 自身`（主树）⟹ 无约束（不计 checked / gap）。"""
    rp = _repo(tmp_path)
    sf = _write_state_file(rp, ".gatekeeper.state.mainwt", str(rp))
    r = C.state_claim_gaps(str(rp), state_files=[sf])
    assert r.get("checked") == 0 and r.get("count") == 0, r


def test_arm8_state_patch_set_top_syncs_claim(tmp_path, monkeypatch):
    """写点②：`state-patch set-top <state> worktree` ⟹ 同步登记 claim（fail-soft、sid-gated）。"""
    import gk_state_patch as SP
    rp = _repo(tmp_path)
    led = tmp_path / "led.jsonl"
    monkeypatch.setenv("GK_WRITE_CLAIMS_PATH", str(led))
    monkeypatch.setenv("GK_SESSION_ID", SID_A)
    st = rp / ".gatekeeper.state"
    st.write_text(json.dumps({"stage": "ECO-EDIT", "gate_data": {}}),
                  encoding="utf-8", newline="\n")
    wt = str((tmp_path / "wt-set").resolve())
    out = SP.cmd_set_top(str(st), "worktree", json.dumps(wt))
    assert out.get("ok") is True, out
    recs = [json.loads(x) for x in led.read_text(encoding="utf-8").splitlines() if x.strip()]
    # [ECC-F24156A47BEB] 同 arm8_sync：存储经 `_norm` 归一 ⟹ 断言同源归一（Windows 反斜杠不误红）。
    assert any(r.get("sid") == SID_A and r.get("worktree") == C._norm(wt) for r in recs), recs

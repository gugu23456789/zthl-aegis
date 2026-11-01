#!/usr/bin/env python3
"""CLI 语义摩擦三条修复 —— 红先臂集（finding `ECC-6056478D1353`）。

覆盖（三条均为**功能臂**，离线可跑）：
  ① `push` **首参 flag 被当 action 吃掉**：`push --repo X` ⟹ `action="--repo"`、`repo` 回落
     `MAIN_REPO_WSL`（实测摩擦；`--repo` 与其余 flag 全丢）。
  ② `push confirm` 直推 URL **不写** `refs/remotes/<remote>/<branch>` ⟹ 本地 `status`/`branch -vv`
     与远端脱节（须手动 `git update-ref` 补刷）。
  ③ **宽度 reclaim**（`--all`）对「分支已并入主树 HEAD 且工作树干净」的 worktree 未自动释放 claim
     ⟹ 须逐条 `--path` 枚举（流程摩擦）。

红先（实现前本文件须见红）：①②③ 三臂对修前版必红；两条 `keeps_guarded_*` 为**守卫臂**
（修前即绿，防修法过宽）。

离线构造要点：① 走**非白名单**本地 remote（`_verify_remote` 必拒并回 `url`）；
② `STATE_FILE` 环境变量可**注入**（gatekeeper-cli.sh L162-167）+ `--push-url` 指本地裸仓 +
`_push_auth_url` 对非 https URL **原样透传**；③ 真 git worktree 夹具 + `GK_WRITE_CLAIMS_PATH` 隔离台账。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI = SKILL_DIR / "gatekeeper-cli.sh"
sys.path.insert(0, str(SCRIPT_DIR))


def _git(repo, *a):
    return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True)


def _cli(*args, env=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    return subprocess.run(["bash", str(CLI), *args], capture_output=True, text=True,
                          env=e, timeout=120)


# ── ① `push` 首参 flag 位置无关 ──────────────────────────────────────────────
class TestPushActionParsing:
    def test_leading_flag_not_taken_as_action(self, tmp_path):
        """`push --repo X`：`--repo` 必须被当 flag 解析（→ repo=X），不得被当 action 吃掉。

        判据（离线）：X 的 origin 指向**非白名单**本地路径 ⟹ `_verify_remote` 必拒并回
        `remote_not_allowed` + `url` 含 X 路径。**修前** `--repo` 被当 action ⟹ repo 回落
        `MAIN_REPO_WSL`（其 origin 形态不同，不会回该 url）⟹ 断言不成立（红）。
        """
        repo = tmp_path / "rp"
        repo.mkdir()
        _git(repo, "init", "-q", "-b", "master")
        _git(repo, "remote", "add", "origin", str(tmp_path / "bare.git"))
        out = _cli("push", "--repo", str(repo)).stdout
        d = json.loads(out)
        assert d.get("error") == "remote_not_allowed", d
        assert str(tmp_path) in (d.get("url") or ""), d


# ── ② `push confirm` 刷新 remote-tracking ref ───────────────────────────────
class TestPushTrackingRef:
    def test_confirm_refreshes_remote_tracking_ref(self, tmp_path):
        """`push confirm` 成功后必须把 `refs/remotes/<remote>/<branch>` 钉到刚推成功的本地 sha。

        离线构造：origin = 本地裸仓；`--push-url` 裸仓；`STATE_FILE` 注入活跃 stage；
        `GITHUB_TOKEN` 伪值（`_push_auth_url` 对非 https URL 原样透传 ⟹ 不触网）。
        """
        bare = tmp_path / "bare.git"
        subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
        repo = tmp_path / "rp"
        repo.mkdir()
        _git(repo, "init", "-q", "-b", "feat")
        (repo / "a.txt").write_text("x", encoding="utf-8")
        _git(repo, "add", "a.txt")
        _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")
        _git(repo, "remote", "add", "origin", str(bare))
        st = tmp_path / "state.json"
        st.write_text(json.dumps({"stage": "R1", "gate_data": {}}), encoding="utf-8")
        out = _cli("push", "confirm", "--repo", str(repo), "--branch", "feat",
                   "--remote", "origin", "--push-url", str(bare),
                   env={"STATE_FILE": str(st), "GITHUB_TOKEN": "fake-token"}).stdout
        d = json.loads(out)
        assert d.get("ok") is True and d.get("phase") == "confirm", d
        local_sha = _git(repo, "rev-parse", "feat").stdout.strip()
        rt = _git(repo, "rev-parse", "refs/remotes/origin/feat")
        assert rt.returncode == 0, "confirm 成功但未刷 refs/remotes/origin/feat（本地与远端脱节）"
        assert rt.stdout.strip() == local_sha, (rt.stdout, local_sha)


# ── ③ 宽度 reclaim（`--all` 内）自动回收「已并入且干净」──────────────────────
@pytest.fixture()
def repo_wt(tmp_path):
    """真 git 仓 + 一个真 worktree（分支 `feat` 与主树同点 ⟹ **已并入**；工作树**干净**）。"""
    repo = tmp_path / "main"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("x", encoding="utf-8")
    _git(repo, "add", "a.txt")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")
    root = tmp_path / "wts"
    root.mkdir()
    wt = root / "wt1"
    _git(repo, "worktree", "add", "-q", "-b", "feat", str(wt))
    import gk_write_claims as wc
    return str(repo), str(root), str(wt), wc


class TestReclaimMergedCleanAutorelease:
    def test_all_sweep_autoreclaims_merged_clean(self, repo_wt, tmp_path, monkeypatch):
        """红先：`--all` 授权下，「已并入主树 HEAD 且干净」的 worktree 自动释放其（含过期的）
        claim 并回收 —— 消除「须逐条 `--path` 枚举」的流程摩擦。修前：claim 一挡 ⟹ 进
        `claim_guarded`/`skipped`，不回收（红）。
        """
        repo, root, wt, wc = repo_wt
        monkeypatch.setenv("GK_WRITE_CLAIMS_PATH", str(tmp_path / "claims.jsonl"))
        monkeypatch.setenv("GK_RECLAIM_ALLOW_FULL", "1")
        monkeypatch.delenv("GK_RECLAIM_CLAIM_GUARD", raising=False)
        assert wc.append(None, sid="t9", worktree=wt, source="test").get("ok"), "夹具：claim 未登记"
        r = wr_reclaim(repo, root)
        removed = [os.path.abspath(p) for p in r.get("removed") or []]
        assert os.path.abspath(wt) in removed, r
        assert any(a.get("reason") == "merged_clean"
                   for a in (r.get("claim_autoreleased") or [])), r

    def test_all_sweep_keeps_guarded_when_dirty(self, repo_wt, tmp_path, monkeypatch):
        """守卫臂（防修法过宽）：**已并入但有未回收残留** ⟹ 仍 fail-closed（拒删 + claim_guarded）。"""
        repo, root, wt, wc = repo_wt
        (Path(wt) / "new_file.txt").write_text("未回收内容", encoding="utf-8")
        monkeypatch.setenv("GK_WRITE_CLAIMS_PATH", str(tmp_path / "claims.jsonl"))
        monkeypatch.setenv("GK_RECLAIM_ALLOW_FULL", "1")
        monkeypatch.delenv("GK_RECLAIM_CLAIM_GUARD", raising=False)
        assert wc.append(None, sid="t9", worktree=wt, source="test").get("ok")
        r = wr_reclaim(repo, root)
        _assert_guarded(r, wt)

    def test_all_sweep_keeps_guarded_when_clean_but_unmerged(self, repo_wt, tmp_path, monkeypatch):
        """守卫臂（隔离 merge-base 判据）：**干净但未并入**（feat 有未入主树的空提交）⟹ 仍拒删。"""
        repo, root, wt, wc = repo_wt
        # 空提交：feat 领先主树一笔，但**文件内容与主树一致** ⟹ merit「干净」仍成立，唯「已并入」不成立
        _git(wt, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "--allow-empty", "-qm", "empty")
        monkeypatch.setenv("GK_WRITE_CLAIMS_PATH", str(tmp_path / "claims.jsonl"))
        monkeypatch.setenv("GK_RECLAIM_ALLOW_FULL", "1")
        monkeypatch.delenv("GK_RECLAIM_CLAIM_GUARD", raising=False)
        assert wc.append(None, sid="t9", worktree=wt, source="test").get("ok")
        r = wr_reclaim(repo, root)
        _assert_guarded(r, wt)


def wr_reclaim(repo, root):
    import gk_worktree_reclaim as _wr
    return _wr.reclaim(repo, root, apply=True, trash=os.path.join(root, "trash"))


def _assert_guarded(r, wt):
    removed = [os.path.abspath(p) for p in r.get("removed") or []]
    assert os.path.abspath(wt) not in removed, r
    assert any(os.path.abspath(g["path"]) == os.path.abspath(wt)
               for g in (r.get("claim_guarded") or [])), r
    assert os.path.isdir(wt), "fail-closed 破了：被拒删的 worktree 竟消失"

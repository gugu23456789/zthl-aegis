#!/usr/bin/env python3
"""红先臂：finding 台账**时效巡检**（TTL 标 stale + 锚文件被 diff 触及 ⟹ reopen）
与**跨仓 `<repo_token>` 索引投影**（2026-11-01，用户裁定「不新建卫星库」）。

缺口：
  ① 终态 finding 一旦关单就**永不回看** ⟹ 修复被后续提交回退时台账仍 `closed`（假绿）；
  ② `open` 条目可无限期躺着 ⟹「陈年未处置」在状态视图里不可见；
  ③ 跨仓 finding 全落调用方 state ⟹ 无法按仓看 open/stale 分布；另建卫星库 = 又一份真相源。

判据（**HEAD 必红** —— `stale_scan` / `_project_repo_index` 尚不存在 ⟹ AttributeError）：
  1) TTL 超期 ⟹ `stale[]` 报告；dry-run **零写盘**；`apply=True` 落 `stale=true` + journal；
  2) 未超期 ⟹ 不报；
  3) 终态 + `commit:<sha>` + 锚文件被 diff 触及 ⟹ `reopened[]`；apply 后 status=open + journal；
  4) 锚文件未被改 ⟹ 不重开（不误伤）；
  5) 无 `commit:` 锚 ⟹ `skipped: no_commit_anchor`（**显式可见**，不静默当干净）；
  6) 锚漂移被 `_guard_precheck` 拦下 ⟹ `blocked[]`，**不**自动重开；
  7) `_project_repo_index` 按 `repo_token` 聚合（无 token 归 `_unattributed`）；
     `_refresh_repo_index` 落盘且 `_checksum` 同步（防 TAMPERED 误报）；
  8) 非法 TTL ⟹ fail-loud。
"""
import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import gk_finding as F  # noqa: E402

GIT = shutil.which("git")


def _mk(tmp_path, findings, name="state.json"):
    p = tmp_path / name
    p.write_text(json.dumps({"gate_data": {"ecc_findings": findings}}, ensure_ascii=False),
                 encoding="utf-8")
    return str(p)


def _iso(days_ago):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


def _read(sf):
    return json.loads(Path(sf).read_text(encoding="utf-8"))


def _checksum_matches(sf):
    d = _read(sf)
    want = hashlib.sha256(json.dumps(d.get("gate_data", {}), sort_keys=True).encode()
                          ).hexdigest()[:16]
    return d.get("_checksum") == want


@pytest.fixture(autouse=True)
def _quiet_guards(monkeypatch):
    """单测不依赖真实锚判决引擎；`_candidate_repos` 由各用例按需注入。"""
    monkeypatch.setenv("GK_FINDING_PRECHECK", "0")
    monkeypatch.setenv("GK_FINDING_ACCEPT", "0")
    monkeypatch.setattr(F, "_candidate_repos", lambda state_file: [])


# ── ① / ② TTL ────────────────────────────────────────────────────────────────

def test_ttl_expired_reported_and_dry_run_is_read_only(tmp_path):
    sf = _mk(tmp_path, [{"id": "ECC-OLD", "title": "陈旧", "status": "open",
                         "created_at": _iso(30)}])
    before = Path(sf).read_bytes()
    out = F.stale_scan(sf, 14)
    assert [x["id"] for x in out["stale"]] == ["ECC-OLD"], out
    assert out["applied"] == {"reopened": 0, "stale": 0}, out
    assert Path(sf).read_bytes() == before, "dry-run 必须零写盘"


def test_ttl_apply_marks_stale_and_journals(tmp_path):
    sf = _mk(tmp_path, [{"id": "ECC-OLD", "title": "陈旧", "status": "open",
                         "created_at": _iso(30)}])
    out = F.stale_scan(sf, 14, apply=True)
    assert out["applied"]["stale"] == 1, out
    f = F.load_findings(sf)[0]
    assert f["stale"] is True and f["stale_reason"] == F._STALE_REASON_TTL, f
    assert f["stale_days"] >= 29, f
    assert f["status"] == "open", "TTL 只打标记，**不**改状态机"
    assert any(e.get("event") == "stale" and e.get("fid") == "ECC-OLD"
               for e in F._journal_events(sf)), "缺 stale journal 留痕"
    assert _checksum_matches(sf), "apply 后 checksum 必须同步（否则误报 TAMPERED）"


def test_fresh_open_not_stale(tmp_path):
    sf = _mk(tmp_path, [{"id": "ECC-NEW", "title": "新", "status": "open",
                         "created_at": _iso(1)}])
    assert F.stale_scan(sf, 14)["stale"] == []


def test_invalid_ttl_fails_loud(tmp_path):
    sf = _mk(tmp_path, [])
    with pytest.raises(ValueError):
        F.stale_scan(sf, 0)


# ── ③ / ④ / ⑤ 锚文件 diff 触及 ⟹ reopen ──────────────────────────────────────

def _git_repo(tmp_path):
    if not GIT:
        pytest.skip("git 不可用")
    repo = tmp_path / "repo"
    repo.mkdir()
    run = lambda *a: subprocess.run([GIT, "-C", str(repo)] + list(a), check=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    run("init", "-q")
    run("config", "user.email", "t@example.com")
    run("config", "user.name", "t")
    (repo / "mod.py").write_text("x = 1\n", encoding="utf-8")
    run("add", "mod.py")
    run("commit", "-q", "-m", "init")
    sha = run("rev-parse", "HEAD").stdout.decode().strip()
    return repo, sha


def test_anchor_changed_reopens(tmp_path, monkeypatch):
    repo, sha = _git_repo(tmp_path)
    monkeypatch.setattr(F, "_candidate_repos", lambda state_file: [str(repo)])
    sf = _mk(tmp_path, [{"id": "ECC-FIX", "title": "已修", "status": "closed",
                         "verify_source": "commit:" + sha, "anchors": ["mod.py:1"],
                         "evidence_hash": "abc"}])
    (repo / "mod.py").write_text("x = 2\n", encoding="utf-8")   # 修复被改（未提交）
    out = F.stale_scan(sf, 14)
    assert [x["id"] for x in out["reopened"]] == ["ECC-FIX"], out
    assert out["reopened"][0]["touched"] == ["mod.py"], out
    assert F.load_findings(sf)[0]["status"] == "closed", "dry-run 不得改状态"

    out = F.stale_scan(sf, 14, apply=True)
    assert out["applied"]["reopened"] == 1, out
    f = F.load_findings(sf)[0]
    assert f["status"] == "open", f
    assert not f.get("verify_source"), "重开清 verify_source（历史留 journal）"
    ev = [e for e in F._journal_events(sf) if e.get("fid") == "ECC-FIX"
          and e.get("to") == "open"]
    assert ev and ev[-1].get("reason") == F._STALE_REASON_ANCHOR, ev
    assert _checksum_matches(sf), "apply 后 checksum 必须同步"


def test_anchor_untouched_no_reopen(tmp_path, monkeypatch):
    repo, sha = _git_repo(tmp_path)
    monkeypatch.setattr(F, "_candidate_repos", lambda state_file: [str(repo)])
    sf = _mk(tmp_path, [{"id": "ECC-OK", "title": "已修", "status": "closed",
                         "verify_source": "commit:" + sha, "anchors": ["mod.py"]}])
    out = F.stale_scan(sf, 14)
    assert out["reopened"] == [] and out["skipped"] == [], out


def test_no_commit_anchor_is_reported_not_silent(tmp_path):
    sf = _mk(tmp_path, [{"id": "ECC-NOSRC", "title": "无源关单", "status": "closed",
                         "verify_source": "manual", "anchors": ["a/b.py"]}])
    out = F.stale_scan(sf, 14)
    assert out["reopened"] == [], out
    assert out["skipped"] == [{"id": "ECC-NOSRC", "why": "no_commit_anchor"}], out


def test_precheck_drift_blocks_auto_reopen(tmp_path, monkeypatch):
    repo, sha = _git_repo(tmp_path)
    monkeypatch.setattr(F, "_candidate_repos", lambda state_file: [str(repo)])
    monkeypatch.delenv("GK_FINDING_PRECHECK", raising=False)
    monkeypatch.setattr(F, "_scan_drift", lambda state_file, fids: [
        {"fid": "ECC-FIX", "anchor": "mod.py:9", "verdict": "missing", "detail": "not found"}])
    sf = _mk(tmp_path, [{"id": "ECC-FIX", "title": "已修", "status": "closed",
                         "verify_source": "commit:" + sha, "anchors": ["mod.py"]}])
    (repo / "mod.py").write_text("x = 3\n", encoding="utf-8")
    out = F.stale_scan(sf, 14, apply=True)
    assert out["blocked"] and out["blocked"][0]["id"] == "ECC-FIX", out
    assert out["applied"]["reopened"] == 0, out
    assert F.load_findings(sf)[0]["status"] == "closed", "漂移条目**不得**自动重开"


# ── ⑥ 跨仓索引投影 ───────────────────────────────────────────────────────────

def test_project_repo_index_groups_by_token():
    idx = F._project_repo_index([
        {"id": "a", "status": "open", "repo_token": "repoA"},
        {"id": "b", "status": "closed", "repo_token": "repoA"},
        {"id": "c", "status": "open", "stale": True, "repo_token": "repoB"},
        {"id": "d", "status": "open"},
    ])
    assert idx["repoA"]["total"] == 2 and idx["repoA"]["open"] == 1
    assert idx["repoA"]["closed"] == 1
    assert idx["repoB"]["stale"] == 1
    assert idx[F._UNATTRIBUTED]["total"] == 1, "无 token 必须显式归 _unattributed（不臆造）"


def test_refresh_repo_index_persists_and_fixes_checksum(tmp_path):
    sf = _mk(tmp_path, [{"id": "a", "status": "open", "repo_token": "repoA"}])
    idx = F._refresh_repo_index(sf)
    assert idx["repoA"]["open"] == 1, idx
    d = _read(sf)
    assert d["gate_data"][F._REPO_INDEX_KEY]["repoA"]["open"] == 1, d
    assert _checksum_matches(sf)


def test_register_accepts_repo_token(tmp_path, monkeypatch):
    monkeypatch.setenv("GK_FINDING_PRECHECK", "1")
    monkeypatch.setattr(F, "_scan_drift", lambda state_file, fids: [])
    sf = _mk(tmp_path, [])
    f = F.register(sf, "跨仓缺陷", "manual", repo_token="repoX")
    assert f["repo_token"] == "repoX", f
    assert _read(sf)["gate_data"][F._REPO_INDEX_KEY]["repoX"]["open"] == 1


def test_register_rejects_bad_repo_token(tmp_path):
    sf = _mk(tmp_path, [])
    with pytest.raises(ValueError):
        F.register(sf, "坏 token", "manual", repo_token="has space")

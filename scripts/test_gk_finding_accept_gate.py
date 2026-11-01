#!/usr/bin/env python3
"""关单**验收对偶门**红先臂（2026-10-13 · `ECC-89CDA3AEC7B5`）。

病象：`gk_finding.close` 只校 `verify_source` **形态**（c9）——不核验证据真实性、不要求有据、不跑测试
⟹ 可凭 `manual`/空串/伪 `commit:<sha>` 关单（「开单有强制预检，关单无对偶验收」）。

修法：`_accept_gate`（对偶于 `register` 的 `route_hard` 准入硬门）—— close 前，`verify_source`
须承载**可核验证据**（`kind ∈ _ACCEPT_KINDS`；`commit:<sha>` 须在技能仓可解析）；否则 fail-loud
`ECC_CLOSE_ACCEPT_FAIL`。仅 **CLI 手工面**强制（`accept_hard=True`）；`--ack-accept` 逃生舱（记 `accept_ack`）。

臂（HEAD 必红：无 `_accept_gate` / `--ack-accept`）：
  · test_accept_blocks_no_evidence（正臂：`manual` 无据被拦）
  · test_accept_blocks_fake_commit（正臂：伪 sha 被拦）
  · test_accept_allows_real_commit（负臂：真 sha 放行）
  · test_accept_allows_tests_kind（负臂：`tests:` 计为证据）
  · test_accept_ack_allows_and_journals（出口：`--ack-accept` 放行 + journal `accept_ack`）
  · test_accept_skipped_when_accept_hard_false（负臂：模块内调用零回归）
  · test_accept_kill_switch（负臂：`GK_FINDING_ACCEPT=0` 跳过）
  · test_accept_cli_wired（静态：CLI close 分支接 `--ack-accept` + `accept_hard=True`）
"""
import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import gk_finding as GF  # noqa: E402

GF_PATH = SCRIPTS / "gk_finding.py"
FID = "ECC-TESTACC0001"


def _head_sha():
    try:
        return subprocess.check_output(
            ["git", "-C", str(GF.DEFAULT_SKILL), "rev-parse", "HEAD"], text=True).strip()
    except Exception:  # noqa: BLE001
        return ""


def _state(tmp_path):
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"gate_data": {"ecc_findings": [
        {"id": FID, "title": "accept-gate 夹具", "source": "manual", "status": "open",
         "anchors": [], "facets": [], "family": "", "cover_layers": [], "gap": False,
         "cover_warnings": [], "root_key": "", "closure_oracle": "", "source_note": "",
         "evidence_hash": "x", "release_state": "none", "provenance": "trusted",
         "declassified": False, "taint": [], "quarantined": False}]}}),
        encoding="utf-8", newline="\n")
    return str(st)


def _run(argv, env=None):
    e = {**os.environ, "GK_FINDING_PRECHECK": "0"}
    if env:
        e.update(env)
    return subprocess.run([sys.executable, str(GF_PATH)] + argv,
                          capture_output=True, text=True, env=e)


def _status(st):
    d = json.loads(Path(st).read_text(encoding="utf-8"))
    return d["gate_data"]["ecc_findings"][0]["status"]


def test_accept_blocks_no_evidence(tmp_path):
    """正臂：无证据（`manual`）⟹ 验收门 fail-loud。"""
    st = _state(tmp_path)
    r = _run(["close", st, FID])
    assert r.returncode != 0, r.stdout + r.stderr
    assert "ECC_CLOSE_ACCEPT_FAIL" in (r.stdout + r.stderr), r.stdout + r.stderr


def test_accept_blocks_fake_commit(tmp_path):
    """正臂：宣称 `commit:<伪sha>` ⟹ 不可解析 ⟹ fail-loud。"""
    st = _state(tmp_path)
    r = _run(["close", st, FID, "--verify-source", "commit:deadbeefdeadbeef"])
    assert r.returncode != 0, r.stdout + r.stderr
    assert "ECC_CLOSE_ACCEPT_FAIL" in (r.stdout + r.stderr), r.stdout + r.stderr


def test_accept_allows_real_commit(tmp_path):
    """负臂：真 sha ⟹ 放行（HEAD 无门亦放行 ⟹ 本臂单独不红，靠组合判）。"""
    sha = _head_sha()
    assert sha, "无法取技能仓 HEAD sha"
    st = _state(tmp_path)
    r = _run(["close", st, FID, "--verify-source", "commit:" + sha])
    assert r.returncode == 0, r.stdout + r.stderr
    assert _status(st) == "closed"


def test_accept_allows_tests_kind(tmp_path):
    """负臂：`tests:` 属证据 kind ⟹ 放行。"""
    st = _state(tmp_path)
    r = _run(["close", st, FID, "--verify-source", "tests:ok"])
    assert r.returncode == 0, r.stdout + r.stderr
    assert _status(st) == "closed"


def test_accept_ack_allows_and_journals(tmp_path):
    """出口：`--ack-accept` 放行无据关单 + journal 记 `accept_ack`（带 fid）。"""
    st = _state(tmp_path)
    r = _run(["close", st, FID, "--ack-accept"])
    assert r.returncode == 0, r.stdout + r.stderr
    assert _status(st) == "closed"
    jr = Path(st + ".finding-journal.jsonl")
    assert jr.exists(), "accept_ack 未落 journal"
    ev = [json.loads(x) for x in jr.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert any(e.get("event") == "accept_ack" and e.get("fid") == FID for e in ev), ev


def test_accept_skipped_when_accept_hard_false(tmp_path):
    """负臂：模块内调用（缺省 `accept_hard=False`）⟹ 不过门、零回归。"""
    st = _state(tmp_path)
    out = GF.close(st, FID, "manual")
    assert out["status"] == "closed"


def test_accept_kill_switch(tmp_path):
    """负臂：`GK_FINDING_ACCEPT=0` ⟹ 门跳过（伪源也放行）。"""
    st = _state(tmp_path)
    r = _run(["close", st, FID, "--verify-source", "commit:deadbeef"],
             env={"GK_FINDING_ACCEPT": "0"})
    assert r.returncode == 0, r.stdout + r.stderr
    assert _status(st) == "closed"


def test_accept_cli_wired():
    """静态：CLI close 分支接 `--ack-accept` 且以 `accept_hard=True` 调 `close`。"""
    src = GF_PATH.read_text(encoding="utf-8")
    seg = src[src.index('elif cmd == "close":'):]
    seg = seg[:seg.index('elif cmd == "reopen":')]
    assert "--ack-accept" in seg, seg
    assert "accept_hard=True" in seg, seg


def test_accept_cross_repo_commit(tmp_path):
    """**跨仓默认**：sha 只在**另一仓**存在 ⟹ 仍放行（非单仓假设）。"""
    other = tmp_path / "other_repo"
    other.mkdir()
    subprocess.run(["git", "-C", str(other), "init", "-q"], check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "-C", str(other),
                    "commit", "--allow-empty", "-qm", "x"], check=True)
    osha = subprocess.check_output(["git", "-C", str(other), "rev-parse", "HEAD"], text=True).strip()
    st = _state(tmp_path)
    r = _run(["close", st, FID, "--verify-source", "commit:" + osha],
             env={"GK_FINDING_REPOS": str(other)})
    assert r.returncode == 0, r.stdout + r.stderr
    assert _status(st) == "closed"


def test_candidate_repos_env_multi(tmp_path, monkeypatch):
    """结构：候选仓 = **多头**（技能仓 + env 追加仓），非单仓。"""
    other = tmp_path / "r2"
    other.mkdir()
    monkeypatch.setenv("GK_FINDING_REPOS", str(other))
    repos = GF._candidate_repos(str(tmp_path / ".gatekeeper.state"))
    assert str(GF.DEFAULT_SKILL) in repos, repos
    assert str(other) in repos, repos
    assert len(repos) >= 2, repos


# ─── ECC-ECDB1C9C2B1D：ecc-finding **全过程默认跨仓**（owner 2026-10-15 硬要求）────────
# 病象：`_accept_gate` 已跨仓（b3da888），但**处置前锚闸**（`_scan_drift`）与**全域对账**
#   （`_ledger_sources`）仍单仓/单目录 ⟹ 他仓锚静默报漂移、他仓 ledger 不在对账面。
# 臂（HEAD 必红）：跨仓锚不误报 / 跨仓 ledger 进枚举 / 跨仓同 fid 进 shared_ids。

def _mk_other_repo(tmp_path, name="other_repo"):
    other = tmp_path / name
    other.mkdir()
    subprocess.run(["git", "-C", str(other), "init", "-q"], check=True)
    return other


def _state_path(tmp_path, name=".gatekeeper.state"):
    return tmp_path / name


def _write_state(p, findings):
    p.write_text(json.dumps({"gate_data": {"ecc_findings": findings}}),
                 encoding="utf-8", newline="\n")
    return str(p)


def test_scan_drift_cross_repo_anchor_not_flagged(tmp_path, monkeypatch):
    """**跨仓默认**：锚只在**他仓**存在 ⟹ 不得报漂移（HEAD 单仓口径 ⟹ 红）。"""
    other = _mk_other_repo(tmp_path)
    (other / "docs").mkdir()
    (other / "docs" / "uniq_crossrepo_probe.md").write_text("a\nb\n", encoding="utf-8")
    monkeypatch.setenv("GK_FINDING_REPOS", str(other))
    st = _write_state(_state_path(tmp_path), [
        {"id": "ECC-XR1", "status": "open",
         "title": "见 docs/uniq_crossrepo_probe.md:1 处"}])
    assert GF._scan_drift(st, ["ECC-XR1"]) == [], \
        "他仓锚被误报漂移（单仓口径）：%r" % (GF._scan_drift(st, ["ECC-XR1"]),)


def test_ledger_sources_cross_repo_enumerated(tmp_path, monkeypatch):
    """**跨仓默认**：候选仓的 ledger 须进全域枚举（HEAD 单目录 ⟹ 红）。"""
    other = _mk_other_repo(tmp_path)
    _write_state(other / ".gatekeeper.state", [])
    monkeypatch.setenv("GK_FINDING_REPOS", str(other))
    base = _write_state(_state_path(tmp_path), [])
    paths = [p for p, _d, _k in GF._ledger_sources(base)]
    assert str(other / ".gatekeeper.state") in paths, paths


def test_ledger_cross_repo_shared_id_detected(tmp_path, monkeypatch):
    """**跨仓默认**：同 fid 跨仓两源 ⟹ `ledger.shared_ids`（+ 状态不一致 ⟹ `conflicts`）须报。"""
    other = _mk_other_repo(tmp_path)
    _write_state(other / ".gatekeeper.state", [{"id": "ECC-XR2", "status": "closed"}])
    monkeypatch.setenv("GK_FINDING_REPOS", str(other))
    base = _write_state(_state_path(tmp_path), [{"id": "ECC-XR2", "status": "open"}])
    r = GF.ledger(base)
    assert "ECC-XR2" in r["shared_ids"], r
    assert any(c.get("id") == "ECC-XR2" for c in r["conflicts"]), r


#!/usr/bin/env python3
"""
Tests for scripts/gk_audit_state.py (batch8 R-T6 Phase 4a)
=============================================================
Covers: state domain 15 checks (migrated from bash heredoc), hint/self/hook/red
extension checks, and run_all aggregation.
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_audit_state as gas

SKILL_DIR = str(Path(__file__).resolve().parent.parent)


def _write_state(data: dict, path: str) -> str:
    """Write state via gk_state._write_state (computes checksum)."""
    import gk_state
    gk_state._write_state(data, path)
    return path


def _empty_state(path: str) -> str:
    return _write_state({
        "gate_data": {},
        "monitor_scores": {},
        "history": [],
        "appeal_records": {},
        "human_resolutions": {},
        "achievements": {},
    }, path)


def test_arm_all_reports_edit_log_summary_and_maintenance(tmp_path):
    """ED2/ED14 臂（2026-10-08）：`--all` 结果须带 `edit_log`（只读摘要 = **生产读取面**，治只写不读）
    + `edit_log_maintenance`（**显式声明**写侧效，原「不并入 result」使「只读审计」自述与实况不符）。"""
    import gk_budget_ledger as B
    st = str(tmp_path / ".gkstate")
    _empty_state(st)
    B.append_edit(st, session="s1", node="STAGE_0", path="/x/a.py")
    r = subprocess.run([sys.executable, str(Path(__file__).resolve().parent / "gk_audit_state.py"),
                        "--all", "--state-file", st],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, "audit --all 失败：%s%s" % (r.stdout, r.stderr)
    out = json.loads(r.stdout)
    assert "edit_log" in out, "缺 edit_log 只读摘要（ED2 未接线）：keys=%r" % (sorted(out.keys()),)
    assert out["edit_log"].get("edits") == 1, "edit_log 摘要计数不符：%r" % (out["edit_log"],)
    assert "edit_log_maintenance" in out, "未显式声明写侧效（ED14）：keys=%r" % (sorted(out.keys()),)


def _git_repo_clean_pushed(tmp: Path, branch: str = "master") -> str:
    """建 bare origin + 工作仓库（已提交已推送，工作区干净），返回仓库路径。

    复刻执行序列 ci_green 判定所需的 git 事实（gatekeeper-cli.sh L2613-2616）。
    """
    origin = tmp / "origin.git"
    subprocess.run(["git", "init", "--bare", str(origin)],
                   check=True, capture_output=True)
    repo = tmp / "work"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", branch, str(repo)],
                   check=True, capture_output=True)
    for k, v in (("user.email", "t@t"), ("user.name", "t"),
                 ("commit.gpgsign", "false")):
        subprocess.run(["git", "-C", str(repo), "config", k, v],
                       check=True, capture_output=True)
    (repo / "f.txt").write_text("x\n")
    subprocess.run(["git", "-C", str(repo), "add", "."],
                   check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "init"],
                   check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", str(origin)],
                   check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "push", "-u", "origin", branch],
                   check=True, capture_output=True)
    return str(repo)


def _journal_write(state_path: str, events: list) -> None:
    """写 `<state>.finding-journal.jsonl`（路径约定单源 = `gk_finding._journal_path`）。"""
    from gk_finding import _journal_path
    with open(_journal_path(state_path), "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")


def _iso_hours_ago(h: float) -> str:
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) - timedelta(hours=h)).isoformat()


def _field(result: dict, name: str) -> dict:
    return next(x for x in result["state_checks"] if x["field"] == name)


# ---------------------------------------------------------------------------
# Phase 4a: state domain
# ---------------------------------------------------------------------------

class TestAuditState:
    def test_empty_state_15_fields(self, tmp_path):
        sp = _empty_state(str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        # E21（A′）：branch_cleaned 只在 STAGE_5/DONE 产出
        # E22（A′ 续）：ci_green 只在 R 生命周期或已声明时产出 ⟹ 空 state（无 stage）为 21 项
        #   2026-11-01：+`fifo_archives`（归档读面）+`bank_actions_view`（事件单写投影）
        assert len(r["state_checks"]) == 21
        assert r["audit_summary"]["total_fields"] == 21

    def test_missing_state_file(self, tmp_path):
        r = gas.check_state_file(str(tmp_path / "nope.json"))
        # 无 state 时不应崩溃; 字段数仍为 21 (空数据默认值；branch_cleaned 仅退休阶段产出、
        # ci_green 仅 R 生命周期产出)
        assert len(r["state_checks"]) == 21

    def test_audit_reports_state_forms_field(self, tmp_path):
        """`state_forms` 项存在；枚举面非空 ⟹ match；legacy **只报不判失败**（② 单一权威）。"""
        (tmp_path / ".gatekeeper.state").write_text("{}", encoding="utf-8")
        (tmp_path / ".gatekeeper.state.2026-01-01-legacy").write_text("{}", encoding="utf-8")
        sp = _empty_state(str(tmp_path / "s.json"))
        r = gas.check_state_file(sp, skill_dir=str(tmp_path))
        sf = next(c for c in r["state_checks"] if c["field"] == "state_forms")
        assert sf["match"] is True, sf
        assert any(".state.2026-01-01-legacy" in i for i in sf["issues"]), sf

    def test_commit_shas_declared(self, tmp_path):
        sp = _write_state({"gate_data": {"commit_shas": "abc123"}}, str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "commit_shas")
        assert c["declared"] is True
        assert c["match"] is True

    def test_branch_cleaned_none_fails(self, tmp_path):
        # F-11: None 不得通过（E21：该检查只在 STAGE_5/DONE 产出 ⟹ 夹具须进入退休阶段）
        sp = _write_state({"stage": "STAGE_5",
                           "gate_data": {"branch_cleaned": None}},
                          str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "branch_cleaned")
        assert c["match"] is False

    def test_branch_cleaned_true_passes(self, tmp_path):
        sp = _write_state({"stage": "STAGE_5",
                           "gate_data": {"branch_cleaned": True}},
                          str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "branch_cleaned")
        assert c["match"] is True

    def test_branch_cleaned_not_emitted_outside_retire_stage(self, tmp_path):
        """E21/A′：非 STAGE_5/DONE 阶段不产出该检查（不进 total，不喂假阳性 finding）。"""
        for stage in ("STAGE_0", "STAGE_4", "ECO-READ", ""):
            sp = _write_state({"stage": stage, "gate_data": {"branch_cleaned": None}},
                              str(tmp_path / ("s_%s.json" % (stage or "empty"))))
            r = gas.check_state_file(sp)
            assert not [x for x in r["state_checks"] if x["field"] == "branch_cleaned"], stage
        sp = _write_state({"stage": "DONE", "gate_data": {"branch_cleaned": False}},
                          str(tmp_path / "s_done.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "branch_cleaned")
        assert c["match"] is False, "进入退休阶段后 False 仍须判失败（只改范围，不改标准）"

    def test_ci_green_true_clean_pushed(self, tmp_path):
        # PASS 路径：已推送 + 工作区干净 + 声明 True → match（复刻执行序列判定）
        repo = _git_repo_clean_pushed(tmp_path)
        sp = _write_state({"branch": "master", "main_repo": repo,
                           "gate_data": {"ci_green": True}}, str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "ci_green")
        assert c["match"] is True
        assert c["replay"] == "pushed=0 clean=0"

    def test_ci_green_true_unpushed_fails(self, tmp_path):
        # 声明 True 但有未推送提交 → FAIL（复刻执行序列 ci_pushed 验证，手写声明不可绕过）
        repo = _git_repo_clean_pushed(tmp_path)
        (Path(repo) / "f2.txt").write_text("y\n")
        subprocess.run(["git", "-C", repo, "add", "."], check=True, capture_output=True)
        subprocess.run(["git", "-C", repo, "commit", "-m", "second"],
                       check=True, capture_output=True)
        sp = _write_state({"branch": "master", "main_repo": repo,
                           "gate_data": {"ci_green": True}}, str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "ci_green")
        assert c["match"] is False
        assert "pushed=1" in c["replay"]

    def test_ci_green_unverifiable_fails(self, tmp_path):
        # 无法 replay（main_repo 指向不存在目录）→ 声明 True 也不通过（-1 = 无法验证）
        # E21/A′：replay 必须说明「为什么 -1」（repo-missing ≠ no-origin）
        sp = _write_state({"branch": "master", "main_repo": str(tmp_path / "no-git"),
                           "gate_data": {"ci_green": True}}, str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "ci_green")
        assert c["match"] is False
        assert c["replay"] == "pushed=-1 clean=-1 unverifiable:repo-missing", c["replay"]

    def test_ci_green_false_declared_fails(self, tmp_path):
        # 声明 False → 即使 git 事实干净也 FAIL
        repo = _git_repo_clean_pushed(tmp_path)
        sp = _write_state({"branch": "master", "main_repo": repo,
                           "gate_data": {"ci_green": False}}, str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "ci_green")
        assert c["match"] is False

    def test_ci_green_not_emitted_outside_r_lifecycle(self, tmp_path):
        """E22/A′：非 R 生命周期（standing/analysis/IDLE）且未声明 ⟹ 不产出（不进 total）。"""
        for stage in ("ECO-READ", "ECO-EDIT", "ECC-AUDIT", "IDLE", ""):
            sp = _write_state({"stage": stage, "branch": "master",
                               "main_repo": str(tmp_path / "no-git"),
                               "gate_data": {}},
                              str(tmp_path / ("s_%s.json" % (stage or "empty"))))
            r = gas.check_state_file(sp)
            assert not [x for x in r["state_checks"] if x["field"] == "ci_green"], stage

    def test_ci_green_emitted_in_r_lifecycle_even_if_undeclared(self, tmp_path):
        """E22/A′：进入 R 生命周期即须被审 —— 未声明也要产出（declared=None、match=False）。

        与「已声明必审」合起来堵住两条自助豁免：把字段删掉、或把 stage 改走。
        """
        sp = _write_state({"stage": "STAGE_3", "branch": "master",
                           "main_repo": str(tmp_path / "no-git"),
                           "gate_data": {}}, str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "ci_green")
        assert c["declared"] is None
        assert c["match"] is False

    def test_ci_green_declared_outside_r_lifecycle_still_audited(self, tmp_path):
        """E22/A′：已声明就必须被审（`in gd` 为 or 条件）—— 删 stage 不能让它消失。"""
        sp = _write_state({"stage": "ECO-EDIT", "branch": "master",
                           "main_repo": str(tmp_path / "no-git"),
                           "gate_data": {"ci_green": True}}, str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "ci_green")
        assert c["match"] is False

    def test_monitor_scores_monotonic(self, tmp_path):
        # 单调递增 3 个 → F-09 判定应为 False (倒序单调)
        sp = _write_state({"monitor_scores": {
            "ECO-READ": {"score": 0.2},
            "ECO-EDIT": {"score": 0.5},
            "ECO-AUDIT": {"score": 0.9},
        }}, str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "monitor_scores")
        assert c["match"] is False

    def test_history_unique(self, tmp_path):
        sp = _write_state({"history": [
            {"r_phase": "R-T1"}, {"r_phase": "R-T2"},
        ]}, str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "history")
        assert c["match"] is True

    def test_history_dup_phases(self, tmp_path):
        sp = _write_state({"history": [
            {"r_phase": "R-T1"}, {"r_phase": "R-T1"},
        ]}, str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "history")
        assert c["match"] is False

    def test_subagent_history_low_confidence(self, tmp_path):
        sp = _write_state({"gate_data": {"subagent_history": [
            {"guardrail": "passed", "confidence": "low"},
            {"guardrail": "passed", "confidence": "low"},
            {"guardrail": "passed", "confidence": "low"},
        ]}}, str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "subagent_history")
        assert c["match"] is False
        assert any("consecutive_low_confidence" in i for i in c.get("issues", []))

    def test_block_log_concentration(self, tmp_path):
        sp = _write_state({"gate_data": {"block_log": [
            {"command": "rm", "timestamp": "2026-08-15T11:31:00Z"},
            {"command": "rm", "timestamp": "2026-08-15T11:32:00Z"},
            {"command": "rm", "timestamp": "2026-08-15T11:33:00Z"},
        ]}}, str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "block_log")
        assert c["match"] is False
        assert any("concentrated" in i for i in c.get("issues", []))

    def test_sealed_score_missing_with_eco_edit(self, tmp_path):
        sp = _write_state({"gate_data": {
            "eco_completions": {"ECO-EDIT": {"completed_at": "2026-08-15"}},
        }}, str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "sealed_agent_score")
        assert c["match"] is False

    def test_sealed_score_present(self, tmp_path):
        sp = _write_state({"gate_data": {
            "_sealed_agent_score": {"score": 0.8, "verdicts": {}, "conclusion": "ok"},
        }}, str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "sealed_agent_score")
        assert c["match"] is True

    def test_adjudicate_missing_verdicts(self, tmp_path):
        sp = _write_state({"gate_data": {"human_calibration_log": [
            {"divergence": 0.05},
        ]}}, str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "adjudicate_records")
        assert c["match"] is False

    def test_appeal_missing_verdict(self, tmp_path):
        sp = _write_state({"appeal_records": {"STAGE_3": {"notes": "x"}}}, str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "appeal_records")
        assert c["match"] is False

    def test_eco_ecc_link_pending(self, tmp_path):
        sp = _empty_state(str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "eco_ecc_link")
        assert c["match"] is True  # pending = OK

    def test_ecc_findings_open_without_journal_fails(self, tmp_path):
        """E23：有台账但无事件账 = 清洗信号 ⟹ FAIL（禁静默通过）；原因须可读。"""
        sp = _write_state({"gate_data": {"ecc_findings": [
            {"id": "F1", "status": "open", "title": "x"},
        ]}}, str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = _field(r, "ecc_findings")
        assert c["match"] is False
        assert any("unverifiable:journal-missing" in i for i in c["issues"]), c

    def test_achievements_format(self, tmp_path):
        sp = _empty_state(str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "achievements")
        assert c["match"] is True


class TestEccFindingsLedgerHealth:
    """E23（2026-10-29）：`ecc_findings` 由 `open == 0`（结构性不可达）收紧为
    ① 无 `critical` open/rejected ② 窗口内「首次登记数」≤「关闭数」。

    基线取自 finding journal（第二副本锚），不新增 state 键 —— 防被审方自写基线。
    """

    def test_empty_ledger_without_journal_passes(self, tmp_path):
        """空台账 + 无事件账 = 从未登记（无账可动），不判失败（区别于「有账无 journal」）。"""
        sp = _empty_state(str(tmp_path / "s.json"))
        assert _field(gas.check_state_file(sp), "ecc_findings")["match"] is True

    def test_critical_open_fails(self, tmp_path):
        sp = _write_state({"gate_data": {"ecc_findings": [
            {"id": "F1", "status": "open", "title": "x", "severity": "critical"}]}},
            str(tmp_path / "s.json"))
        _journal_write(sp, [{"event": "register", "fid": "F1", "ts": _iso_hours_ago(72)}])
        c = _field(gas.check_state_file(sp), "ecc_findings")
        assert c["match"] is False
        assert any("critical_open=1" in i for i in c["issues"]), c

    def test_open_backlog_older_than_window_passes(self, tmp_path):
        """存量 open（30 条、非 critical）+ 窗口内无新增/无关闭 ⟹ 通过：
        旧线「open==0」会把这条永判红，新线只要求「台账在动」。"""
        sp = _write_state({"gate_data": {"ecc_findings": [
            {"id": "F%d" % i, "status": "open", "title": "x"} for i in range(30)]}},
            str(tmp_path / "s.json"))
        _journal_write(sp, [{"event": "register", "fid": "F%d" % i,
                             "ts": _iso_hours_ago(72)} for i in range(30)])
        c = _field(gas.check_state_file(sp), "ecc_findings")
        assert c["match"] is True, c
        assert "new=0" in c["replay"] and "closed=0" in c["replay"], c

    def test_closure_lag_fails(self, tmp_path):
        sp = _write_state({"gate_data": {"ecc_findings": [
            {"id": "F2", "status": "open", "title": "y"}]}},
            str(tmp_path / "s.json"))
        _journal_write(sp, [{"event": "register", "fid": "F2", "ts": _iso_hours_ago(1)}])
        c = _field(gas.check_state_file(sp), "ecc_findings")
        assert c["match"] is False
        assert any("closure_lag" in i and "closed_24h=0" in i for i in c["issues"]), c

    def test_balanced_register_and_close_passes(self, tmp_path):
        sp = _write_state({"gate_data": {"ecc_findings": [
            {"id": "F3", "status": "open", "title": "z"},
            {"id": "F4", "status": "closed", "title": "w"}]}},
            str(tmp_path / "s.json"))
        _journal_write(sp, [
            {"event": "register", "fid": "F3", "ts": _iso_hours_ago(2)},
            {"event": "close", "fid": "F4", "ts": _iso_hours_ago(1)},
        ])
        c = _field(gas.check_state_file(sp), "ecc_findings")
        assert c["match"] is True, c

    def test_reregister_same_fid_not_counted_as_new(self, tmp_path):
        """同一 fid 的 merge+重登记不充作「新增」——否则重复登记即可让 closure_lag 失真。"""
        sp = _write_state({"gate_data": {"ecc_findings": [
            {"id": "F5", "status": "open", "title": "dup"}]}},
            str(tmp_path / "s.json"))
        _journal_write(sp, [
            {"event": "register", "fid": "F5", "ts": _iso_hours_ago(3)},
            {"event": "merge", "fid": "F5", "ts": _iso_hours_ago(2)},
            {"event": "register", "fid": "F5", "ts": _iso_hours_ago(2)},
            {"event": "close", "fid": "F6", "ts": _iso_hours_ago(1)},
        ])
        c = _field(gas.check_state_file(sp), "ecc_findings")
        assert c["match"] is True, c
        assert "new=1" in c["replay"], c["replay"]

    def test_reopen_counts_as_new_backlog(self, tmp_path):
        """E24：`reopen` 把 status 拉回 open 却不产生 `register` ⟹ 必须计入新增；
        否则「closed ≥ new」可在积压回涨时仍为真（关闭配速被 reopen 绕过）。"""
        sp = _write_state({"gate_data": {"ecc_findings": [
            {"id": "F9", "status": "open", "title": "r"}]}},
            str(tmp_path / "s.json"))
        _journal_write(sp, [
            {"event": "register", "fid": "F9", "ts": _iso_hours_ago(72)},
            {"event": "close", "fid": "F9", "ts": _iso_hours_ago(48)},
            {"event": "reopen", "fid": "F9", "ts": _iso_hours_ago(1)},
        ])
        c = _field(gas.check_state_file(sp), "ecc_findings")
        assert c["match"] is False, c
        assert any("closure_lag" in i and "new_24h=1" in i for i in c["issues"]), c
        assert "reopen=1" in c["replay"], c["replay"]

    def test_unparsable_ts_reported_not_silent(self, tmp_path):
        """坏 ts 不得静默吞掉：`bad_ts=N` 出现在 replay 里（仍按可判部分给结论）。"""
        sp = _write_state({"gate_data": {"ecc_findings": [
            {"id": "F7", "status": "open", "title": "t"}]}},
            str(tmp_path / "s.json"))
        _journal_write(sp, [
            {"event": "register", "fid": "F7", "ts": "not-a-time"},
            {"event": "register", "fid": "F8", "ts": _iso_hours_ago(1)},
            {"event": "close", "fid": "F9", "ts": _iso_hours_ago(1)},
        ])
        c = _field(gas.check_state_file(sp), "ecc_findings")
        assert "bad_ts=1" in c["replay"], c["replay"]


class TestClosedLoopBacklogCeiling:
    """E23：`ecc_findings_closed_loop` 注释-代码漂移修正后**钉死语义** ——
    积压 ≤3 通过、≥4 失败（是硬门禁，不是注释曾写的 WARN）。"""

    def test_three_open_passes(self, tmp_path):
        sp = _write_state({"gate_data": {"ecc_findings": [
            {"id": "F%d" % i, "status": "open"} for i in range(3)]}},
            str(tmp_path / "s.json"))
        assert _field(gas.check_state_file(sp), "ecc_findings_closed_loop")["match"] is True

    def test_four_open_fails(self, tmp_path):
        sp = _write_state({"gate_data": {"ecc_findings": [
            {"id": "F%d" % i, "status": "open"} for i in range(4)]}},
            str(tmp_path / "s.json"))
        assert _field(gas.check_state_file(sp), "ecc_findings_closed_loop")["match"] is False

    def test_rejected_counts_toward_backlog(self, tmp_path):
        sp = _write_state({"gate_data": {"ecc_findings": [
            {"id": "F1", "status": "open"}, {"id": "F2", "status": "rejected"},
            {"id": "F3", "status": "rejected"}, {"id": "F4", "status": "rejected"}]}},
            str(tmp_path / "s.json"))
        c = _field(gas.check_state_file(sp), "ecc_findings_closed_loop")
        assert c["match"] is False, "rejected 与 open 同计积压（原实现口径，钉死不许漂移）"


class TestAuditHookBlockLogIntent:
    """state 域第 17 项 hook_block_log — 意图记忆可审计性 + 提权链信号 (2026-09-02)。"""

    def test_empty_intent_log_passes(self, tmp_path):
        # 空意图记忆 = 无记录可审 ≠ 损坏 → match True（对齐 history "0 entries" 语义）
        sp = _empty_state(str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "hook_block_log")
        assert c["match"] is True
        assert "0 intents" in c["declared"]

    def test_valid_records_pass_with_escalation_issue(self, tmp_path):
        # 有效意图记录（含 escalation 提权链）→ match True（证据源可审计），
        # escalation>0 → issues 标注人工复核（与 HOOK-06 互补）
        sp = _write_state({"gate_data": {"hook_block_log": [
            {"ts": 1000.0, "tool": "Edit", "target": "/x/a.md", "kind": "block",
             "cmd": "Edit /x/a.md", "reason": "guard"},
            {"ts": 1001.0, "tool": "RunCommand", "target": "/x/a.md",
             "kind": "escalation", "cmd": "echo > /x/a.md", "reason": "escape"},
        ]}}, str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "hook_block_log")
        assert c["match"] is True
        assert "2 intents (1 escalations)" in c["declared"]
        assert any("escalation_signals=1" in i for i in c["issues"])

    def test_archived_cross_r_survives(self, tmp_path):
        # discover prev_entry 归档幸存 → history[].hook_block_log 仍可跨 R 审计
        sp = _write_state({"gate_data": {},
                           "history": [{"r_phase": "R1", "hook_block_log": [
                               {"ts": 1.0, "tool": "RunCommand", "target": "/x",
                                "kind": "escalation", "cmd": "", "reason": ""},
                           ]}]}, str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "hook_block_log")
        assert c["match"] is True
        assert "archived_cross_r=1" in " ".join(c["issues"])
        assert "1 intents (1 escalations)" in c["declared"]

    def test_malformed_record_fails(self, tmp_path):
        # 损坏记录（缺 ts/tool）→ 不可审计 → match False
        sp = _write_state({"gate_data": {"hook_block_log": [
            {"kind": "block"},  # 缺 ts/tool
        ]}}, str(tmp_path / "s.json"))
        r = gas.check_state_file(sp)
        c = next(x for x in r["state_checks"] if x["field"] == "hook_block_log")
        assert c["match"] is False
        assert any("malformed=1" in i for i in c["issues"])


# ---------------------------------------------------------------------------
# Phase 4c-4f: extension checks
# ---------------------------------------------------------------------------

class TestAuditHint:
    def test_hint_runs(self):
        r = gas.check_hint(SKILL_DIR)
        assert r["audit_summary"]["total_fields"] == 4
        assert "hint_checks" in r


class TestAuditSelf:
    def test_self_runs(self):
        r = gas.check_self(SKILL_DIR)
        assert r["audit_summary"]["total_fields"] == 4
        assert "self_checks" in r


class TestAuditHook:
    def test_hook_runs(self):
        r = gas.check_hook(SKILL_DIR)
        # HOOK-01..04 部署配置 + HOOK-05/06（2026-09-02 提权绕过防线+实时越权监控）= 6
        assert r["audit_summary"]["total_fields"] == 6
        assert "hook_checks" in r


class TestAuditRed:
    def test_red_runs(self):
        r = gas.check_red(SKILL_DIR)
        # red_scope..red_migrate 9 + red_integrity 1 + red_aig 1 + report 1 = 12
        # (2026-09-04 接入 RED-INTEGRITY；2026-10-28 A9 接入 RED-AIG)
        assert r["audit_summary"]["total_fields"] == 12
        assert "red_checks" in r

    def test_red_semantic_coverage(self):
        """S10（2026-09-05）：语义/覆盖回归——registry 16 站 ↔ 引擎 def+dispatcher 对拍零 gap。

        A9（2026-10-28）：新增 RED-AIG 站（KVM 沙箱内的 AIG 车道）⟹ 15 → 16 站。
        """
        r = gas.check_red(SKILL_DIR)
        assert r["red_registry_unreadable"] is False
        assert len(r["red_registry_stations"]) == 16
        assert r["red_registry_gap"] == []          # 车站登记齐全、引擎均有 def+分发
        assert r["audit_summary"]["matches"] == 12   # 全字段语义 match（非仅文本存在）


class TestRunAll:
    def test_run_all_37(self, tmp_path):
        sp = _empty_state(str(tmp_path / "s.json"))
        r = gas.run_all(sp, SKILL_DIR)
        # state 19 + hint 4 + self 4 + hook 6 + red 12 = 45
        # （2026-09-02 HOOK-05/06 + hook_block_log；E21 branch_cleaned、E22 ci_green 收窄产出范围）
        assert r["audit_summary"]["total_fields"] >= 41
        assert r["domains"] == ["state", "hint", "self", "hook", "red"]


# ---------------------------------------------------------------------------
# CLI entry
# ---------------------------------------------------------------------------

class TestCLI:
    def test_cli_state_json(self, tmp_path):
        sp = _empty_state(str(tmp_path / "s.json"))
        r = subprocess.run(
            [sys.executable, str(Path(__file__).parent / "gk_audit_state.py"),
             "--state", "--state-file", sp],
            capture_output=True, text=True, timeout=30,
        )
        assert r.returncode == 0, r.stderr
        data = json.loads(r.stdout)
        assert data["audit_summary"]["total_fields"] == 21

    def test_cli_all_json(self, tmp_path):
        sp = _empty_state(str(tmp_path / "s.json"))
        r = subprocess.run(
            [sys.executable, str(Path(__file__).parent / "gk_audit_state.py"),
             "--all", "--state-file", sp],
            capture_output=True, text=True, timeout=30,
        )
        assert r.returncode == 0, r.stderr
        data = json.loads(r.stdout)
        assert "domains" in data


# ---------------------------------------------------------------------------
# P15（2026-10-01 owner 追认「补当日 raise 阈值」）：当日提额频次闸
# ---------------------------------------------------------------------------
def _seed_ledger(state_path: str, n: int, kind: str = "raise") -> None:
    """写 `<state>.budget-log.jsonl`（n 行、当日 ts）并**补封印**。

    必须补封印：账本存在而无 `.seal` ⟹ `verify_seal` 返 `seal_missing`（`seal_ok=False`）
    ⟹ 会把本组两条臂的判据混在一起（无法区分「阈值」与「封印」两种红）。
    """
    import datetime as _dt
    from gk_budget_ledger import seal_now
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    p = Path(str(state_path) + ".budget-log.jsonl")
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        for _ in range(n):
            fh.write(json.dumps({"kind": kind, "source": "state_patch", "ts": ts}) + "\n")
    seal_now(str(state_path))


def _raises_item(r: dict) -> dict:
    return next(x for x in r["state_checks"] if x["field"] == "edit_budget_raises")


def test_edit_budget_raises_over_daily_threshold_breaks_match(tmp_path):
    """**红先**（P15）：当日提额 **> 阈值** ⟹ 本项 `match` 转 **False**。

    原口径只看 `seal_ok`/`bad` ⟹ 当日提额无论多少次**恒 `True`**（P15「判据恒真」）。
    """
    sp = _write_state({"gate_data": {}}, str(tmp_path / "s.json"))
    _seed_ledger(sp, gas.RAISES_TODAY_MAX + 1)
    c = _raises_item(gas.check_state_file(sp))
    assert c["match"] is False, f"当日提额超阈值仍未失败（P15 恒真复发）：{c}"
    assert any("exceeds" in i for i in c["issues"]), f"未报阈值明细：{c}"


def test_edit_budget_raises_within_daily_threshold_matches(tmp_path):
    """守卫：**未超**阈值且 seal/bad 正常 ⟹ `match` 仍 **True**（防「一有提额就红」的噪声口径）。"""
    sp = _write_state({"gate_data": {}}, str(tmp_path / "s.json"))
    _seed_ledger(sp, gas.RAISES_TODAY_MAX)
    c = _raises_item(gas.check_state_file(sp))
    assert c["match"] is True, f"未超阈值却判失败（噪声）：{c}"


def test_degrade_rows_do_not_count_toward_daily_threshold(tmp_path):
    """守卫（C1 联动）：`kind=degrade` 行**不**计入提额频次 ⟹ 不触发阈值（R2-a 早警不得被当提额）。"""
    sp = _write_state({"gate_data": {}}, str(tmp_path / "s.json"))
    _seed_ledger(sp, gas.RAISES_TODAY_MAX + 5, kind="degrade")
    c = _raises_item(gas.check_state_file(sp))
    assert c["match"] is True, f"降级早警行被误算成提额（C1 破）：{c}"

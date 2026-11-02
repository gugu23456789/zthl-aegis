#!/usr/bin/env python3
"""
Tests for scripts/gk_audit_crossr.py (batch8 R-T6 Phase 5)
=============================================================
Covers cross-R analysis migrated from cmd_audit --crossr bash heredoc:
core fields (rejected_count/best_score/best_stage/rejection_convergence/
last_rejections/history_scores) + Phase 5 added cross-phase pattern analysis
(phase_distribution/stage_patterns/recurring_violations — 计划 L1654:
"audit --crossr 包含跨 phase 模式分析 (非当前 phase 孤立数据)").

Contract: {"rejected_count":N,"best_score":...,"best_stage":...,
           "rejection_convergence":"converging|diverging|stable",
           "last_rejections":[...],"history_scores":{...},
           "phase_patterns":{"phase_distribution":[...],"stage_patterns":[...],
                              "recurring_violations":[...]}}
"""

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_audit_crossr as gac

SCRIPT_DIR = Path(__file__).resolve().parent


def _make_state(state_dir, gate_data=None, history=None):
    """构造最小 state 文件。"""
    state = {
        "meta": {"plan": "batch8-python-migration", "r_phase": "R-T6"},
        "gate_data": gate_data or {},
        "history": history or [],
    }
    path = state_dir / "state.json"
    path.write_text(json.dumps(state), encoding="utf-8")
    return str(path)


def _hist(r_phases, rejections):
    """构造 history 列表：[(r_phase, rejection_count, best_score), ...]"""
    return [{"r_phase": rp, "rejection_count": rc,
             "best": {"score": bs}} for rp, rc, bs in zip(r_phases, rejections, [0.9] * len(r_phases))]


class TestCoreContract:
    def test_returns_core_fields(self, tmp_path):
        st = _make_state(tmp_path, {"rejected_edits": [], "best": {}}, [])
        r = gac.analyze_crossr(st)
        for key in ("rejected_count", "best_score", "best_stage",
                    "rejection_convergence", "last_rejections", "history_scores"):
            assert key in r, f"missing {key}"
        assert r["rejected_count"] == 0
        assert r["rejection_convergence"] == "stable"

    def test_empty_state_no_crash(self, tmp_path):
        st = _make_state(tmp_path)
        r = gac.analyze_crossr(st)
        assert r["rejected_count"] == 0

    def test_missing_state_file_no_crash(self, tmp_path):
        r = gac.analyze_crossr(str(tmp_path / "nope.json"))
        assert r["rejected_count"] == 0
        assert r["rejection_convergence"] == "stable"


class TestConvergence:
    def test_converging_when_last_lt_first(self, tmp_path):
        # rc[-1] < rc[0] → converging
        st = _make_state(tmp_path, history=_hist(["R1", "R2", "R3", "R4", "R5"], [5, 4, 3, 2, 1]))
        assert gac.analyze_crossr(st)["rejection_convergence"] == "converging"

    def test_diverging_when_last_gt_first(self, tmp_path):
        st = _make_state(tmp_path, history=_hist(["R1", "R2", "R3", "R4", "R5"], [1, 2, 3, 4, 5]))
        assert gac.analyze_crossr(st)["rejection_convergence"] == "diverging"

    def test_stable_when_less_than_3_samples(self, tmp_path):
        st = _make_state(tmp_path, history=_hist(["R1", "R2"], [1, 1]))
        assert gac.analyze_crossr(st)["rejection_convergence"] == "stable"

    def test_stable_when_equal(self, tmp_path):
        st = _make_state(tmp_path, history=_hist(["R1", "R2", "R3"], [3, 3, 3]))
        assert gac.analyze_crossr(st)["rejection_convergence"] == "stable"


class TestBestAndRejections:
    def test_best_snapshot(self, tmp_path):
        gd = {"best": {"score": 0.87, "stage": "STAGE_3"}, "rejected_edits": []}
        r = gac.analyze_crossr(_make_state(tmp_path, gd, []))
        assert r["best_score"] == 0.87
        assert r["best_stage"] == "STAGE_3"

    def test_last_rejections_include_stage_violations(self, tmp_path):
        rej = [{"stage": f"STAGE_{i}", "violations": ["v1"]} for i in range(7)]
        r = gac.analyze_crossr(_make_state(tmp_path, {"rejected_edits": rej}, []))
        assert r["rejected_count"] == 7
        assert len(r["last_rejections"]) == 5  # 只取最后 5 条
        assert r["last_rejections"][0]["stage"] == "STAGE_2"
        assert "violations" in r["last_rejections"][0]

    def test_history_scores_map(self, tmp_path):
        h = _hist(["R-T5", "R-T6"], [2, 1])
        r = gac.analyze_crossr(_make_state(tmp_path, history=h))
        assert r["history_scores"] == {"R-T5": 0.9, "R-T6": 0.9}


class TestPhasePatterns:
    """Phase 5 增值：跨 phase 模式分析（计划 L1654 验证点）。"""

    def test_phase_distribution(self, tmp_path):
        h = _hist(["R-T4", "R-T5", "R-T6"], [3, 2, 1])
        r = gac.analyze_crossr(_make_state(tmp_path, history=h))
        pd = r["phase_patterns"]["phase_distribution"]
        assert pd[0]["r_phase"] == "R-T4"
        assert pd[0]["rejection_count"] == 3
        assert pd[2]["rejection_count"] == 1

    def test_stage_patterns_rank(self, tmp_path):
        rej = [{"stage": "STAGE_1", "violations": ["x"]}] * 3 + \
              [{"stage": "STAGE_2", "violations": ["y"]}] * 1
        r = gac.analyze_crossr(_make_state(tmp_path, {"rejected_edits": rej}, []))
        sp = r["phase_patterns"]["stage_patterns"]
        assert sp[0]["stage"] == "STAGE_1"  # 最高频排首位
        assert sp[0]["count"] == 3

    def test_recurring_violations(self, tmp_path):
        rej = [{"stage": "S", "violations": ["scope", "scope", "budget"]}] * 2
        r = gac.analyze_crossr(_make_state(tmp_path, {"rejected_edits": rej}, []))
        rv = r["phase_patterns"]["recurring_violations"]
        top = rv[0]
        assert top["violation"] == "scope"
        assert top["count"] == 4  # 2 条 × 2 次

    def test_no_rejections_empty_patterns(self, tmp_path):
        r = gac.analyze_crossr(_make_state(tmp_path))
        pp = r["phase_patterns"]
        assert pp["stage_patterns"] == []
        assert pp["recurring_violations"] == []


class TestGitScanMerge:
    def test_gitscan_env_merged(self, tmp_path):
        """GITSCAN env（CLI 侧 gk_git_concurrency_check.py 产物）合并进输出。"""
        env = dict(os.environ)
        env["GITSCAN"] = json.dumps({"ok": True, "warnings": ["stuck_lock"]})
        env["STATE_FILE"] = _make_state(tmp_path)
        env["PYTHONPATH"] = str(SCRIPT_DIR)
        r = subprocess.run([sys.executable, str(SCRIPT_DIR / "gk_audit_crossr.py")],
                           capture_output=True, text=True, timeout=30, env=env)
        assert r.returncode == 0, r.stderr
        out = json.loads(r.stdout)
        assert out["git_concurrency"]["warnings"] == ["stuck_lock"]

    def test_gitscan_invalid_json_no_crash(self, tmp_path):
        """GITSCAN 非法 JSON → {"raw":...} 不崩。"""
        env = dict(os.environ)
        env["GITSCAN"] = "not-json{{"
        env["STATE_FILE"] = _make_state(tmp_path)
        env["PYTHONPATH"] = str(SCRIPT_DIR)
        r = subprocess.run([sys.executable, str(SCRIPT_DIR / "gk_audit_crossr.py")],
                           capture_output=True, text=True, timeout=30, env=env)
        assert r.returncode == 0, r.stderr
        out = json.loads(r.stdout)
        assert out["git_concurrency"]["raw"].startswith("not-json")

    def test_no_gitscan_injects_empty(self, tmp_path):
        """无 GITSCAN env → git_concurrency 注入 {}（契约恒有字段）。"""
        r = gac.analyze_crossr(_make_state(tmp_path))
        assert r["git_concurrency"] == {}


class TestRobustness:
    def test_rejection_count_none_no_crash(self, tmp_path):
        """history entry 的 rejection_count 显式 None → 不崩（or 0 加固）。"""
        h = [{"r_phase": f"R{i}", "rejection_count": None, "best": {"score": 0.9}}
             for i in range(5)]
        r = gac.analyze_crossr(_make_state(tmp_path, history=h))
        assert r["rejection_convergence"] == "stable"


class TestCliStyle:
    def test_cli_style_json(self, tmp_path):
        env = dict(os.environ)
        env["STATE_FILE"] = _make_state(tmp_path, {"best": {"score": 0.8, "stage": "STAGE_2"}},
                                        _hist(["R-T4", "R-T5", "R-T6"], [3, 2, 1]))
        env["PYTHONPATH"] = str(SCRIPT_DIR)
        r = subprocess.run([sys.executable, str(SCRIPT_DIR / "gk_audit_crossr.py")],
                           capture_output=True, text=True, timeout=30, env=env)
        assert r.returncode == 0, r.stderr
        out = json.loads(r.stdout)
        assert out["rejected_count"] == 0
        assert out["best_score"] == 0.8
        assert out["rejection_convergence"] == "converging"
        assert "phase_patterns" in out

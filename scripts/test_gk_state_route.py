#!/usr/bin/env python3
"""
Tests for scripts/gk_state_route.py (batch8 R-T6 弹性安全网, 2026-08-20)
=============================================================================
背景: 技能目录默认 .gatekeeper.state 曾被门卫 R7.1 隔离 state 占用
（worktree 指向门卫 worktree），audit --all 读到错误 state（batch8 L454
摸底待办 + 2026-08-20 实测暴露）。

覆盖: plan 指针优先 / 默认 state 归属校验 / 冲突自动纠正（恰好 1 个匹配）/
多候选不纠正 / state 缺失不崩 / CLI style。

判定依据: state 内嵌 worktree 字段 vs skill_dir 归属。
Contract: {"expected","current","conflict","corrected","candidates","warning","source"}
"""

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_state_route as gsr

SCRIPT_DIR = Path(__file__).resolve().parent


def _write_state(path: Path, worktree: str):
    """写最小 state（含 worktree 字段）。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"r_phase": "R-T1", "stage": "STAGE_0",
                                "worktree": worktree, "gate_data": {}}), encoding="utf-8")


def _write_pointer(path: Path, state_file: str, updated: str = None):
    """写 plan 指针；updated 缺省为当前时间（Phase 7b TTL 语义下 fresh）。"""
    if updated is None:
        from datetime import datetime, timezone
        updated = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    path.write_text(json.dumps({"state_file": state_file, "plan": "x", "updated": updated}),
                    encoding="utf-8")


class TestPlanPointerPriority:
    def test_pointer_respected(self, tmp_path):
        sd = tmp_path / "skill"
        sd.mkdir()
        # 默认 state 脏（门卫归属），但 plan 指针指向 batch8 state → 尊重指针
        _write_state(sd / ".gatekeeper.state", str(tmp_path / "gatekeeper_project"))
        _write_state(sd / ".gatekeeper.state.batch8", str(sd))
        _write_pointer(sd / ".gatekeeper.plan", str(sd / ".gatekeeper.state.batch8"))
        r = gsr.resolve_state(str(sd))
        assert r["corrected"] is False
        assert r["expected"] == str(sd / ".gatekeeper.state.batch8")
        assert r["source"] == "plan_pointer"


class TestDefaultOwnership:
    def test_default_state_owned_by_skill(self, tmp_path):
        sd = tmp_path / "skill"
        sd.mkdir()
        _write_state(sd / ".gatekeeper.state", str(sd))
        r = gsr.resolve_state(str(sd))
        assert r["conflict"] is False
        assert r["expected"] == str(sd / ".gatekeeper.state")
        assert r["source"] == "current"

    def test_default_state_foreign_conflict(self, tmp_path):
        sd = tmp_path / "skill"
        sd.mkdir()
        _write_state(sd / ".gatekeeper.state", str(tmp_path / "gatekeeper_project"))
        r = gsr.resolve_state(str(sd))
        assert r["conflict"] is True
        assert r["corrected"] is False  # 无候选
        assert "不自动纠正" in (r["warning"] or "")

    def test_missing_state_no_crash(self, tmp_path):
        sd = tmp_path / "skill"
        sd.mkdir()
        r = gsr.resolve_state(str(sd))
        assert r["conflict"] is False  # state 缺失 → 放行（懒填充场景）
        assert r["expected"] == str(sd / ".gatekeeper.state")

    def test_state_without_worktree_field(self, tmp_path):
        sd = tmp_path / "skill"
        sd.mkdir()
        (sd / ".gatekeeper.state").write_text(json.dumps({"r_phase": "ECO-SCAN"}), encoding="utf-8")
        r = gsr.resolve_state(str(sd))
        assert r["conflict"] is False  # 无 worktree 字段 → 不判冲突（历史 state 放行）


class TestSafetyNetCorrection:
    def test_corrected_when_single_candidate(self, tmp_path):
        sd = tmp_path / "skill"
        sd.mkdir()
        _write_state(sd / ".gatekeeper.state", str(tmp_path / "gatekeeper_project"))  # 脏默认
        _write_state(sd / ".gatekeeper.state.batch8", str(sd))  # 唯一匹配候选
        r = gsr.resolve_state(str(sd))
        assert r["conflict"] is True
        assert r["corrected"] is True
        assert r["expected"] == str(sd / ".gatekeeper.state.batch8")
        assert r["source"] == "safety_net"
        assert "已纠正到" in (r["warning"] or "")

    def test_no_correction_when_multiple_candidates(self, tmp_path):
        sd = tmp_path / "skill"
        sd.mkdir()
        _write_state(sd / ".gatekeeper.state", str(tmp_path / "gatekeeper_project"))
        _write_state(sd / ".gatekeeper.state.batch8", str(sd))
        _write_state(sd / ".gatekeeper.state.r7", str(sd))
        r = gsr.resolve_state(str(sd))
        assert r["conflict"] is True
        assert r["corrected"] is False
        assert len(r["candidates"]) == 2
        assert "不自动纠正" in (r["warning"] or "")
        # T3 (2026-08-25): 多候选 WARN 携带可操作描述 — 文件名 + r_phase/stage
        w = r["warning"] or ""
        assert ".gatekeeper.state.batch8(R-T1/STAGE_0)" in w
        assert ".gatekeeper.state.r7(R-T1/STAGE_0)" in w

    def test_describe_candidates_robust_to_corrupt(self, tmp_path):
        """候选文件损坏时描述不崩（r_phase/stage 空）。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        (sd / "x.state").write_text("{corrupt", encoding="utf-8")
        desc = gsr._describe_candidates([str(sd / "x.state")])
        assert "x.state(/) " in desc or desc.endswith("x.state(/)")

    def test_lock_files_ignored(self, tmp_path):
        sd = tmp_path / "skill"
        sd.mkdir()
        _write_state(sd / ".gatekeeper.state", str(tmp_path / "gatekeeper_project"))
        _write_state(sd / ".gatekeeper.state.batch8", str(sd))
        (sd / ".gatekeeper.state.batch8.lock").write_text("x")  # 不应计入候选
        r = gsr.resolve_state(str(sd))
        assert r["corrected"] is True
        assert len(r["candidates"]) == 1


class TestPointerFailureFallthrough:
    def test_dangling_pointer_falls_through(self, tmp_path):
        """指针 state_file 不存在 → fall through 到归属校验（不返回悬空指针）。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        _write_pointer(sd / ".gatekeeper.plan", str(sd / "missing.state"))
        _write_state(sd / ".gatekeeper.state", str(sd))
        r = gsr.resolve_state(str(sd))
        assert r["source"] == "current"  # 落到归属校验，默认归属正确 → current

    def test_corrupt_pointer_falls_through(self, tmp_path):
        """指针 JSON 损坏 → except pass → 落到归属校验。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        (sd / ".gatekeeper.plan").write_text("{corrupt", encoding="utf-8")
        _write_state(sd / ".gatekeeper.state", str(sd))
        r = gsr.resolve_state(str(sd))
        assert r["source"] == "current"

    def test_marker_variant_not_misclassified(self, tmp_path):
        """含 SKILL_MARKER 前缀但末段目录名不同的变体（-copy）不误判归属。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        wt = "<home>/.trae/skills/spz-gatekeeper-r-sequence-copy"
        _write_state(sd / ".gatekeeper.state", wt)
        r = gsr.resolve_state(str(sd))
        assert r["conflict"] is True  # 变体不归属技能 → 冲突

    def test_arg_state_file_parse(self, tmp_path):
        """--state-file argv 覆盖默认 current。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        _write_state(sd / ".gatekeeper.state", str(tmp_path / "gatekeeper_project"))  # 脏
        env = dict(os.environ)
        env["PYTHONPATH"] = str(SCRIPT_DIR)
        r = subprocess.run(
            [sys.executable, str(SCRIPT_DIR / "gk_state_route.py"),
             "--skill-dir", str(sd), "--state-file", str(sd / ".gatekeeper.state")],
            capture_output=True, text=True, timeout=30, env=env)
        assert r.returncode == 0, r.stderr
        out = json.loads(r.stdout)
        assert out["current"] == str(sd / ".gatekeeper.state")


class TestDevWorktreeOwnership:
    """2026-09-01 扩展：开发 worktree 树（.trae/worktrees/ 等 IDE 受控根）为合法归属——
    worktree 隔离 state 的 worktree 字段指向主仓库 feature worktree（窄任务/节点执行级产物）。"""

    def test_dev_worktree_owned_wsl(self, tmp_path):
        sd = tmp_path / "skill"
        sd.mkdir()
        wt = "<home>/.trae/worktrees/spz_gatekeeper_project/feature/spz-gatekeeper-2.0.4-r7.1"
        _write_state(sd / ".gatekeeper.state.r7", wt)
        r = gsr.resolve_state(str(sd), state_file=str(sd / ".gatekeeper.state.r7"))
        assert r["conflict"] is False
        assert r["warning"] is None
        assert r["source"] == "current"

    def test_dev_worktree_owned_windows(self, tmp_path):
        sd = tmp_path / "skill"
        sd.mkdir()
        wt = r"<home>\.trae\worktrees\spz_gatekeeper_project\feature\spz-gatekeeper-2.0.4-r7.1"
        _write_state(sd / ".gatekeeper.state.r7", wt)
        r = gsr.resolve_state(str(sd), state_file=str(sd / ".gatekeeper.state.r7"))
        assert r["conflict"] is False

    def test_dev_worktree_superpowers_root(self, tmp_path):
        sd = tmp_path / "skill"
        sd.mkdir()
        wt = "/root/.config/superpowers/worktrees/spz_gatekeeper_project/feature/x"
        assert gsr._owned_by_skill(wt, str(sd)) is True

    def test_unrelated_worktree_still_conflict(self, tmp_path):
        """开发 worktree 根之外的路径仍判冲突（防归属放宽误伤安全网）。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        wt = "<home>/Downloads/gatekeeper_project"
        assert gsr._owned_by_skill(wt, str(sd)) is False


class TestWorktreeMatchRoute:
    """2026-09-01: worktree 匹配路由——当前 state 的 worktree 指向开发 worktree 时，
    路由到 worktree 精确匹配的唯一隔离 state（窄任务/节点产物随 worktree 隔离）。"""

    def test_routes_to_matching_isolated_state(self, tmp_path):
        sd = tmp_path / "skill"
        sd.mkdir()
        wt = "<home>/.trae/worktrees/spz_gatekeeper_project/feature/spz-gatekeeper-2.0.4-r7.1"
        _write_state(sd / ".gatekeeper.state", wt)          # 默认 state 指向开发 worktree
        _write_state(sd / ".gatekeeper.state.r7", wt)       # 隔离 state 同 worktree
        r = gsr.resolve_state(str(sd))
        assert r["source"] == "worktree_match"
        assert r["corrected"] is True
        assert r["expected"] == str(sd / ".gatekeeper.state.r7")
        assert r["conflict"] is False
        assert not r["warning"]

    def test_no_match_falls_through(self, tmp_path):
        """无 worktree 匹配的隔离 state → 不路由（归属校验照常）。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        wt = "<home>/.trae/worktrees/other/feature/x"
        _write_state(sd / ".gatekeeper.state", wt)          # 指向开发 worktree（合法归属）
        _write_state(sd / ".gatekeeper.state.r7", "<home>/.trae/worktrees/other/feature/y")
        r = gsr.resolve_state(str(sd))
        assert r["source"] == "current"                     # 无唯一匹配 → 不武断路由
        assert r["expected"] == str(sd / ".gatekeeper.state")

    def test_multiple_matches_no_route(self, tmp_path):
        """worktree 相同有多个隔离 state → 不路由（防武断）。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        wt = "<home>/.trae/worktrees/p/feature/a"
        _write_state(sd / ".gatekeeper.state", wt)
        _write_state(sd / ".gatekeeper.state.a", wt)
        _write_state(sd / ".gatekeeper.state.b", wt)
        r = gsr.resolve_state(str(sd))
        assert r["source"] == "current"                     # 多匹配 → 不路由

    def test_skill_worktree_not_rerouted(self, tmp_path):
        """worktree = 技能目录自身 → 不触发 worktree 匹配（无节点产物可隔离）。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        _write_state(sd / ".gatekeeper.state", str(sd))
        _write_state(sd / ".gatekeeper.state.r7", str(sd))
        r = gsr.resolve_state(str(sd))
        assert r["source"] == "current"
        assert r["expected"] == str(sd / ".gatekeeper.state")


class TestWorktreeMatchPhaseGuard:
    """2026-09-04: worktree 匹配须 r_phase 一致才路由——旧阶段隔离（R7/STAGE_0）带同
    worktree 字段却 checksum 失配，唯一命中会把活跃 campaign 顶替成旧阶段（guard TAMPERED）。"""

    def _write(self, path, r_phase, stage, wt):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"r_phase": r_phase, "stage": stage, "worktree": wt}),
                        encoding="utf-8")

    def test_phase_mismatch_no_route(self, tmp_path):
        """当前默认 R7.1 vs 唯一隔离候选 R7（同 worktree）→ 不路由，落回当前默认。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        wt = "<home>/.trae/worktrees/spz_gatekeeper_project/feature/spz-gatekeeper-2.0.4-r7.1"
        self._write(sd / ".gatekeeper.state", "R7.1", "STAGE_1", wt)      # 活跃默认
        self._write(sd / ".gatekeeper.state.r7", "R7", "STAGE_0", wt)      # 旧阶段同 worktree
        r = gsr.resolve_state(str(sd))
        assert r["source"] == "current"
        assert r["expected"] == str(sd / ".gatekeeper.state")
        assert r["corrected"] is False
        assert r["conflict"] is False

    def test_phase_match_still_routes(self, tmp_path):
        """候选 r_phase 与当前默认一致（R7.1）→ 正常 worktree 路由。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        wt = "<home>/.trae/worktrees/spz_gatekeeper_project/feature/spz-gatekeeper-2.0.4-r7.1"
        self._write(sd / ".gatekeeper.state", "R7.1", "STAGE_1", wt)
        self._write(sd / ".gatekeeper.state.r7.1", "R7.1", "STAGE_1", wt)
        r = gsr.resolve_state(str(sd))
        assert r["source"] == "worktree_match"
        assert r["expected"] == str(sd / ".gatekeeper.state.r7.1")
        assert r["corrected"] is True

    def test_stale_candidate_not_routed(self, tmp_path):
        """候选同 r_phase 但比当前默认旧（worktree 副本 vs 更新的默认）→ 不路由，防回退。"""
        import time as _t
        sd = tmp_path / "skill"
        sd.mkdir()
        wt = "<home>/.trae/worktrees/spz_gatekeeper_project/feature/spz-gatekeeper-2.0.4-r7.1"
        cur = sd / ".gatekeeper.state"
        iso = sd / ".gatekeeper.state.r7.1"
        self._write(cur, "R7.1", "STAGE_1", wt)
        self._write(iso, "R7.1", "STAGE_1", wt)
        now = _t.time()
        os.utime(str(cur), (now, now))
        os.utime(str(iso), (now - 7200, now - 7200))   # 候选 2h 旧
        r = gsr.resolve_state(str(sd))
        assert r["source"] == "current"
        assert r["expected"] == str(cur)
        assert r["corrected"] is False

    def test_phase_mismatch_multiple_candidates_no_route(self, tmp_path):
        """多候选（含旧阶段）本就多匹配不路由（回归既有语义，守卫不改变）。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        wt = "<home>/.trae/worktrees/spz_gatekeeper_project/feature/spz-gatekeeper-2.0.4-r7.1"
        self._write(sd / ".gatekeeper.state", "R7.1", "STAGE_1", wt)
        self._write(sd / ".gatekeeper.state.r7", "R7", "STAGE_0", wt)
        self._write(sd / ".gatekeeper.state.r7.1", "R7.1", "STAGE_1", wt)
        r = gsr.resolve_state(str(sd))
        assert r["source"] == "current"   # 两候选 → 不武断路由（守卫生效前已如此）
        assert r["expected"] == str(sd / ".gatekeeper.state")


class TestCliStyle:
    def test_cli_style_json(self, tmp_path):
        sd = tmp_path / "skill"
        sd.mkdir()
        _write_state(sd / ".gatekeeper.state", str(tmp_path / "gatekeeper_project"))
        _write_state(sd / ".gatekeeper.state.batch8", str(sd))
        env = dict(os.environ)
        env["PYTHONPATH"] = str(SCRIPT_DIR)
        r = subprocess.run(
            [sys.executable, str(SCRIPT_DIR / "gk_state_route.py"), "--skill-dir", str(sd)],
            capture_output=True, text=True, timeout=30, env=env)
        assert r.returncode == 0, r.stderr
        out = json.loads(r.stdout)
        assert out["corrected"] is True
        assert out["expected"] == str(sd / ".gatekeeper.state.batch8")

    # ── REV-5（2026-09-15）：独立入口 argv 契约（缺口 d / 四轮质询 G5）──

    def test_cli_unknown_option_fail_closed(self, tmp_path):
        """未知选项 **fail-closed exit 2**（含**单破折号**形态）—— 原判据只认 `--` 前缀
        ⟹ `-d` 被 `else: i += 1` 静默吞掉（"不静默忽略"只对一半形态成立）。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        _write_state(sd / ".gatekeeper.state", str(sd))
        env = dict(os.environ)
        env["PYTHONPATH"] = str(SCRIPT_DIR)
        for opt in ("-d", "--bogus"):
            r = subprocess.run(
                [sys.executable, str(SCRIPT_DIR / "gk_state_route.py"),
                 "--skill-dir", str(sd), opt],
                capture_output=True, text=True, timeout=30, env=env)
            assert r.returncode == 2, (opt, r.returncode, r.stdout, r.stderr)
            assert json.loads(r.stdout)["error"] == "UNKNOWN_OPTION", r.stdout

    def test_cli_domain_option_parsed(self, tmp_path):
        """`--domain <token>` 独立入口须**被解析**并触发 1b 步（修前 main 不解析 ⟹ 恒返 current）。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        _write_state(sd / ".gatekeeper.state", str(sd))
        _write_state(sd / ".gatekeeper.state.gp.r1", str(sd))
        env = dict(os.environ)
        env["PYTHONPATH"] = str(SCRIPT_DIR)
        r = subprocess.run(
            [sys.executable, str(SCRIPT_DIR / "gk_state_route.py"),
             "--skill-dir", str(sd), "--state-file", str(sd / ".gatekeeper.state"),
             "--plan-pointer", "/nonexistent", "--domain", "gp.r1"],
            capture_output=True, text=True, timeout=30, env=env)
        assert r.returncode == 0, r.stderr
        out = json.loads(r.stdout)
        assert out["source"] == "state_domain", out
        assert out["expected"] == str(sd / ".gatekeeper.state.gp.r1"), out


class TestPhase7bPointerTTL:
    """Phase 7b (2026-08-23): plan 指针 TTL — updated 超 24h 视为失效，
    fall through 到归属校验（safety_net 不被过期指针绕开）。"""

    def test_expired_pointer_falls_through(self, tmp_path):
        sd = tmp_path / "skill"
        sd.mkdir()
        from datetime import datetime, timedelta, timezone
        stale = (datetime.now(timezone.utc) - timedelta(hours=25)).strftime("%Y-%m-%dT%H:%M:%SZ")
        _write_state(sd / ".gatekeeper.state", str(sd))
        _write_state(sd / ".gatekeeper.state.batch8", str(sd))
        _write_pointer(sd / ".gatekeeper.plan", str(sd / ".gatekeeper.state.batch8"), updated=stale)
        r = gsr.resolve_state(str(sd))
        # 过期指针 → 不返回 plan_pointer；当前 state 归属正确 → source=current
        assert r["source"] == "current"
        assert r["expected"] == str(sd / ".gatekeeper.state")

    def test_fresh_pointer_respected(self, tmp_path):
        sd = tmp_path / "skill"
        sd.mkdir()
        _write_state(sd / ".gatekeeper.state", str(tmp_path / "gatekeeper_project"))  # 脏默认
        _write_state(sd / ".gatekeeper.state.batch8", str(sd))
        _write_pointer(sd / ".gatekeeper.plan", str(sd / ".gatekeeper.state.batch8"))  # fresh now
        r = gsr.resolve_state(str(sd))
        assert r["source"] == "plan_pointer"
        assert r["expected"] == str(sd / ".gatekeeper.state.batch8")

    def test_pointer_without_updated_stale(self, tmp_path):
        """旧格式指针（无 updated 字段）→ 视为过期 → fall through。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        _write_state(sd / ".gatekeeper.state", str(sd))
        _write_state(sd / ".gatekeeper.state.batch8", str(sd))
        (sd / ".gatekeeper.plan").write_text(
            json.dumps({"state_file": str(sd / ".gatekeeper.state.batch8"), "plan": "x"}),
            encoding="utf-8")
        r = gsr.resolve_state(str(sd))
        assert r["source"] == "current"

    def test_expired_pointer_safety_net_reengaged(self, tmp_path):
        """过期指针被忽略 → safety_net 重新生效（双计划残留时正确 WARN 不误纠）。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        from datetime import datetime, timedelta, timezone
        stale = (datetime.now(timezone.utc) - timedelta(hours=25)).strftime("%Y-%m-%dT%H:%M:%SZ")
        _write_state(sd / ".gatekeeper.state", str(tmp_path / "gatekeeper_project"))  # 脏默认
        _write_state(sd / ".gatekeeper.state.batch8", str(sd))
        _write_state(sd / ".gatekeeper.state.r7", str(sd))
        _write_pointer(sd / ".gatekeeper.plan", str(sd / ".gatekeeper.state.batch8"), updated=stale)
        r = gsr.resolve_state(str(sd))
        # 过期指针忽略 → 归属校验发现冲突 → 多候选不自动纠正（防误纠）
        assert r["conflict"] is True
        assert r["corrected"] is False
        assert len(r["candidates"]) == 2


class TestCrossRepoWorktreeRouting:
    """2026-09-04 方案 C P1/P2：跨仓库 worktree 就近 state 路由（额外根）——
    修复"worktree 匹配/候选扫描只查技能目录、其他仓库 worktree 隔离 state 漏检"。"""

    def test_extra_root_worktree_match(self, tmp_path):
        """隔离 state 在技能目录之外（就近 worktree 根），显式 extra-root → 命中路由。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        wt_root = tmp_path / "wt" / "repo" / "feature" / "r7.1"
        wt_root.mkdir(parents=True)
        fake_wt = "<home>/.trae/worktrees/repo/feature/r7.1"
        _write_state(sd / ".gatekeeper.state", fake_wt)           # 默认 state 指向跨仓库 worktree
        _write_state(wt_root / ".gatekeeper.state.r7", fake_wt)   # 隔离 state 就近在 worktree
        r = gsr.resolve_state(str(sd), extra_roots=[str(wt_root)])
        assert r["source"] == "worktree_match"
        assert r["expected"] == str(wt_root / ".gatekeeper.state.r7")
        assert r["corrected"] is True

    def test_extra_root_plain_colocated(self, tmp_path):
        """其他仓库就近存放裸 .gatekeeper.state（非 .*. 隔离名）→ 同样纳入匹配。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        wt_root = tmp_path / "wt" / "repo" / "feature" / "r9"
        wt_root.mkdir(parents=True)
        fake_wt = "<home>/.trae/worktrees/repo/feature/r9"
        _write_state(sd / ".gatekeeper.state", fake_wt)
        _write_state(wt_root / ".gatekeeper.state", fake_wt)
        r = gsr.resolve_state(str(sd), extra_roots=[str(wt_root)])
        assert r["source"] == "worktree_match"
        assert r["expected"] == str(wt_root / ".gatekeeper.state")
        assert r["corrected"] is True

    def test_auto_root_from_external_state_file(self, tmp_path):
        """自动扩根①：--state-file 位于技能目录之外 → 其所在目录自动成额外根（同址就近）。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        col = tmp_path / "co" / "repo"                            # 外部仓库同址目录
        col.mkdir(parents=True)
        fake_wt = "<home>/.trae/worktrees/repo/feature/r7.1"
        _write_state(col / ".gatekeeper.state", fake_wt)          # current：外部同址裸 state
        _write_state(col / ".gatekeeper.state.r8", fake_wt)       # 同址隔离 state（目标）
        r = gsr.resolve_state(str(sd), state_file=str(col / ".gatekeeper.state"))
        assert r["source"] == "worktree_match"
        assert r["expected"] == str(col / ".gatekeeper.state.r8")
        assert r["corrected"] is True

    def test_auto_root_from_cwd_worktree(self, tmp_path, monkeypatch):
        """自动扩根②：进程 cwd 位于开发 worktree 树（就近带 state 标记）→ 该 worktree 成额外根。"""
        dev = tmp_path / "dev" / "worktrees"                      # 模拟开发 worktree 根
        wt_dir = dev / "gp" / "feature" / "r7.1"
        wt_dir.mkdir(parents=True)
        # 归属匹配用归一化根（正斜杠、无尾斜杠——对齐 DEV_WORKTREE_ROOTS 规范形式）
        monkeypatch.setattr(gsr, "DEV_WORKTREE_ROOTS",
                            (str(dev).replace("\\", "/").rstrip("/"),))
        sd = tmp_path / "skill"
        sd.mkdir()
        own_wt = str(wt_dir)
        _write_state(sd / ".gatekeeper.state", own_wt)            # 默认 state 指向该 worktree
        _write_state(wt_dir / ".gatekeeper.state", own_wt)        # worktree 就近裸 state
        monkeypatch.chdir(wt_dir)
        r = gsr.resolve_state(str(sd))
        assert r["source"] == "worktree_match"
        assert r["expected"] == str(wt_dir / ".gatekeeper.state")
        assert r["corrected"] is True

    def test_no_field_only_expansion(self, tmp_path):
        """设计约束：仅 state.worktree 字段指向某 worktree（cwd 不在其中、state_file 未指外部）
        → 不自动扩根到该目录（防真实 worktree 混入普通流程）。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        real_like = tmp_path / "realworktree"
        real_like.mkdir()
        _write_state(sd / ".gatekeeper.state", str(real_like))    # 指向真实存在的目录
        _write_state(real_like / ".gatekeeper.state.r7", str(real_like))
        r = gsr.resolve_state(str(sd))                            # cwd 不在 real_like
        # wt=real_like 不在开发根/技能 → 归属冲突；无额外根 → 无候选 → 不自动纠正
        assert r["conflict"] is True
        assert r["corrected"] is False
        assert r["source"] == "safety_net"

    def test_env_roots_cli(self, tmp_path):
        """env GATEKEEPER_STATE_ROOTS 冒号分隔 → CLI 传额外根（跨仓库路由端到端）。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        wt_root = tmp_path / "wt" / "repo" / "feature" / "r7.1"
        wt_root.mkdir(parents=True)
        fake_wt = "<home>/.trae/worktrees/repo/feature/r7.1"
        _write_state(sd / ".gatekeeper.state", fake_wt)
        _write_state(wt_root / ".gatekeeper.state.r7", fake_wt)
        env = dict(os.environ, GATEKEEPER_STATE_ROOTS=str(wt_root))
        out = subprocess.run(
            [sys.executable, str(SCRIPT_DIR / "gk_state_route.py"),
             "--skill-dir", str(sd)],
            capture_output=True, text=True, timeout=30, env=env)
        assert out.returncode == 0, out.stderr
        d = json.loads(out.stdout)
        assert d["source"] == "worktree_match"
        assert d["expected"] == str(wt_root / ".gatekeeper.state.r7")

    def test_default_behavior_unchanged_no_extra(self, tmp_path):
        """未提供任何扩根信号 → 行为与旧版一致（候选只来自技能目录）。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        _write_state(sd / ".gatekeeper.state", str(tmp_path / "gatekeeper_project"))
        _write_state(sd / ".gatekeeper.state.batch8", str(sd))
        r = gsr.resolve_state(str(sd))
        assert r["source"] == "safety_net"
        assert r["corrected"] is True
        assert r["expected"] == str(sd / ".gatekeeper.state.batch8")
        assert len(r["candidates"]) == 1


class TestExplicitStateLazyScan:
    """ECC-7FF904ADF22C（2026-10-10 · L1 惰性化）：显式 state 下**跳过全量候选扫描**。

    判据 = **惰性化契约本身**（不是路由结论）：`_candidate_isolated_states` 是 glob（× 全
    extra_roots）+ **逐候选** `_load_worktree`/`_owned_by_skill`（含 git）的**全量索引**，实测
    ~1.3s/次（17 候选），是 CLI **每次启动**（启动块无条件跑 `resolve-state --derive-domain`）
    的固定开销主成分。显式注入态（env `STATE_FILE_EXPLICIT=1`，测试/集成/论文仓库等）下
    「自动纠正调用方显式指定的 state」与应用语义相悖 ⟹ 惰性化 = 不枚举、不纠正。

    ⚠ 用**计数 spy** 断言「是否发生扫描」，而非断言输出 —— 两侧 `conflict/corrected` 相同，
    唯一切实差别就是那次全量扫描有没有发生。黑盒触发面 = **env**（HEAD 无该 kwarg ⟹ 若用
    新参数会 TypeError 而非干净 assert 失败，故不用参数）。
    """

    def _setup_conflict(self, tmp_path):
        """造「归属冲突的默认 state」= step 4 的触发条件（worktree 指向外部仓 ⟹ 非本技能目录）。"""
        sd = tmp_path / "skill"
        sd.mkdir()
        _write_state(sd / ".gatekeeper.state", str(tmp_path / "gatekeeper_project"))
        return sd

    def _spy(self, monkeypatch):
        calls = {"n": 0}
        real = gsr._candidate_isolated_states

        def _counted(*a, **k):
            calls["n"] += 1
            return real(*a, **k)

        monkeypatch.setattr(gsr, "_candidate_isolated_states", _counted)
        return calls

    def test_explicit_state_skips_candidate_scan(self, tmp_path, monkeypatch):
        """显式态（env=1）⟹ **不得**发生候选扫描（红先：HEAD 上仍扫描 ⟹ 此断言失败）。"""
        sd = self._setup_conflict(tmp_path)
        monkeypatch.setenv("STATE_FILE_EXPLICIT", "1")
        monkeypatch.delenv("STATE_FILE", raising=False)
        monkeypatch.delenv("PLAN_POINTER", raising=False)
        calls = self._spy(monkeypatch)
        r = gsr.resolve_state(str(sd))
        assert calls["n"] == 0, (
            "显式 state（STATE_FILE_EXPLICIT=1）下仍发生全量候选扫描 —— 惰性化未生效"
            "（该扫描是每次 CLI 启动 ~1.3s 的固定开销）")
        assert r["conflict"] is True and r["corrected"] is False
        assert r["candidates"] == []
        assert r["source"] == "safety_net"

    def test_nonexplicit_state_still_scans(self, tmp_path, monkeypatch):
        """守卫臂（两侧皆绿）：**非显式**态必须保持候选扫描 ⟹ 既有安全网零回归。"""
        sd = self._setup_conflict(tmp_path)
        monkeypatch.delenv("STATE_FILE_EXPLICIT", raising=False)
        monkeypatch.delenv("STATE_FILE", raising=False)
        monkeypatch.delenv("PLAN_POINTER", raising=False)
        calls = self._spy(monkeypatch)
        r = gsr.resolve_state(str(sd))
        assert calls["n"] == 1, "非显式态必须保持候选扫描（防惰性化误伤安全网）"
        assert r["conflict"] is True

    def test_explicit_param_overrides_env(self, tmp_path, monkeypatch):
        """注入面单源：`state_file_explicit` 参数优先于 env（供 `gk_route_center` 单点透传）。"""
        sd = self._setup_conflict(tmp_path)
        monkeypatch.setenv("STATE_FILE_EXPLICIT", "0")  # env 说"非显式"
        monkeypatch.delenv("STATE_FILE", raising=False)
        monkeypatch.delenv("PLAN_POINTER", raising=False)
        calls = self._spy(monkeypatch)
        gsr.resolve_state(str(sd), state_file_explicit=True)  # 参数说"显式" ⟹ 跳过
        assert calls["n"] == 0, "参数未覆盖 env：显式态仍发生了候选扫描"

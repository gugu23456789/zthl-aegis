#!/usr/bin/env python3
"""Infra-2 红先臂：收敛评估器（质询轮次循环**早停编排层**）。

正本：`references/convergence-evaluator.md`（本次 Infra-2 建，**禁放 docs/plans**）。
架构（用户 2026-10-05 裁定 = **A 薄编排复用**）：本模块**只编排** —— r̂/N* 一律调
`gk_convergence_estimator`（数学核**单源**；禁第二实现）。
早停判据（用户 2026-10-05 裁定 = **参数化**）：`r̂ ≥ r_min 连续 K 轮`；`r_min`/`K` 走 env
（`GK_CONV_R_MIN` 默认 0.9 / `GK_CONV_K_ROUNDS` 默认 2）；kill switch `GK_CONV_EARLY_STOP`。

判据（HEAD 必红 —— 模块与正本尚不存在）：
  1) `step_ratios`：逐轮 stock 比 μ_n/μ_{n-1}（`prev==0` 跳过；负值 undefined）。
  2) `round_loop_verdict`：末尾 K 个 step ratio **全 ≥ r_min** ⟹ `NO_CONVERGENCE`。
  3) `no_convergence_finding`：仅 `NO_CONVERGENCE` 落 finding + `switch_to="M"`；幂等。
  4) 单源：`r_hat` 必须 == `gk_convergence_estimator.stock_ratio`（禁第二实现）。
"""
import json
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import gk_convergence_evaluator as V  # noqa: E402
import gk_convergence_estimator as E  # noqa: E402

PLAN = "/p/docs/plans/x-plan.md"
LONG_PLAN = "docs/plans/2026-09-14-convergence-evaluator-subplan.md"
REF = SCRIPT_DIR.parent / "references" / "convergence-evaluator.md"


def _state(tmp_path):
    d = {"gate_data": {"subagent_history": [], "ecc_findings": []}}
    p = tmp_path / "state.json"
    p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    return str(p)


def _findings(sf):
    return json.loads(Path(sf).read_text(encoding="utf-8"))["gate_data"]["ecc_findings"]


def _clear_env(monkeypatch):
    for k in ("GK_CONV_R_MIN", "GK_CONV_K_ROUNDS", "GK_CONV_EARLY_STOP"):
        monkeypatch.delenv(k, raising=False)


# ── step_ratios ─────────────────────────────────────────────────────────────

def test_step_ratios_basic():
    ratios, reason = V.step_ratios([8, 10, 9, 9])
    assert reason == "ok", reason
    assert len(ratios) == 3, ratios
    assert abs(ratios[0] - 1.25) < 1e-9 and abs(ratios[1] - 0.9) < 1e-9, ratios
    assert abs(ratios[2] - 1.0) < 1e-9, ratios


def test_step_ratios_skips_zero_prev():
    """`prev == 0` 不构成观测 ⟹ 跳过该对（禁按 1 计）。"""
    ratios, reason = V.step_ratios([0, 5, 5])
    assert reason == "ok", reason
    assert ratios == [1.0], ratios


def test_step_ratios_negative_is_undefined():
    ratios, reason = V.step_ratios([8, -2, 3])
    assert ratios is None and reason == "negative_mu", (ratios, reason)


def test_step_ratios_no_valid_pair():
    ratios, reason = V.step_ratios([0, 0])
    assert ratios == [] and reason == "no_valid_pair", (ratios, reason)


# ── round_loop_verdict（末尾 K 轮判据）───────────────────────────────────────

def test_round_loop_no_convergence_when_trailing_k_ge_rmin(monkeypatch):
    _clear_env(monkeypatch)
    r = V.round_loop_verdict([8, 10, 9, 9], r_min=0.9, k_rounds=2)
    assert r["verdict"] == "NO_CONVERGENCE", r
    assert r["trailing_k"] == [0.9, 1.0], r


def test_round_loop_converging_when_trailing_below(monkeypatch):
    _clear_env(monkeypatch)
    r = V.round_loop_verdict([8, 4, 2, 1], r_min=0.9, k_rounds=2)
    assert r["verdict"] == "CONVERGING", r


def test_round_loop_derives_r_hat_from_default(monkeypatch):
    """行情线：[8,4,2,1] ⟹ r̂=0.5，全程衰减 ⟹ CONVERGING。"""
    _clear_env(monkeypatch)
    r = V.round_loop_verdict([8, 4, 2, 1])
    assert r["verdict"] == "CONVERGING", r


def test_round_loop_insufficient_rounds_k_minus_1(monkeypatch):
    """可用 step ratio 数 < K ⟹ INSUFFICIENT_ROUNDS（禁臆断）。"""
    _clear_env(monkeypatch)
    r = V.round_loop_verdict([8, 4], r_min=0.9, k_rounds=2)
    assert r["verdict"] == "INSUFFICIENT_ROUNDS", r


def test_round_loop_boundary_exactly_k(monkeypatch):
    """恰有 K 个 step ratio ⟹ 够判（不是 INSUFFICIENT）。"""
    _clear_env(monkeypatch)
    r = V.round_loop_verdict([8, 4, 2], r_min=0.9, k_rounds=2)
    assert r["verdict"] == "CONVERGING", r


def test_round_loop_r_min_boundary_equal_triggers(monkeypatch):
    """恰等于 r_min ⟹ 计入（≥ 而非 >）。"""
    _clear_env(monkeypatch)
    r = V.round_loop_verdict([10, 9], r_min=0.9, k_rounds=1)
    assert r["verdict"] == "NO_CONVERGENCE", r


def test_round_loop_r_min_boundary_just_below(monkeypatch):
    """略低于 r_min ⟹ 不触发。"""
    _clear_env(monkeypatch)
    r = V.round_loop_verdict([100, 89], r_min=0.9, k_rounds=1)
    assert r["verdict"] == "CONVERGING", r


def test_round_loop_negative_mu_undefined(monkeypatch):
    _clear_env(monkeypatch)
    r = V.round_loop_verdict([8, -2, 3])
    assert r["verdict"] == "UNDEFINED", r
    assert r["reason"] == "negative_mu", r


def test_round_loop_single_source_r_hat(monkeypatch):
    """单源证明：本函数 r_hat 必须 == 评估器 `stock_ratio`（禁第二实现）。"""
    _clear_env(monkeypatch)
    seq = [8, 10, 9, 9]
    expected, _ = E.stock_ratio(seq)
    r = V.round_loop_verdict(seq, r_min=0.9, k_rounds=2)
    assert abs(r["r_hat"] - expected) < 1e-9, (r["r_hat"], expected)


def test_round_loop_env_r_min_override(monkeypatch):
    """env `GK_CONV_R_MIN` 生效（0.5 ⟹ [8,4,2] 的 0.5/0.5 恰好触发）。"""
    _clear_env(monkeypatch)
    monkeypatch.setenv("GK_CONV_R_MIN", "0.5")
    r = V.round_loop_verdict([8, 4, 2], k_rounds=2)
    assert r["r_min"] == 0.5, r
    assert r["verdict"] == "NO_CONVERGENCE", r


def test_round_loop_env_k_override(monkeypatch):
    """env `GK_CONV_K_ROUNDS` 生效（3 ⟹ 只有 2 个 step ratio ⟹ 不足）。"""
    _clear_env(monkeypatch)
    monkeypatch.setenv("GK_CONV_K_ROUNDS", "3")
    r = V.round_loop_verdict([8, 4, 2])
    assert r["k_rounds"] == 3, r
    assert r["verdict"] == "INSUFFICIENT_ROUNDS", r


# ── no_convergence_finding（落账 + 转 M）────────────────────────────────────

def test_no_convergence_finding_registered(tmp_path, monkeypatch):
    _clear_env(monkeypatch)
    sf = _state(tmp_path)
    res = V.no_convergence_finding(sf, PLAN, [8, 10, 9, 9], r_min=0.9, k_rounds=2)
    assert res["verdict"] == "NO_CONVERGENCE", res
    assert res["switch_to"] == "M", res
    fs = _findings(sf)
    assert len(fs) == 1 and "不收敛" in fs[0]["title"], fs
    assert PLAN in json.dumps(fs[0].get("anchors", [])), fs[0]


def test_no_convergence_finding_none_when_converging(tmp_path, monkeypatch):
    _clear_env(monkeypatch)
    sf = _state(tmp_path)
    res = V.no_convergence_finding(sf, PLAN, [8, 4, 2, 1], r_min=0.9, k_rounds=2)
    assert res["verdict"] == "CONVERGING", res
    assert _findings(sf) == [], "收敛中不得落 NO-CONVERGENCE"


def test_no_convergence_finding_idempotent(tmp_path, monkeypatch):
    _clear_env(monkeypatch)
    sf = _state(tmp_path)
    V.no_convergence_finding(sf, PLAN, [8, 10, 9, 9], r_min=0.9, k_rounds=2)
    V.no_convergence_finding(sf, PLAN, [8, 10, 9, 9], r_min=0.9, k_rounds=2)
    assert len(_findings(sf)) == 1, "同 plan 应幂等合并，不得新增镜像"


def test_no_convergence_finding_long_plan_root_key_within_limit(tmp_path, monkeypatch):
    """真态：长 plan 路径曾致 root_key > 64 字 ValueError（Infra-1 教训）。"""
    _clear_env(monkeypatch)
    sf = _state(tmp_path)
    res = V.no_convergence_finding(sf, LONG_PLAN, [8, 10, 9, 9], r_min=0.9, k_rounds=2)
    assert res.get("finding", {}).get("id", "").startswith("ECC-"), res
    assert len(_findings(sf)) == 1


def test_no_convergence_kill_switch_suppresses(tmp_path, monkeypatch):
    """`GK_CONV_EARLY_STOP=0` ⟹ 只出 verdict、不落 finding（拟设 kill switch）。"""
    _clear_env(monkeypatch)
    monkeypatch.setenv("GK_CONV_EARLY_STOP", "0")
    sf = _state(tmp_path)
    res = V.no_convergence_finding(sf, PLAN, [8, 10, 9, 9], r_min=0.9, k_rounds=2)
    assert res["verdict"] == "NO_CONVERGENCE", res
    assert res.get("suppressed") is True, res
    assert _findings(sf) == []


# ── 入口（python main；CLI 由 gatekeeper-cli.sh `pre-check convergence --loop` 转发）──

def _run_py(argv):
    import subprocess
    return subprocess.run([sys.executable, str(SCRIPT_DIR / "gk_convergence_evaluator.py"), *argv],
                          capture_output=True, text=True)


def test_entry_loop_verdict_only(tmp_path, monkeypatch):
    _clear_env(monkeypatch)
    r = _run_py(["loop", "--mu", "8,10,9,9"])
    assert r.returncode == 0, (r.returncode, r.stderr)
    out = json.loads(r.stdout)
    assert out["verdict"] == "NO_CONVERGENCE", out


def test_entry_loop_emit_finding_end_to_end(tmp_path, monkeypatch):
    _clear_env(monkeypatch)
    sf = _state(tmp_path)
    r = _run_py(["loop", "--state", sf, "--plan", PLAN, "--mu", "8,10,9,9", "--emit-finding"])
    assert r.returncode == 0, (r.returncode, r.stderr)
    out = json.loads(r.stdout)
    assert out["verdict"] == "NO_CONVERGENCE", out
    assert out.get("finding", {}).get("id", "").startswith("ECC-"), out
    assert len(_findings(sf)) == 1


# ── 正本 + 指针（Infra-2 交付 1）─────────────────────────────────────────────

def test_reference_doc_exists_and_covers_key_terms():
    """机制正本须在 `references/`（**禁放 docs/plans**），且含关键口径。"""
    assert REF.is_file(), f"缺正本：{REF}"
    txt = REF.read_text(encoding="utf-8")
    for term in ("r̂", "N*", "早停", "GK_CONV_R_MIN", "GK_CONV_K_ROUNDS"):
        assert term in txt, f"正本缺关键项：{term}"


def test_estimator_docstring_points_to_reference():
    """estimator 的『单一事实源』不得再指 docs/plans（须指 references/ 正本）。"""
    src = (SCRIPT_DIR / "gk_convergence_estimator.py").read_text(encoding="utf-8")
    assert "references/convergence-evaluator.md" in src, "estimator 未指向新正本"


def test_cli_precheck_loop_branch_forwards():
    """deliverable 4：`pre-check convergence --loop` 须转发到编排层（不新增 `_CMD_REG` 命令）。"""
    src = (SCRIPT_DIR.parent / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    assert "gk_convergence_evaluator.py" in src, "CLI 未引用编排层"
    assert "--loop" in src, "CLI 未接线 --loop"
    assert 'loop "$@"' in src, "CLI 未把剩余参数转发给编排层"


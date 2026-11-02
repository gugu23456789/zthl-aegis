#!/usr/bin/env python3
"""Infra-1a 红先臂：MoA 聚合落 ecc-finding（跨轮收敛比对的前置）。

正本：`references/convergence-evaluator.md`（拟建，**禁放 docs/plans**）。
关联：`ECC-1F540718AEE5`（审查轮次不收敛空转 → RCA 早停）。

判据（HEAD 必红 —— `emit_aggregate_finding` 尚不存在）：
  1) 落账：`emit_aggregate_finding` 在 `state.gate_data.ecc_findings` 落一条，锚 = 批身份。
  2) 幂等：同 (plan,batch) 二次调用 → 不新增（按 `root_key` 合并，单一台账）。
  3) fail-loud：无 plan 且无 batch（无锚）→ 不落账（`ok=False`），禁无锚 finding。
"""
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import gk_moa_aggregate as M  # noqa: E402

PLAN = "/p/docs/plans/x-plan.md"
BATCH = "abc123def456"


def _state(tmp_path, rows):
    """rows = [(subagent_id, batch_id, arm_group)]；task 含 PLAN 以便 plan 锚。"""
    hist = [{"subagent_id": sid, "batch_id": bid, "arm_group": g,
             "task": "plan-refinement: %s — 质询 %s" % (PLAN, sid),
             "conclusion": "结论" * 200,
             "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]}
            for (sid, bid, g) in rows]
    d = {"gate_data": {"subagent_history": hist, "ecc_findings": []}}
    p = tmp_path / "state.json"
    p.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    return str(p)


def _findings(sf):
    return json.loads(Path(sf).read_text(encoding="utf-8"))["gate_data"]["ecc_findings"]


def test_emit_registers_finding_anchored_to_batch(tmp_path):
    sf = _state(tmp_path, [("sub-%d" % i, BATCH, "G1") for i in range(6)])
    agg = M.aggregate(sf, None, "plan-refinement", plan=PLAN, batch=BATCH)
    res = M.emit_aggregate_finding(sf, agg, plan=PLAN, batch=BATCH)
    assert res.get("ok") is True, res
    fs = _findings(sf)
    assert len(fs) == 1, fs
    assert BATCH in fs[0].get("title", "") or BATCH in json.dumps(fs[0].get("anchors", [])), fs[0]


def test_emit_idempotent_by_root_key(tmp_path):
    sf = _state(tmp_path, [("sub-%d" % i, BATCH, "G1") for i in range(6)])
    agg = M.aggregate(sf, None, "plan-refinement", plan=PLAN, batch=BATCH)
    M.emit_aggregate_finding(sf, agg, plan=PLAN, batch=BATCH)
    M.emit_aggregate_finding(sf, agg, plan=PLAN, batch=BATCH)
    assert len(_findings(sf)) == 1, "同 (plan,batch) 应幂等合并，不得新增镜像"


def test_emit_without_anchor_is_refused(tmp_path):
    sf = _state(tmp_path, [("sub-1", BATCH, "G1")])
    agg = M.aggregate(sf, None, "plan-refinement", plan=PLAN, batch=BATCH)
    res = M.emit_aggregate_finding(sf, agg, plan="", batch="")
    assert res.get("ok") is False, res
    assert _findings(sf) == [], "无锚不得落 finding（fail-loud）"


# ── 2026-10-26：计划锚归一（同一计划三种路径形态 ⟹ 同一 root_key）────────────
def _emit_plan_only(sf, plan):
    agg = M.aggregate(sf, None, "plan-refinement", plan=PLAN, batch=BATCH)
    return M.emit_aggregate_finding(sf, agg, plan=plan, batch="")


def test_plan_only_anchor_normalized_across_path_forms(tmp_path):
    """实测 2026-10-04-audit-bureau-plan.md 并存三种写法（相对 / skills 绝对 / worktree 绝对）。

    旧实现对原始串取 sha256 ⟹ 同一计划落 3 个 root_key ⟹ `register` 的 root_key 幂等失效，
    台账出现同标题多条（RC0 实测 15 条里同计划多形态并存）。归一后须成一条。
    """
    sf = _state(tmp_path, [("sub-%d" % i, BATCH, "G1") for i in range(6)])
    forms = [
        "docs/plans/2026-10-04-audit-bureau-plan.md",
        "<home>/.trae/skills/spz-gatekeeper-r-sequence/docs/plans/2026-10-04-audit-bureau-plan.md",
        "<home>/.trae/worktrees/spz-gatekeeper-r-sequence/agent/audit-wall/7df45e1/docs/plans/2026-10-04-audit-bureau-plan.md",
    ]
    rks = {_emit_plan_only(sf, p)["finding"]["root_key"] for p in forms}
    assert len(rks) == 1, rks
    assert len(_findings(sf)) == 1, _findings(sf)


# ── Infra-1b：跨轮收敛比对（RCA ρ̂/N* ⟹ 早停）──────────────────────────────

def test_cross_round_flat_mu_triggers_early_stop():
    """本循环实测 μ 存量 [8,10,9,9] ⟹ r̂≈1.04 ≥ 1（μ 不降）⟹ 早停。"""
    r = M.cross_round_convergence([8, 10, 9, 9])
    assert r["early_stop"] is True, r
    assert r["r_hat"] is not None and r["r_hat"] >= 1.0, r


def test_cross_round_decaying_mu_no_stop():
    """存量衰减（[8,4,2,1]）⟹ r̂=0.5 < 1 ⟹ 不早停。"""
    r = M.cross_round_convergence([8, 4, 2, 1])
    assert r["early_stop"] is False, r
    assert r["r_hat"] is not None and r["r_hat"] < 1.0, r


def test_cross_round_single_source_r_hat():
    """单源证明：本函数 r_hat 必须 == 评估器 `stock_ratio`（禁第二实现）。"""
    import gk_convergence_estimator as E
    seq = [8, 10, 9, 9]
    expected, _ = E.stock_ratio(seq)
    r = M.cross_round_convergence(seq)
    assert abs(r["r_hat"] - expected) < 1e-9, (r["r_hat"], expected)


def test_cross_round_short_seq_no_stop():
    """轮数 <2 ⟹ r̂ 不可成形 ⟹ 不早停（禁单轮误判）。"""
    r = M.cross_round_convergence([8])
    assert r["early_stop"] is False, r


def test_estimator_mu0_excludes_measurement_findings():
    """② 白名单：测量 finding（`moa-agg:`/`noconv:`）**不计入** μ̂₀。"""
    import gk_convergence_estimator as E
    fs = [{"status": "open", "root_key": "real:1"},
          {"status": "open", "root_key": "moa-agg:abc"},
          {"status": "in_progress", "root_key": "noconv:def"},
          {"status": "closed", "root_key": "real:2"}]
    assert E.count_mu0(fs) == 1, E.count_mu0(fs)


def test_convergence_finding_registered_on_flat(tmp_path):
    sf = _state(tmp_path, [("sub-1", BATCH, "G1")])
    res = M.convergence_finding(sf, PLAN, [8, 10, 9, 9])
    assert res["early_stop"] is True, res
    fs = _findings(sf)
    assert len(fs) == 1 and "不收敛" in fs[0]["title"], fs
    assert PLAN in json.dumps(fs[0].get("anchors", [])), fs[0]


def test_convergence_finding_none_when_decaying(tmp_path):
    sf = _state(tmp_path, [("sub-1", BATCH, "G1")])
    res = M.convergence_finding(sf, PLAN, [8, 4, 2, 1])
    assert res["early_stop"] is False, res
    assert _findings(sf) == [], "衰减（收敛中）不得落 NO-CONVERGENCE"


# ── Infra-1c：CLI/入口接线（端到端）──────────────────────────────────────────

def _run_py(argv):
    import subprocess
    return subprocess.run([sys.executable, str(SCRIPT_DIR / "gk_moa_aggregate.py"), *argv],
                          capture_output=True, text=True)


def test_entry_emit_finding_end_to_end(tmp_path):
    sf = _state(tmp_path, [("sub-%d" % i, BATCH, "G1") for i in range(6)])
    r = _run_py(["--state", sf, "--plan", PLAN, "--batch", BATCH, "--emit-finding"])
    assert r.returncode == 0, (r.returncode, r.stderr)
    out = json.loads(r.stdout)
    assert out.get("finding", {}).get("ok") is True, out
    assert len(_findings(sf)) == 1


def test_entry_convergence_end_to_end(tmp_path):
    # 2026-10-14（ECC-50A0C5A3F2A8）：`--no-emit-finding` 已封闭 ⟹ 本臂不再靠它隔离被测量；
    # 有锚聚合 finding 与收敛 finding **两条都落**（各自按 root_key 幂等）。
    sf = _state(tmp_path, [("sub-1", BATCH, "G1")])
    r = _run_py(["--state", sf, "--plan", PLAN, "--convergence", "--mu", "8,10,9,9"])
    assert r.returncode == 0, (r.returncode, r.stderr)
    out = json.loads(r.stdout)
    assert out.get("convergence", {}).get("early_stop") is True, out
    assert out.get("finding", {}).get("ok") is True, out
    assert len(_findings(sf)) == 2, _findings(sf)


def test_entry_default_on_with_anchor(tmp_path):
    """T-b（2026-10-06，owner 裁定「每轮必落」）：有锚（--batch/--plan）⟹ 默认落 finding。"""
    sf = _state(tmp_path, [("sub-1", BATCH, "G1")])
    r = _run_py(["--state", sf, "--plan", PLAN, "--batch", BATCH])
    assert r.returncode == 0, (r.returncode, r.stderr)
    out = json.loads(r.stdout)
    assert out.get("finding", {}).get("ok") is True, out
    assert len(_findings(sf)) == 1


def test_entry_no_emit_finding_is_locked(tmp_path):
    """保护锁（`ECC-50A0C5A3F2A8`）：`--no-emit-finding` 已封闭 —— 有锚聚合 fail-loud（rc=2），禁抑制。"""
    sf = _state(tmp_path, [("sub-1", BATCH, "G1")])
    r = _run_py(["--state", sf, "--plan", PLAN, "--batch", BATCH, "--no-emit-finding"])
    assert r.returncode == 2, (r.returncode, r.stderr)
    out = json.loads(r.stdout)
    assert out.get("error") == "emit_finding_suppression_locked", out
    assert _findings(sf) == []


# ── 真态复现臂：长 plan 路径（曾致 root_key >64 字 ValueError）────────────────

LONG_PLAN = "docs/plans/2026-09-14-convergence-evaluator-subplan.md"


def test_emit_long_plan_path_root_key_within_limit(tmp_path):
    """真态：长 plan 路径曾使 root_key > 64 字 ⟹ ValueError（测试用短路径漏掉）。"""
    sf = _state(tmp_path, [("sub-%d" % i, BATCH, "G1") for i in range(6)])
    agg = M.aggregate(sf, None, "plan-refinement", plan=LONG_PLAN, batch=BATCH)
    res = M.emit_aggregate_finding(sf, agg, plan=LONG_PLAN, batch=BATCH)
    assert res.get("ok") is True, res
    assert len(_findings(sf)) == 1


def test_convergence_long_plan_path_root_key_within_limit(tmp_path):
    sf = _state(tmp_path, [("sub-1", BATCH, "G1")])
    res = M.convergence_finding(sf, LONG_PLAN, [8, 10, 9, 9])
    assert res.get("early_stop") is True, res
    assert len(_findings(sf)) == 1




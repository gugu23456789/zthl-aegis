#!/usr/bin/env python3
"""E25 三项机制修复的红先臂（2026-10-30；审计署计划 §28 E25 ⟹ switch_to=M）。

一轮六臂质询结论：0 PASS / 4 WARN / 1 BLOCKED，`r_hat=0.9597` NO_CONVERGENCE；
收敛器 `switch_to=M` = **机制修复**（不是「再跑 M 臂」）。三项落刀：

  A. B3a 动态读不变量 —— 载体在本目录 `test_gk_audit_consumers.py`
     （`test_reverse_no_unregistered_dynamic_domain_reader`）：`gk_audit_registry.register/dual_read`
     按 `domains` 参数动态读**同一批证据键**，原反向面只认字面键 ⟹ 必须登记为 `dynamic_reader`。
  B. E3 RED 命名空间 —— `_FINDING_ID_RE` 只收**大写段**，`RED-SURFACE-audit` 等混合大小写 id
     仍可绕过写侧闸（双边计价 I-2 一债一票被绕）；且读侧零检测（存量/篡改行不可见）。
  C. §17.8 行 397 关系不变量 —— `EDIT_BUDGET_CEILING=32` 与 `DECLARED_HARD_CAP=24` **语义不同**，
     **禁合并成同一常量**，只立 `DECLARED_HARD_CAP ≤ CEILING`；且 `_budget_view` 的实际放行
     读数面 `sessions.<sid>.remaining` 无外生上限（真缺口）。

本文件由主 agent 持有（族 `forbidden_paths` 含本文件）⟹ coder 不得改写判据。
"""
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import gk_credit_ledger as C  # noqa: E402
import gk_edit_gate as G  # noqa: E402

_OUT = {"model_version": "test-model", "temperature": 0.0, "seed": 0}


def _st(tmp: Path) -> str:
    return str(tmp / ".gatekeeper.state")


# ── B（写侧）：E3 命名空间必须覆盖混合大小写 RED-* ─────────────────────────────
@pytest.mark.parametrize("rid", ["RED-SURFACE-audit", "RED-Scope-02", "RED-migrate-X"])
def test_e3_mixed_case_red_id_rejected(tmp_path, rid):
    """写侧闸：混合大小写 RED id 与 `RED-SCOPE-02` 同口径拒写（原正则只收大写段）。"""
    st = _st(tmp_path)
    r = C.append(st, "success", ref=rid, key_dir="", **_OUT)
    assert r["ok"] is False, "RED-* 混合大小写未被拒: %s -> %r" % (rid, r)
    assert "outcome_ref_namespace_violation" in r["error"], r
    assert not Path(str(st) + C.SUFFIX).exists(), "被拒的 RED-* ref 仍落盘: %s" % rid


# ── B（读侧）：存量 / 篡改行必须被检测到 ─────────────────────────────────────
def test_e3_read_side_detects_finding_id_refs(tmp_path):
    """读侧检测臂：绕过 append 闸落进账本的 finding id ref 必须在读侧可见。"""
    st = _st(tmp_path)
    Path(str(st) + C.SUFFIX).write_text(
        json.dumps({"kind": "success", "delta": 5, "ref": "RED-SURFACE-audit"},
                   ensure_ascii=False) + "\n",
        encoding="utf-8")
    _, stat = C.read_records(st)
    assert stat.get("ref_violations") == 1, "读侧未检测 finding id ref: %r" % (stat,)
    rec = C.reconcile(st)
    assert rec.get("ref_violations") == ["RED-SURFACE-audit"], rec


def test_e3_reconcile_fails_on_ref_violation(tmp_path):
    """读侧**闸**（2026-10-30 收口）：违规 ref 不只可见，必须让对账判 `ok=False`。

    理由：`ref_violations` 是「审计产物进了货币账」的直接证据（I-2 一债一票被绕）；
    只暴露不判败 = 读侧仍可被当作「对账通过」（§28.2 原边界）。实测存量账本零违规 ⟹ 无迁移风险。
    """
    st = _st(tmp_path)
    Path(str(st) + C.SUFFIX).write_text(
        json.dumps({"kind": "success", "delta": 5, "ref": "RED-SURFACE-audit"},
                   ensure_ascii=False) + "\n",
        encoding="utf-8")
    rec = C.reconcile(st)
    assert rec.get("ok") is False, "违规 ref 未触发对账失败（读侧只检测不拦截）: %r" % (rec,)
    assert rec.get("ref_violations") == ["RED-SURFACE-audit"], rec


# ── C（关系不变量）：两个常量语义不同，禁合并同值 ─────────────────────────────
def test_c_declared_hard_cap_not_above_ceiling():
    from gk_advance import EDIT_BUDGET_CEILING
    from gk_route_center import DECLARED_HARD_CAP
    assert 0 < DECLARED_HARD_CAP <= EDIT_BUDGET_CEILING, (
        "DECLARED_HARD_CAP(%s) 越过 EDIT_BUDGET_CEILING(%s)：反棘轮可被声明穿透"
        % (DECLARED_HARD_CAP, EDIT_BUDGET_CEILING))


def test_c_constants_remain_independent_symbols():
    """「合并成同一常量」是**错误方向**：两常量语义不同，须各自有独立定义点。"""
    import gk_advance
    import gk_route_center
    rc = Path(gk_route_center.__file__).read_text(encoding="utf-8")
    ad = Path(gk_advance.__file__).read_text(encoding="utf-8")
    assert "DECLARED_HARD_CAP = " in rc, "gk_route_center.DECLARED_HARD_CAP 定义点丢失"
    assert "EDIT_BUDGET_CEILING = " in ad, "gk_advance.EDIT_BUDGET_CEILING 定义点丢失"


# ── C（放行读数面）：`_budget_view` 的实际放行值必须受 CEILING 夹取 ────────────
def test_c_budget_view_clamps_session_remaining():
    from gk_advance import EDIT_BUDGET_CEILING
    d = {"gate_data": {"edit_budget": {"max": 32, "sessions": {
        "s1": {"remaining": 999, "max": 999, "used": 0}}}}}
    bv = G._budget_view(d, "s1")
    assert bv["remaining"] <= EDIT_BUDGET_CEILING, (
        "sessions.<sid>.remaining 无外生上限（放行读数面可被写到 999）: %r" % (bv,))


def test_c_budget_view_clamps_global_remaining():
    from gk_advance import EDIT_BUDGET_CEILING
    d = {"gate_data": {"edit_budget": {"remaining": 999, "max": 999, "used": 0}}}
    bv = G._budget_view(d, "")
    assert bv["remaining"] <= EDIT_BUDGET_CEILING, bv


def test_c_budget_view_preserves_unset_sentinel():
    """`-1` = 未配置（不拦）⟹ 夹取不得改写哨兵语义。"""
    bv = G._budget_view({"gate_data": {}}, "s1")
    assert bv["remaining"] == -1, bv

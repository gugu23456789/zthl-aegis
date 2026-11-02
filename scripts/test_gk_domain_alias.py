#!/usr/bin/env python3
"""§17-1 红先臂：域 token 双形态归一（别名读映射 + 双形态检测告警）。

正本：`docs/plans/2026-09-28-state-single-authority-plan.md` §17-1
（成员 `ECC-55339EF8A5C6` 的 (b) 半段「域 token 形态不一致」）。

现场（2026-10-03 实测）：同计划并存两种域 token 形态 ——
  `.gatekeeper.state.<plan>`（无 repo 段）  vs  `.gatekeeper.state.skill.<plan>`（带 `skill.` 段）
`_DOMAIN_TOKEN_RE` 两形态都合法 ⟹ 无门拦、双形态自由生长；解析到「无段者」（0 条）即**漏**另一形态的 finding。

判据（红先，HEAD 必红）：
  ① 别名读映射：目标形态缺失而**另一形态存在** ⟹ 读映射到存在者（**不建/不迁/不改物理文件**）；
     两形态皆缺 ⟹ 仍 `FINDING_DOMAIN_STATE_MISSING`（fail-closed，不静默回退）。
  ③ 双形态检测告警：只读报「同计划双形态并存」；异 repo 同基名（`gatekeeper.r7`/`spz2glb.r7`/`r7`）**不得**误报。
"""
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import gk_finding as F  # noqa: E402

PLAN = "2026-07-26-zthl-harness-adapter-plan"


def _mk_states(tmp_path, tokens):
    """在 tmp 目录造 `.gatekeeper.state.<token>`（返回基准 state 路径）。"""
    for t in tokens:
        (tmp_path / (".gatekeeper.state." + t)).write_text(
            json.dumps({"gate_data": {"ecc_findings": []}}), encoding="utf-8")
    return str(tmp_path / ".gatekeeper.state")


# ── ① 别名读映射 ───────────────────────────────────────────────────────────

def test_alias_from_bare_token_maps_to_skill_form(tmp_path):
    """裸 token（无 repo 段）缺失、`skill.<plan>` 存在 ⟹ 读映射到后者。"""
    base = _mk_states(tmp_path, ["skill." + PLAN])
    r = F.resolve_domain_state_ex(base, PLAN)
    assert r["path"].endswith(".gatekeeper.state.skill." + PLAN), r
    assert r["alias_from"] == PLAN and r["alias_to"] == "skill." + PLAN, r


def test_alias_from_skill_token_maps_to_bare_form(tmp_path):
    """`skill.<plan>` 缺失、裸 `<plan>` 存在 ⟹ 读映射到后者。"""
    base = _mk_states(tmp_path, [PLAN])
    r = F.resolve_domain_state_ex(base, "skill." + PLAN)
    assert r["path"].endswith(".gatekeeper.state." + PLAN), r
    assert r["alias_from"] == "skill." + PLAN and r["alias_to"] == PLAN, r


def test_no_alias_zero_regression(tmp_path):
    """目标即存在 ⟹ 逐字返回、无别名（零回归）。"""
    base = _mk_states(tmp_path, [PLAN, "skill." + PLAN])
    r = F.resolve_domain_state_ex(base, PLAN)
    assert r["path"].endswith(".gatekeeper.state." + PLAN), r
    assert r["alias_from"] == "" and r["alias_to"] == "", r


def test_str_wrapper_returns_path(tmp_path):
    """`resolve_domain_state`（str 薄壳）仍返回路径（既有调用方零回归）。"""
    base = _mk_states(tmp_path, ["skill." + PLAN])
    assert F.resolve_domain_state(base, PLAN).endswith(".gatekeeper.state.skill." + PLAN)


def test_both_missing_still_fail_closed(tmp_path):
    """两形态都缺 ⟹ 仍 `FINDING_DOMAIN_STATE_MISSING`（不静默回退默认 state）。"""
    base = _mk_states(tmp_path, [])
    try:
        F.resolve_domain_state_ex(base, PLAN)
        assert False, "应 fail-closed"
    except ValueError as e:
        assert "FINDING_DOMAIN_STATE_MISSING" in str(e), e


def test_invalid_token_still_rejected(tmp_path):
    """非法 token 仍拒（别名不放松校验）。"""
    base = _mk_states(tmp_path, [PLAN])
    try:
        F.resolve_domain_state_ex(base, "a/b")
        assert False, "应拒非法 token"
    except ValueError as e:
        assert "非法 token" in str(e), e


# ── ③ 双形态检测告警（只读）───────────────────────────────────────────────

def test_dual_form_detection_hits(tmp_path):
    """同计划两形态并存 ⟹ 报 1 条（含 base 与 forms）。"""
    base = _mk_states(tmp_path, [PLAN, "skill." + PLAN])
    dual = F.dual_form_domains(base)
    assert len(dual) == 1, dual
    assert dual[0]["base"] == PLAN, dual
    assert set(dual[0]["forms"]) == {PLAN, "skill." + PLAN}, dual


def test_dual_form_ignores_cross_repo_same_base(tmp_path):
    """异 repo 同基名（`gatekeeper.r7`/`spz2glb.r7`/`r7`）**不得**误报为双形态。"""
    base = _mk_states(tmp_path, ["gatekeeper.r7", "spz2glb.r7", "r7"])
    assert F.dual_form_domains(base) == [], F.dual_form_domains(base)


def test_dual_form_single_form_clean(tmp_path):
    """单形态（含仅 `skill.` 形态）⟹ 0 条。"""
    base = _mk_states(tmp_path, ["skill." + PLAN])
    assert F.dual_form_domains(base) == [], F.dual_form_domains(base)

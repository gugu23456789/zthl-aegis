"""计划定稿门 + 域 state 种子盒（方案 A，owner 2026-11-14）。

判据（owner 裁定「按方案 A 执行」）：
  · `META.plan_status` 是**唯一**定稿判据；**`frozen` 缺省**（未定稿必须显式写 `draft`）。
  · **未定稿** ⟹ 不跟随 plan 指针、META 域不落域 state（编辑额度回主 state）；
    定稿（`frozen`）才接域路由。
  · 域 state 建库时由 META `edit_budget_declared` 注入**种子盒**
    （`gate_data.edit_budget`）—— 此前 `derive_state_seed` 恒写 `gate_data={}`，
    声明额度只在 standing 注入时落地 ⟹ 「每个计划有独立额度」长期是模糊机制。

零回归边界：指针 `plan` 解析不到计划文件（历史指针 / 测试夹具）⟹ `plan_is_draft`
返回 False ⟹ 既有路由行为逐字不变。
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import gk_route_center as grc  # noqa: E402
import pre_tool_hook as hook  # noqa: E402


def _write_plan(sd: Path, stem: str, *, status=None, domain="gp.psarm",
                declared=None, phases="R1") -> Path:
    d = sd / "docs" / "plans"
    d.mkdir(parents=True, exist_ok=True)
    lines = ["<!-- META", "phases: %s" % phases, "target_repo: skill",
             "project_type: implementation", "worktree_needed: false"]
    if domain:
        lines.append("state_domain: %s" % domain)
    if declared is not None:
        lines.append("edit_budget_declared: %s" % declared)
    if status is not None:
        lines.append("plan_status: %s" % status)
    lines += ["-->", "", "# %s" % stem, ""]
    p = d / (stem + ".md")
    p.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    return p


def _write_state(path: Path, worktree) -> Path:
    path.write_text(json.dumps({"r_phase": "R1", "stage": "STAGE_0",
                                "worktree": str(worktree), "gate_data": {}}),
                    encoding="utf-8", newline="\n")
    return path


def _write_pointer(sd: Path, state_file: Path, plan: str) -> Path:
    p = sd / ".gatekeeper.plan"
    p.write_text(json.dumps({"state_file": str(state_file), "plan": plan,
                             "updated": datetime.now(timezone.utc).isoformat()}),
                 encoding="utf-8", newline="\n")
    return p


def _sandbox(tmp_path):
    sd = tmp_path / "skill"
    sd.mkdir()
    base = _write_state(sd / ".gatekeeper.state", sd)
    return sd, base


# ── 判据单源 ─────────────────────────────────────────────────────────────

def test_plan_status_default_is_frozen():
    # 缺省 frozen（存量计划不因缺字段而失去域路由）；未定稿必须显式 draft。
    assert grc.plan_status({}) == grc.PLAN_STATUS_FROZEN
    assert grc.plan_status({"plan_status": ""}) == grc.PLAN_STATUS_FROZEN
    assert grc.plan_status({"plan_status": "DRAFT"}) == grc.PLAN_STATUS_DRAFT
    # 非法值按缺省 frozen（由 plan-lint 报 medium 提示作者订正）
    assert grc.plan_status({"plan_status": "frozen?"}) == grc.PLAN_STATUS_FROZEN


def test_unresolvable_plan_is_not_draft(tmp_path):
    """零回归边界：解析不到计划文件 ⟹ 不判 draft（历史指针 plan='x' 不受影响）。"""
    sd = tmp_path / "skill"
    sd.mkdir()
    assert grc.plan_is_draft("no-such-plan-ps-arm", str(sd)) is False


# ── 指针门：draft 不跟随 / frozen 跟随 ───────────────────────────────────

def test_draft_plan_pointer_not_followed(tmp_path):
    sd, base = _sandbox(tmp_path)
    plan = _write_plan(sd, "psarm-draft", status="draft")
    dom = _write_state(sd / ".gatekeeper.state.gp.psarm", sd)
    _write_pointer(sd, dom, plan.stem)

    r = grc.resolve_state(str(sd), state_file=str(base))
    assert r["expected"] == str(base), r
    assert r.get("pointer_followed") is False, r
    assert r.get("pointer_reason") == "plan_draft", r


def test_missing_plan_status_treated_frozen(tmp_path):
    """缺省 = frozen：未写 plan_status 的计划保持域路由（存量零回归）。"""
    sd, base = _sandbox(tmp_path)
    plan = _write_plan(sd, "psarm-nostatus", status=None)
    dom = _write_state(sd / ".gatekeeper.state.gp.psarm", sd)
    _write_pointer(sd, dom, plan.stem)

    r = grc.resolve_state(str(sd), state_file=str(base))
    assert r["expected"] == str(dom), r
    assert r.get("pointer_followed") is True, r


def test_frozen_plan_pointer_followed(tmp_path):
    sd, base = _sandbox(tmp_path)
    plan = _write_plan(sd, "psarm-frozen", status="frozen")
    dom = _write_state(sd / ".gatekeeper.state.gp.psarm", sd)
    _write_pointer(sd, dom, plan.stem)

    r = grc.resolve_state(str(sd), state_file=str(base))
    assert r["expected"] == str(dom), r
    assert r.get("pointer_followed") is True, r


def test_explicit_pointer_also_gated(tmp_path):
    """启动块把已选定指针经 argv 显式传入（②b）⟹ 显式面同样过定稿门（防假绿）。"""
    sd, base = _sandbox(tmp_path)
    plan = _write_plan(sd, "psarm-explicit", status="draft")
    dom = _write_state(sd / ".gatekeeper.state.gp.psarm", sd)
    ptr = _write_pointer(sd, dom, plan.stem)

    r = grc.resolve_state(str(sd), state_file=str(base), plan_pointer=str(ptr))
    assert r["expected"] == str(base), r


# ── 域门：draft 不落域 / frozen 落域 ─────────────────────────────────────

def test_resolve_state_cli_draft_does_not_route_domain(tmp_path):
    sd, base = _sandbox(tmp_path)
    plan = _write_plan(sd, "psarm-cli-draft", status="draft", domain="gp.clidraft")
    _write_state(sd / ".gatekeeper.state.gp.clidraft", sd)

    r = grc.resolve_state_cli(str(sd), str(base), plan_file=str(plan))
    assert r["expected"] == str(base), r
    assert r.get("source") != "state_domain", r


def test_resolve_state_cli_frozen_routes_domain(tmp_path):
    sd, base = _sandbox(tmp_path)
    plan = _write_plan(sd, "psarm-cli-frozen", status="frozen", domain="gp.clifrozen")
    dom = _write_state(sd / ".gatekeeper.state.gp.clifrozen", sd)

    r = grc.resolve_state_cli(str(sd), str(base), plan_file=str(plan))
    assert r["expected"] == str(dom), r
    assert r.get("source") == "state_domain", r


def test_explicit_domain_flag_is_escape_hatch(tmp_path):
    """显式 `--domain` 属人工逃生舱：不因计划 draft 被静默丢弃。"""
    sd, base = _sandbox(tmp_path)
    _write_plan(sd, "psarm-escape", status="draft", domain="gp.escape")
    dom = _write_state(sd / ".gatekeeper.state.gp.escape", sd)

    r = grc.resolve_state_cli(str(sd), str(base), domain="gp.escape")
    assert r["expected"] == str(dom), r


# ── 种子盒 ───────────────────────────────────────────────────────────────

def test_seed_injects_declared_budget_box(tmp_path):
    sd, _ = _sandbox(tmp_path)
    plan = _write_plan(sd, "psarm-seed", declared=12, domain="gp.seed")
    out = grc.derive_state_seed(str(plan), str(sd))
    assert out.get("error") is None, out
    assert out["seed"]["gate_data"]["edit_budget"] == {
        "max": 12, "used": 0, "remaining": 12, "overrides": []}, out


def test_seed_without_declared_has_empty_gate_data(tmp_path):
    sd, _ = _sandbox(tmp_path)
    plan = _write_plan(sd, "psarm-seed-none", declared=None, domain="gp.seed2")
    out = grc.derive_state_seed(str(plan), str(sd))
    assert out["seed"]["gate_data"] == {}, out


def test_seed_declared_zero_not_injected(tmp_path):
    sd, _ = _sandbox(tmp_path)
    plan = _write_plan(sd, "psarm-seed-zero", declared=0, domain="gp.seed3")
    out = grc.derive_state_seed(str(plan), str(sd))
    assert out["seed"]["gate_data"] == {}, out


# ── hook 侧同判据（域指针不复活）─────────────────────────────────────────

def test_hook_ignores_draft_pointer(tmp_path, monkeypatch):
    sd, base = _sandbox(tmp_path)
    plan = _write_plan(sd, "psarm-hook-draft", status="draft")
    dom = _write_state(sd / ".gatekeeper.state.gp.hook", sd)
    _write_pointer(sd, dom, plan.stem)

    monkeypatch.setattr(hook, "SKILL_DIR", sd)
    monkeypatch.setattr(hook, "GOVERNED_SCOPES", {})
    monkeypatch.setattr(hook, "_win_to_wsl", lambda p: p)
    assert hook._resolve_state_by_cwd(str(sd)) == base


def test_hook_follows_frozen_pointer(tmp_path, monkeypatch):
    sd, base = _sandbox(tmp_path)
    plan = _write_plan(sd, "psarm-hook-frozen", status="frozen")
    dom = _write_state(sd / ".gatekeeper.state.gp.hook2", sd)
    _write_pointer(sd, dom, plan.stem)

    monkeypatch.setattr(hook, "SKILL_DIR", sd)
    monkeypatch.setattr(hook, "GOVERNED_SCOPES", {})
    monkeypatch.setattr(hook, "_win_to_wsl", lambda p: p)
    assert hook._resolve_state_by_cwd(str(sd)) == dom

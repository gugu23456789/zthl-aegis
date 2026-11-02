#!/usr/bin/env python3
"""test_gk_state_domain_linkage.py — 域绑定**三级联动**红先臂（ECC-F2E2F9E07AC2，2026-09-26）
================================================================================================
断点（读码实测，见 docs/analysis/ecc-e2d00bbce954-evidence.md 追加节）：
  ① `target_repo` 与 `state_domain` **并列但无推导**（`gk_route_center._META_FIELDS` 仅并排列出，
     `meta_state_domain()` 只回已声明值）⟹ 「目标仓=X」推不出「state 域=X」；
  ② `state_domain` 机检门**只挂 `worktree_needed=true`**（`gk_plan_lint.check_meta` /
     `gk_route_center.calibration_from_route`）⟹ `worktree_needed=false` 的**跨仓**计划
     （如 zthl-adapter）连「应声明域」的机检都被 SKIP，finding 可静默错落技能默认 state。

臂（全部为**行为臂**：被测符号/判定面在 HEAD 缺席或恒 SKIP ⟹ 落刀前必红）：
  arm57  `derive_state_domain(meta, plan_file)` 推导 `<target_repo>.<plan-basename>`（声明优先）
  arm58  `gk_plan_lint.check_meta`：跨仓 + `worktree_needed=false` + 未声明域 ⟹ 命中 L-META 并报出可推导域
  arm60  `gk_route_center.calibration_from_route`：同上形态 ⟹ `state_domain` 项 FAIL（不再 SKIP）
非红回归臂（**不入选红先集**）：
  arm59  自指 `target_repo: skill` + `worktree_needed=false` + 未声明域 ⟹ **L-META high**
         （2026-10-04 §18.2 判据 c6 升级：自指且不建 worktree ⟹ 并发会话共享 base state）
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

PLAN_STEM = "2026-09-25-zthl-adapter"
DERIVED = "zthl-adapter." + PLAN_STEM


def _mk_plan(tmp_path: Path, lines) -> Path:
    p = tmp_path / (PLAN_STEM + ".md")
    p.write_text("<!-- META\n" + "\n".join(lines) + "\n-->\n\n# T\n", encoding="utf-8")
    return p


def _mk_repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    (r / "docs" / "plans").mkdir(parents=True, exist_ok=True)
    (r / "a.py").write_text("pass\n", encoding="utf-8")
    return r


def _mk_skill(tmp_path: Path, phase: str = "R7.1") -> Path:
    """最小技能目录 + 默认 state（worktree 指向技能自身 = 默认归属）。"""
    sd = tmp_path / "skill"
    sd.mkdir()
    st = sd / ".gatekeeper.state"
    st.write_text(json.dumps({"r_phase": phase, "stage": "STAGE_0", "worktree": str(sd),
                              "gate_data": {"narrow_tasks": []}}), encoding="utf-8")
    return sd


# ── arm57：`target_repo → state_domain` 推导（单一事实源）────────────────────
def test_arm57_derive_state_domain_from_target_repo(tmp_path):
    """未声明域时按 `<target_repo>.<plan-basename>` 推导；已声明则声明优先（不覆盖）。"""
    import gk_route_center as grc
    plan = _mk_plan(tmp_path, ["phases: R7.1", "target_repo: zthl-adapter",
                              "project_type: standard", "worktree_needed: false"])
    meta = {"phases": "R7.1", "target_repo": "zthl-adapter",
            "project_type": "standard", "worktree_needed": "false"}
    assert grc.derive_state_domain(meta, str(plan)) == DERIVED
    # 声明优先：显式 state_domain 不被推导覆盖
    assert grc.derive_state_domain(dict(meta, state_domain="a.b"), str(plan)) == "a.b"
    # 缺 target_repo / 缺计划路径 ⟹ 无推导（不臆造）
    assert grc.derive_state_domain({"phases": "R7.1"}, str(plan)) == ""
    assert grc.derive_state_domain(meta, "") == ""
    # 非 ASCII / 非法 token 形态 ⟹ 不产出非法域
    assert grc.derive_state_domain({"target_repo": "仓/名"}, str(plan)) == ""


# ── arm58：机检门与 worktree_needed 解耦（跨仓即强制）────────────────────────
def test_arm58_lint_flags_cross_repo_without_state_domain(tmp_path):
    """跨仓计划（target_repo 非自指）未声明 state_domain ⟹ L-META 命中，且报出可推导域。"""
    import gk_plan_lint as pl
    repo = _mk_repo(tmp_path)
    plan = _mk_plan(tmp_path, ["phases: R7.1", "target_repo: zthl-adapter",
                              "project_type: standard", "worktree_needed: false"])
    f = pl.lint(str(plan), str(repo))
    hits = [x for x in f if x[0] == "L-META" and "state_domain" in x[2]]
    assert hits, f
    assert DERIVED in hits[0][2]


# ── arm60：运行时校准同判（不再 SKIP）──────────────────────────────────────
def test_arm60_calibration_flags_cross_repo_without_domain(tmp_path):
    """跨仓 + 未声明域 ⟹ 校准 `state_domain` 项 FAIL（HEAD：worktree_needed=false ⟹ SKIP）。"""
    import gk_route_center as grc
    sd = _mk_skill(tmp_path)
    plan = _mk_plan(tmp_path, ["phases: R7.1", "target_repo: zthl-adapter",
                              "project_type: standard", "worktree_needed: false"])
    cal = grc.route_all(str(sd), plan_file=str(plan), calibrate=True)["calibration"]
    sdck = [c for c in cal["checks"] if c["item"] == "state_domain"][0]
    assert sdck["status"] == "FAIL", sdck
    assert cal["consistent"] is False


# ── arm59（非红回归臂，不入选红先集）：自指计划的判据随 §18.2-c6 升级 ──────────
def test_arm59_self_repo_without_domain_flags_high(tmp_path):
    """判据钉：`target_repo: skill`（自指）+ `worktree_needed=false` + 未声明域 ⟹ **L-META high**。

    2026-10-27（U3 归因）：本臂原断言「零 L-META」，立于 2026-10-04 前的旧判据；§18.2 判据 c6
    落地后该形态**应当**被报（`gk_plan_lint.py` 的 `not dom and self_skill and not wt` ⟹ high，
    理由 = 并发会话共享 base state：抢锁 + 多域台账分裂，见 ECC-46C22B11AD85）。此处保留臂的
    原意「自指形态的判据钉」，把断言方向同步到 c6（并钉住级别 + 可推导域提示）。
    """
    import gk_plan_lint as pl
    repo = _mk_repo(tmp_path)
    plan = _mk_plan(tmp_path, ["phases: R7.1", "target_repo: skill",
                              "project_type: standing", "worktree_needed: false"])
    f = pl.lint(str(plan), str(repo))
    hits = [x for x in f if x[0] == "L-META"]
    assert len(hits) == 1, f
    assert hits[0][1] == "high", hits[0]
    assert "state_domain" in hits[0][2], hits[0]
    assert "skill." + PLAN_STEM in hits[0][2], f"未报出可推导域：{hits[0][2]}"

#!/usr/bin/env python3
"""② 命名形态分类器 + 写门契约测。"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_state_forms as gsf  # noqa: E402


@pytest.mark.parametrize("name,expect", [
    (".gatekeeper.state", "base"),
    (".gatekeeper.state.gatekeeper.r7", "domain"),
    (".gatekeeper.state.r7", "domain"),
    (".gatekeeper.state.2026-09-21-review-runtime-subplan", "legacy_plan"),
    # 挑战8 订正：复合形态（token 任意段命中 4 位年份前缀 = legacy，**不得**判 domain）
    (".gatekeeper.state.r7.2026-06-09-mpr-standing-plan", "legacy_plan"),
    (".gatekeeper.state.finding-journal.jsonl", "artifact"),
    (".gatekeeper.state.finding-archive.jsonl", "artifact"),
    (".gatekeeper.state.pre-budget30.bak", "artifact"),
    # P0-A2 红先（2026-10-04）：`<repo>.<dated-plan>` 是**域化形态**（design §7 可写域 =
    #   `<base>` + `<repo>.<plan>`）；legacy 只认「裸 plan-basename」（date 在**首段**）。
    #   HEAD（`any(段含日期) ⟹ legacy`）误判 `skill.<date>` ⟹ 域 state 不可写（ECC-8486E07DBE34）。
    (".gatekeeper.state.skill.2026-10-04-state-satellite-storage-plan", "domain"),
    (".gatekeeper.state.spz-gatekeeper-r-sequence.2026-10-02-apply-worktree-hook-boundary-hardening-plan", "domain"),
    # ED9 红先（2026-10-08）：旁挂**封印**后缀 `.seal` 必须归 artifact —— 原 `_ARTIFACT_SUFFIXES`
    #   无 `.seal` ⟹ `state_form()` 把 `.edit-log.jsonl.seal` 判为**可写 domain**（域枚举虚增 +
    #   `--domain` 写可砸封印；`ECC-8F359340A5B9` 形状的第二条清单未治）。
    (".gatekeeper.state.edit-log.jsonl.seal", "artifact"),
    (".gatekeeper.state.budget-log.jsonl.seal", "artifact"),
])
def test_state_form_classification(name, expect):
    assert gsf.state_form("/x/" + name) == expect


# ECC-32124F358C56 红先（2026-10-09）：repo 前缀须有**动态源** —— scopes 注册的 `read_repo` 别名
#   （`.gatekeeper.scopes.json` governed_projects[].read_repo）计入 `_repo_prefixes()`，使**非
#   硬编码 `_VALID_REPOS` 表内仓**的 `<repo>.<dated-plan>` 域 token 判 `domain`（可写）。
#   HEAD（只认 `_VALID_REPOS()` + 两个技能别名）⟹ `papers.<date>` 误判 `legacy_plan` 只读
#   （build-state fail-loud `STATE_FORM_NOT_WRITABLE`）。
def test_scopes_read_repo_is_dynamic_repo_prefix(monkeypatch):
    monkeypatch.setattr(gsf, "_scopes_repo_aliases", lambda: {"papers"}, raising=False)
    assert gsf.state_form(
        "/x/.gatekeeper.state.papers.2026-10-09-w2a-primary-instance-design") == "domain"


def test_unregistered_repo_dated_token_stays_legacy(monkeypatch):
    """负臂（防放大）：未注册仓的首段仍判 legacy（写门不放宽）。"""
    monkeypatch.setattr(gsf, "_scopes_repo_aliases", lambda: {"papers"}, raising=False)
    assert gsf.state_form(
        "/x/.gatekeeper.state.r7.2026-06-09-mpr-standing-plan") == "legacy_plan"


@pytest.mark.parametrize("path,skill_root,expect", [
    # 挑战7 订正：形态需**父目录语义** —— 技能根下的 base = 授权；技能根外（worktree 自带）= 只读
    ("/skill/.gatekeeper.state", "/skill", "base"),
    ("/wt/feature-x/.gatekeeper.state", "/skill", "worktree_local"),
])
def test_state_form_worktree_local_by_parent_dir(path, skill_root, expect):
    assert gsf.state_form(path, skill_root=skill_root) == expect


def test_writable_forms_are_base_and_domain():
    assert gsf.WRITABLE_FORMS == ("base", "domain")


def test_write_gate_passes_non_state_path():
    """非 `.gatekeeper.state*` 路径（显式注入面，如测试夹具 `state.json`）⟹ 非 state 形态，放行。

    设计 §7：只读门只管 `legacy_plan`/`worktree_local`；`artifact`（非 state 命名）不拦。
    """
    gsf.assert_writable_form("/x/state.json")


@pytest.mark.parametrize("name", [".gatekeeper.state", ".gatekeeper.state.gatekeeper.r7"])
def test_assert_writable_form_allows_authorized(name):
    gsf.assert_writable_form("/x/" + name)          # 不抛 = 通过


def test_assert_writable_form_rejects_legacy():
    """legacy（`<repo>.<dated-plan>`）必须 fail-loud。

    2026-10-29（去存量跳过）：原实现把 `.gatekeeper.state`（**base = 授权形态**）也塞进本负例
    参数表，再用 `pytest.skip("base 属授权形态")` 跳过 ⟹ 一半是存量跳过。base 的正例判据已由
    `test_assert_writable_form_allows_authorized` 承担，本臂只留真正的负例。
    """
    with pytest.raises(ValueError, match="STATE_FORM_NOT_WRITABLE"):
        gsf.assert_writable_form("/x/.gatekeeper.state.2026-09-21-review-runtime-subplan")


def test_assert_writable_form_allows_repo_prefixed_domain():
    """P0-A2 红先：`<repo>.<dated-plan>` 域化形态**可写**（HEAD 误判 legacy ⟹ 抛 STATE_FORM_NOT_WRITABLE）。"""
    gsf.assert_writable_form(
        "/x/.gatekeeper.state.skill.2026-10-04-state-satellite-storage-plan",
        plan_declared="skill.2026-10-04-state-satellite-storage-plan")   # 不抛 = 通过


def test_write_gate_blocks_legacy_form(tmp_path):
    """写类子命令命中 legacy 形态 ⟹ fail-loud（不静默写）。"""
    import json, subprocess
    from test_gk_edit_budget_metering import _wsl, SKILL_DIR
    legacy = tmp_path / ".gatekeeper.state.2026-01-01-legacy-demo"
    legacy.write_text(json.dumps({"gate_data": {"ecc_findings": []}}), encoding="utf-8")
    r = subprocess.run(["bash", "-lc",
        'cd "%s" && STATE_FILE="%s" bash gatekeeper-cli.sh finding register T manual'
        % (_wsl(SKILL_DIR), _wsl(legacy))], capture_output=True, text=True, timeout=120)
    assert "STATE_FORM_NOT_WRITABLE" in (r.stdout + r.stderr), (r.stdout + r.stderr)[:400]


def test_write_gate_rejects_undeclared_domain_state(tmp_path):
    """未声明 META.state_domain 的计划 ⟹ 不得写 `domain` 形态（fail-loud）。"""
    dom = tmp_path / ".gatekeeper.state.gatekeeper.r7"
    dom.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="STATE_FORM_NOT_OPTED_IN"):
        gsf.assert_writable_form(str(dom), plan_declared="")
    # 有计划上下文且已声明 ⟹ 放行
    gsf.assert_writable_form(str(dom), plan_declared="gatekeeper.r7")


# ②-4 挑战1 不变量基线（**随批准命令同步**：新增/删除 `_CMD_REG` 条目须同步本常量并登记 finding）
# 口径 = **单一事实源** `gk_doc_align._count_cmd_reg`（`_CMD_REG[...]=` **赋值行**数）。
#   `ECC-439C8B7CF048` D2（2026-10-13）：原用 `src.count("_CMD_REG[")` **子串口径**=56（含 2 注释 +
#   3 读取）⟹ 与 doc-align 的 51 三口径分裂，正是 `54→56` 漂移能被藏住的机制。
#   2026-10-14（`ECC-9C3EC260D74D`）：s5.5 `workers` 命令（自适应并发度查询）使 51→52（**随批准命令
#   同步**；`cli-protocol.md` 已由 docgen 同步，`SKILL.md` 计数同步人工补）。
EXPECTED_CMD_REG_COUNT = 52


def test_state_inventory_branch_lists_forms_and_writability(tmp_path):
    """`state --inventory [root]` 枚举 state × 形态 × 条目数 × 是否授权写（挂既有命令，零新增 _CMD_REG）。"""
    import json, subprocess
    from test_gk_edit_budget_metering import _wsl, SKILL_DIR
    (tmp_path / ".gatekeeper.state").write_text(
        json.dumps({"gate_data": {"ecc_findings": [{"id": "X"}]}}), encoding="utf-8")
    (tmp_path / ".gatekeeper.state.2026-01-01-legacy").write_text("{}", encoding="utf-8")
    r = subprocess.run(["bash", "-lc",
        'cd "%s" && bash gatekeeper-cli.sh state --inventory "%s"'
        % (_wsl(SKILL_DIR), _wsl(tmp_path))],
        capture_output=True, text=True, timeout=180)
    d = json.loads([ln for ln in r.stdout.splitlines() if ln.startswith("{")][-1])
    assert d["ok"] is True and d["states"], d
    keys = {"path", "form", "writable", "findings", "would_be"}
    assert keys <= set(d["states"][0]), d["states"][0]
    by_form = {s["form"]: s for s in d["states"]}
    assert by_form["base"]["writable"] is True and by_form["base"]["findings"] == 1, by_form
    assert by_form["legacy_plan"]["writable"] is False, by_form


def test_no_new_cmd_reg_entry_added():
    """挑战1 不变量：`_CMD_REG` **赋值条目**数不变（新功能禁以新命令承载）。口径 = 单一事实源
    `gk_doc_align._count_cmd_reg`（`ECC-439C8B7CF048` D2：原 `src.count("_CMD_REG[")` 子串口径
    把 2 处注释 + 3 处读取也算进去，与 doc-align 分裂）。"""
    from test_gk_edit_budget_metering import SKILL_DIR
    from gk_doc_align import _count_cmd_reg
    src = (SKILL_DIR / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    assert _count_cmd_reg(src) == EXPECTED_CMD_REG_COUNT, "新增了 _CMD_REG 条目（违反禁改不变量）"


# ══════════ 类级守卫：`EXPECTED_CMD_REG_COUNT` 同步台账（`ECC-D934C09CC47F`，2026-10-13）══════════
# 根因（2026-10-13 实测）：`0fcbe84`（`model-probe`，`ECC-75F6A2BB7F2B`）+ `0806f53`（`phase-probe`，
#   `ECC-42B4A6E15927`）两条**已批准** W2A-P2 命令使计数 49→51，而本常量未同步 ⟹ 直到基线重拍
#   （`_accept_cli.sh --snapshot`）才暴露。**口径订正**（`ECC-439C8B7CF048` D2）：常量与判据统一到
#   单一事实源 `gk_doc_align._count_cmd_reg`（赋值行口径）。
# ⚠ 同步策略标记用**拼接**构造（不写字面量）—— 防本臂自身被判成「已声明」（注释盲）。
_SYNC_POLICY_MARK = "随批准" + "命令同步"


def test_cmd_reg_sync_count_and_policy():
    """红先（`ECC-D934C09CC47F`；口径订正 `ECC-439C8B7CF048` D2）：① `EXPECTED_CMD_REG_COUNT`
    须与实际**赋值条目**数一致（口径 = `gk_doc_align._count_cmd_reg`，单一事实源）；
    ② 本常量旁须声明「随批准命令同步」策略（不再是「一次性快照」口径）。"""
    from test_gk_edit_budget_metering import SKILL_DIR
    from gk_doc_align import _count_cmd_reg
    actual = _count_cmd_reg((SKILL_DIR / "gatekeeper-cli.sh").read_text(encoding="utf-8"))
    assert actual == EXPECTED_CMD_REG_COUNT, (
        "计数常量漂移：EXPECTED_CMD_REG_COUNT=%d 实际=%d"
        "（新增/删除 `_CMD_REG` 条目须同步常量 + 附 finding）" % (EXPECTED_CMD_REG_COUNT, actual))
    tf = (SKILL_DIR / "scripts" / "test_gk_state_forms.py").read_text(encoding="utf-8")
    assert _SYNC_POLICY_MARK in tf, "常量旁未声明同步策略（缺『随批准命令同步』）"

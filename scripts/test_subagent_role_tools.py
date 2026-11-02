#!/usr/bin/env python3
"""red-first 门：角色 → 工具面（F-REV-100 / suba-ctx §2-T6）+ 区域声明实测。

两段：
  甲、**区域声明实测**（① 补测，2026-09-17）—— 证明「6 个门禁直通工具的 TOOL_REGION_MAP
      区域声明**不参与运行时校验**」是**结构性事实**（AST）+ **运行时事实**（`_bootstrap` 真值），
      而非读码推断。此段**现在即应全绿**（它锁的是"现状"这一事实）。
  乙、**ROLE_TOOLS 单源**（F-REV-100 本体）—— 此段**先跑出红**（现在三处事实源 + `--tier`
      无条件覆盖 CLI 清单 ⟹ 必然失败），落刀后转绿。**这是本文件的 red-first 语义**。

隔离：本文件用与 `test_subagent_gitnexus_contract.py` 相同的"bootstrap 前后模块全局差集"
清理（F-REV-102），使执行对后续模块**零残留**、与收集顺序无关。
"""
import ast
import os
import sys
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import subagent_runner as sr  # noqa: E402

RUNNER = SCRIPT_DIR / "subagent_runner.py"

# 6 个「门禁直通工具」（工具短名，= TOOL_REGISTRY 键 = CLI valid_tools 项）
GATE_TOOLS = ("state", "self-check", "audit", "advance", "guard-edit", "reflect")
# 短名 → 实现函数名
GATE_TOOL_DEFS = {
    "state": "gk_state_gk", "self-check": "gk_self_check_gk", "audit": "gk_audit_gk",
    "advance": "gk_advance_gk", "guard-edit": "gk_guard_edit_gk", "reflect": "gk_reflect_gk",
}

BOOT_ARGV = ["--task", "t", "--api-base", "https://api.deepseek.com",
             "--api-key", "sk-test"]


def _tree():
    return ast.parse(RUNNER.read_text(encoding="utf-8"))


def _callees(fn_node):
    out = []
    for c in ast.walk(fn_node):
        if isinstance(c, ast.Call):
            f = c.func
            name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
            if name:
                out.append((name, c.lineno))
    return out


@pytest.fixture
def boot(monkeypatch):
    """按 (tier, tools, role_env) 启一次 `_bootstrap`，返回 `sr.tool_names`；teardown 精确清理。"""
    def _run(tier=None, tools=None, role=None, extra_env=None):
        before = set(vars(sr))
        monkeypatch.setattr(sr, "_CFG", None)
        for k in ("SUBAGENT_TOOLS", "SUAGENT_TOOLS", "SUBAGENT_ROLE", "SUBAGENT_ROLE_TOOLS"):
            monkeypatch.delenv(k, raising=False)
        if role:
            monkeypatch.setenv("SUBAGENT_ROLE", role)
        for k, v in (extra_env or {}).items():
            monkeypatch.setenv(k, v)
        argv = list(BOOT_ARGV)
        if tier is not None:
            argv += ["--tier", str(tier)]
        if tools is not None:
            argv += ["--tools", tools]
        try:
            sr._bootstrap(argv)
            return list(sr.tool_names)
        finally:
            # 精确清理（F-REV-102）：只删本次 bootstrap 新增的模块级全局。
            # ⚠ 必须放 finally —— fail-closed 路径会 `sys.exit(2)`（SystemExit），
            #   否则异常用例会把 `client`/`tools` 等残留给后续模块。
            monkeypatch.setattr(sr, "_CFG", None)
            for name in set(vars(sr)) - before:
                delattr(sr, name)
    return _run


# ══════════════════════════════════════════════════════════════════════
# 甲、区域声明实测（① 补测）—— 现状即应全绿
# ══════════════════════════════════════════════════════════════════════
class TestRegionDeclarationsAreInert:
    """证明：6 个门禁直通工具的区域声明**不参与运行时校验**（机制面不适用）。"""

    def test_check_scope_access_has_exactly_one_production_call_site(self):
        """AST 普查：`check_scope_access` 的生产调用点只有 1 处，且在 `_read_guard` 内。

        （F-REV-104 收束后：守卫收进 `_read_guard`，原在 `_read_common` 内。）
        """
        tree = _tree()
        sites = []
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name != "check_scope_access":
                for name, ln in _callees(n):
                    if name == "check_scope_access":
                        sites.append((n.name, ln))
        assert len(sites) == 1, f"期望唯一生产调用点，实得 {sites}"
        assert sites[0][0] == "_read_guard", sites

    def test_read_common_callers_are_only_the_two_read_tools(self):
        """`_read_common` 的调用者只有 `read_gk_file` / `read_repo_file`（分页读取共用体）。

        ⚠ 历史：同族第三次「第三份实现漏检」—— `read_bridge_file` 原**不走** `_read_common`，
        且自备整份守卫 ⟹ 不过 scope 检查。**F-REV-104（2026-09-17）已收束**：三者不再共享
        `_read_common`，而是共享更底层的 `_read_guard`（见 `TestReadGuardSingleSource`）。
        本条保留为「分页读取共用体的调用面」断言。
        """
        tree = _tree()
        callers = set()
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name != "_read_common":
                for name, _ in _callees(n):
                    if name == "_read_common":
                        callers.add(n.name)
        assert callers == {"read_gk_file", "read_repo_file"}, callers

    def test_gate_tools_have_no_in_body_scope_check(self):
        """6 个门禁直通工具的函数体内 `check_scope_access` 调用数 = 0，且签名无「读目标路径」。"""
        tree = _tree()
        by_name = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        for tool in GATE_TOOLS:
            d = by_name.get(GATE_TOOL_DEFS[tool])
            assert d is not None, f"{tool} 的实现函数缺失（TOOL_REGISTRY 键改名？）"
            hits = [n for n, _ in _callees(d) if n == "check_scope_access"]
            assert hits == [], f"{tool} 体内竟有 scope 检查：{hits}"

    def test_scope_access_mechanism_is_path_based(self):
        """机制是 path-based：不落在 PROTECTED_REGIONS 的路径**一律放行**（故无 path 的工具无从判定）。"""
        src = RUNNER.read_text(encoding="utf-8")
        assert "path not in protected region" in src, "解析口径变更 —— 本测试的语义前提需重核"
        # 正面控制：read 家族对保护区路径**会**被角色层拒
        ok, reason = sr.check_scope_access("read_repo", "gatekeeper-cli.sh", "reporter")
        assert ok is False and "scope denied" in reason, reason

    def test_default_role_actually_receives_gate_tools(self, boot):
        """**运行时实证**：CLI 真下发门禁工具时（`--tier` **不传** + 显式清单含 6 件），
        `default` 角色 —— 其 `ROLE_ALLOWED_REGIONS` 只有 `evidence` —— **全部拿到 6 件、零拦截**
        ⟹ 区域声明对它们**完全不生效**（= 声明性）。

        ⚠ **设计要点（首版曾在此判错）**：必须用 `tier=None`。若传 `--tier 3`，则因
        **`SUBA_TIERS[3].tools` 本身就不含这 6 件**，拿到 0 件 —— 那是"档位表没有"，不是
        "区域拦住了"。两个原因必须隔离，否则本类结论不成立。
        """
        got = set(boot(tools=",".join(("code_search", "read") + GATE_TOOLS), role="default"))
        hit = sorted(set(GATE_TOOLS) & got)
        assert hit == sorted(GATE_TOOLS), (
            f"default 角色未拿到全部门禁工具（实得 {hit}）—— 若区域声明生效则不应拿到，本类结论需重核")

    def test_tier_table_has_no_gate_tools(self):
        """隔离项（上一条的前提）：`SUBA_TIERS` 的 4 档**都不含**门禁直通工具。

        ⟹ 门禁工具只能经 CLI 的 per-role 清单下发 —— 这正是 F-REV-100 的受害面所在
        （清单被 `--tier` 静默覆盖 ⟹ 红队四角色拿不到 `state`/`audit`/…）。
        """
        for tier, cfg in sr.SUBA_TIERS.items():
            names = {t.strip() for t in cfg["tools"].split(",")}
            overlap = names & set(GATE_TOOLS)
            assert not overlap, f"tier{tier} 竟含门禁工具 {sorted(overlap)} —— 本类前提需重核"


# ══════════════════════════════════════════════════════════════════════
# 丙、读取守卫单源收束（F1 / F-REV-104）—— **先红后绿**
# ══════════════════════════════════════════════════════════════════════
class TestReadGuardSingleSource:
    """`_read_guard` = 4 个读工具**唯一**守卫（归一化 + traversal + blocked 名单 + 体积 + scope）。

    收束前：`read_bridge_file` 自备整份（不过 scope、不谈审计留痕）、`read_doc_gk` **零守卫**
    ⟹ 本类多数用例先红。
    """

    # ── 前置实测（F1 裁定表 #1 kill switch）：scope 生效后 reporter 是否被误挡 ──
    @pytest.mark.parametrize("path", [
        "docs/plans/2026-07-26-zthl-harness-adapter-plan.md",
        "references/plan-writing-safety-net.md",
    ])
    def test_reporter_reads_bridge_docs_plans_without_false_block(self, path):
        """**前置实测**：`reporter`（`ROLE_ALLOWED_REGIONS` 仅 `evidence`）经 `read_repo(repo=bridge)`
        读 bridge 的 `docs/plans/` / `references/` ⟹ **放行**（不会被误挡）。
        2026-11-01：`read_bridge` 已并入 `read_repo`（bridge 只是 REPO_ROOTS 的一个根）。"""
        ok, reason = sr.check_scope_access("read_repo", path, "reporter")
        assert ok is True, f"{path} 被误挡：{reason}"

    def test_read_guard_has_teeth_for_read_doc_on_gate_region(self):
        """反面控制：同一机制对 `read_doc` 读 gate 区文件**会拒** ⟹ 不是恒放行。"""
        ok, reason = sr.check_scope_access("read_doc", "gatekeeper-cli.sh", "reporter")
        assert ok is False and "scope denied" in reason, reason

    # ── 单源与调用面（AST） ──
    def test_read_guard_callers_cover_all_read_tools(self):
        """等值全集：`_read_guard` 直接调用者 == {`_read_common`, `read_doc_gk`}；
        叠上 `_read_common` 的调用者 == {`read_gk_file`, `read_repo_file`} ⟹ **全部读工具全覆盖**
        （2026-11-01：`read_bridge_file` 已并入 `read_repo`，故该名字不得再出现）。"""
        tree = _tree()

        def callers_of(target):
            out = set()
            for n in ast.walk(tree):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name != target:
                    for name, _ in _callees(n):
                        if name == target:
                            out.add(n.name)
            return out

        assert callers_of("_read_guard") == {"_read_common", "read_doc_gk"}, \
            callers_of("_read_guard")
        assert callers_of("_read_common") == {"read_gk_file", "read_repo_file"}, callers_of("_read_common")

    def test_blocklist_is_single_sourced(self):
        """blocked 名单单源：`.keys/` 字面量在全模块**只出现 1 次**（收束前为 2 次）。"""
        lits = [n for n in ast.walk(_tree())
                if isinstance(n, ast.Constant) and n.value == ".keys/"]
        assert len(lits) == 1, f"`.keys/` 字面量出现 {len(lits)} 次（应 1 ⟹ 名单必须单源）"

    # ── 运行时（收束前：bridge 读路径拦截不留审计痕；read_doc 无任何守卫） ──
    def test_read_repo_bridge_blocked_path_logs_access_violation(self, monkeypatch):
        """`read_repo(repo=bridge)` 被 blocked 名单拦下时**须与 read 同形**：留 Violation 审计痕。
        2026-11-01：原 `read_bridge` 并入 `read_repo` —— 该守卫面**随合并保留**（不是删能力）。"""
        monkeypatch.setenv("SUBAGENT_ROLE", "reporter")
        monkeypatch.setattr(sr, "_BUDGET_ITEM_CAP", 0, raising=False)  # bootstrap 期全局，裸调需补
        n = len(sr._ACCESS_VIOLATIONS)
        with pytest.raises(PermissionError):
            sr.TOOL_REGISTRY["read_repo"].__wrapped__("bridge", ".keys/x")
        assert len(sr._ACCESS_VIOLATIONS) == n + 1, "被拦未留 Violation 审计痕（与 read 不一致）"
        assert sr._ACCESS_VIOLATIONS[-1].tool == "read_repo"

    def test_read_doc_rejects_gate_region_path(self, monkeypatch, tmp_path):
        """收束后 `read_doc` 受**同一** scope 约束（收束前 `read_doc_gk` 零守卫 ⟹ 先红）。"""
        monkeypatch.setenv("SUBAGENT_ROLE", "reporter")
        monkeypatch.setattr(sr, "_BUDGET_ITEM_CAP", 0, raising=False)  # bootstrap 期全局，裸调需补
        p = tmp_path / "gatekeeper-cli.sh"
        p.write_text("x", encoding="utf-8")
        with pytest.raises(PermissionError):
            sr.TOOL_REGISTRY["read_doc"].__wrapped__(str(p))


# ══════════════════════════════════════════════════════════════════════
# 乙、ROLE_TOOLS 单一事实源（F-REV-100 本体）—— **先红后绿**
# ══════════════════════════════════════════════════════════════════════
class TestRoleToolsSingleSource:
    def test_role_tools_table_exists(self):
        """落刀目标：runner 侧必须新增 `ROLE_TOOLS`（唯一注册点）。"""
        assert hasattr(sr, "ROLE_TOOLS"), "ROLE_TOOLS 未实装（F-REV-100 未落刀）"

    def test_role_tools_keys_equal_role_allowed_regions(self):
        """键集等值（同 `TOOL_REGISTRY ↔ valid_tools` 的机检模式）。"""
        assert hasattr(sr, "ROLE_TOOLS"), "ROLE_TOOLS 未实装"
        assert set(sr.ROLE_TOOLS) == set(sr.ROLE_ALLOWED_REGIONS)

    def test_role_tools_entries_are_registered(self):
        """`ROLE_TOOLS` 的每个工具名都必须已在 `TOOL_REGISTRY` 内（防拼写漂移）。"""
        assert hasattr(sr, "ROLE_TOOLS"), "ROLE_TOOLS 未实装"
        unknown = {t for names in sr.ROLE_TOOLS.values() for t in names if t not in sr.TOOL_REGISTRY}
        assert not unknown, f"未注册工具：{sorted(unknown)}"

    def test_explicit_tools_is_not_silently_overridden_by_tier(self, boot):
        """**次序 A**（已裁）：显式 `--tools` 优先于 `SUBA_TIERS[tier]`。

        现状（红）：`--tier 2` + 显式清单含 `state,self-check` ⟹ 被档位表无条件覆盖 ⟹ 全丢。
        """
        got = set(boot(tier=2, tools="code_search,read,gitnexus,state,self-check", role="default"))
        assert {"state", "self-check"} <= got, f"显式 --tools 被 --tier 静默覆盖（实得 {sorted(got)}）"

    def test_role_tools_apply_without_cli_tools(self, boot):
        """无显式 `--tools` 时，生效清单应来自 `ROLE_TOOLS[role]`（而非裸 tier 表）。"""
        assert hasattr(sr, "ROLE_TOOLS"), "ROLE_TOOLS 未实装"
        got = set(boot(tier=3, role="reporter"))
        assert got == set(sr.ROLE_TOOLS["reporter"]), f"reporter 生效清单漂移：{sorted(got)}"

    def test_reporter_keeps_minimal_read_surface(self, boot):
        """②（已裁）：`reporter` 保持最小读面 —— 不得含 `read_repo`/`read_bridge`/`gx_*`。"""
        assert hasattr(sr, "ROLE_TOOLS"), "ROLE_TOOLS 未实装"
        got = set(sr.ROLE_TOOLS["reporter"])
        leak = got & {"read_repo", "gx_context", "gx_impact", "gx_query",
                      "gx_detect_changes", "gx_trace", "gx_guide", "gitnexus"}
        assert not leak, f"reporter 读面被扩大：{sorted(leak)}"

    def test_escape_hatch_subagent_tools_overrides_role(self, boot):
        """逃生位 `SUBAGENT_TOOLS`（**字面工具清单**）优先级最高 —— 高于角色表。

        语义订正（2026-09-17）：统一后的 `SUBAGENT_TOOLS` 是**字面清单**（原 runner 侧语义）；
        CLI 侧旧名 `SUAGENT_TOOLS` 已由 CLI 改名并出 WARN。
        """
        got = set(boot(tier=3, role="auditor", extra_env={"SUBAGENT_TOOLS": "code_search,read"}))
        assert got == {"code_search", "read"}, f"逃生位未压过角色表，实得 {sorted(got)}"

    def test_unknown_tool_is_rejected_fail_closed(self, boot):
        """fail-closed：未知工具必须 **fail-loud**（禁静默过滤）。

        原 CLI 侧 `for t in $subagent_tools; do … unknown tool → return 1` 的闸在删除
        per-role 清单后**迁入 runner 的解析点**；本用例同时锁「入口存在」与「运行时真拒」。
        """
        assert hasattr(sr, "validate_tool_names"), "缺 fail-closed 校验入口"
        valid, unknown = sr.validate_tool_names("code_search,bogus_tool,read")
        assert valid == ["code_search", "read"] and unknown == ["bogus_tool"]
        with pytest.raises(SystemExit) as ei:
            boot(tools="code_search,bogus_tool", role="default")
        assert ei.value.code == 2, "未知工具未以 exit 2 fail-loud"

    def test_kill_switch_skips_role_table(self, boot):
        """kill switch：`SUBAGENT_ROLE_TOOLS=0` ⟹ 跳过角色表，退回**档位阶梯**（对账用）。"""
        got = set(boot(tier=2, role="auditor", extra_env={"SUBAGENT_ROLE_TOOLS": "0"}))
        expect = {t.strip() for t in sr.SUBA_TIERS[2]["tools"].split(",")}
        assert got == expect, f"kill switch 未退回档位阶梯，实得 {sorted(got)}"
        assert "state" not in got, "档位表本不含门禁工具"


# ══════════════════════════════════════════════════════════════════════
# 丙、**角色指令注入**（第 9 层共因，2026-09-23 批次 1）
# ══════════════════════════════════════════════════════════════════════
# 背景（实测，非推测）：`role` 此前**只**参与 `check_scope_access`（三层作用域交集），
#   **无任何角色指令注入** ⟹ 派发 fix 档位时 agent 通篇读 `_DEFAULT_INSTRUCTIONS` 的
#   「独立审查」基调，把「去落刀」自我改写成「核实窄任务可行性」，**零落刀**
#   （F3a 第 4 次派发：turns=7 / 152086 tokens / 双树 0 改动）。第 5 次靠主 agent 手工加
#   task 前缀才落刀 —— 那是**绕过**而非修复。本段把该前缀固化为**机制**（9 族都会踩同一坑）。
class TestRoleInstructions:
    def test_coder_role_gets_executor_directive(self):
        """① 红先：`coder` 必须有「执行者」指令 —— 否则 fix 档位按审查者基调空手而归。"""
        assert hasattr(sr, "role_instructions"), "缺角色指令入口（第 9 层未修）"
        block = sr.role_instructions("coder")
        assert block, "coder 角色的指令为空 ⟹ 执行者语义未固化"
        for kw in ("执行者", "落刀", "红先"):
            assert kw in block, f"coder 指令缺关键词 {kw!r}"

    def test_unknown_role_gets_no_injection(self):
        """② 负臂：无指令的角色**不得**被注入任何文本（防误伤审查/报告类角色）。"""
        for r in ("reporter", "auditor", "exploiter", "scanner", "default", "", "no-such-role"):
            assert sr.role_instructions(r) == "", f"角色 {r!r} 不该有指令注入"

    def test_instruction_keys_are_real_roles(self):
        """③ 契约：指令表的键必须都是 `ROLE_TOOLS` 里的真实角色（防拼写漂移）。"""
        assert set(sr.ROLE_INSTRUCTIONS) <= set(sr.ROLE_TOOLS), (
            f"ROLE_INSTRUCTIONS 出现非角色键：{sorted(set(sr.ROLE_INSTRUCTIONS) - set(sr.ROLE_TOOLS))}")

    def test_bootstrap_actually_appends_role_instructions(self):
        """④ 结构性事实（AST 级）：指令必须被**真拼进** `instructions`（不只是定义了一个常量）。

        本臂防「定义了表但忘了接线」这一类假绿 —— 只测纯函数无法区分「接线了」与「表在那儿」。
        """
        src = RUNNER.read_text(encoding="utf-8")
        assert "instructions + role_instructions(" in src, (
            "`_bootstrap` 未把 role_instructions 拼进 system instructions ⟹ 表形同废除")
        tree = ast.parse(src)
        assert any(isinstance(n, ast.FunctionDef) and n.name == "role_instructions"
                   for n in ast.walk(tree)), "role_instructions 未定义"


# ─── ECC-1B18EF23B8F1：匿名通道无 gate 读权 ⟹ **拒绝理由须可行动**（本轮加固）────────────
# 病象（实测）：不传 `--role` 的匿名任务读 `gatekeeper-cli.sh`（`PROTECTED_REGIONS["gate"]`）
# **结构性失败**——`ROLE_ALLOWED_REGIONS["default"] == ["evidence"]`，三层交集后 `gate` 不在面内；
# 实测 C 组 3 个探测全被拒并留 4 条 access_violations。原理由 `…not in effective_regions` 看不出
# 「**该指定哪个角色**」⟹ 摩擦。**修法 = 理由里按同一张角色表反查候选角色**（不是第二份名单）；
# ⚠ **不是**把 gate 加进 default —— 那是扩大击面（由守护臂钉住）。

def test_scope_denied_reason_is_actionable():
    """拒绝理由必须写出「该指定哪个角色」，且候选角色由 `ROLE_ALLOWED_REGIONS` **反查**得出。"""
    ok, reason = sr.check_scope_access("read", "gatekeeper-cli.sh", "default")
    assert ok is False and "scope denied" in reason, reason
    assert "--role" in reason, "拒绝理由未给出可行动的「指定角色」提示: %r" % (reason,)
    capable = sorted(r for r, regs in sr.ROLE_ALLOWED_REGIONS.items() if "gate" in regs)
    assert capable, "角色表里无任何具 gate 读权的角色 —— 提示面为空（结构性事实异常）"
    assert [r for r in capable if r in reason], (
        "提示未含任何具 gate 读权的角色名（须由角色表反查，禁第二份名单）: %r" % (reason,))


def test_violation_record_carries_actionable_hint():
    """`access_violations[]` 的 reason 同带提示（报告/审计侧直接可读）。非破坏式：只增后比对。"""
    n0 = len(sr._ACCESS_VIOLATIONS)
    sr.check_scope_access("read_repo", "gatekeeper-cli.sh", "reporter")
    assert len(sr._ACCESS_VIOLATIONS) == n0 + 1, "未留 access_violation 审计痕"
    assert "--role" in sr._ACCESS_VIOLATIONS[-1].reason, sr._ACCESS_VIOLATIONS[-1].reason


def test_default_channels_keep_least_privilege():
    """**守护臂**（防「以放宽权限当修复」）：匿名/聚合通道不得持有 gate 读权。

    错修法 = 把 `gate` 加进 `default`/`reporter` ⟹ 匿名通道即可读门禁本体（击面扩大）。
    正解 = 保持最小权限 + 拒绝理由给出「该指定哪个角色」。
    """
    assert "gate" not in sr.ROLE_ALLOWED_REGIONS["default"], "默认角色被放宽到可读 gate（击面扩大）"
    assert "gate" not in sr.ROLE_ALLOWED_REGIONS["reporter"], "reporter 被放宽到可读 gate（击面扩大）"

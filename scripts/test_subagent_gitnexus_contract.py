"""
test_subagent_gitnexus_contract.py — subagent 侧 GitNexus 语义契约测试（F-REV-97）
==================================================================================
2026-09-17：subagent 侧 gitnexus 知识原为 6 行 docstring、instructions 里零指引 ⟹ 实测
14/14 质询 artifact 零 gitnexus 证据。本批把官方 12 份 skill 的**防误判语义**（「零调用者
= UNKNOWN 而非 LOW」/ partial/truncated / worktree 假 clean 等）配给 subagent：

  ① GX_INSTRUCTIONS_BLOCK 静态语义块（按档位条件注入，见 _bootstrap()）
  ② 6 个 gx_* 工具 docstring 从 1 行扩到「何时用 + 前置 + 输出解读」
  ③ 新增 gx_guide（官方 skill 全文按需拉取，topic 白名单 + GX_SKILLS_DIR/GX_JS 推导）
  ④ evidence 契约接受符号级/图级锚（不再只认 file:line）

本模块覆盖上述四面的**行为与结构不变量**；import 做法照抄 test_subagent_runner_extract.py
（该模块已 bootstrap 化，import 零副作用、无需伪造 sys.argv）。
"""
import inspect
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import subagent_runner as sr

RUNNER_SRC = Path(__file__).parent / "subagent_runner.py"


class TestGxInstructionsBlock:
    """① 语义块必须含"不知道就会做错"的防误判条目（缺一条即会产出错误结论，不只是"没查到"）。"""

    def test_block_exists_and_is_static_constant(self):
        assert isinstance(sr.GX_INSTRUCTIONS_BLOCK, str)
        # 静态常量（非运行时拼接）→ 可进 system 面前缀、不损 KV 缓存
        assert len(sr.GX_INSTRUCTIONS_BLOCK) > 800

    @pytest.mark.parametrize("token", [
        "d=1",            # 深度分级（WILL BREAK）
        "UNKNOWN",        # 零调用者 = UNKNOWN 而非 LOW/安全
        "partial",        # 不完整标志
        "truncated",      # 列表被截断
        "riskSharedAxes", # 编辑门禁不得被该字段豁免
        "worktree",       # detect_changes 假 clean
        "taint",          # taint 无 finding ≠ 安全
    ])
    def test_key_semantics_present(self, token):
        assert token in sr.GX_INSTRUCTIONS_BLOCK, f"语义块缺关键条目: {token}"

    def test_zero_caller_is_unknown_not_safe(self):
        """核心防误判：空结果的语义是 UNKNOWN，禁止据此断言"可安全删除"。"""
        b = sr.GX_INSTRUCTIONS_BLOCK
        assert "零调用者 ≠ 安全" in b
        assert "UNKNOWN" in b
        assert "禁止" in b and "可安全删除" in b

    def test_tool_order_recommendation_present(self):
        """推荐顺序是"何时用哪个工具"的唯一载体。"""
        b = sr.GX_INSTRUCTIONS_BLOCK
        for t in ("gx_query", "gx_context", "gx_impact", "gx_trace"):
            assert t in b, t


class TestPlaceholders:
    """② 两个 instructions 常量都须留占位符（组装处按档位替换）。"""

    def test_plan_refinement_has_placeholder(self):
        assert "{__GX_BLOCK__}" in sr._PLAN_REFINEMENT_INSTRUCTIONS

    def test_default_has_placeholder(self):
        assert "{__GX_BLOCK__}" in sr._DEFAULT_INSTRUCTIONS

    def test_placeholder_at_tail(self):
        """占位符置于结尾（append-only，不打断既有指令结构）。"""
        assert sr._PLAN_REFINEMENT_INSTRUCTIONS.endswith("{__GX_BLOCK__}")
        assert sr._DEFAULT_INSTRUCTIONS.endswith("{__GX_BLOCK__}")


class TestEvidenceAnchors:
    """③ evidence 契约从"必须 file:line_range"扩为**四类定位锚**。

    注：default 通道的符号锚写作 `file::symbol` 形态（断言其 `::` 形态），并单列图级证据形式。
    """

    def test_four_anchor_kinds_present(self):
        t = sr._DEFAULT_INSTRUCTIONS
        assert "源码行锚" in t
        assert "符号锚" in t and "::" in t
        assert "命令输出锚" in t
        assert "文档段锚" in t

    def test_symbol_anchor_example_present(self):
        assert "subagent_runner.py::TOOL_REGISTRY" in sr._DEFAULT_INSTRUCTIONS

    def test_command_output_anchor_example_present(self):
        assert "3 命中" in sr._DEFAULT_INSTRUCTIONS

    def test_graph_level_evidence_form_present(self):
        assert '{"kind":"graph"' in sr._DEFAULT_INSTRUCTIONS

    def test_bare_filename_still_rejected(self):
        """裸文件名/裸符号名仍须显式判为错误格式（不因扩锚而松掉底线）。"""
        assert '错误格式' in sr._DEFAULT_INSTRUCTIONS

    def test_plan_template_uses_anchor_placeholder(self):
        t = sr._PLAN_REFINEMENT_INSTRUCTIONS
        assert '"evidence":["<锚>",...]' in t
        assert '"evidence":["file:line_range",...]' not in t
        # 硬性要求段末追加的锚约束句
        assert "四类定位锚之一" in t


class TestEvidenceAnchorMachineCheck:
    """④b F-REV-97 机检（2026-09-22 / 红队 C2 修复）：锚点从 **prompt 层**下沉到 **门禁层**。

    修前病象（红先）：锚点要求**只**存在于 instructions，runner 对 evidence 零机检
    （修前源码 `_missing_evidence_anchors` 命中数 = 0）⟹ 「只给文件名 / 裸符号名」的
    无效锚可直达 L2 交叉审查报告；且门禁产出契约只有 result/gap，**无校验闭环**。
    """

    @pytest.mark.parametrize("text,ok", [
        ("gatekeeper-cli.sh:862-902", True),              # 行锚（区间）
        ("SKILL.md:123", True),                            # 行锚（单行）
        ("subagent_runner.py::TOOL_REGISTRY", True),       # 符号锚
        ("references/meta-routing-protocol.md §4", True),  # 文档段锚
        ("rg 'TOOL_REGISTRY' → 3 命中 (首条 subagent_runner.py:957)", True),  # 命令输出锚
        ("https://api-docs.deepseek.com/guides/search", True),  # URL 锚（web-first）
        ("https://api-docs.deepseek.com/guides/search §Billing", True),  # URL + 段锚
        ("https://api-docs.deepseek.com/guides/search#billing", True),  # URL + fragment
        ("SKILL.md", False),                               # 裸文件名（prompt 明列的错误格式）
        ("cmd_pre_check", False),                          # 裸符号名（同上）
        ("impact 显示没影响", False),                      # 无锚无依据
        ("", False),
    ])
    def test_anchor_predicate(self, text, ok):
        assert sr._has_evidence_anchor(text) is ok, f"{text!r} 判据应为 {ok}"

    def test_missing_list_shape_and_indexed(self):
        m = sr._missing_evidence_anchors({"evidence": [
            {"file": "gatekeeper-cli.sh", "lines": "1-2"},   # 有锚
            {"file": "SKILL.md", "lines": ""},               # 缺锚（规范 dict 形态）
        ]})
        assert len(m) == 1 and m[0].startswith("#1:"), m

    def test_canonical_dict_form_is_accepted(self):
        """prompt 模板的**规范形态**（file / lines 分置两键）不得被误判为缺锚。"""
        assert sr._missing_evidence_anchors(
            {"evidence": [{"file": "subagent_runner.py", "lines": "39-43"}]}) == []
        assert sr._missing_evidence_anchors(
            {"evidence": [{"file": "gatekeeper-cli.sh", "lines": "::cmd_monitor"}]}) == []

    def test_string_form_is_accepted(self):
        assert sr._missing_evidence_anchors({"evidence": ["a.py::foo"]}) == []
        assert sr._missing_evidence_anchors({"evidence": ["no-anchor-here"]}) != []

    def test_absent_evidence_is_not_a_false_positive(self):
        """无 evidence（键缺失 / 空数组 / None）⟹ 无锚可检 ⟹ 空表（不误报 incomplete）。"""
        assert sr._missing_evidence_anchors({}) == []
        assert sr._missing_evidence_anchors({"evidence": []}) == []
        assert sr._missing_evidence_anchors(None) == []

    def test_ecc_output_carries_field(self):
        """EccOutput 必须带该字段（HMAC 两端同构的契约面）。

        2026-11-08 口径变更：CLI 已禁止内联 pydantic 信封（见 `test_gk_monitor_envelope`），
        ECC 模型收敛为单源 ⟹ 有内联副本时仍要求"两份一致"，无副本时只要求引用单源。
        """
        assert "evidence_anchor" in sr.EccOutput.model_fields
        cli = (Path(__file__).parent.parent / "gatekeeper-cli.sh").read_text(encoding="utf-8")
        marker = "evidence_anchor:dict=Field(default_factory=dict)"
        if marker in cli:
            assert cli.count(marker) == 2, \
                "CLI 侧 O() 模型（校验 + HMAC 重算）必须同步新增该字段，否则全部输出判 tampered"
        else:
            assert ("subagent_runner" in cli or "gk_ecc" in cli), \
                "CLI 既无内联 O()，也未引用单源 ECC 模型 ⟹ 双端同构失去守护"

    def test_runner_wires_machine_check_into_output(self):
        """runner 侧须真的机检并写回（重试一次 + 仍缺标 incomplete，同 F-REV-81 形）。"""
        src = RUNNER_SRC.read_text(encoding="utf-8")
        assert "evidence_anchor=evidence_anchor" in src
        assert "[F-REV-97]" in src
        assert '"incomplete" if _uanch else "ok"' in src

    def test_gate_step_consumes_anchor_status(self):
        """门禁消费端（闭环）：L2 步须读 `evidence_anchor.status` 并降级留痕。"""
        cli = (Path(__file__).parent.parent / "gatekeeper-cli.sh").read_text(encoding="utf-8")
        assert '"WARN(锚缺)"' in cli
        assert '_ea.get("status") == "incomplete"' in cli


class TestGxToolRegistration:
    """④ gx_guide 三处注册齐全；tier1/2 **不得**含 gx_*（防幻觉调用）。"""

    def test_in_tool_registry(self):
        assert "gx_guide" in sr.TOOL_REGISTRY
        assert sr.TOOL_REGISTRY["gx_guide"] is sr.gx_guide_gk

    def test_in_tool_region_map(self):
        assert "gx_guide" in sr.TOOL_REGION_MAP
        assert "evidence" in sr.TOOL_REGION_MAP["gx_guide"]

    def test_registry_region_keys_equal(self):
        assert set(sr.TOOL_REGISTRY) == set(sr.TOOL_REGION_MAP)

    @pytest.mark.parametrize("tier", [3, 4])
    def test_tier34_include_gx_guide(self, tier):
        assert "gx_guide" in sr.SUBA_TIERS[tier]["tools"].split(",")

    @pytest.mark.parametrize("tier", [1, 2])
    def test_tier12_exclude_all_gx(self, tier):
        tools = sr.SUBA_TIERS[tier]["tools"].split(",")
        assert not [t for t in tools if t.startswith("gx_")], \
            f"tier{tier} 不得含 gx_*（注入了反而诱发幻觉调用）"
        assert "gitnexus" not in tools


GX_DOC_TOOLS = ("gx_context", "gx_impact", "gx_query",
                "gx_detect_changes", "gx_trace", "gx_guide")


class TestGxDocstrings:
    """⑤ docstring 从 1 行扩到「何时用 + 前置 + 输出解读」（后者才是会做错的地方）。"""

    @pytest.mark.parametrize("name", GX_DOC_TOOLS)
    def test_docstring_length_threshold(self, name):
        doc = inspect.getdoc(sr.TOOL_REGISTRY[name].__wrapped__) or ""
        assert len(doc) >= 120, f"{name} docstring 过短（{len(doc)}）"

    @pytest.mark.parametrize("name", GX_DOC_TOOLS)
    def test_docstring_has_when_to_use(self, name):
        """每个 docstring 须交代"何时用"（gx_impact/detect_changes 写作"…前必查"）。"""
        doc = inspect.getdoc(sr.TOOL_REGISTRY[name].__wrapped__) or ""
        assert "何时用" in doc or "输出解读" in doc or "必查" in doc, name

    def test_impact_docstring_carries_grading_and_unknown(self):
        doc = inspect.getdoc(sr.gx_impact_gk.__wrapped__) or ""
        assert "d=1" in doc and "UNKNOWN" in doc

    def test_detect_changes_docstring_warns_worktree_false_clean(self):
        doc = inspect.getdoc(sr.gx_detect_changes_gk.__wrapped__) or ""
        assert "worktree" in doc and "零变更" in doc

    def test_query_docstring_points_to_guide(self):
        doc = inspect.getdoc(sr.gx_query_gk.__wrapped__) or ""
        assert "gx_guide" in doc


class TestGxSkillsTopics:
    """⑥ topic 白名单硬编码（防路径穿越：不接受任意路径）。"""

    EXPECTED = {"guide", "cli", "exploring", "debugging", "impact-analysis", "refactoring",
                "pdg-query", "taint-analysis", "plan", "review", "work", "lfg"}

    def test_exactly_twelve_topics(self):
        assert len(sr._GX_SKILLS_TOPICS) == 12

    def test_all_expected_keys(self):
        assert set(sr._GX_SKILLS_TOPICS) == self.EXPECTED

    def test_values_are_relative_paths(self):
        for k, v in sr._GX_SKILLS_TOPICS.items():
            assert not v.startswith("/") and ".." not in v, k


class TestGxSkillsDir:
    """⑦ skills 目录解析：env GX_SKILLS_DIR → GX_JS 上溯 package root → ""（不写死用户目录）。"""

    def test_env_override_wins(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GX_SKILLS_DIR", str(tmp_path))
        assert sr._gx_skills_dir() == str(tmp_path)

    def test_derive_from_gx_js_package_root(self, tmp_path, monkeypatch):
        monkeypatch.delenv("GX_SKILLS_DIR", raising=False)
        pkg = tmp_path / "pkg"
        (pkg / "dist").mkdir(parents=True)
        (pkg / "skills").mkdir()
        (pkg / "package.json").write_text("{}", encoding="utf-8")
        monkeypatch.setenv("GX_JS", str(pkg / "dist" / "cli.js"))
        assert sr._gx_skills_dir() == str(pkg / "skills")

    def test_none_found_returns_empty(self, monkeypatch):
        monkeypatch.delenv("GX_SKILLS_DIR", raising=False)
        monkeypatch.delenv("GX_JS", raising=False)
        assert sr._gx_skills_dir() == ""

    def test_gx_js_without_package_json_returns_empty(self, tmp_path, monkeypatch):
        """有 dist/cli.js 但无 package.json → 不得瞎猜（返回 ""）。"""
        monkeypatch.delenv("GX_SKILLS_DIR", raising=False)
        (tmp_path / "dist").mkdir()
        (tmp_path / "skills").mkdir()
        monkeypatch.setenv("GX_JS", str(tmp_path / "dist" / "cli.js"))
        assert sr._gx_skills_dir() == ""

    def test_gx_skills_dir_env_nonexistent_falls_through(self, tmp_path, monkeypatch):
        """GX_SKILLS_DIR 指向不存在目录 → 不返回它（回落 GX_JS 推导）。"""
        monkeypatch.setenv("GX_SKILLS_DIR", str(tmp_path / "nope"))
        monkeypatch.delenv("GX_JS", raising=False)
        assert sr._gx_skills_dir() == ""


class TestGxGuideTool:
    """⑧ gx_guide 错误路径 fail-loud（不静默返回空）。"""

    @pytest.fixture(autouse=True)
    def _boot(self, monkeypatch):
        """`_budget_blocked()` 依赖 `_BUDGET_ITEM_CAP`（在 `_bootstrap()` 内定义）。

        ⚠ 隔离（2026-09-17 实测修复）：`_bootstrap()` 以 `global` 赋值 `client`/`model`/`tools`/
        `tool_names`/`instructions`/`agent` 等模块级名称，**teardown 只重置 `_CFG` 会残留 `sr.client`**
        ⟹ 同进程后续模块的 `TestImportSideEffectFree::test_import_no_client`（断言裸 import 不建网络
        client）会假失败（跨文件顺序依赖）。此处按"bootstrap 前后模块全局差集"精确清理，使本文件的
        执行对后续模块**零残留**、与收集顺序无关。
        """
        before = set(vars(sr))
        monkeypatch.setattr(sr, "_CFG", None)
        sr._bootstrap(["--task", "t", "--api-base", "https://api.deepseek.com",
                       "--api-key", "sk-test", "--tier", "3"])
        yield
        monkeypatch.setattr(sr, "_CFG", None)
        for name in set(vars(sr)) - before:  # 只删本次 bootstrap 新增的模块级全局
            delattr(sr, name)

    def test_unknown_topic_lists_valid_values(self):
        out = sr.gx_guide_gk.__wrapped__("no-such-topic")
        assert out.startswith("[ERROR] unknown topic")
        for k in sr._GX_SKILLS_TOPICS:
            assert k in out

    def test_unknown_topic_empty_string(self):
        assert sr.gx_guide_gk.__wrapped__("").startswith("[ERROR] unknown topic")

    def test_missing_skills_dir_fails_loud(self, monkeypatch):
        monkeypatch.delenv("GX_SKILLS_DIR", raising=False)
        monkeypatch.delenv("GX_JS", raising=False)
        out = sr.gx_guide_gk.__wrapped__()
        assert out.startswith("[ERROR] gitnexus skills 目录未找到")

    def test_missing_topic_file_fails_loud(self, tmp_path, monkeypatch):
        """白名单命中但文件缺失 → [ERROR] read ... failed（不静默）。"""
        monkeypatch.setenv("GX_SKILLS_DIR", str(tmp_path))
        out = sr.gx_guide_gk.__wrapped__("guide")
        assert out.startswith("[ERROR] read gitnexus-guide.md failed")

    def test_topic_read_and_truncated(self, tmp_path, monkeypatch):
        """正常路径：读白名单内文件并按**档位工具窗**前截（2026-11-01：6000 固定值 → `_tool_window()`）。"""
        (tmp_path / "gitnexus-guide.md").write_text("G" * 9000, encoding="utf-8")
        monkeypatch.setenv("GX_SKILLS_DIR", str(tmp_path))
        out = sr.gx_guide_gk.__wrapped__("guide")
        assert out.startswith("G" * sr._tool_window()), "前截窗口未与档位对齐"
        assert "truncated" in out, "截断缺标记（模型会把没看到当没影响）"

    def test_topic_normalized(self, tmp_path, monkeypatch):
        """topic 大小写/空白归一（" IMPACT-ANALYSIS " 命中）。"""
        (tmp_path / "gitnexus-impact-analysis.md").write_text("IMPACT-BODY", encoding="utf-8")
        monkeypatch.setenv("GX_SKILLS_DIR", str(tmp_path))
        assert sr.gx_guide_gk.__wrapped__(" IMPACT-ANALYSIS ") == "IMPACT-BODY"


class TestConditionalInjection:
    """⑨ 落刀 3 的源码不变量：语义块**按档位条件注入**（真跑 API 不在本测试范围）。

    行为面（"注入了什么"）由 instructions 占位符 + 上述块内容测试覆盖；此处只锁**控制流形态**：
    tier1/2 无 gx_* ⟹ _has_gx 假 ⟹ _gx_block 空串 ⟹ 不注入（防幻觉调用）。
    """

    def _src(self):
        return RUNNER_SRC.read_text(encoding="utf-8")

    def test_conditional_flag_and_block_var_present(self):
        src = self._src()
        assert "_has_gx" in src and "_gx_block" in src

    def test_conditional_literal_present(self):
        assert 'GX_INSTRUCTIONS_BLOCK if _has_gx else ""' in self._src()

    def test_no_unconditional_instruction_assignment(self):
        """回归守卫：不得退回"无条件直接用常量"（占位符会原样进 system 面）。"""
        src = self._src()
        assert "instructions = _PLAN_REFINEMENT_INSTRUCTIONS\n" not in src
        assert 'instructions = _DEFAULT_INSTRUCTIONS.replace("{__TOOLS__}", ", ".join(tool_names))\n' \
            not in src

    def test_placeholder_replaced_in_both_branches(self):
        """两个分支都须做 {__GX_BLOCK__} 替换（缺一即有一个通道裸奔）。"""
        assert self._src().count('.replace("{__GX_BLOCK__}", _gx_block)') == 2

    def test_absorbed_known_append_kept(self):
        """紧随其后的 ABSORBED_KNOWN 拼接不得被改动。"""
        assert "instructions = instructions + ABSORBED_KNOWN" in self._src()

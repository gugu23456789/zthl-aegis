"""
test_subagent_runner_extract.py — subagent_runner._extract_llm_json 宽容 JSON 提取测试
==================================================================================
2026-08-29：fse-industry eval 角色回退 deterministic 驱动——模型输出带前缀说明文字
（"已完成全文通读…以下为评审输出。\n\n{...}"）且无 markdown 代码块时，原实现
raw_decode 只在 startswith("{") 时启用导致漏检 → non_json_output 误杀整个角色。
修复后无条件从首个 '{' 尝试 raw_decode，本测试覆盖前缀/后缀/代码块/无 JSON 四类形态。
"""
import json
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
# 2026-08-29 重构（用户质询"大量 args 是工程债"）：subagent_runner 已 bootstrap 化
# （parse_args/client/agent 组装移入 _bootstrap()），import 零副作用、无需伪造 sys.argv。
# 此前须在 import 前注入 argv（缺 --task/--api-base 直接 SystemExit），影响测试真实性。
import subagent_runner as sr


class TestImportSideEffectFree:
    """2026-08-29：import 不受限制（重构验收）——裸 import 不触发任何运行时初始化。"""

    def test_import_no_cfg(self):
        assert sr._CFG is None  # 未 bootstrap

    def test_import_no_client(self):
        assert not hasattr(sr, "client")  # 不创建网络 client

    def test_cfg_fail_closed_before_bootstrap(self):
        """未 bootstrap 访问运行时配置 → fail-closed 报错（拒绝半初始化运行）。"""
        with pytest.raises(RuntimeError):
            sr._cfg()

    def test_bootstrap_sets_cfg(self, monkeypatch):
        """_bootstrap(fake_argv) 可独立初始化（tier 映射 + instructions 占位符解析）。"""
        monkeypatch.setattr(sr, "_CFG", None)
        a = sr._bootstrap(["--task", "t", "--api-base", "https://api.deepseek.com",
                           "--api-key", "sk-test", "--tier", "3"])
        assert sr._cfg() is a
        assert a.tier == 3 and a.max_turns == 800
        assert "__TOOLS__" not in sr.instructions  # 默认指令占位符已解析
        monkeypatch.setattr(sr, "_CFG", None)  # 隔离：避免影响同进程其他用例

    def test_sdk_guard_version_range_covers_0_23(self, monkeypatch):
        """2026-10-14（owner 裁定）：SDK 护栏区间放宽 `>=0.22,<0.24`。

        依据：0.23.1 已用**真臂**实测兼容（4 轮 / 73,858 token / 完整 ECC 载荷，无 error）；
        且 0.23.1 与 0.23.0 运行时代码相同（仅发布测试差）。旧护栏 `!= (0, 22)` 会把 0.23 当场拒。
        **必红**：旧护栏下首次 `_bootstrap("0.23.1")` 即 `SystemExit(2)` ⟹ 本臂红。
        """
        from importlib import metadata as md
        for ver in ("0.23.1", "0.22.3"):
            monkeypatch.setattr(md, "version", lambda name: ver)
            monkeypatch.setattr(sr, "_CFG", None)
            a = sr._bootstrap(["--task", "t", "--api-base", "https://api.deepseek.com",
                               "--api-key", "sk-test", "--tier", "1"])
            assert a.tier == 1                      # 0.22/0.23 均放行
        monkeypatch.setattr(md, "version", lambda name: "0.21.0")
        monkeypatch.setattr(sr, "_CFG", None)
        with pytest.raises(SystemExit) as e:        # <0.22 仍 fail-loud
            sr._bootstrap(["--task", "t", "--api-base", "https://api.deepseek.com",
                           "--api-key", "sk-test", "--tier", "1"])
        assert e.value.code == 2
        monkeypatch.setattr(sr, "_CFG", None)


class TestStripTexComment:
    """2026-08-30 Bug C 修复（ADI 深度评审 45.0 实测驱动）：read_repo_file 对 .tex 返回前
    剥离行内注释（% TODO 草稿遗留不判占位），与 gk_paper_review local 检查语义一致。"""

    def test_comment_truncated_to_eol(self):
        assert sr._strip_tex_comment("% TODO draft leak") == ""
        assert sr._strip_tex_comment("body text % TODO tail") == "body text "

    def test_escaped_percent_kept(self):
        assert sr._strip_tex_comment("a \\% b % c") == "a \\% b "

    def test_no_comment_unchanged(self):
        assert sr._strip_tex_comment("plain text no comment") == "plain text no comment"

    def test_does_not_strip_other_chars(self):
        # 反斜杠后的字符一律保留两位（含 \x 宏等），非 % 截断语义不变
        assert sr._strip_tex_comment(r"\section{Intro}") == r"\section{Intro}"


class TestTaskFile:
    """2026-08-30 Bug A 修复（ADI 实跑 Errno 7 驱动）：超长 task（全文注入 317K prompt）经
    argv 触发 Argument list too long → 新增 --task-file 文件通道；file 优先、缺失 fail-closed。"""

    def test_task_file_loaded_into_task(self, tmp_path, monkeypatch):
        f = tmp_path / "task.txt"
        f.write_text("超长 prompt " * 100, encoding="utf-8")
        monkeypatch.setattr(sr, "_CFG", None)
        a = sr._bootstrap(["--task-file", str(f), "--api-base", "https://api.deepseek.com",
                           "--api-key", "sk-test"])
        assert a.task == "超长 prompt " * 100
        assert "task-file" not in a.task  # 已解析为实际内容
        monkeypatch.setattr(sr, "_CFG", None)

    def test_task_file_prefers_over_task(self, tmp_path, monkeypatch):
        f = tmp_path / "task.txt"
        f.write_text("file content", encoding="utf-8")
        monkeypatch.setattr(sr, "_CFG", None)
        a = sr._bootstrap(["--task", "argv content", "--task-file", str(f),
                           "--api-base", "https://api.deepseek.com", "--api-key", "sk-test"])
        assert a.task == "file content"
        monkeypatch.setattr(sr, "_CFG", None)

    def test_missing_task_fail_closed(self, monkeypatch):
        monkeypatch.setattr(sr, "_CFG", None)
        with pytest.raises(SystemExit) as e:
            sr._bootstrap(["--api-base", "https://api.deepseek.com", "--api-key", "sk-test"])
        assert e.value.code == 2
        monkeypatch.setattr(sr, "_CFG", None)


class TestExtractLlmJson:
    def test_pure_json(self):
        d = sr._extract_llm_json('{"evaluation": {"score": 0.75, "issues": []}}')
        assert d["evaluation"]["score"] == 0.75

    def test_json_with_prefix_text(self):
        """本次 bug 场景：JSON 前有前缀说明文字且无代码块。"""
        out = '已完成全文通读（main.tex，70,460 字符，连续读完）。以下为评审输出。\n\n' \
              '{"evaluation": {"score": 0.75, "issues": []}}'
        d = sr._extract_llm_json(out)
        assert d["evaluation"]["score"] == 0.75

    def test_json_with_suffix_text(self):
        """JSON 后有尾部说明文字（2026-08-29 首次修复场景）。"""
        out = '{"soundness": {"score": 0.6}} 以上为评审意见，如有需要可补充。'
        d = sr._extract_llm_json(out)
        assert d["soundness"]["score"] == 0.6

    def test_json_in_markdown_fence(self):
        out = '```json\n{"related_work": {"score": 0.5}}\n```'
        d = sr._extract_llm_json(out)
        assert d["related_work"]["score"] == 0.5

    def test_prefix_and_suffix_both(self):
        out = '前置说明\n```json\n{"a": {"score": 0.4}}\n```\n尾部说明'
        d = sr._extract_llm_json(out)
        assert d["a"]["score"] == 0.4

    def test_no_json_returns_empty(self):
        """无任何 JSON → {}（调用方 fail-closed 触发条件）。"""
        assert sr._extract_llm_json("模型没有输出结构化 JSON") == {}
        assert sr._extract_llm_json("") == {}
        assert sr._extract_llm_json(None) == {}

    # ── 极限压力测试（2026-10-04）：畸形/退化输入不得崩溃，也不得**静默降级为内层对象** ──
    # 事故：模型外层 JSON 非法（`challenges]` 与 `"slashed"` 间缺逗号）⟹ 原实现 `find("{",pos+1)`
    #   扫到内层 `adaptive_difficulty` 并返回它 ⟹ agent_payload/verdicts/score 全被掏空（假绿）
    #   + 报告模板误判 default（sub-1791075048-21915-31873）。修法 = 只在**首个** `{` 试一次，失败即 {}。
    _MALFORMED_CASES = {
        "missing_comma_top": '{"a":1"b":2}',
        "missing_comma_then_inner": '{"challenges":["x"]"slashed":[],'
                                    '"adaptive_difficulty":{"base":"b","factors":["f"],"final":"h"}}',
        "single_quotes": "{'a':1}",
        "trailing_comma": '{"a":1,}',
        "bare_word": "{a:1}",
        "truncated": '{"a":1,"b":',
        "control_char": '{"a":"x\x01y","b":{"c":1}}',
    }

    def test_malformed_inputs_fail_closed_no_inner_degradation(self):
        """畸形外层 JSON ⟹ 必须 `{}`（禁回退到内层子对象；否则信号被掏空、假绿）。"""
        for name, s in self._MALFORMED_CASES.items():
            d = sr._extract_llm_json(s)
            assert d == {}, f"{name}: 畸形输入竟返回 {d!r}（应 fail-closed 为 {{}}）"

    def test_unescaped_newline_repaired_to_outer_not_inner(self):
        """2026-10-07 兜底（paper-review AC 聚合实测）：字符串内**裸换行**由 raw_decode 判死，
        兜底转义后解析**最外层**对象；**不得**掏成内层子对象（保持禁内层降级契约）。"""
        d = sr._extract_llm_json('{"conclusion":"l1\nl2","x":{"a":1}}')
        assert d == {"conclusion": "l1\nl2", "x": {"a": 1}}
        # 结构性畸形（缺逗号）仍 fail-closed（兜底不得掩盖真错）
        assert sr._extract_llm_json('{"a":1"b":2}') == {}

    def test_toplevel_array_not_unwrapped(self):
        """顶层数组不是 ECC 对象 ⟹ 不得拆出内层对象（`[{"a":1}]` 应 {}）。"""
        assert sr._extract_llm_json('[{"a":1}]') == {}

    def test_valid_prefix_and_suffix_preserved(self):
        """守回归：前缀文字 / 后缀文字 的容忍语义**不变**。"""
        assert sr._extract_llm_json('{"a":1} trailing') == {"a": 1}
        assert sr._extract_llm_json('note\n{"a":1}') == {"a": 1}

    def test_deep_nesting_does_not_crash(self):
        """超深嵌套不得抛 RecursionError（须被吞为 `{}`，禁崩掉整个 subagent）。"""
        assert sr._extract_llm_json('{"a":' + '[' * 200000) == {}


class TestRetryNoClobber:
    """2026-10-04（极限压力）：F-REV-81/97 重试**不得**用退化结果覆盖首轮良构结果。

    病象（实测 sub-1791078093-145-720）：首轮良构 → 机检缺字段 → 重试；重试输出畸形
    （`_extract_llm_json` fail-closed 为 `{}`）原实现直接赋回 `llm_data` ⟹ 整份 ECC 退化
    （agent_payload/verdicts/score/evidence 全空 = 假绿）。修法 = 重试只在产出**非空 dict**
    时接管，否则回退首轮（`_pick_retry_result` 单源，两处重试共用）。
    """

    def test_valid_retry_takes_over(self):
        prev = ("R0", "t0", {"a": 1})
        new = ("R1", "t1", {"constraint_matrix": [], "verification_checklist": []})
        assert sr._pick_retry_result(prev, new) == new

    def test_empty_retry_falls_back_to_prev(self):
        prev = ("R0", "t0", {"a": 1})
        assert sr._pick_retry_result(prev, ("R1", "malformed-text", {})) == prev

    def test_non_dict_retry_falls_back(self):
        prev = ("R0", "t0", {"a": 1})
        assert sr._pick_retry_result(prev, ("R1", "x", None)) == prev
        assert sr._pick_retry_result(prev, ("R1", "x", [])) == prev


class TestValidateReviewSchema:
    """2026-08-29：评审专用输出边界（--output-schema review）结构校验。
    gk_paper_review 消费面二选一：准则映射（顶层=准则→{score,issues}）或
    ECC 单对象（{score, issues}）。其余形态 fail-closed。"""

    def test_criteria_mapping_valid(self):
        """形态 A：顶层 = 准则 key → {score, issues} 映射。"""
        d = {"evaluation": {"score": 0.75, "issues": ["缺对照"]},
             "soundness": {"score": 0.6, "issues": []}}
        assert sr._validate_review_schema(d) is None

    def test_criteria_entry_without_issues_valid(self):
        """单准则条目可省略 issues。"""
        assert sr._validate_review_schema({"soundness": {"score": 0.6}}) is None

    def test_single_object_valid(self):
        """形态 B：ECC 单对象 {score, issues} — 综合分由消费方应用到角色全部准则。"""
        assert sr._validate_review_schema({"score": 0.72, "issues": ["缺 baseline"]}) is None

    def test_single_object_float_score(self):
        assert sr._validate_review_schema({"score": 7.5, "issues": []}) is None

    def test_empty_dict_rejected(self):
        err = sr._validate_review_schema({})
        assert err and "review_schema_invalid" in err

    def test_non_dict_rejected(self):
        err = sr._validate_review_schema([])
        assert err and "review_schema_invalid" in err

    def test_entry_missing_score_rejected(self):
        err = sr._validate_review_schema({"evaluation": {"issues": []}})
        assert err and "evaluation" in err and "缺 score" in err

    def test_entry_score_non_numeric_rejected(self):
        err = sr._validate_review_schema({"soundness": {"score": "high"}})
        assert err and "score 非数值" in err

    def test_entry_non_dict_rejected(self):
        err = sr._validate_review_schema({"evaluation": 0.75})
        assert err and "值类型" in err

    def test_bool_score_rejected(self):
        """bool 是 int 子类但语义非数值 → 拒绝。"""
        err = sr._validate_review_schema({"soundness": {"score": True}})
        assert err and "score 非数值" in err

    def test_single_object_issues_non_list_rejected(self):
        err = sr._validate_review_schema({"score": 0.7, "issues": "缺对照"})
        assert err and "issues 必须是数组" in err

    def test_mixed_rejected(self):
        """形态混用（含顶层 score 又含准则映射）→ 按单对象判定；准则值含 score 视为合法条目。
        2026-08-30 宽容化：附带非准则键（如 "x"）被忽略，合法准则存在即通过。"""
        d = {"score": 0.7, "evaluation": {"score": 0.75, "issues": []}}
        assert sr._validate_review_schema(d) is None  # score 存在 → 单对象形态
        assert sr._validate_review_schema({"evaluation": {"score": 0.75, "issues": []}, "x": 1}) is None

    def test_criteria_mapping_with_extra_fields_tolerated(self):
        """2026-08-30 宽容化（RepuNet rigor 角色实测驱动）：顶层附加非准则键
        （"task" 等 LLM 说明/元数据字段，字符串/数字值）被忽略——≥1 个合法准则即通过，
        不再因附带字段丢整角色；全部键非法（零有效评审内容）仍 fail-closed。"""
        assert sr._validate_review_schema(
            {"soundness": {"score": 0.8, "issues": []}, "task": "深度评审说明"}) is None
        assert sr._validate_review_schema(
            {"originality": {"score": 0.6}, "note": 123, "extra": ["a"]}) is None
        assert sr._validate_review_schema(
            {"task": "仅说明无准则", "note": "x"}) is not None


class TestReadWindow:
    """2026-08-30 档位化读窗口（用户质询"各档位的工具限制太小了；不同档位窗口不一致？"）：
    单次 read 窗口随 tier 缩放（1:20K/2:30K/3:40K/4:60K），env GK_READ_WINDOW 全局覆盖，
    未 bootstrap 按 tier3（40000）兜底。"""

    def test_pre_bootstrap_falls_back_to_tier3(self, monkeypatch):
        monkeypatch.setattr(sr, "_CFG", None)
        assert sr._read_window() == 40_000

    def test_tier1_window(self, monkeypatch):
        monkeypatch.setattr(sr, "_CFG", None)
        sr._bootstrap(["--task", "t", "--api-base", "http://x",
                       "--api-key", "sk-test", "--tier", "1"])
        assert sr._read_window() == 20_000
        monkeypatch.setattr(sr, "_CFG", None)

    def test_tier4_window(self, monkeypatch):
        monkeypatch.setattr(sr, "_CFG", None)
        sr._bootstrap(["--task", "t", "--api-base", "http://x",
                       "--api-key", "sk-test", "--tier", "4"])
        assert sr._read_window() == 60_000
        monkeypatch.setattr(sr, "_CFG", None)

    def test_env_override_wins(self, monkeypatch):
        monkeypatch.setattr(sr, "_CFG", None)
        monkeypatch.setenv("GK_READ_WINDOW", "50000")
        assert sr._read_window() == 50_000


class TestToolWindow:
    """2026-10-01（用户裁定「提高硬截断上限」）：**工具回显**窗口档位化 —— 原三处硬编码
    （search_gk 800 / code_search_gk 1500 / gitnexus_gk 与 _gatekeeper_cli 1500）统一到
    `_tool_window()`：1:1500 / 2:3000 / 3:5000 / 4:10000；env `GK_TOOL_OUTPUT_WINDOW` 全局
    覆盖；未 bootstrap 按 tier3（5000）；下限 800。"""

    def test_pre_bootstrap_falls_back_to_tier3(self, monkeypatch):
        monkeypatch.setattr(sr, "_CFG", None)
        assert sr._tool_window() == 5_000

    def test_tier1_window_is_old_code_search_value(self, monkeypatch):
        """零回归锚：tier1 = 1500 = 旧 code_search/gitnexus 硬编码值（不得更低）。

        用 `SimpleNamespace(tier=N)` 直设 `_CFG`，**不经 `_bootstrap()`** —— 后者会写
        `os.environ["SUBAGENT_MAX_TOKENS"/"SUBAGENT_TIMEOUT"]`，跨文件泄漏进
        `test_eco_integration.TestWslenvInteropEnv` 的 WSLENV 白名单臂（既有隔离缺陷）。
        """
        monkeypatch.setattr(sr, "_CFG", types.SimpleNamespace(tier=1))
        assert sr._tool_window() == 1_500

    def test_tier4_window(self, monkeypatch):
        monkeypatch.setattr(sr, "_CFG", types.SimpleNamespace(tier=4))
        assert sr._tool_window() == 10_000

    def test_env_override_wins(self, monkeypatch):
        monkeypatch.setattr(sr, "_CFG", None)
        monkeypatch.setenv("GK_TOOL_OUTPUT_WINDOW", "7777")
        assert sr._tool_window() == 7_777

    def test_floor_800(self, monkeypatch):
        """负臂：env 配成过小（100）⟹ 下限 800 兜住（防回显被压到无信息）。"""
        monkeypatch.setattr(sr, "_CFG", None)
        monkeypatch.setenv("GK_TOOL_OUTPUT_WINDOW", "100")
        assert sr._tool_window() == 800


class TestToolOutputWindowWiring:
    """文本不变量（同仓 arm50 范式）：三处硬编码**已收敛**到单点，且 `--max-count` 可配。

    只读源码、不起子进程 —— `@function_tool` 装饰后的对象是 FunctionTool（非可调用），
    直接 `sr.code_search_gk(...)` 会 TypeError，故行为面由 `_tool_window()` 单测承担。
    """

    @staticmethod
    def _src() -> str:
        return (Path(__file__).parent / "subagent_runner.py").read_text(encoding="utf-8")

    def test_no_hardcoded_trunc_left(self):
        src = self._src()
        for dead in ("_trunc(r.stdout, 800)",
                     "_trunc(r.stdout + r.stderr, 1500)",
                     "_trunc(r.stdout, 1500)"):
            assert dead not in src, f"仍有硬编码截断残留（应走 _tool_window()）：{dead}"

    def test_call_sites_use_tool_window(self):
        src = self._src()
        # 2026-11-01：`search` 工具并入 `code_search`（原断言点随单点迁移）
        assert src.count('_trunc(r.stdout, _w, "search")') == 1, "code_search_gk 未接单点"
        assert "def search_gk" not in src and '"search": search_gk' not in src, \
            "search 工具已合并（不得残留第二检索通道）"
        # A1（2026-10-28）：`_gitnexus_cmd` 改走 `gk_gitnexus.run_raw` ⟹ 变量名从 r.stdout/r.stderr
        # 变成 out/err，但**截断单点**不变（仍必须经 `_tool_window()` + 类型 "gitnexus"）。
        assert src.count('_trunc(out + (err or ""), _tool_window(), "gitnexus")') == 1, \
            "gitnexus_gk 未接单点"
        assert src.count("_trunc(r.stdout + r.stderr, _tool_window())") == 1, \
            "_gatekeeper_cli 未接单点（默认 generic）"

    def test_truncation_marker_reports_current_window(self):
        """截断标记不得写死 1500（提上限后标记会说谎）。"""
        src = self._src()
        assert "exceeded 1500 chars" not in src
        assert "output exceeded {_w} chars" in src

    def test_max_count_is_env_readable(self):
        src = self._src()
        assert '_env_int("GK_CODE_SEARCH_MAX_COUNT", 30)' in src
        assert '"--max-count", "30"' not in src


class TestSoftTruncTypeAware:
    """ECC-7C85AE0600AC（2026-10-02）：软限塌缩从「一律 min(limit,600)」改为**类型化** head/tail。

    红先依据：原实现软限触发后 `limit = min(limit, 600)` + `s[:limit]` ⟹ ① 类型盲（read/error
    同一把刀）② 悬崖式 ③ 丢尾部（关键报错常在尾部）④ 无续读标记。本臂落刀前必红。
    """

    def _soft(self, monkeypatch):
        monkeypatch.setattr(sr, "_BUDGET", {**sr._BUDGET, "soft": True})

    def test_soft_keeps_tail_and_marker(self, monkeypatch):
        """软限后须保**尾部** + 带续读标记（原实现 head-only 且无标记）。"""
        self._soft(monkeypatch)
        s = "H" * 3000 + "TAIL_ERROR_MARKER"
        out = sr._trunc(s, 6000, "read")
        assert "TAIL_ERROR_MARKER" in out, "软限塌缩丢了尾部（关键报错在尾部会被砍）"
        assert "truncated" in out, "软限截断缺续读标记"

    def test_soft_window_type_aware_not_flat_600(self, monkeypatch):
        """软限窗口须**类型化**：read/search 明显 > 600，error 更紧（非一律 600）。"""
        self._soft(monkeypatch)
        big = "A" * 10000
        assert len(sr._trunc(big, 6000, "read")) > 600, "read 软限仍塌成 600（类型盲）"
        assert len(sr._trunc(big, 5000, "search")) > 600, "search 软限仍塌成 600（类型盲）"
        assert len(sr._trunc(big, 400, "error")) <= 520, "error 软限应更紧"

    def test_non_soft_path_keeps_head_and_marks_truncation(self, monkeypatch):
        """2026-11-01 契约变更：非软限也**必须带截断标记**（原 `s[:limit]` 零标记会让模型
        把「没看到」当「没影响」；标记里给出调参入口）。前截语义不变 = 前缀仍是原文。"""
        monkeypatch.setattr(sr, "_BUDGET", {**sr._BUDGET, "soft": False})
        out = sr._trunc("A" * 10000, 6000, "read")
        assert out.startswith("A" * 6000), "非软限前缀语义变了（应仍为前截）"
        assert "truncated 4000 chars" in out, "非软限截断缺标记"
        assert "GK_TOOL_OUTPUT_WINDOW" in out, "标记须指明调参入口"


class TestJsonTools:
    """JSON 专业工具（2026-09-01 用户质询：配 json 解析/读取/写专业工具 + subagent 全量配置）。
    统一注册于 TOOL_REGISTRY（json_extract/json_read/json_write），全档位白名单 + valid_tools 同步。"""

    def test_registered_in_registry(self):
        for name in ("json_extract", "json_read", "json_write"):
            assert name in sr.TOOL_REGISTRY
            assert name in sr.TOOL_REGION_MAP

    def test_all_tiers_include_json_tools(self):
        for tier in (1, 2, 3, 4):
            tools = set(sr.SUBA_TIERS[tier]["tools"].split(","))
            assert {"json_extract", "json_read", "json_write"} <= tools

    def test_extract_picks_result_not_warn(self):
        out = '{"level":40,"msg":"warn"}\n{"markdown": "x", "row_count": 9}'
        r = sr.TOOL_REGISTRY["json_extract"].__wrapped__(out)
        assert '"row_count": 9' in r

    def test_extract_with_path(self):
        r = sr.TOOL_REGISTRY["json_extract"].__wrapped__('{"stats": {"cdg": 8062}}',
                                                         "stats.cdg")
        assert '"value": 8062' in r

    def test_extract_no_json(self):
        r = sr.TOOL_REGISTRY["json_extract"].__wrapped__("纯文本输出")
        assert '"ok": false' in r

    def test_extract_default_fallback(self):
        r = sr.TOOL_REGISTRY["json_extract"].__wrapped__("{}", "a.b", "5")
        assert '"value": 5' in r

    def test_read_json_file(self, tmp_path):
        p = tmp_path / "r.json"
        p.write_text('{"a": 1}', encoding="utf-8")
        r = sr.TOOL_REGISTRY["json_read"].__wrapped__(str(p))
        assert '"a": 1' in r

    def test_read_missing_error(self):
        r = sr.TOOL_REGISTRY["json_read"].__wrapped__("Z:/nonexistent/x.json")
        assert '"error"' in r

    def test_write_json_atomic(self, tmp_path):
        p = tmp_path / "w.json"
        r = sr.TOOL_REGISTRY["json_write"].__wrapped__(str(p), "ok=true;n=3")
        assert '"ok": true' in r
        d = json.loads(p.read_text(encoding="utf-8"))
        assert d == {"ok": True, "n": 3}


class TestScopeAccessRoleGate:
    """F-REV-11 C1 (2026-09-10)：审计/红队角色 gate 源码只读面。

    审计/红队承担 gate 源码审查职责（gate = 红队重点打击对象），原 auditor/scanner/exploiter
    无 gate 区 → read_repo 读 gatekeeper-cli.sh 被 scope denied（L2/后R/红队 access_violations
    实证）→ 结构性覆盖缺口。C1 = 三角色 +gate 只读。F-REV-25 (2026-09-11)：read 工具区
    对齐 read_repo（亦含 gate）——同文件同角色不得因工具不同而拒；无 gate 角色
    （reporter/default）由角色层挡，泄漏面不扩。"""

    def test_auditor_can_read_gate_via_read_repo(self):
        ok, reason = sr.check_scope_access("read_repo", "gatekeeper-cli.sh", "auditor")
        assert ok, reason

    def test_scanner_can_read_gate_via_read_repo(self):
        ok, reason = sr.check_scope_access("read_repo", "gatekeeper-cli.sh", "scanner")
        assert ok, reason

    def test_exploiter_can_read_gate_via_read_repo(self):
        ok, reason = sr.check_scope_access("read_repo", "gatekeeper-cli.sh", "exploiter")
        assert ok, reason

    def test_reporter_still_denied_gate(self):
        """reporter 仅聚合证据，不读 gate 源码 → 保持 evidence-only。"""
        ok, _ = sr.check_scope_access("read_repo", "gatekeeper-cli.sh", "reporter")
        assert not ok

    def test_default_still_denied_gate(self):
        ok, _ = sr.check_scope_access("read_repo", "gatekeeper-cli.sh", "default")
        assert not ok

    def test_read_tool_region_matches_read_repo(self):
        """F-REV-25：read 工具区对齐 read_repo（同文件同角色不得因工具不同而拒）。"""
        assert "gate" in sr.TOOL_REGION_MAP["read"]
        assert set(sr.TOOL_REGION_MAP["read"]) == set(sr.TOOL_REGION_MAP["read_repo"])

    def test_read_tool_gate_allowed_for_gated_roles(self):
        """含 gate 角色经 read 亦可读 gate（修复前 read 无 gate → 同文件被拒 footgun）。"""
        for role in ("auditor", "scanner", "exploiter", "plan-refinement"):
            ok, reason = sr.check_scope_access("read", "gatekeeper-cli.sh", role)
            assert ok, f"{role}: {reason}"

    def test_read_tool_gate_denied_for_ungated_roles(self):
        """read 工具含 gate 后，无 gate 角色仍被角色层挡（泄漏面不扩）。"""
        for role in ("default", "reporter"):
            ok, _ = sr.check_scope_access("read", "gatekeeper-cli.sh", role)
            assert not ok, role

    def test_plan_refinement_precedent_unchanged(self):
        """plan-refinement 的 gate 只读先例不受 C1 影响。"""
        ok, reason = sr.check_scope_access("read_repo", "gatekeeper-cli.sh", "plan-refinement")
        assert ok, reason

    def test_role_region_matrix_has_gate(self):
        for role in ("auditor", "scanner", "exploiter", "plan-refinement"):
            assert "gate" in sr.ROLE_ALLOWED_REGIONS[role]
        assert "gate" not in sr.ROLE_ALLOWED_REGIONS["reporter"]
        assert "gate" not in sr.ROLE_ALLOWED_REGIONS["default"]


class TestGateEvidenceSnippet:
    """F-REV-11 C2 (2026-09-10)：GK_GATE_EVIDENCE（CLI 预取）→ 尾部追加 gate 源码变更证据。

    （F-REV-32 ⑩ 2026-09-11：注入位置从 instructions 迁到 user 输入尾部以提 KV 缓存命中；
    本类只验证 snippet 提取契约，"不进 instructions" 的位置断言见 TestKvCacheEvidenceTail。）

    C2 缺口 = L2/后R 此前无 gate 变更面证据（红队因读不到 bash 误判"F-REV-9 未接线"）。
    注入契约与 _l3_evidence_snippet 同构：缺 env / available:false / 坏 JSON / 空 digest
    → 一律返回空串（降级不阻断）。"""

    def test_no_env_empty(self, monkeypatch):
        monkeypatch.delenv("GK_GATE_EVIDENCE", raising=False)
        assert sr._gate_evidence_snippet() == ""

    def test_available_digest_injected(self, monkeypatch):
        monkeypatch.setenv("GK_GATE_EVIDENCE", json.dumps(
            {"available": True, "digest": "变更文件 1 个 · 变更块 2 个\n  gatekeeper-cli.sh +5/-1"}))
        out = sr._gate_evidence_snippet()
        assert "gate 源码变更证据" in out
        assert "gatekeeper-cli.sh +5/-1" in out

    def test_unavailable_empty(self, monkeypatch):
        monkeypatch.setenv("GK_GATE_EVIDENCE", json.dumps({"available": False, "error": "x"}))
        assert sr._gate_evidence_snippet() == ""

    def test_bad_json_empty(self, monkeypatch):
        monkeypatch.setenv("GK_GATE_EVIDENCE", "{not json")
        assert sr._gate_evidence_snippet() == ""

    def test_empty_digest_empty(self, monkeypatch):
        monkeypatch.setenv("GK_GATE_EVIDENCE", json.dumps({"available": True, "digest": ""}))
        assert sr._gate_evidence_snippet() == ""


class TestKvCacheEvidenceTail:
    """F-REV-32 ⑩ (2026-09-11 用户指令"KV 缓存参考 DSH 提高缓存命中的机制")。

    动态证据（L3 图证据 / gate 源码变更）原先拼进 instructions（进 system 面）→ 逐次变动使
    整个 system 前缀失配、KV 缓存命中率受损。改为随 user 输入**尾部追加**（对齐 DSH
    RuntimeContextProjection 尾部追加语义）。本类断言 instructions（system 面）不含证据摘要 ——
    行为断言，非源码子串断言（对齐 F-REV-31 断言纪律）。"""

    def test_evidence_excluded_from_instructions(self, monkeypatch):
        monkeypatch.setenv("GK_L3_EVIDENCE", json.dumps(
            {"available": True, "digest": "L3DIGEST-MARKER-XYZ"}))
        monkeypatch.setenv("GK_GATE_EVIDENCE", json.dumps(
            {"available": True, "digest": "GATEDIGEST-MARKER-ABC"}))
        monkeypatch.setattr(sr, "_CFG", None)
        sr._bootstrap(["--task", "t", "--api-base", "https://api.deepseek.com",
                       "--api-key", "sk-test"])
        # system 面（instructions）必须静态：不含逐次变动的证据摘要
        assert "L3DIGEST-MARKER-XYZ" not in sr.instructions
        assert "GATEDIGEST-MARKER-ABC" not in sr.instructions
        # 证据仍可取到 → 由 main() 尾部追加进 user 输入（内容不丢）
        assert "L3DIGEST-MARKER-XYZ" in sr._l3_evidence_snippet()
        assert "GATEDIGEST-MARKER-ABC" in sr._gate_evidence_snippet()
        monkeypatch.setattr(sr, "_CFG", None)  # 隔离：避免影响同进程其他用例


class TestStaticSystemPrompt:
    """F-REV-32 ⑤ (2026-09-11)：system prompt 深度静态化 + 工具字典序（对齐 DSH ①）。

    instructions（= system 面）须与「调用方传参顺序 / 逐次变动的 ctx」解耦：
      ① 工具列表按 **locale 无关字典序** 排序（同一工具集合换序 → instructions 逐字节相同）；
      ② 代码库上下文（files + r_phase）**迁出 instructions** → user 输入尾部（`_ctx_tail()`）。
    行为断言（真实 tmp 上下文文件 + 真实 bootstrap），非源码子串断言（对齐 F-REV-31 断言纪律）。"""

    def _boot(self, monkeypatch, extra):
        monkeypatch.setattr(sr, "_CFG", None)
        return sr._bootstrap(["--task", "t", "--api-base", "https://api.deepseek.com",
                              "--api-key", "sk-test"] + extra)

    def test_tool_order_locale_independent(self, monkeypatch):
        """同一工具集合、不同传入顺序 → tool_names 与 instructions 逐字节相同。"""
        self._boot(monkeypatch, ["--tools", "code_search,read,gitnexus"])
        names1, instr1 = list(sr.tool_names), sr.instructions
        self._boot(monkeypatch, ["--tools", "gitnexus,code_search,read"])
        assert names1 == sorted(names1)  # 字典序（码点序，locale 无关）
        assert list(sr.tool_names) == names1
        assert sr.instructions == instr1  # system 面不随传参顺序漂移
        monkeypatch.setattr(sr, "_CFG", None)  # 隔离：避免影响同进程其他用例

    def test_ctx_excluded_from_instructions(self, monkeypatch, tmp_path):
        """ctx（files + r_phase）不进 instructions；仍由 _ctx_tail() 取到（内容不丢）。"""
        ctxf = tmp_path / "ctx.json"
        ctxf.write_text(json.dumps({"files": ["/proj/RPHASE-MARKER-FILE"],
                                    "r_phase": "RPHASE-MARKER"}), encoding="utf-8")
        monkeypatch.setattr(sr, "CONTEXT_FILE", str(ctxf))
        self._boot(monkeypatch, ["--inject-context"])
        assert "RPHASE-MARKER" not in sr.instructions
        tail = sr._ctx_tail()
        assert "RPHASE-MARKER" in tail and "RPHASE-MARKER-FILE" in tail
        monkeypatch.setattr(sr, "_CFG", None)

    def test_ctx_tail_empty_without_flag(self, monkeypatch, tmp_path):
        """未启用 --inject-context → _ctx_tail() 返回 ""（不注入）。"""
        ctxf = tmp_path / "ctx.json"
        ctxf.write_text(json.dumps({"r_phase": "X"}), encoding="utf-8")
        monkeypatch.setattr(sr, "CONTEXT_FILE", str(ctxf))
        self._boot(monkeypatch, [])
        assert sr._ctx_tail() == ""
        monkeypatch.setattr(sr, "_CFG", None)

    def test_compose_task_last(self):
        """顺序契约：准稳定预取块（ctx + 证据）在前、**任务本体在末尾**（DSH ④ 指令置末同源）。"""
        out = sr._compose_user_text("TASK-BODY", "CTX-BLOCK\n", "EV-BLOCK\n")
        assert out == "CTX-BLOCK\nEV-BLOCK\nTASK-BODY"
        assert out.endswith("TASK-BODY")

    def test_compose_degenerate_unchanged(self):
        """无 ctx / 无证据 → 逐字节等价于旧行为（向后兼容）。"""
        assert sr._compose_user_text("TASK-BODY", "", "") == "TASK-BODY"
        assert sr._compose_user_text("TASK-BODY", "CTX", "") == "CTXTASK-BODY"


class TestImageInputPipeline:
    """F-REV-32 ⑬ (2026-09-11 用户指令"subagent 的图片输入对齐 DSH 的完整管线")。

    最小可用核心：content-part 序列化（base64 内联）+ 双守卫 + 预算/占位符（最旧优先 offload）。
    行为断言（真实 tmp 文件），对齐 F-REV-31 断言纪律。"""

    def _cfg_with_images(self, monkeypatch, paths):
        monkeypatch.setattr(sr, "_CFG", types.SimpleNamespace(image=[str(p) for p in paths]))

    def test_no_images_keeps_plain_string(self, monkeypatch):
        monkeypatch.delenv("SUBAGENT_IMAGES", raising=False)
        monkeypatch.setattr(sr, "_CFG", types.SimpleNamespace(image=[]))
        assert sr._build_run_input("task-text", "deepseek-flash") == "task-text"

    def test_text_only_route_fails_loud(self, monkeypatch, tmp_path):
        img = tmp_path / "a.png"
        img.write_bytes(b"\x89PNG\r\n\x1a\n")
        self._cfg_with_images(monkeypatch, [img])
        with pytest.raises(ValueError) as ei:
            sr._build_run_input("t", "deepseek-v4-pro")
        assert "UNSUPPORTED_CONTENT" in str(ei.value)

    def test_image_capable_model_builds_content_parts(self, monkeypatch, tmp_path):
        img = tmp_path / "a.png"
        img.write_bytes(b"\x89PNG\r\n\x1a\nDATA")
        self._cfg_with_images(monkeypatch, [img])
        out = sr._build_run_input("task", "deepseek-flash")
        assert isinstance(out, list) and out[0]["role"] == "user"
        content = out[0]["content"]
        assert content[0]["type"] == "input_text" and content[0]["text"] == "task"
        imgp = [p for p in content if p["type"] == "input_image"][0]
        assert imgp["image_url"].startswith("data:image/png;base64,")
        assert imgp["detail"] == "auto"

    def test_unreadable_image_fails_loud(self, monkeypatch, tmp_path):
        self._cfg_with_images(monkeypatch, [tmp_path / "nope.png"])
        with pytest.raises(ValueError) as ei:
            sr._build_run_input("t", "deepseek-flash")
        assert "IMAGE_UNREADABLE" in str(ei.value)

    def test_bad_extension_fails_loud(self, monkeypatch, tmp_path):
        p = tmp_path / "a.txt"
        p.write_bytes(b"x")
        self._cfg_with_images(monkeypatch, [p])
        with pytest.raises(ValueError) as ei:
            sr._build_run_input("t", "deepseek-flash")
        assert "UNSUPPORTED_CONTENT" in str(ei.value)

    def test_over_count_budget_oldest_offloaded(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SUBAGENT_MAX_IMAGES", "1")
        a = tmp_path / "a.png"
        a.write_bytes(b"A")
        b = tmp_path / "b.png"
        b.write_bytes(b"B")
        self._cfg_with_images(monkeypatch, [a, b])
        content = sr._build_run_input("t", "deepseek-flash")[0]["content"]
        # 最旧（a）降级为占位符，最新（b）保留为真图（DSH oldest-first offload）
        assert sum(1 for p in content if p["type"] == "input_image") == 1
        assert any(p["type"] == "input_text" and "图片未随请求发送" in p["text"] and str(a) in p["text"]
                   for p in content)
        # b"="B" 的 base64 = "Qg=="
        assert [p for p in content if p["type"] == "input_image"][0]["image_url"] == \
            "data:image/png;base64,Qg=="


    def test_sdk_converter_maps_to_chat_image_url(self, monkeypatch, tmp_path):
        """真实 SDK 契约校验（**无网络**）：agents 的 chatcmpl converter 把我们的
        input_text/input_image content-parts 映射为 chat completions 的 text/image_url。

        这是"构造对不对"到"SDK 真接受"的桥——不依赖 API 调用（F-REV-32 ⑬ 最小核心）。"""
        from agents.models.chatcmpl_converter import Converter
        img = tmp_path / "a.png"
        img.write_bytes(b"\x89PNG\r\n\x1a\nDATA")
        self._cfg_with_images(monkeypatch, [img])
        content = sr._build_run_input("task", "deepseek-flash")[0]["content"]
        out = Converter.extract_all_content(content)
        assert [p["type"] for p in out] == ["text", "text", "image_url"]
        assert out[2]["image_url"]["url"].startswith("data:image/png;base64,")
        assert out[2]["image_url"]["detail"] == "auto"


class _WireCaptured(Exception):
    """哨兵：伪造 client 捕获请求实参后抛出，终止 SDK 调用（零网络、零 API key）。"""


class TestWireLevelRequestShape:
    """F-REV-32 ⑤ 交叉验证：在 **SDK wire 层**（`chat.completions.create(**kwargs)` 实参）验证
    「静态前缀 + 末位任务」契约。

    方法：伪造 AsyncOpenAI client 捕获实参后抛哨兵，直接调用 SDK 真实的 `_fetch_response`
    （`agents.models.openai_chatcompletions.OpenAIChatCompletionsModel`）——断言对象是 **SDK 真正
    会发出去的请求体**（system 消息 / tools 数组顺序 / 末条 user 消息），而非本仓内部列表，
    故独立于实现细节（对齐 F-REV-31 断言纪律：行为断言优先）。

    覆盖两点本仓内部断言无法证实的性质：
      ① 工具顺序在 wire 上确为字典序（SDK 保序转换，见 openai_chatcompletions.py:637）；
      ② instructions 进 system 消息头部、且**不含** ctx/证据标记；块顺序为「准稳定块 → 任务」。
    """

    def _boot(self, monkeypatch, argv):
        monkeypatch.setattr(sr, "_CFG", None)
        return sr._bootstrap(["--task", "t", "--api-base", "https://api.deepseek.com",
                              "--api-key", "sk-test"] + argv)

    def _capture(self, monkeypatch, user_text):
        import asyncio

        from agents.models.interface import ModelTracing
        from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel

        captured: dict = {}

        class _FakeClient:
            base_url = "https://api.deepseek.com"

            def __init__(self):
                self.chat = types.SimpleNamespace(
                    completions=types.SimpleNamespace(create=self._create))

            async def _create(self, **kwargs):
                captured.update(kwargs)
                raise _WireCaptured

        model = OpenAIChatCompletionsModel(model=sr.model.model, openai_client=_FakeClient())

        async def _go():
            await model._fetch_response(
                system_instructions=sr.instructions, input=user_text,
                model_settings=sr.ds_settings, tools=sr.tools, output_schema=None,
                handoffs=[], span=None, tracing=ModelTracing.DISABLED, stream=False)

        with pytest.raises(_WireCaptured):
            asyncio.run(_go())
        monkeypatch.setattr(sr, "_CFG", None)  # 隔离：避免影响同进程其他用例
        return captured

    def test_wire_shape_static_prefix_and_task_last(self, monkeypatch, tmp_path):
        ctxf = tmp_path / "ctx.json"
        ctxf.write_text(json.dumps({"files": ["/proj/WIRE-CTX-FILE"],
                                    "r_phase": "WIRE-CTX-MARKER"}), encoding="utf-8")
        monkeypatch.setattr(sr, "CONTEXT_FILE", str(ctxf))
        monkeypatch.setenv("GK_L3_EVIDENCE", json.dumps(
            {"available": True, "digest": "WIRE-EV-MARKER"}))
        monkeypatch.setenv("GK_GATE_EVIDENCE", json.dumps(
            {"available": True, "digest": "WIRE-GATE-MARKER"}))

        self._boot(monkeypatch, ["--tools", "code_search,read,gitnexus", "--inject-context"])
        user_text = sr._compose_user_text(
            "WIRE-TASK-BODY", sr._ctx_tail(),
            sr._l3_evidence_snippet() + sr._gate_evidence_snippet())
        assert "WIRE-CTX-MARKER" in user_text  # 前置条件：ctx 确已生成
        req = self._capture(monkeypatch, user_text)

        # ① system 面 = instructions 且不为动态块污染（前缀可缓存）
        assert req["messages"][0]["role"] == "system"
        assert req["messages"][0]["content"] == sr.instructions
        for marker in ("WIRE-CTX-MARKER", "WIRE-EV-MARKER", "WIRE-GATE-MARKER"):
            assert marker not in req["messages"][0]["content"]
        # ② wire 层工具顺序 = 注册键字典序（`@function_tool` 以函数名为 wire 名，故按注册键序展开）
        names = [t["function"]["name"] for t in req["tools"]]
        assert names == [sr.TOOL_REGISTRY[k].name for k in sorted(("code_search", "read", "gitnexus"))]
        # ③ 末条 user 消息：准稳定块在前、任务本体在末尾；动态块内容不丢
        last = req["messages"][-1]
        assert last["role"] == "user"
        text = "\n".join(p["text"] for p in last["content"]) if isinstance(last["content"], list) \
            else last["content"]
        assert text.endswith("WIRE-TASK-BODY")
        assert "WIRE-CTX-MARKER" in text and "WIRE-EV-MARKER" in text

    def test_wire_tools_order_invariant_to_arg_order(self, monkeypatch):
        """① 交叉验证（顺序解耦）：`--tools` 传参顺序不同 → wire 层 tools 数组**逐字节相同**。

        这是"工具字典序"在 wire 层的可观测形式：SDK 保序转换（openai_chatcompletions.py:637）
        ⇒ 只要本仓传入的 `tools` 列表确定，请求体 `tools` 即确定，不受 CLI 传参顺序影响。"""
        self._boot(monkeypatch, ["--tools", "code_search,read,gitnexus"])
        a = self._capture(monkeypatch, "T")["tools"]
        self._boot(monkeypatch, ["--tools", "gitnexus,read,code_search"])
        b = self._capture(monkeypatch, "T")["tools"]
        assert a == b
        assert [t["function"]["name"] for t in a] != []  # 非空：确实下发了工具

    def test_wire_model_field_matches_chat_endpoint(self, monkeypatch):
        """chat completions 端点的模型名（非 responses 的 `deepseek-flash` 别名）随实参原样下发。"""
        self._boot(monkeypatch, ["--api-model", "deepseek-v4-flash"])
        req = self._capture(monkeypatch, "T")
        assert req["model"] == "deepseek-v4-flash"


class TestForeignContentForms:
    """F-REV-10 XSPI 覆盖面扩展（2026-09-11）：`_check_foreign_content` 用户根形态全覆盖。

    原实现只认 `C:\\Users\\<n>\\` 一种形态 ⇒ 正斜杠 / WSL / 长路径 / 行尾无分隔符 全漏，
    而本仓 scopes、REPO_ROOTS、文档日常就在写 `C:/` 与 `/mnt/c/` 形态。本类为**行为断言**
    （对齐 F-REV-31 断言纪律），并同时锁"不误报"面（URL 路径 / Windows 系统目录 / 任意
    `C:/x` 盘符路径 / 容器通用名）。"""

    def test_foreign_forms_all_detected(self):
        for text in ("<home>/proj/file.py",
                     r"<home>",                 # 行尾无分隔符
                     "<home>/x",
                     r"\\?\<home>\x",           # 长路径前缀
                     r"\\host\Users\otheruser\x"):          # UNC
            assert sr._check_foreign_content(text) is not None, text

    def test_own_user_forms_clean(self):
        own = sr._OWN_USER
        for text in (f"C:/Users/{own}/proj/file.py",
                     f"C:\\Users\\{own}\\proj",
                     f"/mnt/c/Users/{own}/proj",
                     f"/mnt/c/users/{own.lower()}/proj",     # 大小写归一
                     r"\\?\C:\Users" + f"\\{own}\\x"):
            assert sr._check_foreign_content(text) is None, text

    def test_no_false_positive_surfaces(self):
        own = sr._OWN_USER
        assert sr._check_foreign_content("https://example.com/Users/foo") is None  # URL 路径
        assert sr._check_foreign_content("<home>/Documents/x") is None    # Windows 系统目录
        assert sr._check_foreign_content("C:/temp/build.log") is None              # 非用户根，任意盘符路径
        assert sr._check_foreign_content("/home/root/x") is None                   # 容器通用名
        assert sr._check_foreign_content("plain text, no paths") is None
        assert own  # 前提：自有用户可解析

    def test_posix_home_foreign_detected(self):
        # P2c（2026-10-31）：返回契约随单源统一为具名 reason（原为裸 `/home/alice`）
        assert sr._check_foreign_content("/home/alice/project/src/a.py") == "foreign_user:alice"

    def test_legacy_literal_markers_still_hit(self):
        # P2c：字面量命中统一打 `leakage_marker:` 前缀（与 appeal/escalate 契约对齐）
        assert sr._check_foreign_content("xhs-copilot injected here") == "leakage_marker:xhs-copilot"
        assert sr._check_foreign_content("来源：小红书") == "leakage_marker:小红书"

    def test_empty_input_clean(self):
        assert sr._check_foreign_content("") is None


class TestFailPayloadSalvage:
    """2026-10-03（C4「凡有产出必留存」）：fail-closed 错误载荷的**单一构造点** `_ecc_fail_payload`。

    病象：原三出口（non_json_output / empty_ecc / empty_ecc_structure）各只留 `output_head[:200]`
    ⟹ 预算 HARD 截断的大 JSON / 结构不全的大 ECC 被吞（实测 10,937 字符计划质询分析丢失，
    sub-1791040188-202-6710）。修法 = 三出口共用本函数，恒留 head[:2000] + tail[-500:] + len。
    """

    def test_carries_head_tail_len(self):
        p = sr._ecc_fail_payload("truncated_json_output", "hint", "x" * 3000)
        assert p["mode"] == "subagent"
        assert p["error"] == "truncated_json_output"
        assert p["output_head"] == "x" * 2000
        assert p["output_tail"] == "x" * 500
        assert p["output_len"] == 3000
        assert p["hint"] == "hint"

    def test_empty_raw_is_zero_len(self):
        p = sr._ecc_fail_payload("empty_ecc", "hint", "")
        assert (p["output_head"], p["output_tail"], p["output_len"]) == ("", "", 0)

    def test_none_raw_tolerated(self):
        p = sr._ecc_fail_payload("non_json_output", "hint", None)
        assert p["output_len"] == 0 and p["output_head"] == ""

    def test_short_raw_not_padded(self):
        p = sr._ecc_fail_payload("non_json_output", "hint", "abc")
        assert p["output_head"] == "abc" and p["output_tail"] == "abc" and p["output_len"] == 3


class TestForeignContentSmuggle:
    """白名单提权走私攻防复跑（2026-09-13）。

    对齐 [test_pre_tool_hook](file:///c:/Users/HP/.trae/skills/spz-gatekeeper-r-sequence/scripts/test_pre_tool_hook.py)
    插件白名单豁免走私 A/B/C 先例（`--pid swe-rb` 豁免攻防），对象改为
    `_check_foreign_content` **新增的自有用户名白名单 + 豁免集**（F-REV-35 → F-REV-38）。
    走私定义 = 让**外租户内容**伪装成"自有/豁免"从而绕过检测。三类已被本轮修复；
    仍**有意保留**的豁免登记为已知走私面（锁定现状防静默扩大）。"""

    def test_A_root_relative_backslash_smuggled(self):
        """A：根相对 `\\Users\\<other>\\x`（归一 `//Users/<other>`）——旧正则要求带根前缀 ⇒ 漏检。"""
        assert sr._check_foreign_content(r"\Users\otheruser\x") is not None

    def test_B_traversal_after_own_prefix(self):
        """B：`C:/Users/<own>/../<other>/x` —— 自家前缀打头骗过白名单（提权走私核心形态）。"""
        own = sr._OWN_USER
        assert sr._check_foreign_content(f"C:/Users/{own}/../otheruser/secret.py") is not None
        assert sr._check_foreign_content(f"/home/{own}/../alice/x") is not None

    def test_C_posix_home_without_trailing_slash(self):
        """C：行尾 `/home/<other>`（无尾随 `/`）——旧正则要求尾随分隔符 ⇒ 漏检。"""
        assert sr._check_foreign_content("copy from /home/alice") is not None

    def test_url_host_not_regressed_by_new_bare_branch(self):
        """回归：A 的裸 `/Users/` 分支不得把 URL host 尾字母路径误报（负向断言）。"""
        assert sr._check_foreign_content("https://example.com/Users/foo") is None
        assert sr._check_foreign_content("see https://example.com/home/about") is None

    def test_known_exemptions_locked(self):
        """仍有意保留的豁免（已知走私面，F-REV-38 登记）——锁定现状防静默扩大。"""
        assert sr._check_foreign_content("<home>/Documents/x") is None
        assert sr._check_foreign_content("/home/root/.ssh/x") is None
        assert sr._check_foreign_content("/home/test/x") is None

    def test_own_user_forms_still_clean(self):
        own = sr._OWN_USER
        assert sr._check_foreign_content(f"C:/Users/{own}/proj") is None
        assert sr._check_foreign_content(r"\Users" + f"\\{own}\\x") is None


class TestVerdictVocab:
    """F-REV-21 范围外待办 → 实装（2026-09-11，XSPI 覆盖面扩展）：verdicts 闭词表约束。

    verdicts 是持久通道载波（state.human_calibration_log[].verdicts_json = 人类裁判通道 /
    state.subagent_history[].verdicts = 子代理自评通道，两通道禁合并——F-REV-41 第三轮
    键名勘误；聚合器/appeal/audit 回读），自由文本 = 无界注入面。约束 = 归一
    ∈{PASS,WARN,BLOCKED} + 越界登记（禁静默改写）。"""

    def test_vocab_passthrough_and_case(self):
        out, vv = sr._normalize_verdicts({"F1": "PASS", "F2": "warn", "F3": " blocked "})
        assert out == {"F1": "PASS", "F2": "WARN", "F3": "BLOCKED"} and vv == []

    def test_alias_normalization(self):
        out, vv = sr._normalize_verdicts(
            {"F1": "passed", "F2": "FAIL", "F3": "Suspect", "F4": "OK"})
        assert out == {"F1": "PASS", "F2": "BLOCKED", "F3": "WARN", "F4": "PASS"} and vv == []

    def test_bool_mapping(self):
        out, vv = sr._normalize_verdicts({"F1": True, "F2": False})
        assert out == {"F1": "PASS", "F2": "BLOCKED"} and vv == []

    def test_out_of_vocab_kept_and_logged(self):
        out, vv = sr._normalize_verdicts({"F1": "maybe-later"})
        assert out["F1"] == "maybe-later"          # 不静默丢弃
        assert vv == [{"key": "F1", "raw": "maybe-later", "reason": "out_of_vocab"}]

    def test_long_value_truncated_to_bound(self):
        out, vv = sr._normalize_verdicts({"F1": "X" * 200})
        assert len(out["F1"]) == sr._VERDICT_RAW_MAX and vv[0]["reason"] == "out_of_vocab"

    def test_non_dict_raw_fails_soft(self):
        out, vv = sr._normalize_verdicts(None)
        assert out == {} and vv[0]["reason"] == "not_a_dict"

    def test_non_string_value_logged(self):
        out, vv = sr._normalize_verdicts({"F1": 7})
        assert out["F1"] == "7" and vv[0]["reason"] == "non_string:int"


class TestPlanRequiredFieldCheck:
    """F-REV-81（2026-09-16）：质询「五源验证」必需字段的机检 + 指令模板合一守护。

    根因（读码 + 14/14 artifact 实测）：指令**两份输出模板自相矛盾**（一份要求
    verification_checklist，最终模板不含该字段且写死"未按此格式判失败"）⟹ 模型恒不加，
    且 runner 无任何机检。修法 = 模板合一 + 本机检（缺 → 重试一次 → status=incomplete）。
    """

    def test_missing_plan_fields_present(self):
        ok = {"constraint_matrix": [{"constraint": "F1"}], "verification_checklist": [{"task": "x"}]}
        assert sr._missing_plan_fields(ok) == []

    def test_missing_plan_fields_absent_and_degenerate(self):
        """键缺失 / 空 list / 非 list 一律判缺（非空数组才算齐备）。"""
        assert sr._missing_plan_fields({}) == ["constraint_matrix", "verification_checklist"]
        assert sr._missing_plan_fields({"constraint_matrix": [],
                                        "verification_checklist": {}}) == [
            "constraint_matrix", "verification_checklist"]

    def test_missing_plan_fields_none_safe(self):
        assert sr._missing_plan_fields(None) == ["constraint_matrix", "verification_checklist"]

    def test_partial_missing(self):
        assert sr._missing_plan_fields({"constraint_matrix": [1]}) == ["verification_checklist"]

    def test_verification_field_in_ecc(self):
        """verification 必须在 EccOutput（runner 侧确定性写入）；HMAC 双端同构由 parity 类守护。"""
        assert "verification" in sr.EccOutput.model_fields

    def test_instruction_template_single_authoritative(self):
        """模板合一：质询指令只保留**一份**输出模板，且必需字段均在其中（防两份模板再分叉）。"""
        t = sr._PLAN_REFINEMENT_INSTRUCTIONS
        assert t.count("## 输出 JSON") == 1, "质询指令出现多份输出模板（F-REV-81 根因复发）"
        assert "唯一权威模板" in t
        for f in sr._PLAN_REQUIRED_FIELDS:
            assert f in t, f


class TestTokenUsageTrace:
    """F-REV-82（2026-09-16，用户裁定「先留痕再标定」）：token 五元组留痕。

    口径警告：`token_budget` 是**成本当量**（miss + hit×系数 + completion×系数），不是 raw token
    ⟹ 留痕必须同时给 raw/hit/miss/completion，否则无法回答「档位相对日耗是否过低」。
    """

    def test_field_in_ecc(self):
        assert "token_usage" in sr.EccOutput.model_fields

    def test_budget_usage_keys(self):
        # 2026-09-23 P2（对齐 DSH `TokenUsage`）：新增 `reasoning` 桶。
        # DSH `packages/llm/llm/src/types.ts::TokenUsage` = {inputTokens, outputTokens,
        # totalTokens?, cacheReadTokens?, cacheWriteTokens?, reasoningTokens?}；映射到本仓：
        #   inputTokens → (hit + miss) / outputTokens → completion / totalTokens → raw /
        #   cacheReadTokens → hit / **reasoningTokens → reasoning（新增）** /
        #   cacheWriteTokens → 本仓 provider（DeepSeek）**不上报** ⟹ 如实不设该桶
        #   （不造恒 0 的假字段：假字段会让「DV 里有没有这个量」再也无法用字段存在性判定）。
        # 2026-10-17 P2（二条件 b）：新增运行时前缀/相位观测量
        #   prefix_changes → 前缀指纹变化次数（缓存失效归因）
        #   phase_turns    → 相位有效轮次数（GK_PHASE_TURN_STRIDE 调度）
        #   phase_injections → 相位边界尾部追加实际发生次数（干预层）
        assert set(sr._BUDGET["usage"]) == {
            "raw", "hit", "miss", "completion", "cost", "rounds", "reasoning",
            "prefix_changes", "phase_turns", "phase_injections"}

    def test_on_llm_end_traces_reasoning_bucket(self):
        """红先臂（P2）：`completion_tokens_details.reasoning_tokens` 必须进 `reasoning` 桶。

        口径（**防重复计费**）：`reasoning` 是 `completion` 的**子集**（DeepSeek 的
        `completion_tokens` 本身已含思考 token）⟹ 只作**观测量**，**不得**并入 `cost` 当量。
        """
        import asyncio

        class _D:
            reasoning_tokens = 30

        class _U:
            total_tokens = 1000
            prompt_cache_hit_tokens = 900
            prompt_cache_miss_tokens = 100
            completion_tokens = 50
            completion_tokens_details = _D()

        class _R:
            usage = _U()

        before = dict(sr._BUDGET["usage"])
        tok_before = sr._BUDGET["tokens"]
        asyncio.run(sr._BudgetHooks().on_llm_end(None, None, _R()))
        u = sr._BUDGET["usage"]
        assert u["reasoning"] - before["reasoning"] == 30, (
            "未采集 reasoning token（DSH TokenUsage.reasoningTokens 对应桶）")
        exp_cost = 100 + round(900 * sr._PRICE_HIT_RATIO) + round(50 * sr._PRICE_OUTPUT_RATIO)
        assert sr._BUDGET["tokens"] - tok_before == exp_cost, (
            f"reasoning 是 completion 的子集 ⟹ 不得并入 cost 当量（重复计费）："
            f"实测 {sr._BUDGET['tokens'] - tok_before} ≠ {exp_cost}")

    def test_reasoning_bucket_absent_provider_is_zero(self):
        """负臂 · 守「provider 不上报时不崩、不虚增」：无 `completion_tokens_details` → 桶保持 0。

        判别面：`getattr` 链必须是**防御式**的（旧 provider / 无缓存字段的降级路径同样要活）。
        """
        import asyncio

        class _U:
            total_tokens = 500
            prompt_cache_hit_tokens = 0
            prompt_cache_miss_tokens = 0
            completion_tokens = 20

        class _R:
            usage = _U()

        before = sr._BUDGET["usage"]["reasoning"]
        asyncio.run(sr._BudgetHooks().on_llm_end(None, None, _R()))
        assert sr._BUDGET["usage"]["reasoning"] == before, "缺字段时 reasoning 桶被虚增"

    def test_on_llm_end_accumulates_five_tuple(self):
        import asyncio

        class _U:
            total_tokens = 1000
            prompt_cache_hit_tokens = 900
            prompt_cache_miss_tokens = 100
            completion_tokens = 50

        class _R:
            usage = _U()

        before = dict(sr._BUDGET["usage"])
        tok_before = sr._BUDGET["tokens"]
        asyncio.run(sr._BudgetHooks().on_llm_end(None, None, _R()))
        u = sr._BUDGET["usage"]
        assert u["raw"] - before["raw"] == 1000
        assert u["hit"] - before["hit"] == 900
        assert u["miss"] - before["miss"] == 100
        assert u["completion"] - before["completion"] == 50
        assert u["rounds"] - before["rounds"] == 1
        exp_cost = 100 + round(900 * sr._PRICE_HIT_RATIO) + round(50 * sr._PRICE_OUTPUT_RATIO)
        assert u["cost"] - before["cost"] == exp_cost
        assert sr._BUDGET["tokens"] - tok_before == exp_cost   # 预算口径 = cost 当量（非 raw）


class TestEccModelParity:
    """HMAC 双端模型同构守护（2026-09-11 新增）。

    已知故障模式（subagent_runner 注释实录）：CLI 侧 `O()` 与 runner 侧 `EccOutput` 字段
    不同构 → 两端 `model_dump()` 重算 payload 不一致 → **全部输出判 tampered** → ECO-EDIT
    断链。此前无任何自动化守护（仅靠注释纪律）；本测试解析两端字段集合并断言相等，同时断言
    CLI 内两份 `O()` 冗余副本彼此一致（副本漂移属同族故障）。"""

    def _cli_o_field_sets(self) -> list[set]:
        import re
        cli = (Path(__file__).parent.parent / "gatekeeper-cli.sh").read_text(encoding="utf-8")
        bodies = re.findall(r"class O\(BaseModel\):\s*(.+)$", cli, re.M)
        return [{seg.split(":", 1)[0].strip() for seg in b.split(";") if ":" in seg}
                for b in bodies]

    def test_cli_copies_identical_and_match_runner(self):
        sets = self._cli_o_field_sets()
        assert sets, "CLI 中未找到 O() 模型"
        assert all(s == sets[0] for s in sets), "CLI 内两份 O() 副本字段漂移"
        assert sets[0] == set(sr.EccOutput.model_fields), (
            "HMAC 双端字段不同构 → 全部输出将判 tampered（ECO-EDIT 断链）")


class TestCliMonitorUnknownFlag:
    """ECC-310D65FD844A（2026-09-24 实测）：cmd_monitor 的 catch-all `*) stage="$1"` 会把**任意
    未识别 token** 写进 `stage`，而 `--subagent` 模式下 `stage` 就是**任务载体** ⟹
    `monitor --subagent <任务> --tier 1` 会把任务**静默覆盖**成 `1`（三次运行实证：报告头
    「任务」字段均为 `1`）。修法 = 未知 flag **fail-loud**（对齐 paper-review 的 unknown arg
    exit 2）；**档位走 env `SUBAGENT_TIER`**（apply-worktree 返回的 next 串即此形），
    禁止在 monitor 上再造 `--tier` 第二通道。bash CLI 依赖 WSL 形态 → 按本文件既有先例做文本断言。
    """

    CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"

    @staticmethod
    def _monitor_body() -> str:
        import re
        txt = TestCliMonitorUnknownFlag.CLI.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"^cmd_monitor\(\)\s*\{.*?\n\}", txt, re.S | re.M)
        assert m, "cmd_monitor 函数体未定位"
        return m.group(0)

    @staticmethod
    def _unknown_flag_branch() -> str:
        """切出 `-*)` 分支本体（`-*)` → 该分支首个 `;;`）。

        判据必须**绑在分支内**：全局搜 `SUBAGENT_TIER` 会被函数体里既有的 env 透传注释
        （L3437/3569）喂饱 ⟹ 恒真空臂（首版即此坑，HEAD 上假绿）。"""
        import re
        m = re.search(r"^\s*-\*\).*?;;", TestCliMonitorUnknownFlag._monitor_body(), re.S | re.M)
        assert m, "cmd_monitor 无未知 flag 的 fail-loud 分支"
        return m.group(0)

    def test_unknown_flag_fails_loud(self):
        branch = self._unknown_flag_branch()
        assert "unknown flag" in branch, "未知 flag 分支未给出显式错误"
        assert "return 2" in branch, "未知 flag 分支未 fail-loud（缺 return 2）"

    def test_tier_flag_is_not_silently_accepted(self):
        import re
        assert not re.search(r"--tier\)", self._monitor_body()), \
            "cmd_monitor 出现了 --tier 分支（档位应只走 env SUBAGENT_TIER，勿造第二通道）"

    def test_unknown_flag_hint_points_to_env_tier(self):
        assert "SUBAGENT_TIER" in self._unknown_flag_branch(), \
            "未知 flag 的 usage 未指向 env SUBAGENT_TIER（档位唯一通道）"

    def test_stage_positional_still_supported(self):
        import re
        assert re.search(r"^\s*\*\)\s*stage=\"\$1\";\s*shift\s*;;", self._monitor_body(), re.M), \
            "stage 位置参数通道被误删（--local/--api 调用方依赖）"


class TestCliMonitorRoleWiring:
    """F-REV-11 C2：cmd_monitor --role 白名单与 ROLE_ALLOWED_REGIONS 同集 + crossfull 具名角色。

    bash CLI 依赖 WSL 形态（pytest 内无法可靠直跑）→ 按本仓既有先例（test_eco_integration
    的 CLI 结构断言）做定向文本断言。角色白名单双源漂移由本类第一条用例守护。"""

    CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"

    def _text(self):
        return self.CLI.read_text(encoding="utf-8", errors="replace")

    def test_role_whitelist_matches_runner(self):
        """bash 白名单必须与 subagent_runner.ROLE_ALLOWED_REGIONS 同集（防第二事实源漂移）。"""
        import re
        m = re.search(r"^\s*(default\|plan-refinement\|[a-z|\-]+\)\s*;;)", self._text(), re.M)
        assert m, "cmd_monitor --role 白名单 case 行未找到"
        roles = set(m.group(1).split(")")[0].split("|"))
        assert roles == set(sr.ROLE_ALLOWED_REGIONS), \
            f"角色白名单漂移: {roles ^ set(sr.ROLE_ALLOWED_REGIONS)}"

    def test_role_flag_parsed(self):
        # 2026-09-24（flag 缺值族修复 `ECC-AAD612CC8270`）：`$2` 全仓加缺省引用
        # （`${2:-}`）⟹ 断言语义改为「--role 分支把值赋给 role_override」，
        # 不再钉死 `$2` 字面（否则机械改写即红，测试锁住实现细节）。
        assert '--role) role_override="' in self._text(), "cmd_monitor 未解析 --role"

    def test_role_override_applied(self):
        assert '[ -n "$role_override" ] && subagent_role="$role_override"' in self._text(), \
            "--role 未覆盖自动推导的 subagent_role"

    def test_gate_evidence_env_injected(self):
        txt = self._text()
        assert 'GK_GATE_EVIDENCE="${_gtev:-}"' in txt, "subagent 调用未注入 GK_GATE_EVIDENCE"
        assert "gk_gate_evidence.py" in txt, "gate 证据计算点缺失（bash 侧唯一计算点）"

    def test_crossfull_driver_named_roles(self):
        """L2 --crossrev → auditor；后R #1 → auditor / #2 → exploiter（不再落 default）。"""
        txt = self._text()
        assert '"--crossrev", "--role", "auditor"' in txt, "L2 未传具名角色"
        assert '"--role", _rrole' in txt, "后R 未传具名角色"
        assert '"auditor")' in txt and '"exploiter")' in txt, "后R 角色映射缺失"


class TestBudgetPriceRatios:
    """F-REV-17a 峰谷口径：系数取自 DeepSeek V4.1 Flash 官方峰谷定价表的**同比值**。

    空闲 hit 0.02 / miss 1.00 / out 4.00；高峰 hit 0.04 / miss 2.00 / out 8.00
    ⇒ 命中:未命中 = 1/50 = 0.02（峰谷同比 ⇒ 单组系数即忠实）。
    回归锚：原实现 0.1（与注释"50 倍差"自相矛盾、高估 5×）。
    """

    def test_hit_ratio_is_table_derived(self):
        assert sr._PRICE_HIT_RATIO == 0.02

    def test_output_ratio_keeps_tier_calibration(self):
        """输出真实比值 4.0，但默认保持 1.0（SUBA_TIERS 按旧口径标定；改 4.0 需先重标定）。"""
        assert sr._PRICE_OUTPUT_RATIO == 1.0


class TestModelChainDsAlignment:
    """F-REV-17：模型链对齐 DSH `llm-deepseek`（单一 route + model id 透传 + env 覆盖）。

    DSH 原则：model id 透传上线（新模型免改代码）、baseURL env 优先、catalog 仅 advisory。
    回归网：V3 旧名 `deepseek-chat` 已停用（2026-04-24 公告 2026-07-24 停用）→ 全链清零。
    """

    CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"

    def _text(self):
        return self.CLI.read_text(encoding="utf-8", errors="replace")

    def test_no_stale_deepseek_chat_in_cli(self):
        assert "deepseek-chat" not in self._text(), "CLI 残留 V3 旧模型名 deepseek-chat"

    def test_default_models_are_deepseek_flash(self):
        txt = self._text()
        assert 'DS_MODEL_CRITIC="${GK_CRITIC_MODEL:-deepseek-flash}"' in txt
        assert 'DS_MODEL_ACTOR="${GK_ACTOR_MODEL:-deepseek-flash}"' in txt

    def test_base_url_env_precedence(self):
        assert 'DS_API_BASE="${DEEPSEEK_BASE_URL:-https://api.deepseek.com}"' in self._text()

    def test_reasoning_effort_env_override(self):
        assert 'DS_REASONING_EFFORT="${GK_REASONING_EFFORT:-max}"' in self._text()

    def test_advisory_catalog_present(self):
        assert "DS_CATALOG_MODELS=" in self._text(), "advisory catalog 缺失（DSH 语义）"

    def test_python_defaults_aligned(self):
        for f in ("subagent_runner.py", "gk_monitor_api.py", "gk_reflect.py",
                  "gk_self_check.py", "gk_appeal.py"):
            p = Path(__file__).parent / f
            assert "deepseek-chat" not in p.read_text(encoding="utf-8"), f"{f} 残留旧模型名"


class TestReadCommonMerge:
    """F-REV-25 (2026-09-11)：read_gk_file / read_repo_file 双实现合并为 _read_common。

    合并后两工具共享同一 blocklist（含 .git/）与 .tex 注释剥离；差异仅由参数注入
    （root / region_key / tool_label / display）。本类用隔离 tmp 根验证行为一致，
    工具签名/docstring（LLM 面 schema）不变。"""

    @pytest.fixture
    def skill_root(self, tmp_path, monkeypatch):
        """隔离 SKILL_DIR + bootstrap 配置（_check_file_size 需 _cfg().tier）+ 具名角色。"""
        monkeypatch.setattr(sr, "_CFG", types.SimpleNamespace(tier=3, mode="crossrev"))
        monkeypatch.setattr(sr, "SKILL_DIR", str(tmp_path))
        monkeypatch.setenv("SUBAGENT_ROLE", "auditor")
        yield tmp_path
        monkeypatch.setattr(sr, "_CFG", None)

    def _read(self, path, offset=0):
        return sr.TOOL_REGISTRY["read"].__wrapped__(path, offset)

    def test_reads_content(self, skill_root):
        (skill_root / "notes.txt").write_text("hello body", encoding="utf-8")
        assert self._read("notes.txt") == "hello body"

    def test_paging_marker(self, skill_root, monkeypatch):
        monkeypatch.setenv("GK_READ_WINDOW", "1500")
        (skill_root / "big.txt").write_text("a" * 2000, encoding="utf-8")
        out = self._read("big.txt", 0)
        assert out.startswith("[chars 0-1500 of 2000")
        assert "offset=1500" in out

    def test_traversal_denied(self, skill_root):
        with pytest.raises(PermissionError):
            self._read("../escape.txt")

    def test_git_internal_blocked(self, skill_root):
        """.git/ 拦截为合并后统一行为（原 read_gk_file 缺此条 ⇒ 双实现漂移）。"""
        (skill_root / ".git").mkdir()
        (skill_root / ".git" / "config").write_text("x", encoding="utf-8")
        with pytest.raises(PermissionError) as e:
            self._read(".git/config")
        assert "VCS" in str(e.value)

    def test_crypto_material_blocked(self, skill_root):
        (skill_root / ".keys").mkdir()
        (skill_root / ".keys" / "audit_ed25519").write_text("k", encoding="utf-8")
        with pytest.raises(PermissionError):
            self._read(".keys/audit_ed25519")

    def test_gate_readable_by_gated_role(self, skill_root):
        """auditor（含 gate）经 read 可读 gatekeeper-cli.sh（合并前被工具区拒 = footgun）。"""
        (skill_root / "gatekeeper-cli.sh").write_text("#!/bin/bash\n", encoding="utf-8")
        assert self._read("gatekeeper-cli.sh") == "#!/bin/bash\n"

    def test_gate_denied_for_ungated_role(self, skill_root, monkeypatch):
        monkeypatch.setenv("SUBAGENT_ROLE", "default")
        (skill_root / "gatekeeper-cli.sh").write_text("x", encoding="utf-8")
        with pytest.raises(PermissionError):
            self._read("gatekeeper-cli.sh")

    def test_tex_comment_stripped(self, skill_root):
        """.tex 注释剥离为合并后统一行为（原 read_gk_file 缺此条）。"""
        (skill_root / "p.tex").write_text("body % TODO leak\n", encoding="utf-8")
        assert self._read("p.tex") == "body "

    def test_access_violation_logged(self, skill_root):
        n = len(sr._ACCESS_VIOLATIONS)
        (skill_root / ".git").mkdir()
        (skill_root / ".git" / "config").write_text("x", encoding="utf-8")
        with pytest.raises(PermissionError):
            self._read(".git/config")
        assert len(sr._ACCESS_VIOLATIONS) == n + 1
        assert sr._ACCESS_VIOLATIONS[-1].tool == "read_gk_file"

    def test_read_repo_unknown_repo_error(self):
        out = sr.TOOL_REGISTRY["read_repo"].__wrapped__("nope-repo", "x.txt")
        assert out.startswith("[ERROR] unknown repo")

    def test_read_repo_shares_common_path(self, tmp_path, monkeypatch):
        """read_repo_file 经同一 _read_common：.git/ 拦截 + gate 区域 + 正常读一致。"""
        monkeypatch.setattr(sr, "_CFG", types.SimpleNamespace(tier=3, mode="crossrev"))
        monkeypatch.setenv("SUBAGENT_ROLE", "auditor")
        monkeypatch.setitem(sr.REPO_ROOTS, "tmprepo", str(tmp_path))
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "HEAD").write_text("x", encoding="utf-8")
        with pytest.raises(PermissionError) as e:
            sr.TOOL_REGISTRY["read_repo"].__wrapped__("tmprepo", ".git/HEAD")
        assert "VCS" in str(e.value)
        (tmp_path / "gatekeeper-cli.sh").write_text("z", encoding="utf-8")
        assert sr.TOOL_REGISTRY["read_repo"].__wrapped__("tmprepo", "gatekeeper-cli.sh") == "z"
        monkeypatch.setattr(sr, "_CFG", None)


class TestCliCtxInjectGuard:
    """F-REV-24 (2026-09-11)：cmd_monitor 上下文注入**四态**须全覆盖（禁静默放行）。

    缺口 = ctx 文件**整体缺失**时 sig_invalid/sig_missing 两条分支都不命中 ⇒ inject_flag 空
    且 ctx_inject_ok 保持 true：既不注入也不阻断 → 审查/质询通道无上下文仍照常下发。
    修法 = else 分支（ctx_missing）+ preflight A 单列错误码。R2 MoA 质询（2026-09-11）追加：
    ① 细分 ctx_missing / ctx_missing_orphan_sig（运维动作不同：context --update vs 清孤儿 sig）；
    ② 覆盖边界显式化（阻断仅 plan-refinement / --crossrev 两通道，RED-*/default 仅 WARN）。
    bash 逻辑在 pytest 内无法可靠直跑 → 按 TestCliMonitorRoleWiring 先例做定向结构断言
    （已知局限：只证源码含该控制流，不证运行时分支走向）。"""

    CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"

    def _text(self):
        return self.CLI.read_text(encoding="utf-8", errors="replace")

    def test_ctx_inject_four_states_covered(self):
        """四态齐全：sig_invalid / sig_missing / ctx_missing / ctx_missing_orphan_sig 各自赋值。"""
        txt = self._text()
        for reason in ("sig_invalid", "sig_missing", "ctx_missing", "ctx_missing_orphan_sig"):
            assert f'ctx_inject_reason="{reason}"' in txt, reason

    def test_ctx_missing_marks_not_ok(self):
        """两缺失态必须把 ctx_inject_ok 置 false（消灭"保持 true 的静默放行"）。"""
        txt = self._text()
        assert 'ctx_inject_ok=false; ctx_inject_reason="ctx_missing"' in txt
        assert 'ctx_inject_ok=false; ctx_inject_reason="ctx_missing_orphan_sig"' in txt

    def test_orphan_sig_branch_before_else(self):
        """孤儿签名分支必须在 else 之前（防两态再被压平致诊断信息损失）。"""
        assert 'elif [ -f "$ctx_sig" ]; then' in self._text()

    def test_orphan_sig_distinct_fix_hint(self):
        """孤儿签名态须带独有文案 + 运维引导（清理孤儿 .sig）。"""
        txt = self._text()
        assert "orphan .sig present" in txt
        assert "删除孤儿 references/subagent-context.json.sig" in txt

    def test_ctx_missing_warns_and_logs(self):
        """缺失态必须显式 WARN + GK_DBG_LOG 留痕（与另两态同构，禁静默）。"""
        txt = self._text()
        assert "context file missing — no context injection" in txt
        assert "[ctx-inject] context file missing" in txt
        assert "[ctx-inject] ctx missing + orphan sig" in txt
        assert "review_block_candidate" in txt

    def test_preflight_distinguishes_missing_states(self):
        """preflight A 对两缺失态单列错误码（CONTEXT_MISSING / CONTEXT_MISSING_ORPHAN_SIG）。"""
        txt = self._text()
        assert '_a_err="CONTEXT_STALE_OR_UNSIGNED"' in txt
        assert 'ctx_missing_orphan_sig)' in txt
        assert '_a_err="CONTEXT_MISSING_ORPHAN_SIG"' in txt
        assert '_a_err="CONTEXT_MISSING"' in txt
        assert '"error\\":\\"$_a_err\\"' in txt

    def test_preflight_only_two_channels(self):
        """覆盖边界（R2）：preflight 仅 plan-refinement / --crossrev 两通道触发；
        RED-*/default 车道不调 preflight ⇒ ctx 缺失仅 WARN，不硬阻断（纠正"全序列恒阻断"误判）。

        2026-10-01（`ECC-FAB556F786E5`）：**载体**由「推断出的 `subagent_role`」改为**显式**
        `role_override` —— 原条件 = 被守卫对象自身（循环依赖：角色靠 task 自由文本子串猜、
        门禁靠角色 ⟹ 猜错时门禁根本不 arm）。语义不变（仍恰两通道），本臂随契约同步。
        """
        assert '[ "$role_override" = "plan-refinement" ] || $crossrev_flag' in self._text()

    def test_degrade_switch_semantics_noted(self):
        """GK_ALLOW_STALE_CTX 亦授权 missing（语义扩容）→ 须代码内显式注记，防运维误用。"""
        assert "该开关名只表 stale" in self._text()

    def test_preflight_blocks_before_dispatch(self):
        """阻断必须在 subagent 下发前（preflight 调用早于 runner 调用）。"""
        txt = self._text()
        i_prefl = txt.index('_review_channel_preflight "$_rp_channel"')
        i_disp = txt.index('$subagent_python "$subagent_runner"')
        assert i_prefl < i_disp

    def test_allow_stale_ctx_still_degrades(self):
        """GK_ALLOW_STALE_CTX=1 降级出口保留（缺失/失效不硬锁死运维通道）。"""
        txt = self._text()
        assert 'GK_ALLOW_STALE_CTX' in txt
        assert "ctx degrade allowed (GK_ALLOW_STALE_CTX=1)" in txt


class TestCodeSearchRgFix:
    """F-REV-26 (2026-09-11)：code_search_gk 宿主路径形态错配修复。

    缺口 = 原实现 `bash -c "cd {SKILL_DIR} && rg … 2>/dev/null"`：生产宿主（Windows py311，
    `suagent_py311.sh`）下 `bash` 是 **WSL bash**，`cd C:\\…` 的反斜杠被吞 → 必然失败，且
    stderr 被 `2>/dev/null` 吞 ⇒ 恒 `[NO MATCH]`（工具层静默失效）。
    修法 = 直连 rg（argv 列表 + `cwd=SKILL_DIR`，无 shell）+ 失败禁静默。
    本类在 **Windows py311（= 生产宿主形态）** 下运行 ⇒ `test_real_search_returns_matches`
    即生产形态的行为验收（旧实现在此形态下恒 [NO MATCH]）。"""

    @pytest.fixture(autouse=True)
    def _boot(self, monkeypatch):
        """工具首行 `_budget_blocked()` 依赖 `_BUDGET_*` 全局（定义在 `_bootstrap()` 内）。"""
        monkeypatch.setattr(sr, "_CFG", None)
        sr._bootstrap(["--task", "t", "--api-base", "https://api.deepseek.com",
                       "--api-key", "sk-test", "--tier", "3"])
        yield
        monkeypatch.setattr(sr, "_CFG", None)

    def test_no_bash_shell_used(self):
        """结构回归守卫：不得再经 `bash -c`（路径形态错配的载体）。

        只断言**代码字面量** `["bash"`（docstring 里描述旧写法不算）。
        """
        import inspect
        src = inspect.getsource(sr.code_search_gk.__wrapped__)
        assert '["bash"' not in src, "code_search 仍经 bash 壳 → 宿主路径错配会复发"
        assert "cwd=SKILL_DIR" in src, "路径形态应由 cwd 承担（host 无关）"

    def test_rg_bin_env_override(self, monkeypatch):
        monkeypatch.setenv("GK_RG", "/custom/rg")
        assert sr._rg_bin() == "/custom/rg"

    def test_rg_bin_path_lookup(self, monkeypatch):
        monkeypatch.delenv("GK_RG", raising=False)
        assert sr._rg_bin() == sr.shutil.which("rg")

    def test_missing_rg_fails_loud(self, monkeypatch):
        """无 rg → 显式 ERROR（不再静默 [NO MATCH]）。patch 模块内 _rg_bin，不碰标准库全局。"""
        monkeypatch.setattr(sr, "_rg_bin", lambda: None)
        out = sr.code_search_gk.__wrapped__("x")
        assert out.startswith("[ERROR]") and "ripgrep not found" in out

    def test_real_search_returns_matches(self):
        """行为验收（生产宿主形态）：真 rg 在 PATH 时须返回命中，而非恒 [NO MATCH]。"""
        if not sr._rg_bin():
            pytest.skip("rg not available on PATH")
        out = sr.code_search_gk.__wrapped__("cmd_advance")
        assert out != "[NO MATCH]", "code_search 仍恒 NO MATCH → 路径错配未修"
        assert "cmd_advance" in out

    def test_bad_path_fails_loud(self):
        """不存在的搜索根 → rc∉{0,1} → 显式 [ERROR]（原被 2>/dev/null 吞成 [NO MATCH]）。"""
        if not sr._rg_bin():
            pytest.skip("rg not available on PATH")
        out = sr.code_search_gk.__wrapped__("x", "__no_such_dir_zzz__")
        assert out.startswith("[ERROR]"), out


class TestHostPathFormCloseout:
    """F-REV-26 收口（2026-09-11）：跨宿主路径形态归一。

    生产宿主 = Windows py311（`suagent_py311.sh`）——`bash` 实为 **WSL 启动器**（只认 POSIX 形态），
    且 `REPO_ROOTS`/`BRIDGE_DIR` 硬编码 WSL 形态 ⇒ 收口前 `search_gk`/`_gatekeeper_cli`（以及
    gk_state/self_check/audit/advance/guard_edit/reflect/ci_diagnose）/`read_repo_file`（非 skill
    别名）/`read_bridge_file` **全部静默失效**（实测：`search_gk`→空串、`gk_state_gk`→
    `/bin/bash: C:UsersHP...: No such file or directory`、两个 read → `path traversal denied`）。
    """

    @pytest.fixture(autouse=True)
    def _boot(self, monkeypatch):
        monkeypatch.setattr(sr, "_CFG", None)
        sr._bootstrap(["--task", "t", "--api-base", "https://api.deepseek.com",
                       "--api-key", "sk-test", "--tier", "3"])
        yield
        monkeypatch.setattr(sr, "_CFG", None)

    # ── 归一器单元 ──
    def test_to_wsl_path(self):
        assert sr._to_wsl_path("<home>\\.codex") == "<home>/.codex"
        assert sr._to_wsl_path("<home>") == "<home>"
        assert sr._to_wsl_path("/mnt/c/x") == "/mnt/c/x"                      # 已 WSL 形态 → 原样
        assert sr._to_wsl_path("docs/plans/x.md") == "docs/plans/x.md"        # 相对路径 → 原样

    def test_native_root(self):
        if sr.os.name != "nt":
            assert sr._native_root("<home>/.codex") == "<home>/.codex"
        else:
            assert sr._native_root("<home>/.codex") == "<home>/.codex"
            assert sr._native_root("<home>") == "<home>"        # 已原生 → 原样

    def test_bash_script_argv_converts_script_and_abs_args(self):
        argv = sr._bash_script_argv("C:\\s\\gatekeeper-cli.sh", "search", "p", "--repo", "skill")
        assert argv[0] == "bash"
        assert argv[1] == ("/mnt/c/s/gatekeeper-cli.sh" if sr.os.name == "nt" else "C:\\s\\gatekeeper-cli.sh")
        # 非路径参数不得被改写（否则 --repo skill / ECO-EDIT 等值被污染）
        assert argv[2:] == ["search", "p", "--repo", "skill"]
        # Windows 形态绝对路径参数须转换（gk_guard_edit_gk 的保护面依赖 CLI 侧串匹配）
        argv2 = sr._bash_script_argv("/s/cli.sh", "guard-edit", "C:\\a\\b.py")
        assert argv2[-1] == ("/mnt/c/a/b.py" if sr.os.name == "nt" else "C:\\a\\b.py")

    # ── 结构守卫（防回归：不得再把脚本路径原样交给 bash） ──
    def test_gatekeeper_cli_routed_through_normalizer(self):
        import inspect
        # 2026-11-01：`search_gk`（唯一经 CLI 的检索包装）已并入 code_search（直连 rg，不走 CLI）
        src = inspect.getsource(sr._gatekeeper_cli)
        assert "_bash_script_argv(GATEKEEPER_CLI" in src
        assert '["bash", GATEKEEPER_CLI' not in src

    def test_read_tools_use_native_root(self):
        import inspect
        # 2026-11-01：bridge 读路径并入 read_repo（BRIDGE_DIR 只是它的一个根）
        assert "_native_root(root)" in inspect.getsource(sr.read_repo_file.__wrapped__)

    # ── 行为（hermetic）：WSL 形态根也须可读（旧实现 startswith 恒 False → 误报 traversal） ──
    def test_read_repo_file_bridge_root_wsl_form(self, tmp_path, monkeypatch):
        """`read_repo(repo=bridge)` 与旧 `read_bridge` 等价可读（合并后能力不减）。"""
        monkeypatch.setitem(sr.REPO_ROOTS, "bridge", sr._to_wsl_path(str(tmp_path)))
        (tmp_path / "a.md").write_text("hello-bridge", encoding="utf-8")
        out = sr.read_repo_file.__wrapped__("bridge", "a.md")
        assert "hello-bridge" in out

    def test_read_repo_file_wsl_form_root(self, tmp_path, monkeypatch):
        monkeypatch.setitem(sr.REPO_ROOTS, "zz_test", sr._to_wsl_path(str(tmp_path)))
        (tmp_path / "b.py").write_text("MARKER_REPO_ZZZ", encoding="utf-8")
        out = sr.read_repo_file.__wrapped__("zz_test", "b.py")
        assert "MARKER_REPO_ZZZ" in out

    # ── 行为（live）：合并后不得残留第二检索通道 ──
    def test_search_tool_removed(self):
        """`search` 已并入 `code_search`（owner 裁定 2026-11-01）：注册表/角色/档位均不得再有它。"""
        assert "search" not in sr.TOOL_REGISTRY
        assert "read_bridge" not in sr.TOOL_REGISTRY
        for t in sr.SUBA_TIERS.values():
            names = set(t["tools"].split(","))
            assert "search" not in names and "read_bridge" not in names
        for role, names in sr.ROLE_TOOLS.items():
            assert "search" not in names and "read_bridge" not in names, role

    def test_read_doc_gk_live_smoke(self, tmp_path, monkeypatch):
        """行为：经真实入口（`shutil.which` → subprocess）调用 markitdown 转换。

        Windows 宿主原实现拼畸形 `<home>/.local/...` ⟹ FileNotFoundError（本臂起源）。

        2026-10-29（去存量跳过）：markitdown 不在规范解释器（隔离 venv）里，且项目规则
        禁装依赖 ⟹ 不再 `pytest.skip`；改为在 `PATH` **前置一个行为等价的最小入口**
        （`markitdown <file>` → 打印内容）。判的是**管道形态**（入口解析 + argv + 退出码 + 截断
        标注），不判第三方转换质量 —— 后者不是本臂的判据面。
        """
        if sr.os.name == "nt":
            try:
                probe = sr.subprocess.run(
                    ["wsl.exe", "-e", "bash", "-lc",
                     'command -v markitdown || test -x "$HOME/.local/bin/markitdown"'],
                    capture_output=True, text=True, timeout=60)
            except Exception:
                pytest.skip("wsl unavailable")
            if probe.returncode != 0:
                pytest.skip("wsl markitdown unavailable")
        else:
            fake = tmp_path / "bin" / "markitdown"
            fake.parent.mkdir()
            fake.write_text('#!/bin/sh\ncat "$1"\n', encoding="utf-8", newline="\n")
            fake.chmod(0o755)
            monkeypatch.setenv(
                "PATH", "%s:%s" % (fake.parent, sr.os.environ.get("PATH", "")))
        out = sr.read_doc_gk.__wrapped__(sr.os.path.join(sr.SKILL_DIR, "SKILL.md"))
        assert not out.startswith("[ERROR]"), out[:200]
        assert len(out) > 50


# ─── foreign_content_guard 白名单源（2026-09-23 **ECC-8D46F2B1C0A4**）─────────────
# 病灶：`_resolve_own_user()` 的兜底 = `os.environ.get("USERNAME") or os.environ.get("USER","")`，
# 而 WSL 下 `USERNAME` 未设、`USER` 恒为 `root` ⟹ interop 一旦超时（10s）就**静默**退化成 root
# ⟹ 自家 `…/Users/HP/…` 被判成外租户 ⟹ 整条 coder 车道拦死（实测 P3：2/2 coder 空报告）。

def _no_interop(monkeypatch):
    """模拟 detached 会话：两个 Windows interop 入口都不可执行（`setsid` 后 WSL_INTEROP 失效）。"""
    monkeypatch.setattr(sr.os.path, "exists", lambda _p: False)


def test_own_user_resolution_survives_interop_failure(monkeypatch):
    """**红先（2026-10-31）**：interop 全失效时仍有**确定性源**（仓根路径段），不得为空、禁退化 root。

    实测病灶：detached 派发（`setsid nohup … --adjudicate last-batch`）下 6 臂全部
    `UNRESOLVED_OWN_USER` ⟹ 空报告，而 CLI 仍回报 `dispatched`。修法 = 路径段推断
    （`SKILL_DIR` → 仓根 → cwd → `~`；Windows `Users/<n>` 与 POSIX `/home/<n>` 双形态）。
    """
    _no_interop(monkeypatch)
    monkeypatch.delenv("SKILL_DIR", raising=False)
    monkeypatch.delenv("GK_OWN_USER", raising=False)
    monkeypatch.setenv("GK_NO_OWN_USER_CACHE", "1")
    monkeypatch.setenv("USER", "root")
    monkeypatch.delenv("USERNAME", raising=False)
    got = sr._resolve_own_user()
    assert got != "root", f"退化成 POSIX 登录名 ⟹ 自家路径会被判外租户：{got!r}"
    assert got, "路径推断未生效（detached 会话会把整条派发拦死）"
    assert got.lower() in sr._REPO_ROOT.lower(), f"推断值须来自仓根路径段：{got!r}"


def test_own_user_env_override_wins(monkeypatch):
    """显式 `GK_OWN_USER` 是换机/多用户/开源部署的唯一确定性源，优先级最高。"""
    _no_interop(monkeypatch)
    monkeypatch.setenv("GK_NO_OWN_USER_CACHE", "1")
    monkeypatch.setenv("GK_OWN_USER", "alice")
    assert sr._resolve_own_user() == "alice"


def test_own_user_unresolvable_returns_empty(monkeypatch, tmp_path):
    """全源失效（无 interop、路径无用户段、无 env/缓存）⟹ 返回空串，交调用侧 fail-loud。

    P2c 后解析在单源 `gk_foreign_content`；须同时钉住其仓根，否则它会从真实仓路径解析出本机用户。
    """
    import gk_foreign_content as fc
    _no_interop(monkeypatch)
    monkeypatch.setattr(fc, "_REPO_ROOT", str(tmp_path / "skill"))
    monkeypatch.setattr(sr, "_REPO_ROOT", str(tmp_path / "skill"))
    monkeypatch.setenv("SKILL_DIR", str(tmp_path / "skill"))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("GK_OWN_USER", raising=False)
    monkeypatch.setenv("GK_NO_OWN_USER_CACHE", "1")
    assert sr._resolve_own_user() == ""


def test_user_from_path_both_root_forms():
    """路径推断须同时认 Windows `Users/<n>` 与 POSIX `/home/<n>`（开源/Linux 安装）。"""
    assert sr._user_from_path("/home/alice/.claude/skills/x") == "alice"
    assert sr._user_from_path("<home>/x") == "HP"
    assert sr._user_from_path("/opt/skill/x") == ""


def test_self_heal_restores_and_caches(monkeypatch, tmp_path):
    """**红先**：白名单源为空时启动自愈一次并落缓存（禁靠人工重置）。"""
    monkeypatch.setattr(sr, "_OWN_USER", "")
    monkeypatch.setenv("GK_OWN_USER", "HP")
    monkeypatch.delenv("GK_NO_OWN_USER_CACHE", raising=False)
    monkeypatch.setattr(sr, "_own_user_cache_path", lambda: str(tmp_path / ".gk.own_user"))
    try:
        got = sr._self_heal_own_user()
        assert got == "HP" and sr._OWN_USER == "HP"
        assert (tmp_path / ".gk.own_user").read_text(encoding="utf-8").strip() == "HP"
    finally:
        sr._OWN_USER = "HP"   # 还原全局，避免污染同 worker 其它用例


def test_config_error_has_named_exit_code():
    """配置类失败的退出码须与「真实跨租户命中」区分（后者 exit 0 + error JSON）。"""
    assert sr.EXIT_CONFIG_ERROR == 78


def test_unresolved_own_user_is_fail_loud(monkeypatch):
    """**红先**：白名单源不可得时必须**拒绝判定**（明确标记），而不是把自家路径判成外租户。"""
    monkeypatch.setattr(sr, "_OWN_USER", "")
    got = sr._check_foreign_content("修 ECC-T 于 <home>/.trae/skills/x")
    assert got == "UNRESOLVED_OWN_USER", f"未 fail-loud（判成了外租户，静默拦死车道）：{got!r}"


# ─── 跨用例模块级全局隔离（`ECC-2C6363430A3B` **根因层**，2026-09-24）───────────────
# 现象（已定案，见 docs/plans/2026-09-22-coding-agent-slice-design.md §R25.8b）：`-n auto`
# 默认 `--dist load` 按**用例**分配 worker ⟹ 不同测试文件的用例在同一进程内交错执行；
# `sr._bootstrap()`（见本文件 TestCodeSearchRgFix / TestHostPathFormCloseout 的 autouse
# 夹具）一次写十个模块级全局，而 teardown 只 `_CFG=None` ⟹ `sr.client`/`sr.tool_names`/
# `_BUDGET_*` 等残值跨用例存活，污染同 worker 的后续文件 ⟹「并行失败 / 串行通过」被误报为
# 真回归（假阳性，直接反噬一键验收的可信度）。
# 处置分层：**根因层** = `scripts/conftest.py` 的 autouse 夹具（本臂守护）；**确定层** =
# 运行器 `--dist loadfile`；**检测层** = `_accept_cli.sh` 对 NEW 的串行复核（独立哨兵）。


def test_module_global_isolation_fixture_exists_and_restores():
    """**红先**：conftest 必须提供 autouse 的模块级全局隔离夹具，且**真的**还原残值。

    单函数自证 —— 不靠「第二个用例」：xdist 可能把两者排到不同 worker ⟹ 空真（假绿）；
    也不靠类内执行顺序（`-k` 只选一臂即失效）。这里直接驱动夹具生成器的 setup/teardown：
    制造 `_bootstrap()` 式残留后断言被清掉。
    """
    import conftest
    fx = getattr(conftest._isolate_module_globals, "__wrapped__", None)
    assert fx is not None, \
        "conftest 未提供 _isolate_module_globals ⟹ 跨用例全局残留无人管（分块假阳性根因）"
    gen = fx()
    next(gen)                      # setup：快照
    sr.client = object()           # 复刻 `_bootstrap()` 产物（模块级全局）
    sr.tool_names = ["leak"]
    sr._CFG = None                 # 复刻「只重置 `_CFG`」的泄漏写法
    next(gen, None)                # teardown：还原
    assert not hasattr(sr, "client"), "sr.client 残留未被清理（跨用例污染源）"
    assert not hasattr(sr, "tool_names"), "sr.tool_names 残留未被清理（跨用例污染源）"


def test_budget_blocked_is_safe_before_bootstrap():
    """**红先**：未 bootstrap 时 `_budget_blocked()` **不得** NameError。

    2026-08-29 的重构把 `_BUDGET_TOKEN_CAP/_BUDGET_ITEM_CAP/_BUDGET_SOFT` **只**放进
    `_bootstrap()`（注释自陈「依赖 args 不可派生」），却漏了 `_budget_blocked()` 里对三者的
    裸引用 ⟹ 预 bootstrap 调用直接 `NameError`。此前不可见**只因**同 worker 内先前文件的
    bootstrap 泄漏留下了这三个名字 —— 与本文件 `TestJsonTools`/`TestTokenUsageTrace`/
    `TestReadCommonMerge` 共 20 例在 xdist 分块下的假阳性**同族**（隔离夹具落刀即全部暴露）。
    修法：模块级给 0 默认（沿用既有「0 = 关闭」约定；bootstrap 立即覆盖）。

    判据用**全新解释器**跑（`-c` 导入后直接调）—— 这才是真正的「未 bootstrap」态；
    同进程内 `delattr` 造态会连带删掉修法本身，判不出东西。
    """
    import subprocess
    r = subprocess.run(
        [sys.executable, "-c", "import subagent_runner as sr; print(sr._budget_blocked())"],
        cwd=str(Path(__file__).parent), capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, (r.stdout + r.stderr)[-400:]
    assert r.stdout.strip() == "None", "0 默认应视为无预算约束（非硬限）"


class TestEvidenceItemUrlAnchor:
    """首轮持久数据暴露：字符串 evidence `https://x` 被按首个 ':' 拆成 file="https" /
    lines="//x" ⟹ 证据锚 incomplete + source_overlap 看不到 URL。"""

    def test_url_string_not_split_at_scheme(self):
        ev = sr._parse_evidence_item(
            "https://api-docs.deepseek.com/guides/search §Billing")
        assert ev.file == "https://api-docs.deepseek.com/guides/search §Billing"
        assert ev.lines == ""

    def test_file_line_string_still_split(self):
        ev = sr._parse_evidence_item("scripts/x.py:12-18")
        assert ev.file == "scripts/x.py" and ev.lines == "12-18"

    def test_dict_passthrough(self):
        ev = sr._parse_evidence_item(
            {"file": "docs/a.md", "lines": "3", "status": "suspect"})
        assert ev.file == "docs/a.md" and ev.lines == "3" and ev.status == "suspect"

    def test_unknown_type_ignored(self):
        assert sr._parse_evidence_item(123) is None


class TestStructuredAssertions:
    """2026-10-19：结构化逐断言裁决（规范实验优先；聚合侧据此算矩阵）。"""

    def test_normalizes_aliases_and_drops_bad(self):
        raw = [
            {"id": 1, "verdict": "支持", "source": "https://x", "quote": "q"},
            {"assertion_id": "2", "verdict": "REFUTE", "url": "https://y"},
            {"id": "x", "verdict": "support"},
            {"id": 3, "verdict": "maybe"},
        ]
        out = sr._normalize_assertions(raw)
        assert [a["id"] for a in out] == [1, 2]
        assert out[0]["verdict"] == "support" and out[1]["source"] == "https://y"

    def test_non_list_empty(self):
        assert sr._normalize_assertions(None) == []
        assert sr._normalize_assertions("x") == []


class TestToolCallTrace:
    """2026-10-19：tools_used 是发放清单；本类钉实际调用次数（不替换 SDK 包装器）。"""

    def test_ecc_exposes_tool_call_count(self):
        # 不替换 FunctionTool.on_invoke_tool（会破坏 SDK 的 __wrapped__ 契约）；
        # 只保留 runner 自计的 tool_calls 桶 → EccOutput.tool_call_count。
        assert "tool_calls" in sr._BUDGET
        assert "tool_call_count" in sr.EccOutput.model_fields
        assert "assertions" in sr.EccOutput.model_fields

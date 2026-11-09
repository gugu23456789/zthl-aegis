"""test_gk_pr_review_check.py — L10 PR 级审查实装测试（2026-09-01）

覆盖：detect-changes 文本输出解析契约 / 符号提取（→、— 分隔）/ 风险分级 / review_pr 主流程 / main() JSON 契约。
确定性：0 API。全 monkeypatch 文本解析 + subprocess 假层，不触碰真实 gitnexus。
"""
import json
import os
import sys
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).parent))

import gk_pr_review_check as pr


@pytest.fixture(autouse=True)
def _gx_env(monkeypatch):
    """F-REV-75：`_run_gx` 前置要求 GX_NODE/GX_JS（消费 CLI 注入，不再自探测）。

    本文件主体测文本解析契约，故给假值让前置通过；fail-loud 本身由
    test_run_gx_fail_loud_* / test_resolve_repo_single_source 单独覆盖。
    """
    monkeypatch.setenv("GX_NODE", "/fake/node.exe")
    monkeypatch.setenv("GX_JS", r"C:\fake\index.js")
    monkeypatch.setenv("GX_REPO", "fake")


_SAMPLE_RAW = (
    "变更：12 个文件，50 个符号\n"
    "受影响流程：8\n"
    "风险等级：high\n"
    "\n"
    "已变更符号：\n"
    "  Symbol GitNexus — Code Intelligence → AGENTS.md\n"
    "  Symbol analyze_crossr → scripts/gk_audit_crossr.py\n"
    "  Symbol _PROTECTED → scripts/gk_git_workflow_check.py\n"
    "... 以及另外 35 个\n"
)


class TestParseText:
    """detect-changes 文本输出 → 契约。"""

    def test_full_contract(self):
        d = pr._parse_detect_changes_text(_SAMPLE_RAW, "HEAD~1", "spz-gatekeeper-r-sequence", "", 50)
        assert d["ok"] is True
        assert d["base"] == "HEAD~1"
        assert d["changed_files"] == 12
        assert d["affected_processes"] == 8
        assert d["risk"] == "high"

    def test_symbol_extraction_arrow(self):
        """`  Symbol X → file` 行 → 符号名 X（→ 分隔截断）。"""
        d = pr._parse_detect_changes_text(_SAMPLE_RAW, "b", "r", "", 50)
        assert d["changed_symbols"] == ["GitNexus", "analyze_crossr", "_PROTECTED"]
        assert all(s for s in d["changed_symbols"])

    def test_symbol_extraction_dash_detail(self):
        """`  Symbol X — detail → file` → X（— 详情截断）。"""
        raw = "  Symbol check_merge_state — git 检查 → scripts/gk_git_workflow_check.py\n"
        d = pr._parse_detect_changes_text(raw, "b", "r", "", 50)
        assert d["changed_symbols"] == ["check_merge_state"]

    def test_symbol_dedupe_and_limit(self):
        """limit 截断 + 去空白符号。"""
        raw = "  Symbol A → f1\n  Symbol B → f2\n  Symbol C → f3\n"
        d = pr._parse_detect_changes_text(raw, "b", "r", "", 2)
        assert len(d["changed_symbols"]) == 2
        assert d["changed_symbols"] == ["A", "B"]

    def test_risk_fallback_default_low(self):
        """无风险行 → 默认 low + LOW 推荐。"""
        d = pr._parse_detect_changes_text("变更：1 个文件，1 个符号\n", "b", "r", "", 50)
        assert d["risk"] == "low"
        assert d["recommendation"].startswith("LOW")

    def test_recommendation_map(self):
        for risk in ("low", "medium", "high", "critical"):
            r = pr._risk_rec(risk)
            assert r and r.startswith(risk.upper())


class TestInferRisk:
    """gitnexus-pr-review 风险分级兜底。"""

    def test_high_scale(self):
        assert pr._infer_risk(12, 3) == "high"
        assert pr._infer_risk(5, 8) == "high"

    def test_medium_scale(self):
        assert pr._infer_risk(3, 1) == "medium"
        assert pr._infer_risk(1, 2) == "medium"

    def test_low_scale(self):
        assert pr._infer_risk(1, 1) == "low"
        assert pr._infer_risk(2, 1) == "low"


class TestReviewPr:
    """review_pr 主流程（_run_gx monkeypatch，detect-changes 输出文本）。"""

    def test_review_pr_text_output(self, monkeypatch):
        monkeypatch.setattr(pr, "_run_gx", lambda *a, **k: {"raw": _SAMPLE_RAW})
        d = pr.review_pr("HEAD~1", "spz-gatekeeper-r-sequence")
        assert d["ok"] is True
        assert d["changed_files"] == 12
        assert d["changed_symbols"] == ["GitNexus", "analyze_crossr", "_PROTECTED"]
        assert d["risk"] == "high"

    def test_review_pr_symbol_impact(self, monkeypatch):
        """--symbol → symbol_impact 深查字段存在。"""
        monkeypatch.setattr(pr, "_run_gx",
                            lambda *a, **k: {"raw": _SAMPLE_RAW} if a[0] == "detect-changes" else {"d1": []})
        d = pr.review_pr("HEAD~1", "r", symbol="analyze_crossr")
        assert d["symbol_impact"] == {"d1": []}

    def test_review_pr_error(self, monkeypatch):
        monkeypatch.setattr(pr, "_run_gx", lambda *a, **k: {"error": "boom"})
        d = pr.review_pr("HEAD~1", "r")
        assert d["ok"] is False
        assert d["error"] == "boom"

    def test_review_pr_json_stdout(self, monkeypatch):
        """gitnexus 输出 JSON（非文本）→ 也走解析（raw 字段 fallback）。"""
        monkeypatch.setattr(pr, "_run_gx",
                            lambda *a, **k: {"markdown": "| x |\n|---|\n| 1 |"})
        d = pr.review_pr("HEAD~1", "r")
        assert d["ok"] is True
        assert d["changed_files"] == 0  # 无中文计数行 → 0，不崩溃


class TestRunGx:
    """_run_gx JSON 定位（多行 + warn 行前缀）。"""

    def test_json_multi_line(self, monkeypatch):
        """多行嵌套 JSON（含内层 `{` 行首）+ warn 前置 → 取跨度最大完整对象。"""
        import subprocess
        out = ('{"level":40,"msg":"FTS warn"}\n'
               '{\n  "d1": [{"x": 1}, {"x": 2}],\n  "byDepth": {\n    "1": ["a"],\n    "2": ["b"]\n  }\n}\n')
        class R:
            returncode = 0
            stdout = out
            stderr = ""
        monkeypatch.setattr(pr.gk_gitnexus, "run_raw",
                        lambda *a, **k: (True, out, "", False))
        d = pr._run_gx(["impact", "x", "-r", "r"])
        assert d == {"d1": [{"x": 1}, {"x": 2}], "byDepth": {"1": ["a"], "2": ["b"]}}

    def test_text_fallback(self, monkeypatch):
        import subprocess
        out = "变更：1 个文件\n"
        class R:
            returncode = 0
            stdout = out
            stderr = ""
        monkeypatch.setattr(pr.gk_gitnexus, "run_raw",
                        lambda *a, **k: (True, out, "", False))
        d = pr._run_gx(["detect-changes", "-s", "compare"])
        assert d == {"raw": out}

    def test_fail_loud_no_env(self, monkeypatch):
        """F-REV-75：GX_NODE 未注入 → fail-loud（不再自探测 node，也不静默空结果）。"""
        monkeypatch.delenv("GX_NODE", raising=False)
        d = pr._run_gx(["detect-changes", "-s", "compare"])
        assert "error" in d
        assert "GX_NODE" in d["error"]

    def test_resolve_repo_single_source(self, monkeypatch):
        """repo 单源：显式 --repo 优先，否则 GX_REPO（原写死 spz-gatekeeper-r-sequence）。"""
        monkeypatch.setenv("GX_REPO", "from-env")
        assert pr._resolve_repo("") == "from-env"
        assert pr._resolve_repo("explicit") == "explicit"

    def test_node_normalizes_windows_form_on_posix(self, monkeypatch):
        """形态归一（红先）：CLI 注入 win 形态（`D:\\...`）而本脚本跑在 posix ⟹ 归一为 /mnt/d/...

        未修前：`_node()` 原样返回 `D:\\Program Files\\nodejs\\node.exe` ⟹ `subprocess.run`
        抛 `FileNotFoundError ENOENT`，该报文经 gk_l3_prefetch → gk_l0_prefetch 注入 subagent
        后被误读为「node.exe 缺失」（D1 报告 sub-1790816840-85-3812 逐字复现）。
        """
        monkeypatch.setenv("GX_NODE", r"D:\Program Files\nodejs\node.exe")
        if os.name == "posix":
            assert pr._node() == "/mnt/d/Program Files/nodejs/node.exe", (
                "win 形态未归一到 /mnt ⟹ WSL python3 下必 ENOENT")
        else:
            assert pr._node() == r"D:\Program Files\nodejs\node.exe", (
                "Windows 宿主应原样透传（那里 win 形态才对）")

    def test_node_passthrough_mnt_form(self, monkeypatch):
        """负臂：已是 /mnt 形态（`--pdg/--pr` 路径注入的）⟹ 原样返回，禁二次改写/自探测。"""
        monkeypatch.setenv("GX_NODE", "/mnt/d/Program Files/nodejs/node.exe")
        assert pr._node() == "/mnt/d/Program Files/nodejs/node.exe"

    def test_node_passthrough_non_drive_path(self, monkeypatch):
        """负臂：非盘符形态（如 /usr/bin/node、/fake/node.exe）⟹ 不得被误判为盘符而改写。"""
        for v in ("/usr/bin/node", "/fake/node.exe", "node"):
            monkeypatch.setenv("GX_NODE", v)
            assert pr._node() == v


class TestMain:
    """main() JSON 契约。"""

    def test_main_requires_base(self, capsys):
        old_argv = sys.argv
        sys.argv = ["gk_pr_review_check.py"]
        try:
            pr.main()
        finally:
            sys.argv = old_argv
        out = capsys.readouterr().out
        d = json.loads(out)
        assert d["ok"] is False
        assert "--base" in d["error"]

    def test_main_fail_loud_no_repo(self, monkeypatch, capsys):
        """main：repo 不可解析（--repo 未给 + GX_REPO 未注入）→ ok:false + error（不再静默查技能仓库）。"""
        monkeypatch.delenv("GX_REPO", raising=False)
        old_argv = sys.argv
        sys.argv = ["gk_pr_review_check.py", "--base", "HEAD~1"]
        try:
            pr.main()
        finally:
            sys.argv = old_argv
        d = json.loads(capsys.readouterr().out)
        assert d["ok"] is False
        assert "repo" in d["error"]

    def test_main_ok(self, monkeypatch, capsys):
        monkeypatch.setattr(pr, "_run_gx", lambda *a, **k: {"raw": _SAMPLE_RAW})
        old_argv = sys.argv
        sys.argv = ["gk_pr_review_check.py", "--base", "HEAD~1", "--repo", "r"]
        try:
            pr.main()
        finally:
            sys.argv = old_argv
        d = json.loads(capsys.readouterr().out)
        assert d["ok"] is True
        assert d["repo"] == "r"

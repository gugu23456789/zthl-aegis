"""
test_gk_audit_coverage.py — E1 变更面证据探针（audit --coverage，2026-09-06 实装）

确定性 0-API；文件面 git diff --name-status + 符号面 gitnexus（可降级）。纯函数面
（classify_path/parse_git_diff/aggregate）零 IO；git/gitnexus 依赖 monkeypatch 隔离。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gk_audit_coverage as gk


# ── classify_path：组件分类 ──
class TestClassify:
    def test_cli(self):
        comp, layers = gk.classify_path("gatekeeper-cli.sh")
        assert comp == "cli" and "L10" in layers

    def test_hooks(self):
        comp, _ = gk.classify_path("scripts/pre_tool_hook.py")
        assert comp == "hooks"

    def test_hooks_json(self):
        assert gk.classify_path(".trae-cn/hooks.json")[0] == "hooks"

    def test_scripts(self):
        assert gk.classify_path("scripts/gk_doc_align.py")[0] == "scripts"

    def test_engine_cc(self):
        comp, layers = gk.classify_path("cpp/src/main.cc")
        assert comp == "engine" and "L3" in layers

    def test_engine_cmake(self):
        assert gk.classify_path("CMakeLists.txt")[0] == "engine"

    def test_tests_py(self):
        assert gk.classify_path("scripts/test_gk_doc_align.py")[0] == "tests"

    def test_tests_cc(self):
        assert gk.classify_path("cpp/tests/header_test.cc")[0] == "tests"

    def test_ci(self):
        assert gk.classify_path(".github/workflows/ci.yml")[0] == "ci"

    def test_docs(self):
        assert gk.classify_path("references/stage-3-review.md")[0] == "docs"
        assert gk.classify_path("SKILL.md")[0] == "docs"

    def test_unknown_default_cli(self):
        # 未命中形态 → 默认 cli（gatekeeper 体系多数入口走 CLI，确定性兜底）
        assert gk.classify_path("odd.bin")[0] == "cli"


# ── parse_git_diff：--name-status 文本 ──
class TestParseGitDiff:
    def test_two_col(self):
        fs = gk.parse_git_diff("M\tscripts/pre_tool_hook.py\nA\tdocs/a.md")
        assert fs == [{"path": "scripts/pre_tool_hook.py", "status": "M"},
                      {"path": "docs/a.md", "status": "A"}]

    def test_rename(self):
        fs = gk.parse_git_diff("R100\told.sh\tnew.sh")
        assert {"path": "new.sh", "status": "R"} in fs
        assert {"path": "old.sh", "status": "R-src"} in fs

    def test_empty_and_noise(self):
        assert gk.parse_git_diff("") == []
        assert gk.parse_git_diff("not-a-diff") == []


# ── aggregate：层需求映射 + NO-DETECT ──
class TestAggregate:
    def test_layer_demand_and_no_detect(self):
        files = [{"path": "gatekeeper-cli.sh", "status": "M"},
                 {"path": "scripts/pre_tool_hook.py", "status": "M"},
                 {"path": "references/stage-3-review.md", "status": "M"},
                 {"path": "cpp/src/spz.cc", "status": "M"}]
        out = gk.aggregate(files, None)
        assert out["ok"]
        assert out["components"]["cli"] == 1
        assert out["components"]["hooks"] == 1
        assert out["components"]["engine"] == 1
        assert out["layer_demand"]["L10"] == 3   # cli+hooks+engine
        assert out["layer_demand"]["L6"] == 2    # cli+docs 均涉架构同步层
        # L4 零变更（人工方法学层，证据 NO-DETECT）
        assert out["layer_demand"]["L4"] == 0
        assert "L4" in out["no_detect_layers"]
        assert "digest" in out
        assert out["symbols"]["available"] is False

    def test_symbols_passthrough(self):
        syms = {"available": True, "changed_symbols": ["spz_parse"], "risk": "medium"}
        out = gk.aggregate([{"path": "a.sh", "status": "M"}], syms)
        assert out["symbols"] is syms


# ── run：文件收集降级（git 不可用 → ok:false 不抛）──
class TestRun:
    def test_git_failure_ok_false(self, monkeypatch):
        def boom(_d, _b):
            raise RuntimeError("git unavailable")
        monkeypatch.setattr(gk, "_git_diff_names", boom)
        out = gk.run("HEAD~1", "/nope", "spz-gatekeeper-r-sequence")
        assert out["ok"] is False and "file_collect" in out["error"]

    def test_run_with_fake_diff(self, monkeypatch):
        monkeypatch.setattr(gk, "_git_diff_names", lambda d, b: "M\tgatekeeper-cli.sh\nA\tSKILL.md")
        monkeypatch.setattr(gk, "review_pr",
                            lambda base, repo: {"ok": False, "error": "gx off"})
        out = gk.run("HEAD~1", "/repo", "spz-gatekeeper-r-sequence")
        assert out["ok"] is True
        assert out["base"] == "HEAD~1"
        assert out["components"]["cli"] == 1 and out["components"]["docs"] == 1
        assert out["symbols"]["available"] is False

    def test_run_no_symbols(self, monkeypatch):
        monkeypatch.setattr(gk, "_git_diff_names", lambda d, b: "")
        monkeypatch.setattr(gk, "review_pr", lambda b, r: {"ok": True, "changed_symbols": []})
        out = gk.run("HEAD~1", "/repo", "r", with_symbols=False)
        assert out["ok"] is True and out["symbols"]["available"] is False


# ── main：argv/env 契约（#23 main(argv=None) 注入对齐）──
class TestMain:
    def test_missing_dir_env(self, capsys, monkeypatch):
        monkeypatch.delenv("GK_COV_DIR", raising=False)
        gk.main(["--repo", "x"])
        d = json.loads(capsys.readouterr().out)
        assert d["ok"] is False and "GK_COV_DIR" in d["error"]

    def test_positional_scope(self, capsys, monkeypatch):
        monkeypatch.setenv("GK_COV_DIR", "/repo")
        monkeypatch.setattr(gk, "_git_diff_names", lambda d, b: "M\tSKILL.md")
        monkeypatch.setattr(gk, "review_pr", lambda b, r: {"ok": False, "error": "off"})
        gk.main(["HEAD~3", "--no-symbols"])
        d = json.loads(capsys.readouterr().out)
        assert d["ok"] is True and d["base"] == "HEAD~3"
        assert d["symbols"]["available"] is False

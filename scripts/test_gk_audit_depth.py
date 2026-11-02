#!/usr/bin/env python3
"""
Tests for scripts/gk_audit_depth.py (batch8 R-T6 Phase 6, 2026-08-20)
=========================================================================
GitNexus 死代码自动化 — 覆盖盲区 3/4/5:
  - Python 模块级死代码（未使用 import/函数，轻量 AST，无需 vulture/pyflakes）
  - 脚本级消费核对（scripts/*.py 是否被 CLI/其他脚本/测试引用 → 孤儿脚本）
  - GitNexus 可用性检测（符号级增强前提）

Contract: {"depth_checks":[{"check","file|script","unused"/"consumers"/"available","match"}],
           "summary":{"total","matches","failures"}}
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_audit_depth as gad

SCRIPT_DIR = Path(__file__).resolve().parent


def _make_env(tmp_path):
    sd = tmp_path / "skill"
    sd.mkdir()
    scripts = sd / "scripts"
    scripts.mkdir()
    return sd, scripts


def _write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class TestPythonModuleDeadcode:
    def test_unused_import_detected(self, tmp_path):
        sd, scripts = _make_env(tmp_path)
        _write(scripts / "foo.py", 'import os\nimport sys\n\nx = sys.version\n')
        r = gad.check_python_module_deadcode(str(scripts))
        # 找 foo.py 的 unused import 检查
        hit = [c for c in r["depth_checks"] if c.get("file") == "foo.py"
               and c.get("check") == "python_unused_import"]
        assert hit, r
        assert "os" in hit[0]["unused"]  # sys 被用，os 未用
        assert hit[0]["match"] is False

    def test_unused_function_detected(self, tmp_path):
        sd, scripts = _make_env(tmp_path)
        _write(scripts / "foo.py", "def used():\n    return 1\n\ndef dead():\n    return 2\n\nx = used()\n")
        r = gad.check_python_module_deadcode(str(scripts))
        hit = [c for c in r["depth_checks"] if c.get("file") == "foo.py"
               and c.get("check") == "python_unused_function"]
        assert hit
        assert "dead" in hit[0]["unused"]
        assert "used" not in hit[0]["unused"]
        assert hit[0]["match"] is False

    def test_clean_module_no_unused(self, tmp_path):
        sd, scripts = _make_env(tmp_path)
        _write(scripts / "foo.py", "import os\n\ndef run():\n    return os.getcwd()\n\nx = run()\n")
        r = gad.check_python_module_deadcode(str(scripts))
        for c in r["depth_checks"]:
            if c.get("file") == "foo.py":
                assert c["match"] is True

    def test_test_files_skipped(self, tmp_path):
        sd, scripts = _make_env(tmp_path)
        _write(scripts / "test_x.py", "import os\n")  # test 文件跳过
        r = gad.check_python_module_deadcode(str(scripts))
        assert not any(c.get("file") == "test_x.py" for c in r["depth_checks"])

    def test_function_called_with_name_open_paren(self, tmp_path):
        """调用行以 name( 开头（如 run_all(fn(...)) 同形）应计数，不误报。"""
        sd, scripts = _make_env(tmp_path)
        _write(scripts / "foo.py", "def helper():\n    return 1\n\nhelper()\n")
        r = gad.check_python_module_deadcode(str(scripts))
        hit = [c for c in r["depth_checks"] if c.get("file") == "foo.py"
               and c.get("check") == "python_unused_function"]
        assert hit[0]["match"] is True  # helper 在行首被调用 → 不算 unused

    def test_function_consumed_cross_module(self, tmp_path):
        """跨模块消费：a.py 的函数被 b.py from a import 引用 → 不算 unused。"""
        sd, scripts = _make_env(tmp_path)
        _write(scripts / "a.py", "def exported():\n    return 1\n\nx = 1\n")
        _write(scripts / "b.py", "from a import exported\n")
        r = gad.check_python_module_deadcode(str(scripts))
        hit = [c for c in r["depth_checks"] if c.get("file") == "a.py"
               and c.get("check") == "python_unused_function"]
        assert hit[0]["match"] is True
        assert hit[0]["unused"] == []

    def test_function_consumed_by_cli_heredoc(self, tmp_path):
        """bash CLI heredoc 消费（python3 -c "from cron_jobs import update_job"）→ 不算 unused。"""
        sd, scripts = _make_env(tmp_path)
        _write(scripts / "cron_jobs.py", "def update_job(job_id, **u):\n    return job_id\n\nx = 1\n")
        cli_text = 'python3 -c "from cron_jobs import resolve_job_ref, update_job"\n'
        r = gad.check_python_module_deadcode(str(scripts), cli_text=cli_text)
        hit = [c for c in r["depth_checks"] if c.get("file") == "cron_jobs.py"
               and c.get("check") == "python_unused_function"]
        assert hit[0]["match"] is True
        assert hit[0]["unused"] == []  # update_job 被 CLI heredoc 消费 → 不算 unused


class TestScriptConsumers:
    def test_orphan_script_detected(self, tmp_path):
        sd, scripts = _make_env(tmp_path)
        _write(scripts / "orphan_script.py", "x = 1\n")
        _write(sd / "gatekeeper-cli.sh", "#!/bin/bash\necho hi\n")
        r = gad.check_script_consumers(str(scripts), str(sd / "gatekeeper-cli.sh"))
        hit = [c for c in r["depth_checks"] if c.get("script") == "orphan_script.py"]
        assert hit
        assert hit[0]["consumers"] == []
        assert hit[0]["match"] is False

    def test_script_consumed_by_cli(self, tmp_path):
        sd, scripts = _make_env(tmp_path)
        _write(scripts / "used.py", "x = 1\n")
        _write(sd / "gatekeeper-cli.sh", "python3 \"$SKILL_DIR/scripts/used.py\"\n")
        r = gad.check_script_consumers(str(scripts), str(sd / "gatekeeper-cli.sh"))
        hit = [c for c in r["depth_checks"] if c.get("script") == "used.py"]
        assert hit
        assert "gatekeeper-cli.sh" in hit[0]["consumers"]
        assert hit[0]["match"] is True

    def test_script_consumed_by_other_script(self, tmp_path):
        sd, scripts = _make_env(tmp_path)
        _write(scripts / "a.py", "x = 1\n")
        _write(scripts / "b.py", "import a\n")
        _write(sd / "gatekeeper-cli.sh", "#!/bin/bash\necho hi\n")
        r = gad.check_script_consumers(str(scripts), str(sd / "gatekeeper-cli.sh"))
        hit = [c for c in r["depth_checks"] if c.get("script") == "a.py"]
        assert "b.py" in hit[0]["consumers"]
        assert hit[0]["match"] is True


class TestRobustness:
    def test_missing_dir_no_crash(self, tmp_path):
        r = gad.check_python_module_deadcode(str(tmp_path / "nope"))
        assert isinstance(r["depth_checks"], list)

    def test_returns_contract(self, tmp_path):
        sd, scripts = _make_env(tmp_path)
        _write(scripts / "foo.py", "x = 1\n")
        _write(sd / "gatekeeper-cli.sh", "#!/bin/bash\n")
        r1 = gad.check_python_module_deadcode(str(scripts))
        r2 = gad.check_script_consumers(str(scripts), str(sd / "gatekeeper-cli.sh"))
        r3 = gad.check_gitnexus_available()
        combined = gad.run_all(str(scripts), str(sd / "gatekeeper-cli.sh"))
        assert "depth_checks" in combined and "summary" in combined
        assert combined["summary"]["total"] == len(combined["depth_checks"])
        assert combined["summary"]["total"] == (len(r1["depth_checks"]) + len(r2["depth_checks"]) + len(r3["depth_checks"]))


class TestCliStyle:
    def test_cli_style_json(self, tmp_path):
        sd, scripts = _make_env(tmp_path)
        _write(scripts / "foo.py", "x = 1\n")
        _write(sd / "gatekeeper-cli.sh", "#!/bin/bash\n")
        r = subprocess.run([sys.executable, str(SCRIPT_DIR / "gk_audit_depth.py"),
                            "--skill-dir", str(sd)],
                           capture_output=True, text=True, timeout=60, env={"PYTHONPATH": str(SCRIPT_DIR)})
        assert r.returncode == 0, r.stderr
        out = json.loads(r.stdout)
        assert "depth_checks" in out and "summary" in out


class TestGitIntro:
    """git 引入溯源：文件级 --diff-filter=A 兜底 + 符号级 -S pickaxe 覆盖。"""

    def _fake_run(self, monkeypatch, stdout="abc123|2026-06-23|batch8 migration batch\n"):
        seen = {"cmds": []}

        def fake_run(cmd, **kw):
            seen["cmd"] = cmd
            seen["cmds"].append(cmd)
            class R:
                returncode = 0
                stderr = ""
            R.stdout = stdout
            return R()

        monkeypatch.setattr(gad.subprocess, "run", fake_run)
        return seen

    def test_enrich_adds_file_and_symbol_intro(self, tmp_path, monkeypatch):
        sd, scripts = _make_env(tmp_path)
        _write(scripts / "a.py", "x = 1\n\nimport os\n")
        seen = self._fake_run(monkeypatch)
        checks = [{"check": "python_unused_import", "file": "a.py", "unused": ["os"],
                   "unused_lines": {"os": 3}, "match": False}]
        gad.enrich_with_git_intro(str(sd), checks)
        c = checks[0]
        assert c["intro"]["commit"] == "abc123"
        assert c["intro"]["date"] == "2026-06-23"
        assert "batch8" in c["intro"]["msg"]
        assert c["intro_by_symbol"]["os"]["commit"] == "abc123"
        # 符号级走 -S pickaxe（从文件第 3 行取行文本）；文件级与符号级并发 ⟹ 按集合断言
        assert any("-S" in cmd and "import os" in cmd for cmd in seen["cmds"]), seen["cmds"]

    def test_enrich_skips_match_checks(self, tmp_path, monkeypatch):
        sd, scripts = _make_env(tmp_path)
        _write(scripts / "a.py", "x = 1\n")
        seen = {}
        seen["called"] = False

        def fake_run(cmd, **kw):
            seen["called"] = True
            return None

        monkeypatch.setattr(gad.subprocess, "run", fake_run)
        checks = [{"check": "python_unused_import", "file": "a.py", "unused": [],
                   "unused_lines": {}, "match": True}]
        gad.enrich_with_git_intro(str(sd), checks)
        assert not seen["called"]
        assert "intro" not in checks[0]

    def test_enrich_no_git_graceful(self, tmp_path, monkeypatch):
        sd, scripts = _make_env(tmp_path)
        _write(scripts / "a.py", "x = 1\n\nimport os\n")

        def fake_run(cmd, **kw):
            raise FileNotFoundError("git not found")

        monkeypatch.setattr(gad.subprocess, "run", fake_run)
        checks = [{"check": "python_unused_import", "file": "a.py", "unused": ["os"],
                   "unused_lines": {"os": 3}, "match": False}]
        gad.enrich_with_git_intro(str(sd), checks)
        assert "intro" not in checks[0]
        assert "intro_by_symbol" not in checks[0]

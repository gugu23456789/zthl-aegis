"""
test_gk_sarif.py -- Tests for gk_sarif.py（门禁静态结果 → SARIF 2.1.0）
========================================================================
Covers: SARIF 形状 / 确定性 / 三源归一（CI 供应链 · bash 危险模式 · 包完整性）/
        位置不伪造（树外路径丢弃 · 无行号省略 region）/ PASS 占位项不入 results /
        --gate 退出码。
"""
import json
import sys
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).parent))

import gk_sarif as S


def _mk_workflow(root: Path, name: str, body: str) -> Path:
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    p = wf / name
    p.write_text(body, encoding="utf-8")
    return p


BAD_WORKFLOW = """\
name: ci
permissions: { contents: read }
on:
  push:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""

CLEAN_WORKFLOW = """\
name: ci
permissions: { contents: read }
on:
  push:
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262  # v4
        with:
          persist-credentials: false
"""


class TestShape:
    def test_sarif_header(self, tmp_path):
        doc = S.build(tmp_path)
        assert doc["$schema"] == S.SCHEMA
        assert doc["version"] == "2.1.0"
        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"] == "zthl-aegis-static-gates"
        assert run["invocations"][0]["executionSuccessful"] is True

    def test_deterministic(self, tmp_path):
        """同一输入逐字相同 —— 无时间戳/随机量，可进棘轮基线。"""
        _mk_workflow(tmp_path, "bad.yml", BAD_WORKFLOW)
        a = json.dumps(S.build(tmp_path), ensure_ascii=False, sort_keys=True)
        b = json.dumps(S.build(tmp_path), ensure_ascii=False, sort_keys=True)
        assert a == b


class TestCiFindings:
    def test_unpinned_action_maps_to_workflow_file(self, tmp_path):
        _mk_workflow(tmp_path, "bad.yml", BAD_WORKFLOW)
        res = [r for r in S.build(tmp_path)["runs"][0]["results"] if r["ruleId"] == "ci_security"]
        assert res, "未钉 SHA 的 uses 必须产出 ci_security finding"
        assert any(r["level"] == "error" for r in res)
        uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                for r in res if r.get("locations")}
        assert ".github/workflows/bad.yml" in uris

    def test_clean_workflow_no_error(self, tmp_path):
        _mk_workflow(tmp_path, "ok.yml", CLEAN_WORKFLOW)
        res = [r for r in S.build(tmp_path)["runs"][0]["results"]
               if r["ruleId"] == "ci_security" and r["level"] == "error"]
        assert res == []


class TestBashFindings:
    def test_dangerous_command_keeps_file_and_line(self, tmp_path):
        (tmp_path / "gatekeeper-cli.sh").write_text("#!/bin/bash\necho ok\nrm -rf /var/backups\n",
                                                    encoding="utf-8")
        res = [r for r in S.build(tmp_path)["runs"][0]["results"]
               if r["ruleId"].startswith("bash_static_")]
        assert res, "P8 危险命令必须转成 finding"
        hit = res[0]
        assert hit["level"] == "error"
        loc = hit["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "gatekeeper-cli.sh"
        assert loc["region"]["startLine"] == 3

    def test_pass_placeholders_not_reported(self, tmp_path):
        """scan_skill 的 PASS 占位项不是缺陷 —— 不得灌进告警面板。"""
        (tmp_path / "gatekeeper-cli.sh").write_text("#!/bin/bash\necho ok\n", encoding="utf-8")
        res = [r for r in S.build(tmp_path)["runs"][0]["results"]
               if r["ruleId"].startswith("bash_static_")]
        assert res == []


class TestPackageFindings:
    def test_external_path_dropped(self, monkeypatch, tmp_path):
        """树外载体（../）不得生成 locations —— relative uri 逃出仓库根会被判越界。"""
        import gk_package_integrity as P

        monkeypatch.setattr(P, "collect", lambda root=None: {
            "ok": True, "errors": 0, "warnings": 1,
            "issues": [{"level": "warn", "check": "plugin_manifest",
                        "detail": "外部技能源", "path": "../git-workflow/scripts/x.sh"}],
        })
        finds = S._pkg_findings(tmp_path)
        assert len(finds) == 1
        assert finds[0]["file"] == ""

    def test_artifact_hint_when_no_path(self, monkeypatch, tmp_path):
        import gk_package_integrity as P

        monkeypatch.setattr(P, "collect", lambda root=None: {
            "ok": False, "errors": 1, "warnings": 0,
            "issues": [{"level": "error", "check": "hook_lifecycle",
                        "detail": "install.sh 未接 gk_hook_manage.py"}],
        })
        finds = S._pkg_findings(tmp_path)
        assert finds[0]["file"] == "install.sh"
        assert finds[0]["level"] == "error"

    def test_backslash_path_normalized(self, monkeypatch, tmp_path):
        import gk_package_integrity as P

        monkeypatch.setattr(P, "collect", lambda root=None: {
            "ok": False, "errors": 1, "warnings": 0,
            "issues": [{"level": "error", "check": "hook_wrapper", "detail": "wrapper 缺失",
                        "path": "scripts\\pre_tool_hook_wrapper.sh"}],
        })
        assert S._pkg_findings(tmp_path)[0]["file"] == "scripts/pre_tool_hook_wrapper.sh"


class TestGate:
    def test_gate_returns_1_on_error(self, tmp_path):
        _mk_workflow(tmp_path, "bad.yml", BAD_WORKFLOW)
        out = tmp_path / "results.sarif"
        rc = S.main(["--root", str(tmp_path), "--out", str(out), "--gate"])
        assert rc == 1
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert doc["version"] == "2.1.0"

    def test_report_mode_returns_0(self, tmp_path):
        """无 --gate 时是纯报告出口：有 finding 也 exit 0（判据归各原始门）。"""
        _mk_workflow(tmp_path, "bad.yml", BAD_WORKFLOW)
        out = tmp_path / "results.sarif"
        assert S.main(["--root", str(tmp_path), "--out", str(out)]) == 0
        assert out.is_file()


class TestRealRepo:
    def test_current_tree_has_no_error(self):
        """当前树必须零 error 级 finding（否则 CI 的 --gate 会红）。"""
        doc = S.build(S.ROOT)
        errors = [r for r in doc["runs"][0]["results"] if r["level"] == "error"]
        assert errors == [], errors

    def test_rules_and_results_index_consistent(self):
        run = S.build(S.ROOT)["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        for r in run["results"]:
            assert rules[r["ruleIndex"]]["id"] == r["ruleId"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))

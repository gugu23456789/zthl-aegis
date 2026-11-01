#!/usr/bin/env python3
"""test_gk_l0_prefetch.py — L0 全量预取（L0-a 图/环境源 + L0-b 自检/guard-edit，2026-09-16）

覆盖:
  gk_l0_prefetch.build     L0-a 环境四元 / 索引状态透传 / detect-changes 降级不阻断；
                           L0-b self-check 聚合 / PROTECTED_REGION 标记派生 / repo 缺失 fail-loud
  gk_l0_prefetch._digest   分节与降级文案
  subagent_runner._l0_evidence_snippet  env 注入 / 缺省与不可用 → 空 / digest 截断 2400
确定性：0 API。git / subprocess 均 monkeypatch。
"""
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_l0_prefetch as l0  # noqa: E402
import subagent_runner as sr  # noqa: E402


class _env:
    """临时环境变量注入（测试无副作用）。"""

    def __init__(self, **kv):
        self.kv = kv
        self.old = {}

    def __enter__(self):
        for k, v in self.kv.items():
            self.old[k] = os.environ.get(k)
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return self

    def __exit__(self, *a):
        for k, v in self.old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


_SAMPLE_CHANGED = {"available": True, "repo": "r", "base": "HEAD~1", "changed_files": 4,
                   "changed_symbols": ["a", "b"], "affected_processes": 2, "risk": "medium"}


@pytest.fixture
def _no_git(monkeypatch):
    """git 查询固定返回值（不触真实仓库）。"""
    monkeypatch.setattr(l0, "_git",
                        lambda repo_dir, *a: "master" if "--abbrev-ref" in a else "deadbeef")


@pytest.fixture
def _no_selfcheck(monkeypatch):
    """self-check 固定聚合结果（不触真实 gk_self_check）。"""
    import gk_self_check
    monkeypatch.setattr(gk_self_check, "run_all",
                        lambda *a, **k: {"issues": 2, "checks": [
                            {"check": "bash_static", "status": "FAIL"},
                            {"check": "state_file", "status": "PASS"}]})


class TestL0a:
    def test_env_quad_and_index_status(self, monkeypatch, _no_git):
        monkeypatch.setattr(l0, "_l0b", lambda *a, **k: {})
        monkeypatch.setattr("gk_l3_prefetch.prefetch", lambda repo, base: dict(_SAMPLE_CHANGED))
        out = l0.build("r", "/tmp/r", "HEAD~1", "stale", "", "")
        assert out["available"] is True
        assert out["l0a"]["branch"] == "master"
        assert out["l0a"]["head"] == "deadbeef"
        assert out["l0a"]["index_status"] == "stale"

    def test_changed_prefetch_exception_degrades_only_l0a(self, monkeypatch, _no_git):
        monkeypatch.setattr(l0, "_l0b", lambda *a, **k: {"self_check": {"available": True, "issues": 0}})

        def boom(repo, base):
            raise RuntimeError("no node")

        monkeypatch.setattr("gk_l3_prefetch.prefetch", boom)
        out = l0.build("r", "/tmp/r", "HEAD~1", "current", "", "")
        assert out["available"] is True                      # 整体仍可用
        assert out["l0a"]["changed"]["available"] is False   # 仅该分节降级
        assert "l3_prefetch_exception" in out["l0a"]["changed"]["error"]

    def test_repo_missing_fail_loud(self, monkeypatch):
        monkeypatch.setattr(l0, "_l0a", lambda *a, **k: {})
        out = l0.build("", "/tmp/r", "HEAD~1", "current", "", "")
        assert out["available"] is False
        assert "repo 未解析" in out["error"]


class TestL0b:
    def test_self_check_aggregation(self, monkeypatch, _no_git, _no_selfcheck, tmp_path):
        monkeypatch.setattr("gk_l3_prefetch.prefetch", lambda repo, base: dict(_SAMPLE_CHANGED))
        out = l0.build("r", str(tmp_path), "HEAD~1", "current", str(tmp_path), "")
        sc = out["l0b"]["self_check"]
        assert sc["available"] is True
        assert sc["issues"] == 2
        assert sc["failed_checks"] == ["bash_static"]

    def test_self_check_exception_degrades(self, monkeypatch, _no_git, tmp_path):
        import gk_self_check
        monkeypatch.setattr(gk_self_check, "run_all",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        monkeypatch.setattr("gk_l3_prefetch.prefetch", lambda repo, base: dict(_SAMPLE_CHANGED))
        out = l0.build("r", str(tmp_path), "HEAD~1", "current", str(tmp_path), "")
        assert out["l0b"]["self_check"]["available"] is False
        assert "self_check_exception" in out["l0b"]["self_check"]["error"]

    def test_protected_regions_derived_from_markers(self, tmp_path):
        """保护区范围由 gatekeeper-cli.sh 的 PROTECTED_REGION 标记**派生**（标记 = 唯一事实源）。"""
        (tmp_path / "gatekeeper-cli.sh").write_text(
            "x=1\n# PROTECTED_REGION_START::core\ny=2\n# PROTECTED_REGION_END::core\n", encoding="utf-8")
        regs = l0._protected_regions(str(tmp_path))
        assert regs == [{"name": "core", "start": 2, "end": 4}]

    def test_protected_regions_missing_file(self, tmp_path):
        assert l0._protected_regions(str(tmp_path)) == []
        assert l0._protected_regions("") == []

    def test_guard_edit_entry_is_pointer(self, monkeypatch, _no_git):
        monkeypatch.setattr(l0, "_l0b", lambda *a, **k: {"guard_edit_entry": "bash gatekeeper-cli.sh guard-edit <path> [line]"})
        out = l0.build("r", "/tmp/r", "HEAD~1", "current", "", "")
        assert "guard-edit" in out["l0b"]["guard_edit_entry"]


class TestDigest:
    def test_sections_and_degraded_text(self, monkeypatch, _no_git, _no_selfcheck):
        monkeypatch.setattr("gk_l3_prefetch.prefetch", lambda repo, base: dict(_SAMPLE_CHANGED))
        out = l0.build("r", "/tmp/r", "HEAD~1", "current", "", "")
        d = out["digest"]
        assert "[L0-a 图/环境源]" in d and "[L0-b 自检/guard-edit]" in d
        assert "gitnexus_index=current" in d
        assert "issues=2" in d

    def test_changed_degraded_line(self, monkeypatch, _no_git):
        monkeypatch.setattr(l0, "_l0b", lambda *a, **k: {"self_check": {"available": False, "error": "x"}})
        monkeypatch.setattr("gk_l3_prefetch.prefetch",
                            lambda repo, base: {"available": False, "error": "no index"})
        out = l0.build("r", "/tmp/r", "HEAD~1", "unavailable", "", "")
        assert "变更摘要不可用：no index" in out["digest"]
        assert "self-check 不可用：x" in out["digest"]


class TestCli:
    def test_main_json_contract(self, monkeypatch, capsys, _no_git, tmp_path):
        monkeypatch.setattr("gk_l3_prefetch.prefetch", lambda repo, base: dict(_SAMPLE_CHANGED))
        old = os.environ.get("GX_REPO")
        os.environ["GX_REPO"] = "r-from-env"
        try:
            l0.main(["--repo-dir", str(tmp_path), "--base", "HEAD~3",
                     "--index-status", "current", "--skill-dir", str(tmp_path),
                     "--no-selfcheck"])
        finally:
            if old is None:
                os.environ.pop("GX_REPO", None)
            else:
                os.environ["GX_REPO"] = old
        out = json.loads(capsys.readouterr().out)
        assert out["available"] is True
        assert out["repo"] == "r-from-env"       # 未给 --repo → 单源 GX_REPO
        assert out["base"] == "HEAD~3"

    def test_main_exception_degrades(self, monkeypatch, capsys):
        monkeypatch.setattr(l0, "build", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        l0.main(["--repo", "r"])
        out = json.loads(capsys.readouterr().out)
        assert out["available"] is False
        assert "l0_prefetch_exception" in out["error"]


class TestSnippet:
    def test_injected_when_available(self):
        ev = {"available": True, "digest": "[L0-a 图/环境源]\nrepo=r"}
        with _env(GK_L0_EVIDENCE=json.dumps(ev)):
            s = sr._l0_evidence_snippet()
        assert "L0 全量预取" in s
        assert "repo=r" in s

    def test_empty_without_env(self):
        with _env(GK_L0_EVIDENCE=None):
            assert sr._l0_evidence_snippet() == ""

    def test_empty_when_unavailable(self):
        with _env(GK_L0_EVIDENCE=json.dumps({"available": False, "error": "x"})):
            assert sr._l0_evidence_snippet() == ""

    def test_empty_on_bad_json(self):
        with _env(GK_L0_EVIDENCE="{not json"):
            assert sr._l0_evidence_snippet() == ""

    def test_long_digest_truncated(self):
        with _env(GK_L0_EVIDENCE=json.dumps({"available": True, "digest": "X" * 9000})):
            s = sr._l0_evidence_snippet()
        assert len(s) < 2600   # digest 截断 2400 + 固定头
        assert s.endswith("\n")


class TestRunnerWiring:
    """F-REV-80 接线机检：证据尾块对 plan-refinement **不再豁免**（源码级，防回潮）。"""

    _SRC = (Path(__file__).resolve().parent / "subagent_runner.py").read_text(encoding="utf-8")

    def test_evidence_tail_unconditional(self):
        start = self._SRC.index("_evidence_tail = (")
        end = self._SRC.index("\n    # F-REV-32", start)
        block = self._SRC[start:end]
        for fn in ("_l0_evidence_snippet()", "_l3_evidence_snippet()", "_gate_evidence_snippet()"):
            assert fn in block, fn
        assert "args.mode" not in block, "证据尾块不得再按 mode 条件化（plan-refinement 豁免已撤销）"

    def test_l0_snippet_defined_before_use(self):
        assert self._SRC.index("def _l0_evidence_snippet") < self._SRC.index("_evidence_tail = (")

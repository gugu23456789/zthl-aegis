#!/usr/bin/env python3
"""test_gk_l3_prefetch.py — L3 图证据预取 + subagent 注入测试（2026-09-04 L2/L3 换位）

覆盖:
  gk_l3_prefetch.prefetch  成功（digest 组装/符号 cap 20）/ gitnexus 失败降级（available:false）/
                            异常降级（不阻断 L2）
  subagent_runner._l3_evidence_snippet  env 注入（available 摘要出现 / 缺失/不可用 → 空 /
                            超长 digest 截断 1600）
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_l3_prefetch as lp  # noqa: E402
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


_SAMPLE_OK = {"ok": True, "base": "HEAD~1", "repo": "spz-gatekeeper-r-sequence",
              "changed_files": 3, "changed_symbols": ["resolve_plan", "resolve_worktree"],
              "affected_processes": 2, "risk": "medium"}


class TestPrefetch:
    def test_success_digest(self, monkeypatch):
        monkeypatch.setattr(lp, "review_pr", lambda base, repo: dict(_SAMPLE_OK))
        r = lp.prefetch("spz-gatekeeper-r-sequence", "HEAD~1")
        assert r["available"] is True
        assert r["changed_files"] == 3
        assert r["changed_symbols"] == ["resolve_plan", "resolve_worktree"]
        assert "repo=spz-gatekeeper-r-sequence" in r["digest"]
        assert "受影响流程 2" in r["digest"]
        assert "resolve_plan" in r["digest"]

    def test_symbols_capped_20(self, monkeypatch):
        ok = dict(_SAMPLE_OK, changed_symbols=[f"s{i}" for i in range(50)])
        monkeypatch.setattr(lp, "review_pr", lambda base, repo: ok)
        r = lp.prefetch("r", "HEAD~1")
        assert len(r["changed_symbols"]) == 20

    def test_gitnexus_fail_degrades(self, monkeypatch):
        monkeypatch.setattr(lp, "review_pr", lambda base, repo: {"ok": False, "error": "no index"})
        r = lp.prefetch("spz_gatekeeper", "HEAD~1")
        assert r["available"] is False
        assert "no index" in r["error"]

    def test_exception_degrades(self, monkeypatch):
        def boom(base, repo):
            raise RuntimeError("node missing")

        monkeypatch.setattr(lp, "review_pr", boom)
        r = lp.prefetch("r", "HEAD~1")
        assert r["available"] is False
        assert "prefetch_exception" in r["error"]

    def test_main_cli_json(self, monkeypatch, capsys):
        monkeypatch.setattr(lp, "review_pr", lambda base, repo: dict(_SAMPLE_OK))
        old = sys.argv
        sys.argv = ["gk_l3_prefetch.py", "--repo", "spz-gatekeeper-r-sequence", "--base", "HEAD~2"]
        try:
            lp.main()
        finally:
            sys.argv = old
        out = json.loads(capsys.readouterr().out)
        assert out["available"] is True
        assert out["base"] == "HEAD~2"


class TestSnippet:
    def test_injected_when_available(self):
        ev = {"available": True, "digest": "repo=x\n变更文件 2 · 符号 1"}
        with _env(GK_L3_EVIDENCE=json.dumps(ev)):
            s = sr._l3_evidence_snippet()
        assert "L3 图证据预取" in s
        assert "repo=x" in s

    def test_empty_without_env(self):
        with _env(GK_L3_EVIDENCE=None):
            assert sr._l3_evidence_snippet() == ""

    def test_empty_when_unavailable(self):
        with _env(GK_L3_EVIDENCE=json.dumps({"available": False, "error": "x"})):
            assert sr._l3_evidence_snippet() == ""

    def test_long_digest_truncated(self):
        ev = {"available": True, "digest": "X" * 5000}
        with _env(GK_L3_EVIDENCE=json.dumps(ev)):
            s = sr._l3_evidence_snippet()
        # digest 本体截断至 1600 + 固定头 ~110 字符
        assert len(s) < 1800
        assert s.endswith("\n")

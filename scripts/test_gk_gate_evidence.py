"""
test_gk_gate_evidence.py — gate 源码变更证据摘要测试（F-REV-11 C2，2026-09-10）
============================================================================
覆盖：numstat 解析（含二进制）/ hunk 头提取与限长 / 仓不存在 → available:false /
真实临时仓 → 变更计数与摘要 / max_chars 有界 / 路径过滤无变更 / CLI 子命令输出契约。
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import gk_gate_evidence as gge


class TestParseNumstat:
    def test_basic(self):
        assert gge.parse_numstat("5\t1\tgatekeeper-cli.sh\n") == [
            {"path": "gatekeeper-cli.sh", "added": 5, "deleted": 1}]

    def test_binary_marked_none(self):
        r = gge.parse_numstat("-\t-\tbin.dat\n")
        assert r[0]["added"] is None and r[0]["deleted"] is None

    def test_malformed_skipped(self):
        assert gge.parse_numstat("garbage\n\n\t\t\n") == []


class TestHunkHeaders:
    def test_limit(self):
        t = "\n".join(f"@@ -{i},1 +{i},1 @@" for i in range(20))
        assert gge.hunk_headers(t, limit=3) == [
            "@@ -0,1 +0,1 @@", "@@ -1,1 +1,1 @@", "@@ -2,1 +2,1 @@"]

    def test_ignores_non_hunk(self):
        assert gge.hunk_headers("diff --git a/x b/x\n+++ b/x\n") == []


@pytest.mark.skipif(shutil.which("git") is None, reason="git unavailable")
class TestBuild:
    @staticmethod
    def _repo(d: Path):
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
        subprocess.run(["git", "init", "-q", str(d)], check=True, env=env)
        (d / "gatekeeper-cli.sh").write_text("a\n", encoding="utf-8")
        (d / "other.txt").write_text("x\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(d), "add", "."], check=True, env=env)
        subprocess.run(["git", "-C", str(d), "commit", "-qm", "one"], check=True, env=env)
        (d / "gatekeeper-cli.sh").write_text("a\nb\nc\n", encoding="utf-8")
        (d / "other.txt").write_text("x\ny\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(d), "add", "."], check=True, env=env)
        subprocess.run(["git", "-C", str(d), "commit", "-qm", "two"], check=True, env=env)

    def test_missing_repo_unavailable(self, tmp_path):
        r = gge.build(str(tmp_path / "nope"), "HEAD~1")
        assert r["available"] is False and "error" in r

    def test_change_digest(self, tmp_path):
        d = tmp_path / "r"
        d.mkdir()
        self._repo(d)
        r = gge.build(str(d), "HEAD~1")
        assert r["available"] is True
        assert r["files"] == [{"path": "gatekeeper-cli.sh", "added": 2, "deleted": 0}]
        assert "gate 源码变更证据" in r["digest"]
        assert "gatekeeper-cli.sh +2/-0" in r["digest"]

    def test_path_filter_excludes_other_files(self, tmp_path):
        """--paths 只纳入 gate 源：other.txt 的变更不得进 files（防变更面泛化）。"""
        d = tmp_path / "r"
        d.mkdir()
        self._repo(d)
        r = gge.build(str(d), "HEAD~1", paths=["other.txt"])
        assert [f["path"] for f in r["files"]] == ["other.txt"]

    def test_no_change_paths(self, tmp_path):
        d = tmp_path / "r"
        d.mkdir()
        self._repo(d)
        r = gge.build(str(d), "HEAD~1", paths=["nonexistent.sh"])
        assert r["files"] == [] and "无变更" in r["digest"]

    def test_max_chars_bounds_digest(self, tmp_path):
        d = tmp_path / "r"
        d.mkdir()
        self._repo(d)
        r = gge.build(str(d), "HEAD~1", max_chars=20)
        assert len(r["digest"]) <= 20


class TestCli:
    def test_main_emits_json(self, tmp_path, capsys):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = gge.main(["--repo-dir", str(tmp_path / "nope"), "--base", "HEAD~1"])
        assert rc == 0
        assert json.loads(buf.getvalue())["available"] is False

    def test_default_paths_is_gate(self):
        assert gge.DEFAULT_PATHS == ["gatekeeper-cli.sh"]

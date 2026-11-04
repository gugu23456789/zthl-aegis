"""test_gk_edit_verify.py — 写后落盘校验（用户：确保修改真的落盘）。

覆盖：文件缺失 / 锚点命中与行号 / absent / 指定行断言 / sha256 / git 改动对账 / 退出码。
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).parent))

import gk_edit_verify as V


def _w(tmp_path, name="x.py", text="line1\ndef foo():\n    return 1\n") -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


class TestBasic:
    def test_missing_file_fails(self, tmp_path):
        r = V.verify(tmp_path / "nope.py")
        assert r["ok"] is False
        assert r["checks"][0]["check"] == "exists"

    def test_empty_file_fails(self, tmp_path):
        p = tmp_path / "empty.py"
        p.write_text("", encoding="utf-8")
        r = V.verify(p)
        assert r["ok"] is False
        assert any(c["check"] == "non_empty" and c["status"] == "FAIL" for c in r["checks"])


class TestAnchors:
    def test_contains_reports_line_numbers(self, tmp_path):
        p = _w(tmp_path)
        r = V.verify(p, contains=["def foo"])
        assert r["ok"] is True
        hit = next(c for c in r["checks"] if c["check"] == "contains")
        assert "行号 [2]" in hit["detail"]

    def test_missing_anchor_fails(self, tmp_path):
        p = _w(tmp_path)
        r = V.verify(p, contains=["def bar"])
        assert r["ok"] is False

    def test_absent_ok_and_violation(self, tmp_path):
        p = _w(tmp_path)
        assert V.verify(p, absent=["def bar"])["ok"] is True
        r = V.verify(p, absent=["def foo"])
        assert r["ok"] is False
        assert any(c["check"] == "absent" and c["status"] == "FAIL" for c in r["checks"])

    def test_line_assertion(self, tmp_path):
        p = _w(tmp_path)
        assert V.verify(p, line=3, line_has="return 1")["ok"] is True
        r = V.verify(p, line=3, line_has="return 2")
        assert r["ok"] is False
        assert any(c["check"] == "line" and c["status"] == "FAIL" for c in r["checks"])

    def test_line_out_of_range(self, tmp_path):
        p = _w(tmp_path)
        r = V.verify(p, line=99, line_has="x")
        assert r["ok"] is False
        assert "越界" in r["checks"][-1]["detail"]


class TestSha256:
    def test_match(self, tmp_path):
        p = _w(tmp_path)
        assert V.verify(p, sha256=hashlib.sha256(p.read_bytes()).hexdigest())["ok"] is True

    def test_mismatch(self, tmp_path):
        p = _w(tmp_path)
        r = V.verify(p, sha256="0" * 64)
        assert r["ok"] is False
        assert any(c["check"] == "sha256" and c["status"] == "FAIL" for c in r["checks"])


class TestGitChanged:
    def _git_repo(self, tmp_path):
        try:
            r = subprocess.run(["git", "init", "-q", str(tmp_path)],
                               capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError):  # pragma: no cover
            pytest.skip("git 不可用")
        if r.returncode != 0:  # pragma: no cover
            pytest.skip("git init 失败")
        return tmp_path

    def test_untracked_file_counts_as_changed(self, tmp_path):
        repo = self._git_repo(tmp_path)
        p = _w(repo)
        r = V.verify(p, expect_changed=True, root=repo)
        assert r["ok"] is True
        assert r["git"]["status"] == "changed"

    def test_non_repo_is_warn_not_fail(self, tmp_path):
        p = _w(tmp_path)
        r = V.verify(p, expect_changed=True, root=tmp_path)
        assert r["ok"] is True
        assert r["git"]["status"] == "unknown"
        assert any(c["check"] == "expect_changed" and c["status"] == "WARN"
                   for c in r["checks"])


class TestCli:
    def test_json_output_and_exit_code(self, tmp_path, capsys):
        p = _w(tmp_path)
        rc = V.main(["--file", str(p), "--contains", "def foo", "--json"])
        assert rc == 0
        assert json.loads(capsys.readouterr().out)["ok"] is True

    def test_exit_1_on_missing_anchor(self, tmp_path):
        p = _w(tmp_path)
        assert V.main(["--file", str(p), "--contains", "def bar"]) == 1

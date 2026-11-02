#!/usr/bin/env python3
"""test_gk_py_argv_inject.py — self-check #23 python_argv_inject 测试（2026-09-05 C10 卫生轮）。

约定 = main(argv=None) 注入；旧式 = def main() + 直读 sys.argv。
判定：新（未跟踪）文件旧式 → FAIL；存量（已跟踪）旧式 → WARN；git 不可用 → 保守 WARN。
"""
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import gk_self_check as sc  # noqa: E402


OLD_STYLE = 'import sys\n\ndef main():\n    args = sys.argv[1:]\n    print(args)\n\n\nif __name__ == "__main__":\n    main()\n'
NEW_STYLE = ('def main(argv=None):\n'
             '    import sys\n'
             '    args = list(sys.argv[1:] if argv is None else argv)\n'
             '    print(args)\n'
             '\n\nif __name__ == "__main__":\n    main()\n')


@pytest.fixture
def skill_dir(tmp_path):
    d = tmp_path / "skill"
    (d / "scripts").mkdir(parents=True)
    return str(d)


def _write(d, name, content):
    p = Path(d) / "scripts" / name
    p.write_text(content, encoding="utf-8")
    return p


def _tracked_true(d, rel):
    return True


def _tracked_false(d, rel):
    return False


def _tracked_none(d, rel):
    return None


class TestPythonArgvInject:
    def test_new_injected_style_pass(self, skill_dir, monkeypatch):
        _write(skill_dir, "gk_new_ok.py", NEW_STYLE)
        monkeypatch.setattr(sc, "_run_git_tracked", _tracked_false)
        r = sc.check_python_argv_inject(skill_dir)
        assert r["status"] == "PASS", r

    def test_new_old_style_fail(self, skill_dir, monkeypatch):
        _write(skill_dir, "gk_new_bad.py", OLD_STYLE)
        monkeypatch.setattr(sc, "_run_git_tracked", _tracked_false)
        r = sc.check_python_argv_inject(skill_dir)
        assert r["status"] == "FAIL", r
        assert "main(argv=None)" in r["detail"]

    def test_legacy_tracked_old_style_warn(self, skill_dir, monkeypatch):
        _write(skill_dir, "gk_legacy.py", OLD_STYLE)
        monkeypatch.setattr(sc, "_run_git_tracked", _tracked_true)
        r = sc.check_python_argv_inject(skill_dir)
        assert r["status"] == "WARN", r
        assert "存量" in r["detail"]

    def test_git_unavailable_conservative_warn(self, skill_dir, monkeypatch):
        _write(skill_dir, "gk_no_git.py", OLD_STYLE)
        monkeypatch.setattr(sc, "_run_git_tracked", _tracked_none)
        r = sc.check_python_argv_inject(skill_dir)
        assert r["status"] == "WARN", r  # git 不可用 → 全部按存量，不误拦

    def test_no_gk_files_pass(self, skill_dir, monkeypatch):
        monkeypatch.setattr(sc, "_run_git_tracked", _tracked_false)
        r = sc.check_python_argv_inject(skill_dir)
        assert r["status"] == "PASS", r

    def test_missing_skill_dir_skip(self, tmp_path):
        r = sc.check_python_argv_inject(str(tmp_path / "nope"))
        assert r["status"] == "SKIP", r

    def test_mixed_legacy_and_violation(self, skill_dir, monkeypatch):
        _write(skill_dir, "gk_legacy.py", OLD_STYLE)      # tracked → 存量
        _write(skill_dir, "gk_new_bad.py", OLD_STYLE)     # untracked → 违规
        _write(skill_dir, "gk_new_ok.py", NEW_STYLE)

        def _mixed(d, rel):
            return "legacy" in rel

        monkeypatch.setattr(sc, "_run_git_tracked", _mixed)
        r = sc.check_python_argv_inject(skill_dir)
        assert r["status"] == "FAIL" and r["legacy"] == 1, r

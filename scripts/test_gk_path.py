"""test_gk_path.py — B9f 红先：`gk_path.py realpath <p>`（替代两处内联 realpath）。"""
import subprocess
import sys
from pathlib import Path

CLI = Path(__file__).parent / "gk_path.py"


def _run(*args):
    return subprocess.run([sys.executable, str(CLI)] + list(args),
                          capture_output=True, text=True, encoding="utf-8")


class TestRealpath:
    def test_resolves_dotdot(self, tmp_path):
        (tmp_path / "a").mkdir()
        p = tmp_path / "a" / ".." / "a"
        r = _run("realpath", str(p))
        assert r.returncode == 0, r
        assert r.stdout.strip() == str((tmp_path / "a").resolve())

    def test_nonexistent_path_still_printed(self, tmp_path):
        """`os.path.realpath` 不要求路径存在（纯字符串归一）。"""
        p = tmp_path / "nope" / "x"
        r = _run("realpath", str(p))
        assert r.returncode == 0 and r.stdout.strip() == str(p)

    def test_missing_arg_exit_2(self):
        assert _run("realpath").returncode == 2

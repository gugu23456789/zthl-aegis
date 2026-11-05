"""test_gk_accept_env_confusion.py — 验收解释器解析的**环境混淆攻击**臂（2026-11-05）。

威胁模型：调用方 cwd / 环境变量 / pin 文件可能被替换或写错平台 ⟹ 若解析器按「相对路径 /
错误平台标签 / PATH 诱饵」取候选，就会加载攻击者指定的解释器（供应链面）。
判据：**只有**「绝对且存在的 pin」「仓内 `.venv*`」「裸命令名走 PATH」三类可信来源能生效；
相对 `ACCEPT_PY`、相对 pin、错平台 pin、cwd 诱饵 `.venv` 一律忽略。
"""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_accept_py as A  # noqa: E402


def _exe(p: Path) -> str:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("", encoding="utf-8")
    try:
        os.chmod(p, 0o755)
    except OSError:
        pass
    return str(p)


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    monkeypatch.delenv("ACCEPT_PY", raising=False)
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(A, "LOCAL_FILE", str(tmp_path / "pin.local"), raising=False)
    monkeypatch.setattr(A, "_repo_roots", lambda: [str(repo)])
    monkeypatch.setattr(A.shutil, "which", lambda _n: "")
    return tmp_path


def test_relative_accept_py_is_ignored(sandbox, monkeypatch):
    decoy = _exe(sandbox / "evil" / "python")
    monkeypatch.setenv("ACCEPT_PY", "../evil/python")
    got = A.resolve()
    assert got != decoy and "evil" not in got


def test_absolute_but_missing_accept_py_is_ignored(sandbox, monkeypatch):
    monkeypatch.setenv("ACCEPT_PY", str(sandbox / "nope" / "python"))
    assert A.resolve() == A.DEFAULT


def test_bare_command_name_uses_path(sandbox, monkeypatch):
    monkeypatch.setenv("ACCEPT_PY", "python3")
    monkeypatch.setattr(A.shutil, "which", lambda n: "/usr/bin/python3" if n == "python3" else "")
    assert A.resolve() == "/usr/bin/python3"


def test_pin_is_platform_tagged(sandbox, monkeypatch):
    win_py = _exe(sandbox / "w" / "python.exe")
    wsl_py = _exe(sandbox / "u" / "bin" / "python")
    (sandbox / "pin.local").write_text(
        "win: %s\nwsl: %s\n" % (win_py, wsl_py), encoding="utf-8")
    monkeypatch.setattr(A, "_plat_of_this_process", lambda: "win")
    assert A.resolve() == win_py
    monkeypatch.setattr(A, "_plat_of_this_process", lambda: "wsl")
    assert A.resolve() == wsl_py


def test_wrong_platform_pin_is_not_used(sandbox, monkeypatch):
    decoy = _exe(sandbox / "decoy" / "python.exe")
    (sandbox / "pin.local").write_text("wsl: %s\n" % decoy, encoding="utf-8")
    monkeypatch.setattr(A, "_plat_of_this_process", lambda: "win")
    got = A.resolve()
    assert got != decoy, "错平台的行不得被选中"


def test_relative_pin_is_ignored(sandbox, monkeypatch):
    decoy = _exe(sandbox / "evil" / "python")
    (sandbox / "pin.local").write_text("win: ../evil/python\n", encoding="utf-8")
    monkeypatch.setattr(A, "_plat_of_this_process", lambda: "win")
    got = A.resolve()
    assert got != decoy and "evil" not in got


def test_malformed_pin_lines_are_ignored(sandbox, monkeypatch):
    repo_py = _exe(sandbox / "repo" / ".venv-x" / "Scripts" / "python.exe")
    (sandbox / "pin.local").write_text(
        "windows: C:\\nope\\python.exe\nwin C:\\nope\\python.exe\nwin:\n: bad\n",
        encoding="utf-8")
    monkeypatch.setattr(A, "_plat_of_this_process", lambda: "win")
    assert A.resolve() == repo_py, "坏行跳过，回落仓内 .venv*"


def test_cwd_decoy_venv_not_used(sandbox, monkeypatch):
    _exe(sandbox / ".venv" / "Scripts" / "python.exe")     # cwd 诱饵（不在仓根）
    _exe(sandbox / ".venv" / "bin" / "python")
    monkeypatch.setattr(A, "_plat_of_this_process", lambda: "win")
    assert A.resolve() == A.DEFAULT, "cwd 下的 .venv 不属于仓内候选"


def test_repo_venv_beats_path_decoy(sandbox, monkeypatch):
    repo_py = _exe(sandbox / "repo" / ".venv" / "Scripts" / "python.exe")
    _exe(sandbox / "repo" / ".venv" / "bin" / "python")
    monkeypatch.setattr(A, "_plat_of_this_process", lambda: "win")
    monkeypatch.setattr(A.shutil, "which", lambda _n: str(sandbox / "evil" / "python3"))
    got = A.resolve()
    assert got == repo_py and "evil" not in got, "仓内 venv 优先于 PATH 诱饵"


def test_accept_py_is_stripped(sandbox, monkeypatch):
    real = _exe(sandbox / "real" / "python")
    monkeypatch.setenv("ACCEPT_PY", "  %s  " % real)
    assert A.resolve() == real

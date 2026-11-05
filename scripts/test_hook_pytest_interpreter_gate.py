#!/usr/bin/env python3
"""Gate R0.16（pytest 必须用配好的解释器）红先测试。

背景（2026-10-27 实证）：裸 `python -m pytest` 走 Windows Python 3.11 ⟹ 路径语义/依赖面
全变（实测：大量环境性红 + `.keys` 无法 stat），而此前**没有任何一道门**检查解释器。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pre_tool_hook as hook  # noqa: E402


def test_block_python_m_pytest():
    hit = hook._pytest_wrong_interpreter("python -m pytest scripts/test_x.py -q")
    assert hit and "配好的解释器" in hit[0]
    assert "_accept_cli.sh" in hit[1]


def test_block_python3_m_pytest():
    assert hook._pytest_wrong_interpreter("python3 -m pytest scripts -q")


def test_block_py_launcher():
    assert hook._pytest_wrong_interpreter("py -m pytest scripts/test_x.py")


def test_block_bare_pytest():
    """`cd … && pytest` 也是命令位（不能只认 `python -m pytest`）。"""
    assert hook._pytest_wrong_interpreter("cd scripts && pytest test_x.py -q")


def test_block_wrapped_payload():
    cmd = "wslsh -c 'cd /mnt/c/x && python3 -m pytest scripts -q'"
    assert hook._pytest_wrong_interpreter(cmd)


def test_block_with_interpreter_flags():
    assert hook._pytest_wrong_interpreter("python -u -m pytest scripts")


def test_allow_accept_cli():
    assert hook._pytest_wrong_interpreter(
        "bash scripts/_accept_cli.sh scripts/test_x.py") is None


def test_allow_redfirst():
    assert hook._pytest_wrong_interpreter(
        'bash scripts/_redfirst_cli.sh HEAD scripts/test_x.py "x"') is None


def test_allow_configured_interpreter():
    assert hook._pytest_wrong_interpreter(
        "/opt/venv/bin/python -m pytest scripts -q") is None


def test_allow_quoted_literal():
    """写文档时的字符串字面量不误伤（非 `-c` 载荷）。"""
    assert hook._pytest_wrong_interpreter("echo 'python -m pytest scripts'") is None


def test_allow_heredoc_body():
    cmd = "cat > notes.md <<'EOF'\npython -m pytest scripts\nEOF"
    assert hook._pytest_wrong_interpreter(cmd) is None


def test_allow_escape_hatch():
    assert hook._pytest_wrong_interpreter(
        "GK_ALLOW_ANY_PYTEST=1 python -m pytest scripts") is None


def test_allow_non_pytest_python():
    assert hook._pytest_wrong_interpreter("python -c 'print(1)'") is None
    assert hook._pytest_wrong_interpreter("python scripts/gk_self_check.py") is None


def test_gate_name_family_consistent():
    assert hook.BLUE_FAT_FISH_PYTEST_GATE_NAME == "蓝色大肥鱼与配好的解释器之间不得不说的故事"

#!/usr/bin/env python3
"""test_gk_accept_factor.py — f 自动分档（408 三档口径）的判定锁（2026-11-09）。

只测**分类与聚合**（纯文本），不跑 pytest、不碰系统读数；扫描面 = 临时文件。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_accept_factor as af  # noqa: E402


PLAIN = """
def test_a():
    assert 1 == 1

def test_b():
    assert 2 == 2
"""

ONE_BASH = """
import subprocess

def test_a():
    subprocess.run(["echo", "x"])

def test_b():
    subprocess.run(["echo", "y"])
"""

HEAVY = """
import subprocess

def test_a():
    subprocess.run(["wsl", "-d", "Ubuntu", "--", "openssl", "version"])
"""

MANY_CALLS = """
import subprocess

def test_a():
    subprocess.run(["a"])
    subprocess.run(["b"])
    subprocess.run(["c"])
"""


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_plain_is_zero(tmp_path):
    assert af.classify_text(PLAIN) == 0
    assert af.classify_files([_write(tmp_path, "test_plain.py", PLAIN)]) == 0


def test_one_bash_per_test_is_one(tmp_path):
    assert af.classify_text(ONE_BASH) == 1


def test_wsl_or_openssl_is_three(tmp_path):
    assert af.classify_text(HEAVY) == 3


def test_density_above_one_is_three():
    assert af.classify_text(MANY_CALLS) == 3


def test_no_tests_file_is_zero():
    assert af.classify_text("# 没有用例\n") == 0


def test_batch_all_light_is_zero(tmp_path):
    paths = [_write(tmp_path, "test_a.py", PLAIN), _write(tmp_path, "test_c.py", PLAIN)]
    assert af.classify_files(paths) == 0


def test_batch_majority_heavy_is_three(tmp_path):
    paths = [_write(tmp_path, "test_h1.py", HEAVY), _write(tmp_path, "test_h2.py", HEAVY),
             _write(tmp_path, "test_l.py", PLAIN)]
    assert af.classify_files(paths) == 3


def test_batch_minority_heavy_stays_one(tmp_path):
    """混跑按 1：重活只占少数文件时不得把全量压到 f=3（实测全量 n=8 最优）。"""
    paths = [_write(tmp_path, "test_h.py", HEAVY),
             _write(tmp_path, "test_l1.py", ONE_BASH), _write(tmp_path, "test_l2.py", ONE_BASH),
             _write(tmp_path, "test_l3.py", PLAIN)]
    assert af.classify_files(paths) == 1


def test_missing_files_are_ignored(tmp_path):
    assert af.classify_files([tmp_path / "nope.py"]) == 1   # 空集 ⟹ 混合缺省


def test_cli_prints_single_integer(tmp_path, capsys):
    p = _write(tmp_path, "test_h.py", HEAVY)
    assert af.main([str(p)]) == 0
    assert capsys.readouterr().out.strip() == "3"

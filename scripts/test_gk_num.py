"""test_gk_num.py — 数值运算/阈值判定工具测试（2026-08-26 批次 2 剩余）。

覆盖: ratio 除法 round / denom=0 容错 / norm 百分比归一化 / round / gt 退出码（verdict）。
安全网 R1: 纯函数只读，无外部副作用。
"""
import subprocess
import sys
from pathlib import Path

_SCRIPT = Path(__file__).parent / "gk_num.py"


def _run(*args, expect_ok=True):
    r = subprocess.run([sys.executable, str(_SCRIPT), *args],
                       capture_output=True, text=True, encoding="utf-8", timeout=10)
    assert r.returncode == 0 if expect_ok else r.returncode != 0
    return r.stdout.strip()


def test_ratio():
    assert _run("ratio", "3", "4") == "0.75"
    assert _run("ratio", "1", "3") == "0.33"


def test_ratio_zero_denom():
    """denom=0/非法 → 0.0（对齐原内联容错方向，不崩溃）。"""
    assert _run("ratio", "5", "0") == "0.0"
    assert _run("ratio", "5", "abc") == "0.0"


def test_norm_percent():
    """score>1 视为百分比（s/100），≤1 原样——L2287 语义。"""
    assert _run("norm", "87.5") == "0.88"
    assert _run("norm", "0.75") == "0.75"
    assert _run("norm", "0") == "0.0"  # float 语义 round(0.0,2)，JSON 数值等价


def test_round():
    assert _run("round", "0.666") == "0.67"


def test_gt_exit_code():
    """verdict 判定：score>0.5 → exit 0（PASS 分支），否则 exit 1（BLOCKED）。"""
    assert _run("gt", "0.8", "0.5") == ""
    r = subprocess.run([sys.executable, str(_SCRIPT), "gt", "0.4", "0.5"],
                       capture_output=True, text=True, timeout=10)
    assert r.returncode == 1


def test_gt_non_numeric():
    """空/非法输入按 0.0 → gt 判 false（保守方向：空 score 不 PASS）。"""
    r = subprocess.run([sys.executable, str(_SCRIPT), "gt", "", "0.5"],
                       capture_output=True, text=True, timeout=10)
    assert r.returncode == 1

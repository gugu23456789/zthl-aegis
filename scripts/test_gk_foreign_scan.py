"""test_gk_foreign_scan.py — 跨租户外链检测测试（2026-08-26 批次 2 剩余）。

覆盖: Layer1 外部用户路径 / 本用户豁免 / 白名单用户 / Layer2 泄漏 markers / clean。
安全网 R1: 只读 tmp_path 文件。
"""
import subprocess
import sys
from pathlib import Path

_SCRIPT = Path(__file__).parent / "gk_foreign_scan.py"


def _run(text: str, own: str = "hp") -> str:
    f = Path(__file__).parent / "tmp_foreign_in.txt"
    f.write_text(text, encoding="utf-8")
    r = subprocess.run([sys.executable, str(_SCRIPT), str(f), own],
                       capture_output=True, text=True, encoding="utf-8", timeout=10)
    f.unlink(missing_ok=True)
    assert r.returncode == 0
    return r.stdout.strip()


def test_foreign_user_path():
    assert _run(r"referenced <home>\file") == "foreign_user:attacker"
    assert _run("<home>/x") == "foreign_user:other"
    assert _run("<home>/docs") == "foreign_user:intruder"


def test_own_user_exempt():
    assert _run(r"<home>\state", own="HP") == "clean"


def test_whitelist_exempt():
    assert _run(r"<home>\share") == "clean"


def test_leakage_marker():
    assert _run("leak: xhs-copilot in log") == "leakage_marker:xhs-copilot"
    assert _run("发现小红书内容") == "leakage_marker:小红书"


def test_clean():
    assert _run("no foreign content here") == "clean"

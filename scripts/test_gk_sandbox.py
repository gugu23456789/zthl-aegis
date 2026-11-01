#!/usr/bin/env python3
"""gk_sandbox 回归：正常执行 / 超时杀 / 内存硬上限生效 / fail-loud 契约。"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_sandbox as sb  # noqa: E402

PY = sys.executable


def test_run_normal_ok():
    r = sb.run([PY, "-c", "print('hi')"], mem_mb=256, timeout_s=30, fail_closed=False)
    assert r["ok"] is True and r["rc"] == 0 and r["timed_out"] is False


def test_timeout_kills_child():
    r = sb.run([PY, "-c", "import time; time.sleep(30)"],
               mem_mb=256, timeout_s=0.6, fail_closed=False)
    assert r["ok"] is True and r["timed_out"] is True and r["rc"] == -1


def test_memory_cap_is_enforced_and_bounded():
    """子进程试图超额分配 ⟹ 分配失败（非拖垮宿主）；且沙箱限制确已生效。"""
    child = ("import sys\n"
             "try:\n"
             "    b = bytearray(400*1024*1024)\n"
             "    sys.exit(0)\n"
             "except MemoryError:\n"
             "    sys.exit(3)\n")
    r = sb.run([PY, "-c", child], mem_mb=64, timeout_s=30, fail_closed=True)
    assert r["ok"] is True, "限制应可强制（本机 Job Object 可用）"
    assert r["enforced"] is True
    assert r["rc"] != 0, "超出内存上限的子进程不得成功"


def test_empty_argv_rejected():
    r = sb.run([])
    assert r["ok"] is False and r["reason"] == "empty argv"


def test_fail_closed_when_unenforceable(monkeypatch):
    """限制不可强制 + fail_closed ⟹ 拒跑（不静默假装有沙箱）。"""
    monkeypatch.setattr(sb, "_win_run" if sb.os.name == "nt" else "_posix_run",
                        lambda *a, **k: (None, False, False))
    r = sb.run([PY, "-c", "print(1)"], mem_mb=64, fail_closed=True)
    assert r["ok"] is False and r["enforced"] is False


def test_cli_run_json(capsys):
    rc = sb.main(["run", "--mem-mb", "256", "--timeout", "30", "--json", "--",
                  PY, "-c", "print(1)"])
    assert rc == 0
    assert '"ok": true' in capsys.readouterr().out

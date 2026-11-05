"""`gk_budget_snap.py`（`_budget_snap` 内联块下沉，2026-11-04）等价臂。

判据：global / session 两域、新会话条目未建时的预演口径、state 不可用降级、
以及 CLI 输出的 CRLF 净化（Windows print 不得污染三字段串）。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
from gk_budget_snap import snapshot  # noqa: E402


def _state(tmp_path, eb):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"gate_data": {"edit_budget": eb}}), encoding="utf-8")
    return str(p)


def test_global_domain(tmp_path):
    p = _state(tmp_path, {"max": 8, "used": 3, "remaining": 5})
    assert snapshot(p) == ("global", 3, 5)


def test_session_existing(tmp_path):
    p = _state(tmp_path, {"max": 8, "sessions": {"s1": {"used": 2, "remaining": 6}}})
    assert snapshot(p, "s1") == ("session", 2, 6)


def test_session_missing_presimulates_max(tmp_path):
    """会话条目未建 → used=0 / remaining=max（与扣减点 setdefault 同口径）。"""
    p = _state(tmp_path, {"max": 8})
    assert snapshot(p, "new") == ("session", 0, 8)


def test_unreadable_degrades(tmp_path):
    assert snapshot(str(tmp_path / "absent.json")) == ("-", "-", "-")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert snapshot(str(bad)) == ("-", "-", "-")


def test_cli_output_has_no_cr(tmp_path):
    p = _state(tmp_path, {"max": 8, "used": 1, "remaining": 7})
    env = dict(os.environ, STATE_FILE=p, GK_SESSION_ID="")
    out = subprocess.run([sys.executable, str(HERE / "gk_budget_snap.py")],
                         capture_output=True, env=env)
    assert out.stdout == b"global 1 7\n", out.stdout

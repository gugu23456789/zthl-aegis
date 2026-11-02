#!/usr/bin/env python3
"""test_gk_io.py — B10a：`gk_io.py write-text`（原 `python3 -c "open(...).write(...)"`）。"""
import subprocess
import sys
from pathlib import Path

CLI = Path(__file__).parent / "gk_io.py"


def _run(*args, stdin_text="", env=None):
    e = None
    if env:
        import os
        e = os.environ.copy()
        e.update(env)
    return subprocess.run([sys.executable, str(CLI)] + list(args),
                          input=stdin_text, capture_output=True, text=True,
                          encoding="utf-8", env=e)


def test_write_text_exact(tmp_path):
    p = tmp_path / "msg.txt"
    r = _run("write-text", str(p), stdin_text="feat: 中文\n\nbody line")
    assert r.returncode == 0, r
    assert p.read_text(encoding="utf-8") == "feat: 中文\n\nbody line"


def test_write_empty(tmp_path):
    p = tmp_path / "empty.txt"
    assert _run("write-text", str(p), stdin_text="").returncode == 0
    assert p.read_text(encoding="utf-8") == ""


def test_overwrite(tmp_path):
    p = tmp_path / "m.txt"
    p.write_text("old", encoding="utf-8")
    _run("write-text", str(p), stdin_text="new")
    assert p.read_text(encoding="utf-8") == "new"


def test_unwritable_nonzero(tmp_path):
    r = _run("write-text", str(tmp_path / "no" / "dir" / "x.txt"), stdin_text="x")
    assert r.returncode == 1


def test_usage_exit_2():
    assert _run().returncode == 2
    assert _run("write-text").returncode == 2
    assert _run("nope", "x").returncode == 2

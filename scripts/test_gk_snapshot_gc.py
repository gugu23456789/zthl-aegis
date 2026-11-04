#!/usr/bin/env python3
"""gk_snapshot_gc 红先臂 —— 保留最近 N 份 + 年龄阈值 + 默认 dry-run。"""
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_snapshot_gc as G  # noqa: E402


def _mk(root: Path, name: str, age_days: float):
    p = root / name
    p.mkdir()
    (p / "f.txt").write_text("x", encoding="utf-8")
    t = time.time() - age_days * 86400
    os.utime(p, (t, t))
    return p


def test_plan_keeps_newest_and_respects_age(tmp_path, capsys):
    _mk(tmp_path, "snap-v1", 30)
    _mk(tmp_path, "snap-v2", 20)
    _mk(tmp_path, "snap-v3", 0.1)
    rc = G.main(["--root", str(tmp_path), "--prefix", "snap-", "--keep", "1",
                 "--min-age-days", "7"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    acts = {Path(i["path"]).name: i["action"] for i in out["items"]}
    assert acts == {"snap-v1": "delete", "snap-v2": "delete", "snap-v3": "keep"}
    assert out["removed"] == []  # 默认 dry-run


def test_apply_deletes_only_stale(tmp_path):
    _mk(tmp_path, "snap-v1", 30)
    _mk(tmp_path, "snap-v2", 20)
    _mk(tmp_path, "snap-v3", 0.1)
    assert G.main(["--root", str(tmp_path), "--prefix", "snap-", "--keep", "1",
                   "--min-age-days", "7", "--apply"]) == 0
    left = sorted(p.name for p in tmp_path.iterdir())
    assert left == ["snap-v3"]


def test_keep_two_protects_recent(tmp_path, capsys):
    _mk(tmp_path, "snap-a", 40)
    _mk(tmp_path, "snap-b", 30)
    _mk(tmp_path, "snap-c", 0.1)
    G.main(["--root", str(tmp_path), "--prefix", "snap-", "--keep", "2",
            "--min-age-days", "7"])
    out = json.loads(capsys.readouterr().out)
    acts = {Path(i["path"]).name: i["action"] for i in out["items"]}
    assert acts["snap-c"] == "keep" and acts["snap-b"] == "keep"
    assert acts["snap-a"] == "delete"


def test_bad_root_exit_2(tmp_path, capsys):
    assert G.main(["--root", str(tmp_path / "nope")]) == 2


def test_non_matching_dirs_untouched(tmp_path):
    _mk(tmp_path, "other-dir", 100)
    _mk(tmp_path, "snap-x", 100)
    G.main(["--root", str(tmp_path), "--prefix", "snap-", "--keep", "1",
            "--min-age-days", "7", "--apply"])
    assert (tmp_path / "other-dir").is_dir()

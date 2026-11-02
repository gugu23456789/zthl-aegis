"""Test gk_git_concurrency_check.py — git 并发抢锁检测（2026-08-15 追加交叉审查项）"""
import sys
import time
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent))

import gk_git_concurrency_check as gcc


def test_parse_ref_date_with_offset():
    """+0800 无冒号偏移格式（reflog --date=iso 输出）必须可解析。"""
    dt = gcc._parse_ref_date("2026-08-15 12:15:24 +0800")
    assert dt.year == 2026 and dt.month == 8 and dt.hour == 12


def test_stuck_lock_detected(tmp_path):
    """>10 分钟未消失的 .git/*.lock = stuck，必须检出。"""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    lock = git_dir / "index.lock"
    lock.write_text("")
    old = time.time() - 3600  # 1 小时前
    import os
    os.utime(lock, (old, old))
    res = gcc.check_stuck_locks(str(tmp_path))
    assert res["status"] == "warn"
    assert res["stuck_locks"][0]["name"] == "index.lock"


def test_fresh_lock_not_stuck(tmp_path):
    """新锁文件（正常生命周期内）不应报 stuck。"""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "index.lock").write_text("")
    res = gcc.check_stuck_locks(str(tmp_path))
    assert res["status"] == "ok"


def test_windows_git_trace_detected(tmp_path):
    """vscode-merge-base = VS Code git 集成痕迹，必须检出。"""
    import subprocess
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "branch.master.vscode-merge-base", "origin/master"], check=True)
    res = gcc.check_windows_git_trace(str(tmp_path))
    assert res["status"] == "warn"
    assert any("vscode-merge-base" in t for t in res["trace"])


def test_dense_commit_detected(monkeypatch):
    """近窗口内 >6 commit 且间隔 <30s = 密集提交（并发高风险）。"""
    base = time.time()
    # 构造 8 个 commit，间隔 10s（密集）
    lines = ""
    for i in range(8):
        ts = time.strftime("%Y-%m-%d %H:%M:%S +0800", time.localtime(base - i * 10))
        lines += f"abc{i} HEAD@{{{ts}}}: commit: fix#{i}\n"
    monkeypatch.setattr(gcc, "_git", lambda repo, *a, **k: (0, lines, ""))
    res = gcc.check_dense_commit("/fake/repo")
    assert res["status"] == "warn"
    assert res["dense"] is True


def test_sparse_commits_ok(monkeypatch):
    """窗口内 commit 少（≤6）= 非密集。"""
    base = time.time()
    lines = ""
    for i in range(3):
        ts = time.strftime("%Y-%m-%d %H:%M:%S +0800", time.localtime(base - i * 600))
        lines += f"abc{i} HEAD@{{{ts}}}: commit: fix#{i}\n"
    monkeypatch.setattr(gcc, "_git", lambda repo, *a, **k: (0, lines, ""))
    res = gcc.check_dense_commit("/fake/repo")
    assert res["status"] == "ok"


def test_repo_healthy_detects_bad_head(monkeypatch):
    """HEAD 不可解析 = 仓库不健康。"""
    monkeypatch.setattr(gcc, "_git", lambda repo, *a, **k: (1, "", "fatal: bad HEAD"))
    res = gcc.check_repo_healthy("/fake/repo")
    assert res["status"] == "warn"

#!/usr/bin/env python3
"""gk_commit_size_guard 单测（2026-11-10，红先）。

契约：
- 默认 `warn`：只产出 `warnings`，不阻断（`ok` 仍为 true）
- `off`：完全静默
- `block`：超判据 ⟹ `ok:false` + `error:COMMIT_TOO_LARGE` + rc=1
- 判据 = **主题混合度（模块数）+ 可配阈值**（文件数/行数），env 可调
- 拆分建议**不绑定 git-workflow**：只有 `git-workflow` 在 PATH 里才提 stage-pick
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import gk_commit_size_guard as G  # noqa: E402


def _repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    subprocess.run(["git", "init", "-q", str(r)], check=True)
    for d in ("scripts", "references", "docs"):
        (r / d).mkdir()
    return r


def _stage(repo, rel, body="x\n" * 5):
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", rel], check=True)


def _out(capsys):
    return json.loads(capsys.readouterr().out.strip().splitlines()[-1])


def test_small_commit_is_clean(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("GK_COMMIT_GUARD", raising=False)
    r = _repo(tmp_path)
    _stage(r, "scripts/a.py")
    assert G.main(["--repo", str(r)]) == 0
    d = _out(capsys)
    assert d["warnings"] == [] and d["ok"] is True
    assert d["modules"] == ["scripts"]


def test_three_modules_warn_but_do_not_block(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("GK_COMMIT_GUARD", raising=False)
    r = _repo(tmp_path)
    for rel in ("scripts/a.py", "references/b.md", "docs/c.md"):
        _stage(r, rel)
    assert G.main(["--repo", str(r)]) == 0
    d = _out(capsys)
    assert d["ok"] is True
    assert d["warnings"] and d["warnings"][0]["id"] == "COMMIT_TOO_LARGE"
    assert sorted(d["modules"]) == ["docs", "references", "scripts"]


def test_file_threshold_env_override(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("GK_COMMIT_GUARD_FILES", "1")
    r = _repo(tmp_path)
    _stage(r, "scripts/a.py")
    _stage(r, "scripts/b.py")
    assert G.main(["--repo", str(r)]) == 0
    assert _out(capsys)["warnings"]


def test_line_threshold_env_override(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("GK_COMMIT_GUARD_LINES", "5")
    r = _repo(tmp_path)
    _stage(r, "scripts/big.py", body="y\n" * 40)
    assert G.main(["--repo", str(r)]) == 0
    assert _out(capsys)["warnings"]


def test_off_mode_silences(tmp_path, capsys, monkeypatch):
    r = _repo(tmp_path)
    for rel in ("scripts/a.py", "references/b.md", "docs/c.md"):
        _stage(r, rel)
    assert G.main(["--repo", str(r), "--mode", "off"]) == 0
    d = _out(capsys)
    assert d["warnings"] == [] and d["ok"] is True


def test_block_mode_returns_error(tmp_path, capsys, monkeypatch):
    r = _repo(tmp_path)
    for rel in ("scripts/a.py", "references/b.md", "docs/c.md"):
        _stage(r, rel)
    assert G.main(["--repo", str(r), "--mode", "block"]) == 1
    d = _out(capsys)
    assert d["ok"] is False and d["error"] == "COMMIT_TOO_LARGE"


def test_suggest_mentions_tool_only_when_installed(tmp_path, capsys, monkeypatch):
    r = _repo(tmp_path)
    for rel in ("scripts/a.py", "references/b.md", "docs/c.md"):
        _stage(r, rel)
    monkeypatch.setattr(G.shutil, "which", lambda _n: None)
    G.main(["--repo", str(r)])
    assert "git-workflow" not in _out(capsys)["warnings"][0]["suggest"]
    monkeypatch.setattr(G.shutil, "which", lambda _n: "/usr/bin/git-workflow")
    G.main(["--repo", str(r)])
    assert "git-workflow" in _out(capsys)["warnings"][0]["suggest"]


def test_missing_repo_fails_loud(capsys):
    assert G.main(["--repo", "/nonexistent/repo/xyz"]) == 2
    d = _out(capsys)
    assert d["ok"] is False and "repo" in d["error"].lower()

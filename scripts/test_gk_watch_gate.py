#!/usr/bin/env python3
"""Gate R0.15（蓝鳍瞭望观测准入）红先臂（2026-11-01）。

要求：
  1. 默认只放「本侧 + 脱敏」；
  2. `--reveal`（回显身份字面量全文）⟹ 拒，除非 `GK_WATCH_APPROVED=1`；
  3. `--cross-side`（观测另一侧目录）⟹ 拒，除非显式批准；
  4. 非观测命令 ⟹ `matched=False`（不误伤）；
  5. allow/deny 都落访客记录（身份面齐全：user/host/pid/agent_id）。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pre_tool_hook as H  # noqa: E402


def test_plain_watch_is_allowed(monkeypatch):
    monkeypatch.delenv(H.WATCH_APPROVE_ENV, raising=False)
    g = H._watch_gate("bash gatekeeper-cli.sh state --watch --hours 6")
    assert g["matched"] and g["allow"] and g["scope"] == "own", g


def test_reveal_denied_without_approval(monkeypatch):
    monkeypatch.delenv(H.WATCH_APPROVE_ENV, raising=False)
    g = H._watch_gate("python scripts/gk_watch.py --reveal")
    assert g["matched"] and not g["allow"] and "GK_WATCH_APPROVED" in g["reason"], g


def test_cross_side_denied_without_approval(monkeypatch):
    monkeypatch.delenv(H.WATCH_APPROVE_ENV, raising=False)
    g = H._watch_gate("python scripts/gk_watch.py --cross-side")
    assert g["matched"] and not g["allow"] and g["scope"] == "cross-side", g


def test_approved_allows_cross_boundary(monkeypatch):
    monkeypatch.setenv(H.WATCH_APPROVE_ENV, "1")
    g = H._watch_gate("python scripts/gk_watch.py --cross-side --reveal")
    assert g["matched"] and g["allow"], g


def test_non_watch_command_not_matched():
    assert H._watch_gate("git status --short")["matched"] is False
    assert H._watch_gate("")["matched"] is False


def test_visit_record_has_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("GK_SKILL_DIR", str(tmp_path))
    H._CALL_CMD = "python gk_watch.py --cross-side"
    H._record_watch_visit({"allow": False, "reason": "WATCH_GATE: test",
                           "scope": "cross-side", "reveal": False}, str(tmp_path))
    lines = (tmp_path / ".gatekeeper.state.watch-log.jsonl").read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[-1])
    assert rec["event"] == "observe-hook" and rec["decision"] == "deny"
    assert rec["scope"] == "cross-side"
    for k in ("ts", "user", "host", "pid", "agent_id", "cmd", "cwd"):
        assert k in rec, k


def test_visit_log_falls_back_to_skill_dir_not_cwd(tmp_path, monkeypatch):
    """无 `GK_SKILL_DIR` 时落**技能目录**，不落 hook 的 cwd。

    落 cwd 会：① 与 CLI 侧（`--skill-dir SKILL_DIR`）分叉成两份日志；
    ② 把 host/user 记录泼到无关仓库；③ cwd 只读时 `except OSError` 静默丢记录。
    """
    monkeypatch.delenv("GK_SKILL_DIR", raising=False)
    monkeypatch.setattr(H, "SKILL_DIR", tmp_path)
    other_cwd = tmp_path / "some-project"
    other_cwd.mkdir()
    H._record_watch_visit({"allow": True, "reason": "own-scope masked",
                           "scope": "own", "reveal": False}, str(other_cwd))
    assert (tmp_path / ".gatekeeper.state.watch-log.jsonl").is_file()
    assert not (other_cwd / ".gatekeeper.state.watch-log.jsonl").exists()
    assert H._watch_log_path() == str(tmp_path / ".gatekeeper.state.watch-log.jsonl")

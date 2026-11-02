"""F7 基座：edit 四道闸 + 原子写（red-first）。子进程门禁以 stub 注入。"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_agent_edit as ae

FAM = {
    "allowed_paths": ["gatekeeper-cli.sh", "scripts/gk_"],
    "forbidden_paths": ["docs/"],
}


@pytest.fixture()
def wt(tmp_path):
    d = tmp_path / "wt"
    (d / "scripts").mkdir(parents=True)
    (d / "gatekeeper-cli.sh").write_text("L1\nL2\n", encoding="utf-8")
    (d / "scripts" / "gk_x.py").write_text("a=1\n", encoding="utf-8")
    (d / "docs").mkdir()
    (d / "docs" / "p.md").write_text("d\n", encoding="utf-8")
    return str(d)


def _gates_ok(monkeypatch):
    monkeypatch.setattr(ae, "_cli_gate_ok", lambda *a, **k: (True, ""))


def test_happy_path_replaces_and_is_atomic(wt, monkeypatch):
    _gates_ok(monkeypatch)
    r = ae.apply_edit(wt, "gatekeeper-cli.sh", "L1\n", "L1X\n", FAM, used=0, allowed=3)
    assert r["ok"] is True
    assert open(os.path.join(wt, "gatekeeper-cli.sh"), encoding="utf-8").read() == "L1X\nL2\n"


def test_guard_edit_block_stops_before_write(wt, monkeypatch):
    monkeypatch.setattr(ae, "_cli_gate_ok", lambda *a, **k: (False, "PROTECTED_REGION"))
    r = ae.apply_edit(wt, "gatekeeper-cli.sh", "L1\n", "L1X\n", FAM, used=0, allowed=3)
    assert r["ok"] is False and "guard-edit" in r["blocked_by"]
    assert open(os.path.join(wt, "gatekeeper-cli.sh"), encoding="utf-8").read() == "L1\nL2\n"


def test_forbidden_path_block(wt, monkeypatch):
    _gates_ok(monkeypatch)
    r = ae.apply_edit(wt, "docs/p.md", "d\n", "d2\n", FAM, used=0, allowed=3)
    assert r["ok"] is False and r["blocked_by"] == "forbidden_paths"


def test_outside_allowed_paths_block(wt, monkeypatch):
    _gates_ok(monkeypatch)
    r = ae.apply_edit(wt, "other.txt", "x", "y", FAM, used=0, allowed=3)
    assert r["ok"] is False and r["blocked_by"] == "allowed_paths"


def test_quota_exhausted_blocks(wt, monkeypatch):
    _gates_ok(monkeypatch)
    r = ae.apply_edit(wt, "gatekeeper-cli.sh", "L1\n", "L1X\n", FAM, used=3, allowed=3)
    assert r["ok"] is False and r["blocked_by"] == "edit_quota"


def test_old_str_not_found_fails_loud(wt, monkeypatch):
    _gates_ok(monkeypatch)
    r = ae.apply_edit(wt, "gatekeeper-cli.sh", "NOPE\n", "X\n", FAM, used=0, allowed=3)
    assert r["ok"] is False and r["blocked_by"] == "old_str_not_found"


def test_path_traversal_block(wt, monkeypatch):
    _gates_ok(monkeypatch)
    r = ae.apply_edit(wt, "scripts/../../etc/passwd", "a", "b", FAM, used=0, allowed=3)
    assert r["ok"] is False and r["blocked_by"] in ("path_escape", "allowed_paths")


# ─── T6：per-agent 配额（口径乙 + 零落盘派生量）───────────────────────────
def _git_init(d):
    import subprocess
    subprocess.run(["git", "-C", d, "init", "-q", "-b", "main"], check=True)
    subprocess.run(["git", "-C", d, "add", "-A"], check=True)
    subprocess.run(["git", "-C", d, "-c", "user.email=t@t", "-c", "user.name=t",
                    "commit", "-qm", "base"], check=True)
    return subprocess.run(["git", "-C", d, "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()


def test_agent_used_counts_changed_lines_only(wt):
    base = _git_init(wt)
    p = os.path.join(wt, "gatekeeper-cli.sh")
    with open(p, "a", encoding="utf-8") as f:
        f.write("L3\nL4\n")
    assert ae.agent_used(wt, base) == 2


def test_agent_used_zero_before_any_edit(wt):
    base = _git_init(wt)
    assert ae.agent_used(wt, base) == 0


def test_agent_used_ignores_untracked_noise(wt):
    base = _git_init(wt)
    with open(os.path.join(wt, "gatekeeper-cli.sh"), "a", encoding="utf-8") as f:
        f.write("X\n")
    with open(os.path.join(wt, "junk.bin"), "w", encoding="utf-8") as f:
        f.write("noise")
    assert ae.agent_used(wt, base) == 1  # junk.bin 未跟踪 → 不计


def test_record_agent_finish_patches_one_row(monkeypatch):
    calls = []

    def _fake_patch(frag):
        calls.append(frag)
        return {"ok": True}

    monkeypatch.setattr(ae, "_state_patch", _fake_patch)
    ae.record_agent_finish("F3-state-write-integrity#ECC-X", "/tmp/wt", 3, 2, "done")
    assert len(calls) == 1
    assert "agents" in calls[0] and "F3-state-write-integrity#ECC-X" in calls[0]
    assert "used" in calls[0]


def test_record_agent_finish_appends_not_replaces(tmp_path, monkeypatch):
    """负臂：连续两次留痕必须追加（防「顶层键整体替换」丢历史）。"""
    import json as _json
    state = {"gate_data": {"edit_budget": {"agents": []}}}

    def _patch(frag):
        _key, _, val = frag.partition(":")
        cur = state["gate_data"]["edit_budget"]["agents"]
        state["gate_data"]["edit_budget"]["agents"] = (cur + _json.loads(val))[-ae.AGENTS_CAP:]
        return {"ok": True}

    monkeypatch.setattr(ae, "_state_patch", _patch)
    ae.record_agent_finish("F#A", "/wt/a", 3, 1, "done")
    ae.record_agent_finish("F#B", "/wt/b", 3, 2, "done")
    assert len(state["gate_data"]["edit_budget"]["agents"]) == 2

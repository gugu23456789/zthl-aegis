#!/usr/bin/env python3
"""红先臂：OVERWRITE_EXISTING_FILE —— 已存在文件的「整体写」须 BLOCK（用户裁定 2026-10-09）。

缺陷（本批修）：写闸（`pre_tool_hook` Gate4 → CLI `pre-tool-check` → `gk_edit_gate`）把
**所有写动词一视同仁**（F-REV-45 只做**工具名**归一），从不区分「整体覆盖」
（`Write`/`CreateFile` 打在**已存在**文件）与「带锚局部改」（`Edit`/`SearchReplace`）
⟹ IDE 的 `Write` 可**整文件覆盖**已存在文件，绕过 `gk_agent_edit.apply_edit` 的
「`old_str` 非空且必命中」局部-only 纪律。

本批判据（单一实现 = `gk_edit_gate.evaluate`，两消费点同源）：
  归一后工具 ∈ {write, createfile} ∧ 目标**已存在** ⟹ BLOCK `OVERWRITE_EXISTING_FILE`；
  显式逃生舱 `GK_OVERWRITE_OK=1` 放行；`tool` 缺省 ""（旧调用方 / guard-edit 面）**行为不变**。

红先：本批前 `evaluate()` 无 `tool` 参数、无该判据 ⟹ 下列正臂必红（`TypeError` / `allow`）。
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
CLI = SCRIPTS.parent / "gatekeeper-cli.sh"
sys.path.insert(0, str(SCRIPTS))

import gk_edit_gate as G  # noqa: E402 — 红先：本模块先于实现存在


def _state(tmp_path, worktree):
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({
        "stage": "ECO-EDIT", "r_phase": "R1",
        "worktree": str(worktree), "worktrees_extra": [],
        "gate_data": {"project_type": "standard",
                      "edit_budget": {"max": 99, "used": 0, "remaining": 99}}},
        ensure_ascii=False), encoding="utf-8", newline="\n")
    return str(st)


@pytest.fixture()
def sandbox(tmp_path, monkeypatch):
    wt = tmp_path / "wt"
    wt.mkdir()
    monkeypatch.delenv("GK_OVERWRITE_OK", raising=False)
    monkeypatch.delenv("GK_BUDGET_OVERRIDE", raising=False)
    return wt, _state(tmp_path, wt)


def _existing(wt):
    f = wt / "a.py"
    f.write_text("x", encoding="utf-8")
    return str(f)


class TestOverwriteGuard:
    def test_write_on_existing_blocks(self, sandbox):
        wt, st = sandbox
        out = G.evaluate(st, _existing(wt), tool="write")
        assert out["decision"] == "block" and out["reason"] == "OVERWRITE_EXISTING_FILE", out

    def test_write_on_missing_allows_create(self, sandbox):
        wt, st = sandbox
        assert G.evaluate(st, str(wt / "new.py"), tool="write")["decision"] == "allow"

    def test_edit_and_searchreplace_unaffected(self, sandbox):
        wt, st = sandbox
        f = _existing(wt)
        assert G.evaluate(st, f, tool="edit")["decision"] == "allow"
        assert G.evaluate(st, f, tool="searchreplace")["decision"] == "allow"

    def test_createfile_semantics(self, sandbox):
        wt, st = sandbox
        assert G.evaluate(st, _existing(wt), tool="createfile")["reason"] == "OVERWRITE_EXISTING_FILE"
        assert G.evaluate(st, str(wt / "n.py"), tool="createfile")["decision"] == "allow"

    def test_deletefile_unaffected(self, sandbox):
        wt, st = sandbox
        assert G.evaluate(st, _existing(wt), tool="deletefile")["decision"] == "allow"

    def test_overwrite_ok_escape(self, sandbox, monkeypatch):
        wt, st = sandbox
        monkeypatch.setenv("GK_OVERWRITE_OK", "1")
        assert G.evaluate(st, _existing(wt), tool="write")["decision"] == "allow"

    def test_default_tool_unchanged(self, sandbox):
        wt, st = sandbox
        assert G.evaluate(st, _existing(wt))["decision"] == "allow"

    def test_uppercase_tool_normalized(self, sandbox):
        """hook 传的是 Trae 原名 `Write`（首字母大写）⟹ 本判据须自归一（对齐 F-REV-45 纪律）。"""
        wt, st = sandbox
        assert G.evaluate(st, _existing(wt), tool="Write")["reason"] == "OVERWRITE_EXISTING_FILE"


def test_cli_delegates_with_tool():
    """静态臂：`pre_tool_check` 委派 `gk_edit_gate.py check` 时必须**同载荷**传 `--tool "$_ct"`。

    判据收紧到**精确串**：首版只断 `"--tool" in src`，被 CLI 他处同名串**虚过**（本臂曾假绿）。
    """
    src = CLI.read_text(encoding="utf-8")
    assert '--tool "$_ct"' in src, (
        "pre_tool_check 未把归一工具名传给 gk_edit_gate ⟹ OVERWRITE_EXISTING_FILE 判据恒不可达")


@pytest.mark.skipif(shutil.which("bash") is None, reason="本机无 bash")
def test_e2e_pre_tool_check_write_blocks_on_existing(tmp_path):
    """端到端（hook Gate4 的真实调用形态）：`pre-tool-check Write <已存在文件>` 须 BLOCK；
    目标不存在（建新文件）须放行。"""
    wt = tmp_path / "wt"
    wt.mkdir()
    st = _state(tmp_path, wt)
    ex = _existing(wt)
    env = {**os.environ, "STATE_FILE": st, "GK_SESSION_ID": "", "GK_BUDGET_OVERRIDE": "0"}
    p = subprocess.run(["bash", str(CLI), "pre-tool-check", "Write", ex],
                       capture_output=True, text=True, timeout=180, env=env)
    assert "禁止整体覆盖" in p.stdout, (p.returncode, p.stdout, p.stderr)
    p2 = subprocess.run(["bash", str(CLI), "pre-tool-check", "Write", str(wt / "brand_new.py")],
                        capture_output=True, text=True, timeout=180, env=env)
    assert p2.returncode == 0, (p2.returncode, p2.stdout, p2.stderr)

#!/usr/bin/env python3
"""红先测试：ECC-32C6F93A9FFB —— apply_edit 建新文件语义。

运行前置（2026-10-29 去环境依赖）：`apply_edit` 内部走真实 CLI 闸（guard-edit /
pre-tool-check），按该 state 的 worktree 判含并计费 ⟹ 夹具**自建**沙箱 worktree + 域化 state
（`stage=STAGE_0` / `worktree=沙箱根` / 预算 8），显式 `STATE_FILE` 注入（CLI 启动块里显式 state
优先于主树归一）。原实现用模块级 `pytestmark.skipif(not ambient STATE_FILE)` ⟹ 无 ambient state
的机器上 4 臂**恒 skip**（存量跳过，非环境不可满足）。
"""
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest

import gk_agent_edit as ae  # noqa: E402

SANDBOX = "edit_create_test"
FAM = {"family": "T", "forbidden_paths": ["forbidden/"],
       "allowed_paths": [f"{SANDBOX}/new_ok.py", f"{SANDBOX}/exists_edit.py"]}


@pytest.fixture
def wt(tmp_path, monkeypatch):
    """沙箱 worktree + 显式 STATE_FILE（`apply_edit` 的闸①③ 会真跑 CLI）。"""
    d = (tmp_path / "wt").resolve()
    d.mkdir()
    st = d / ".gatekeeper.state"
    st.write_text(json.dumps({
        "stage": "STAGE_0", "r_phase": "R1", "worktree": str(d),
        "gate_data": {"project_type": "standing",
                      "edit_budget": {"max": 8, "used": 0, "remaining": 8}},
    }, ensure_ascii=False), encoding="utf-8", newline="\n")
    monkeypatch.setenv("STATE_FILE", str(st))
    return d


@pytest.fixture
def sandbox(wt):
    d = wt / SANDBOX
    d.mkdir(parents=True, exist_ok=True)
    yield d
    shutil.rmtree(d, ignore_errors=True)


def _rel(name: str) -> str:
    return f"{SANDBOX}/{name}"


def test_create_on_missing(sandbox, wt):
    r = ae.apply_edit(str(wt), _rel("new_ok.py"), "", "hello\n", FAM, used=0, allowed=5)
    assert r["ok"] is True, r
    assert (sandbox / "new_ok.py").read_text(encoding="utf-8") == "hello\n"


def test_reject_empty_oldstr_on_existing(sandbox, wt):
    (sandbox / "exists_edit.py").write_text("orig\n", encoding="utf-8")
    r = ae.apply_edit(str(wt), _rel("exists_edit.py"), "", "x\n", FAM, used=0, allowed=5)
    assert r["ok"] is False and r["blocked_by"] == "old_str_empty_existing", r
    assert (sandbox / "exists_edit.py").read_text(encoding="utf-8") == "orig\n"


def test_replace_still_works(sandbox, wt):
    (sandbox / "exists_edit.py").write_text("orig\n", encoding="utf-8")
    r = ae.apply_edit(str(wt), _rel("exists_edit.py"), "orig", "changed", FAM, used=0, allowed=5)
    assert r["ok"] is True, r
    assert (sandbox / "exists_edit.py").read_text(encoding="utf-8") == "changed\n"


def test_escape_still_blocked(wt):
    r = ae.apply_edit(str(wt), "../escape.py", "", "x", FAM, used=0, allowed=5)
    assert r["ok"] is False and r["blocked_by"] == "path_escape", r

#!/usr/bin/env python3
"""红先臂：#39 state 归属一致性 + **可选修复**（2026-11-01）。

病象（实测日志）：主树种子 state 复制进 worktree 后**顶层 `worktree`** 仍指向主树 ⟹ 启动期
归属扫描（`gk_state_route._load_worktree` 投影顶层 `worktree/r_phase/stage`）判 conflict，把
expected 纠正到主树 state（当时 active-r = R7 ⟹ `.gatekeeper.state.gatekeeper.r7`）⟹ 域路由拿
r7 state 解析新计划域必然 `MISMATCH`。

判据：
  1. `state["worktree"]` == 当前工作树（realpath）⟹ PASS；
  2. 不一致 ⟹ **WARN 且零写盘**（默认只报）；
  3. `GK_SELFCHECK_REPAIR_WORKTREE=1` ⟹ 原地改写 + 重算 checksum ⟹ PASS(repaired)；
  4. 缺字段 ⟹ WARN（给修复指引）；state 缺失 ⟹ SKIP；
  5. **防自证**：检查读取的字段必须与 `gk_state_route._load_worktree` 一致（扫描读什么，检查读什么）；
     `proj.worktree` 是**错**字段（该投影只读顶层），不得被本检查当作归属；
  6. `run_all` 必须挂载第 39 项（防「函数在但没接线」）。
"""
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import gk_self_check as SC  # noqa: E402
import gk_state_route as SR  # noqa: E402


def _mk(tmp_path, worktree=None, name=".gatekeeper.state", proj_stray=None):
    p = tmp_path / name
    d = {"gate_data": {"x": 1}}
    if worktree is not None:
        d["worktree"] = worktree
    if proj_stray is not None:
        d["proj"] = {"worktree": proj_stray}
    p.write_text(json.dumps(d), encoding="utf-8")
    return str(p)


def _checksum_ok(sf):
    d = json.loads(Path(sf).read_text(encoding="utf-8"))
    want = hashlib.sha256(json.dumps(d.get("gate_data", {}), sort_keys=True).encode()).hexdigest()[:16]
    return d.get("_checksum") == want


def test_equal_worktree_is_pass(tmp_path):
    sf = _mk(tmp_path, str(tmp_path))
    r = SC.check_state_ownership(sf, str(tmp_path))
    assert r["status"] == "PASS", r


def test_mismatch_is_warn_and_zero_write(tmp_path, monkeypatch):
    monkeypatch.delenv("GK_SELFCHECK_REPAIR_WORKTREE", raising=False)
    sf = _mk(tmp_path, "<home>/.trae/skills/spz-gatekeeper-r-sequence")
    before = Path(sf).read_bytes()
    r = SC.check_state_ownership(sf, str(tmp_path))
    assert r["status"] == "WARN" and "不一致" in r["detail"], r
    assert Path(sf).read_bytes() == before, "默认只报不写"


def test_repair_rewrites_top_level_field_and_checksum(tmp_path, monkeypatch):
    monkeypatch.setenv("GK_SELFCHECK_REPAIR_WORKTREE", "1")
    sf = _mk(tmp_path, "/old/main/tree")
    r = SC.check_state_ownership(sf, str(tmp_path))
    assert r["status"] == "PASS" and r.get("repaired") is True, r
    d = json.loads(Path(sf).read_text(encoding="utf-8"))
    assert os.path.realpath(d["worktree"]) == os.path.realpath(str(tmp_path)), d.get("worktree")
    assert _checksum_ok(sf), "修复后 checksum 必须同步"


def test_wrong_field_proj_is_not_ownership(tmp_path, monkeypatch):
    """防自证：只写 `proj.worktree`（扫描不读）必须判 WARN，而不是 PASS。"""
    monkeypatch.delenv("GK_SELFCHECK_REPAIR_WORKTREE", raising=False)
    sf = _mk(tmp_path, None, proj_stray=str(tmp_path))
    r = SC.check_state_ownership(sf, str(tmp_path))
    assert r["status"] == "WARN" and "缺顶层 worktree" in r["detail"], r


def test_check_reads_same_field_as_router(tmp_path):
    """字段单源：检查读到的值 == `gk_state_route._load_worktree` 读到的值。"""
    sf = _mk(tmp_path, "/some/tree")
    r = SC.check_state_ownership(sf, str(tmp_path))
    assert r["data"]["state_worktree"] == SR._load_worktree(sf)


def test_cross_os_path_forms_are_equal():
    """跨平台归一：`C:\\a\\b` / `c:/a/b/` / `/mnt/c/a/b` 必须同一棵树（否则两侧互判不一致）。"""
    a = SC._canon_tree(r"<home>\x")
    b = SC._canon_tree("c:/Users/HP/x/")
    c = SC._canon_tree("<home>/x")
    assert a == b == c == "c:/users/hp/x"


def test_win_form_worktree_matches_wsl_root(tmp_path, monkeypatch):
    """Windows 形态的 `worktree` 在 WSL 侧判 PASS（不再因形态差异误报 MISMATCH）。"""
    monkeypatch.setattr(SC, "_worktree_root", lambda _d: "<home>/x")
    sf = _mk(tmp_path, "<home>/x")
    r = SC.check_state_ownership(sf, str(tmp_path))
    assert r["status"] == "PASS", r


def test_missing_state_is_skip(tmp_path):
    assert SC.check_state_ownership(str(tmp_path / "nope"), str(tmp_path))["status"] == "SKIP"


def test_run_all_mounts_ownership_check(tmp_path, monkeypatch):
    """挂载臂：run_all 聚合输出必须含 `state_ownership`（防函数在但没接线）。"""
    sf = _mk(tmp_path, str(tmp_path))
    monkeypatch.setenv("GK_SELFCHECK_TESTS", "skip")
    for name in ("check_gitnexus", "check_provider", "check_tests", "check_checksum",
                 "check_gate_data", "check_state_file", "red_meta_scan",
                 "check_python_argv_inject", "check_egress_chain",
                 "check_bridge_import_safety"):
        if hasattr(SC, name):
            monkeypatch.setattr(SC, name, lambda *a, **k: {"check": name, "status": "PASS"})
    out = SC.run_all(sf, str(tmp_path))
    assert any(c.get("check") == "state_ownership" for c in out["checks"]), \
        [c.get("check") for c in out["checks"]]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))

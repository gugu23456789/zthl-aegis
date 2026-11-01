#!/usr/bin/env python3
"""test_gk_subagent_unlogged.py — 报告 ↔ 派发账本对账（A，2026-10-28）。

用户裁定：「AB 应该都做」。A = 常驻 WARN + 近期（24h）未入账 ⟹ FAIL + 历史基线冻结。
本文件把三条判据钉成可回归事实：
  ① 账本起点之前的报告**不计入**（历史不可追责）；
  ② 近期未入账 ⟹ FAIL；仅存量未入账 ⟹ WARN；基线冻结项不报；
  ③ B 的 `dispatch_tickets[].report_file` 与 `subagent_history[].report_file` **等价**计入已入账。
"""
import json
import os
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import gk_doc_align as DA  # noqa: E402


def _mk(skill: Path, name: str, mtime: float) -> Path:
    p = skill / "docs" / "analysis" / "subagent" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("# report %s\n" % name, encoding="utf-8")
    os.utime(p, (mtime, mtime))
    return p


def _state(skill: Path, history=None, tickets=None) -> None:
    gd = {}
    if history is not None:
        gd["subagent_history"] = history
    if tickets is not None:
        gd["dispatch_tickets"] = tickets
    (skill / ".gatekeeper.state").write_text(
        json.dumps({"gate_data": gd}, ensure_ascii=False), encoding="utf-8")


def _baseline(skill: Path, names, frozen_at=None) -> None:
    p = skill / "docs" / "analysis" / "subagent-unlogged-baseline.json"
    p.write_text(json.dumps({"frozen_at": time.time() if frozen_at is None else frozen_at,
                             "files": list(names)}, ensure_ascii=False), encoding="utf-8")


def test_no_reports_passes(tmp_path):
    r = DA.check_subagent_unlogged(str(tmp_path))
    assert r["status"] == "PASS", r


def test_old_files_before_ledger_start_are_out_of_scope(tmp_path):
    now = time.time()
    _mk(tmp_path, "logged.md", now - 3 * 86400)
    _mk(tmp_path, "ancient.md", now - 30 * 86400)      # 早于账本起点 ⟹ 不计
    _state(tmp_path, history=[{"report_file": str(tmp_path / "docs/analysis/subagent/logged.md")}])
    r = DA.check_subagent_unlogged(str(tmp_path))
    assert r["status"] == "PASS", r
    assert r["scope"] == 1, r


def test_fresh_unlogged_fails(tmp_path):
    now = time.time()
    _mk(tmp_path, "logged.md", now - 3 * 86400)
    _mk(tmp_path, "fresh.md", now - 60)                # 1 分钟前落盘、无记录
    _state(tmp_path, history=[{"report_file": str(tmp_path / "docs/analysis/subagent/logged.md")}])
    r = DA.check_subagent_unlogged(str(tmp_path))
    assert r["status"] == "FAIL" and r["fresh"] == ["fresh.md"], r


def test_stale_unlogged_warns(tmp_path):
    now = time.time()
    _mk(tmp_path, "logged.md", now - 5 * 86400)
    _mk(tmp_path, "stale.md", now - 2 * 86400)         # 48h 前，超过 fresh 窗口
    _state(tmp_path, history=[{"report_file": str(tmp_path / "docs/analysis/subagent/logged.md")}])
    r = DA.check_subagent_unlogged(str(tmp_path))
    assert r["status"] == "WARN" and r["unlogged"] == 1, r


def test_baseline_freezes_legacy(tmp_path):
    now = time.time()
    _mk(tmp_path, "logged.md", now - 5 * 86400)
    _mk(tmp_path, "stale.md", now - 2 * 86400)
    _state(tmp_path, history=[{"report_file": str(tmp_path / "docs/analysis/subagent/logged.md")}])
    _baseline(tmp_path, ["stale.md"])
    r = DA.check_subagent_unlogged(str(tmp_path))
    assert r["status"] == "PASS", r
    assert r["baselined"] == 1, r


def test_baselined_name_rewritten_after_freeze_fails(tmp_path):
    """基线只冻结**冻结时点之前**的文件：同名文件冻结后被重写，仍须 FAIL（不得拿基线洗白）。"""
    now = time.time()
    _mk(tmp_path, "logged.md", now - 10 * 86400)
    _mk(tmp_path, "stale.md", now - 60)                # 基线里有它，但它是刚写的
    _state(tmp_path, history=[{"report_file": str(tmp_path / "docs/analysis/subagent/logged.md")}])
    _baseline(tmp_path, ["stale.md"], frozen_at=now - 5 * 86400)
    r = DA.check_subagent_unlogged(str(tmp_path))
    assert r["status"] == "FAIL" and r["fresh"] == ["stale.md"], r


def test_ticket_bound_report_counts_as_logged(tmp_path):
    """B：`dispatch_tickets[].report_file` 与 history 的 `report_file` 等价。"""
    now = time.time()
    _mk(tmp_path, "logged.md", now - 3 * 86400)
    _mk(tmp_path, "fresh.md", now - 60)
    _state(tmp_path,
           history=[{"report_file": str(tmp_path / "docs/analysis/subagent/logged.md")}],
           tickets=[{"report_file": str(tmp_path / "docs/analysis/subagent/fresh.md")}])
    r = DA.check_subagent_unlogged(str(tmp_path))
    assert r["status"] == "PASS", r


def test_history_archive_jsonl_counts_as_logged(tmp_path):
    now = time.time()
    _mk(tmp_path, "logged.md", now - 3 * 86400)
    _mk(tmp_path, "fresh.md", now - 60)
    _state(tmp_path, history=[{"report_file": str(tmp_path / "docs/analysis/subagent/logged.md")}])
    (tmp_path / ".gatekeeper.state.history-archive.jsonl").write_text(
        json.dumps({"report_file": str(tmp_path / "docs/analysis/subagent/fresh.md")}) + "\n",
        encoding="utf-8")
    r = DA.check_subagent_unlogged(str(tmp_path))
    assert r["status"] == "PASS", r


def test_ledger_without_valid_pointers_warns(tmp_path):
    _mk(tmp_path, "fresh.md", time.time())
    _state(tmp_path, history=[{"report_file": str(tmp_path / "gone.md")}])
    r = DA.check_subagent_unlogged(str(tmp_path))
    assert r["status"] == "WARN" and "无法对账" in r["detail"], r


def test_state_roots_covers_main_worktree():
    """linked worktree 兜底：主树 state 必须进账本读取根（否则 worktree 内对账恒红）。"""
    sk = str(HERE.parent)
    roots = DA._state_roots(sk)
    assert Path(sk).resolve() in [r.resolve() for r in roots]
    assert any((r / ".gatekeeper.state").exists() for r in roots) or len(roots) == 1, roots


def test_ledger_aggregates_multiple_roots(tmp_path, monkeypatch):
    a = tmp_path / "wt"
    b = tmp_path / "main"
    for d, name in ((a, "x.md"), (b, "y.md")):
        d.mkdir()
        rep = d / name
        rep.write_text("r", encoding="utf-8")
        (d / ".gatekeeper.state").write_text(json.dumps(
            {"gate_data": {"subagent_history": [{"report_file": str(rep)}]}}), encoding="utf-8")
    monkeypatch.setattr(DA, "_state_roots", lambda _sk: [a, b])
    names, mtimes = DA._subagent_ledger(str(a))
    assert {"x.md", "y.md"} <= names and len(mtimes) == 2, (names, mtimes)


def test_fresh_window_is_configurable(tmp_path):
    now = time.time()
    _mk(tmp_path, "logged.md", now - 5 * 86400)
    _mk(tmp_path, "x.md", now - 3 * 3600)              # 3h 前
    _state(tmp_path, history=[{"report_file": str(tmp_path / "docs/analysis/subagent/logged.md")}])
    assert DA.check_subagent_unlogged(str(tmp_path))["status"] == "FAIL"
    assert DA.check_subagent_unlogged(str(tmp_path), fresh_h=1)["status"] == "WARN"

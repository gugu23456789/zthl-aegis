#!/usr/bin/env python3
"""G12 ②（2026-11-15）：AUDIT 相位失败态留痕 + AUDIT-REPORT 可达性。

原实现（`gk_advance._audit_order`）：进入相位即 append `audit_phases_completed`
⟹ 审计执行失败（结果缺失 / error / `ok:false`）也记成 completed，`AUDIT-REPORT`
仍可达且失败无留痕（审计署计划 §23.3 D7-B ③）。

现判据：
  · 执行失败 ⟹ `audit_phase_failures` 有该相位，completed **不含**它；
  · 成功重入 ⟹ completed 追加，failures 清除（可修复、不锁死）；
  · `AUDIT-REPORT` ⟹ required 全 completed 且无失败记录；
  · 旧 state（只有 completed、无 failures）⟹ 原样放行（向后兼容）。

红先性：本文件在修复前 `phase_failed` 字段不存在、失败相位仍进 completed ⟹ 前 3 臂必红。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from gk_advance import _audit_order  # noqa: E402


def _d(result=None, phases=None, failures=None):
    d = {"gate_data": {}, "audit_phases_completed": list(phases or [])}
    if result is not None:
        d["gate_data"]["audit_state_result"] = result
    if failures is not None:
        d["audit_phase_failures"] = failures
    return d


def test_missing_result_records_failure_not_completed():
    """审计结果缺失（崩溃/未产出）⟹ 留痕 + 不计 completed。"""
    d = _d()
    r = _audit_order(d, "AUDIT-STATE")
    assert r.get("ok") is True and r.get("phase_failed") is True, r
    assert "AUDIT-STATE" not in d.get("audit_phases_completed", []), d
    f = d.get("audit_phase_failures") or []
    assert f and f[0]["phase"] == "AUDIT-STATE" and "result_missing" in f[0]["reason"], f
    assert f[0].get("ts"), f


def test_error_result_records_failure():
    d = _d({"error": "boom"})
    r = _audit_order(d, "AUDIT-STATE")
    assert r.get("phase_failed") is True, r
    assert "AUDIT-STATE" not in d.get("audit_phases_completed", []), d
    assert "audit_error" in d["audit_phase_failures"][0]["reason"], d


def test_heredoc_error_records_failure():
    """CLI 兜底形态 `audit_summary.heredoc_error` 也算执行失败（不是 finding）。"""
    d = _d({"state_checks": [],
            "audit_summary": {"total_fields": 0, "heredoc_error": "edge"}})
    r = _audit_order(d, "AUDIT-STATE")
    assert r.get("phase_failed") is True, r
    assert "AUDIT-STATE" not in d.get("audit_phases_completed", []), d


def test_findings_are_not_phase_failures():
    """matches < total（audit finding）不得当相位失败 —— 否则报告会被 finding 永久锁死。"""
    d = _d({"state_checks": [{"field": "x", "match": False}],
            "audit_summary": {"total_fields": 21, "matches": 20}})
    r = _audit_order(d, "AUDIT-STATE")
    assert r.get("ok") is True and not r.get("phase_failed"), r
    assert "AUDIT-STATE" in d.get("audit_phases_completed", []), d


def test_success_appends_completed_and_clears_failure():
    d = _d({"state_checks": [], "audit_summary": {"total_fields": 1, "matches": 1}},
           failures=[{"phase": "AUDIT-STATE",
                      "reason": "result_missing:audit_state_result", "ts": "x"}])
    r = _audit_order(d, "AUDIT-STATE")
    assert r.get("ok") is True and not r.get("phase_failed"), r
    assert "AUDIT-STATE" in d.get("audit_phases_completed", []), d
    assert not d.get("audit_phase_failures"), d


def test_report_blocked_by_recorded_failure():
    d = {"gate_data": {},
         "audit_phases_completed": ["AUDIT-STATE", "AUDIT-MEMORY", "AUDIT-CROSSR"],
         "audit_phase_failures": [{"phase": "AUDIT-CROSSR",
                                   "reason": "audit_error:x", "ts": "t"}]}
    r = _audit_order(d, "AUDIT-REPORT")
    assert r.get("ok") is False and "AUDIT-CROSSR" in r.get("error", ""), r


def test_legacy_state_without_failures_still_reports():
    """向后兼容：旧 state 只有 completed、无 failures ⟹ 不因新判据被锁。"""
    d = {"gate_data": {},
         "audit_phases_completed": ["AUDIT-STATE", "AUDIT-MEMORY", "AUDIT-CROSSR"]}
    assert _audit_order(d, "AUDIT-REPORT").get("ok") is True


def test_report_still_requires_all_phases():
    d = {"gate_data": {}, "audit_phases_completed": ["AUDIT-STATE"]}
    r = _audit_order(d, "AUDIT-REPORT")
    assert r.get("ok") is False and "order violation" in r.get("error", ""), r


def test_failed_phase_then_success_reenables_report():
    """失败 → 修复 → 同相位成功重入 ⟹ 可继续到 AUDIT-REPORT（不产生死路）。"""
    d = {"gate_data": {}, "audit_phases_completed": []}
    _audit_order(d, "AUDIT-STATE")  # 结果缺失 → 失败
    assert d.get("audit_phase_failures"), d
    d["gate_data"]["audit_state_result"] = {
        "state_checks": [], "audit_summary": {"total_fields": 0, "matches": 0}}
    _audit_order(d, "AUDIT-STATE")  # 成功重入
    assert "AUDIT-STATE" in d["audit_phases_completed"], d
    assert not d.get("audit_phase_failures"), d

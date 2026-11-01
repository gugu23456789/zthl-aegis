#!/usr/bin/env python3
"""
`audit --report` 签发前置判据回归臂（finding `ECC-DD4FF260119F`）。

背景：判据原**内联**在 `gatekeeper-cli.sh::cmd_audit --report`，且写死
`project_type == 'standing'` ⟹ 非 standard/standing 的新路线（`zthl-adapter`）即便五域证据
已落盘也恒被判「无证据」⟹ `audit --all` 的 report 域恒失败。现规则上收
`gk_node_guard.report_evidence_ok`（owner 令「尽量不内联 gatekeeper-cli.sh」）。

红先：`report_evidence_ok` 未落刀前本文件 import 即 `ImportError`；且第 3 臂
（zthl-adapter + 证据）在旧判据下为 False。
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gk_node_guard import report_evidence_ok  # noqa: E402

_CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def _state(pt="", evidence=(), phases=None):
    gd = {"project_type": pt}
    for k in evidence:
        gd[k] = {"ok": True}
    return {"gate_data": gd, "audit_phases_completed": phases or []}


class TestReportEvidenceOk:
    def test_standard_无相位_即便有证据也拒(self):
        """standard 路线**不影响**：仍严格要求 AUDIT-STATE 相位（不因本次放宽而漏放）。"""
        s = _state("standard", evidence=("audit_state_result", "audit_docs_result"))
        assert report_evidence_ok(s) is False

    def test_standard_有相位_放行(self):
        """standard：相位标记 **+ 两域持久化证据** 才放行（E8 2026-10-28；E2 同批收紧为 all-of）。"""
        s = _state("standard", evidence=("audit_state_result", "audit_docs_result"),
                   phases=["AUDIT-STATE"])
        assert report_evidence_ok(s) is True

    def test_standard_有相位_仅state域_拒(self):
        """E2（2026-10-28）：`audit_all_recorded` 由 `any` 收紧为 all-of（有生产者两域）
        ⟹ 只跑 `audit --state` 不再能放行 `audit --report`。"""
        s = _state("standard", evidence=("audit_state_result",), phases=["AUDIT-STATE"])
        assert report_evidence_ok(s) is False

    def test_standard_仅进入相位无证据_拒(self):
        """E8（2026-10-28，6 臂质询）：`audit_phases_completed` 在**进入**相位时即 append
        （`gk_advance.py:322-326`）⟹ 单凭它放行 = `audit --report` 前置可空过
        （`advance AUDIT-STATE` 后未真跑审计也能签发报告）。"""
        s = _state("standard", phases=["AUDIT-STATE"])
        assert report_evidence_ok(s) is False

    def test_非standard_新路线_有证据_放行(self):
        """本 finding 的核心臂：zthl-adapter（旧判据下恒 False）。"""
        s = _state("zthl-adapter", evidence=("audit_state_result", "audit_docs_result"))
        assert report_evidence_ok(s) is True

    def test_非standard_无证据_拒(self):
        s = _state("zthl-adapter")
        assert report_evidence_ok(s) is False

    def test_非standard_仅state域_拒(self):
        """E2 负臂：非 standard 路线同样不能靠单域（`audit --state`）过签发前置。"""
        s = _state("zthl-adapter", evidence=("audit_state_result",))
        assert report_evidence_ok(s) is False

    def test_standing_有证据_放行_向后兼容(self):
        s = _state("standing", evidence=("audit_state_result", "audit_docs_result"))
        assert report_evidence_ok(s) is True

    def test_历史形态_audit_result_不再采信(self):
        """E2（2026-10-28）：`audit_result` 全仓**零生产者**（仅测试构造），E1 已封三写面
        ⟹ 不再作采信面（采信它只可能来自篡改/回放）。"""
        gd = {"project_type": "zthl-adapter", "audit_result": {"ok": True}}
        assert report_evidence_ok({"gate_data": gd, "audit_phases_completed": []}) is False

    def test_畸形输入_不抛(self):
        assert report_evidence_ok(None) is False
        assert report_evidence_ok({}) is False
        assert report_evidence_ok({"gate_data": None, "audit_phases_completed": None}) is False
        assert report_evidence_ok({"gate_data": "x"}) is False


class TestCliWiring:
    """接线不变量：CLI 只**调用**、不复刻规则（防回归为内联硬编码）。"""

    def test_cli_calls_single_source(self):
        text = _CLI.read_text(encoding="utf-8", errors="replace")
        assert "from gk_node_guard import report_evidence_ok" in text, \
            "CLI 未调用 python 侧单一事实源"
        assert "report_evidence_ok(s)" in text

    def test_cli_无残留内联硬编码(self):
        text = _CLI.read_text(encoding="utf-8", errors="replace")
        assert not re.search(r"ok_std_alt\s*=\s*pt\s*==\s*'standing'", text), \
            "旧内联判据（写死 standing）残留"
        assert "audit_all_recorded(gd)" not in text, \
            "CLI 内仍在复刻五域证据判据（双轨风险）"

"""
test_gk_escalate_resolve.py -- Tests for gk_escalate_resolve.py
"""

import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent))

from gk_escalate_resolve import escalate, resolve, _detect_foreign_content


class TestForeignContent:
    def test_clean(self):
        assert _detect_foreign_content("normal text") == "clean"

    def test_foreign_user(self):
        assert "foreign_user" in _detect_foreign_content("<home>\\file")

    def test_leakage_marker(self):
        assert "leakage_marker" in _detect_foreign_content("xhs-copilot content")


class TestEscalate:
    def test_missing_gate(self):
        result = escalate(gate="", reason="test", state_path="/tmp/x")
        assert result["ok"] is False

    def test_foreign_content_blocked(self, tmp_path):
        state_file = tmp_path / "state.json"
        state = {"appeal_denied_gates": ["ECO-AUDIT"]}
        state_file.write_text(json.dumps(state))
        result = escalate("ECO-AUDIT", "xhs-copilot injected", str(state_file))
        assert result["ok"] is False
        assert "FOREIGN_CONTENT" in result["error"]

    def test_appeal_not_denied(self, tmp_path):
        state_file = tmp_path / "state.json"
        state = {"appeal_denied_gates": []}
        state_file.write_text(json.dumps(state))
        result = escalate("ECO-AUDIT", "test", str(state_file))
        assert result["ok"] is False
        assert "APPEAL_NOT_DENIED" in result["error"]

    def test_escalate_success(self, tmp_path):
        state_file = tmp_path / "state.json"
        state = {"appeal_denied_gates": ["ECO-AUDIT"], "appeal_records": {}, "gate_data": {}}
        state_file.write_text(json.dumps(state))
        result = escalate("ECO-AUDIT", "test reason", str(state_file), str(tmp_path))
        assert result["ok"] is True
        assert result["escalated"] is True
        assert "report" in result


class TestResolve:
    def test_missing_gate(self):
        result = resolve(gate="", resolution="force_advance", state_path="/tmp/x")
        assert result["ok"] is False

    def test_invalid_resolution(self, tmp_path):
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({}))
        result = resolve("ECO-AUDIT", "invalid", state_path=str(state_file))
        assert result["ok"] is False

    def test_unknown_gate(self, tmp_path):
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps({}))
        result = resolve("UNKNOWN", "force_advance", state_path=str(state_file))
        assert result["ok"] is False
        assert "Unknown gate" in result["error"]

    def test_appeal_denied_blocked(self, tmp_path):
        state_file = tmp_path / "state.json"
        state = {"appeal_denied_gates": ["ECO-AUDIT"]}
        state_file.write_text(json.dumps(state))
        result = resolve("ECO-AUDIT", "force_advance", state_path=str(state_file))
        assert result["ok"] is False
        assert "APPEAL_DENIED_PERMANENTLY" in result["error"]

    def test_appeal_required_blocked(self, tmp_path):
        state_file = tmp_path / "state.json"
        state = {"gate_data": {"appeal_required": "ECO-AUDIT"}}
        state_file.write_text(json.dumps(state))
        result = resolve("ECO-AUDIT", "force_advance", state_path=str(state_file))
        assert result["ok"] is False
        assert "APPEAL_REQUIRED_BEFORE_RESOLVE" in result["error"]

    def test_appeal_blocks_new_source_blocked(self, tmp_path):
        """X1（2026-10-31）：`appeal_blocks` 的第二阻断源同样必须拦 resolve force_advance。

        原实现直读单值 `gate_data.appeal_required` ⟹ 额度/审计源对 G-17 不可见（fail-open）。
        """
        state_file = tmp_path / "state.json"
        state = {"gate_data": {"appeal_blocks": {"credit": {"gate": "ECO-AUDIT"}}}}
        state_file.write_text(json.dumps(state))
        result = resolve("ECO-AUDIT", "force_advance", state_path=str(state_file))
        assert result["ok"] is False
        assert "APPEAL_REQUIRED_BEFORE_RESOLVE" in result["error"]
        assert "ECO-AUDIT" in result["detail"]

    def test_appeal_blocks_multi_source_lists_gates(self, tmp_path):
        state_file = tmp_path / "state.json"
        state = {"gate_data": {"appeal_blocks": {
            "entropy": {"gate": "ECO-EDIT"},
            "credit": {"gate": "ECO-AUDIT"}}}}
        state_file.write_text(json.dumps(state))
        result = resolve("ECO-AUDIT", "force_advance", state_path=str(state_file))
        assert result["ok"] is False
        assert "ECO-AUDIT" in result["detail"] and "ECO-EDIT" in result["detail"]

    def test_resolve_success(self, tmp_path):
        state_file = tmp_path / "state.json"
        state = {"appeal_records": {"ECO-AUDIT": {}}, "gate_data": {}}
        state_file.write_text(json.dumps(state))
        result = resolve("ECO-AUDIT", "force_advance", "test reason", str(state_file))
        assert result["ok"] is True
        assert result["resolution"]["resolution"] == "force_advance"

    def test_manual_fix(self, tmp_path):
        state_file = tmp_path / "state.json"
        state = {"gate_data": {}}
        state_file.write_text(json.dumps(state))
        result = resolve("ECO-EDIT", "manual_fix", "fixed manually", str(state_file))
        assert result["ok"] is True
        assert result["resolution"]["source"] == "escalate"

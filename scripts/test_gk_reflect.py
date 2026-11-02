"""
test_gk_reflect.py -- Tests for gk_reflect.py
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch


sys.path.insert(0, str(Path(__file__).parent))

from gk_reflect import reflect


class TestReflectStatic:
    def test_missing_stage(self):
        result = reflect(stage="", state_path="/tmp/x")
        assert result["ok"] is False

    def test_static_mode_no_api(self, tmp_path):
        state_file = tmp_path / "state.json"
        state = {"gate_data": {"rejected_edits": [], "best": {}, "human_calibration_log": []}}
        state_file.write_text(json.dumps(state))
        result = reflect("STAGE_0", state_path=str(state_file))
        assert result["ok"] is True
        assert result["mode"] == "static"
        assert "rejected_edits" in result

    def test_with_rejected_edits(self, tmp_path):
        state_file = tmp_path / "state.json"
        state = {
            "gate_data": {
                "rejected_edits": [{"violation": "test1"}, {"violation": "test2"}],
                "best": {"score": 0.8},
                "human_calibration_log": [{"human_score": 0.7}]
            }
        }
        state_file.write_text(json.dumps(state))
        result = reflect("STAGE_0", state_path=str(state_file))
        assert result["ok"] is True
        assert len(result["rejected_edits"]) == 2
        assert result["best"]["score"] == 0.8

    def test_cross_r_history(self, tmp_path):
        state_file = tmp_path / "state.json"
        state = {
            "gate_data": {},
            "history": [{"r_phase": "ECO-SCAN", "best": {"score": 0.9}, "rejection_count": 3}]
        }
        state_file.write_text(json.dumps(state))
        result = reflect("STAGE_0", state_path=str(state_file))
        assert result["ok"] is True


class TestReflectAPI:
    @patch("gk_reflect.requests.post")
    def test_api_mode_success(self, mock_post, tmp_path):
        state_file = tmp_path / "state.json"
        state = {"gate_data": {}}
        state_file.write_text(json.dumps(state))

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": json.dumps({
                "pattern_analysis": "test",
                "stage_ranking": "test",
                "recommendations": ["test"],
                "summary": "test"
            })}}]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        result = reflect("STAGE_0", api_key="test-key", state_path=str(state_file))
        assert result["ok"] is True
        assert result["mode"] == "api"

    @patch("gk_reflect.requests.post")
    def test_api_fallback_to_static(self, mock_post, tmp_path):
        import requests
        state_file = tmp_path / "state.json"
        state = {"gate_data": {}}
        state_file.write_text(json.dumps(state))

        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = requests.exceptions.Timeout()
        mock_post.return_value = mock_resp

        result = reflect("STAGE_0", api_key="test-key", state_path=str(state_file))
        assert result["ok"] is True
        assert result["mode"] == "static_fallback"

"""
test_replay.py -- Tests for _replay.py
=======================================
Covers: valid state with history, missing state, empty history,
        format validation (entropy_rate, timestamp, all_ok, stages, gates_count).
"""
import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent))


def _run_replay(state_file):
    """Run _replay.py as subprocess and capture output."""
    import subprocess
    result = subprocess.run(
        [sys.executable, str(Path(__file__).parent / "_replay.py"), str(state_file)],
        capture_output=True, text=True, timeout=5
    )
    return result


def _write_state(tmp_path, state, name="state.json"):
    sf = tmp_path / name
    sf.write_text(json.dumps(state, indent=2), encoding="utf-8")
    return str(sf)


class TestReplayValid:
    """Test _replay.py with valid state containing history."""

    def test_valid_history_returns_ok(self, tmp_path):
        """State with history entries should return ok=true."""
        state = {
            "r_phase": "ECO-SCAN",
            "stage": "STAGE_0",
            "gate_data": {
                "_advance_log": [
                    {"to_stage": "ECO-SCAN", "timestamp": "2026-01-01T00:00:00Z", "entropy_rate": 0.3, "all_ok": True, "gates_count": 1}
                ]
            },
            "history": [
                {"from": "IDLE", "to": "STAGE_0", "timestamp": "2026-01-01T00:00:00Z"}
            ]
        }
        sf = _write_state(tmp_path, state)
        result = _run_replay(sf)
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert output.get("ok") is True

    def test_empty_history(self, tmp_path):
        """State with empty history should still return ok."""
        state = {"r_phase": "ECO-SCAN", "stage": "STAGE_0", "gate_data": {}, "history": []}
        sf = _write_state(tmp_path, state)
        result = _run_replay(sf)
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert output.get("ok") is True


class TestReplayMissing:
    """Test _replay.py with missing/invalid state."""

    def test_missing_state_file(self, tmp_path):
        """Missing state file should return ok=false."""
        sf = str(tmp_path / "nonexistent.json")
        result = _run_replay(sf)
        assert result.returncode == 1
        output = json.loads(result.stdout)
        assert output.get("ok") is False

    def test_no_arguments(self):
        """No arguments should return ok=false."""
        import subprocess
        result = subprocess.run(
            [sys.executable, str(Path(__file__).parent / "_replay.py")],
            capture_output=True, text=True, timeout=5
        )
        assert result.returncode == 1
        output = json.loads(result.stdout)
        assert output.get("ok") is False


class TestReplayFormat:
    """Test _replay.py format validation."""

    def test_advance_log_entropy_rate(self, tmp_path):
        """advance_log with valid entropy_rate should parse correctly."""
        state = {
            "r_phase": "ECO-SCAN",
            "stage": "STAGE_0",
            "gate_data": {
                "_advance_log": [
                    {"to_stage": "ECO-SCAN", "entropy_rate": 0.5, "all_ok": True, "gates_count": 2, "timestamp": "2026-01-01T00:00:00Z"}
                ]
            },
            "history": []
        }
        sf = _write_state(tmp_path, state)
        result = _run_replay(sf)
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert output.get("ok") is True

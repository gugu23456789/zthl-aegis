"""Test gk_gate_checksum.py — tamper detection gate."""
import json
import hashlib
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent))  # 2026-08-15 环境修复: 原 `from scripts.xxx` 需 scripts 包

from gk_gate_checksum import verify_checksum


def _make_state(gate_data=None, checksum=None):
    """Build a minimal state dict."""
    d = {"r_phase": "ECO-EDIT", "stage": "ECO-EDIT", "gate_data": gate_data or {}}
    if checksum is not None:
        d["_checksum"] = checksum
    return d


def _write_state(data, path):
    with open(path, "w") as f:
        json.dump(data, f)


def test_clean_state_matches(tmp_path):
    """Clean state: checksum computed and stored correctly.
    2026-08-15 环境修复: NamedTemporaryFile 在 Windows 下句柄未关致 WinError 32 → 改 tmp_path"""
    gate_data = {"project_type": "standing", "scheduler": {"mode": "cosine", "max_lr": 4}}
    gd = json.dumps(gate_data, sort_keys=True)
    checksum = hashlib.sha256(gd.encode()).hexdigest()[:16]
    state = _make_state(gate_data, checksum)

    p = tmp_path / "state.json"
    _write_state(state, str(p))
    result = verify_checksum(str(p))

    assert "ok" in result
    assert result.get("checksum") == checksum


def test_tampered_state_blocked(tmp_path):
    """Tampered state: checksum mismatch → BLOCK."""
    gate_data = {"project_type": "standing", "scheduler": {"mode": "cosine", "max_lr": 4}}
    gd_old = json.dumps({"project_type": "standing"}, sort_keys=True)
    checksum = hashlib.sha256(gd_old.encode()).hexdigest()[:16]
    state = _make_state(gate_data, checksum)  # checksum is for old gate_data

    p = tmp_path / "state.json"
    _write_state(state, str(p))
    result = verify_checksum(str(p))

    assert "error" in result
    assert result["error"] == "STATE_FILE_TAMPERED"


def test_missing_file():
    """Missing state file → unreadable."""
    result = verify_checksum("/nonexistent/path/.gatekeeper.state")
    assert result["error"] == "STATE_FILE_UNREADABLE"

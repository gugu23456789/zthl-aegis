"""
test_gk_state.py -- Tests for gk_state.py
==========================================
4 scenarios per command:
  1. Happy path (normal operation)
  2. Edge case (boundary conditions)
  3. Error path (invalid input)
  4. Exception handling (file not found, etc.)
"""

import json
import hashlib
import sys
from pathlib import Path


# Add scripts directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from gk_state import _read_state, _write_state, _verify_checksum, _compute_checksum


class TestReadState:
    """Test _read_state function."""
    
    def test_happy_path(self, tmp_state):
        """Normal read returns state dict."""
        result = _read_state(tmp_state)
        assert "r_phase" in result
        assert result["r_phase"] == "ECO-SCAN"
        assert "_checksum_warning" not in result
    
    def test_happy_path_with_checksum(self, tmp_state_with_checksum):
        """Read with valid checksum returns no warning."""
        result = _read_state(tmp_state_with_checksum)
        assert "_checksum_warning" not in result
        assert result["_checksum"] != ""
    
    def test_tampered_checksum(self, tmp_state_tampered):
        """Read with tampered checksum sets warning."""
        result = _read_state(tmp_state_tampered)
        assert "_checksum_warning" in result
        assert "mismatch" in result["_checksum_warning"]
    
    def test_file_not_found(self, tmp_path):
        """Read non-existent file returns error dict."""
        result = _read_state(str(tmp_path / "nonexistent.json"))
        assert "error" in result
        assert result["error"] == "state_file_not_found"
    
    def test_invalid_json(self, tmp_path):
        """Read invalid JSON returns error dict."""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not valid json{{", encoding="utf-8")
        result = _read_state(str(bad_file))
        assert "error" in result
        assert result["error"] == "json_decode_error"


class TestWriteState:
    """Test _write_state function."""
    
    def test_happy_path(self, tmp_path):
        """Normal write creates file with checksum."""
        state_file = str(tmp_path / "new_state.json")
        data = {"r_phase": "ECO-SCAN", "gate_data": {"test": "value"}}
        result = _write_state(data, state_file)
        assert result["ok"] is True
        assert "checksum" in result
        
        # Verify file exists
        assert Path(state_file).exists()
        
        # Verify checksum is correct
        with open(state_file, "r", encoding="utf-8") as f:
            written = json.load(f)
        assert written["_checksum"] == result["checksum"]
    
    def test_overwrite_existing(self, tmp_state):
        """Overwrite existing state file updates checksum."""
        data = {"r_phase": "ECO-READ", "gate_data": {"new": "data"}}
        result = _write_state(data, tmp_state)
        assert result["ok"] is True
        
        # Verify new data
        with open(tmp_state, "r", encoding="utf-8") as f:
            written = json.load(f)
        assert written["r_phase"] == "ECO-READ"
        assert written["gate_data"]["new"] == "data"
    
    def test_empty_gate_data(self, tmp_path):
        """Write with empty gate_data produces valid checksum."""
        state_file = str(tmp_path / "empty.json")
        data = {"r_phase": "ECO-SCAN", "gate_data": {}}
        result = _write_state(data, state_file)
        assert result["ok"] is True
        
        # Verify checksum matches
        gate_dump = json.dumps({}, sort_keys=True, ensure_ascii=True)
        expected = hashlib.sha256(gate_dump.encode()).hexdigest()[:16]
        assert result["checksum"] == expected
    
    def test_unicode_content(self, tmp_path):
        """Write with unicode content preserves data."""
        state_file = str(tmp_path / "unicode.json")
        data = {"r_phase": "ECO-SCAN", "gate_data": {"中文": "测试"}}
        result = _write_state(data, state_file)
        assert result["ok"] is True
        
        with open(state_file, "r", encoding="utf-8") as f:
            written = json.load(f)
        assert written["gate_data"]["中文"] == "测试"


class TestVerifyChecksum:
    """Test _verify_checksum function."""
    
    def test_valid_checksum(self, tmp_state_with_checksum):
        """Valid checksum returns verified=True."""
        result = _verify_checksum(tmp_state_with_checksum)
        assert result["ok"] is True
        assert result["verified"] is True
    
    def test_tampered_checksum(self, tmp_state_tampered):
        """Tampered checksum returns verified=False."""
        result = _verify_checksum(tmp_state_tampered)
        assert result["ok"] is False
        assert result["verified"] is False
        assert result["stored"] != result["computed"]
    
    def test_no_checksum(self, tmp_state):
        """Missing checksum returns ok=True with verified="no_checksum"."""
        result = _verify_checksum(tmp_state)
        assert result["ok"] is True
        assert result["verified"] == "no_checksum"
    
    def test_file_not_found(self, tmp_path):
        """Non-existent file returns error."""
        result = _verify_checksum(str(tmp_path / "nonexistent.json"))
        assert "error" in result


class TestComputeChecksum:
    """Test _compute_checksum function."""
    
    def test_happy_path(self, tmp_state):
        """Compute checksum updates file."""
        result = _compute_checksum(tmp_state)
        assert result["ok"] is True
        assert "checksum" in result
        
        # Verify checksum was written
        with open(tmp_state, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["_checksum"] == result["checksum"]
    
    def test_idempotent(self, tmp_state_with_checksum):
        """Computing checksum twice produces same result."""
        result1 = _compute_checksum(tmp_state_with_checksum)
        result2 = _compute_checksum(tmp_state_with_checksum)
        assert result1["checksum"] == result2["checksum"]
    
    def test_file_not_found(self, tmp_path):
        """Non-existent file returns error."""
        result = _compute_checksum(str(tmp_path / "nonexistent.json"))
        assert "error" in result


class TestWriteTimestamp:
    """Test that _write_state updates last_updated timestamp."""
    
    def test_timestamp_updated(self, tmp_path):
        """Write updates last_updated in current section."""
        state_file = str(tmp_path / "ts.json")
        data = {"r_phase": "ECO-SCAN", "gate_data": {}}
        _write_state(data, state_file)
        
        with open(state_file, "r", encoding="utf-8") as f:
            written = json.load(f)
        assert "current" in written
        assert "last_updated" in written["current"]
        assert "T" in written["current"]["last_updated"]  # ISO format
    
    def test_no_gate_data_defaults(self, tmp_path):
        """Write with no gate_data key defaults to empty dict."""
        state_file = str(tmp_path / "no_gd.json")
        data = {"r_phase": "ECO-SCAN"}
        result = _write_state(data, state_file)
        assert result["ok"] is True
        
        # Verify empty gate_data checksum
        gate_dump = json.dumps({}, sort_keys=True, ensure_ascii=True)
        expected = hashlib.sha256(gate_dump.encode()).hexdigest()[:16]
        assert result["checksum"] == expected


class TestRoundTrip:
    """Test write-then-read round trip."""
    
    def test_write_read_roundtrip(self, tmp_path):
        """Write then read produces same data."""
        state_file = str(tmp_path / "rt.json")
        original = {
            "r_phase": "ECO-EDIT",
            "stage": "STAGE_2",
            "gate_data": {"key": "value", "nested": {"a": 1}}
        }
        _write_state(original, state_file)
        readback = _read_state(state_file)
        
        assert readback["r_phase"] == original["r_phase"]
        assert readback["stage"] == original["stage"]
        assert readback["gate_data"] == original["gate_data"]
        assert "_checksum_warning" not in readback
    
    def test_checksum_verified_after_write(self, tmp_path):
        """Checksum is verified after write."""
        state_file = str(tmp_path / "verify.json")
        data = {"r_phase": "ECO-SCAN", "gate_data": {"test": "value"}}
        _write_state(data, state_file)
        
        # Verify checksum
        result = _verify_checksum(state_file)
        assert result["ok"] is True
        assert result["verified"] is True
    
    def test_checksum_changes_on_write(self, tmp_path):
        """Checksum changes when gate_data changes."""
        state_file = str(tmp_path / "change.json")
        data1 = {"r_phase": "ECO-SCAN", "gate_data": {"a": 1}}
        _write_state(data1, state_file)
        checksum1 = _verify_checksum(state_file)["checksum"]
        
        data2 = {"r_phase": "ECO-SCAN", "gate_data": {"a": 2}}
        _write_state(data2, state_file)
        checksum2 = _verify_checksum(state_file)["checksum"]
        
        assert checksum1 != checksum2


class TestEdgeCases:
    """Test edge cases."""
    
    def test_empty_file(self, tmp_path):
        """Read empty file returns error."""
        empty_file = tmp_path / "empty.json"
        empty_file.write_text("", encoding="utf-8")
        result = _read_state(str(empty_file))
        assert "error" in result
        assert result["error"] == "json_decode_error"
    
    def test_large_gate_data(self, tmp_path):
        """Write with large gate_data works."""
        state_file = str(tmp_path / "large.json")
        large_data = {"key_" + str(i): "value_" + str(i) for i in range(1000)}
        data = {"r_phase": "ECO-SCAN", "gate_data": large_data}
        result = _write_state(data, state_file)
        assert result["ok"] is True
        
        # Verify readback
        readback = _read_state(state_file)
        assert readback["gate_data"] == large_data
        assert "_checksum_warning" not in readback
    
    def test_special_characters(self, tmp_path):
        """Write with special characters preserves data."""
        state_file = str(tmp_path / "special.json")
        data = {
            "r_phase": "ECO-SCAN",
            "gate_data": {
                "quote": "He said \"hello\"",
                "newline": "line1\nline2",
                "tab": "col1\tcol2",
                "backslash": "path\\to\\file"
            }
        }
        result = _write_state(data, state_file)
        assert result["ok"] is True
        
        readback = _read_state(state_file)
        assert readback["gate_data"]["quote"] == "He said \"hello\""
        assert readback["gate_data"]["newline"] == "line1\nline2"
        assert readback["gate_data"]["tab"] == "col1\tcol2"
        assert readback["gate_data"]["backslash"] == "path\\to\\file"


class TestCliGet:
    """`gk_state.py get`（2026-10-27，RED-MIGRATE-INLINE 批次 5）。

    唯一读入口 = `_read_state`（checksum 校验只加 `_checksum_warning`，**不**改输出）。
    失败面对齐旧内联 `json.load(open(STATE_FILE))`：缺文件 / 坏 JSON / 根非 dict ⟹ 默认档。
    """

    def _run(self, args, state_path=None):
        import subprocess
        av = [sys.executable, str(Path(__file__).parent / "gk_state.py"), "get"] + args
        if state_path is not None:
            av += ["--path", str(state_path)]
        return subprocess.run(av, capture_output=True, text=True, encoding="utf-8")

    def _write(self, tmp_path, obj, name="s.json"):
        p = tmp_path / name
        p.write_text(json.dumps(obj), encoding="utf-8")
        return p

    def test_plain_value(self, tmp_path):
        p = self._write(tmp_path, {"gate_data": {"last_release_check": 123}})
        r = self._run(["gate_data.last_release_check", "--default", "0"], p)
        assert r.returncode == 0 and r.stdout == "123\n", r

    def test_missing_key_uses_default(self, tmp_path):
        p = self._write(tmp_path, {"gate_data": {}})
        r = self._run(["gate_data.last_release_check", "--default", "0"], p)
        assert r.returncode == 0 and r.stdout == "0\n", r

    def test_file_not_found_uses_default(self, tmp_path):
        r = self._run(["gate_data.last_release_check", "--default", "0"],
                      tmp_path / "nope.json")
        assert r.returncode == 0 and r.stdout == "0\n", r

    def test_bad_json_uses_default_invalid(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not json", encoding="utf-8")
        r = self._run(["x", "--default", "D", "--default-invalid", "INV"], p)
        assert r.returncode == 0 and r.stdout == "INV\n", r

    def test_non_dict_root_uses_default_invalid(self, tmp_path):
        p = self._write(tmp_path, ["a"])
        r = self._run(["x", "--default", "D", "--default-invalid", "INV"], p)
        assert r.stdout == "INV\n", r

    def test_explicit_null_prints_none(self, tmp_path):
        """显式 null 不是缺键：旧 `d.get(k, 'null')` → None → `print` 出 "None"。"""
        p = self._write(tmp_path, {"gate_data": {"entropy_rate": None}})
        r = self._run(["gate_data.entropy_rate", "--default", "null"], p)
        assert r.stdout == "None\n", r

    def test_default_falsy(self, tmp_path):
        p = self._write(tmp_path, {"gate_data": {"project_type": None}})
        r = self._run(["gate_data.project_type", "--default", "",
                       "--default-falsy", ""], p)
        assert r.stdout == "\n", r
        p2 = self._write(tmp_path, {"gate_data": {"project_type": "standing"}})
        r2 = self._run(["gate_data.project_type", "--default", "",
                        "--default-falsy", ""], p2)
        assert r2.stdout == "standing\n", r2

    def test_as_yes_no(self, tmp_path):
        p = self._write(tmp_path, {"gate_data": {"human_calibration_log": []}})
        r = self._run(["gate_data.human_calibration_log", "--as", "yes:no"], p)
        assert r.returncode == 0 and r.stdout == "no\n", r
        p2 = self._write(tmp_path, {"gate_data": {"human_calibration_log": [{"a": 1}]}})
        r2 = self._run(["gate_data.human_calibration_log", "--as", "yes:no"], p2)
        assert r2.stdout == "yes\n", r2

    def test_json_compact(self, tmp_path):
        p = self._write(tmp_path, {"history": [{"a": 1}]})
        r = self._run(["history", "--json", "--default", "[]"], p)
        assert r.stdout == '[{"a": 1}]\n', r

    def test_json_indent(self, tmp_path):
        p = self._write(tmp_path, {"gate_data": {"best": {"score": 1}}})
        r = self._run(["gate_data.best", "--json", "--indent", "2"], p)
        assert r.stdout == '{\n  "score": 1\n}\n', r

    def test_json_missing_prints_default_raw(self, tmp_path):
        p = self._write(tmp_path, {"gate_data": {}})
        r = self._run(["gate_data.best", "--json", "--default", "{}"], p)
        assert r.stdout == "{}\n", r

    def test_tampered_checksum_does_not_change_output(self, tmp_path):
        p = self._write(tmp_path, {"gate_data": {"x": 1},
                                   "_checksum": "deadbeefdeadbeef"})
        r = self._run(["gate_data.x", "--default", "0"], p)
        assert r.returncode == 0 and r.stdout == "1\n", r

    def test_usage_without_path(self):
        r = self._run([])
        assert r.returncode == 2, r

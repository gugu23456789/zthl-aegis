#!/usr/bin/env python3
"""Gate: Verify state file checksum integrity (D1 BLOCK on tamper).

Usage: python3 gk_gate_checksum.py <state_file_path>
Exit: 0 if checksum matches, 1 if tampered.
Output: JSON to stdout.
"""
import json
import hashlib
import sys


def verify_checksum(state_file: str) -> dict:
    """Verify SHA256(gate_data) matches stored _checksum."""
    try:
        with open(state_file) as f:
            d = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"error": "STATE_FILE_UNREADABLE", "file": state_file}

    saved = d.get("_checksum", "")
    gd = json.dumps(d.get("gate_data", {}), sort_keys=True)
    computed = hashlib.sha256(gd.encode()).hexdigest()[:16]

    if saved and saved != computed:
        # D1: BLOCK — do NOT write state on tamper detection
        return {
            "error": "STATE_FILE_TAMPERED",
            "saved": saved,
            "computed": computed,
        }

    return {"ok": True, "checksum": computed}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: gk_gate_checksum.py <state_file>"}))
        sys.exit(1)

    result = verify_checksum(sys.argv[1])
    print(json.dumps(result))
    if "error" in result:
        sys.exit(1)

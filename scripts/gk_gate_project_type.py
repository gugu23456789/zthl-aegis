#!/usr/bin/env python3
"""Gate: Read project_type from state file.

Usage: python3 gk_gate_project_type.py <state_file>
Output: JSON with project_type to stdout. Exit 0 always.
"""
import json
import sys


def get_project_type(state_file: str) -> str:
    try:
        with open(state_file) as f:
            d = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return "standard"
    return d.get("gate_data", {}).get("project_type", "standard")


if __name__ == "__main__":
    sf = sys.argv[1] if len(sys.argv) > 1 else ""
    ptype = get_project_type(sf) if sf else "standard"
    print(ptype)

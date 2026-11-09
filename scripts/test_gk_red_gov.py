#!/usr/bin/env python3
"""RED-GOV 治理面向量回归（2026-11-09）。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import _red_attacks as R  # noqa: E402
import gk_red_vectors as V  # noqa: E402


def test_red_gov_clean_on_current_code():
    fs = R.red_gov()
    assert fs == [], [f["id"] for f in fs]


def test_red_gov_detects_missing_lock(tmp_path, monkeypatch):
    (tmp_path / "scripts").mkdir(parents=True)
    (tmp_path / "scripts/pre_tool_hook.py").write_text("", encoding="utf-8")
    (tmp_path / "scripts/gk_budget_ledger.py").write_text("", encoding="utf-8")
    monkeypatch.setattr(R, "SKILL_DIR", str(tmp_path))
    ids = {f["id"] for f in R.red_gov()}
    assert "RED-GOV-BANK-01" in ids
    assert "RED-GOV-BANK-03" in ids
    assert "RED-GOV-CONC-01" in ids
    assert "RED-GOV-PATH-01" in ids


def test_red_diff_governance_contract_clean():
    c = R.SKILL_DIR + "/references/governance-contract.json"
    fs = R.red_diff({"contract_path": c, "submit_root": R.SKILL_DIR})
    assert [f for f in fs if f.get("severity") == "high"] == [], fs


def test_red_vectors_registry_check():
    r = V.check()
    assert r["ok"] is True, r.get("errors")

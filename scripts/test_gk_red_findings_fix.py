#!/usr/bin/env python3
"""红队 C1/C3/C5 修复回归（2026-11-09）。"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_advance
import gk_budget_ledger as bl
import gk_json_utils as gu


def _bank_event(stage="ECO-EDIT", to_stage="ECO-VERIFY", outcome="blocked"):
    return {"stage": stage, "to_stage": to_stage, "source": "bank",
            "outcome": outcome, "score": 0.3, "violations": [], "timestamp": "t"}


def test_view_bank_actions_includes_journal(tmp_path):
    state = tmp_path / "state.json"
    journal = Path(str(state) + ".rejected-edits-journal.jsonl")
    journal.write_text(json.dumps(_bank_event()) + "\n", encoding="utf-8")
    out = gu.view_bank_actions({}, str(state))
    assert len(out) == 1
    assert out[0].get("journal") is True
    assert gu.view_bank_actions({}) == []


def test_bank_event_survives_cap_eviction_via_journal(tmp_path):
    state = tmp_path / "state.json"
    gd = {"rejected_edits": []}
    gk_advance._append_rejected(gd, _bank_event(), str(state))
    for i in range(gk_advance.REJECTED_CAP + 5):
        gk_advance._append_rejected(
            gd, {"stage": "S", "to_stage": "T", "source": "gates", "violations": []}, str(state))
    # live 窗口已把 bank 事件挤出；审计读面必须从 journal 找回
    live = [e for e in gd["rejected_edits"] if e.get("source") == "bank"]
    assert live == []
    out = gu.view_bank_actions(gd, str(state))
    assert any(e.get("journal") is True and e.get("stage") == "ECO-EDIT" for e in out)


def test_lock_key_normalizes_host_forms():
    # 两种拼法必须命中同一把锁（C5）
    assert gu._lock_key("C:/foo/bar") == gu._lock_key("/mnt/c/foo/bar")


def test_append_rolls_back_on_seal_failure(tmp_path, monkeypatch):
    state = tmp_path / "state.json"
    r1 = bl.append(str(state), "charge", reason="first")
    assert r1.get("ok") is True, r1
    ledger = bl._logical_path(str(state))
    seal = bl._seal_path(str(state))
    chain = bl._chain_path(seal)
    before = (ledger.read_bytes(), seal.read_bytes(), chain.read_bytes())

    def boom(*a, **k):
        return None, "seal_write_failed: boom"

    monkeypatch.setattr(bl, "_seal_with_chain", boom)
    r2 = bl.append(str(state), "charge", reason="second")
    assert r2.get("ok") is False
    assert r2.get("rolled_back") is True
    assert (ledger.read_bytes(), seal.read_bytes(), chain.read_bytes()) == before

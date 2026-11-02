#!/usr/bin/env python3
"""熵第三支（当日提额）接线回归臂（2026-10-31，owner 令「修接线缺口」）。

缺陷（实测）：`gk_advance._compute_entropy(d, stage)` 调
`compute_entropy_from_dict(d, stage)` 时**未传 `state_file`** ⟹ 第三支恒 0
（同日 2 条 raise：0.0 vs 带 state_file 0.667）；只有 bash `cmd_monitor` 的模式选择看得到。
本臂钉死：advance 侧必须吃得到同日提额条数。

红先：`_compute_entropy` 旧签名不收 `state_file` ⟹ TypeError。
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_advance as A  # noqa: E402


def _state(tmp_path, raises=0):
    st = tmp_path / "s.state"
    st.write_text(json.dumps({"gate_data": {}}), encoding="utf-8")
    if raises:
        with open(str(st) + ".budget-log.jsonl", "w", encoding="utf-8") as f:
            for _ in range(raises):
                f.write(json.dumps({"kind": "raise",
                                    "ts": datetime.now(timezone.utc).isoformat()}) + "\n")
        # 2026-10-31（§9.4 缺口①）：有账本必须有封印，否则读侧 RAISE_LEDGER_SEAL_INVALID
        import gk_budget_ledger as _L
        _L.seal_now(str(st))
    return str(st)


def test_two_raises_reach_advance_entropy(tmp_path):
    """F=1/K=4（owner 签 §8 #4）：2 次 → (2−1)/4 = 0.25。"""
    st = _state(tmp_path, 2)
    d = json.load(open(st, encoding="utf-8"))
    assert round(A._compute_entropy(d, "STAGE_2", st), 4) == 0.25


def test_one_raise_is_free_quota(tmp_path):
    """F=1：第 1 次提额在免费额度内 ⟹ 熵 0（不再是一刀切的 1/3）。"""
    st = _state(tmp_path, 1)
    d = json.load(open(st, encoding="utf-8"))
    assert A._compute_entropy(d, "STAGE_2", st) == 0.0


def test_four_raises_crosses_block_line(tmp_path):
    """n=4 = 宽松分布 q90 ⟹ (4−1)/4 = 0.75 > 0.5（阻断膝点）。"""
    st = _state(tmp_path, 4)
    d = json.load(open(st, encoding="utf-8"))
    assert round(A._compute_entropy(d, "STAGE_2", st), 4) == 0.75


def test_no_raises_is_zero(tmp_path):
    st = _state(tmp_path, 0)
    d = json.load(open(st, encoding="utf-8"))
    assert A._compute_entropy(d, "STAGE_2", st) == 0.0


def test_legacy_call_without_state_file_stays_zero(tmp_path):
    """旧调用面（不传 state_file）保持 0，防未迁移调用点静默变更语义。"""
    st = _state(tmp_path, 2)
    d = json.load(open(st, encoding="utf-8"))
    assert A._compute_entropy(d, "STAGE_2") == 0.0


def test_raise_driven_block_is_staged_off_by_default(monkeypatch):
    """经济参数未定前：仅提额驱动的越线只测量不阻断（owner 2026-10-31）。"""
    monkeypatch.delenv("GK_ENTROPY_RAISE_ENFORCE", raising=False)
    assert A._entropy_enforced(0.9, 0.0) is False


def test_raise_driven_block_can_be_enabled(monkeypatch):
    monkeypatch.setenv("GK_ENTROPY_RAISE_ENFORCE", "1")
    assert A._entropy_enforced(0.9, 0.0) is True


def test_rejected_edits_block_is_unchanged(monkeypatch):
    """base 已越线（rejected_edits）⟹ 既有硬阻断零变更，与开关无关。"""
    monkeypatch.delenv("GK_ENTROPY_RAISE_ENFORCE", raising=False)
    assert A._entropy_enforced(0.9, 0.6) is True


def test_below_threshold_never_blocks():
    assert A._entropy_enforced(0.4, 0.0) is False

#!/usr/bin/env python3
"""p_meta 冻结通道测试（2026-11-06，用户令「那个 p_meta 通道需要传」）。

三条判据：
  1. adjudicate 能把 divergence 冻结到 stage 对应 finding 的 `batch:<12hex>` facet；
  2. 解析不到批号 ⟹ 不冻结（禁猜）；
  3. 折扣只在 ≥3 批时启用，取中位数（单批只观测）。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_adjudicate as A  # noqa: E402
import gk_moa_aggregate as M  # noqa: E402


def _state(tmp_path, findings=None, kappa=None):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({
        "stage": "TEST",
        "monitor_scores": {"TEST": {"score": 0.5},
                           "ECC-AAA": {"score": 0.5},
                           "ECC-BBB": {"score": 0.5}},
        "gate_data": {"ecc_findings": findings or [], "kappa_p_meta": kappa or {}},
    }, ensure_ascii=False), encoding="utf-8")
    return str(p)


def test_freeze_resolves_batch(tmp_path):
    st = _state(tmp_path, [{"id": "ECC-AAA", "status": "open",
                            "facets": ["batch:abc123def456", "plan:x"]}])
    r = A.adjudicate({"F1": "PASS"}, 1.0, stage="ECC-AAA", state_path=st)
    assert r["entry"]["p_meta_freeze"] == {"batch": "abc123def456", "value": 0.5}


def test_no_freeze_when_unresolved(tmp_path):
    st = _state(tmp_path, [{"id": "ECC-BBB", "status": "open", "facets": ["plan:x"]}])
    r = A.adjudicate({"F1": "PASS"}, 1.0, stage="ECC-BBB", state_path=st)
    assert r["entry"]["p_meta_freeze"] == {}


def test_discount_needs_three_batches(tmp_path):
    st2 = _state(tmp_path, kappa={"a": {"value": 0.1}, "b": {"value": 0.2}})
    assert M._p_meta_for_discount(st2) is None
    st3 = _state(tmp_path, kappa={"a": {"value": 0.1}, "b": {"value": 0.2}, "c": {"value": 0.9}})
    assert M._p_meta_for_discount(st3) == 0.2

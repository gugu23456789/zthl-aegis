#!/usr/bin/env python3
"""T-b 红先：MoA 聚合在**有批锚**时须默认落 finding（「每轮必落」），并留显式 opt-out。

缺陷（实测）：`--emit-finding` 是 **opt-in（默认关）** ⟹ 聚合页/流程跑完常常**不落 finding**
⟹ 跨轮收敛无锚、ecc-findings 面恒空（owner 反馈 2026-10-06）。

修法：`--batch`/`--plan` 存在 ⟹ 默认落 finding（无锚时仍默认不落）。
2026-10-14（`ECC-50A0C5A3F2A8`，用户令「不能抑制」）：`--no-emit-finding` 由 opt-out **升级为保护锁** ——
有锚聚合给出该 flag 即 fail-loud（rc=2，`emit_finding_suppression_locked`），**不再能掐掉**自动 finding。
"""
import contextlib
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_moa_aggregate as moa  # noqa: E402

ENTRY = {"batch_id": "b1", "task": "plan-refinement: x — t", "subagent_id": "sub-1",
         "conclusion": "WARN", "seven_dim_score": {"scope": 50}, "verdicts": {"F1": "WARN"}}


def _mk(path):
    path.write_text(json.dumps({"gate_data": {"subagent_history": [ENTRY]}}, ensure_ascii=False),
                    encoding="utf-8")


def _run(monkeypatch, argv):
    calls = []
    monkeypatch.setattr(moa, "emit_aggregate_finding",
                        lambda *a, **k: (calls.append(k) or {"ok": True, "stub": True}))
    monkeypatch.setattr(sys, "argv", ["gk_moa_aggregate"] + argv)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        moa.main()
    return calls, json.loads(buf.getvalue())


def test_emit_finding_defaults_on_with_batch(tmp_path, monkeypatch):
    st = tmp_path / "s.json"
    _mk(st)
    calls, out = _run(monkeypatch, ["--state", str(st), "--batch", "b1"])
    assert calls, "有批锚却默认未落 finding（每轮必落未生效）"
    assert "finding" in out, "envelope 未带 finding"


def test_no_emit_finding_is_locked(tmp_path, monkeypatch):
    """保护锁（`ECC-50A0C5A3F2A8`，2026-10-14 用户令「不能抑制」）：有锚聚合**禁**抑制 finding。

    `--no-emit-finding` 已封闭 ⟹ 给出即 **fail-loud（rc=2）**，且**仍不落** finding（既不静默忽略、
    也不放行）。HEAD 必红：旧语义下 rc=0 且静默退出（opt-out 生效）。
    """
    st = tmp_path / "s.json"
    _mk(st)
    calls = []
    monkeypatch.setattr(moa, "emit_aggregate_finding",
                        lambda *a, **k: (calls.append(k) or {"ok": True, "stub": True}))
    monkeypatch.setattr(sys, "argv", ["gk_moa_aggregate", "--state", str(st),
                                      "--batch", "b1", "--no-emit-finding"])
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = moa.main()
    out = json.loads(buf.getvalue())
    assert rc == 2, "抑制口未封闭（应 fail-loud rc=2，实际 rc=%r）" % (rc,)
    assert out.get("error") == "emit_finding_suppression_locked", out
    assert not calls, "封闭后仍不得落 finding"

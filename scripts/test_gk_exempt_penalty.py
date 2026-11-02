#!/usr/bin/env python3
"""豁免惩罚 —— 红先臂（2026-10-05，用户令「给豁免加惩罚机制」）。

病象：`--acknowledge-injected` 逐项豁免 L2 入站门的阻断项，此前**零代价** ⟹ agent 可整表豁免
（本轮实测：一次转录 18 项即把 `leading_question`/`novel_phrase_ungrounded` 全数抹平，无痛绕过
入站门）。现给豁免定价：每豁免 1 项 = 信用分 **−1**（`kind=exempt`，非对称定价族），计入
旁挂信用账本（`<state>.credit-ledger.jsonl`，append-only + 封印，跨会话累积，audit 可见）。

判据（红先，落刀前 HEAD **必红**）：
  arm1  `gk_credit_ledger.DELTA` 含 `exempt = -1`，且显式 delta 计入 score（HEAD 无 → 红）
  arm2  `cmd_plan_refinement` 接线 `_credit_log_append "exempt"`（HEAD 无 → 红）
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def _state(d):
    p = Path(d) / ".gatekeeper.state.test"
    p.write_text(json.dumps({"gate_data": {}}), encoding="utf-8")
    return str(p)


def test_credit_ledger_exempt_kind():
    """arm1：`exempt` 为非对称定价族成员（−1/项）；显式 delta 生效并计入 score。"""
    from gk_credit_ledger import DELTA, append, score
    assert DELTA.get("exempt") == -1, "缺 exempt 定价（豁免仍零代价）"
    with tempfile.TemporaryDirectory() as d:
        st = _state(d)
        r1 = append(st, "exempt", -3, source="plan-refinement", reason="acknowledge 3 项")
        assert r1.get("ok") is True, r1
        assert r1["record"]["kind"] == "exempt"
        assert r1["record"]["delta"] == -3
        assert score(st) == -3, "豁免惩罚未计入 score"


def test_cmd_plan_refinement_charges_exempt_penalty():
    """arm2：submit 成功后按 acknowledge 项数计费（接线单源 = `_credit_log_append`）。"""
    s = CLI.read_text(encoding="utf-8")
    assert '_credit_log_append "exempt"' in s, (
        "缺豁免惩罚接线 ⟹ `--acknowledge-injected` 仍零代价（整表豁免无痛绕过 L2 门）")

#!/usr/bin/env python3
"""
`audit --state` 输出 `credit_score` 回归臂（2026-10-30 owner 裁 ①）。

背景（用户裁定）：`gk_credit_ledger.score` 在全仓非测试代码零消费点（只记账不阻断）。
方案 ① = **只读接收**：`audit --state` 输出 `credit_score`，显式标注无门禁权威；
不改任何放行/阻断语义，也不把它塞进 `audit_summary.total_fields`（不是 check）。

红先：实现前 `check_state_file()` 回包无 `credit_score` 键 ⟹ 本文件必红。
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import gk_audit_state as A  # noqa: E402
import gk_credit_ledger as CL  # noqa: E402


def _state(tmp_path) -> str:
    p = tmp_path / "s.state"
    p.write_text(json.dumps({"stage": "ECO-RESEARCH", "gate_data": {}}), encoding="utf-8")
    return str(p)


def _write_ledger(state: str, rows):
    p = Path(str(state) + CL.SUFFIX)
    p.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows),
                 encoding="utf-8")


def test_credit_score_present_and_read_only(tmp_path):
    out = A.check_state_file(_state(tmp_path))
    assert "credit_score" in out, "audit --state 未输出 credit_score（方案① 未落刀）"
    blk = out["credit_score"]
    assert blk["authority"] == "read_only", "必须显式声明无门禁权威"
    assert blk["score"] == 0


def test_credit_score_sums_ledger_deltas(tmp_path):
    st = _state(tmp_path)
    _write_ledger(st, [
        {"id": "20261030T000000-0001", "kind": "success", "delta": 5},
        {"id": "20261030T000000-0002", "kind": "fail", "delta": -15},
    ])
    blk = A.check_state_file(st)["credit_score"]
    assert blk["score"] == -10
    assert blk["records"] == 2


def test_credit_score_is_not_a_check(tmp_path):
    """只读观测不得扰动审计计分：不加 check、不改 total_fields。"""
    out = A.check_state_file(_state(tmp_path))
    assert "credit_score" not in [c["field"] for c in out["state_checks"]]
    assert out["audit_summary"]["total_fields"] == len(out["state_checks"])


def test_audit_state_cli_exposes_credit_score(tmp_path):
    """CLI 级：`gk_audit_state.py --state` 的 stdout 顶层带 credit_score。"""
    st = _state(tmp_path)
    _write_ledger(st, [{"id": "20261030T000000-0001", "kind": "success", "delta": 5}])
    cp = subprocess.run(
        [sys.executable, str(HERE / "gk_audit_state.py"), "--state", "--state-file", st,
         "--skill-dir", str(HERE.parent)],
        capture_output=True, text=True, timeout=120)
    assert cp.returncode == 0, cp.stderr[-500:]
    payload = json.loads(cp.stdout)
    assert payload["credit_score"]["score"] == 5
    assert payload["credit_score"]["authority"] == "read_only"

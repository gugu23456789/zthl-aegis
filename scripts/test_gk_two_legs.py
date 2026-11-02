#!/usr/bin/env python3
"""C2③（`ECC-75DAED1C537C`）红先臂 —— 两条腿**只读体积门**（2026-09-28）。

病象（计划 §十一-C2③）：state 无「撞墙前」预警 —— 两条腿（`subagent_history` + `ecc_findings`）
各自独立定价、单调增长，直到 `advance`/写盘撞 262144 B 才暴露（实测余量曾 1.2%）。

判据（红先，HEAD 必红）：`gk_json_utils.two_legs_report(state)` 报「两腿字节占比 + 余量 + warn」，
并在 `advance` 结果里带出（防「撞墙才发现」）；目标稳态余量 ≥ 32KB ⟹ 低于 `STATE_SIZE_RESERVE` 即 warn。
"""
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import gk_json_utils as gju  # noqa: E402


def _write_state(tmp_path, hist_bytes: int, find_bytes: int) -> str:
    sp = tmp_path / ".gatekeeper.state"
    d = {"gate_data": {
        "subagent_history": [{"conclusion": "x" * hist_bytes}],
        "ecc_findings": [{"title": "y" * find_bytes}],
    }}
    sp.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    return str(sp)


def test_two_legs_report_shape(tmp_path):
    """③ 仪表须报两腿字节 + 占比 + 余量 + warn（红先：HEAD 无该函数）。"""
    sp = _write_state(tmp_path, 1000, 500)
    r = gju.two_legs_report(sp)
    assert r["ok"] is True, r
    assert set(r["legs"]) == {"subagent_history", "ecc_findings"}, r
    assert r["legs"]["subagent_history"] > r["legs"]["ecc_findings"] > 0, r
    assert "legs_share_pct" in r and "margin" in r and "warn" in r, r


def test_two_legs_report_math(tmp_path):
    """③ 余量口径 = `STATE_SIZE_WALL - canon_bytes(state)`；低于 reserve ⟹ warn。"""
    sp = _write_state(tmp_path, 1000, 500)
    r = gju.two_legs_report(sp)
    assert r["wall"] == gju.STATE_SIZE_WALL, r
    assert r["margin"] == gju.STATE_SIZE_WALL - gju.canon_bytes(json.loads(Path(sp).read_text(encoding="utf-8"))), r
    assert r["warn"] is False, r
    sp2 = _write_state(tmp_path, gju.STATE_SIZE_WALL, 1000)   # 单腿即超墙 ⟹ margin < reserve
    r2 = gju.two_legs_report(sp2)
    assert r2["warn"] is True and r2["margin"] < r2["reserve"], r2


def test_advance_reports_state_size():
    """③ `advance` 结果须带 `state_size`（接线，非仅函数在场）。"""
    src = (SCRIPTS / "gk_advance.py").read_text(encoding="utf-8")
    assert "two_legs_report" in src, (
        "gk_advance 未接线 two_legs_report ⟹ advance 无体积预警（C2③ 未落）")

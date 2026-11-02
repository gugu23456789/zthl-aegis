#!/usr/bin/env python3
"""`ECC-03F2EB7D6607` 计量半红先臂 —— `ecc_findings` 配额体检（**只读**，2026-09-28）。

病象（实测 2026-09-28）：`ecc_findings` 是 state 里**唯一无配额**且单调增长的分量 ——
154,626 B = 硬墙（262,144）的 **59%**、canon_total（174,727）的 **88.5%**，而
`_SINGLE_KEY_PCT_WARN` 只查**顶层键**（`state_size_report` 的 `top_keys`）⟹ 实测只报
`SINGLE_KEY_HEAVY: gate_data = 164,536 B (94.0%)`，**指不到**真重键 `gate_data.ecc_findings`
（154,626 B）—— 归因盲区（有预警、无归因）。

判据（红先，HEAD 必红 = 无 `ecc_cap_report` / `ECC_MAX_*`）：
  1. 三个配额常量在场且自洽（`ECC_MAX_OPEN < ECC_MAX_ENTRIES`；`ECC_MAX_BYTES < STATE_SIZE_WALL`）；
  2. `ecc_cap_report(state)` 报三轴 used/cap/ratio/over（bytes / entries / **open**）——
     `open` 单列是关键：`archive_closed` **只动 closed**，open **无回收通路**；
  3. `over_axes` 逐轴可机检；`reclaimable_closed` = 可归档回收的 closed 条数；
  4. **零写盘**（与 `two_legs_report` 同纪律：读前后字节不变）。
"""
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import gk_json_utils as gju  # noqa: E402


def _write_state(tmp_path, findings):
    sp = tmp_path / ".gatekeeper.state"
    sp.write_text(json.dumps({"gate_data": {"ecc_findings": findings}},
                             ensure_ascii=False), encoding="utf-8")
    return str(sp)


def _fk(status, n=10):
    return {"id": "ECC-%s" % status, "title": "x" * n, "status": status}


# ── 1. 常量在场且自洽 ──────────────────────────────────────────────────────
def test_constants_present_and_sane():
    assert gju.ECC_MAX_BYTES > 0
    assert gju.ECC_MAX_ENTRIES > 0
    assert gju.ECC_MAX_OPEN > 0
    # open 是 entries 的子集 ⟹ open 上限须严格更小（否则后者无意义）
    assert gju.ECC_MAX_OPEN < gju.ECC_MAX_ENTRIES
    # 单一子系统不得占满硬墙（否则他人无预留）
    assert gju.ECC_MAX_BYTES < gju.STATE_SIZE_WALL


# ── 2. 形态与算术 ─────────────────────────────────────────────────────────
def test_report_shape_and_math(tmp_path):
    fs = [_fk("open"), _fk("open"), _fk("closed")]
    sp = _write_state(tmp_path, fs)
    r = gju.ecc_cap_report(sp)
    assert r["ok"] is True, r
    assert (r["entries"], r["open"], r["closed"]) == (3, 2, 1), r
    assert r["bytes"] == gju.ser_bytes(fs), r
    assert {"bytes_cap", "entries_cap", "open_cap", "over", "warn",
            "over_axes", "reclaimable_closed"} <= set(r), r
    assert r["bytes_cap"] == gju.ECC_MAX_BYTES, r
    assert r["entries_cap"] == gju.ECC_MAX_ENTRIES, r
    assert r["open_cap"] == gju.ECC_MAX_OPEN, r


def test_reclaims_reported(tmp_path):
    sp = _write_state(tmp_path, [_fk("open"), _fk("closed"), _fk("closed")])
    r = gju.ecc_cap_report(sp)
    assert r["reclaimable_closed"] == 2, r


# ── 3. 三轴各自可触发 ─────────────────────────────────────────────────────
def test_under_caps_no_over(tmp_path):
    r = gju.ecc_cap_report(_write_state(tmp_path, [_fk("open")]))
    assert r["over"] is False and r["warn"] is False, r
    assert r["over_axes"] == [], r


def test_over_bytes(tmp_path):
    sp = _write_state(tmp_path, [{"id": "ECC-B", "title": "y" * gju.ECC_MAX_BYTES,
                                  "status": "open"}])
    r = gju.ecc_cap_report(sp)
    assert r["bytes_over"] is True and r["over"] is True, r
    assert r["over_axes"] == ["bytes"], r


def test_over_open(tmp_path):
    sp = _write_state(tmp_path, [_fk("open") for _ in range(gju.ECC_MAX_OPEN + 1)])
    r = gju.ecc_cap_report(sp)
    assert r["open_over"] is True and r["over"] is True, r
    assert "open" in r["over_axes"], r


def test_over_entries(tmp_path):
    sp = _write_state(tmp_path, [_fk("closed") for _ in range(gju.ECC_MAX_ENTRIES + 1)])
    r = gju.ecc_cap_report(sp)
    assert r["entries_over"] is True and r["over"] is True, r
    assert "entries" in r["over_axes"], r


def test_warn_before_over(tmp_path):
    """ratio 触及预警线但未超上限 ⟹ warn=True 而 over=False（先预警后撞墙）。"""
    n = int(gju.ECC_MAX_BYTES * 0.9)     # ≈ cap 的 90% ⟹ 未超（overlay 60 B 头）
    sp = _write_state(tmp_path, [{"id": "ECC-W", "title": "z" * n, "status": "closed"}])
    r = gju.ecc_cap_report(sp)
    assert r["over"] is False and r["warn"] is True, r


# ── 4. 只读纪律 + 边界 ────────────────────────────────────────────────────
def test_readonly_zero_write(tmp_path):
    sp = _write_state(tmp_path, [_fk("open")])
    before = Path(sp).read_bytes()
    gju.ecc_cap_report(sp)
    assert Path(sp).read_bytes() == before, "ecc_cap_report 不得改写 state（只读纪律）"


def test_missing_state(tmp_path):
    r = gju.ecc_cap_report(str(tmp_path / "nope.state"))
    assert r["ok"] is False and "error" in r, r

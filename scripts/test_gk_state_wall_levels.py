#!/usr/bin/env python3
"""红先臂：state 墙**四级水位**（50/80/90/95%）+ 95% 写拦截 + 卫星容量/索引 GC。

用户 2026-11-01 裁定两点：
  ① 墙加过一个 0（256KB → 2.6MB）⟹ 三条腿按比例放大（见 test_gk_state_trim_lines.py）；
  ② 给墙加**分级告警**：50% 提示过半 / 80% 警告 / 90% 提示需裁剪 / **95% 触发拦截**。
  ③ 卫星容量 = 计划质询 10 轮 × 6 臂 = **60 臂/kind**（history 产物落点）。

判据（**HEAD 必红** —— `wall_level` / `gc_index` / `verify_shards` 尚不存在）：
  1. `wall_level()` 五档边界（ok/notice/warn/trim/block）；阈值单源 = `WALL_LEVELS`；
  2. `state_size_report` / `two_legs_report` 暴露 `level`/`pct`，warnings 带 `WALL_*`；
  3. `dump_state` 在 ≥95% **拒写**（`STATE_WALL_BLOCK`）；收缩写放行；逃生舱
     `GK_STATE_WALL_BLOCK=0` 放行；
  4. 卫星容量口径 = 60 臂/kind；`verify_shards` 报 dangling / orphan / over_capacity；
  5. `gc_index` **只**删「已墓碑 / 片不存在」叶子（有片的过期叶子保留），apply 后 checksum 同步。
"""
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import gk_json_utils as J  # noqa: E402
import gk_satellite as SAT  # noqa: E402

W = J.STATE_SIZE_WALL


# ── ① 水位分档 ───────────────────────────────────────────────────────────────

def test_wall_level_bands():
    assert J.wall_level(int(W * 0.10))["level"] == "ok"
    assert J.wall_level(int(W * 0.499))["level"] == "ok"
    assert J.wall_level(int(W * 0.50))["level"] == "notice"
    assert J.wall_level(int(W * 0.79))["level"] == "notice"
    assert J.wall_level(int(W * 0.80))["level"] == "warn"
    assert J.wall_level(int(W * 0.899))["level"] == "warn"
    assert J.wall_level(int(W * 0.90))["level"] == "trim"
    assert J.wall_level(int(W * 0.949))["level"] == "trim"
    assert J.wall_level(int(W * 0.95))["level"] == "block"
    assert J.wall_level(W + 1)["level"] == "block"


def test_wall_thresholds_single_source():
    """阈值只许在 gk_json_utils 定义（50/80/90/95），且与分档表同源。"""
    assert (J.WALL_NOTICE_PCT, J.WALL_WARN_PCT, J.WALL_TRIM_PCT, J.WALL_BLOCK_PCT) == \
        (50.0, 80.0, 90.0, 95.0)
    assert [n for _, n in J.WALL_LEVELS] == ["block", "trim", "warn", "notice"]


def test_state_size_report_exposes_level(tmp_path):
    sf = tmp_path / "s.json"
    sf.write_text(json.dumps({"gate_data": {"pad": "y" * int(W * 0.55)}}),
                  encoding="utf-8", newline="\n")
    rep = J.state_size_report(str(sf))
    assert rep["level"] == "notice", rep["level"]
    assert rep["pct"] >= 50.0, rep["pct"]
    assert any(w.startswith("WALL_NOTICE") for w in rep["warnings"]), rep["warnings"]


def test_two_legs_report_exposes_level(tmp_path):
    sf = tmp_path / "s.json"
    sf.write_text(json.dumps({"gate_data": {"ecc_findings": [], "subagent_history": []}}),
                  encoding="utf-8", newline="\n")
    r = J.two_legs_report(str(sf))
    assert r["level"] == "ok" and r["pct"] < 1.0, r


# ── ② 95% 写拦截 ─────────────────────────────────────────────────────────────

def _big(pct: float) -> dict:
    return {"gate_data": {"pad": "y" * int(W * pct)}}


def test_dump_state_blocks_at_95(tmp_path):
    sf = tmp_path / "s.json"
    with pytest.raises(ValueError) as ei:
        J.dump_state(str(sf), _big(0.96))
    assert "STATE_WALL_BLOCK" in str(ei.value)
    assert not sf.exists(), "被拦截的写不得落盘"


def test_dump_state_allows_shrink(tmp_path):
    """已超水位的 state 允许**收缩写**（否则裁剪通路自锁）。"""
    sf = tmp_path / "s.json"
    sf.write_text(json.dumps(_big(0.97)), encoding="utf-8", newline="\n")
    J.dump_state(str(sf), {"gate_data": {"pad": "y" * int(W * 0.955)}})
    assert json.loads(sf.read_text(encoding="utf-8"))["gate_data"]["pad"]


def test_dump_state_escape_hatch(tmp_path, monkeypatch):
    monkeypatch.setenv("GK_STATE_WALL_BLOCK", "0")
    sf = tmp_path / "s.json"
    J.dump_state(str(sf), _big(0.96))
    assert sf.exists()


def test_dump_state_normal_size_ok(tmp_path):
    sf = tmp_path / "s.json"
    J.dump_state(str(sf), {"gate_data": {"pad": "y" * 1024}})
    assert sf.exists()


# ── ③ 卫星容量 / 一致性 / GC ─────────────────────────────────────────────────

def _state_with_index(tmp_path, leaves, name="s.json"):
    p = tmp_path / name
    p.write_text(json.dumps({"gate_data": {"satellite_index": leaves}}), encoding="utf-8")
    return str(p)


def test_satellite_capacity_is_10_rounds_x_6_arms():
    assert (SAT.SAT_ROUNDS_BUDGET, SAT.SAT_ARMS_PER_ROUND) == (10, 6)
    assert SAT.SAT_MAX_ARMS_PER_KIND == 60
    # 一轮 = 6 臂 × 单臂 16KB × 120% 余量；一片 = 10 轮
    assert SAT.SAT_ROUND_BUDGET_BYTES == 6 * 16 * 1024 * 120 // 100
    assert SAT.SAT_SHARD_BUDGET_BYTES == 10 * SAT.SAT_ROUND_BUDGET_BYTES


def test_verify_shards_reports_dangling(tmp_path):
    sf = _state_with_index(tmp_path, {"b1": {"a1": {"kind": "history", "ttl_s": 3600}}})
    v = SAT.verify_shards(sf)
    assert v["ok"] is False and v["dangling_count"] == 1, v
    assert v["capacity"]["max_arms_per_kind"] == 60


def test_verify_shards_reports_orphan(tmp_path):
    sf = _state_with_index(tmp_path, {})
    Path(sf + SAT.KIND_SUFFIX["history"]).write_text('{"x":1}\n', encoding="utf-8")
    v = SAT.verify_shards(sf)
    assert v["ok"] is False and v["orphan_shards"] == ["history"], v


def test_gc_removes_tombstoned_and_dangling_only(tmp_path):
    sf = _state_with_index(tmp_path, {
        "b1": {"a-dead": {"kind": "history", "reclaimed_ts": "2026-10-01T00:00:00+00:00"}},
        "b2": {"a-dangle": {"kind": "finding"}},      # finding 片不存在 ⟹ 悬空
        "b3": {"a-live": {"kind": "history"}},
    })
    Path(sf + SAT.KIND_SUFFIX["history"]).write_text('{"y":2}\n', encoding="utf-8")
    out = SAT.gc_index(sf)
    assert out["removed_count"] == 2, out
    assert {r["why"] for r in out["removed"]} == {"tombstoned", "dangling"}, out
    assert out["kept"] == 1 and out["dry_run"] is True

    out = SAT.gc_index(sf, dry_run=False)
    assert out["applied"] == 2, out
    d = json.loads(Path(sf).read_text(encoding="utf-8"))
    si = d["gate_data"]["satellite_index"]
    assert list(si) == ["b3"] and list(si["b3"]) == ["a-live"], si
    want = hashlib.sha256(json.dumps(d["gate_data"], sort_keys=True).encode()).hexdigest()[:16]
    assert d["_checksum"] == want, "GC 后 checksum 必须同步（否则误报 TAMPERED）"


def test_gc_dry_run_is_zero_write(tmp_path):
    sf = _state_with_index(tmp_path, {"b1": {"a1": {"kind": "finding",
                                                   "reclaimed_ts": "2026-10-01T00:00:00+00:00"}}})
    before = Path(sf).read_bytes()
    SAT.gc_index(sf)
    assert Path(sf).read_bytes() == before


def test_gc_reports_over_capacity_without_deleting(tmp_path):
    leaves = {"b1": {"a%02d" % i: {"kind": "history"} for i in range(61)}}
    sf = _state_with_index(tmp_path, leaves)
    Path(sf + SAT.KIND_SUFFIX["history"]).write_text("{}\n", encoding="utf-8")
    out = SAT.gc_index(sf, dry_run=False)
    assert out["removed_count"] == 0, "有片的叶子越容量只报不删（保可回溯性）"
    assert out["over_capacity"]["history"] == {"leaves": 61, "cap": 60}, out


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))

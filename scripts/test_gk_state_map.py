#!/usr/bin/env python3
"""state 地图 / 隔离 state 归档 红先臂集（2026-10-31）。

背景：现场 1 base + 79 隔离 `.gatekeeper.state.<token>`，而既有入口只有
`state --clean-isolated --force`（`rm -f`：看不见 / 判据粗 / 不可逆）。

本臂守四条：
  ① **地图**可见（形态 / 大小 / 年龄 / 相位 / 卫星 / 当前态 / claim）；
  ② 归档判据 = 形态 + 非当前 + 过 TTL + 无 live claim（**全部**成立才可归档）；
  ③ 动作**可逆**（`os.replace` 到 `.trae/state-archive/<ts>/` + `manifest.json`，禁 `rm`）；
  ④ `dry_run` 零写盘（缺省即 dry-run）。
"""
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_state_map as SM  # noqa: E402


def _mk_state(root: Path, name: str, payload=None, mtime_ago_days: float = 0.0):
    p = root / name
    p.write_text(json.dumps(payload or {"r_phase": "R5", "stage": "S1",
                                        "gate_data": {}}), encoding="utf-8")
    if mtime_ago_days:
        t = time.time() - mtime_ago_days * 86400
        os.utime(p, (t, t))
    return p


def _skill(tmp_path):
    root = tmp_path / "skill"
    root.mkdir()
    return root


def test_map_lists_forms_and_excludes_artifacts(tmp_path):
    """① 地图：base / domain / legacy 可枚举；旁挂 artifact 不算 state。"""
    root = _skill(tmp_path)
    _mk_state(root, ".gatekeeper.state")
    _mk_state(root, ".gatekeeper.state.alpha")
    _mk_state(root, ".gatekeeper.state.2026-08-26-legacy-plan")
    _mk_state(root, ".gatekeeper.state.alpha.history-archive.jsonl")   # artifact
    m = SM.build_map(str(root), current=str(root / ".gatekeeper.state"))
    forms = {r["name"]: r["form"] for r in m["states"]}
    assert forms[".gatekeeper.state"] == "base"
    assert forms[".gatekeeper.state.alpha"] == "domain"
    assert forms[".gatekeeper.state.2026-08-26-legacy-plan"] == "legacy_plan"
    assert all(".jsonl" not in n for n in forms), "旁挂件被当成 state"
    assert m["summary"]["states"] == 3
    assert m["summary"]["base"] == 1 and m["summary"]["domain"] == 1


def test_ttl_and_current_and_base_guards(tmp_path):
    """② 归档判据四重：base / 当前 / 未过 TTL / live claim 一律不可归档。"""
    root = _skill(tmp_path)
    base = _mk_state(root, ".gatekeeper.state", mtime_ago_days=30)
    cur = _mk_state(root, ".gatekeeper.state.current", mtime_ago_days=30)
    fresh = _mk_state(root, ".gatekeeper.state.fresh", mtime_ago_days=1)
    stale = _mk_state(root, ".gatekeeper.state.stale", mtime_ago_days=10)
    plan = SM.reclaim_plan(str(root), current=str(cur), ttl_days=7)
    paths = {os.path.basename(x["path"]) for x in plan["plan"]}
    assert paths == {".gatekeeper.state.stale"}, plan
    skipped = {os.path.basename(x["path"]): x["reason"] for x in plan["skipped"]}
    assert "当前活动 state" in skipped[".gatekeeper.state.current"]
    assert "未过 TTL" in skipped[".gatekeeper.state.fresh"]
    assert ".gatekeeper.state" not in skipped and ".gatekeeper.state" not in paths
    # live claim 覆盖 ⟹ 从可归档降级为跳过
    import gk_write_claims as WC
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    claim = {"sid": "s1", "state": "live", "ts": ts, "ttl_s": 3600,
             "paths": [str(stale)]}
    orig = WC.live
    WC.live = lambda repo=None, now=None: [claim]
    try:
        plan2 = SM.reclaim_plan(str(root), current=str(cur), ttl_days=7)
    finally:
        WC.live = orig
    assert {os.path.basename(x["path"]) for x in plan2["plan"]} == set(), plan2
    assert any("live write claim" in x["reason"] for x in plan2["skipped"])


def test_dry_run_zero_write(tmp_path):
    """④ 缺省 dry-run：零移动、零目录。"""
    root = _skill(tmp_path)
    st = _mk_state(root, ".gatekeeper.state.stale", mtime_ago_days=10)
    before = st.read_text(encoding="utf-8")
    r = SM.apply_archive(str(root), current="", ttl_days=7)
    assert r["dry_run"] is True and r["applied"] == 0
    assert st.is_file() and st.read_text(encoding="utf-8") == before
    assert not (root / ".trae" / "state-archive").exists()


def test_apply_moves_state_and_sidecars_reversibly(tmp_path):
    """③ 归档 = 移动（含卫星片/journal），写 manifest；base 与当前态不动。"""
    root = _skill(tmp_path)
    _mk_state(root, ".gatekeeper.state", mtime_ago_days=30)
    cur = _mk_state(root, ".gatekeeper.state.current", mtime_ago_days=30)
    stale = _mk_state(root, ".gatekeeper.state.stale", mtime_ago_days=10)
    side = root / (stale.name + ".history-archive.jsonl")
    side.write_text('{"x":1}\n', encoding="utf-8")
    r = SM.apply_archive(str(root), current=str(cur), ttl_days=7, dry_run=False)
    assert r["ok"] and r["applied"] == 1 and not r["failed"], r
    dest = Path(r["dest"])
    assert (dest / ".gatekeeper.state.stale").is_file()
    assert (dest / side.name).is_file()
    assert not stale.exists() and not side.exists()
    assert (root / ".gatekeeper.state").is_file() and cur.is_file()
    man = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
    assert len(man["moves"]) == 2 and all(m["ok"] for m in man["moves"])
    # 可逆：把 dst 搬回 src 即恢复
    for m in man["moves"]:
        os.replace(m["dst"], m["src"])
    assert stale.is_file() and side.is_file()


def test_unreadable_state_still_mapped(tmp_path):
    """坏 state 不崩：地图照列（age/bytes 照实），归档裁决不因解析失败而误判。"""
    root = _skill(tmp_path)
    bad = root / ".gatekeeper.state.broken"
    bad.write_text("{not-json", encoding="utf-8")
    t = time.time() - 10 * 86400
    os.utime(bad, (t, t))
    m = SM.build_map(str(root))
    row = next(r for r in m["states"] if r["name"] == ".gatekeeper.state.broken")
    assert row["bytes"] > 0 and row["age_days"] and row["r_phase"] is None
    assert row["archivable"] is True

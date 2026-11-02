#!/usr/bin/env python3
"""自维护A 红先臂：ecc-finding **只读读取检查面** `gk_finding.check`（写前核验既有同根因登记）。

缺陷（`ECC-43C982F794B8`，2026-10-14 用户令）：`register` 只在**锁内**按 `root_key` 静默合并，
**无对外 check 面**；`cross_domain_dups` 只读检测虽在，却未接入「写前核验」⟹ 调用方**无从**
在写前知道「是否已有同根因 / 同锚登记」。

判据（**HEAD 必红** —— `gk_finding.check` 尚不存在 ⟹ AttributeError）：
  1) `root_key` 命中：同 `root_key` 既有 finding 被报出（id/status）；
  2) `title` 命中；
  3) `anchors` 交集命中（报出交了什么）；
  4) 无命中 ⟹ `matches` 为空（不误报）；
  5) **只读**：调用后 state 字节不变（禁写盘）。
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_finding as F  # noqa: E402


def _mk(tmp_path, findings, name="s.json"):
    p = tmp_path / name
    p.write_text(json.dumps({"gate_data": {"ecc_findings": findings}}, ensure_ascii=False),
                 encoding="utf-8")
    return str(p)


def _f(fid, title, root_key="", anchors=None, status="open"):
    return {"id": fid, "title": title, "root_key": root_key,
            "anchors": anchors or [], "status": status}


def test_check_matches_by_root_key(tmp_path):
    sf = _mk(tmp_path, [_f("ECC-AAA", "t1", root_key="moa-agg:deadbeef")])
    res = F.check(sf, root_key="moa-agg:deadbeef")
    assert res["ok"] is True, res
    assert [m["id"] for m in res["matches"]] == ["ECC-AAA"], res


def test_check_matches_by_title(tmp_path):
    sf = _mk(tmp_path, [_f("ECC-BBB", "同名标题")])
    res = F.check(sf, title="同名标题")
    assert [m["id"] for m in res["matches"]] == ["ECC-BBB"], res


def test_check_matches_by_anchor_intersection(tmp_path):
    sf = _mk(tmp_path, [_f("ECC-CCC", "t", anchors=["batch:abc123def456", "plan:p"])])
    res = F.check(sf, anchors=["batch:abc123def456", "plan:other"])
    assert [m["id"] for m in res["matches"]] == ["ECC-CCC"], res
    assert any("anchors:" in h for h in res["matches"][0]["matched_by"]), res


def test_check_no_hit_is_clean(tmp_path):
    sf = _mk(tmp_path, [_f("ECC-DDD", "其它", root_key="k2", anchors=["x"])])
    res = F.check(sf, root_key="nope", title="无", anchors=["batch:none"])
    assert res["matches"] == [], res


def test_check_is_read_only(tmp_path):
    sf = _mk(tmp_path, [_f("ECC-EEE", "t", root_key="rk")])
    before = Path(sf).read_bytes()
    F.check(sf, root_key="rk")
    assert Path(sf).read_bytes() == before, "check 不得写盘（只读面）"

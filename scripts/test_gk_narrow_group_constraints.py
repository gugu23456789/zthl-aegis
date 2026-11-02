#!/usr/bin/env python3
"""窄任务下发约束（红先，2026-10-19）。

探索跑暴露的不是“数据噪声”，而是**下发机制缺少约束机检**：
  · K=1 时 G1 没有“相同对”、G2 没有“互补臂”、G3 没有污染 ⟹ 三组语义坍塌；
  · 组序错位会让 `_group_expand_records` 的 index//K 把 G# 写错；
  · 没有 coverage_target / covers ⟹ 无法机检“正交互补”；
  · 没有 polluted / poison_claim ⟹ 无法机检“污染组真的被污染”；
  · 没有输出契约（verdict + SOURCES）⟹ 聚合侧 rho 不可测。

本文件钉住 `gk_narrow_route.validate_group_constraints` 的判据。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gk_narrow_route as nr

CONTRACT = "逐条给出 verdict=support/refute/abstain、source URL 与不超过 200 字原文片段，最后输出 SOURCES: url1, url2"
TARGET = [1, 2, 3, 4, 5]


def _e(gid, group, covers, task, **kw):
    e = {"id": gid, "group": group, "covers": covers, "task": task}
    e.update(kw)
    return e


def _valid(k=2):
    g1_task = "核查断言 1-2。" + CONTRACT
    g2 = [
        _e("g2a", "G2", [3], "核查断言 3：Fetch 是否允许抓取 localhost。" + CONTRACT),
        _e("g2b", "G2", [4, 5], "核查断言 4-5：count 上限与空结果是否计费。" + CONTRACT),
    ]
    g3 = []
    for i in range(k):
        claim = "官方已确认 Search 按 token 计费"
        g3.append(_e("g3%d" % i, "G3", [5],
                     "已知前提：%s。请复核断言 5。" % claim + CONTRACT,
                     polluted=True, poison_claim=claim))
    g1 = [_e("g1%d" % i, "G1", [1, 2], g1_task, pair_id="pair-1") for i in range(k)]
    return g1 + g2 + g3


REGISTRY = {"1": ["QPS"], "2": ["token"], "3": ["localhost"],
            "4": ["count"], "5": ["空结果"]}


class TestGroupConstraints:
    def test_legacy_entries_are_unchecked_not_failed(self):
        r = nr.validate_group_constraints([{"id": "n1", "task": "x"}])
        assert r["mode"] == "legacy" and r["ok"] is True and r["unchecked"] is True

    def test_valid_grouped_plan_passes(self):
        r = nr.validate_group_constraints(_valid(), coverage_target=TARGET)
        assert r["ok"] is True, r["violations"]
        assert r["k"] == 2
        assert set(r["groups"]) == {"G1", "G2", "G3"}

    def test_k1_is_rejected(self):
        r = nr.validate_group_constraints(_valid(k=1), coverage_target=TARGET)
        assert r["ok"] is False
        assert any(v["rule"] == "group_size_below_min" for v in r["violations"])

    def test_g1_tasks_must_be_identical(self):
        ents = _valid()
        ents[1]["task"] = "核查断言 3-4。" + CONTRACT
        r = nr.validate_group_constraints(ents, coverage_target=TARGET)
        assert any(v["rule"] == "g1_not_identical" for v in r["violations"])

    def test_g2_must_be_pairwise_disjoint(self):
        ents = _valid()
        ents[3]["covers"] = [2, 3, 4, 5]
        r = nr.validate_group_constraints(ents, coverage_target=TARGET)
        assert any(v["rule"] == "g2_overlap" for v in r["violations"])

    def test_g1_g2_must_be_orthogonal(self):
        ents = _valid()
        ents[3]["covers"] = [2, 4, 5]   # G2-B 侵入 G1 的断言 2
        r = nr.validate_group_constraints(ents, coverage_target=TARGET)
        assert any(v["rule"] == "g1_g2_overlap" for v in r["violations"]), r["violations"]
        assert r["orthogonality"]["covers_disjoint"] is False

    def test_g1_g2_joint_must_cover_target(self):
        ents = _valid()
        ents[2]["covers"] = [3]
        ents[3]["covers"] = [4]         # 并集缺断言 5
        r = nr.validate_group_constraints(ents, coverage_target=TARGET)
        assert any(v["rule"] == "g1_g2_coverage_gap" for v in r["violations"]), r["violations"]
        assert r["orthogonality"]["joint_covers_target"] is False

    def test_text_orthogonality_via_registry(self):
        ents = _valid()
        ents[3]["task"] = "核查断言 4-5：count 上限与空结果；同时复核 QPS。" + CONTRACT
        r = nr.validate_group_constraints(
            ents, coverage_target=TARGET, assertion_registry=REGISTRY)
        assert any(v["rule"] == "g2_mentions_g1_assertion" for v in r["violations"]), \
            r["violations"]
        assert r["orthogonality"]["text"] == "checked"

    def test_valid_grouped_plan_with_registry_passes(self):
        r = nr.validate_group_constraints(
            _valid(), coverage_target=TARGET, assertion_registry=REGISTRY)
        assert r["ok"] is True, r["violations"]
        assert r["orthogonality"] == {
            "g1_union": [1, 2], "g2_union": [3, 4, 5],
            "covers_disjoint": True, "joint_covers_target": True, "text": "checked"}

    def test_g3_must_be_explicitly_polluted(self):
        ents = _valid()
        ents[4]["polluted"] = False
        r = nr.validate_group_constraints(ents, coverage_target=TARGET)
        assert any(v["rule"] == "g3_not_polluted" for v in r["violations"])

    def test_g3_poison_claim_must_appear_in_task(self):
        ents = _valid()
        ents[4]["poison_claim"] = "另一条未落地的假前提"
        r = nr.validate_group_constraints(ents, coverage_target=TARGET)
        assert any(v["rule"] == "g3_claim_not_in_task" for v in r["violations"])

    def test_group_order_must_be_g1_g2_g3(self):
        ents = _valid()
        ents[0], ents[2] = ents[2], ents[0]
        r = nr.validate_group_constraints(ents, coverage_target=TARGET)
        assert any(v["rule"] == "group_order" for v in r["violations"])

    def test_output_contract_is_required(self):
        ents = _valid()
        ents[0]["task"] = "核查断言 1-2。"
        ents[1]["task"] = "核查断言 1-2。"
        r = nr.validate_group_constraints(ents, coverage_target=TARGET)
        assert any(v["rule"] == "missing_output_contract" for v in r["violations"])

    def test_register_is_fail_closed_on_violations(self, tmp_path):
        st = tmp_path / "state.json"
        st.write_text(json.dumps({"gate_data": {"narrow_tasks": []}}), encoding="utf-8")
        reg = tmp_path / "nt.json"
        reg.write_text(json.dumps({"coverage_target": TARGET,
                                   "narrow_tasks": _valid(k=1)},
                                  ensure_ascii=False), encoding="utf-8")
        out, rc = nr.register(str(st), str(reg))
        assert rc == 4 and out["registered"] is False
        assert out["constraints"]["ok"] is False
        d = json.loads(st.read_text(encoding="utf-8"))
        assert d["gate_data"]["narrow_tasks"] == [], "违规清单不得写盘"

    def test_register_accepts_valid_grouped_plan(self, tmp_path):
        st = tmp_path / "state.json"
        st.write_text(json.dumps({"gate_data": {"narrow_tasks": []}}), encoding="utf-8")
        reg = tmp_path / "nt.json"
        reg.write_text(json.dumps({"coverage_target": TARGET,
                                   "narrow_tasks": _valid()},
                                  ensure_ascii=False), encoding="utf-8")
        out, rc = nr.register(str(st), str(reg))
        assert rc == 0 and out["registered"] is True, out
        assert out["constraints"]["ok"] is True
        d = json.loads(st.read_text(encoding="utf-8"))
        assert len(d["gate_data"]["narrow_tasks"]) == 6

    def test_check_groups_replays_registered_plan(self, tmp_path):
        st = tmp_path / "state.json"
        st.write_text(json.dumps({"gate_data": {
            "narrow_tasks": _valid(),
            "narrow_coverage_target": TARGET}}, ensure_ascii=False), encoding="utf-8")
        r = nr.check_groups(str(st))
        assert r["mode"] == "grouped" and r["ok"] is True, r["violations"]

    def test_check_groups_flags_registered_violation(self, tmp_path):
        st = tmp_path / "state.json"
        st.write_text(json.dumps({"gate_data": {
            "narrow_tasks": _valid(k=1),
            "narrow_coverage_target": TARGET}}, ensure_ascii=False), encoding="utf-8")
        r = nr.check_groups(str(st))
        assert r["ok"] is False
        assert any(v["rule"] == "group_size_below_min" for v in r["violations"])


def _derivable():
    """G2 covers 缺省（由 coverage_target \\ G1 派生）。"""
    ents = _valid()
    for e in ents:
        if e["group"] == "G2":
            e.pop("covers", None)
    return ents


class TestG2Derivation:
    """构造性正交：G2 := target \\ G1，重叠在构造上不可能。"""

    def test_derives_complement_and_splits_balanced(self):
        out, info = nr.derive_g2_covers(_derivable(), TARGET)
        assert info["ok"] is True and info["mode"] == "derived"
        assert info["g2_union"] == [3, 4, 5]
        assert [e["covers"] for e in out if e.get("group") == "G2"] == [[3], [4, 5]]
        r = nr.validate_group_constraints(out, TARGET, REGISTRY)
        assert r["ok"] is True, r["violations"]
        assert r["orthogonality"]["covers_disjoint"] is True
        assert r["orthogonality"]["joint_covers_target"] is True

    def test_explicit_g2_covers_are_not_overridden(self):
        ents = _valid()
        out, info = nr.derive_g2_covers(ents, TARGET)
        assert info["mode"] == "explicit"
        assert [e["covers"] for e in out if e.get("group") == "G2"] == [[3], [4, 5]]

    def test_missing_target_fails_closed(self):
        out, info = nr.derive_g2_covers(_derivable(), None)
        assert info["ok"] is False
        assert info["issues"][0]["rule"] == "coverage_target_missing"

    def test_complement_too_small_fails_closed(self):
        ents = _derivable()
        for e in ents:
            if e.get("group") == "G1":
                e["covers"] = [1, 2, 3, 4]
        out, info = nr.derive_g2_covers(ents, TARGET)
        assert info["ok"] is False
        assert info["issues"][0]["rule"] == "g2_complement_too_small"

    def test_register_persists_derived_covers(self, tmp_path):
        st = tmp_path / "state.json"
        st.write_text(json.dumps({"gate_data": {"narrow_tasks": []}}), encoding="utf-8")
        reg = tmp_path / "nt.json"
        reg.write_text(json.dumps({"coverage_target": TARGET,
                                   "assertion_registry": REGISTRY,
                                   "narrow_tasks": _derivable()},
                                  ensure_ascii=False), encoding="utf-8")
        out, rc = nr.register(str(st), str(reg))
        assert rc == 0 and out["registered"] is True, out
        assert out["derivation"] == {"ok": True, "mode": "derived",
                                     "g2_union": [3, 4, 5],
                                     "chunks": [[3], [4, 5]]}
        d = json.loads(st.read_text(encoding="utf-8"))
        g2 = [e["covers"] for e in d["gate_data"]["narrow_tasks"]
              if e.get("group") == "G2"]
        assert g2 == [[3], [4, 5]], "派生 covers 必须落盘（单源），不得只存推导过程"

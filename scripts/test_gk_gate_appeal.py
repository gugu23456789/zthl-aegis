"""test_gk_gate_appeal.py -- X1 多源 appeal 阻断单源（2026-10-31）

红先臂（standard §12-X1/X2/X3 三读点同改）：
- 旧 scalar（`gate_data.appeal_required`）零回归：blocked / resolved / denied / dangling
- 多源并存：熵 + 额度两条同时阻断，互不覆盖
- 聚合优先级：denied > blocked > dangling > resolved
- 清场：按 source / 按 gate / 全清（--force 语义）
- bash G-17 入口：`--blocking` CLI 必须看见新源（否则 fail-open）
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gk_gate_appeal as ga


def _d(gate_data=None, records=None):
    return {"gate_data": gate_data or {}, "appeal_records": records or {}}


class TestLegacyScalarCompat:
    def test_clear(self):
        assert ga.check_appeal_dict(_d()) == "clear"

    def test_blocked(self):
        assert ga.check_appeal_dict(_d({"appeal_required": "STAGE_3"})) == "blocked:STAGE_3"

    def test_resolved(self):
        d = _d({"appeal_required": "STAGE_3"},
               {"STAGE_3": {"verdict": "APPROVED"}})
        assert ga.check_appeal_dict(d) == "resolved"

    def test_denied(self):
        d = _d({"appeal_required": "STAGE_3"},
               {"STAGE_3": {"verdict": "DENIED"}})
        assert ga.check_appeal_dict(d) == "denied:STAGE_3"

    def test_dangling(self):
        d = _d({"appeal_required": "STAGE_3"}, {"STAGE_3": {"score": 0.4}})
        assert ga.check_appeal_dict(d) == "dangling:STAGE_3"

    def test_legacy_source_is_entropy(self):
        items = ga.evaluate(_d({"appeal_required": "STAGE_3"}))
        assert [(i["source"], i["gate"]) for i in items] == [("entropy", "STAGE_3")]


class TestMultiSource:
    def test_two_sources_coexist(self):
        gd = {"appeal_blocks": {
            "entropy": {"gate": "STAGE_3"},
            "credit": {"gate": "STAGE_3", "score": 5},
        }}
        assert ga.check_appeal_dict(_d(gd)) == "blocked:STAGE_3"
        assert ga.blocking_gates(_d(gd)) == ["STAGE_3"]   # 同 gate 去重

    def test_distinct_gates_both_blocking(self):
        gd = {"appeal_blocks": {
            "entropy": {"gate": "STAGE_3"},
            "credit": {"gate": "ECO-EDIT"},
        }}
        assert ga.blocking_gates(_d(gd)) == ["ECO-EDIT", "STAGE_3"]

    def test_denied_beats_blocked(self):
        gd = {"appeal_blocks": {
            "entropy": {"gate": "STAGE_3"},
            "credit": {"gate": "ECO-EDIT"},
        }}
        d = _d(gd, {"STAGE_3": {"verdict": "DENIED"}})
        assert ga.check_appeal_dict(d) == "denied:STAGE_3"

    def test_resolved_source_does_not_hide_other(self):
        gd = {"appeal_blocks": {
            "entropy": {"gate": "STAGE_3"},
            "credit": {"gate": "ECO-EDIT"},
        }}
        d = _d(gd, {"STAGE_3": {"verdict": "APPROVED"}})
        assert ga.check_appeal_dict(d) == "blocked:ECO-EDIT"
        assert ga.blocking_gates(d) == ["ECO-EDIT"]

    def test_list_form_tolerated(self):
        gd = {"appeal_blocks": [{"source": "credit", "gate": "STAGE_4"}]}
        assert ga.check_appeal_dict(_d(gd)) == "blocked:STAGE_4"

    def test_blocks_win_over_stale_legacy_mirror(self):
        """规范载体更新：同一 source 以 appeal_blocks 为准，旧镜像不覆盖。"""
        gd = {"appeal_required": "STAGE_2",
              "appeal_blocks": {"entropy": {"gate": "STAGE_3"}}}
        assert ga.check_appeal_dict(_d(gd)) == "blocked:STAGE_3"


class TestWrites:
    def test_add_entropy_mirrors_legacy(self):
        gd = {}
        ga.add_block(gd, "entropy", "STAGE_3", entropy_rate=0.75)
        assert gd["appeal_required"] == "STAGE_3"
        assert gd["appeal_entropy_at_block"] == 0.75
        assert gd["appeal_blocks"]["entropy"]["gate"] == "STAGE_3"
        assert gd["appeal_blocks"]["entropy"]["entropy_rate"] == 0.75

    def test_add_second_source_keeps_legacy_mirror_owner(self):
        gd = {}
        ga.add_block(gd, "entropy", "STAGE_3", entropy_rate=0.6)
        ga.add_block(gd, "credit", "ECO-EDIT", score=3)
        assert gd["appeal_required"] == "STAGE_3"       # credit 不越权改写 mirror
        assert set(gd["appeal_blocks"]) == {"entropy", "credit"}

    def test_add_is_idempotent_per_source(self):
        gd = {}
        ga.add_block(gd, "entropy", "STAGE_3", entropy_rate=0.6)
        ga.add_block(gd, "entropy", "STAGE_4", entropy_rate=0.9)
        assert len(gd["appeal_blocks"]) == 1
        assert gd["appeal_blocks"]["entropy"]["gate"] == "STAGE_4"
        assert gd["appeal_required"] == "STAGE_4"

    def test_clear_by_source_keeps_other(self):
        gd = {}
        ga.add_block(gd, "entropy", "STAGE_3", entropy_rate=0.6)
        ga.add_block(gd, "credit", "ECO-EDIT", score=3)
        removed = ga.clear_blocks(gd, source="credit")
        assert removed == [("credit", "ECO-EDIT")]
        assert set(gd["appeal_blocks"]) == {"entropy"}
        assert gd["appeal_required"] == "STAGE_3"
        assert ga.check_appeal_dict(_d(gd)) == "blocked:STAGE_3"

    def test_clear_entropy_removes_legacy_mirror_and_rate(self):
        gd = {}
        ga.add_block(gd, "entropy", "STAGE_3", entropy_rate=0.6)
        ga.add_block(gd, "credit", "ECO-EDIT", score=3)
        ga.clear_blocks(gd, source="entropy")
        assert "appeal_required" not in gd
        assert "appeal_entropy_at_block" not in gd
        assert set(gd["appeal_blocks"]) == {"credit"}
        assert ga.check_appeal_dict(_d(gd)) == "blocked:ECO-EDIT"

    def test_clear_all_force_semantics(self):
        gd = {}
        ga.add_block(gd, "entropy", "STAGE_3", entropy_rate=0.6)
        ga.add_block(gd, "credit", "ECO-EDIT", score=3)
        removed = ga.clear_blocks(gd)
        assert len(removed) == 2
        assert "appeal_blocks" not in gd
        assert "appeal_required" not in gd
        assert ga.check_appeal_dict(_d(gd)) == "clear"

    def test_clear_by_gate(self):
        gd = {"appeal_blocks": {"entropy": {"gate": "STAGE_3"},
                                "credit": {"gate": "STAGE_3"},
                                "audit": {"gate": "ECO-DOC"}}}
        ga.clear_blocks(gd, gate="STAGE_3")
        assert set(gd["appeal_blocks"]) == {"audit"}


class TestCLI:
    def _write(self, tmp_path, state):
        p = tmp_path / "state.json"
        p.write_text(json.dumps(state), encoding="utf-8")
        return p

    def test_blocking_sees_new_source(self, tmp_path, capsys):
        """bash G-17 回归臂：新源（appeal_blocks）必须被 --blocking 看见。"""
        p = self._write(tmp_path, {"gate_data": {"appeal_blocks": {
            "credit": {"gate": "ECO-EDIT"}}}})
        rc = ga.main(["--blocking", str(p)])
        assert rc == 0
        assert capsys.readouterr().out.strip() == "ECO-EDIT"

    def test_blocking_legacy(self, tmp_path, capsys):
        p = self._write(tmp_path, {"gate_data": {"appeal_required": "STAGE_3"}})
        assert ga.main(["--blocking", str(p)]) == 0
        assert capsys.readouterr().out.strip() == "STAGE_3"

    def test_blocking_empty_when_resolved(self, tmp_path, capsys):
        p = self._write(tmp_path, {"gate_data": {"appeal_required": "STAGE_3"},
                                   "appeal_records": {"STAGE_3": {"verdict": "APPROVED"}}})
        assert ga.main(["--blocking", str(p)]) == 0
        assert capsys.readouterr().out.strip() == ""

    def test_legacy_cli_output_unchanged(self, tmp_path, capsys):
        p = self._write(tmp_path, {"gate_data": {"appeal_required": "STAGE_3"}})
        assert ga.main([str(p)]) == 0
        assert capsys.readouterr().out.strip() == "blocked:STAGE_3"

    def test_blocking_unreadable_state_fails_open(self, tmp_path, capsys):
        """与旧 `gk_state_query --default ""` 一致：坏 state 不误锁 resolve。"""
        assert ga.main(["--blocking", str(tmp_path / "missing.json")]) == 0
        assert capsys.readouterr().out.strip() == ""

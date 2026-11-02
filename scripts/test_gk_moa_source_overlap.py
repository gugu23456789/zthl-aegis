#!/usr/bin/env python3
"""W2A 金字塔仪器（红先，2026-10-18）：证据同源度必须进聚合器。

缺陷（L1-L3 实跑）：`rho` 只在旁路 `summarize_w2a_web_runs.py` 里用正则抠
`SOURCES:` 行得出，生产聚合器 `gk_moa_aggregate` 不输出 `source_overlap` /
`false_convergence` ⟹ 同源回声（agreement 高 + 证据有效样本量 1）会被读成
真收敛。本文件钉死三件事：

  1 `source_overlap(refs)`：从 conclusion / evidence 提取 URL，归一化后算
    两两 Jaccard 均值 `rho`，并按 Kish 得 `n_eff_evidence = n/(1+(n-1)rho)`；
  2 `cluster_references` 的 `consensus` 必须携带 `rho` / `n_eff_evidence` /
    `source_coverage` / `false_convergence`；
  3 无 URL ⟹ 指标为 `None`（**不冒充**独立性），不得把「没测量」记成 rho=0。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from gk_moa_aggregate import cluster_references, source_overlap


def _ref(sid, conclusion, evidence=None):
    return {"subagent_id": sid, "conclusion": conclusion,
            "evidence": evidence or [], "verdicts": {}}


class TestSourceOverlap:
    def test_same_source_is_rho_one(self):
        refs = [
            _ref("a", "断言#1 support。SOURCES: https://api-docs.deepseek.com/guides/search"),
            _ref("b", "断言#1 support。SOURCES: https://api-docs.deepseek.com/guides/search"),
        ]
        so = source_overlap(refs)
        assert so["rho"] == 1.0, so
        assert so["n_eff_evidence"] == 1.0, so
        assert so["n_with_sources"] == 2 and so["source_coverage"] == 1.0

    def test_disjoint_sources_is_rho_zero(self):
        refs = [
            _ref("a", "见 https://a.example.com/x §1"),
            _ref("b", "见 https://b.example.com/y §2"),
        ]
        so = source_overlap(refs)
        assert so["rho"] == 0.0 and so["n_eff_evidence"] == 2.0, so

    def test_url_normalization_ignores_case_scheme_fragment_and_trailing_slash(self):
        refs = [
            _ref("a", "https://Example.com/a/"),
            _ref("b", "http://www.example.com/a#billing"),
        ]
        assert source_overlap(refs)["rho"] == 1.0

    def test_absent_sources_are_none_not_zero(self):
        so = source_overlap([_ref("a", "无来源"), _ref("b", "也无来源")])
        assert so["rho"] is None and so["n_eff_evidence"] is None, so
        assert so["source_coverage"] == 0.0

    def test_evidence_field_urls_count(self):
        refs = [
            _ref("a", "结论", [{"file": "https://example.com/a", "lines": "", "note": ""}]),
            _ref("b", "结论", ["https://example.com/a"]),
        ]
        assert source_overlap(refs)["rho"] == 1.0

    def test_legacy_split_url_evidence_is_repaired(self):
        """首轮持久数据：字符串 evidence `https://x` 被旧 parser 按首个 ':' 拆成
        file="https" / lines="//x" ⟹ 读侧必须拼回，否则 URL 永远测不到。"""
        refs = [
            _ref("a", "结论", [{"file": "https", "lines": "//example.com/a", "note": ""}]),
            _ref("b", "结论", [{"file": "https", "lines": "//example.com/a", "note": ""}]),
        ]
        so = source_overlap(refs)
        assert so["n_with_sources"] == 2 and so["rho"] == 1.0, so


class TestConsensusCarriesInstrument:
    def test_echo_convergence_flagged(self):
        refs = [
            _ref("a", "结论一致。SOURCES: https://api-docs.deepseek.com/guides/search"),
            _ref("b", "结论一致。SOURCES: https://api-docs.deepseek.com/guides/search"),
        ]
        c = cluster_references(refs)["consensus"]
        assert c["agreement"] == 1.0
        assert c["rho"] == 1.0 and c["n_eff_evidence"] == 1.0
        assert c["false_convergence"] is True

    def test_independent_sources_not_flagged(self):
        refs = [
            _ref("a", "甲。SOURCES: https://a.example.com/x"),
            _ref("b", "乙。SOURCES: https://b.example.com/y"),
        ]
        c = cluster_references(refs)["consensus"]
        assert c["rho"] == 0.0 and c["false_convergence"] is False

    def test_unmeasured_is_none(self):
        c = cluster_references([_ref("a", "甲"), _ref("b", "乙")])["consensus"]
        assert c["rho"] is None and c["false_convergence"] is None


class TestPerGroupMetrics:
    """三组语义不同 ⟹ 指标必须分组解读，不能用一个全局 rho 判所有组。"""

    def _r(self, sid, group, conclusion):
        return {"subagent_id": sid, "arm_group": group, "conclusion": conclusion,
                "evidence": [], "verdicts": {}}

    def test_g1_identical_pair_is_expected_consistency(self):
        from gk_moa_aggregate import group_metrics
        refs = [
            self._r("a", "G1", "断言#1 support。SOURCES: https://x.example/a"),
            self._r("b", "G1", "断言#1 support。SOURCES: https://x.example/a"),
        ]
        g = group_metrics(refs)["G1"]
        assert g["status"] == "expected_consistency"
        assert g["rho"] == 1.0 and g["semantics"]["role"] == "identical_pair"

    def test_g2_disjoint_is_ok(self):
        from gk_moa_aggregate import group_metrics
        refs = [
            self._r("a", "G2", "断言#1 support。SOURCES: https://a.example/x"),
            self._r("b", "G2", "断言#2 refute。SOURCES: https://b.example/y"),
        ]
        g = group_metrics(refs)["G2"]
        assert g["status"] == "ok" and g["rho"] == 0.0

    def test_g3_divergence_flags_pollution(self):
        from gk_moa_aggregate import group_metrics
        refs = [
            self._r("a", "G3", "断言#5 support。SOURCES: https://x.example/a"),
            self._r("b", "G3", "断言#5 refute。SOURCES: https://x.example/a"),
        ]
        g = group_metrics(refs)["G3"]
        assert g["status"] == "pollution_flagged"
        assert g["semantics"]["role"] == "pollution"

    def test_unmeasured_group_is_explicit(self):
        from gk_moa_aggregate import group_metrics
        refs = [self._r("a", "G1", "无来源"), self._r("b", "G1", "无来源")]
        g = group_metrics(refs)["G1"]
        assert g["status"] == "unmeasured" and g["rho"] is None


class TestVerdictCanonicalization:
    """首轮 1/11 臂在 verdicts 里写散文（OK（…）/suspect（…））⟹ 聚合侧须归一，禁拆票。"""

    def test_prose_suffix_is_canonicalized(self):
        from gk_moa_aggregate import _verdict_consensus
        refs = [
            {"subagent_id": "a", "verdicts": {"F1": "ok（#3 与本版本一致）"}},
            {"subagent_id": "b", "verdicts": {"F1": "suspect（#3 证据在官方文档不存在）"}},
            {"subagent_id": "c", "verdicts": {"F1": "PASS"}},
        ]
        c = _verdict_consensus(refs)["F1"]
        assert c["counts"] == {"PASS": 2, "WARN": 1}, c
        assert c["majority"] == "PASS" and c["unanimous"] is False


class TestPerAssertionMetrics:
    """逐断言矩阵：结论散文里的 (断言, verdict) 不再被全局 agreement 平均掉。"""

    def test_extracts_assertion_votes(self):
        from gk_moa_aggregate import assertion_metrics
        refs = [
            _ref("a", "断言 1 support；断言 2 refute。"),
            _ref("b", "断言 1 support；断言 2 refute。"),
            _ref("c", "断言 1 = refute；断言 2 = refute。"),
        ]
        m = assertion_metrics(refs)
        assert m["n_with_assertions"] == 3
        a1 = m["per_assertion"]["1"]
        assert a1["support"] == 2 and a1["refute"] == 1 and a1["majority"] == "support"
        assert a1["agreement"] == 0.6667
        assert m["per_assertion"]["2"]["majority"] == "refute"

    def test_no_assertion_text_is_unmeasured_not_zero_votes(self):
        from gk_moa_aggregate import assertion_metrics
        m = assertion_metrics([_ref("a", "无关文本")])
        assert m["n_with_assertions"] == 0
        assert m["per_assertion"]["1"]["total"] == 0
        assert m["per_assertion"]["1"]["majority"] is None

    def test_structured_assertions_take_precedence_over_prose(self):
        """规范实验输出 assertions[] 时，不得再被结论散文里的旧裁决覆盖。"""
        from gk_moa_aggregate import assertion_metrics
        refs = [{"subagent_id": "a", "conclusion": "断言 1 refute",
                 "assertions": [{"id": 1, "verdict": "support"}]}]
        a1 = assertion_metrics(refs)["per_assertion"]["1"]
        assert a1["support"] == 1 and a1["refute"] == 0, a1


class TestRealizedOrthogonality:
    """正交不是「声明即事实」：由每臂实际 assertions[] 反算 G1/G2 交集与越界。"""

    def test_realized_disjoint_and_covers_target(self):
        from gk_moa_aggregate import orthogonality_metrics
        refs = [
            {"subagent_id": "a", "arm_group": "G1",
             "assertions": [{"id": 1}, {"id": 2}]},
            {"subagent_id": "b", "arm_group": "G1",
             "assertions": [{"id": 1}, {"id": 2}]},
            {"subagent_id": "c", "arm_group": "G2",
             "assertions": [{"id": 3}]},
            {"subagent_id": "d", "arm_group": "G2",
             "assertions": [{"id": 4}, {"id": 5}]},
        ]
        m = orthogonality_metrics(
            refs, {"g1": {1, 2}, "g2a": {3}, "g2b": {4, 5}},
            {"G1": {1, 2}, "G2": {3, 4, 5}}, [1, 2, 3, 4, 5])
        assert m["measured"] is True
        assert m["realized_disjoint"] is True
        assert m["realized_intersection"] == []
        assert m["realized_union"] == [1, 2, 3, 4, 5]
        assert m["declared_disjoint"] is True
        assert m["declared_covers_target"] is True
        assert m["missing_from_realized"] == []
        assert m["scope_violations"] == []

    def test_realized_overlap_is_detected(self):
        from gk_moa_aggregate import orthogonality_metrics
        refs = [
            {"subagent_id": "a", "arm_group": "G1", "assertions": [{"id": 1}]},
            {"subagent_id": "b", "arm_group": "G2", "assertions": [{"id": 1}]},
        ]
        m = orthogonality_metrics(refs)
        assert m["realized_disjoint"] is False
        assert m["realized_intersection"] == [1]

    def test_out_of_scope_uses_declared_covers_per_arm(self):
        from gk_moa_aggregate import orthogonality_metrics
        task = "x\n\n【本臂窄任务（G2｜id=g2a）】\n核查断言 3"
        m = orthogonality_metrics(
            [{"subagent_id": "a", "task": task,
              "assertions": [{"id": 3}, {"id": 1}]}],
            {"g2a": {3}}, {"G1": {1, 2}, "G2": {3}})
        assert m["scope_violations"] == [
            {"subagent_id": "a", "group": "G2", "narrow_id": "g2a",
             "assertions": [1]}]

    def test_unmeasured_does_not_claim_orthogonal(self):
        from gk_moa_aggregate import orthogonality_metrics
        m = orthogonality_metrics([{"subagent_id": "a", "arm_group": "G1"}])
        assert m["measured"] is False
        assert m["realized_disjoint"] is None


class TestRunSummarizerReusesInstrument:
    """旁路 summarizer 必须复用生产仪器（禁第二套 rho 实现）。"""

    def _log(self, tmp_path, conclusions):
        import json
        refs = [{"subagent_id": "s%d" % i, "conclusion": c}
                for i, c in enumerate(conclusions)]
        line = json.dumps({"ok": True, "aggregate": {"references": refs}},
                          ensure_ascii=False)
        p = tmp_path / "run.log"
        p.write_text(line + "\n", encoding="utf-8")
        return str(p)

    def test_summarizer_matches_production_rho(self, tmp_path):
        import summarize_w2a_web_runs as sw
        p = self._log(tmp_path, [
            "断言#1 verdict=support。SOURCES: https://api-docs.deepseek.com/guides/search",
            "断言#1 verdict=support。SOURCES: https://api-docs.deepseek.com/guides/search",
        ])
        out = sw.summarize("L1", p)
        assert out["rho"] == 1.0
        assert out["n_eff_evidence"] == 1.0
        assert out["false_convergence"] is True

    def test_summarizer_unmeasured_is_none(self, tmp_path):
        import summarize_w2a_web_runs as sw
        p = self._log(tmp_path, ["无来源甲", "无来源乙"])
        out = sw.summarize("L1", p)
        assert out["rho"] is None and out["false_convergence"] is None

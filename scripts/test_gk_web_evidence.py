"""
test_gk_web_evidence.py — 受治联网「证据注入契约」（单出网口 · 设计稿 §9.7）测试
=============================================================================
红先：本批改动前 `gk_evidence` 模块**不存在**（collect 期即 ImportError ⟹ 全红）。

覆盖：new_evidence 字段（L / phase）/ provenance 恒 untrusted /
      dumps↔loads 往返 / render_snippet↔parse_snippet 往返 / 坏 JSON fail-loud。
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import gk_evidence as ge


class TestNewEvidence:
    def test_fields_and_len(self):
        r = ge.new_evidence(source_id="https://a/b", content="x" * 137,
                            egress_ref="eg-abc", fetched_at=1234)
        assert r["source_id"] == "https://a/b"
        assert r["egress_ref"] == "eg-abc"
        assert r["fetched_at"] == 1234
        assert r["content_len"] == 137
        assert r["phase"] is None            # 未给 S ⟹ phase 未知（不得瞎算）
        assert r["provenance"] == "untrusted"
        assert len(r["excerpt"]) == 137

    def test_phase_from_modulus(self):
        r = ge.new_evidence(source_id="u", content="x" * 137, phase_modulus=128)
        assert r["phase"] == 137 % 128

    def test_excerpt_truncated(self):
        r = ge.new_evidence(source_id="u", content="y" * 9999, excerpt_max=10)
        assert len(r["excerpt"]) == 10 and r["content_len"] == 9999

    def test_provenance_forced_untrusted(self):
        r = ge.new_evidence(source_id="u", content="z")
        assert r["provenance"] == ge.PROVENANCE_UNTRUSTED


class TestSerde:
    def test_dumps_loads_roundtrip(self):
        recs = [ge.new_evidence(source_id="a", content="hello", egress_ref="eg-1")]
        assert ge.loads(ge.dumps(recs)) == recs

    def test_loads_empty(self):
        assert ge.loads("") == []

    def test_loads_bad_json_fail_loud(self):
        with pytest.raises(Exception):
            ge.loads("{not json")

    def test_loads_non_list_fail_loud(self):
        with pytest.raises(Exception):
            ge.loads('{"a": 1}')

    def test_snippet_roundtrip(self):
        recs = [ge.new_evidence(source_id="a", content="hello", egress_ref="eg-1")]
        text = ge.render_snippet(recs)
        assert ge.EVIDENCE_ENV == "GK_WEB_EVIDENCE"
        assert ge.parse_snippet(text) == recs

    def test_parse_snippet_absent(self):
        assert ge.parse_snippet("no fence here") == []


class TestWebEvidenceSnippet:
    """注入接线（subagent_runner._web_evidence_snippet）：env 缺失即 ""、坏 JSON fail-soft。"""

    def test_absent_env_returns_empty(self, monkeypatch):
        import subagent_runner as sr
        monkeypatch.delenv(ge.EVIDENCE_ENV, raising=False)
        assert sr._web_evidence_snippet() == ""

    def test_injected_env_renders(self, monkeypatch):
        import subagent_runner as sr
        recs = [ge.new_evidence(source_id="u", content="hello")]
        monkeypatch.setenv(ge.EVIDENCE_ENV, ge.dumps(recs))
        assert ge.parse_snippet(sr._web_evidence_snippet()) == recs

    def test_bad_json_fail_soft(self, monkeypatch):
        import subagent_runner as sr
        monkeypatch.setenv(ge.EVIDENCE_ENV, "{bad json")
        assert sr._web_evidence_snippet() == ""

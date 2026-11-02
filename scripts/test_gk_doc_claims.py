"""test_gk_doc_claims.py — 文档 claim 门（声明 ↔ 代码）。"""
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
ROOT = Path(__file__).resolve().parent.parent


def test_real_docs_pass():
    import gk_doc_claims as C
    r = C.check(str(ROOT))
    assert r["ok"], r


def test_broken_relative_link_fails(tmp_path):
    import gk_doc_claims as C
    (tmp_path / "references").mkdir()
    (tmp_path / "README.md").write_text("[x](missing.md)\n", encoding="utf-8")
    (tmp_path / "references" / "state-storage.md").write_text("", encoding="utf-8")
    (tmp_path / "references" / "research-408.md").write_text("", encoding="utf-8")
    issues = C._check_links(tmp_path)
    assert any(i["claim"] == "missing.md" for i in issues), issues


def test_claim_constant_mismatch_fails():
    import gk_doc_claims as C
    issues = C._check_claim(ROOT, {
        "doc": "README.md", "needle": "每 kind ≤6 叶", "kind": "const",
        "target": "gk_satellite.INLINE_LEAVES_MAX_PER_KIND", "expect": 999})
    assert issues and "期望 999" in issues[0].get("error", ""), issues


def test_release_mode_is_green():
    """发布门只看公开导出面：私有 docs/plans、subagent 报告不阻断。"""
    import gk_doc_align as D
    r = D.run_all(str(ROOT), "", "", release=True)
    assert r["issues"] == 0 and r["warns"] == 0, r
    by = {c["check"]: c for c in r["checks"]}
    assert by["plan_landing_drift"]["status"] == "SKIP"
    assert by["subagent_unlogged"]["status"] == "SKIP"
    assert by["anchor_existence"]["status"] in ("PASS", "SKIP")

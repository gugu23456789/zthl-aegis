#!/usr/bin/env python3
"""S5 红先：ecc-findings → 单一批级裁定评分（无 arm 维度，2026-10-06）。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_finding_score as S  # noqa: E402


def test_single_batch_verdicts_no_arm_dimension():
    findings = [
        {"title": "收窄范围", "facets": ["carrier:P", "classification:plan-error"], "status": "open"},
        {"title": "预算截停无告警", "facets": ["carrier:M", "classification:infra-defect"], "status": "open"},
        {"title": "同型复发", "facets": ["carrier:L", "classification:infra-defect"], "status": "open"},
    ]
    out = S.score(findings)
    assert set(out["verdicts"]) == {"F1", "F2", "F3", "F4", "F5", "F6", "F7"}, out["verdicts"]
    assert all(v in ("PASS", "WARN", "BLOCKED") for v in out["verdicts"].values())
    assert isinstance(out["score"], int) and 0 <= out["score"] <= 100
    assert out["decision"]
    assert set(out["concessions"]) <= set(out["verdicts"])
    assert set(out["concessions"]) == {c for c, v in out["verdicts"].items() if v != "PASS"}


def test_blocked_when_two_or_more_infra():
    findings = [{"title": "x", "facets": ["classification:infra-defect"]} for _ in range(2)]
    out = S.score(findings)
    assert out["verdicts"]["F4"] == "BLOCKED", out


def test_clean_single_finding_warn():
    out = S.score([{"title": "ok", "facets": ["carrier:P", "classification:plan-error"]}])
    assert out["verdicts"]["F1"] == "WARN" and out["score"] == 88, out


def test_score_creates_missing_out_dir(tmp_path, monkeypatch):
    """S5：`--out-dir <新目录>` 须自建（页面命令链直接落盘，用户目录未必已存在）。"""
    import json
    f = tmp_path / "findings.json"
    f.write_text(json.dumps([{"title": "x", "facets": ["classification:infra-defect"]}]),
                 encoding="utf-8")
    outd = tmp_path / "fresh"
    monkeypatch.setattr(sys, "argv",
                        ["gk_finding_score.py", "--file", str(f), "--out-dir", str(outd)])
    assert S.main() == 0 and (outd / "verdicts.json").exists(), "未自建 out-dir"


def test_empty_findings_all_pass_but_warns():
    """① 空 findings 护栏（2026-10-06）：0 条 ⟹ 全 PASS/100（静默放行陷阱）⟹ 须带 warning。"""
    out = S.score([])
    assert out["score"] == 100 and all(v == "PASS" for v in out["verdicts"].values()), out
    assert "warning" in out and "空 findings" in out["warning"], out
    # 有 finding 时不得误报告警
    assert "warning" not in S.score([{"title": "x", "facets": ["classification:plan-error"]}])


# ══════════ 相关性隔离 + 结论方向三态（2026-10-06）══════════

def test_relevance_out_quarantined_not_counted():
    """`relevance:out`（未锚定）⟹ 隔离进 unverified，**不计缺陷**（也不丢弃）。"""
    fs = [{"title": "无关条目", "facets": ["relevance:out", "classification:plan-error"]},
          {"title": "切题条目", "facets": ["relevance:in", "classification:plan-error"]}]
    out = S.score(fs)
    assert out["counts"]["plan_error"] == 1, out          # 只计切题那条
    assert out["unverified"] == ["无关条目"], out
    assert out["verdicts"]["F1"] == "WARN", out            # 1 条 ⟹ WARN（2 条会 BLOCKED）
    assert out["score"] == 88, out


def test_direction_allow_keeps_only_infra_penalty():
    """方向=放行：列表项视为已接受观察 ⟹ 不罚分；仅机制类（F4）保留罚分。"""
    fs = [{"title": "范围蔓延", "facets": ["classification:plan-error"]},
          {"title": "机制缺陷", "facets": ["classification:infra-defect"]}]
    out = S.score(fs, direction="allow")
    assert out["verdicts"]["F1"] == "PASS", out
    assert out["verdicts"]["F4"] == "WARN", out
    assert out["score"] == 88, out
    assert "人工放行" in out["decision"], out


def test_direction_abstain_no_judgement():
    """方向=弃权：不做判定（verdicts={} / score=None），仅落台账。"""
    out = S.score([{"title": "x", "facets": ["classification:infra-defect"]}], direction="abstain")
    assert out["abstained"] is True and out["verdicts"] == {} and out["score"] is None, out
    assert "弃权" in out["decision"], out


def test_direction_reject_is_default_unchanged():
    """缺省方向 = 驳回（零回归）：与旧口径逐字一致。"""
    fs = [{"title": "x", "facets": ["classification:infra-defect"]} for _ in range(2)]
    assert S.score(fs) == S.score(fs, direction="reject")

#!/usr/bin/env python3
"""S4 红先：散文 → ecc-findings（确定性规则解析，2026-10-06）。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_prose_findings as P  # noqa: E402

PROSE = """# 本轮结论
- (P) T3 的范围界定模糊，须收窄到原定模块。
- (M) 预算耗尽截停无告警，须补预算看门狗。
- (L) 同型 finding 两轮复发，须加 PW-SN 规则防复发。
- 观测到 hmac 未验签。
"""


def test_convert_marks_carriers_and_classes():
    fs = P.convert(PROSE, plan="/p/docs/plans/x.md", batch="b1")
    assert len(fs) == 4, fs
    p = [f for f in fs if "carrier:P" in f["facets"]][0]
    assert "classification:plan-error" in p["facets"], p
    m = [f for f in fs if "carrier:M" in f["facets"]][0]
    assert "classification:infra-defect" in m["facets"], m
    lo = [f for f in fs if "carrier:L" in f["facets"]][0]
    assert "classification:infra-defect" in lo["facets"], lo
    un = [f for f in fs if not any(x.startswith("carrier:") for x in f["facets"])][0]
    assert "classification:unknown" in un["facets"], un


def test_root_key_and_anchors():
    fs = P.convert("- 无标记项", plan="/p/x.md", batch="b1")
    assert fs[0]["root_key"].startswith("prose:") and len(fs[0]["root_key"]) == 6 + 16
    assert "plan:/p/x.md" in fs[0]["anchors"] and "batch:b1" in fs[0]["anchors"]


def test_output_fields_complete():
    """S4-a：输出字段齐（`source`/`root_key`/`anchors`）——直喂 `gk_finding.register`。

    2026-10-16（`ECC-E844E67E64A5`）：`family` **删除**（convert 产出但 register 零消费 = 死字段）；
    `source` 由 `review` 改 **`prose`**（原与 MoA 聚合 finding 同源不可分）。
    """
    f = P.convert("- (P) x")[0]
    for k in ("title", "source", "root_key", "anchors", "facets", "source_note"):
        assert k in f, k
    assert f["source"] == "prose", f
    assert "family" not in f, "family 死字段应已删除"


def test_headings_ignored_paragraphs_kept():
    """M1：混合输入不得静默丢弃普通段落；标题仍不入。"""
    fs = P.convert("# 标题\n普通段落不含标记\n- 仅此一条\n")
    assert len(fs) == 2, fs
    assert any("普通段落" in f["title"] for f in fs), fs
    assert any(f["title"] == "仅此一条" for f in fs), fs


def test_severity_high_on_keywords():
    assert P.convert("- (M) 输出被截断")[0]["severity"] == "high"


def test_out_creates_missing_parent_dir(tmp_path, monkeypatch):
    """S4：`--out <新目录>/findings.json` 须自建父目录（页面命令链直接落盘，用户目录未必已存在）。"""
    src = tmp_path / "p.txt"
    src.write_text("- (P) x\n", encoding="utf-8")
    out = tmp_path / "newdir" / "findings.json"
    monkeypatch.setattr(sys, "argv",
                        ["gk_prose_findings.py", "--file", str(src), "--out", str(out)])
    assert P.main() == 0 and out.exists(), "未自建父目录 ⟹ 命令链第一步失败"


def test_cjk_ordinals_and_parenthesized_parsed():
    """C 扩：中文序号（`一、`）/ 括号序号（`（3）`）/ `1、` 均须识别为列表项（原仅 ASCII `-`/`1.`）。"""
    prose = ("一、T3 范围界定模糊，须收窄到原定模块。\n"
             "二、预算耗尽截停无告警，须补预算看门狗。\n"
             "（3）同型 finding 两轮复发，须加 PW-SN 规则。\n"
             "1、锁定框架未声明，须补退路。\n")
    fs = P.convert(prose)
    assert len(fs) == 4, fs
    assert all(not f["title"].startswith(("一、", "二、", "（3）", "1、")) for f in fs), fs


def test_plain_paragraph_blocks_become_findings():
    """C 扩：无任何列表标记的**纯散文** ⟹ 按空行分段，每段成一条（原整行丢弃 ⟹ 0 finding）。

    段内换行合并为一条（不逐行拆），以兼容折行输入。"""
    prose = "本轮结论第一段。\n这是同段第二行。\n\n第二段自成一题。\n"
    fs = P.convert(prose)
    assert len(fs) == 2, fs
    assert "同段第二行" in fs[0]["title"], fs
    assert fs[1]["title"] == "第二段自成一题。", fs


def test_heading_only_prose_yields_zero():
    """仅标题（`#`/`##`）⟹ 0 条（护栏仍须能触发；标题行不入 finding）。"""
    assert P.convert("# 标题\n## 小标题\n") == []


def test_empty_prose_warns_loud(tmp_path, monkeypatch, capsys):
    """① 空 findings 护栏（2026-10-06）：无可解析条目（此处 = 仅标题）⟹ count=0，
    须 **stderr + JSON warning 显式告警**（否则下游恒全 PASS ⟹ 静默放行）。"""
    import json as _j
    src = tmp_path / "plain.txt"
    src.write_text("# 只有标题\n", encoding="utf-8")
    out = tmp_path / "f.json"
    monkeypatch.setattr(sys, "argv",
                        ["gk_prose_findings.py", "--file", str(src), "--out", str(out)])
    assert P.main() == 0
    cap = capsys.readouterr()
    assert "finding" in cap.err, cap.err
    res = _j.loads(cap.out)
    assert res["count"] == 0 and "warning" in res, res
    assert _j.loads(out.read_text(encoding="utf-8")) == []


_REFS_REL = [{"subagent_id": "a1", "arm_group": "G1",
              "task": "plan-refinement: /p/x.md — 质询",
              "conclusion": "判据2a 的写面单点假设不成立；cmd_update_gate_data 未接载荷键检查。",
              "evidence": [{"file": "scripts/gk_state_patch.py", "lines": "166-547"}]}]


def test_relevance_gate_facets_in_and_out():
    """相关性闸（锚定硬下限 + BM25）：切题 ⟹ relevance:in；无关 ⟹ relevance:out（供下游隔离）。"""
    prose = ("- (P) cmd_update_gate_data 未接载荷键检查，判据2a 须补。\n"
             "- (P) 首页配色与设计稿不一致，须统一改为品牌蓝。\n")
    fs = P.convert(prose, refs=_REFS_REL)
    assert "relevance:in" in fs[0]["facets"], fs[0]
    assert "relevance:out" in fs[1]["facets"], fs[1]
    assert any(x.startswith("bm25:") for x in fs[0]["facets"]), "缺 BM25 分值 facet（τ 标定用）"
    assert any(x.startswith("anchor:") for x in fs[0]["facets"]), "缺锚定计数 facet"


def test_relevance_weak_facet_for_single_anchor():
    """M2：弱锚定（仅 1 个共享 token）须显式标 relevance:weak，供下游 triage。"""
    refs = [{"task": "cmd_update_gate_data 未接载荷键检查",
             "conclusion": "判据2a 的写面单点假设不成立。"}]
    fs = P.convert("- (P) cmd_update_gate_data 未接检查", refs=refs)
    assert "relevance:in" in fs[0]["facets"], fs[0]
    assert "relevance:weak" in fs[0]["facets"], fs[0]


def test_relevance_gate_off_without_context():
    """不给 refs ⟹ 不启用闸（向后兼容：无 relevance facet）。"""
    fs = P.convert("- (P) 任意条目")
    assert not any(str(x).startswith("relevance:") for x in fs[0]["facets"]), fs[0]

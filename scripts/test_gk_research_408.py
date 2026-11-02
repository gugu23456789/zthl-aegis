"""test_gk_research_408.py — 408 特化 research frame 接线（默认 auto，advisory 不阻塞）。"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
ROOT = Path(__file__).resolve().parent.parent


def test_hint_exposes_408_frame():
    import gk_advance as A
    pre = A._HINT_PHASES["ECO-RESEARCH"]["research_prelude"]
    assert pre["frame_env"] == "GK_RESEARCH_FRAME"
    assert pre["default_frame"] == "auto"
    assert pre["auto"] is True and pre["non_blocking"] is True
    f = pre["frames"]["408"]
    assert f["axes"] == ["数据结构", "计算机组成", "操作系统", "计算机网络"]
    assert len(f["template"]) == 8
    assert (ROOT / f["doc"]).is_file()


def test_reference_doc_has_axes_and_template():
    txt = (ROOT / "references" / "research-408.md").read_text(encoding="utf-8")
    for axis in ("数据结构", "计算机组成", "操作系统", "计算机网络"):
        assert axis in txt, "缺 408 轴: %s" % axis
    assert "GK_RESEARCH_FRAME=408" in txt
    for section in ("负载模型", "内存与写路径", "并发与崩溃一致性", "失败模式", "408 结论"):
        assert section in txt, "缺八段之一: %s" % section


def test_schema_marks_research_frame_optional():
    d = json.loads((ROOT / "monitor-schemas" / "ECO-RESEARCH.json").read_text(encoding="utf-8"))
    assert "research_frame" not in d.get("produces", []), "research_frame 不得成为必产物"
    assert any("408" in e for e in d.get("evidence", [])), "schema evidence 未登记 408 帧"
    assert "block_edit_on_missing_research_frame" in d.get("must_not", [])


def test_node_guard_checklist_mentions_408():
    import gk_node_guard as G
    items = G._CHECKLISTS["ECO-RESEARCH"]
    assert any("research-408" in x for x in items), items


def test_architecture_map_lists_reference():
    txt = (ROOT / "references" / "architecture-overview.md").read_text(encoding="utf-8")
    assert "research-408.md" in txt


def test_auto_classifier_system_vs_creative():
    import gk_advance as A
    env = {"GK_RESEARCH_FRAME": "auto"}
    assert A.classify_research_frame("修复 state 写入并发锁", stage="ECO-RESEARCH",
                                     project_type="standing", env=env)["frame"] == "408"
    assert A.classify_research_frame("写一篇品牌文案，艺术创作", stage="ECO-RESEARCH",
                                     project_type="standing", env=env)["frame"] == "generic"
    assert A.classify_research_frame("state of the art copywriting", stage="ECO-RESEARCH",
                                     project_type="standing", env=env)["frame"] == "generic"
    assert A.classify_research_frame("写文案介绍 state 存储", stage="ECO-RESEARCH",
                                     project_type="standing", env=env)["frame"] == "generic"
    assert A.classify_research_frame("", stage="ECO-RESEARCH",
                                     project_type="standing", env=env)["frame"] == "408"
    assert A.classify_research_frame("做一张海报", stage="plan-refinement",
                                     project_type="analysis", env=env)["frame"] == "generic"
    assert A.classify_research_frame("随便", stage="plan-refinement",
                                     project_type="analysis", env=env)["frame"] == "generic"
    assert A.classify_research_frame("做海报", env={"GK_RESEARCH_FRAME": "408"})["frame"] == "408"


def test_hint_extras_is_advisory_not_gate():
    import gk_advance as A
    hint, extras = A._hint_for("ECO-RESEARCH",
                               {"project_type": "standing",
                                "gate_data": {"project_type": "standing"}},
                               {}, "", "")
    rf = extras["research_frame"]
    assert rf["frame"] == "408" and rf["blocking"] is False
    assert "research_frame" not in hint, "frame 只能走 extras，不能变成 hint 必填"

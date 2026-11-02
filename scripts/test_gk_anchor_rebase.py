#!/usr/bin/env python3
"""锚重钉执行器回归（S1-a，2026-09-19）。

背景：`gk_doc_align.py::anchor_rebase_plan` 只**规划**清单，仓内无写回实现 ⟹ P5 §7 的
「生成重钉清单**并执行**」只有前半（`ECC-4CFD7F53E00F`）。本门锁 `gk_anchor_rebase.py`
的四条安全性质 —— 它们是「能跑」与「跑错」的分界：

  ① **白名单为空 ⟹ 零改写**（防手滑全量，把密封/熔断中的计划一起改掉）
  ② **重钉后漂移真的清零**（不是只改了字符串而锚仍漂）
  ③ **区间引用永不被碰**（`manual` 全留 —— 机器给不出跨度的新位置，
     `ECC-F1AEA5F5F0AC`）
  ④ **清单条目在目标行对不上 ⟹ 记 not_found 且不写**（宁可少改，不改错）
  ⑤ CRLF 文档保持 CRLF（防整份文档被改写成 LF 的大 diff）

`manual` 的「不碰」在本门里以 ③ 的计数形式断言（`manual_untouched`）。
"""
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from gk_anchor_rebase import apply_edits, plan_edits  # noqa: E402

# scripts/gk_demo.py 第 11 行为 `def route():`（5 组两行占位 + 定义行）
_BODY = "# 占位\nx = 1\n" * 5 + "def route():\n    return 'tier'\n"
_ANCHOR = "见 `scripts/gk_demo.py%s route` 的语义。"   # 实参自带冒号；符号绑定形态（route 有唯一定义）


def _mk(tmp_path, ref: str) -> Path:
    docs = tmp_path / "docs" / "plans"
    docs.mkdir(parents=True)
    (tmp_path / "scripts").mkdir(exist_ok=True)
    (tmp_path / "scripts" / "gk_demo.py").write_text(_BODY, encoding="utf-8", newline="\n")
    (docs / "p.md").write_text(_ANCHOR % ref, encoding="utf-8", newline="\n")
    return tmp_path


def _doc(tmp_path) -> Path:
    return tmp_path / "docs" / "plans" / "p.md"


def test_empty_whitelist_is_noop(tmp_path):
    """判据①：白名单为空 ⟹ 一条都不排、文件一字节不动。"""
    d = _mk(tmp_path, ":1")
    before = _doc(d).read_bytes()
    p = plan_edits(str(d), [])
    assert p["edits"] == [], f"空白名单却排出了改写：{p['edits']}"
    assert len(p["skipped"]) == 1 and p["skipped"][0]["why"] == "doc_not_in_whitelist"
    assert apply_edits(str(d), p["edits"], apply=True) == []
    assert _doc(d).read_bytes() == before


def test_apply_clears_drift(tmp_path):
    """判据②：重钉后 `rebase_plan.count` 归零（锚真的落在含其关键词的行上）。"""
    from gk_doc_align import check_anchor_existence
    d = _mk(tmp_path, ":1")
    p = plan_edits(str(d), ["p.md"])
    assert len(p["edits"]) == 1, p
    assert p["edits"][0]["new"] == "scripts/gk_demo.py:11", p["edits"][0]
    r = apply_edits(str(d), p["edits"], apply=True)
    assert r[0]["status"] == "applied", r
    after = check_anchor_existence(str(d))
    assert after["rebase_plan"]["count"] == 0, (
        f"重钉后仍有漂移：{after['rebase_plan']}")
    assert "scripts/gk_demo.py:11" in _doc(d).read_text(encoding="utf-8")


def test_range_ref_never_touched(tmp_path):
    """判据③：**无绑定**的区间引用 `path:A-B` 永不出现在 edits（留在 manual），文件不动。

    2026-09-19 S1-a 二阶段口径收窄：`manual.range_ref` 现在**只管无绑定区间**；
    有符号绑定的区间走 `rebase_plan.repin_range`（判据④）。理由同 `ECC-F1AEA5F5F0AC`：
    `nearest_hit` 只给单行，无绑定 ⟹ 跨度不可推、必猜错。
    """
    d = _mk(tmp_path, ":1-3")
    _doc(d).write_text("见 scripts/gk_demo.py:1-3 的 route 语义。", encoding="utf-8")  # 无 backtick ⟹ 无绑定
    p = plan_edits(str(d), ["p.md"])
    assert p["edits"] == [], f"无绑定区间被纳入重钉（会被压成单行）：{p['edits']}"
    assert p["manual_untouched"] == 1, p
    assert ":1-3" in _doc(d).read_text(encoding="utf-8")


def test_bound_range_ref_repins_span_aware(tmp_path):
    """判据④：**有绑定**的区间引用 ⟹ 保跨度重钉（起点 = 符号命中行 11、终点 = 11+2-1 = 12）。

    ⚠ 夹具跨度取 2 而非 3：`_BODY` 仅 12 行，起点 11 + 跨度 3 ⟹ 终点 13 越 EOF，
    下一轮扫描会判 `line_over_eof` —— 那是**真**溢出，不该被实现「夹取」掩盖。
    """
    d = _mk(tmp_path, ":1-2")
    p = plan_edits(str(d), ["p.md"])
    assert len(p["edits"]) == 1, p
    assert p["edits"][0]["old"] == "scripts/gk_demo.py:1-2", p["edits"][0]
    assert p["edits"][0]["new"] == "scripts/gk_demo.py:11-12", p["edits"][0]
    r = apply_edits(str(d), p["edits"], apply=True)
    assert r[0]["status"] == "applied", r
    from gk_doc_align import check_anchor_existence
    after = check_anchor_existence(str(d))
    assert after["rebase_plan"]["count"] == 0, f"保跨度重钉后仍有漂移：{after['rebase_plan']}"
    assert "scripts/gk_demo.py:11-12" in _doc(d).read_text(encoding="utf-8")


def test_refs_filter_limits_edits(tmp_path):
    """判据⑦：`refs` 显式白名单 ⟹ 只有列出的 ref 被改，其余记 `ref_not_in_whitelist`。

    存在理由：`repin` 的「最近命中」对高频字面量会给**错值**（实测 conv-eval
    `gatekeeper-cli.sh:6648 _CMD_REG` 工具给 6701 / 真值 6734；
    `:6309 cmd_plan_refinement` 工具给 6377 / 真值 6395）⟹ 只允许 apply 已逐条读码核实的子集。
    """
    d = _mk(tmp_path, ":1")
    _doc(d).write_text((_ANCHOR % ":1") + "\n" + (_ANCHOR % ":2") + "\n", encoding="utf-8")
    p = plan_edits(str(d), ["p.md"], refs=["scripts/gk_demo.py:1"])
    assert len(p["edits"]) == 1, f"未按 refs 收敛：{p['edits']}"
    assert p["edits"][0]["old"] == "scripts/gk_demo.py:1", p["edits"][0]
    assert any(s.get("why") == "ref_not_in_whitelist" for s in p["skipped"]), p["skipped"]


def test_not_found_is_not_written(tmp_path):
    """判据④：清单条目在目标行对不上 ⟹ `not_found` 且**不写**（宁可少改，不改错）。"""
    d = _mk(tmp_path, ":1")
    bogus = [{"doc": "p.md", "doc_line": 1,
              "old": "scripts/gk_demo.py:999", "new": "scripts/gk_demo.py:11"}]
    r = apply_edits(str(d), bogus, apply=True)
    assert r[0]["status"] == "not_found", r
    assert "scripts/gk_demo.py:1 " in _doc(d).read_text(encoding="utf-8"), "对不上却写了"


def test_crlf_preserved(tmp_path):
    """判据⑤：CRLF 文档改写后仍是 CRLF（否则整份文档变成 LF 大 diff）。"""
    d = _mk(tmp_path, ":1")
    f = _doc(d)
    f.write_bytes((_ANCHOR % ":1" + "\r\n第二行\r\n").encode("utf-8"))
    assert "\r\n" in f.open(encoding="utf-8", newline="").read()
    p = plan_edits(str(d), ["p.md"])
    assert apply_edits(str(d), p["edits"], apply=True)[0]["status"] == "applied"
    assert "\r\n" in f.open(encoding="utf-8", newline="").read(), "CRLF 被改写成 LF"


def test_map_pairs_applied_without_prefix_damage(tmp_path):
    """判据⑧：`mapping` 显式对（old→new）⟹ 按对精确改写，且**不误伤前缀相同者**。

    用途（实测 2026-09-19）：一批 `literal_outside_range` 锚的真值**不在** `rebase_plan.repin`
    里（如 `gatekeeper-cli.sh:199` 在 doc-align 侧连 `content_drift` 都不是），而工具的
    「最近命中」对高频字面量又是**错值** ⟹ 真值只能读码定，再由本参数机械落盘。
    `:199` 是 `:1991` 的前缀：无边界保护会把 `:1991` 改成 `:2191`（**静默串改**）。
    """
    d = _mk(tmp_path, ":1")
    _doc(d).write_text((_ANCHOR % ":12") + "\n" + (_ANCHOR % ":1") + "\n", encoding="utf-8")
    p = plan_edits(str(d), ["p.md"],
                   mapping={"scripts/gk_demo.py:1": "scripts/gk_demo.py:11"})
    assert len(p["edits"]) == 1, f"前缀相同者被误伤（`:12` 被当成 `:1`）：{p['edits']}"
    e = p["edits"][0]
    assert e["doc_line"] == 2 and e["old"] == "scripts/gk_demo.py:1", e
    assert e["new"] == "scripts/gk_demo.py:11", e
    r = apply_edits(str(d), p["edits"], apply=True)
    assert r[0]["status"] == "applied", r
    txt = _doc(d).read_text(encoding="utf-8")
    assert "scripts/gk_demo.py:12" in txt, f"前缀锚被串改：{txt}"
    assert "scripts/gk_demo.py:11 route" in txt, txt


def test_map_hashl_pair_is_bounded(tmp_path):
    """A2 回归臂（ECC-F68E6BEE4F68）：`--map` 对 `#L` 形态（含区间 `#L102-L109`）可落刀。

    ⚠ **非红先**：本臂在 A2 落刀前即绿 —— 实证（2026-09-29）`--map` 的既有有界判据
    （`old` 之后不得紧跟数字或连字符）对 `#L` 键本已成立（`#L102-L109` 之后是 `)` / 空格）。
    落此臂是为把「A2 的 `#L` 面经 `--map` 可重钉」钉成回归（此前无任何 `#L` 面测试）。"""
    d = _mk(tmp_path, "#L102-L109")
    p = plan_edits(str(d), ["p.md"], mapping={"scripts/gk_demo.py#L102-L109":
                                              "scripts/gk_demo.py#L11-L18"})
    assert len(p["edits"]) == 1, f"`#L` 区间键被有界判据误杀：{p['edits']}"
    assert p["edits"][0]["old"] == "scripts/gk_demo.py#L102-L109", p["edits"][0]
    r = apply_edits(str(d), p["edits"], apply=True)
    assert r and r[0]["status"] == "applied", r
    txt = _doc(d).read_text(encoding="utf-8")
    assert "scripts/gk_demo.py#L11-L18 route" in txt, txt


def test_map_hashl_prefix_is_not_corrupted(tmp_path):
    """A2 回归臂（非红先）：`#L1` 键**不得**命中 `#L11`（数字边界）—— 否则是静默串改。"""
    d = _mk(tmp_path, "#L11")
    p = plan_edits(str(d), ["p.md"], mapping={"scripts/gk_demo.py#L1":
                                              "scripts/gk_demo.py#L99"})
    assert p["edits"] == [], f"`#L` 前缀形态被误伤：{p['edits']}"


def test_apply_false_is_read_only(tmp_path):
    """判据⑥：默认（不传 `--apply`）只预览不落盘。"""
    d = _mk(tmp_path, ":1")
    p = plan_edits(str(d), ["p.md"])
    r = apply_edits(str(d), p["edits"], apply=False)
    assert r[0]["status"] == "preview", r
    assert "scripts/gk_demo.py:1 " in _doc(d).read_text(encoding="utf-8")


def test_hashl_anchor_is_repinnable(tmp_path):
    """A2 红先臂（ECC-F68E6BEE4F68）：`#L` 形态锚此前对锚提取器**完全不可见**
    （`iter_anchor_refs(loose=True)` 只认 `path:line`）⟹ `plan_edits` 排不出任何 edits。
    钉死三件：① `#L` 锚可见；② 可落刀（rule #6 逐条校验语义不变）；③ **写回仍是 `#L`**
    形态（不混入第二套锚口径）。"""
    d = _mk(tmp_path, "#L1")
    p = plan_edits(str(d), ["p.md"])
    assert len(p["edits"]) == 1, f"`#L` 锚未进重钉面（A2 未落刀时此处为 0）：{p}"
    e = p["edits"][0]
    assert e["old"] == "scripts/gk_demo.py#L1", e
    assert e["new"] == "scripts/gk_demo.py#L11", e
    r = apply_edits(str(d), p["edits"], apply=True)
    assert r and r[0]["status"] == "applied", r
    assert "scripts/gk_demo.py#L11 route" in _doc(d).read_text(encoding="utf-8")

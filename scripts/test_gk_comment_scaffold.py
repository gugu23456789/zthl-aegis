"""test_gk_comment_scaffold.py — 注释骨架登记表与发生器的安全网（2026-11-10）。

红先形态：本模块落刀前 `gk_comment_scaffold.py` 与 `references/comment-templates.json`
均不存在 ⟹ 整体 ImportError/FileNotFoundError。故回归面 = 登记表自洽 + 禁止第二份名单
+ 渲染 fail-loud + check 规则命中/不误伤 + promote 回环闸。

安全网：只读仓内登记表；不 patch 全局；tmp 文件仅用于 check/promote 的行为臂。
"""
import json
import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).parent
_REG = _HERE.parent / "references" / "comment-templates.json"
sys.path.insert(0, str(_HERE))

import gk_comment_scaffold as cs  # noqa: E402


# ── 登记表自洽 ────────────────────────────────────────────────
def test_module_and_registry_exist():
    assert (_HERE / "gk_comment_scaffold.py").is_file()
    assert _REG.is_file()


def test_registry_self_consistent():
    reg = cs.load_registry()
    positions = set(reg["positions"])
    for t in reg["templates"]:
        body = t["body"]
        need = set(cs._PH_RE.findall(body))
        declared = set(t["placeholders"])
        assert need == declared, "%s: body 占位符 %s ≠ 声明 %s" % (t["id"], need, declared)
        assert need, "%s: body 至少要含 1 个占位符" % t["id"]
        assert t["position"] in positions, "%s: 未登记位置 %s" % (t["id"], t["position"])
        assert t["keywords"], "%s: 缺 keywords" % t["id"]
        assert set(t.get("lang") or []) <= {"py", "sh"}, "%s: lang 非法" % t["id"]


def test_ids_unique_and_no_second_list():
    reg = cs.load_registry()
    ids = cs.template_ids(reg)
    assert ids and all(ids)
    assert len(ids) == len(set(ids))
    assert ids == [t["id"] for t in reg["templates"]]


def test_every_position_has_template():
    reg = cs.load_registry()
    have = {t["position"] for t in reg["templates"]}
    assert have == set(reg["positions"]), "位置登记与模版覆盖不一致: %s" % (set(reg["positions"]) - have)


def test_every_template_renders_with_own_placeholders():
    reg = cs.load_registry()
    for t in reg["templates"]:
        vals = {p.strip("{}"): "X" for p in t["placeholders"]}
        code = cs.render(t["id"], vals, reg)
        assert not cs._PH_RE.findall(code), "%s 渲染后有残留" % t["id"]


# ── 渲染 fail-loud ───────────────────────────────────────────
def test_render_rejects_missing_extra_and_unknown():
    vals = {p.strip("{}"): "X" for p in cs.get_template("anchor-line")["placeholders"]}
    for bad in ({"date": "X"}, {**vals, "extra": "X"}):
        with pytest.raises(ValueError):
            cs.render("anchor-line", bad)
    with pytest.raises(ValueError):
        cs.render("no-such-template", vals)


# ── 分类 / 骨架 ───────────────────────────────────────────────
def test_classify_uses_position_as_hard_filter():
    c = cs.classify("事故 根因 判据 防线", position="incident")
    assert c["decision"] == "reuse" and c["id"] == "incident-replay"
    c2 = cs.classify("锚点 净 0 行", position="anchor-line")
    assert c2["decision"] == "reuse" and c2["id"] == "anchor-line"


def test_classify_unknown_position_loud():
    with pytest.raises(ValueError):
        cs.classify("x", position="no-such-position")


def test_scaffold_incomplete_is_not_a_deliverable():
    out = cs.scaffold("锚点 净 0 行", position="anchor-line", values={"date": "2026-11-10"})
    assert out["decision"] == "reuse"
    assert out["code"] == "" and out["missing"]
    assert "{date}" in out["skeleton"]


def test_scaffold_complete_renders():
    vals = {p.strip("{}"): "X" for p in cs.get_template("anchor-line")["placeholders"]}
    out = cs.scaffold("锚点 净 0 行", position="anchor-line", values=vals)
    assert out["code"] and not out["missing"] and "{" not in out["code"]


def test_scaffold_new_shape_returns_empty_draft():
    out = cs.scaffold("完全无关的词汇组合", position="inline-why")
    assert out["decision"] == "new"
    assert out["draft"]["body"] == ""


# ── check：命中 ──────────────────────────────────────────────
def _rules(res):
    return {v["rule"] for v in res["violations"]}


def test_check_clean_anchor_has_no_findings():
    text = ("#!/bin/bash\n"
            "# 2026-11-10 R7.7：新增 --x；为什么必须逐字；**净 0 行**；证据：test_foo\n"
            "set -uo pipefail\n")
    res = cs.check_text(text, ext=".sh")
    assert res["ok"] is True
    assert res["summary"]["ERROR"] == 0


def test_check_hits_future_date_bare_todo_what_and_residual():
    text = ("#!/bin/bash\n"
            "# 2030-01-01 R1：未来日期\n"
            "# TODO: 裸待办\n"
            "# 设置变量\n"
            "# 未填槽位 {why}\n")
    res = cs.check_text(text, ext=".sh")
    rules = _rules(res)
    assert "anchor-date-future" in rules
    assert "todo-bare" in rules
    assert "comment-what" in rules
    assert "placeholder-residual" in rules
    assert res["ok"] is False
    assert res["summary"]["ERROR"] == 2


def test_check_flags_overlong_hash_block_but_not_docstring():
    long_block = "\n".join("# 说明第 %d 行" % i for i in range(21))
    res = cs.check_text(long_block + "\n", ext=".sh")
    assert "comment-block-too-long" in _rules(res)

    doc = '"""\n' + "\n".join("契约第 %d 行" % i for i in range(25)) + '\n"""\n'
    res2 = cs.check_text(doc, ext=".py")
    assert "comment-block-too-long" not in _rules(res2)


def test_check_ratio_budget():
    text = "\n".join("# 注释 %d" % i for i in range(40)) + "\ncode\n"
    res = cs.check_text(text, ext=".sh", path="scripts/x.sh")
    assert "comment-ratio-over" in _rules(res)


# ── check_file / changed_only ───────────────────────────────
def test_check_file_reads_disk_and_reports_unavailable_changed_only(tmp_path):
    p = tmp_path / "sample.sh"
    p.write_text("# TODO: 裸待办\n", encoding="utf-8")
    res = cs.check_file(str(p), changed_only=True)
    assert res["file"] == str(p)
    assert "todo-bare" in _rules(res)
    assert str(res.get("changed_only", "")).startswith("unavailable")


def test_check_file_missing_loud(tmp_path):
    with pytest.raises(ValueError):
        cs.check_file(str(tmp_path / "nope.sh"))


# ── promote 回环 ─────────────────────────────────────────────
def _draft(**kw):
    d = {"id": "unit-test-shape", "position": "inline-why", "desc": "单测形态",
         "when": "单测", "keywords": ["单测", "unit"],
         "placeholders": ["{id}", "{date}"],
         "body": "# {id}（{date}）：测试用形态 —— 不要回灌到生产表"}
    d.update(kw)
    return d


def _registry_copy(tmp_path):
    p = tmp_path / "comment-templates.json"
    p.write_text(_REG.read_text(encoding="utf-8"), encoding="utf-8")
    return p


def test_promote_rejects_incomplete_or_duplicate(tmp_path):
    reg = _registry_copy(tmp_path)
    ev = tmp_path / "ev.sh"
    ev.write_text("# UT（2026-11-10）：测试用形态 —— 不要回灌到生产表\n", encoding="utf-8")
    with pytest.raises(ValueError):
        cs.promote({"id": "x"}, str(reg), str(ev))
    with pytest.raises(ValueError):
        cs.promote(_draft(position="no-such"), str(reg), str(ev))
    with pytest.raises(ValueError):
        cs.promote(_draft(id="anchor-line"), str(reg), str(ev))
    with pytest.raises(ValueError):
        cs.promote(_draft(body="# 无占位符"), str(reg), str(ev))


def test_promote_rejects_unused_or_failing_evidence(tmp_path):
    reg = _registry_copy(tmp_path)
    unused = tmp_path / "unused.sh"
    unused.write_text("# 无关注释\n", encoding="utf-8")
    with pytest.raises(ValueError):
        cs.promote(_draft(), str(reg), str(unused))

    used = tmp_path / "used.sh"
    used.write_text("# UT（2026-11-10）：测试用形态 —— 不要回灌到生产表\n", encoding="utf-8")
    with pytest.raises(ValueError):
        cs.promote(_draft(), str(reg), str(used),
                   checker=lambda f: {"summary": {"ERROR": 1}})


def test_promote_accepts_used_clean_evidence_and_bumps_version(tmp_path):
    reg = _registry_copy(tmp_path)
    before = json.loads(reg.read_text(encoding="utf-8"))
    used = tmp_path / "used.sh"
    used.write_text("# UT（2026-11-10）：测试用形态 —— 不要回灌到生产表\n", encoding="utf-8")
    out = cs.promote(_draft(), str(reg), str(used))
    assert out["ok"] is True
    after = json.loads(reg.read_text(encoding="utf-8"))
    assert after["version"] == before["version"] + 1
    assert "unit-test-shape" in cs.template_ids(after)


# ── CLI 冒烟 ────────────────────────────────────────────────
def test_cli_list_and_check_missing(capsys):
    assert cs.main(["list"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True and "anchor-line" in out["ids"]
    assert cs.main(["check", str(Path("no/such/file.sh"))]) == 2

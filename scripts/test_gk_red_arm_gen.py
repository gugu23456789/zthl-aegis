"""test_gk_red_arm_gen.py — 红先模版发生器安全网（2026-09-23，用户裁定「扩展红先测试模版」）。

红先形态说明：本模块是**新增**能力，落刀前 `gk_red_arm_gen` 与
`references/red-arm-templates.json` 均不存在 ⟹ 本文件整体 ImportError/FileNotFoundError
（`api-absent` 形态的红先）。故此处以「登记表自洽 + 禁止第二份名单 + fail-loud」为回归面。

安全网 R1：只读仓内文件；不 patch 标准库全局；不产副作用。
"""
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).parent
_REG = _HERE.parent / "references" / "red-arm-templates.json"
sys.path.insert(0, str(_HERE))

import gk_red_arm_gen as gen  # noqa: E402

# 2026-11-09 扩展形态（本批「大幅刷新」的 8 个新形状；红先：HEAD 版登记表尚无这些 id）
NEW_SHAPES = [
    "fail-open-to-fail-loud",
    "generated-artifact-sync",
    "required-subset-registry",
    "cross-copy-equality",
    "consumer-wiring",
    "empty-vs-missing-loud",
    "snapshot-pollution-guard",
    "tamper-flip-detector",
]


def test_module_and_registry_exist():
    """落刀前置：模块与登记表实存（红先时二者皆无）。"""
    assert (_HERE / "gk_red_arm_gen.py").is_file()
    assert (_HERE.parent / "references" / "red-arm-templates.json").is_file()


def test_registry_self_consistent():
    """每条模版：body 内占位符集合 ⊇/== 声明的 placeholders（防声明与体漂移）。"""
    reg = gen.load_registry()
    for t in reg["templates"]:
        body = t["body"]
        need = set(gen._PH_RE.findall(body))
        declared = set(t["placeholders"])
        assert need == declared, "%s: body 占位符 %s ≠ 声明 %s" % (t["id"], need, declared)


def test_ids_unique_and_nonempty():
    reg = gen.load_registry()
    ids = gen.template_ids(reg)
    assert ids and all(ids), f"模版 id 不得为空: {ids}"
    assert len(ids) == len(set(ids)), f"模版 id 重复: {ids}"


def test_no_second_template_list():
    """禁止第二份名单：`template_ids()` 必须**逐字**等于登记表内的 id 序列。"""
    reg = gen.load_registry()
    assert gen.template_ids(reg) == [t["id"] for t in reg["templates"]]


def test_every_template_renders_with_its_own_placeholders():
    """每条模版都能用「它自己声明的占位符」渲染成功（防某条被写坏却无人发现）。

    判据 = **无 `{word}` 形态残留**（不能用「无花括号」——模版体合法含字面 `{{`，
    如 python 源码里的 `"() {{"`；上线当天此过严断言曾误红）。
    """
    reg = gen.load_registry()
    for t in reg["templates"]:
        vals = {p.strip("{}"): "X" for p in t["placeholders"]}
        out = gen.render(t["id"], vals, reg)
        assert gen._PH_RE.findall(out) == [], "%s 渲染后有占位符残留" % t["id"]


def test_render_substitutes_values():
    out = gen.render("source-absence", {
        "target": "demo", "func": "cmd_demo", "must_have": "A",
        "must_absent": "B", "head_count_cmd": "count"})
    assert "A" in out and "B" in out and "count" in out
    assert "{" not in out and "}" not in out


class TestFailLoud:
    def test_unknown_id(self):
        with pytest.raises(ValueError) as e:
            gen.render("no-such-template", {})
        assert "未知模版 id" in str(e.value)

    def test_missing_placeholder(self):
        with pytest.raises(ValueError) as e:
            gen.render("source-absence", {"target": "t"})
        assert "缺占位符" in str(e.value)

    def test_extra_key_rejected(self):
        vals = {"target": "t", "func": "f", "must_have": "a",
                "must_absent": "b", "head_count_cmd": "c", "bogus": "d"}
        with pytest.raises(ValueError) as e:
            gen.render("source-absence", vals)
        assert "多余键" in str(e.value)

    def test_cli_render_rc2_on_error(self, capsys):
        assert gen.main(["render", "no-such"]) == 2
        assert json.loads(capsys.readouterr().out)["ok"] is False

    def test_cli_list_ok(self, capsys):
        assert gen.main(["list"]) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["ok"] is True and out["ids"]


# ── 2026-11-09：扩展形态 + 自动判定/骨架/回灌闭环（红先新增面）──────────────
def test_registry_has_extended_shapes():
    ids = set(gen.template_ids())
    missing = [i for i in NEW_SHAPES if i not in ids]
    assert not missing, f"扩展形态未登记: {missing}"
    assert len(ids) >= 20, f"模版数应 ≥20（大幅刷新），实际 {len(ids)}"


def test_every_template_has_classify_metadata():
    """分类器只读登记表 ⟹ 每条必须有 keywords/when/desc（防第二份形态清单）。"""
    for t in gen.load_registry()["templates"]:
        assert isinstance(t.get("keywords"), list) and t["keywords"], f"{t.get('id')}: 缺 keywords"
        assert str(t.get("when") or "").strip(), f"{t.get('id')}: 缺 when"
        assert str(t.get("desc") or "").strip(), f"{t.get('id')}: 缺 desc"


class TestClassify:
    def test_reuse_fail_open_to_fail_loud(self):
        r = gen.classify("把 ⑦ 的 fail-open 改成 fail-loud：缺失基线和空单元格也要 WARN")
        assert r["decision"] == "reuse"
        assert r["id"] == "fail-open-to-fail-loud", r

    def test_reuse_generated_artifact_sync(self):
        r = gen.classify("新增自动生成登记表，用 --check 防漂移")
        assert r["decision"] == "reuse"
        assert r["id"] == "generated-artifact-sync", r

    def test_reuse_cross_copy(self):
        r = gen.classify("双副本常量被单边篡改，需要差分检出")
        assert r["decision"] == "reuse"
        assert r["id"] == "cross-copy-equality", r

    def test_new_when_unmatched(self):
        r = gen.classify("把界面按钮颜色改成蓝色")
        assert r["decision"] == "new", r


class TestScaffold:
    def test_reuse_exports_skeleton(self):
        r = gen.scaffold("fail-open 改 fail-loud，缺失基线要 loud")
        assert r["decision"] == "reuse"
        assert r["skeleton"].count("{") >= 1, "骨架必须保留占位符"
        assert r["missing"], "未给值时 missing 必须非空（不能伪装成已填充）"

    def test_reuse_fills_code_when_all_values_given(self):
        t = gen.get_template("fail-open-to-fail-loud")
        vals = {p.strip("{}"): "X" for p in t["placeholders"]}
        r = gen.scaffold("fail-open 改 fail-loud，缺失基线要 loud", values=vals)
        assert r["decision"] == "reuse" and r["missing"] == []
        assert gen._PH_RE.findall(r["code"]) == []

    def test_new_returns_draft(self):
        r = gen.scaffold("完全无关的界面颜色调整", id_hint="ui-color")
        assert r["decision"] == "new"
        assert r["draft"]["id"] == "ui-color"
        assert r["draft"]["body"] == "", "新形态草案不得伪造已写好的臂"


def _draft(**kw) -> dict:
    d = {
        "id": "demo-new-shape",
        "desc": "示例新形态",
        "when": "改动是示例面时",
        "keywords": ["示例", "demo"],
        "placeholders": ["{target}", "{anchor}"],
        "body": 'def test_{target}():\n    assert "{anchor}" in _txt()',
        "test_file": "scripts/test_demo.py",
        "shape_k": "test_demo",
        "rev": "HEAD~1",
    }
    d.update(kw)
    return d


class TestPromote:
    def _runner_ok(self, rev, test_file, k, expect):
        return 0

    def test_promote_appends_and_bumps_version(self, tmp_path):
        reg = tmp_path / "reg.json"
        shutil.copy(_REG, reg)
        before = json.loads(reg.read_text(encoding="utf-8"))
        r = gen.promote(_draft(), str(reg), runner=self._runner_ok)
        after = json.loads(reg.read_text(encoding="utf-8"))
        assert r["ok"] is True
        assert after["version"] == before["version"] + 1
        assert "demo-new-shape" in [t["id"] for t in after["templates"]]

    def test_promote_rejects_duplicate_id(self, tmp_path):
        reg = tmp_path / "reg.json"
        shutil.copy(_REG, reg)
        with pytest.raises(ValueError) as e:
            gen.promote(_draft(id="source-absence"), str(reg), runner=self._runner_ok)
        assert "已存在" in str(e.value)

    def test_promote_requires_red_then_green(self, tmp_path):
        reg = tmp_path / "reg.json"
        shutil.copy(_REG, reg)

        def red_fail(rev, test_file, k, expect):
            return 1 if expect == "red" else 0

        with pytest.raises(ValueError) as e:
            gen.promote(_draft(), str(reg), runner=red_fail)
        assert "红" in str(e.value)
        assert "demo-new-shape" not in [t["id"] for t in json.loads(
            reg.read_text(encoding="utf-8"))["templates"]], "红未达成不得回灌"

    def test_promote_rejects_placeholder_drift(self, tmp_path):
        reg = tmp_path / "reg.json"
        shutil.copy(_REG, reg)
        with pytest.raises(ValueError) as e:
            gen.promote(_draft(placeholders=["{target}"]), str(reg), runner=self._runner_ok)
        assert "占位符" in str(e.value)


class TestDocAlignKeywordsGuard:
    def test_doc_align_flags_missing_keywords(self, tmp_path):
        """登记表条目缺 keywords → doc-align 必须 FAIL（HEAD 版忽略 keywords ⟹ 红）。"""
        import gk_doc_align as gda

        (tmp_path / "references").mkdir()
        (tmp_path / "scripts").mkdir()
        shutil.copy(_HERE / "gk_red_arm_gen.py", tmp_path / "scripts" / "gk_red_arm_gen.py")
        reg = json.loads(_REG.read_text(encoding="utf-8"))
        reg["templates"] = [dict(reg["templates"][0])]
        reg["templates"][0].pop("keywords", None)
        (tmp_path / "references" / "red-arm-templates.json").write_text(
            json.dumps(reg, ensure_ascii=False), encoding="utf-8")
        (tmp_path / "SKILL.md").write_text("references/red-arm-templates.json", encoding="utf-8")
        r = gda.check_red_arm_templates(str(tmp_path))
        assert r["status"] == "FAIL"
        assert "keywords" in r["detail"]

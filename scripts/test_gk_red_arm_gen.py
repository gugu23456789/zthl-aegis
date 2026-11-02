"""test_gk_red_arm_gen.py — 红先模版发生器安全网（2026-09-23，用户裁定「扩展红先测试模版」）。

红先形态说明：本模块是**新增**能力，落刀前 `gk_red_arm_gen` 与
`references/red-arm-templates.json` 均不存在 ⟹ 本文件整体 ImportError/FileNotFoundError
（`api-absent` 形态的红先）。故此处以「登记表自洽 + 禁止第二份名单 + fail-loud」为回归面。

安全网 R1：只读仓内文件；不 patch 标准库全局；不产副作用。
"""
import json
import os
import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE))

import gk_red_arm_gen as gen  # noqa: E402


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

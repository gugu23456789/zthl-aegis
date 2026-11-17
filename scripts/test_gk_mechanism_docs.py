"""test_gk_mechanism_docs.py — 机制正本闸的红先臂（2026-11-16）。

病象：v0.10.0 之前的 260 个提交里，工作目录池 / 合并闸 / 发布管线 / 审计生命周期
四个机制都没有对外正本文档；文档面全靠人记，机制一改就静默滞后。

本闸的两条判据（全部确定性、零网络）：
  A. **登记即闭环**：每个登记机制的正本文档必须带 GK-MECH 事实块，块内容 = 从活代码
     重新派生的结果（入口脚本 / 公开函数数 / CLI 入口 / 测试 / 校验命令）；漂移即红。
  B. **新增即登记**：`prev..HEAD` 新增的 `scripts/gk_*.py` 必须落在某个机制的入口清单里，
     否则要么补正本、要么在登记表里写明豁免理由（禁静默漏登记）。
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gk_mechanism_docs as M  # noqa: E402

SD = Path(__file__).resolve().parent.parent

_DOC = """# 演示机制（机制正本）

{start}
{body}
{end}
"""


def _tree(tmp_path, registry=None, doc_body=None):
    """最小夹具树：两个入口脚本 + 一份带标记的正本文档 + CLI 注册面。"""
    (tmp_path / "scripts").mkdir()
    (tmp_path / "references").mkdir()
    (tmp_path / "scripts" / "gk_demo_a.py").write_text(
        "def alpha():\n    pass\n\ndef beta():\n    pass\n\ndef _hidden():\n    pass\n",
        encoding="utf-8")
    (tmp_path / "scripts" / "gk_demo_b.py").write_text(
        "def gamma():\n    pass\n", encoding="utf-8")
    (tmp_path / "scripts" / "test_gk_demo_a.py").write_text("def test_x():\n    pass\n",
                                                            encoding="utf-8")
    (tmp_path / "gatekeeper-cli.sh").write_text(
        '_CMD_REG[demo]="cmd_demo|none|any|"\n', encoding="utf-8")
    reg = registry or {
        "schema": "gk-mechanism-registry/1",
        "coverage": {"glob": "scripts/gk_*.py", "waivers": []},
        "mechanisms": [{
            "id": "demo",
            "title": "演示机制",
            "doc": "references/demo.md",
            "entrypoints": ["scripts/gk_demo_a.py", "scripts/gk_demo_b.py"],
            "cli": ["demo"],
            "tests": ["scripts/test_gk_demo_a.py"],
        }],
        "security_invariants": [],
    }
    (tmp_path / "references" / "mechanism-registry.json").write_text(
        json.dumps(reg, ensure_ascii=False), encoding="utf-8")
    mech = (reg.get("mechanisms") or [{}])[0]
    start = M.block_start(mech.get("id", "demo"))
    end = M.block_end(mech.get("id", "demo"))
    (tmp_path / "references" / "demo.md").write_text(
        _DOC.format(start=start, body=doc_body if doc_body is not None else
                    "（待生成）", end=end), encoding="utf-8")
    return tmp_path


def test_render_block_derives_from_live_code(tmp_path):
    sd = _tree(tmp_path)
    block = M.render_block(M.load_registry(sd)["mechanisms"][0], sd)
    assert "`gk_demo_a.py`" in block and "`gk_demo_b.py`" in block, block
    assert "| 公开函数 | 3（demo_a 2 / demo_b 1）" in block, block
    assert "`demo`" in block and "`scripts/test_gk_demo_a.py`" in block, block
    assert block.startswith(M.block_start("demo")) and block.endswith(M.block_end("demo"))


def test_write_makes_tree_clean_then_idempotent(tmp_path):
    sd = _tree(tmp_path)
    first = M.write(sd)
    assert first["ok"] and "references/demo.md" in first["changed"], first
    assert M.check(sd)["ok"], M.check(sd)
    assert M.write(sd)["changed"] == [], "二次写必须幂等"


def test_check_detects_block_drift(tmp_path):
    sd = _tree(tmp_path)
    M.write(sd)
    doc = sd / "references" / "demo.md"
    doc.write_text(doc.read_text(encoding="utf-8").replace("| 公开函数 | 3", "| 公开函数 | 99"),
                   encoding="utf-8")
    r = M.check(sd)
    assert not r["ok"] and any("--write" in i for i in r["issues"]), r


def test_check_detects_missing_doc(tmp_path):
    sd = _tree(tmp_path)
    (sd / "references" / "demo.md").unlink()
    r = M.check(sd)
    assert not r["ok"] and any("正本文档缺失" in i for i in r["issues"]), r


def test_check_detects_missing_entrypoint(tmp_path):
    sd = _tree(tmp_path)
    M.write(sd)                      # 先让块与代码一致，再删入口
    (sd / "scripts" / "gk_demo_b.py").unlink()
    r = M.check(sd)
    assert not r["ok"] and any("入口脚本缺失" in i for i in r["issues"]), r


def test_check_detects_missing_markers(tmp_path):
    sd = _tree(tmp_path)
    (sd / "references" / "demo.md").write_text("# 演示机制\n\n没有事实块。\n", encoding="utf-8")
    r = M.check(sd)
    assert not r["ok"] and any("GK-MECH" in i for i in r["issues"]), r


def test_unregistered_new_script_is_red_and_waiver_clears(tmp_path):
    """新增机制脚本必须登记；豁免必须带 reason（禁静默放过）。"""
    sd = _tree(tmp_path)
    M.write(sd)
    r = M.check(sd, added=["scripts/gk_new_mech.py"])
    assert not r["ok"] and any("未登记" in i for i in r["issues"]), r

    reg = json.loads((sd / "references" / "mechanism-registry.json").read_text(encoding="utf-8"))
    reg["coverage"]["waivers"] = [{"pattern": "scripts/gk_new_mech.py",
                                   "reason": "内部工具，无对外机制面"}]
    (sd / "references" / "mechanism-registry.json").write_text(
        json.dumps(reg, ensure_ascii=False), encoding="utf-8")
    assert M.check(sd, added=["scripts/gk_new_mech.py"])["ok"]


def test_waiver_requires_reason(tmp_path):
    reg_path = None
    sd = _tree(tmp_path)
    reg_path = sd / "references" / "mechanism-registry.json"
    reg = json.loads(reg_path.read_text(encoding="utf-8"))
    reg["coverage"]["waivers"] = [{"pattern": "scripts/gk_new_mech.py"}]
    reg_path.write_text(json.dumps(reg, ensure_ascii=False), encoding="utf-8")
    r = M.check(sd, added=["scripts/gk_new_mech.py"])
    assert not r["ok"] and any("reason" in i for i in r["issues"]), r


def test_cli_key_missing_is_red(tmp_path):
    sd = _tree(tmp_path)
    M.write(sd)
    (sd / "gatekeeper-cli.sh").write_text("# no commands\n", encoding="utf-8")
    r = M.check(sd)
    assert not r["ok"] and any("CLI 入口" in i for i in r["issues"]), r


def test_real_tree_mechanisms_are_clean():
    """仓内四个机制正本必须与活代码一致（本文件即闸的常驻臂）。"""
    r = M.check(SD)
    assert r["ok"], r["issues"]


def test_real_tree_registry_covers_known_mechanisms():
    ids = {m["id"] for m in M.load_registry(SD)["mechanisms"]}
    assert {"merge-gate", "worktree-pool", "audit-lifecycle", "release-pipeline"} <= ids

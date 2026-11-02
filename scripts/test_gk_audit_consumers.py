#!/usr/bin/env python3
"""AUDIT 证据消费者登记表不变量（2026-10-28，B3a）。

覆盖审计署计划 §27.1 的「只登记式消费者映射」验收要求：
  正向 —— 每个登记项的文件 / 符号 / 行为臂必须**实存**（先落臂再引用，防幻影载体）；
  反向 —— 仓内对 `audit_state_result` / `audit_docs_result` 的**直接读点**必须**全部登记**
          （防 B3b 漏改；第三轮质询 G2 的清单漏项正是此面）。

两栏禁混（质询 G2）：`domain="eco"` 项不得计入 AUDIT 派发域；写方（`cmd_audit` /
`audit --all` 聚合器）禁列。
"""
import ast
import json
import re
from pathlib import Path

import gk_node_guard

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent

# 直接读点正则：只认「取值语法」，不认 docstring / 注释里的裸键名。
_READ_RE = re.compile(r"""\.get\(\s*["']audit_(?:state|docs)_result["']"""
                      r"""|\[\s*["']audit_(?:state|docs)_result["']\s*\]""")
_DELEGATE_RE = re.compile(r"audit_all_recorded\(|report_evidence_ok\(|review_exit_gate\(")
# E25 B3a（2026-10-30）：**动态域读点** —— 键集由 `domains` 参数驱动（`in domains` 迭代 / 推导），
#   字面键正则（`_READ_RE`）对此类读点是**盲区**（`gk_audit_registry.dual_read` 即此形态）。
_DYNAMIC_READ_RE = re.compile(r"\bin\s+domains\b")

_REGISTRY = gk_node_guard.AUDIT_EVIDENCE_CONSUMERS


def _tree(rel: str):
    p = SCRIPTS / rel
    return p, ast.parse(p.read_text(encoding="utf-8"))


def _functions(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def _segment(tree, src: str, name: str):
    for node in _functions(tree):
        if node.name == name:
            return ast.get_source_segment(src, node) or ""
    return None


def _direct_readers(rel: str):
    p, tree = _tree(rel)
    src = p.read_text(encoding="utf-8")
    out = set()
    for node in _functions(tree):
        seg = ast.get_source_segment(src, node) or ""
        if _READ_RE.search(seg):
            out.add(node.name)
    return out


def _dynamic_domain_readers(rel: str):
    """动态域读点：函数内出现 `in domains` 迭代（键集由参数驱动 ⟹ `_READ_RE` 盲区）。

    不解析「读了哪个 dict」——`in domains` 在本仓是**唯一**的动态域信号（E25 实测），
    保持判据确定性；新增动态读点时必须显式登记（先落臂再引用）。
    """
    p, tree = _tree(rel)
    src = p.read_text(encoding="utf-8")
    out = set()
    for node in _functions(tree):
        seg = ast.get_source_segment(src, node) or ""
        if _DYNAMIC_READ_RE.search(seg):
            out.add(node.name)
    return out


def _all_test_sources():
    return {p: p.read_text(encoding="utf-8", errors="ignore")
            for p in SCRIPTS.glob("test_*.py")}


def test_registry_shape_two_columns_not_mixed():
    assert isinstance(_REGISTRY, tuple) and len(_REGISTRY) >= 6, _REGISTRY
    domains = {e["domain"] for e in _REGISTRY}
    assert domains == {"audit", "eco"}, domains
    eco = [e for e in _REGISTRY if e["domain"] == "eco"]
    assert [e["symbol"] for e in eco] == ["_eco_prereq_heuristic"], eco
    # 写方禁列（生产者不是消费者）
    assert "cmd_audit" not in {e["symbol"] for e in _REGISTRY}
    # 必备五读点（质询 G2 补齐后的 AUDIT 面）
    ids = {e["id"] for e in _REGISTRY if e["domain"] == "audit"}
    assert {"review_exit_gate", "report_evidence_ok", "guard_cli_inject",
            "audit_link_view", "redteam_findings", "cli_audit_link"} <= ids, ids


def test_every_entry_anchor_exists_and_kind_matches():
    for e in _REGISTRY:
        if e["file"].endswith(".sh"):
            src = (ROOT / e["file"]).read_text(encoding="utf-8", errors="ignore")
            assert e["symbol"] in src, e
            # 该 CLI 读点必须真的转调 gk_views 的 audit-link 视图
            assert re.search(r"gk_views\.py[\"']?\s+audit-link", src), e
            continue
        p, tree = _tree(e["file"])
        src = p.read_text(encoding="utf-8")
        seg = _segment(tree, src, e["symbol"])
        assert seg is not None, "登记符号不存在: %s" % e
        if e["kind"] == "reader":
            assert _READ_RE.search(seg), "reader 未直接读键: %s" % e
        elif e["kind"] == "dynamic_reader":
            assert _DYNAMIC_READ_RE.search(seg), "dynamic_reader 未迭代 domains: %s" % e
        else:
            assert e["kind"] == "delegate", e
            assert _DELEGATE_RE.search(seg), "delegate 未走单一事实源: %s" % e


def test_reverse_no_unregistered_direct_reader():
    """反向不变量：三份产码文件里的直接读点必须与登记表 reader 栏**逐一相等**。"""
    scanned = set()
    for rel in ("gk_node_guard.py", "gk_views.py", "gk_advance.py",
                "gk_audit_findings.py"):
        for name in _direct_readers(rel):
            scanned.add((rel, name))
    declared = {(e["file"], e["symbol"]) for e in _REGISTRY if e["kind"] == "reader"}
    assert scanned == declared, {
        "unregistered_readers": sorted(scanned - declared),
        "stale_registry_entries": sorted(declared - scanned),
    }


def test_reverse_no_unregistered_dynamic_domain_reader():
    """反向不变量（E25 B3a，2026-10-30）：**动态域读点**必须与字面读点同入登记。

    病象（一轮六臂质询 WARN）：原反向面只认 `_READ_RE`（字面键）⟹
    `gk_audit_registry.register/dual_read` 用 `domains` 参数动态读**同一批键**，
    却完全不在不变量面内（「反向读点无遗漏」= over-claim）。
    """
    scanned = set()
    for p in sorted(SCRIPTS.glob("gk_*.py")):
        for name in _dynamic_domain_readers(p.name):
            scanned.add((p.name, name))
    declared = {(e["file"], e["symbol"]) for e in _REGISTRY
                if e["kind"] == "dynamic_reader"}
    assert scanned == declared, {
        "unregistered_dynamic_readers": sorted(scanned - declared),
        "stale_dynamic_entries": sorted(declared - scanned),
    }


def test_every_arm_exists_in_tests():
    """先落臂再引用：登记表里的行为臂必须能在 scripts/test_*.py 中找到。"""
    sources = _all_test_sources()
    for e in _REGISTRY:
        assert any(e["arm"] in s for s in sources.values()), "幻影臂: %s" % e


def test_registry_is_stable_across_import_roundtrip():
    """JSON 往返不丢字段（防登记表被写成不可序列化对象）。"""
    dumped = json.dumps(_REGISTRY, ensure_ascii=False)
    assert json.loads(dumped) == list(_REGISTRY)

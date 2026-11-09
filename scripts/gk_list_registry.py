#!/usr/bin/env python3
"""gk_list_registry.py — 裁决面清单登记表**生成器**（2026-11-09）。

为什么自动生成：技能内 allow/deny/exempt/skip/baseline 清单 ≥36 份，手写登记表必然
漂移成「第二份白名单」。本模块从源码/引用文件机械扫描，产出
`references/list-registry.json`；`--check` 只比对不写盘，供测试/CI 守漂移。

扫描面（全量，不做人工取舍 ⟹ 不需要人工白名单）:
  · scripts/*.py 顶层 Assign/AnnAssign，名字含 ALLOW/DENY/WHITELIST/EXEMPT/SKIP/
    IGNORE/BASELINE/KNOWN/SAFE/TRUST/PROTECTED，且值为集合/构造调用（排除标量枚举）；
  · scripts|references 下 `*whitelist*.json`、`_accept_*.txt`；
  · references/*.md 的 `## ...白名单基线` 章节。

用法:
  python3 scripts/gk_list_registry.py --write
  python3 scripts/gk_list_registry.py --check   # 漂移 → exit 1
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

# 命名启发式（只决定「像不像清单」，不决定收不收）：语义词 + 结构词（路由根/目录/形态/宿主）。
# 结构词是必要的：`DEV_WORKTREE_ROOTS` / `SEARCH_DIRS` / `WORKTREE_ROUTES` / `PRIOR_ART_HOSTS`
# 不含任何 allow/deny 字样，但正是 ⑦ 与出网闸的核心白名单。
_NAME_RE = re.compile(
    r"(ALLOW|DENY|WHITELIST|EXEMPT|SKIP|IGNORE|BASELINE|KNOWN|SAFE|TRUST|PROTECTED"
    r"|ROOTS|DIRS|ROUTES|HOSTS|BASES|REGIONS)")
_KIND_ORDER = ("denylist", "exemption", "allowlist", "baseline", "registry")
_REL = "references/list-registry.json"

# 关键项的人工注释（**只写语义，不决定收不收**；收不收由扫描面决定）。
_FAILURE_NOTES = {
    ("scripts/gk_route_center.py", "DEV_WORKTREE_ROOTS"):
        "fail-closed（worktree 目录扫描；空集 → 找不到 worktree）",
    ("scripts/gk_state_route.py", "DEV_WORKTREE_ROOTS"):
        "fail-closed（state 根扩展；空集 → 只认技能仓默认根）",
    ("scripts/gk_route_center.py", "SEARCH_DIRS"):
        "fail-closed（plan 发现金字塔；空集 → 找不到计划）",
    ("scripts/gk_route_center.py", "WORKTREE_ROUTES"):
        "fail-closed（route 形态不匹配 → worktree 不可见）",
    ("scripts/gk_role_regions.py", "ROLE_ALLOWED_REGIONS"):
        "fail-closed（未知角色回落 reporter/evidence）",
    ("scripts/gk_public_bridge.py", "REMOTE_ALLOW"):
        "fail-closed（非白名单远端拒绝推送）",
    ("scripts/pre_tool_hook.py", "MCP_EGRESS_ALLOWLIST"):
        "fail-closed（域外 BLOCK；与 PRIOR_ART_HOSTS 同源）",
    ("scripts/gk_evidence.py", "PRIOR_ART_HOSTS"):
        "fail-closed（唯一出网口白名单）",
    ("scripts/gk_monitor_api.py", "ALLOWED_BASES"):
        "fail-closed（域名投毒 / SSRF 拒绝）",
    ("scripts/pre_tool_hook.py", "_TRUST_ROOT_SCRIPTS"):
        "fail-open（豁免脚本内容扫描；仅 hook 自指入口）",
    ("scripts/gk_self_check.py", "_EXEMPT8"):
        "计数≠8 直接 FAIL（注册表被静默删改即红）",
    ("scripts/gk_state_patch.py", "_TOP_DENY"):
        "fail-closed（顶层键拒写）",
    ("references/oss-export-whitelist.json", "<file>"):
        "fail-open（文件不可读 → 空排除面，不误伤）",
    ("references/meta-routing-protocol.md", "## 路由白名单基线"):
        "fail-loud（2026-11-09 起：缺失/空单元格入 WARN）",
    ("scripts/_accept_baseline.txt", "<file>"):
        "fail-closed（缺失 → 无基线，失败全计 NEW）",
    ("scripts/_accept_location_exempt.txt", "<file>"):
        "fail-closed（缺失 → 无位置依赖豁免）",
}

_DEFAULT_FAILURE = {
    "allowlist": "fail-closed（准入类；缺失/空集 → 能力不可用或被拒）",
    "denylist": "fail-closed（拒绝类；缺失 → 危险面失去拦截）",
    "exemption": "fail-open（豁免类；命中即跳过对应检查）",
    "baseline": "baseline（缺失 → 对照面失效）",
    "registry": "registry（登记/状态类；不直接决定放行）",
}


def _kind(name: str) -> str:
    n = name.upper()
    if "DENY" in n or "BLACK" in n:
        return "denylist"
    if any(k in n for k in ("EXEMPT", "SKIP", "IGNORE", "KNOWN", "SAFE", "TRUST", "PROTECTED")):
        return "exemption"
    if "ALLOW" in n or "WHITELIST" in n or "WHITE_LIST" in n:
        return "allowlist"
    if "BASELINE" in n:
        return "baseline"
    return "registry"


def _is_collection_value(node) -> bool:
    """集合/构造调用才算「清单」；标量枚举（EXIT_UNKNOWN = 3）不收。"""
    if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict,
                         ast.ListComp, ast.SetComp, ast.DictComp)):
        return True
    return isinstance(node, ast.Call)


def _target_names(node) -> list:
    if isinstance(node, ast.Assign):
        return [t.id for t in node.targets if isinstance(t, ast.Name)]
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return [node.target.id]
    return []


def _py_texts(root: Path) -> dict:
    out = {}
    for p in sorted((root / "scripts").glob("*.py")):
        try:
            out[p.name] = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return out


def _referenced_by(symbol: str, own: str, texts: dict, pat: str = None) -> list:
    rx = re.compile(pat) if pat else re.compile(r"(?<![\w])" + re.escape(symbol) + r"(?![\w])")
    # 测试文件不算消费方（否则登记表随测试断言文本漂移）；只看生产脚本。
    hits = [f"scripts/{name}" for name, t in texts.items()
            if f"scripts/{name}" != own and not name.startswith("test_") and rx.search(t)]
    return sorted(hits)[:5]


def _exported(rel: str, root: Path) -> bool:
    try:
        from oss_export_surface import is_excluded
        return bool(is_excluded(rel, str(root)))
    except Exception:  # noqa: BLE001 — 判定不可用时不伪造排除
        return False


def _entry(eid: str, kind: str, file: str, symbol: str, line: int,
           refs: list, failure: str, root: Path) -> dict:
    return {
        "id": eid,
        "kind": kind if kind in _KIND_ORDER else "registry",
        "file": file,
        "symbol": symbol,
        "line": line,
        "referenced_by": refs,
        "failure_mode": failure,
        "exported": _exported(file, root),
    }


def build_registry(root: Path) -> dict:
    root = Path(root).resolve()
    texts = _py_texts(root)
    entries = []
    # ① scripts/*.py 顶层裁决面常量（排除测试/conftest/生成器自身）
    for p in sorted((root / "scripts").glob("*.py")):
        if p.name.startswith("test_") or p.name == "conftest.py":
            continue
        try:
            tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError):
            continue
        rel = f"scripts/{p.name}"
        for node in tree.body:
            if not _is_collection_value(getattr(node, "value", None)):
                continue
            for name in _target_names(node):
                if not _NAME_RE.search(name):
                    continue
                key = (rel, name)
                entries.append(_entry(
                    f"{p.stem}.{name}", _kind(name), rel, name, node.lineno,
                    _referenced_by(name, rel, texts),
                    _FAILURE_NOTES.get(key, _DEFAULT_FAILURE[_kind(name)]), root))
    # ② 文件型清单（scripts/references 下 *whitelist*.json、_accept_*.txt）
    for base in ("scripts", "references"):
        for p in sorted((root / base).glob("*")):
            if p.suffix not in (".json", ".txt"):
                continue
            low = p.name.lower()
            if "whitelist" not in low and "_accept_" not in low:
                continue
            rel = f"{base}/{p.name}"
            if "whitelist" in low:
                kind = "allowlist"
            elif "baseline" in low:
                kind = "baseline"
            elif "exempt" in low:
                kind = "exemption"
            else:
                kind = "registry"
            entries.append(_entry(
                p.stem, kind, rel, "<file>", 1,
                _referenced_by(p.name, rel, texts, pat=re.escape(p.name)),
                _FAILURE_NOTES.get((rel, "<file>"), _DEFAULT_FAILURE[kind]), root))
    # ③ references/*.md 的「白名单基线」章节
    for p in sorted((root / "references").glob("*.md")):
        rel = f"references/{p.name}"
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in re.finditer(r"(?m)^(## .*白名单基线.*)$", text):
            heading = m.group(1).strip()
            line = text[:m.start()].count("\n") + 1
            entries.append(_entry(
                f"{p.stem}.{heading.lstrip('# ').strip()}", "baseline", rel, heading, line,
                _referenced_by(heading, rel, texts),
                _FAILURE_NOTES.get((rel, heading), _DEFAULT_FAILURE["baseline"]), root))
    entries.sort(key=lambda e: e["id"])
    return {
        "_generated": True,
        "_generator": "scripts/gk_list_registry.py",
        "schema": 1,
        "scope": ("scripts/*.py 顶层裁决面常量（集合/构造调用）+ scripts|references 清单文件"
                  " + references/*.md 白名单基线章节；测试代码不计"),
        "entries": entries,
    }


def _dump(obj: dict) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False) + "\n"


def _diff(expected: dict, actual: dict) -> list:
    e = {x["id"]: x for x in expected.get("entries", [])}
    a = {x["id"]: x for x in actual.get("entries", [])}
    out = []
    for i in sorted(set(e) - set(a)):
        out.append(f"missing: {i}")
    for i in sorted(set(a) - set(e)):
        out.append(f"extra: {i}")
    for i in sorted(set(e) & set(a)):
        if e[i] != a[i]:
            out.append(f"changed: {i}")
    return out[:20]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="裁决面清单登记表生成器")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--write", action="store_true", help="写 references/list-registry.json")
    g.add_argument("--check", action="store_true", help="只比对；漂移 exit 1")
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    reg = build_registry(root)
    target = root / _REL
    payload = _dump(reg)
    if args.write:
        target.write_text(payload, encoding="utf-8")
        print(f"wrote {_REL}: {len(reg['entries'])} entries")
        return 0
    if not target.exists():
        print(f"DRIFT: {_REL} 缺失 — 跑 --write")
        return 1
    old = target.read_text(encoding="utf-8")
    if old == payload:
        print(f"ok: {_REL} 与源码同步（{len(reg['entries'])} entries）")
        return 0
    try:
        actual = json.loads(old)
    except json.JSONDecodeError as e:
        print(f"DRIFT: {_REL} 不是合法 JSON: {e}")
        return 1
    print(f"DRIFT: {_REL} 与源码不一致 — 跑 --write")
    for line in _diff(reg, actual):
        print("  " + line)
    return 1


if __name__ == "__main__":
    sys.exit(main())

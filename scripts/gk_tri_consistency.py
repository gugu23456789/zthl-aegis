"""gk_tri_consistency.py — 三面一致性闸（plan ↔ family ↔ finding_arms）。

**骨架由主 agent 落**（定 API 面 + 落刀点实存，防 coder 自定接口）；函数体由 coder 按
`docs/plans/2026-10-06-tri-consistency-gate-plan.md` §2 实装。骨架期一律 `NotImplementedError`
⟹ 红先 3 臂必红（对 HEAD/骨架均红）。

正本 finding：`ECC-CA582C23D36A`（root_key = plan-family-arm-tri-consistency）。
"""
import argparse
import ast
import json
import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent      # scripts/ 的父目录 = 仓根
_SCRIPTS = Path(__file__).resolve().parent
# 只认 `"verdict": "<literal>"` 形态（字典字面量），不把文档字符串里的词当判决。
_VERDICT_LITERAL_RE = re.compile(r'["\']verdict["\']\s*:\s*["\']([^"\']+)["\']')


def enumerate_write_surfaces(src="scripts/gk_finding.py"):
    """AST 求 `save_findings(` 的**可达闭包**，回**写面函数名**集合（替代手抄写面表）。

    语义（2026-10-06 三面校准 — 计划 §0.1/§2.1 ↔ 本骨架 ↔ arm_a）：
      · 取 `src` 内**传递可达** `save_findings(` 的函数名 —— 含经 `amend_title` **间接落刀**的
        `amend_anchors`（实测直呼者 9 = close/verify/reopen/amend_title/archive_closed/
        prune_duplicates/conflicts/register/upsert_red_findings；闭包 +amend_anchors = 10）。
      · **排除** CLI 入口 `main`（dispatcher，非写面；含之会与计划写面表误报）。

    （待 coder 实装；见计划 §2.1 / T1）
    """
    path = Path(src)
    if not path.is_absolute():
        path = _ROOT / src
    tree = ast.parse(path.read_text(encoding="utf-8"))
    calls = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            called = calls.setdefault(node.name, set())
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                    called.add(sub.func.id)
    surfaces = {name for name, cs in calls.items() if "save_findings" in cs}
    changed = True
    while changed:                       # 传递闭包：迭代到不动点
        changed = False
        for name, cs in calls.items():
            if name not in surfaces and (cs & surfaces):
                surfaces.add(name)
                changed = True
    surfaces.discard("main")             # CLI dispatcher，非写面
    return surfaces


def check_family(path):
    """族自洽机检：`test_first`/`affected_tests` 的**文件**存在 + `edit_quota >= len(allowed_paths)`。

    返 `{"ok": bool, "violations": [{"rule": ...}]}`。（待 coder 实装；见计划 §2.2 / T2）
    """
    try:
        fam = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return {"ok": False, "violations": [{"rule": "family_unreadable"}]}
    if not isinstance(fam, dict):
        return {"ok": False, "violations": [{"rule": "family_unreadable"}]}

    def _file_of(ref):
        return str(ref).split("::", 1)[0]

    def _exists(rel):
        return bool(rel) and (_ROOT / rel).is_file()   # 文件存在性按**仓根**解析

    violations = []
    test_first = fam.get("test_first")
    if test_first and not _exists(_file_of(test_first)):
        violations.append({"rule": "test_first_missing"})
    for ref in (fam.get("affected_tests") or []):
        if not _exists(_file_of(ref)):
            violations.append({"rule": "affected_test_missing"})
            break
    allowed = fam.get("allowed_paths")
    quota = fam.get("edit_quota")
    if isinstance(allowed, list) and isinstance(quota, int) and quota < len(allowed):
        violations.append({"rule": "quota_lt_paths"})
    return {"ok": not violations, "violations": violations}


def check_verdict_domain():
    """判决器可能返回值域 ⊆ `_VERDICT_ORDER ∪ 显式登记例外`；回**缺口列表**（空 = 覆盖完整）。

    （待 coder 实装；见计划 §2.3 / T3）
    """
    src = (_SCRIPTS / "gk_ecc_review.py").read_text(encoding="utf-8")
    produced = set(_VERDICT_LITERAL_RE.findall(src))
    if str(_SCRIPTS) not in sys.path:
        sys.path.insert(0, str(_SCRIPTS))
    import gk_ecc_review as rev
    registered = set(getattr(rev, "_VERDICT_ORDER", ())) \
        | set(getattr(rev, "_VERDICT_EXTRA", ()))
    return sorted(produced - registered)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="gk_tri_consistency")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--family")
    c.add_argument("--plan")
    args = ap.parse_args(argv)
    result = {"ok": True}
    if args.family:
        fam = check_family(args.family)
        result["family"] = fam
        if not fam["ok"]:
            result["ok"] = False
    missing = check_verdict_domain()
    result["verdict_missing"] = missing
    if missing:
        result["ok"] = False
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())

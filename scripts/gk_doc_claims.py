#!/usr/bin/env python3
"""gk_doc_claims.py — 自述文档的**确定性 claim 门**（发布前第三道）。

doc-align 查结构漂移（命令数/锚/跨引/旧站名）；本模块查**声明 ↔ 代码**：
  · 关键数字/后缀必须等于代码常量（如热索引 cap、侧车后缀）；
  · README 目录表里的路径必须存在；
  · 文档中的 `bash gatekeeper-cli.sh <cmd>` 必须已注册；
  · 相对 Markdown 链接目标必须存在。

用法：
  python3 scripts/gk_doc_claims.py [--summary]
输出：{"ok": bool, "issues": [...], "checks": N}
exit code: 1 if issues > 0。
"""
import argparse
import importlib
import json
import os
import re
import sys
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
DOCS = ["README.md", "references/state-storage.md", "references/research-408.md"]

# 关键声明表：needle 必须出现在 doc 中，且代码常量/符号必须与 expect 一致。
CLAIMS = [
    {"doc": "README.md", "needle": "每 kind ≤6 叶",
     "kind": "const", "target": "gk_satellite.INLINE_LEAVES_MAX_PER_KIND", "expect": 6},
    {"doc": "README.md", "needle": "satellite-index.jsonl",
     "kind": "const", "target": "gk_satellite.INDEX_SIDECAR_SUFFIX",
     "expect": ".satellite-index.jsonl"},
    {"doc": "README.md", "needle": "update_state", "kind": "symbol",
     "target": "gk_json_utils.update_state"},
    {"doc": "references/state-storage.md", "needle": "INLINE_LEAVES_MAX_PER_KIND",
     "kind": "const", "target": "gk_satellite.INLINE_LEAVES_MAX_PER_KIND", "expect": 6},
    {"doc": "references/state-storage.md", "needle": "satellite-index.jsonl",
     "kind": "const", "target": "gk_satellite.INDEX_SIDECAR_SUFFIX",
     "expect": ".satellite-index.jsonl"},
    {"doc": "references/research-408.md", "needle": "GK_RESEARCH_FRAME=408",
     "kind": "frame", "target": "gk_advance._HINT_PHASES", "expect": "408"},
]

README_PATHS = [
    "gatekeeper-cli.sh", "scripts", "references", "monitor-schemas",
    "assets", "zthl", "install.sh", "uninstall.sh",
]

_CMD_RE = re.compile(r"(?m)^\s*_CMD_REG\[['\"]?([A-Za-z0-9_-]+)['\"]?\]=")
_CLI_EXAMPLE_RE = re.compile(r"bash\s+gatekeeper-cli\.sh\s+([A-Za-z0-9_-]+)")
_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _resolve_const(target: str):
    mod, attr = target.rsplit(".", 1)
    return getattr(importlib.import_module(mod), attr)


def _check_claim(root: Path, c: dict) -> list:
    txt = _read(root / c["doc"])
    if c["needle"] not in txt:
        return [{"doc": c["doc"], "claim": c["needle"],
                 "error": "声明文本缺失（文档已改写，请更新 claim 表）"}]
    if c["kind"] == "symbol":
        try:
            obj = _resolve_const(c["target"])
        except Exception as e:  # noqa: BLE001
            return [{"doc": c["doc"], "claim": c["needle"],
                     "error": "符号解析失败: %s: %s" % (type(e).__name__, e)}]
        return [] if callable(obj) else [{"doc": c["doc"], "claim": c["needle"],
                                          "error": "目标不是可调用符号: %s" % c["target"]}]
    if c["kind"] == "const":
        try:
            actual = _resolve_const(c["target"])
        except Exception as e:  # noqa: BLE001
            return [{"doc": c["doc"], "claim": c["needle"],
                     "error": "常量解析失败: %s: %s" % (type(e).__name__, e)}]
        if actual != c["expect"]:
            return [{"doc": c["doc"], "claim": c["needle"],
                     "error": "%s=%r，文档期望 %r" % (c["target"], actual, c["expect"])}]
        return []
    if c["kind"] == "frame":
        try:
            import gk_advance as A
            pre = A._HINT_PHASES["ECO-RESEARCH"]["research_prelude"]
            ok = c["expect"] in (pre.get("frames") or {})
        except Exception as e:  # noqa: BLE001
            return [{"doc": c["doc"], "claim": c["needle"],
                     "error": "frame 解析失败: %s: %s" % (type(e).__name__, e)}]
        return [] if ok else [{"doc": c["doc"], "claim": c["needle"],
                               "error": "hint 未注册 frame %s" % c["expect"]}]
    return [{"doc": c["doc"], "claim": c["needle"], "error": "未知 claim kind"}]


def _check_paths(root: Path) -> list:
    return [{"doc": "README.md", "claim": p, "error": "目录表路径不存在"}
            for p in README_PATHS if not (root / p).exists()]


def _check_cli_examples(root: Path) -> list:
    cli = _read(root / "gatekeeper-cli.sh")
    if not cli:
        return []
    registered = set(_CMD_RE.findall(cli))
    out = []
    for doc in DOCS:
        for cmd in _CLI_EXAMPLE_RE.findall(_read(root / doc)):
            if cmd not in registered:
                out.append({"doc": doc, "claim": "bash gatekeeper-cli.sh %s" % cmd,
                            "error": "命令未在 _CMD_REG 注册"})
    return out


def _check_links(root: Path) -> list:
    out = []
    for doc in DOCS:
        p = root / doc
        for href in _LINK_RE.findall(_read(p)):
            if href.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target = href.split("#", 1)[0]
            if not target:
                continue
            if not (p.parent / target).exists():
                out.append({"doc": doc, "claim": href, "error": "相对链接目标不存在"})
    return out


def check(skill_dir: str = "") -> dict:
    root = Path(skill_dir) if skill_dir else SKILL_DIR
    issues = []
    n = 0
    for c in CLAIMS:
        issues += _check_claim(root, c); n += 1
    issues += _check_paths(root); n += 1
    issues += _check_cli_examples(root); n += 1
    issues += _check_links(root); n += 1
    return {"ok": not issues, "issues": issues, "checks": n,
            "docs": [d for d in DOCS if (root / d).is_file()]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_doc_claims.py")
    ap.add_argument("--summary", action="store_true")
    a = ap.parse_args(argv)
    res = check()
    if a.summary:
        print("gk_doc_claims: %s issues=%d checks=%d"
              % ("PASS" if res["ok"] else "FAIL", len(res["issues"]), res["checks"]))
    else:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""gk_doc_features.py — 常驻功能 ↔ 自述文档覆盖检查（发布门）。

两类判据
=========
1. **功能覆盖**：`references/resident-features.json` 每条 `{id, doc, pattern}` 必须在对应文档中
   命中（正则）。新增常驻能力（基准、hook 门、MCP 安全网、来源链…）而未写进自述文档 ⟹ 判红。
2. **自动刷新文档**：调用 `gk_docgen_facts.py check`，要求 GK-FACTS / GK-REFS / state 容量水位表
   与活文件一致；不一致（需要 `--write`）⟹ 判红。

设计纪律
--------
- 登记表是**唯一事实源**：检查器不内置功能清单，避免第二份名单漂移。
- 只读：本脚本不改文档、不写 state。
- 失败可解释：输出缺失项 `{id, doc, pattern}` 与 facts 的实际状态。

用法：
  python3 scripts/gk_doc_features.py [--json] [--registry FILE] [--skip-facts]
退出码：0 = 全绿；1 = 有缺失/漂移；2 = 登记表不可读/非法。
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REGISTRY = ROOT / "references" / "resident-features.json"
FACTS = ROOT / "scripts" / "gk_docgen_facts.py"
SCHEMA = "gk-resident-features/1"


def load_registry(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != SCHEMA:
        raise ValueError("登记表 schema 不符：%r" % data.get("schema"))
    feats = data.get("features")
    if not isinstance(feats, list) or not feats:
        raise ValueError("登记表 features 为空或类型错误")
    for f in feats:
        for k in ("id", "doc", "pattern"):
            if not isinstance(f.get(k), str) or not f.get(k):
                raise ValueError("登记项缺字段 %s：%r" % (k, f))
    return data


def check_features(feats: list) -> list:
    missing = []
    cache = {}
    for f in feats:
        doc = f["doc"]
        if doc not in cache:
            p = ROOT / doc
            cache[doc] = p.read_text(encoding="utf-8") if p.is_file() else None
        text = cache[doc]
        if text is None:
            missing.append({"id": f["id"], "doc": doc, "pattern": f["pattern"],
                            "reason": "文档不存在"})
            continue
        if not re.search(f["pattern"], text):
            missing.append({"id": f["id"], "doc": doc, "pattern": f["pattern"],
                            "reason": "文档未覆盖"})
    return missing


def check_facts() -> dict:
    if not FACTS.is_file():
        return {"status": "MISSING", "detail": "gk_docgen_facts.py 不存在"}
    p = subprocess.run([sys.executable, str(FACTS), "check"],
                       capture_output=True, text=True, timeout=120)
    try:
        return json.loads(p.stdout)
    except Exception:  # noqa: BLE001 — 非 JSON 输出按失败处理
        return {"status": "FAIL", "detail": (p.stderr or p.stdout or "")[-300:],
                "rc": p.returncode}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_doc_features.py")
    ap.add_argument("--registry", default=str(DEFAULT_REGISTRY))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--skip-facts", action="store_true")
    a = ap.parse_args(argv)
    try:
        reg = load_registry(Path(a.registry))
    except Exception as e:  # noqa: BLE001 — 登记表是输入边界
        print(json.dumps({"ok": False, "error": "%s: %s" % (type(e).__name__, e)},
                         ensure_ascii=False))
        return 2
    missing = check_features(reg["features"])
    facts = {"status": "SKIP"} if a.skip_facts else check_facts()
    facts_ok = bool(a.skip_facts) or facts.get("status") == "PASS"
    ok = not missing and facts_ok
    out = {"ok": ok, "checked": len(reg["features"]), "missing": missing, "facts": facts}
    print(json.dumps(out, ensure_ascii=False, indent=2))
    if not a.json:
        if missing:
            for m in missing:
                print("MISSING %s -> %s (%s)" % (m["id"], m["doc"], m["reason"]),
                      file=sys.stderr)
        if not facts_ok:
            print("FACTS %s: %s" % (facts.get("status"), facts.get("detail", "")),
                  file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

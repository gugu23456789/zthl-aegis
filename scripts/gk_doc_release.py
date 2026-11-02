#!/usr/bin/env python3
"""gk_doc_release.py — 发布前文档门（串联三道，单一入口）。

  1. `gk_docgen_facts.py check`   — 自动生成事实块/索引/容量表是否与活文件一致
  2. `gk_doc_align.py`            — 结构漂移（命令数/锚/跨引/旧站名/计划落刀…）
  3. `gk_doc_claims.py`           — 声明 ↔ 代码（常量/后缀/路径/命令/相对链接）

用法：
  python3 scripts/gk_doc_release.py [--strict] [--summary]
`--strict`：doc-align 的 WARN 也计失败（当前存量 WARN 会红，发布前须清零或显式豁免）。
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _run(script: str, *args) -> dict:
    p = subprocess.run([sys.executable, str(ROOT / "scripts" / script)] + list(args),
                       cwd=str(ROOT), capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    try:
        d = json.loads(p.stdout)
    except Exception:  # noqa: BLE001
        d = {"raw": (p.stdout or "")[-800:], "stderr": (p.stderr or "")[-800:],
             "rc": p.returncode}
    d.setdefault("rc", p.returncode)
    return d


def check(strict: bool = False) -> dict:
    facts = _run("gk_docgen_facts.py", "check")
    # 发布门只看**公开导出面**：--release 跳过 docs/plans、docs/analysis/subagent 等私有树，
    # 避免历史计划/报告漂移阻断公开包（内部完整检查仍走不带 --release 的 doc-align）。
    align = _run("gk_doc_align.py", "--release")
    claims = _run("gk_doc_claims.py")
    facts_ok = facts.get("status") == "PASS"
    align_ok = (bool(align.get("ok"))
                and int(align.get("issues", 0) or 0) == 0
                and (not strict or int(align.get("warns", 0) or 0) == 0))
    claims_ok = bool(claims.get("ok"))
    return {
        "ok": facts_ok and align_ok and claims_ok,
        "strict": bool(strict),
        "facts": facts,
        "align": {"ok": align.get("ok"), "issues": align.get("issues"),
                  "warns": align.get("warns")},
        "claims": claims,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_doc_release.py")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--summary", action="store_true")
    a = ap.parse_args(argv)
    res = check(strict=a.strict)
    if a.summary:
        print("gk_doc_release: %s strict=%s facts=%s align(issues=%s,warns=%s) claims=%s"
              % ("PASS" if res["ok"] else "FAIL", a.strict,
                 res["facts"].get("status"), res["align"].get("issues"),
                 res["align"].get("warns"), "PASS" if res["claims"].get("ok") else "FAIL"))
    else:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())

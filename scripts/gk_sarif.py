#!/usr/bin/env python3
"""gk_sarif.py — 门禁静态结果 → SARIF 2.1.0（2026-11-04）。

为什么要有：三个静态门（workflow 供应链 / bash 危险命令 / 包-钩子完整性）此前各自
输出**私有 JSON 形状**，只有读得懂这三个脚本的人才能消费；接不进 GitHub code
scanning、GitLab SAST、VS Code SARIF Viewer。SARIF 2.1.0 是这些平台共同的
最小公分母 —— 一份结果，三个消费端。

设计约束（确定性优先，对齐 bashpy `sarif.py` 同款口径）：
- **无时间戳、无随机量** ⟹ 同一输入逐字相同输出，可直接进棘轮基线。
- **固定排序**：rules 按 ruleId 字典序；results 按 (文件, 行, 规则, 消息)，
  无行号的排最后。
- **分级映射固定**：门禁 `error` → SARIF error，`warn` → warning，
  `bash_static` 的 `WARN` 状态 → warning，其余 → note。
- **不伪造行号**：包完整性/供应链类问题多是「注册面 vs 载体」级，无行号就省略 region。
- **只报不 PASS**：`scan_skill` 的 PASS 占位项不是缺陷，不转 results。

数据源（全部只读、零网络）：
  `gk_ci_security_lint.check()`      .github/workflows 供应链/权限
  `gk_bash_static_scan.scan_skill()` P2-P8 危险模式（带 file/line）
  `gk_package_integrity.collect()`   注册面 ↔ 载体

用法：
  python3 scripts/gk_sarif.py                        # SARIF 打到 stdout
  python3 scripts/gk_sarif.py --out results.sarif    # 写文件 + stderr 摘要
  python3 scripts/gk_sarif.py --gate                 # 有 error 级finding ⟹ exit 1
退出码：0 报告已生成（无 --gate）；1 --gate 且存在 error 级 finding。
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
VERSION = "2.1.0"
INFORMATION_URI = "https://github.com/gugu23456789/zthl-aegis"

# 包完整性问题的载体推断（仅当 issue 未自带 `path` 时使用）。
# 只登记**确定对应**的映射；拿不准的宁可不给位置，也不编一个假路径。
_ARTIFACT_HINTS = {
    "hook_wrapper": "scripts/pre_tool_hook_wrapper.sh",
    "hook_dependency": "scripts/pre_tool_hook.py",
    "hook_lifecycle": "install.sh",
    "cli_cmd_registry": "gatekeeper-cli.sh",
    "plugin_manifest": "scripts/gk_plugin_manifest.py",
    "monitor_schema": "monitor-schemas",
}
_TAGS = ["aegis", "static-analysis"]
_SEV_RANK = {"note": 0, "warning": 1, "error": 2}
_LEVEL_OF_PKG = {"error": "error", "warn": "warning", "warning": "warning"}
# 设计内信息 ≠ 缺陷（2026-11-05）：外部源插件（pip/npm/同级技能）按设计不随包，
# 之前映射成 warning 会在 GitHub Security 页变黄条，读者误读为漏洞 ⟹ 降为 note。
_DESIGN_NOTE_PKG = frozenset(("plugin_manifest",))


def _posix(p) -> str:
    """路径 → SARIF artifactLocation uri：正斜杠、去前导 ./（GitHub 按仓库根解析）。"""
    s = str(p or "").replace("\\", "/").strip()
    while s.startswith("./"):
        s = s[2:]
    return s


def _ci_findings(root: Path) -> list:
    import gk_ci_security_lint as L

    r = L.check(root / ".github" / "workflows")
    out = []
    for it in r.get("issues", []):
        wf = str(it.get("workflow") or "")
        out.append({
            "rule": "ci_security",
            "level": "error",
            "message": "%s: %s" % (wf, it.get("error", "")),
            "file": ".github/workflows/%s" % wf if wf else ".github/workflows",
            "line": None,
            "props": {"workflow": wf},
        })
    for it in r.get("warnings", []):
        wf = str(it.get("workflow") or "")
        out.append({
            "rule": "ci_security",
            "level": "warning",
            "message": "%s: %s" % (wf, it.get("warning", "")),
            "file": ".github/workflows/%s" % wf if wf else ".github/workflows",
            "line": None,
            "props": {"workflow": wf},
        })
    return out


def _bash_findings(root: Path) -> list:
    import gk_bash_static_scan as B

    r = B.scan_skill(root)
    out = []
    for c in r.get("checks", []):
        status = str(c.get("status") or "")
        if status == "PASS":
            continue  # 「无命中」不是缺陷
        out.append({
            "rule": str(c.get("check") or "bash_static"),
            "level": "error" if status == "FAIL" else "warning",
            "message": str(c.get("detail") or c.get("check") or ""),
            "file": _posix(c.get("file") or ""),
            "line": c.get("line"),
            "props": {"status": status},
        })
    return out


def _pkg_findings(root: Path) -> list:
    import gk_package_integrity as P

    r = P.collect(root)
    out = []
    for it in r.get("issues", []):
        check = str(it.get("check") or "package")
        path = _posix(it.get("path") or "")
        if path.startswith("../"):
            # 树外载体（独立技能 / 邻仓）—— SARIF 的 relative uri 不得逃出仓库根，
            # 逃出会被 code scanning 判为越界；宁可不给位置，也不编造仓内路径。
            # 注意：这里**不能**回落到 _ARTIFACT_HINTS ——「树外」是明确结论，不是「缺信息」。
            file = ""
        elif path:
            file = path
        else:
            file = _ARTIFACT_HINTS.get(check, "")
        extra = {k: v for k, v in it.items()
                 if k not in ("level", "check", "detail", "path")}
        msg = str(it.get("detail") or check)
        if extra:
            msg = "%s（%s）" % (msg, json.dumps(extra, ensure_ascii=False, sort_keys=True))
        out.append({
            "rule": "pkg_%s" % check,
            "level": ("note" if check in _DESIGN_NOTE_PKG
                      else _LEVEL_OF_PKG.get(str(it.get("level") or "").lower(), "note")),
            "message": msg,
            "file": file,
            "line": None,
            "props": dict(extra, check=check),
        })
    return out


_COLLECTORS = (_ci_findings, _bash_findings, _pkg_findings)


def _fingerprint(rule: str, uri: str, line, message: str) -> str:
    """稳定指纹（跨运行不变）：只依赖规则/文件/行号/消息，不含时间。"""
    raw = "%s|%s|%s|%s" % (rule, uri, line if line else "", message)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def collect_findings(root: Path = None) -> list:
    """三个静态门 → 归一 findings（去重 + 固定排序）。"""
    root = Path(root or ROOT)
    raw = []
    for collect in _COLLECTORS:
        raw.extend(collect(root))

    seen, uniq = set(), []
    for f in raw:
        key = (f["rule"], f["file"], f["line"], f["message"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    uniq.sort(key=lambda f: (f["file"], f["line"] is None, f["line"] or 0,
                             f["rule"], f["message"]))
    return uniq


def build(root: Path = None, tool_version: str = "") -> dict:
    """SARIF 2.1.0 文档（确定性：同一输入逐字相同）。"""
    findings = collect_findings(root)

    rule_ids = sorted({f["rule"] for f in findings})
    rules, index = [], {}
    for rid in rule_ids:
        occ = [f for f in findings if f["rule"] == rid]
        worst = max(occ, key=lambda f: _SEV_RANK.get(f["level"], 0))
        rules.append({
            "id": rid,
            "shortDescription": {"text": str(worst["message"])[:160]},
            "defaultConfiguration": {"level": worst["level"]},
            "properties": {"tags": list(_TAGS)},
        })
        index[rid] = len(rules) - 1

    results = []
    for f in findings:
        uri = _posix(f["file"])
        res = {
            "ruleId": f["rule"],
            "ruleIndex": index[f["rule"]],
            "level": f["level"],
            "message": {"text": str(f["message"])},
            "partialFingerprints": {
                "aegis/v1": _fingerprint(f["rule"], uri, f.get("line"), str(f["message"])),
            },
            "properties": dict(f.get("props") or {}),
        }
        if uri:
            loc = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
            if f.get("line"):
                loc["physicalLocation"]["region"] = {"startLine": int(f["line"])}
            res["locations"] = [loc]
        results.append(res)

    return {
        "$schema": SCHEMA,
        "version": VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "zthl-aegis-static-gates",
                "version": str(tool_version or "0"),
                "informationUri": INFORMATION_URI,
                "rules": rules,
            }},
            "columnKind": "unicodeCodePoints",
            "invocations": [{"executionSuccessful": True}],
            "results": results,
            "properties": {"deterministic": True, "sources": len(_COLLECTORS)},
        }],
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_sarif.py")
    ap.add_argument("--out", default="", help="SARIF 输出路径（缺省 stdout）")
    ap.add_argument("--root", default="", help="待检查树（默认 = 本仓根）")
    ap.add_argument("--version", default="", help="写进 tool.driver.version")
    ap.add_argument("--gate", action="store_true", help="存在 error 级 finding 时退出 1")
    ns = ap.parse_args(argv)

    doc = build(ns.root or None, ns.version)
    results = doc["runs"][0]["results"]
    errors = sum(1 for r in results if r["level"] == "error")
    warnings = sum(1 for r in results if r["level"] == "warning")

    text = json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True)
    if ns.out:
        Path(ns.out).write_text(text + "\n", encoding="utf-8")
        print("gk_sarif: results=%d errors=%d warnings=%d -> %s"
              % (len(results), errors, warnings, ns.out), file=sys.stderr)
    else:
        print(text)
        print("gk_sarif: results=%d errors=%d warnings=%d"
              % (len(results), errors, warnings), file=sys.stderr)
    return 1 if (ns.gate and errors) else 0


if __name__ == "__main__":
    sys.exit(main())

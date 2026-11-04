#!/usr/bin/env python3
"""gk_bash_static_scan.py — bash 静态漏洞模式扫描 (2026-08-15 固化)

安全网拦截体系的"扩展 bash 检查机制"：扫描 gatekeeper-cli.sh + scripts/*.py
的已知高危模式，供 self-check / 红队 RED-HOOK / 审计防护消费。

模式 (P2-P8, 单行级检测，避免跨块状态机误判):
  P2: json.loads(sys.stdin)            → TypeError（应 json.load / json.loads(stdin.read())）
  P3: json.loads('''...''')            → 三引号注入（LLM/外部内容可注入 python -c）；标 LLM 来源为高危
  P4: .get('output'/.get("output"      → subagent 结果错键（runner 顶层只发 conclusion）
  P5: --tools evidence,constants       → 非 TOOL_REGISTRY 工具（工具集为空）
  P7: python3 -c " 同一行内裸反引号      → bash 命令替换污染（未转义）
  P8: 危险命令字面量（2026-08-15）      → rm -rf 家族 / git push --force / git reset --hard /
                                          git clean -f（对齐 pre_tool_hook Gate R0.2 类2 高危破坏）。
                                          仅扫 .sh 目标（Python 目标跳过：检测器/业务字符串
                                          天然含危险命令字面量，单行级无法区分上下文）；
                                          $_tmp 变量形态豁免（CLI 内部临时目录白名单）

用法: python3 gk_bash_static_scan.py [--json] [--skill-dir <dir>]
输出: 默认 human；--json 输出 {"issues":N,"checks":[{"check","status","detail","count"}]}
"""
import argparse
import json
import re
import sys
from pathlib import Path

DEFAULT_SKILL = Path(__file__).resolve().parent.parent

# LLM 来源变量（json.loads('''$var''') 的 var 来自不可信 LLM → 注入高危）
_LLM_SRC_VARS = re.compile(
    r"\$(_subagent_result|llm_analysis|guidance|subagent_out)"
)

# ── P8: 危险命令字面量（2026-08-15，对齐 pre_tool_hook Gate R0.2 类2 高危破坏）──
# 规则与 _dangerous_command 同构：git push --force / git reset --hard / git clean -f / rm -rf 家族
_P8_RULES = (
    (r"\bgit\b[^|&;\n]*\bpush\b[^|&;\n]*(?:--force(?!-)\b|-f\b)", "git push --force (不可逆覆盖远端)"),
    (r"\bgit\b[^|&;\n]*\breset\s+--hard\b", "git reset --hard (丢弃工作区+暂存区)"),
    (r"\bgit\b[^|&;\n]*\bclean\s+-(?:f|fd|ffd)\b", "git clean -f (删除未跟踪文件)"),
    (r"\brm\s+-r\w*\b", "rm -rf (递归强制删除)"),
)
# CLI 内部临时目录变量白名单（$_tmp 家族，与 R0.2 豁免同构）
_P8_TMP_EXEMPT = re.compile(r"\$\{?_?tmp")


def scan_file(path: Path) -> list:
    """返回 [(pattern, line_no, desc, severity)]"""
    is_shell = path.suffix == ".sh"  # P8 仅扫 shell 脚本目标
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings = []
    for i, ln in enumerate(content.split("\n"), 1):
        stripped_ln = ln.lstrip()
        if stripped_ln.startswith("#"):
            continue  # 跳过注释行（bash 注释 / python heredoc 注释），避免误报
        # P2
        if re.search(r"json\.loads\(sys\.stdin\)", ln):
            findings.append(("P2", i, "json.loads(sys.stdin) → 应 json.load(sys.stdin)", "high"))
        # P3
        if "json.loads('''" in ln:
            sev = "high" if _LLM_SRC_VARS.search(ln) else "medium"
            src = "LLM来源" if sev == "high" else "内部数据"
            findings.append(("P3", i, f"三引号注入 json.loads('''...''') ({src})", sev))
        # P4
        if re.search(r"\.get\('output'|\.get\(\"output\"", ln):
            findings.append(("P4", i, "get('output') 错键（runner 发 conclusion）", "high"))
        # P5
        if "--tools evidence,constants" in ln or "--tools \"evidence" in ln:
            findings.append(("P5", i, "--tools evidence,constants 不在 TOOL_REGISTRY", "high"))
        # P7: python3 -c " 行内未转义反引号
        if re.search(r'python3 -c "', ln):
            # 去掉转义的反引号 \` 后，若仍有裸反引号
            stripped = re.sub(r"\\`", "", ln)
            if "`" in stripped:
                findings.append(("P7", i, "python3 -c \" 行内裸反引号 → 命令替换污染", "high"))
        # P8: 危险命令字面量（2026-08-15，Gate R0.2 对齐，仅 .sh 目标）
        #   $_tmp 变量形态豁免（CLI 内部临时目录白名单）
        if is_shell:
            for pat, desc in _P8_RULES:
                if re.search(pat, ln, re.IGNORECASE):
                    if desc.startswith("rm") and _P8_TMP_EXEMPT.search(ln):
                        continue  # CLI 内部 $_tmp 临时目录变量白名单
                    findings.append(("P8", i, f"危险命令: {desc}", "high"))
                    break
    return findings


def scan_skill(skill_dir: Path) -> dict:
    checks = []
    issues = 0
    targets = [
        ("gatekeeper-cli.sh", skill_dir / "gatekeeper-cli.sh"),
        ("pre_tool_hook.py", skill_dir / "scripts" / "pre_tool_hook.py"),
    ]
    for name, p in targets:
        fs = scan_file(p)
        try:
            rel = str(p.relative_to(skill_dir)).replace("\\", "/")
        except ValueError:
            rel = name
        for pat, line, desc, sev in fs:
            issues += 1
            checks.append({
                "check": f"bash_static_{pat.lower()}",
                "status": "FAIL" if sev == "high" else "WARN",
                "detail": f"{name}:L{line} — {desc}",
                "count": 1,
                # 2026-11-04：结构化定位（SARIF 消费）—— detail 保持人类可读串，
                # 下游不再反向解析散文。
                "file": rel,
                "line": line,
                "severity": sev,
            })
    # 无命中也登记 PASS 项（self-check 可视化）
    for pat in ("P2", "P3", "P4", "P5", "P7", "P8"):
        if not any(c["check"] == f"bash_static_{pat.lower()}" for c in checks):
            checks.append({
                "check": f"bash_static_{pat.lower()}",
                "status": "PASS",
                "detail": f"模式 {pat} 无命中",
                "count": 0,
            })
    return {"ok": issues == 0, "issues": issues, "checks": checks}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--skill-dir", default=str(DEFAULT_SKILL))
    args = ap.parse_args()
    result = scan_skill(Path(args.skill_dir))
    if args.json:
        # --json 是数据输出：退出码恒 0，状态由 checks 字段表达。
        # bash 侧 `cmd || echo fallback` 会把 issues>0 的 exit 1 误判为执行失败覆盖输出（2026-08-15 实测）。
        print(json.dumps(result))
        sys.exit(0)
    print(f"issues={result['issues']}")
    for c in result["checks"]:
        print(f"  [{c['status']}] {c['check']}: {c['detail']}")
    sys.exit(0 if result["issues"] == 0 else 1)


if __name__ == "__main__":
    main()

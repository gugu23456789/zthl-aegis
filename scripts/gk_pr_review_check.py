#!/usr/bin/env python3
"""gk_pr_review_check.py — L10 PR 级审查实装（2026-09-01）

此前 stage-3-review.md 仅登记"L10 接 gitnexus-pr-review 待接入"，本脚本实装：
  PR 级 diff→符号→受影响流程→风险等级 确定性审查（gitnexus detect-changes compare），
  供后R 红队独立检查 + merge gate 前置证据使用。

能力（对齐 gitnexus-pr-review skill 本地等价）:
  - detect-changes compare base_ref → 变更文件/符号/受影响流程/风险等级
  - 符号爆破半径（impact upstream，可选 --symbol 深查）

调用：python3 gk_pr_review_check.py --base <ref> [--symbol <fn>] [--repo <name>] [--limit <n>]
输出契约：
  {"ok": true, "base": "...", "repo": "...",
   "changed_files": N, "changed_symbols": [...],
   "affected_processes": N, "risk": "low|medium|high",
   "symbol_impact": {...},  # --symbol 时
   "recommendation": "..."}
确定性：0 API。Windows node.exe 直调 gitnexus CLI（同 subagent_runner._gitnexus_cmd）；node/js/repo
三要素由 gatekeeper-cli.sh（`_gx_subagent_gx_env`）经 GX_NODE/GX_JS/GX_REPO 注入，本脚本**不自探测**
（F-REV-75）。
"""
import json
import os
import sys

import gk_gitnexus  # A1（2026-10-28）：node/js/repo 探测与 spawn 的**唯一** python 侧入口

# F-REV-75（2026-09-16，用户裁定「同根因修」）：node/js/repo **一律不自探测**。
# A1（2026-10-28）：本文件原有的 `_node/_gx_js/_gx_env_error/_resolve_repo` 四件复制
# **已收敛**到 `gk_gitnexus`（单源）；下面四个薄壳仅为既有测试/调用点保留原名。
def _node() -> str:
    """Windows node.exe 的 WSL 可执行形态（/mnt/...）—— CLI 注入，不自探测。

    形态归一（**仅转换、不探测**）：CLI 侧 `_gx_subagent_gx_env win` 在 subagent_python 为
    Windows 解释器（suagent_py311.sh / *.exe）时注入 **Windows 形态**（`D:\\...`），而本脚本
    恒经 WSL `python3` 运行 ⟹ 直接 `subprocess.run` 抛 `FileNotFoundError ENOENT`；该报文经
    `gk_l3_prefetch` → `gk_l0_prefetch` 注入 subagent 后被误读为「node.exe 缺失」（实为路径
    **形态**不匹配：同一 node 的 /mnt 形态可正常执行 v24.14.0）。故 posix 宿主下把 `D:\\...`
    归一到 `/mnt/d/...`；Windows 宿主（os.name=='nt'）原样透传（那里 win 形态才是对的）。
    """
    return gk_gitnexus.node_exe()


def _gx_js() -> str:
    """gitnexus CLI 入口的 **Windows 形态**路径（node.exe 是 Windows 二进制，不认 /mnt 路径）。"""
    return gk_gitnexus.js_path()


def _gx_env_error() -> str:
    """env 可用性检查（fail-loud 文案）；可用则返回空串。"""
    return gk_gitnexus.env_error("本脚本须经 gatekeeper-cli.sh 调用 —— audit --pr，CLI 自动注入")


def _resolve_repo(explicit: str) -> str:
    """repo 单源解析：显式 --repo 优先，否则用 CLI 注入的 GX_REPO（原写死 spz-gatekeeper-r-sequence）。"""
    return gk_gitnexus.resolve_repo(explicit)


def _run_gx(args: list[str]) -> dict:
    """node.exe 直调 gitnexus 子命令（detect-changes/impact/context）。

    JSON 提取收敛到 `gk_gitnexus.run_json`（A1：spawn+提取单源）：多 JSON/warn 后置均取
    最后完整对象；纯文本输出（detect-changes）→ `{"raw": ...}`。
    `strict=False` 保留本脚本既有语义：**不看 rc**，只解析 stdout。
    """
    # F-REV-75 fail-loud 前置（不再有硬编码路径兜底 ⟹ env 缺失必须显式报错而非静默空结果）
    err = _gx_env_error()
    if err:
        return {"error": err}
    return gk_gitnexus.run_json(list(args), timeout=60, strict=False)


def _extract_md_table(d: dict) -> list[list[str]]:
    """markdown 表 → 行列表（跳过表头/分隔线）。"""
    md = d.get("markdown", "")
    rows = []
    for line in md.splitlines():
        line = line.strip()
        if line.startswith("|") and "---" not in line and not line.startswith("| Symbol"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            rows.append(cells)
    return rows


def review_pr(base: str, repo: str, symbol: str = "", limit: int = 50) -> dict:
    d = _run_gx(["detect-changes", "-s", "compare", "-b", base, "-r", repo, "-l", str(limit)])
    if "error" in d:
        return {"ok": False, "base": base, "repo": repo, "error": d["error"]}
    # CLI detect-changes 输出 = 文本（"变更：N 个文件，M 个符号 / 受影响流程：K / 风险等级：X / 已变更符号：..."）
    raw = d.get("raw") or d.get("text") or json.dumps(d, ensure_ascii=False)
    return _parse_detect_changes_text(raw, base, repo, symbol, limit)


def _parse_detect_changes_text(raw: str, base: str, repo: str, symbol: str, limit: int) -> dict:
    """解析 CLI detect-changes 文本输出 → 契约。"""
    import re as _re
    files = processes = 0
    risk = "low"
    symbol_list = []
    for line in raw.splitlines():
        line = line.strip()
        m = _re.match(r"变更：(\d+) 个文件，(\d+) 个符号", line)
        if m:
            files = int(m.group(1))
        m = _re.match(r"受影响流程：(\d+)", line)
        if m:
            processes = int(m.group(1))
        m = _re.match(r"风险等级：(\w+)", line)
        if m:
            risk = m.group(1).lower()
        if line.startswith("Symbol "):
            # "Symbol Name → file" 或 "Symbol Name — detail → file"
            name = line[len("Symbol "):].split("→")[0].split("—")[0].strip()
            if name:
                symbol_list.append(name)
    out = {"ok": True, "base": base, "repo": repo,
           "changed_files": files, "changed_symbols": symbol_list[:limit],
           "affected_processes": processes, "risk": risk,
           "recommendation": _risk_rec(risk)}
    if symbol:
        out["symbol_impact"] = _run_gx(["impact", symbol, "-r", repo])
    return out


def _infer_risk(n_symbols: int, n_processes: int) -> str:
    """gitnexus-pr-review 风险分级（本地降级推断，detect-changes 无 risk 字段时兜底）。"""
    if n_symbols > 10 or n_processes > 5:
        return "high"
    if n_symbols >= 3 or n_processes >= 2:
        return "medium"
    return "low"


def _risk_rec(risk: str) -> str:
    return {
        "low": "LOW — 变更面小，merge gate 可放行（后R 红队仍需攻击链核查）",
        "medium": "MEDIUM — 变更涉及多符号/流程，merge 前核对爆破半径 + 测试覆盖",
        "high": "HIGH — 大变更面，merge 前必须 impact 逐符号核查 + 双独立检查",
        "critical": "CRITICAL — 触及认证/支付/数据完整性，暂停 merge 走 adjudicate",
    }.get(risk, "风险未知 — 手工评估")


def main(argv=None) -> None:
    base = ""
    repo = ""          # F-REV-75：默认值留空，解析后经 _resolve_repo 单源化（GX_REPO）
    symbol = ""
    limit = 50
    args = list(sys.argv[1:] if argv is None else argv)
    for i, a in enumerate(args):
        if a == "--base" and i + 1 < len(args):
            base = args[i + 1]
        elif a == "--repo" and i + 1 < len(args):
            repo = args[i + 1]
        elif a == "--symbol" and i + 1 < len(args):
            symbol = args[i + 1]
        elif a == "--limit" and i + 1 < len(args):
            try:
                limit = int(args[i + 1])
            except ValueError:
                pass
    if not base:
        print(json.dumps({"ok": False, "error": "--base <ref> required（对比基准 ref，如 HEAD~1）"},
                         ensure_ascii=False))
        return
    repo = _resolve_repo(repo)
    if not repo:
        print(json.dumps({"ok": False, "base": base, "repo": "",
                          "error": "[ERROR] repo 未解析：--repo 未给且 GX_REPO 未注入（F-REV-75）"},
                         ensure_ascii=False))
        return
    print(json.dumps(review_pr(base, repo, symbol, limit), ensure_ascii=False))


if __name__ == "__main__":
    main()

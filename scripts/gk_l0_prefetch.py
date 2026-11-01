#!/usr/bin/env python3
"""gk_l0_prefetch.py — L0 全量预取（L0-a 图/环境源 + L0-b 自检/guard-edit），2026-09-16

动机（用户裁定「全量：L0-a + L0-b + 指令统一 + 机检」）：
  质询（plan-refinement）指令自称「五源验证」，但实测 14/14 质询 artifact **零 gitnexus /
  命令输出证据**（evidence 抽检 10 条全为源码锚）。除指令两份模板自相矛盾外，**注入面本就为
  空**：runner 的证据尾块对 plan-refinement **显式豁免**，且 CLI 只在 crossrev / 具名角色车道
  预取（见 gk_l3_prefetch 的调用条件）。本脚本补 L0 全量预取，CLI 经 GK_L0_EVIDENCE env 注入。

  L0-a（图/环境源）：repo / branch / HEAD / base 四元 + gitnexus 索引状态（**CLI 单点判定后
    传入**，本脚本不自探测）+ detect-changes 变更摘要（复用 gk_l3_prefetch.prefetch）。
  L0-b（自检/guard-edit）：gk_self_check.run_all **唯一实现复用**（issues + 失败项）+
    PROTECTED_REGION 标记清单（从 gatekeeper-cli.sh 的**标记派生**，不复制策略）+
    MAIN worktree 事实。⚠ 逐文件 guard-edit 判定仍是**唯一事实源**，此处只给事实与入口。

确定性：0 API。不可用 → available:false（降级不阻断，对齐 gk_l3_prefetch 契约）。
用法：gk_l0_prefetch.py --repo <name> --repo-dir <dir> [--base <ref>] [--index-status <s>]
                       [--skill-dir <dir>] [--state-file <path>] [--no-selfcheck]
输出：{"available": bool, "digest": "≤2400", "l0a": {...}, "l0b": {...}[, "error"]}
"""
import argparse
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_DIGEST_CAP = 2400


def _git(repo_dir: str, *args: str) -> str:
    """git 只读查询；失败 → ""（不抛：预取不可用不阻断）。"""
    if not repo_dir or not os.path.isdir(repo_dir):
        return ""
    try:
        r = subprocess.run(["git", "-C", repo_dir, *args], capture_output=True,
                           text=True, timeout=15)
        return (r.stdout or "").strip() if r.returncode == 0 else ""
    except Exception:
        return ""


def _l0a(repo: str, repo_dir: str, base: str, index_status: str) -> dict:
    """图/环境源：环境四元 + 索引状态（CLI 传入）+ detect-changes 摘要（复用 L3 预取）。"""
    changed = {}
    try:
        from gk_l3_prefetch import prefetch
        changed = prefetch(repo, base)
    except Exception as e:  # 单点实现异常 → 该分节降级，不影响 L0-b
        changed = {"available": False, "error": f"l3_prefetch_exception: {e}"}
    return {
        "repo": repo,
        "repo_dir": repo_dir,
        "branch": _git(repo_dir, "rev-parse", "--abbrev-ref", "HEAD"),
        "head": _git(repo_dir, "rev-parse", "--short", "HEAD"),
        "base": base,
        "index_status": index_status or "unknown",
        "changed": changed,
    }


_PROTECTED_RE = re.compile(r"^#\s*PROTECTED_REGION_(START|END)::(\w+)")


def _protected_regions(skill_dir: str) -> list[dict]:
    """从 gatekeeper-cli.sh 的 PROTECTED_REGION 标记**派生**范围（标记 = 唯一事实源）。"""
    cli = os.path.join(skill_dir or "", "gatekeeper-cli.sh")
    if not skill_dir or not os.path.exists(cli):
        return []
    stack, out = {}, []
    try:
        with open(cli, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, 1):
                m = _PROTECTED_RE.match(line.strip())
                if not m:
                    continue
                if m.group(1) == "START":
                    stack[m.group(2)] = i
                elif m.group(2) in stack:
                    out.append({"name": m.group(2), "start": stack.pop(m.group(2)), "end": i})
    except Exception:
        return []
    return out


def _l0b(skill_dir: str, state_file: str, with_selfcheck: bool = True) -> dict:
    """自检/guard-edit 事实：self-check 聚合（唯一实现复用）+ 保护区清单 + MAIN worktree。"""
    sc: dict = {"available": False, "error": "disabled"}
    if with_selfcheck:
        try:
            from gk_self_check import run_all
            res = run_all(state_file or "", skill_dir or "")
            fails = [c.get("check", "?") for c in (res.get("checks") or [])
                     if str(c.get("status")) in ("FAIL", "MISSING")]
            sc = {"available": True, "issues": res.get("issues", 0),
                  "failed_checks": fails[:20]}
        except Exception as e:
            sc = {"available": False, "error": f"self_check_exception: {e}"}
    regions = _protected_regions(skill_dir)
    return {
        "self_check": sc,
        "protected_regions": regions,
        "main_worktree": os.environ.get("GK_L0_MAIN_WORKTREE", "") or "",
        "guard_edit_entry": "bash gatekeeper-cli.sh guard-edit <path> [line]  # 逐文件判定唯一事实源",
    }


def _digest(l0a: dict, l0b: dict) -> str:
    ch = l0a.get("changed") or {}
    syms = [s for s in (ch.get("changed_symbols") or []) if s]
    lines = [
        "[L0-a 图/环境源]",
        f"repo={l0a['repo']} branch={l0a.get('branch') or '?'} HEAD={l0a.get('head') or '?'} "
        f"base={l0a.get('base')} gitnexus_index={l0a.get('index_status')}",
    ]
    if ch.get("available"):
        lines.append(f"变更：{ch.get('changed_files', 0)} 文件 / {len(syms)} 符号 / "
                     f"{ch.get('affected_processes', 0)} 受影响流程 / 风险={ch.get('risk') or '?'}")
        lines.append("变更符号: " + (", ".join(syms[:30]) if syms else "(无符号——纯文本/配置/数据变更)"))
    else:
        lines.append(f"变更摘要不可用：{ch.get('error') or 'unknown'}")
    sc = l0b.get("self_check") or {}
    lines.append("[L0-b 自检/guard-edit]")
    if sc.get("available"):
        lines.append(f"self-check：issues={sc.get('issues', 0)}"
                     + ("；失败项: " + ", ".join(sc.get("failed_checks") or []) if sc.get("failed_checks") else "；失败项: 无"))
    else:
        lines.append(f"self-check 不可用：{sc.get('error') or 'unknown'}")
    regs = l0b.get("protected_regions") or []
    lines.append("受保护区（PROTECTED_REGION 标记派生）: "
                 + (", ".join(f"{r['name']}(L{r['start']}-L{r['end']})" for r in regs[:20])
                    if regs else "(无标记)"))
    if l0b.get("main_worktree"):
        lines.append(f"MAIN worktree={l0b['main_worktree']}（直接编辑被 guard-edit 拒 → 须落 feature worktree）")
    lines.append(l0b.get("guard_edit_entry", ""))
    return "\n".join(x for x in lines if x)[:_DIGEST_CAP]


def build(repo: str, repo_dir: str, base: str, index_status: str,
          skill_dir: str, state_file: str, with_selfcheck: bool = True) -> dict:
    if not repo:
        return {"available": False, "error": "[ERROR] repo 未解析（--repo 未给且 GX_REPO 未注入）"}
    l0a = _l0a(repo, repo_dir, base, index_status)
    l0b = _l0b(skill_dir, state_file, with_selfcheck)
    return {"available": True, "repo": repo, "base": base,
            "l0a": l0a, "l0b": l0b, "digest": _digest(l0a, l0b)}


def main(argv=None) -> None:
    p = argparse.ArgumentParser(description="L0 全量预取（图/环境源 + 自检/guard-edit）")
    p.add_argument("--repo", default="")
    p.add_argument("--repo-dir", default="")
    p.add_argument("--base", default="HEAD~1")
    p.add_argument("--index-status", default="")
    p.add_argument("--skill-dir", default="")
    p.add_argument("--state-file", default="")
    p.add_argument("--no-selfcheck", action="store_true")
    a = p.parse_args(sys.argv[1:] if argv is None else argv)
    repo = a.repo or os.environ.get("GX_REPO", "") or ""
    try:
        out = build(repo, a.repo_dir, a.base, a.index_status,
                    a.skill_dir or os.environ.get("SKILL_DIR", ""),
                    a.state_file or os.environ.get("STATE_FILE", ""),
                    with_selfcheck=not a.no_selfcheck)
    except Exception as e:  # 预取失败**不阻断**派发（降级 = 无 L0 预取）
        out = {"available": False, "error": f"l0_prefetch_exception: {e}"}
    print(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    main()

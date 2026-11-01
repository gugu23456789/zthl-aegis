#!/usr/bin/env python3
"""gk_l3_prefetch.py — L3 图证据预取（2026-09-04 L2/L3 换位 · 代码级证据预取 v1）

crossrev（L2 交叉审查）在 preflight B（L3 基线 status-fresh/analyze）之后调用本脚本，
预取 gitnexus `detect-changes compare` 的确定性变更摘要 → CLI 经 GK_L3_EVIDENCE env
注入 subagent 指令（graph-anchored 预取，防 L2 整仓裸读；token 账 30-90k vs 289k）。

实现复用 gk_pr_review_check.review_pr（同一 node.exe 直调 gitnexus + 文本解析契约），
0 API 确定性。

输出契约（CLI/subagent 消费）：
  {"available": true, "repo", "base", "changed_files", "changed_symbols": [...≤20],
   "affected_processes", "risk", "digest": "≤1600 字符摘要"}
  {"available": false, "error": "..."}   # 失败 exit 0 —— 预取不可用不阻断 L2（降级无预取）
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gk_pr_review_check import _resolve_repo, review_pr  # noqa: E402  复用 node 直调 + 解析


def prefetch(repo: str, base: str) -> dict:
    """detect-changes 摘要预取；gitnexus 不可用/解析失败 → available:false（不抛）。"""
    try:
        r = review_pr(base, repo)
    except Exception as e:  # node 缺省/超时/契约异常一律降级，不阻断 L2
        return {"available": False, "error": f"prefetch_exception: {e}"}
    if not r.get("ok"):
        return {"available": False, "error": str(r.get("error", "unknown"))}
    syms = (r.get("changed_symbols") or [])[:20]
    lines = [
        f"repo={repo} base={base}",
        f"变更文件 {r.get('changed_files', 0)} · 符号 {len(syms)} · "
        f"受影响流程 {r.get('affected_processes', 0)} · 风险 {r.get('risk', '?')}",
        "变更符号: " + (", ".join(syms) if syms else "(无符号——纯文本/配置/数据类变更)"),
    ]
    return {
        "available": True,
        "repo": repo,
        "base": base,
        "changed_files": r.get("changed_files", 0),
        "changed_symbols": syms,
        "affected_processes": r.get("affected_processes", 0),
        "risk": r.get("risk", ""),
        "digest": "\n".join(lines),
    }


def main(argv=None) -> None:
    repo = ""          # F-REV-75：默认值留空，解析后单源化（GX_REPO）
    base = "HEAD~1"
    args = list(sys.argv[1:] if argv is None else argv)
    for i, a in enumerate(args):
        if a == "--repo" and i + 1 < len(args):
            repo = args[i + 1]
        elif a == "--base" and i + 1 < len(args):
            base = args[i + 1]
    repo = _resolve_repo(repo)
    if not repo:
        # 契约：预取不可用**不阻断** L2（降级无预取）—— 故 fail-loud 走 available:false，非退出码。
        print(json.dumps({"available": False, "repo": "",
                          "error": "[ERROR] repo 未解析：--repo 未给且 GX_REPO 未注入（F-REV-75）"},
                         ensure_ascii=False))
        return
    print(json.dumps(prefetch(repo, base), ensure_ascii=False))


if __name__ == "__main__":
    main()

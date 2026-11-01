#!/usr/bin/env python3
"""gk_audit_coverage.py — E1 变更面证据探针（audit --coverage，2026-09-06 实装）

出处：security-hardening-assessment §15.1 E1（P2 唯一未实装评估器）→ §15.6 ㉕③ 落点修正：
E1-E4 = plan-refinement（SCR）质询协议的子集评估器，**不新建收敛 CLI**；本命令只产
**变更面事实**（detect-changes 变更符号 + git diff 文件 → 组件分类 → 层需求映射 +
NO-DETECT 标注），收敛/层扩展决策交 plan-refinement 质询子集（绑定句 EVAL-MATRIX）。

确定性：0 API。文件面 = `git diff --name-status <base>..HEAD`（WSL git）；符号面 = 复用
gk_pr_review_check.review_pr（node.exe 直调 gitnexus detect-changes compare，与 L3 预取
gk_l3_prefetch 同链）——gitnexus 不可用/解析失败 → symbols.available:false（降级无符号，
文件面仍成立，不阻断）。A4 合规：无新 _CMD_REG 命令（扩展既有 audit）。

输出契约（CLI/质询 preflight 证据注入消费）：
  {"ok": true, "probe": "E1-coverage", "base", "repo", "repo_dir",
   "changed_files": [{"path","status","component","layers":[...]}...],
   "components": {"cli": n, ...},
   "layer_demand": {"L1": n, ..., "PR": n},       # 每层应跑审查的变更计数（证据，非决策）
   "no_detect_layers": [...],                     # 零变更层 → cell NO-DETECT（GK_ALLOW_NO_DETECT 条件化放行）
   "symbols": {"available": true, "changed_symbols":[...], "risk": "..."}
           | {"available": false, "error": "..."},
   "digest": "≤N 字符摘要行"}
  失败（git 不可用等）→ {"ok": false, "error": "..."}，exit 0（证据探针不阻断）。
"""
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gk_pr_review_check import _resolve_repo, review_pr  # noqa: E402  复用 node 直调 + 解析

_DEFAULT_BASE = "HEAD~1"

# 审查层全集（11 层，含 PR 门禁；E4 四件套同源 REVIEW_LAYERS 语义，仅本探针的
# "潜在层需求" 面使用 —— 变更层映射是证据事实，非决策出口）
_LAYERS = ("L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8", "L9", "L10", "PR")

# 组件 → 潜在应跑审查层（确定性启发式；E1 只产"变更触到哪些层"事实）
_COMPONENT_LAYERS = {
    "cli":     ("L1", "L2", "L6", "L7", "L8", "L9", "L10"),
    "scripts": ("L1", "L2", "L6", "L7", "L8", "L9", "L10"),
    "hooks":   ("L8", "L9", "L10"),
    "engine":  ("L2", "L3", "L5", "L10"),
    "tests":   ("L1", "L8", "L9"),
    "ci":      ("L7", "L10"),
    "docs":    ("L6", "L9"),
    "config":  ("L7",),
}

# 路径形态 → 组件（顺序判定：命中第一个）；pattern = 小写正斜杠归一后 regex
_PATH_RULES = (
    # 测试（先于 hooks/engine/scripts：test_*/_test.* 优先归测试组件）
    ("tests",   (r"tests?/", r"/test_", r"test_[\w-]*\.py$", r"[\w-]*_test\.(py|cc|cpp|h|js|ts)$",
                 r"\.tmp_path_test\.py$")),
    # hooks（pre_tool_hook* / wrapper / env_inject 是 hook 域，非 test_ 前缀才落此）
    ("hooks",   (r"\.trae/hooks", r"hooks\.json", r"pre_tool_hook", r"hook_wrapper")),
    # CI workflow
    ("ci",      (r"\.github/workflows", r"\.gitlab-ci")),
    # 引擎（C++/C/CMake/WASM 源）
    ("engine",  (r"\.(cc|cpp|h|hpp|hh|c|m|mm)$", r"cmakelists\.txt$", r"\.cmake$",
                 r"\.wasm", r"\.cjs$")),
    # 核心 CLI（skill 仓库 gatekeeper-cli.sh）
    ("cli",     (r"gatekeeper-cli\.sh$", r"^bin/", r"\.trae/bin/")),
    # 其余 shell/python 归 scripts
    ("scripts", (r"\.sh$", r"\.py$", r"scripts?/", r"^scripts/")),
    # 文档 / 配置（放后：references/ 与 docs/ 是 md；.json/.toml/.yaml 除 workflow）
    ("docs",    (r"\.(md|markdown)$", r"references?/", r"^docs/", r"skill\.md$")),
    ("config",  (r"\.(json|toml|yaml|yml|ini|cfg)$",)),
)


def classify_path(path: str) -> tuple[str, tuple[str, ...]]:
    """路径 → (component, layers)；未命中默认 cli（gatekeeper 体系多数入口走 CLI）。"""
    p = (path or "").replace("\\", "/").lower()
    for comp, pats in _PATH_RULES:
        for pat in pats:
            if re.search(pat, p):
                return comp, _COMPONENT_LAYERS[comp]
    return "cli", _COMPONENT_LAYERS["cli"]


def parse_git_diff(text: str) -> list[dict]:
    """git diff --name-status 输出 → [{"path","status"}]（跳过 rename 的 → 目标与源）。"""
    files = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status = parts[0]
        # rename/copy: "R100\told\tnew"
        if status[:1] in ("R", "C") and len(parts) >= 3:
            files.append({"path": parts[2], "status": status[:1]})
            files.append({"path": parts[1], "status": status[:1] + "-src"})
        else:
            files.append({"path": parts[1], "status": status[:1]})
    return files


def _git_diff_names(repo_dir: str, base: str) -> str:
    r = subprocess.run(
        ["git", "-C", repo_dir, "diff", "--name-status", f"{base}..HEAD"],
        capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout or "").strip()[:300])
    return r.stdout or ""


def collect_files(repo_dir: str, base: str) -> list[dict]:
    """文件面收集（git diff --name-status base..HEAD）。"""
    return parse_git_diff(_git_diff_names(repo_dir, base))


def aggregate(files: list[dict], symbols: dict | None = None,
              meta: dict | None = None) -> dict:
    """纯聚合（文件 → 组件/层需求/NO-DETECT）。symbols 可选注入（enrich 或降级）。
    meta: {"base","repo","repo_dir"}（digest/输出头元数据）。"""
    meta = meta or {}
    base = meta.get("base", "")
    repo = meta.get("repo", "")
    repo_dir = meta.get("repo_dir", "")
    changed = []
    components: dict[str, int] = {}
    layer_demand = {L: 0 for L in _LAYERS}
    for f in files:
        comp, layers = classify_path(f["path"])
        changed.append({"path": f["path"], "status": f.get("status", "?"),
                        "component": comp, "layers": list(layers)})
        components[comp] = components.get(comp, 0) + 1
        for L in layers:
            layer_demand[L] += 1
    no_detect = [L for L in _LAYERS if layer_demand[L] == 0]
    digest_lines = [
        f"base={base} repo={repo} 变更文件 {len(files)} "
        f"· 组件 {sorted(components, key=components.get, reverse=True)}",
        "层需求: " + ", ".join(f"{L}={layer_demand[L]}" for L in _LAYERS if layer_demand[L])
        + (" | NO-DETECT: " + ",".join(no_detect) if no_detect else ""),
    ]
    out = {"ok": True, "probe": "E1-coverage", "base": base,
           "repo": repo, "repo_dir": repo_dir,
           "changed_files": changed, "components": components,
           "layer_demand": layer_demand, "no_detect_layers": no_detect,
           "digest": "\n".join(digest_lines)}
    out["symbols"] = (symbols if symbols
                      else {"available": False, "error": "no symbols payload"})
    return out


def _enrich_symbols(repo_dir: str, repo: str, base: str) -> dict:
    """符号面 enrich：复用 gk_pr_review_check.review_pr（gitnexus detect-changes）。
    任何异常/失败 → available:false（文件面不阻断）。"""
    try:
        r = review_pr(base, repo)
    except Exception as e:  # node 缺省/超时/解析异常 → 降级无符号
        return {"available": False, "error": f"symbols_enrich_exception: {e}"}
    if not r.get("ok"):
        return {"available": False, "error": str(r.get("error", "unknown"))}
    return {"available": True,
            "changed_symbols": (r.get("changed_symbols") or [])[:50],
            "affected_processes": r.get("affected_processes", 0),
            "risk": r.get("risk", "low")}


def run(base: str, repo_dir: str, repo: str, with_symbols: bool = True) -> dict:
    """证据探针主路径：文件面（git）+ 符号面（gitnexus，可降级）。"""
    try:
        files = collect_files(repo_dir, base)
    except Exception as e:  # git 不可用/base 无效/仓库无历史 → 探针失败（exit 0）
        return {"ok": False, "probe": "E1-coverage", "base": base, "repo": repo,
                "repo_dir": repo_dir, "error": f"file_collect: {e}"}
    syms = _enrich_symbols(repo_dir, repo, base) if with_symbols else None
    return aggregate(files, syms, {"base": base, "repo": repo, "repo_dir": repo_dir})


def main(argv: list[str] | None = None) -> None:
    args = list(sys.argv[1:] if argv is None else argv)
    base = _DEFAULT_BASE
    repo = _resolve_repo("")   # F-REV-75：--repo 未给 → 用 CLI 注入的 GX_REPO（原写死技能仓库名）
    repo_dir = os.environ.get("GK_COV_DIR", "")
    no_sym = False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--base" and i + 1 < len(args):
            base = args[i + 1]; i += 2
        elif a == "--repo" and i + 1 < len(args):
            repo = args[i + 1]; i += 2
        elif a == "--repo-dir" and i + 1 < len(args):
            repo_dir = args[i + 1]; i += 2
        elif a == "--no-symbols":
            no_sym = True; i += 1
        elif not a.startswith("-") and a != base:
            base = a; i += 1  # 位置参数 = scope（兼容 `audit --coverage HEAD~3`）
        else:
            i += 1
    if not repo_dir:
        print(json.dumps({"ok": False, "probe": "E1-coverage",
                          "error": "GK_COV_DIR/repo-dir 缺失（由 cmd_audit 计算活动仓库目录）"},
                         ensure_ascii=False))
        return
    print(json.dumps(run(base, repo_dir, repo, with_symbols=not no_sym),
                     ensure_ascii=False))


if __name__ == "__main__":
    main()

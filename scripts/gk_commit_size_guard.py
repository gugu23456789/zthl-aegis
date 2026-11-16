#!/usr/bin/env python3
"""gk_commit_size_guard.py — 提交面「主题混合度 + 阈值」提示（2026-11-10）。

设计（用户裁定 2026-11-10）：
- **默认 warn**：只产出 `warnings`，不阻断提交；`GK_COMMIT_GUARD=block` 才拒绝，
  `off` 完全静默。门禁是**建议**而不是交警，避免把正常重构卡死。
- **判据 = 主题混合度 + 可配阈值**（不是死板的单一数字）：
    · 模块数（staged 路径顶层目录）≥ `GK_COMMIT_GUARD_MODULES`（默认 3）
    · 文件数 > `GK_COMMIT_GUARD_FILES`（默认 10）
    · 行数（insertions+deletions）> `GK_COMMIT_GUARD_LINES`（默认 500）
  任一命中即提示。
- **不绑定 git-workflow**：只有 `git-workflow` 在 PATH 里才给 `history stage-pick`
  建议，否则给通用 git 分批提交指引 —— 技能是通用件，不能假设外部工具存在。

用法：`python3 scripts/gk_commit_size_guard.py --repo <dir> [--mode warn|block|off]`
退出码：0 = 通过（含 warn）；1 = block 且命中；2 = 参数/环境错。
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

_DEFAULTS = {"files": 10, "lines": 500, "modules": 3}


def _run(repo: str, *args: str) -> str:
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""


def _staged_files(repo: str) -> list:
    return [x.strip() for x in _run(repo, "diff", "--cached", "--name-only").splitlines()
            if x.strip()]


def _changed_lines(repo: str) -> int:
    stat = _run(repo, "diff", "--cached", "--shortstat")
    ins = re.search(r"(\d+) insertions?\(\+\)", stat)
    dele = re.search(r"(\d+) deletions?\(-\)", stat)
    return int(ins.group(1) if ins else 0) + int(dele.group(1) if dele else 0)


def _module(path: str) -> str:
    """顶层目录 = 主题单位；根文件归 `(root)`。`scripts/test_*` 天然同属 scripts。"""
    p = path.replace("\\", "/")
    return p.split("/", 1)[0] if "/" in p else "(root)"


def _int_env(name: str, default: int) -> int:
    try:
        return max(0, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


def _suggest(repo: str) -> str:
    """拆分建议：git-workflow 存在才提它（不产生依赖）。"""
    if shutil.which("git-workflow"):
        return "git-workflow history stage-pick --repo %s" % repo
    return "按模块分批：git restore --staged <其余文件> → 逐组 git add && git commit"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_commit_size_guard.py")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--mode", default=os.environ.get("GK_COMMIT_GUARD", "warn"),
                    choices=("warn", "block", "off"))
    a = ap.parse_args(argv)

    if not os.path.isdir(os.path.join(a.repo, ".git")) and not os.path.isdir(a.repo):
        print(json.dumps({"ok": False, "error": "repo not found: %s" % a.repo},
                         ensure_ascii=False))
        return 2
    if a.mode == "off":
        print(json.dumps({"ok": True, "warnings": [], "mode": "off"}, ensure_ascii=False))
        return 0

    files = _staged_files(a.repo)
    lines = _changed_lines(a.repo)
    mods = sorted({_module(f) for f in files})
    caps = {"files": _int_env("GK_COMMIT_GUARD_FILES", _DEFAULTS["files"]),
            "lines": _int_env("GK_COMMIT_GUARD_LINES", _DEFAULTS["lines"]),
            "modules": _int_env("GK_COMMIT_GUARD_MODULES", _DEFAULTS["modules"])}

    hit = (len(files) > caps["files"]
           or lines > caps["lines"]
           or len(mods) >= caps["modules"])
    out = {"ok": True, "mode": a.mode, "files": len(files), "lines": lines,
           "modules": mods, "thresholds": caps, "warnings": []}
    if not hit:
        print(json.dumps(out, ensure_ascii=False))
        return 0

    item = {"id": "COMMIT_TOO_LARGE", "files": len(files), "lines": lines,
            "modules": mods, "thresholds": caps, "suggest": _suggest(os.path.abspath(a.repo))}
    if a.mode == "block":
        out.update({"ok": False, "error": "COMMIT_TOO_LARGE", "detail": item})
        print(json.dumps(out, ensure_ascii=False))
        return 1
    out["warnings"].append(item)
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

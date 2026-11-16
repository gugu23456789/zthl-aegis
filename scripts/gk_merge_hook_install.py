#!/usr/bin/env python3
"""gk_merge_hook_install.py — 安装/卸载 `reference-transaction` 合并闸钩子（R0.24，2026-11-13）。

契约:
  - 输入: `install|uninstall|status` [--repo <path>] [--force]
  - 输出: stdout JSON `{ok, action, hook, installed, ...}`；rc 0=成功 1=拒绝
  - 失败: 已有**非本闸**的钩子且未 `--force` ⟹ 拒绝（不覆盖别人的钩子，fail-closed）

单一事实源: 判据全在 `scripts/gk_merge_hook.py`；安装时**拷贝到钩子同目录**（`gk_merge_hook.py`），
shim 只做「定位同目录模块 + 解析解释器」。**禁写绝对路径**：写死安装时的解释器/技能路径会踩两个
坑——worktree 退役后指向消失、换机/换 venv 即全部失效（CONVENTIONS「禁止写死个人 venv 路径」）。
解释器与 `scripts/_accept_cli.sh` 同式：`ACCEPT_PY` → `gk_accept_py.py` → `python3`。

为什么需要它: Agent 面 Gate R0.24 只覆盖"经过 hook 的工具调用"；人手终端 / 脚本 / CI 直跑 git
时会绕过 ⟹ 必须在 git ref 更新处再设一道（`reference-transaction` 是唯一能**阻断**快进 merge
的钩子点，`pre-merge-commit` 对 ff 不触发）。
"""
import argparse
import json
import os
import shutil
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_merge_guard as G  # noqa: E402
import gk_merge_hook as H   # noqa: E402

_HOOK = "reference-transaction"
_MOD = "gk_merge_hook.py"
_MARK = "gk_merge_hook.py"
_SRC = Path(H.__file__).resolve()


def _hooks_dir(repo: str) -> str:
    cd = H.common_dir(repo)
    return os.path.join(cd, "hooks") if cd else ""


def hook_path(repo: str) -> str:
    cd = H.common_dir(repo)
    return os.path.join(cd, "hooks", _HOOK) if cd else ""


def module_path(repo: str) -> str:
    d = _hooks_dir(repo)
    return os.path.join(d, _MOD) if d else ""


def _shim() -> str:
    """shim：只做两件事 —— 定位**同目录**模块 + 按单源解析解释器（无绝对路径）。"""
    return (
        "#!/bin/sh\n"
        "# 由 `gatekeeper-cli.sh merge-hook --install` 生成（2026-11-13 R0.24）；**禁手改**。\n"
        "# 判据实现 = 同目录 %s（安装时从 skills 拷贝）；解释器单源 = ACCEPT_PY → gk_accept_py.py → python3。\n"
        "H=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\n"
        "REPO=$(git rev-parse --show-toplevel 2>/dev/null)\n"
        "PY=\"\"\n"
        "if [ -n \"$REPO\" ] && [ -f \"$REPO/scripts/gk_accept_py.py\" ]; then\n"
        "  PY=$(python3 \"$REPO/scripts/gk_accept_py.py\" 2>/dev/null)\n"
        "fi\n"
        "[ -n \"$PY\" ] || PY=$(command -v python3 2>/dev/null)\n"
        # Windows Git-Bash 常只有 `python`/`py`（无 python3）⟹ 逐个回退，仍 fail-closed
        "[ -n \"$PY\" ] || PY=$(command -v python 2>/dev/null)\n"
        "[ -n \"$PY\" ] || PY=$(command -v py 2>/dev/null)\n"
        "[ -n \"$PY\" ] || { echo 'BLOCK[merge-hook]: 无可用 python（fail-closed）' >&2; exit 1; }\n"
        "exec \"$PY\" \"$H/%s\" \"$@\"\n" % (_MARK, _MOD)
    )


def _write_exec(path: str, text: str) -> None:
    Path(path).write_text(text, encoding="utf-8")
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def install(repo: str, force: bool = False) -> dict:
    repo = G.norm_repo(repo or G._default_repo())
    p, mod = hook_path(repo), module_path(repo)
    if not p:
        return {"ok": False, "action": "install", "error": "COMMON_DIR_UNRESOLVED", "repo": repo}
    os.makedirs(os.path.dirname(p), exist_ok=True)
    if os.path.exists(p):
        try:
            old = Path(p).read_text(encoding="utf-8", errors="replace")
        except OSError:
            old = ""
        if _MARK not in old and not force:
            return {"ok": False, "action": "install", "hook": p, "installed": False,
                    "error": "HOOK_EXISTS_NOT_OURS",
                    "next": "确认可覆盖后加 --force（本闸会接管该仓库全部合并）"}
    shutil.copyfile(str(_SRC), mod)                     # 判据实现随钩子落地（worktree 退役不影响）
    _write_exec(p, _shim())
    return {"ok": True, "action": "install", "hook": p, "module": mod,
            "installed": True, "repo": repo}


def uninstall(repo: str, force: bool = False) -> dict:
    repo = G.norm_repo(repo or G._default_repo())
    p, mod = hook_path(repo), module_path(repo)
    if not p:
        return {"ok": False, "action": "uninstall", "error": "COMMON_DIR_UNRESOLVED"}
    if not os.path.exists(p):
        return {"ok": True, "action": "uninstall", "hook": p, "installed": False}
    try:
        old = Path(p).read_text(encoding="utf-8", errors="replace")
    except OSError:
        old = ""
    if _MARK not in old and not force:
        return {"ok": False, "action": "uninstall", "hook": p, "error": "HOOK_NOT_OURS",
                "next": "确认要删除他人钩子再加 --force"}
    os.unlink(p)
    if os.path.exists(mod):
        os.unlink(mod)
    return {"ok": True, "action": "uninstall", "hook": p, "module": mod, "installed": False}


def status(repo: str) -> dict:
    repo = G.norm_repo(repo or G._default_repo())
    p, mod = hook_path(repo), module_path(repo)
    if not p:
        return {"ok": False, "action": "status", "error": "COMMON_DIR_UNRESOLVED"}
    try:
        txt = Path(p).read_text(encoding="utf-8", errors="replace")
    except OSError:
        txt = ""
    stale = True
    if os.path.exists(mod):
        try:
            stale = Path(mod).read_bytes() != _SRC.read_bytes()
        except OSError:
            stale = True
    return {"ok": True, "action": "status", "hook": p, "module": mod,
            "installed": bool(txt), "ours": _MARK in txt, "stale": stale,
            "repo": repo, "ticket_ttl": H.TICKET_TTL}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_merge_hook_install.py")
    ap.add_argument("action", choices=["install", "uninstall", "status"])
    ap.add_argument("--repo", default="")
    ap.add_argument("--force", action="store_true")
    ns = ap.parse_args(argv)
    if ns.action == "install":
        out = install(ns.repo, ns.force)
    elif ns.action == "uninstall":
        out = uninstall(ns.repo, ns.force)
    else:
        out = status(ns.repo)
    print(json.dumps(out, ensure_ascii=False))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())

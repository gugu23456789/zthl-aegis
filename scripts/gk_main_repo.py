#!/usr/bin/env python3
"""主仓路径**运行时解析**（开源前置，2026-10-31；单源，禁第二实现）。

优先级：`GK_MAIN_REPO`（绝对路径）→ `state.target_repo` → META `target_repo` → `git rev-parse`。
解析失败 ⟹ `ok=False`（调用方 fail-closed；**绝不**用调用方 cwd 冒充主仓）。

安全：只接受绝对路径且拒绝 `..` 段；`state` / META 的值同样校验（防 scope 边界重定向）。
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path


def _abs(p) -> str:
    p = str(p or "").strip().replace("\\", "/")
    if not p:
        return ""
    if ".." in p.split("/"):
        return ""
    if re.match(r"^[A-Za-z]:/", p) or p.startswith("/"):
        return p
    return ""


def _from_state(state_file: str):
    try:
        d = json.loads(Path(state_file).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return "", ""
    gd = d.get("gate_data") or {}
    return (str(d.get("target_repo") or gd.get("target_repo") or ""),
            str(gd.get("plan") or d.get("plan") or ""))


def _from_meta(plan_file: str) -> str:
    try:
        text = Path(plan_file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    m = re.search(r"^\s*target_repo:\s*(\S+)\s*$", text, re.M)
    return m.group(1) if m else ""


def _wslpath(flag: str, p: str) -> str:
    try:
        out = subprocess.run(["wslpath", flag, p], capture_output=True, text=True, timeout=5)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def _to_wsl(p: str) -> str:
    """已是 WSL 形态（以 `/` 开头）⟹ 原样返回；仅 Windows 形态才过 wslpath。

    2026-10-31 实测：本机 `wslpath -u /tmp/x` 会误返回 `/mnt/c/tmp/x`，故必须先判形态。
    """
    if p.startswith("/"):
        return p
    return _wslpath("-u", p) or p


def _to_win(p: str) -> str:
    w = _wslpath("-w", p)
    if w:
        return w.replace("\\", "/")
    m = re.match(r"^/mnt/([A-Za-z])/(.*)$", p)
    return ("%s:/%s" % (m.group(1).upper(), m.group(2))) if m else ""


def resolve(state_file: str = "", plan_file: str = "", cwd: str = "", env=None) -> dict:
    e = env if env is not None else os.environ
    cand = _abs(e.get("GK_MAIN_REPO") or "")
    source = "env" if cand else ""
    if not cand and state_file:
        v, plan = _from_state(state_file)
        cand, source = _abs(v), "state.target_repo"
        plan_file = plan_file or plan
    if not cand and plan_file:
        cand, source = _abs(_from_meta(plan_file)), "meta.target_repo"
    if not cand:
        try:
            base = cwd or (e.get("GK_WORKTREE_CWD") or "") or os.getcwd()
            out = subprocess.run(["git", "-C", base, "rev-parse", "--show-toplevel"],
                                 capture_output=True, text=True, timeout=10)
            if out.returncode == 0:
                cand, source = _abs(out.stdout.strip()), "git"
        except (OSError, subprocess.SubprocessError):
            pass
    if not cand:
        return {"ok": False, "error": "MAIN_REPO_UNRESOLVED", "source": "",
                "wsl": "", "win": ""}
    wsl = _to_wsl(cand)
    return {"ok": True, "source": source, "wsl": wsl, "win": _to_win(wsl)}


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="gk_main_repo.py")
    ap.add_argument("--state", default="")
    ap.add_argument("--plan", default="")
    ap.add_argument("--cwd", default="")
    ap.add_argument("--print-lines", action="store_true")
    a = ap.parse_args(argv)
    r = resolve(a.state or os.environ.get("STATE_FILE", ""), a.plan, a.cwd)
    if a.print_lines:
        print(r.get("wsl", ""))
        print(r.get("win", ""))
        return 0 if r.get("ok") else 1
    print(json.dumps(r, ensure_ascii=False))
    return 0 if r.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

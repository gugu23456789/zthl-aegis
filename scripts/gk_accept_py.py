#!/usr/bin/env python3
"""gk_accept_py.py — **验收解释器解析的唯一事实源**（公开面不写死个人 venv 路径）。

优先级（确定性，无探测副作用）：
  1. 环境变量 `ACCEPT_PY`（显式 = 最高优先，CI / 本机覆盖都走这里）；
  2. `scripts/_accept_py.local`（**本机私有**，随仓 gitignore；一行解释器路径）——
     维护者机器用它绑定隔离 venv，公开 clone 不会有此文件；
  3. 回落 `python3`（公开面缺省 = 系统解释器，`python3 -m pytest` 可跑即可）。

为什么单独成模块：`scripts/_accept_cli.sh`（bash）、`scripts/_redfirst_cli.sh`（bash）、
`scripts/pre_tool_hook.py`（Gate R0.16）与 `scripts/test_gk_accept_cli.py` 都需要同一个答案；
四处各写一份 `"/opt/…"` 字面量 = 漂移源（换机器/换 venv 即四处不同步）。
"""
import os
import re
import shutil
import subprocess

LOCAL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_accept_py.local")
DEFAULT = "python3"


def _plat_of_this_process() -> str:
    return "win" if os.name == "nt" else "wsl"


def _pin_candidates() -> list:
    """本机 pin：按平台标记取行（`win:` / `wsl:` / 裸路径通吃）。"""
    plat = _plat_of_this_process()
    out = []
    try:
        with open(LOCAL_FILE, encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"^(win|msys|wsl|linux)\s*:\s*(.+)$", line)
                if m:
                    tag = "win" if m.group(1) in ("win", "msys") else "wsl"
                    if tag == plat:
                        out.append(m.group(2).strip())
                else:
                    out.append(line)          # 旧格式：裸路径 = 通吃
    except OSError:
        pass
    return out


def _repo_roots() -> list:
    """仓根 + （worktree 时）主树根 —— `.venv*` 在 gitignore 里，不随 worktree 派生。"""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    roots = [here]
    try:
        r = subprocess.run(["git", "-C", here, "rev-parse", "--git-common-dir"],
                           capture_output=True, text=True, timeout=20)
        gcd = (r.stdout or "").strip()
        if gcd:
            if not os.path.isabs(gcd):
                gcd = os.path.join(here, gcd)
            main = os.path.dirname(os.path.abspath(gcd))
            if os.path.isdir(main) and os.path.normcase(main) != os.path.normcase(here):
                roots.append(main)
    except Exception:
        pass
    return roots


def _venv_candidates() -> list:
    """仓内 `.venv*`：按**本进程平台**只取对应布局（Windows=Scripts/，POSIX=bin/）。"""
    win = _plat_of_this_process() == "win"
    out = []
    for root in _repo_roots():
        try:
            names = sorted(os.listdir(root))
        except OSError:
            continue
        for n in names:
            if n != ".venv" and not n.startswith(".venv-"):
                continue
            v = os.path.join(root, n)
            if not os.path.isdir(v):
                continue
            sub = [("Scripts", "python.exe")] if win else [("bin", "python"), ("bin", "python3")]
            for d, exe in sub:
                p = os.path.join(v, d, exe)
                if os.path.isfile(p):
                    out.append(p)
    return out


def resolve() -> str:
    """验收解释器解析（**顺序契约与 `scripts/py_resolve.sh` 一致**，禁各自发明优先级）。

    env `ACCEPT_PY` → 本机 pin（按平台取行）→ 仓内 `.venv*`（含 worktree 的主树回落）
    → PATH 上的 `python3`/`python` → `python3`。

    ⚠ 为什么这里**不 spawn bash 去复用** `py_resolve.sh`（2026-11-02 实测）：
      Windows python 的 `subprocess(["bash"])` 在本机命中的是 `System32\bash.exe`（WSL），
      其 `uname` 是 Linux ⟹ 自动探测会把**Windows 调用方**判成 wsl ⟹ 候选变成 `/opt/…`
      （WSL 里存在、Windows 上不可执行）⟹ 返回一个本侧根本用不了的解释器。
      故：**平台由本进程的 `os.name` 权威判定**，两侧各自实现同一顺序契约（有回归臂对拍）。
    """
    env = (os.environ.get("ACCEPT_PY") or "").strip()
    if env:
        return env
    win = _plat_of_this_process() == "win"

    def _ok(p: str) -> bool:
        if not p or not os.path.isfile(p):
            return win and shutil.which(p) is not None   # 允许 PATH 名（如 python3）
        return os.access(p, os.X_OK) or win

    for c in _pin_candidates():
        if _ok(c):
            return c
    for c in _venv_candidates():
        if _ok(c):
            return c
    for name in ("python3", "python"):
        w = shutil.which(name)
        if w:
            return w
    return DEFAULT


if __name__ == "__main__":
    print(resolve())

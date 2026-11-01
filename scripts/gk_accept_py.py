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

LOCAL_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_accept_py.local")
DEFAULT = "python3"


def resolve() -> str:
    env = (os.environ.get("ACCEPT_PY") or "").strip()
    if env:
        return env
    try:
        with open(LOCAL_FILE, encoding="utf-8") as f:
            line = f.readline().strip()
        if line:
            return line
    except OSError:
        pass
    return DEFAULT


if __name__ == "__main__":
    print(resolve())

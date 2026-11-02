#!/usr/bin/env python3
"""gk_worker_epoch.py — worker 服务面依赖文件的**指纹**（A7 接线，2026-10-29）

## 为什么需要它（实测缺口）

`gk_worker.py` 把 `pid/port/token` 写进 pidfile，但**没有代码版本**。daemon 在启动时
import 各 `gk_*` 模块 ⟹ 代码改了之后，只要 daemon 还活着（TTL 内），它仍按**旧逻辑**作答。
对 fail-closed 启动路径来说这是**静默错误**（预算/门禁/域路由都可能按旧规则判）。

修法：daemon 启动时算一次 `code_epoch` 写 pidfile 第 4 行；客户端每次调用前本地重算并比对，
不符 ⟹ 视为不可用（调用方回退直读），**绝不**静默用旧逻辑。

## 指纹口径

只取 `(文件名, st_mtime_ns, st_size)` 三元组（不读内容 ⟹ 每次调用只付 8 次 stat）。
覆盖 worker 实际服务的模块（`_GK_MODULES` 的宿主 + state 读面 + 本文件）。
缺文件记 `missing`（缺依赖也是状态的一部分：装上/删掉都会换 epoch）。
"""
import hashlib
import os

# 顺序固定（哈希稳定）；新增/删除都会改 epoch，这是**期望行为**。
_DEPS = (
    "gk_worker.py",
    "gk_worker_epoch.py",
    "gk_route_center.py",
    "gk_state_route.py",
    "gk_state.py",
    "gk_json_utils.py",
    "gk_state_forms.py",
    "gk_state_query.py",
)

_EPOCH_LEN = 16


def code_epoch(script_dir: str = "") -> str:
    """返回 16 位十六进制指纹；任何 stat 失败都记 missing（不抛）。"""
    d = script_dir or os.path.dirname(os.path.abspath(__file__))
    h = hashlib.sha256()
    for name in _DEPS:
        p = os.path.join(d, name)
        try:
            st = os.stat(p)
        except OSError:
            h.update(("%s:missing;" % name).encode())
            continue
        h.update(("%s:%d:%d;" % (name, st.st_mtime_ns, st.st_size)).encode())
    return h.hexdigest()[:_EPOCH_LEN]


def main(argv=None) -> int:
    import sys
    print(code_epoch((sys.argv[1:2] or [""])[0]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

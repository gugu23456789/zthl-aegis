#!/usr/bin/env python3
"""REPO_ROOTS 不得含死路径（S7 / `spz2glb` 实证，2026-09-20）。

现场（实测，非读码推测）：`REPO_ROOTS["spz2glb"]` 的值多嵌了一层 `<workspace>/`
（`.../Downloads/<workspace>/spz_ecosystem_simplified/tools/spz_to_glb`）—— 实测**不存在**；
真实位置 `.../Downloads/spz_ecosystem_simplified/tools/spz_to_glb` 实测**存在**。
逐项实存性核对：该字典 8 项里 `spz2glb` 是**唯一** MISSING（其余 7 项 + 计划给的新值全 EXISTS）
⟹ 正是计划 §8.1 的 S7「既有死路径，与迁移无关但会被迁移放大」：
`read_repo(spz2glb)` 恒失败（`[ERROR]` 或 traversal 分支），而该别名用于 subagent 只读取用 spz2glb 样例。

判据单源：复用 `subagent_runner._native_root` 做宿主形态归一（`/mnt/c/x` → `C:/x`），
即生产代码在 `startswith(root)` 之前用的**同一个**函数 —— 避免测试自抄一份形态转换。

宿主适用性：`REPO_ROOTS` 是**宿主机绝对路径**清单，非本机宿主上整文件 skip
（对齐既有 `symbol_index_existence SKIP` 一类处置）—— 本用例只在主仓 root 可解析时生效。
"""
import sys
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import subagent_runner as sr  # noqa: E402

pytestmark = pytest.mark.skipif(
    not Path(sr._native_root(sr.REPO_ROOTS["gatekeeper"])).exists(),
    reason="非本机宿主：REPO_ROOTS 为宿主机绝对路径清单，跨宿主不适用")


def _missing() -> dict:
    """当前死路径清单（键 → 原值）。"""
    return {k: v for k, v in sr.REPO_ROOTS.items() if not Path(sr._native_root(v)).exists()}


def test_repo_roots_all_exist():
    """每一项都必须在本宿主实存 —— 红先形态：修前 `spz2glb` 必在此清单内。"""
    assert _missing() == {}, "REPO_ROOTS 含死路径（键 → 值）：%s" % _missing()


def test_detector_can_flag_dead_path(monkeypatch):
    """自证判据不是恒真：注入一条死路径必须被检出（防「空断言假绿」）。"""
    monkeypatch.setitem(sr.REPO_ROOTS, "__probe_no_such_repo__", "/mnt/c/__no_such_repo__")
    assert "__probe_no_such_repo__" in _missing()

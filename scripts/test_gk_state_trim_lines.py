#!/usr/bin/env python3
"""state 三条腿裁剪线**按墙比例定价** + 余量不变式（owner 2026-11-01 裁定「按比例放大」）。

背景
====
2026-10-16 墙已 ×10（`STATE_SIZE_WALL` = 2,621,440 B），但三条腿在 2026-10-26 被**统一拍成
128KB 定值** ⟹ 相对墙从 31.25%/25%/25% 掉到 4.9% ⟹ **裁剪线结构性失效**（三腿全满也只占墙
14.6%，永远撞不到墙，等于没有裁剪线）。2026-11-01 owner 裁定按**同一比例**回填。

三条腿（数值单源 = `gk_json_utils`）：
  · `subagent_history`  → `HIST_MAX_BYTES`        = 墙 × 45% = 1152KB（bash `_HIST_MAX_BYTES` 为同值字面量）
  · `task_pipeline`     → `TASK_PIPE_MAX_BYTES`   = 墙 × 20% = 512KB（`gk_task_gate` **import** 本常量）
  · `ecc_findings`      → `ECC_MAX_BYTES`         = 墙 × 20% = 512KB

判据
====
1. bash 字面量 == python 单源值（禁各自漂移）；
2. `gk_task_gate` 的腿 == `gk_json_utils.TASK_PIPE_MAX_BYTES`（禁本地第二定义）；
3. 每条腿 == 墙的固定比例（45% 或 20%）；
4. **比例不变式**：三腿合计 ∈ [75%, 90%] 墙 —— 既不得「三腿满线仍只占零头」（失效），
   也不得「三腿合法 ⟹ 整 state 违规」（余量至少 10%）；
5. bash 侧保留 `GK_STATE_TRIM_KB` 覆盖口（运维显式改线，不需改源码）。
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_json_utils as J  # noqa: E402
import gk_task_gate  # noqa: E402

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_CLI = os.path.join(os.path.dirname(_SCRIPT_DIR), "gatekeeper-cli.sh")


def _cli_text() -> str:
    with open(_CLI, encoding="utf-8", errors="replace") as f:
        return f.read()


def _hist_max_bytes() -> int:
    """从 CLI 源码读出 `_HIST_MAX_BYTES`（bash 常量，Python 不可 import）。"""
    m = re.search(r"^_HIST_MAX_BYTES=(\d+)", _cli_text(), re.M)
    assert m, "gatekeeper-cli.sh 缺 `_HIST_MAX_BYTES=<int>` 定义"
    return int(m.group(1))


def test_three_legs_match_single_source():
    """bash 字面量与 python 单源逐值一致（禁三份各自漂移）。"""
    assert _hist_max_bytes() == J.HIST_MAX_BYTES, (
        "history 腿漂移：bash=%d python=%d" % (_hist_max_bytes(), J.HIST_MAX_BYTES))
    assert gk_task_gate._TASK_PIPE_MAX_BYTES == J.TASK_PIPE_MAX_BYTES, (
        "pipeline 腿漂移：%d vs %d"
        % (gk_task_gate._TASK_PIPE_MAX_BYTES, J.TASK_PIPE_MAX_BYTES))
    assert J.ECC_MAX_BYTES == J.TASK_PIPE_MAX_BYTES, (
        "findings 腿与 pipeline 腿不同比例：%d vs %d" % (J.ECC_MAX_BYTES, J.TASK_PIPE_MAX_BYTES))


def test_legs_are_wall_ratios():
    """每条腿 = 墙的固定比例（history 45%，pipeline/findings 20%）。"""
    wall = J.STATE_SIZE_WALL
    assert J.HIST_MAX_BYTES == wall * 45 // 100, (J.HIST_MAX_BYTES, wall * 45 // 100)
    assert J.TASK_PIPE_MAX_BYTES == wall * 20 // 100, (J.TASK_PIPE_MAX_BYTES, wall * 20 // 100)
    assert J.ECC_MAX_BYTES == wall * 20 // 100


def test_legs_scale_is_not_structurally_dead():
    """三腿合计须占墙 [75%, 90%]：太小 = 裁剪线失效；太大 = 三腿合法却撞墙。"""
    total = J.HIST_MAX_BYTES + J.TASK_PIPE_MAX_BYTES + J.ECC_MAX_BYTES
    ratio = float(total) / J.STATE_SIZE_WALL
    assert 0.75 <= ratio <= 0.90, (
        "三腿合计 %.3f 墙（%d B / %d B）—— 应落在 [0.75, 0.90]" % (ratio, total, J.STATE_SIZE_WALL))


def test_trim_line_env_override_documented():
    """bash 侧须有 `GK_STATE_TRIM_KB` 覆盖口（运维可改线，不需改源码）。"""
    assert "GK_STATE_TRIM_KB" in _cli_text(), "缺 GK_STATE_TRIM_KB 覆盖口"

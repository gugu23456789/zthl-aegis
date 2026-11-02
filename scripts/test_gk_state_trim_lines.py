#!/usr/bin/env python3
"""state 三条腿裁剪线**按墙比例定价** + 有界不变式（owner 2026-11-02「收紧 payload」）。

背景
====
2026-10-16 墙已 ×10（`STATE_SIZE_WALL` = 2,621,440 B）。2026-11-01 曾把三腿抬到
45%/20%/20%（合计 85%）以「按比例放大」；但 satellite 冷侧车/分片已承接 bulk ⟹ 该口径
会把主 state 继续推向墙。2026-11-02 收紧为**三腿各 5% = 15%**，其余 85% 留给其它 key。

三条腿（数值单源 = `gk_json_utils`）：
  · `subagent_history`  → `HIST_MAX_BYTES`        = 墙 × 5% = 128KB（bash `_HIST_MAX_BYTES` 同值）
  · `task_pipeline`     → `TASK_PIPE_MAX_BYTES`   = 墙 × 5% = 128KB（`gk_task_gate` **import** 本常量）
  · `ecc_findings`      → `ECC_MAX_BYTES`         = 墙 × 5% = 128KB

判据
====
1. bash 字面量 == python 单源值（禁各自漂移）；
2. `gk_task_gate` 的腿 == `gk_json_utils.TASK_PIPE_MAX_BYTES`（禁本地第二定义）；
3. 每条腿 == 墙的固定比例（5%）；
4. **有界不变式**：单腿 ≥ 一轮预算（否则归档抖动），单腿 ≤ 10% 墙、三腿合计 ≤ 30% 墙
   （主 state 必须给其它 key 留 ≥70% 余量）；
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
    """每条腿 = 墙的固定比例（2026-11-02 起各 5%）。"""
    wall = J.STATE_SIZE_WALL
    assert J.HIST_MAX_BYTES == wall * 5 // 100, (J.HIST_MAX_BYTES, wall * 5 // 100)
    assert J.TASK_PIPE_MAX_BYTES == wall * 5 // 100, (J.TASK_PIPE_MAX_BYTES, wall * 5 // 100)
    assert J.ECC_MAX_BYTES == wall * 5 // 100


def test_legs_bounded_and_hold_one_round():
    """单腿 ≥ 一轮（防归档抖动）；单腿 ≤10% 墙、三腿合计 ≤30% 墙（给其它 key 留余量）。"""
    import gk_satellite as S
    wall = J.STATE_SIZE_WALL
    for leg in (J.HIST_MAX_BYTES, J.TASK_PIPE_MAX_BYTES, J.ECC_MAX_BYTES):
        assert leg >= S.SAT_ROUND_BUDGET_BYTES, "腿小于一轮预算 ⟹ 归档抖动"
        assert leg <= wall * 10 // 100, "单腿 > 10% 墙 ⟹ 多腿可撑爆 state"
    total = J.HIST_MAX_BYTES + J.TASK_PIPE_MAX_BYTES + J.ECC_MAX_BYTES
    assert total <= wall * 30 // 100, (
        "三腿合计 %d B > 30%% 墙（%d B）" % (total, wall * 30 // 100))


def test_trim_line_env_override_documented():
    """bash 侧须有 `GK_STATE_TRIM_KB` 覆盖口（运维可改线，不需改源码）。"""
    assert "GK_STATE_TRIM_KB" in _cli_text(), "缺 GK_STATE_TRIM_KB 覆盖口"

#!/usr/bin/env python3
"""裸跑质询拦截 + 质询基线新鲜度门 —— 红先臂（2026-10-05，用户令）。

病象①（裸跑质询裸窄任务）：`monitor --subagent --role plan-refinement "<裸窄任务>"` 绕过统一入口
  `plan-refinement <plan> --task …`（其产出的 full_task 才是 task_pipeline 的合法载体）⟹
  裸 task 不入 task_pipeline、未过 L2 入站门，却因原注释「逃生 = 显式 --role plan-refinement」
  而径直进入高权质询通道。实证：本轮两臂即裸任务下发，`moa-aggregate --role` 归属失据、被过滤。
病象②（质询无基线门）：`_review_channel_preflight` 的「L3 基线 status-fresh」（B）原仅 crossrev
  通道 ⟹ 质询可在 gitnexus baseline stale 时照跑（`node_guard` 仅 advance 且默认 advisory）。

判据（红先，落刀前 HEAD **必红**）：
  arm1  `gk_task_gate.task_in_pipeline` 存在且按 full_task 命中（HEAD 无该符号 → 红）
  arm2  `cmd_monitor` 质询守卫须含 `BARE_PLAN_REFINEMENT` + 消费 `task_in_pipeline`（HEAD 无 → 红）
  arm3  `_review_channel_preflight` 的 B 块须覆盖 plan-refinement + `BASELINE_STALE`（HEAD 仅 crossrev → 红）
  arm4  守门臂（改前已绿）：`REVIEW_ROLE_UNSPECIFIED` 与 B 块两通道并集不得被破坏
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def _src() -> str:
    return CLI.read_text(encoding="utf-8")


def test_task_in_pipeline_helper(tmp_path):
    """arm1：按 full_task 归属判定；裸 task / 读失败 ⟹ False（fail-closed）。"""
    from gk_task_gate import task_in_pipeline
    st = tmp_path / ".gatekeeper.state.test"
    ft = "plan-refinement: docs/plans/x.md — 质询X"
    st.write_text(json.dumps({"gate_data": {"task_pipeline": [
        {"id": "t1", "full_task": ft, "status": "pending"}]}}), encoding="utf-8")
    assert task_in_pipeline(str(st), ft) is True
    assert task_in_pipeline(str(st), "裸窄任务（不在 pipeline）") is False
    assert task_in_pipeline(str(tmp_path / "不存在.state"), ft) is False


def test_monitor_guards_bare_plan_refinement():
    """arm2：显式 `--role plan-refinement` 必须过 task_pipeline 归属校验，否则 BARE_PLAN_REFINEMENT。"""
    s = _src()
    assert "BARE_PLAN_REFINEMENT" in s, (
        "缺 BARE_PLAN_REFINEMENT ⟹ 裸 `--role plan-refinement` 仍可绕过统一入口（原「逃生」洞）")
    assert "task_in_pipeline" in s, (
        "质询守卫未消费 task_pipeline 归属（须按 full_task 校验，非裸串放行）")


def test_preflight_baseline_covers_plan_refinement():
    """arm3：质询通道须并入基线 status-fresh 门（B）。

    2026-11-02 语义变更（owner 裁定「并发质询永久卡死」）：`stale` 由 fail-closed 改 **advisory**
    —— 索引落后于 HEAD 只告警放行；**只有 `unavailable`（根本没有索引）才阻断**。
    本臂随之改判据：断言信源码里**仍有**门（不是被删），且阻断面已收窄到 unavailable。
    """
    s = _src()
    assert "BASELINE_UNAVAILABLE" in s, \
        "质询通道缺基线门判定（B 的 unavailable 分支被删 ⟹ 连没索引都放行）"
    assert "advisory" in s and "图证据不完整" in s, \
        "stale 未降级为 advisory（并发提交下会再次永久卡死）"
    assert "GK_ALLOW_STALE_BASELINE" in s, "缺逃生口（依赖不可用不得锁死序列）"


def test_existing_guards_preserved():
    """arm4：既有守门路径（REVIEW_ROLE_UNSPECIFIED + B 两通道并集）不得被本刀破坏。"""
    s = _src()
    assert "REVIEW_ROLE_UNSPECIFIED" in s, "既有免猜门被破坏"
    assert 'if [ "$channel" = "crossrev" ] || [ "$channel" = "plan-refinement" ]' in s, (
        "B 块须为 crossrev ∪ plan-refinement 并集（crossrev 语义零回归）")

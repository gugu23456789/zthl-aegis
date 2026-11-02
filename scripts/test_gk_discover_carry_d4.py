"""红先臂：`discover` 重建 state 的保全清单须含跨轮基础设施键（ECC-A4223D19AA16）。

病象（2026-10-07 实测）：`cmd_discover` 重建 state 只写
`{r_phase,stage,branch,worktree,main_repo,gate_data:{},monitor_scores,history}`，靠
`gk_discover_carry.CARRY_*` 白名单回填。白名单仅 `edit_budget / ecc_findings /
worktrees_extra` ⟹ 实测 `gate_data` 从 14 键掉到 6 键：`subagent_history`(7→0)、
`task_pipeline`(6→0)、`t_star`、`satellite_index`、`jti_store`、`subagent_last`、
`_sealed_agent_score`、`edit_count` 全被抹。后果：质询 6 臂在窗口内被抹且未入卫星片 ⟹
`moa-aggregate` references=0（六臂聚合不可得）。

三臂：臂1 = 红（新键保全）；臂2 = 负臂（缺键不造空壳）；臂3 = 回归（既有键不变）。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_discover_carry as C  # noqa: E402


def _old():
    return {
        "gate_data": {
            "edit_budget": {"sessions": {"s1": {"max": 32}}},
            "ecc_findings": [{"id": "ECC-1"}],
            "t_star": {"frozen_at": "2026-10-07T00:26:32Z", "sha256": "abc"},
            "satellite_index": {"skill.x": {"history": {"kind": "history", "records": 2}}},
            "jti_store": {"jti-1": 1791360000},
            "_sealed_agent_score": {"score": 57.1},
            "edit_count": 7,
            "subagent_history": [{"subagent_id": "sub-a"}, {"subagent_id": "sub-b"}],
            "task_pipeline": [{"id": "pr-1", "status": "pending"}],
        },
        "worktrees_extra": ["/mnt/c/wt/1"],
    }


def _new():
    return {"r_phase": "ECO-SCAN", "stage": "STAGE_0", "gate_data": {},
            "monitor_scores": {}, "history": []}


def test_arm1_cross_round_keys_carried():
    """臂1（红）：跨轮基础设施键须全部回填。"""
    n = C.carry_over(_old(), _new())
    gd = n["gate_data"]
    for k in ("t_star", "satellite_index", "jti_store", "_sealed_agent_score"):
        assert gd.get(k), "gate_data.%s 未保全" % k
    assert gd.get("subagent_history"), "gate_data.subagent_history 未保全"
    assert gd.get("task_pipeline"), "gate_data.task_pipeline 未保全"
    assert gd.get("edit_count") == 7, "gate_data.edit_count 未保全"


def test_arm2_absent_keys_no_empty_shell():
    """臂2（负）：旧 state 无该键 ⟹ 不造空壳（`-1 = 未配置` 语义不被污染）。"""
    old = {"gate_data": {"ecc_findings": [{"id": "ECC-1"}]}}
    n = C.carry_over(old, _new())
    gd = n["gate_data"]
    for k in ("t_star", "satellite_index", "jti_store", "_sealed_agent_score",
              "subagent_history", "task_pipeline", "edit_count", "edit_budget"):
        assert k not in gd, "空壳 %s 被造出" % k


def test_arm3_existing_keys_regression():
    """臂3（回归）：既有三类保全零回归。"""
    n = C.carry_over(_old(), _new())
    gd = n["gate_data"]
    assert gd.get("edit_budget")
    assert gd.get("ecc_findings")
    assert n.get("worktrees_extra") == ["/mnt/c/wt/1"]

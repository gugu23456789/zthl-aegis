#!/usr/bin/env python3
"""`discover` 重建 state 时的**跨会话基础设施键**保全（finding `ECC-A135BE8837AF`）。

病象（实测 2026-10-01T03:57，2026-10-07 复发）
--------------------------------------------
`cmd_discover` 重建 state 时只写
`{r_phase, stage, branch, worktree, main_repo, gate_data:{}, monitor_scores, history}`
⟹ 并发会话的 `gate_data.edit_budget.sessions[*]`（额度盒）与顶层 `worktrees_extra`
（活动写面允许集，RC1 单写通路 = `apply-worktree`）被**一并抹掉**；hook 下次编辑时按缺省
**自动建盒 0/0** ⟹ 他会话被 Gate4 `edit_budget exhausted` 死锁（实测：并发会话
`6a3e34696caeb2204fa8bc88` 的 `max32/used58/remaining2` 被抹成 `0/0/0`，ledger 可查）。

判据：「**跨会话共享**」≠「**本轮燃烧项**」
------------------------------------------
- **保全**（跨会话 / 跨轮基础设施）：
  · dict 值 —— `gate_data.edit_budget` / `t_star` / `satellite_index` / `jti_store` /
    `_sealed_agent_score`
  · list 值 —— `gate_data.ecc_findings` / `task_pipeline` / `subagent_history` /
    `hook_block_log`（`gk_ember_replay` 回判消费的**意图记忆链**，见下）
  · int 值 —— `gate_data.edit_count`
  · 顶层 —— `worktrees_extra`
- **仍清空**（本轮燃烧项）：`rejected_edits` / `entropy_history` / `audit_*_result` …
- **只在旧 state 确有**该键且非空时回填（缺键**不造**空壳 —— 否则 `edit_budget.max` 的
  `-1 = 未配置` 语义会被写成 `{}` 造出的假盒）。
- 2026-10-02（`ECC-01E84B0E87F5`）：原把 `ecc_findings` 归「本轮数据」不保全 ⟹ 任一会话跑一次
  `discover`（重建 state 时 `gate_data={}`）即抹掉基座 state **全部 live finding**（实测
  2026-10-02T14:01Z 30 条记录被删、`.finding-journal.jsonl` 幸存）⟹ 现纳入保全。
- 2026-10-07（`ECC-A4223D19AA16` 实测）：原把 `subagent_history` / `task_pipeline` 归
  「本轮数据」不保全 ⟹ 6 臂质询派发后任一会话跑 `discover` 即把**窗口内**臂记录抹掉
  （实测 `gate_data` 14→6 键：`subagent_history` 7→0、`task_pipeline` 6→0，且 `t_star` /
  `satellite_index` / `jti_store` / `subagent_last` / `_sealed_agent_score` / `edit_count`
  一并丢失），且**未入卫星片**（`_satellite_history_union` 读不到）⟹ `moa-aggregate`
  references=0，六臂聚合不可得。**窗口内未入片即丢 = 数据丢失**，非「本轮燃烧项」所能豁免
  ⟹ 现纳入保全（卫星片语义不变；保全只保证 `discover` 不吞在窗条目，出窗仍由归档负责）。
- 2026-10-07（**连带 ember**，同批）：`hook_block_log` 原同列「本轮燃烧项」⟹ `discover` 抹掉后，
  `gk_ember_replay._hook_block_slice_anomalies` 的「`prev_entry` 有切片 / `gate_data_full` 空」
  判据**必然命中** `gate_data_full 含 hook_block_log 但 prev_entry 无归档切片` 对偶分支
  （`归档接线缺失`）⟹ 每次相位回放报**假异常**（意图记忆链被误判为断裂）。
  ⟹ 纳入保全：`hook_block_log` 是**跨相位**回判基准，非本轮燃烧项。
- 2026-10-07（`ECC-4815C3350DB5` 质询 6 臂**跨臂共识**）：`subagent_last` 已被上文 2026-10-07
  事故清单**点名**（"一并丢失"），却**未**进任何 CARRY 元组 ⟹ **判据零覆盖的第三态**：既未
  保全、也未显式归入「仍清空」参数集 ⟹ 每次 `discover` 仍静默抹掉（生产者
  `gatekeeper-cli.sh` 的 `gd['subagent_last']=entry` 仍在写）⟹ 纳入保全（dict 值 → `CARRY_GATE_KEYS`）。

实现纪律：本模块只提供**纯函数** `carry_over(old, new)`；落盘由调用方（bash `_state_write`）
经 `gk_json_utils` **单一出纳**完成 —— 本模块**不**自己写 state（禁第二写者）。
"""
from __future__ import annotations

__all__ = ["CARRY_GATE_KEYS", "CARRY_GATE_LIST_KEYS", "CARRY_GATE_SCALAR_KEYS",
           "CARRY_TOP_KEYS", "carry_over"]

# 保全清单（单一登记点；新增键只改这里 + 本模块 docstring 判据）
CARRY_GATE_KEYS = ("edit_budget", "t_star", "satellite_index", "jti_store",
                   "_sealed_agent_score", "subagent_last")   # gate_data 内的跨会话/跨轮键（dict 值）
CARRY_GATE_LIST_KEYS = ("ecc_findings", "task_pipeline", "subagent_history",
                        "hook_block_log")           # 跨轮台账（list 值；hook_block_log=ember 意图记忆链）
CARRY_GATE_SCALAR_KEYS = ("edit_count",)           # 跨轮计数器（int 值）
CARRY_TOP_KEYS = ("worktrees_extra",)              # 顶层跨会话键（写面允许集）


def _ensure_gd(new: dict) -> dict:
    """取 `new['gate_data']`（非 dict 时改为新 dict 并挂回）。"""
    new_gd = new.get("gate_data")
    if not isinstance(new_gd, dict):
        new_gd = {}
        new["gate_data"] = new_gd
    return new_gd


def carry_over(old: dict, new: dict) -> dict:
    """把 `old` 里的跨会话/跨轮基础设施键并进 `new`（**就地**改 `new` 并返回；纯函数，无 I/O）。

    - `old`/`new` 非 dict → 原样返回 `new`（fail-soft：保全失败绝不阻断 discover 主流程）
    - 值须为**非空**容器（或非零 int）才回填（空/缺失 ⟹ 跳过，不造空壳）

    ⚠ **闸外边界（§9-7 方案 B，2026-10-07）**：本函数对 `ecc_findings`（∈ `CARRY_GATE_LIST_KEYS`）
    是**整份承接**（`new_gd[key] = val`），**不经** `gk_finding._guard_precheck`（处置前强制回环闸）。
    即 `discover` 迁移态对 finding 标题锚**不做**预检 —— 这是**显式声明的已知边界**（迁移面本质
    绕开 finding 处置语义），非疏漏。
    """
    if not isinstance(old, dict) or not isinstance(new, dict):
        return new
    old_gd = old.get("gate_data")
    if isinstance(old_gd, dict):
        for key in CARRY_GATE_KEYS:
            val = old_gd.get(key)
            if not isinstance(val, dict) or not val:
                continue
            _ensure_gd(new)[key] = val
        for key in CARRY_GATE_LIST_KEYS:
            val = old_gd.get(key)
            if not isinstance(val, list) or not val:
                continue
            _ensure_gd(new)[key] = val
        for key in CARRY_GATE_SCALAR_KEYS:
            val = old_gd.get(key)
            if isinstance(val, bool) or not isinstance(val, int) or not val:
                continue
            _ensure_gd(new)[key] = val
    for key in CARRY_TOP_KEYS:
        val = old.get(key)
        if isinstance(val, list) and val:
            new[key] = list(val)
    return new

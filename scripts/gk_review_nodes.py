#!/usr/bin/env python3
"""gk_review_nodes.py — 审查节点判据（**单源**）。

消费者（两处，2026-09-21 由双源收敛为单源）：
- `scripts/pre_tool_hook.py` Gate 1b（`_review_node_ok` 薄包装 → 本模块）
- `gatekeeper-cli.sh` `_review_channel_preflight` C（crossrev 节点绑定）

判据**政策**（不变，2026-09-04 定案）：交叉审查的 subagent/LLM 车道必须在**审查节点**运行 ——
常驻（ECO）序列 → `ECO-RESEARCH|ECO-VERIFY`（2026-10-28 A4 合并前为 `ECO-READ|ECO-AUDIT`，
旧名保留在集合内以兼容存量 state）；其余 → `STAGE_3|AUDIT-CROSSR`。

判据**键**（2026-09-21 修正）：原按 `gate_data.project_type` 分支。该键是**活动计划的 META
声明**（单源 = `gk_route_center._META_FIELDS`），随活动计划切换而翻转 —— 0913 家族 META
= `standing`，而本会话 hook 计划 META = `analysis`。后果：**同一条 `ECO-*` 常驻序列在
`analysis` 型活动计划下，审查节点恒不命中**；且因 `project_type` 与序列无关，**即便把序列
推进到 `ECO-AUDIT` 也仍被拦** ⟹ 正规路径被系统性堵死，逼出两条旁路：
`audit --crossfull --isolate` 把副本 state 的 `stage` 改写成 `AUDIT-CROSSR`（**自证式**满足），
或 `GK_DEGRADE_REVIEW=1` 降级。

现键改为**序列命名空间**：`stage` 命中 `ECO-` 前缀即常驻序列（`stage` 为空时以 `r_phase` 兜底）。
另保留 `project_type == "standing"` 的旧分支，使 standing 型态的既有拦/放**逐字不回退**。
"""

REVIEW_NODE_STANDARD = frozenset({"STAGE_3", "AUDIT-CROSSR"})   # standard / audit 序列
# A4（2026-10-28）：4 站规范名 + 旧名（存量 state 的 stage 仍可能是旧名）
REVIEW_NODE_STANDING = frozenset({"ECO-RESEARCH", "ECO-VERIFY", "ECO-READ", "ECO-AUDIT"})

_ECO_PREFIX = "ECO-"


def review_namespace(stage, r_phase) -> str:
    """序列命名空间判据：`"ECO"` = 常驻序列；`"standard"` = 其余。

    `stage` 为空时才以 `r_phase` 兜底 —— 避免"`stage` 已是 `STAGE_3` 而残留旧 `r_phase=ECO-*`"
    这类混态被 ECO 分支误捕（回归面：standard 态的既有行为逐字不变）。
    """
    s = str(stage or "")
    r = str(r_phase or "")
    if s.startswith(_ECO_PREFIX) or (not s and r.startswith(_ECO_PREFIX)):
        return "ECO"
    return "standard"


def review_node_ok(stage, r_phase="", project_type="") -> dict:
    """判据本体。返回 `{"ok": bool, "namespace": str, "expected": str}`。

    `expected` 供错误消息构造（消费者不再各自维护白名单常量）。
    """
    ns_eco = review_namespace(stage, r_phase) == "ECO"
    allowed = REVIEW_NODE_STANDING if (ns_eco or project_type == "standing") else REVIEW_NODE_STANDARD
    return {
        "ok": str(stage or "") in allowed,
        "namespace": "ECO" if ns_eco else "standard",
        "expected": "|".join(sorted(allowed)),
    }

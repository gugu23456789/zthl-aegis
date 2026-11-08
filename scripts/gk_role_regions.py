#!/usr/bin/env python3
"""gk_role_regions.py — 子 agent 角色→允许区域表（**轻量单源**，零第三方依赖）。

为什么单独成文件（2026-11-08，**消减暗依赖**）：
  `subagent_runner.py` 顶层 `import openai / agents` 属**重依赖**。表原先放在该文件里，
  于是 `gatekeeper-cli.sh` 为了打印角色白名单（L4524 的一行 `import subagent_runner`）
  也把整棵 openai 依赖树拖进进程 ⟹ **不跑 LLM 的命令同样硬依赖 openai 装好**，
  缺依赖时报的是 `ROLE_TABLE_UNREADABLE`（看起来像表坏了，其实是环境缺包）。
  同先例：`SUBA_TIERS` / `DEFAULT_TIER` 于 2026-10-08 迁出为 `gk_suba_tiers.py`。

纪律：
  · 本文件**禁止** import 任何第三方包（stdlib 以外）；
  · 名字 `ROLE_ALLOWED_REGIONS` 不变 ⟹ `subagent_runner` 内既有引用零回归
    （`subagent_runner.py` 以 `from gk_role_regions import ROLE_ALLOWED_REGIONS` 单点转发）。
"""

# 子 agent 角色→允许区域 — 对应 gatekeeper-cli.sh case...esac 中实际存在的角色
# 4大类: default(standard 序列补位: W9 LLM 兜底 + STAGE_2 CI 维护)/计划质询(plan-refinement)/
#        红队(scanner/exploiter/auditor/reporter)
# 审计(AUDIT-STATE/MEMORY/CROSSR/REPORT)是 bash cmd_audit 管道，不走 subagent 引擎
ROLE_ALLOWED_REGIONS: dict[str, list[str]] = {
    # 类型1: default — standard 序列补位兜底（只读分析：CI 失败/门禁 BLOCK 的 LLM 兜底）
    "default":  ["evidence"],
    # 类型2: 计划质询 — F1-F7 约束检查
    # 2026-08-27 扩展: +gate 只读 CLI 实现（验证计划约束与 _CMD_REG/side_effects 实际一致，
    # T1 窄任务暴露 read_repo 读 gatekeeper-cli.sh 被拒 2 次 access violations）
    "plan-refinement": ["evidence", "transition", "gate"],
    # 类型3: 红队序列 — 4 角色 (scanner/exploiter/auditor/reporter), gatekeeper-cli.sh L1052-1067
    # F-REV-11 C1 (2026-09-10): 审计/红队承担 gate 源码审查职责（gate = 红队重点打击对象：
    # advance 绕过/--force/guard-edit 全在 gate bash），但原三角色无 gate 区 → read_repo 读
    # gatekeeper-cli.sh 被 scope denied（L2/后R/红队 access_violations 实证）→ 结构性覆盖缺口。
    # +gate 只读（read / read_repo 工具区均含 gate；F-REV-25 合并后两工具区域一致）→
    # 不扩大泄漏面：无 gate 角色（default/reporter）由角色层挡，与工具无关；
    # reporter 仅聚合证据，不读 gate 源码，保持 evidence-only。
    "scanner":  ["evidence", "transition", "gate"],
    "exploiter":["evidence", "transition", "appeal", "gate"],
    "auditor":  ["evidence", "constants", "gate"],
    "reporter": ["evidence"],
    # 类型5: venue-prior-art（论文对照，只读 evidence；工具面见 ROLE_TOOLS）
    "venue-prior-art": ["evidence"],
    # 类型6: research-408（408 分析帧研究报告；只读 evidence）。工具面见 ROLE_TOOLS，
    #   出网须 `--web 1` 显式授权（2026-11-08）。
    "research-408": ["evidence"],
    # 类型4: coder（fix 档位）— 2026-09-23（ECC-591BA1B918B4 配套）：
    # 「能落刀的 agent 必须能读它要改的代码」是硬约束 —— fix 档位落点必然在 `gate` 段
    # （gatekeeper-cli.sh 本体）与 `transition` 段（幂等/状态机测试），而原 `--code-fix`
    # 派发未指定角色 ⟹ 落 `default`（仅 evidence）⟹ 实测 agent 的 read 全被
    # `scope denied: gate/transition not in effective_regions={'evidence'}` 拒，
    # 拿不到待改函数逐字原文、无法构造 old_str ⟹ 零落刀。单列 coder 承接。
    "coder":    ["evidence", "transition", "gate"],
}

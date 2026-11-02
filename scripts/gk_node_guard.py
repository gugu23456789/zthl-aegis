#!/usr/bin/env python3
"""
Gatekeeper Node Guard — 序列节点安全网承载（2026-08-27）
================================================================
序列节点安全网实装（此前仅 references/sequence-node-safety-net-template.md 设计文档，
无承载 py 脚本 / 无启动门禁 / 无 hook）。本模块将模板落成可执行代码。

对齐：
  - 模板五元组 SN=⟨G,B,C,T,D⟩ + 数学公理 A1-A8（references/sequence-node-safety-net-template.md §1）
  - Phase 3.5d 结构化提示词 route_template（batch8 plan L2414-2440）→ 流程总运行线路
  - H-SLSN 带状态循环（scripts/pre_tool_hook.py _hslsn_*）→ node_guard/node_verdict 同构

核心能力：
  1. NODE_REGISTRY  — 序列节点统一注册表（节点→路线→门禁→checklist→安全网→下一站）
                     修复「序列节点注册缺失」：advance 未知节点全放行 → 无注册表可查
  2. node_guard()   — G 谓词：前置产物齐备性检查（代码库地图/基线/源文档/窄任务清单）
  3. route_map()    — 流程总运行线路（地铁总运行路线）：全线路图 + 当前站定位 + 下一站预报
  4. station_announcement() — 单节点车站播报（当前 + 下一站 + 进入门禁 + checklist）
                     注入 advance hint（Phase 3.5d route_template 的实装形态）

用法（CLI）:
  python3 gk_node_guard.py route-map --route standing
  python3 gk_node_guard.py announce --node ECO-RESEARCH
  python3 gk_node_guard.py guard --node ECO-EDIT --state-file <state> [--ctx '{...}']
  python3 gk_node_guard.py register --node FOO   # 注册校验：未知节点 exit 2
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# ─── 节点注册表（NODE_REGISTRY）───────────────────────────────────────────────
# 统一节点注册：id → {route, next, prev, gate, checklist, safety, preconditions}
# checklist 字段合并 Phase 3.5d route_template（batch8 plan L2414）的 phase_start_checklist。
# 来源：gk_advance.py _HINT_PHASES/_CHECKLISTS/_GATES_JSON（语义对齐，非复制——单一事实源 = 本表）。

# 2026-10-28（A4 裁定）：standing 5 站合并为 4 站，旧站名作为**别名**保留。
# 单源在此处（gk_advance 反向 import），避免两套映射漂移。
ECO_ALIASES = {
    "ECO-SCAN": "ECO-RESEARCH",
    "ECO-READ": "ECO-RESEARCH",
    "ECO-AUDIT": "ECO-VERIFY",
}


def canon_eco(node_id: str) -> str:
    """旧 ECO 站名 → 4 站规范名（幂等；非 ECO 站原样返回）。"""
    return ECO_ALIASES.get(node_id, node_id)


_ROUTES = {
    "standing": {
        "name": "MPR Standing 常驻序列",
        "nodes": ["ECO-RESEARCH", "ECO-EDIT", "ECO-VERIFY", "ECO-DOC"],
        "loop": True,
        # 2026-10-28（A4）：5 站合并为 4 站（SCAN+READ→RESEARCH；AUDIT→VERIFY）。
        # 旧站名仍可 advance（gk_advance.canon_eco 归一），但不进本路线。
    },
    "standard": {
        "name": "2.0.2 R 序列",
        "nodes": ["STAGE_0", "STAGE_1", "STAGE_2", "STAGE_3", "STAGE_4", "STAGE_5", "DONE"],
        "loop": False,
    },
    "red": {
        "name": "红队序列",
        "nodes": ["RED-SCOPE", "RED-SURFACE", "RED-CONSTRAINTS", "RED-EXPLOIT",
                  "RED-POSTEX", "RED-REPORT", "RED-HINT", "RED-HOOK", "RED-PY",
                  "RED-POISON", "RED-REGISTRY", "RED-GHOST", "RED-COVERAGE", "RED-DIFF",
                  "RED-INTEGRITY", "RED-AIG"],
        "loop": False,
        # WAD 标注（2026-09-07 批③ ⑤ 复核，追认 2026-09-05 R4）：red = 引擎分发（_red_attacks
        # dispatcher 逐阶段 + audit --red），非 advance 逐站 walk——站级门禁语义在引擎/registry 面
        # （check_red S10 语义回归 = dispatcher 分发 + registry 覆盖），node_guard 三面元数据不描述
        # 逐站 walk → sequence_node_safety 不将本路线计 thin（防双事实源机械补 _GATES 串）。
        # A9（2026-10-28）：新增 RED-AIG（AI-Infra-Guard，只在 KVM 沙箱内跑不可信样本）。
        "walk": "dispatcher",
    },
    "audit": {
        # D7-B（2026-10-27，owner 裁 J1+S1）：整建制归审计署 ⟹ 此处只登记**派发归属**；
        #   **不搬迁 state、不改节点集/分发方式**（被审证据仍留在被审 state）。
        "name": "审计执行序列（审计署下属）",
        "owner": "skill.2026-10-04-audit-bureau-plan",
        "nodes": ["AUDIT-STATE", "AUDIT-MEMORY", "AUDIT-CROSSR", "AUDIT-REPORT"],
        "loop": False,
        # WAD 标注（同 red 复核）：audit = cmd_audit 家族分发 + audit --all 聚合，非 advance 逐站 walk。
        "walk": "dispatcher",
    },
    # 2026-08-29 实装（序列节点安全网模板 references/sequence-node-safety-net-template.md）：
    # 循环 A = 插件自维护（standing ECO 双文档同步，对象=插件本体）；
    # 循环 B = 上岗任务执行（standard cmd_migrate 串联）。独立路线避免与 standing ECO-* 同名冲突。
    "plugin-a": {
        "name": "循环 A 插件自维护（ECO 双文档同步）",
        "nodes": ["ECO-SCAN-PLUGIN", "ECO-EDIT-PLUGIN", "ECO-DOC-PLUGIN"],
        "loop": True,
    },
    "plugin-b": {
        "name": "循环 B 上岗任务执行（cmd_migrate）",
        "nodes": ["MIGRATE-ANALYZE", "MIGRATE-VERIFY", "MIGRATE-AUDIT"],
        "loop": False,
    },
    "plugin-c": {
        "name": "循环 C：SWE-RB 上岗任务执行（swe-rb）",
        "nodes": ["SRB-ANALYZE", "SRB-VERIFY", "SRB-AUDIT"],
        "loop": False,
    },
    # 2026-10-01（H3 开工前置；用户裁定「选 A」）：`zthl` 路线登记 ——
    # `zthl-harness-adapter` 计划（META `project_type: zthl-adapter` / `phases: ZH1..ZH4`）既非
    # standing/standard，也未在 NODE_REGISTRY ⟹ `advance ZH1` 被《序列节点安全网》硬阻断
    # （`UNKNOWN_NODE: 'ZH1' 未注册`，gk_advance.py::_registered_node）。本路线补登记；
    # checklist 逐条对齐计划 §3 ZH 表任务名（唯一源，勿在此复述计划正文）。
    "zthl": {
        "name": "ZTHL Harness 适配序列",
        "nodes": ["ZH1", "ZH2", "ZH3", "ZH4"],
        "loop": False,
    },
    # 2026-10-12（W2A-P2 相位实验；owner 裁定「消除 D 三无」）：`2026-10-12-w2a-p2-phase-experiment-plan`
    # （META `project_type: plan` / `phases: W2A-P2`）既非 standing/standard，也未在 NODE_REGISTRY ⟹
    # `discover --plan` 报 `unknown R-phase — plan declares phases: W2A-P2`、`advance W2A-P2` 被
    # 《序列节点安全网》硬阻断（`UNKNOWN_NODE`，`ECC-82C90896751F`）。本路线补登记；**单站序列**
    # （起点亦终点）——checklist 逐条对齐计划 §9 机检判据（唯一源，勿在此复述计划正文）。
    "w2a-p2": {
        "name": "W2A P2 相位实验序列",
        "nodes": ["W2A-P2"],
        "loop": False,
    },
}

_CHECKLISTS = {
    "ECO-RESEARCH": ["discover (同步状态)", "state (检查当前阶段)", "self-check (环境完整性检查)",
                     "research-prelude: 问题分解 → 外部检索（按需）→ 证据清单（可跳过：GK_SKIP_RESEARCH_PRELUDE=1）",
                     "research-408（默认 auto；GK_RESEARCH_FRAME=408|generic 覆盖；advisory 不阻塞，见 references/research-408.md）",
                     "monitor --subagent 分析参考项目", "gitnexus context (代码结构360度视图)", "read 参考项目关键文件"],
    "ECO-EDIT": ["guard-edit <file> (编辑权限检查)", "pre-tool-check (门禁验证)", "pytest (测试通过后再 commit)"],
    "ECO-VERIFY": ["self-check (env/gitnexus/key/tests)", "context --update (子agent上下文更新)", "reflect (反思当前进展)", "audit --crossfull (统一启动器: 全量交叉审查一条命令)"],
    "ECO-DOC": ["docgen (文档同步)", "gitnexus analyze --embeddings (更新基线)", "search --repo 确认无遗漏"],
    # 2026-10-28（A4 收尾）：旧站名清单已删除——`_node_defaults` 先 canon_eco 归一，
    #   旧键永不可达（保留=第二份站定义）。别名语义单源 = ECO_ALIASES。
    "STAGE_0": ["worktree 创建/恢复", "plan META 读取", "state 初始化 (discover)"],
    "STAGE_1": ["feature worktree 编码", "pytest 全量通过", "push 前 L1-L2 轻量审查 (git 完整性 + code-to-spec；完整 L1-L10 在 STAGE_3，2026-09-01 修正原 L1-L9)"],
    "STAGE_2": ["CI 绿", "ci-diagnose (CI 红时)", "STAGE_1→2 stash/detect-changes 门禁"],
    "STAGE_3": ["L1-L10 交叉审查（≥2 轮 + 轮间红队挖洞，2026-09-05 纪律节点化，防一轮了事）", "requesting-code-review", "红队引擎 (L10)", "audit --crossfull (统一启动器: 近 N commit runbook 0-13 全量串行)"],
    "STAGE_4": ["PR 创建 (git-workflow)", "merge 验证", "remote URL 白名单 (F8.1)"],
    "STAGE_5": ["分支退休", "post-R 回顾", "gitnexus analyze 终态"],
    "DONE": ["终站：序列结束（无下一站；R 收尾产物已在 STAGE_5 完成）"],
    "RED-SCOPE": ["self-check (环境状态)", "state (当前快照)", "discover (项目结构)"],
    "RED-SURFACE": ["search (攻击面搜索)", "gitnexus context (入口点分析)", "gitnexus impact (爆破半径)"],
    "RED-CONSTRAINTS": ["pre-tool-check (门禁枚举)", "guard-edit (保护区域枚举)", "audit --state (状态审计)"],
    "RED-EXPLOIT": ["尝试 advance bypass", "尝试 --force abuse", "audit tamper (篡改检测)"],
    "RED-POSTEX": ["self-check (防御验证)", "reflect (攻击链反思)", "audit --state (状态一致性)"],
    "RED-REPORT": ["audit --verify (完整性验证)", "state (最终快照)"],
    "RED-HINT": ["检查 advance hint JSON 完整性", "验证 checklist/tool_policy/post_check/gates 均注入"],
    "RED-HOOK": ["验证 pre_tool_hook.py Gate0-4 + R0.1-R0.4 存在", "验证 hook matcher 覆盖 CreateFile|DeleteFile", "验证 red_hook RED-HOOK-00..16 无 finding"],
    "RED-PY": ["验证 gk_self_check.py 全部 check 注册", "验证每个 check 有 try/except 隔离", "验证 red_py RED-PY-* 无 finding"],
    # 2026-08-28 红队引擎扩展 4 阶段（audit --red poison/registry/ghost/coverage，
    # 域1/2/4、域5、域8、审计覆盖）——作为红队序列站点注册，checklist 引导确定性扫描
    "RED-POISON": ["audit --red poison (投毒攻击面: 窄任务 8 类注入 + Unicode + 重复凸显)"],
    "RED-REGISTRY": ["audit --red registry (元数据路由: scopes 篡改/孤儿/别名/_checksum/audit_log)"],
    "RED-GHOST": ["audit --red ghost (高威胁: 预算域越界/超界/递归/无签名)"],
    "RED-COVERAGE": ["audit --red coverage (审计覆盖缺口: 新增安全措施入审计/红队序列)"],
    # 2026-08-31 红队引擎扩展第 14 阶段（RED-DIFF 差分对拍，F3 最小闭环）——
    # 编排宿主 = red_attacks 引擎；契约模型由 swe-rb analyze 产物或 RED_DIFF_CONTRACT 提供
    "RED-DIFF": ["audit --red diff (差分对拍: RED_DIFF_CONTRACT 契约模型 → 差分攻击向量实测)"],
    # 2026-09-04 红队引擎扩展第 15 阶段（RED-INTEGRITY 产品代码 fail-open/fail-closed 模式）——
    # 编排宿主 = red_attacks 引擎 red_integrity()；RED_INTEGRITY_TARGET 指向产品代码根。
    # 背景: R7_1d 红队轮 V9/V10/V11 载荷 + red subagent 缺口评估——既有阶段仅覆盖门卫自身
    # 逃逸面，产品完整性 fail-open 复发不可测（RED-COVERAGE 只跟踪覆盖率不判模式语义）。
    "RED-INTEGRITY": ["audit --red integrity (RED_INTEGRITY_TARGET 产品代码完整性模式: P1 catch-all→null 降级 / P2 能力缺失降级 / P3 失败未 fail-closed / P4 探针-执行分裂 TOCTOU / P5 哨兵特判跳过)"],
    # A9（2026-10-28）：AI-Infra-Guard 车道 —— **不可信样本只在 KVM 沙箱内**处理
    "RED-AIG": ["确认 gk_kvm_launcher.py probe 通过（/dev/kvm + qemu 可用）",
                "确认 GK_KVM_IMAGE 已配置（无镜像 ⟹ 拒绝执行，禁退回宿主）",
                "audit --red aig (AIG_BIN + RED_AIG_TARGET；启动/超时/网络隔离三件套)"],
    "AUDIT-STATE": ["self-check (环境状态)", "state (当前快照)", "reflect (反射审计结果)"],
    "AUDIT-MEMORY": ["self-check (环境状态)", "reflect (重放分析)", "state (历史记录)"],
    "AUDIT-CROSSR": ["self-check (环境状态)", "state (跨R基线)", "reflect (趋势分析)", "audit --crossfull (统一启动器: 近 N commit 全量串行)"],
    "AUDIT-REPORT": ["self-check (环境状态)", "state (最终快照)", "docgen (报告生成)"],
    # 2026-08-29 插件生态节点（bashpy A/B 环；五元组实例化见 _PLUGIN_PROFILES）
    "ECO-SCAN-PLUGIN": ["manifest 登记存在 (gk_plugin_manifest.get_manifest 非空且未 disabled)",
                        "加载安全网 load_status ∈ {release, release_unverified, dev}",
                        "分类学计数基线 (audit --bomb 计数 vs bashpy-problem-taxonomy.md §2 漂移检测)",
                        "插件权威源 zthl-bashpy-migrate/docs/migration-issues.md 可读"],
    "ECO-EDIT-PLUGIN": ["双文档收敛方案存在 (插件 + 技能各一份)",
                        "方案已过 ECO-RESEARCH 审查 (gate_data.eco_plugin.edit_plan)"],
    "ECO-DOC-PLUGIN": ["双文档同步完成 (插件+技能不同构 → fail-closed 阻断)",
                       "分类学 §2 计数更新 (gate_data.eco_plugin.doc_synced)"],
    "MIGRATE-ANALYZE": ["统一入口 (hook R0.4 _plugin_bare_call 拦裸调用)",
                        "cap 白名单 (check_capability(pid, analyze))",
                        "加载安全网三连 (cap → validate → load_status ∈ {release, release_unverified, dev})"],
    "MIGRATE-VERIFY": ["契约改进白名单就绪 (Bash 语义等价检测，防 Blindness)",
                       "analyze 产物存在 (gate_data.migrate.last_analyze)"],
    "MIGRATE-AUDIT": ["verify 通过 (gate_data.migrate.verify_result)",
                      "bomb 扫描目标就绪 (gate_data.migrate.audit_findings)"],
    # 2026-08-31 插件生态节点（swe-rb 循环 C；zthl-swe-rb 骨架登记）
    "SRB-ANALYZE": ["契约模型就绪 (swe-rb analyze --out contract.json，tests/ 隔离确认)",
                    "task_type 适配器命中 (language_rewrite/build_migration/platform_port/framework_migration)"],
    "SRB-VERIFY": ["契约守卫通过 (swe-rb verify --contract-only)",
                   "提交自一致性（不触碰评分 oracle）"],
    "SRB-AUDIT": ["verify 通过 (gate_data.srb.verify_result)",
                  "redteam 扫描 + 差分对拍候选 (differential_probe_plan)"],
    # w2a-p2 路线（2026-10-12；条目对齐 D 计划 §9「开跑前须全绿」机检判据）
    "W2A-P2": ["§2 五载体可导入且纯函数（含 gk_phase_probe）",
               "§4 参数表无空格（模型 / S / N_LENGTHS / Δ / τ / M 全定值）",
               "N_LENGTHS ≥ 2S（覆盖所选 S）",
               "§5 四红线各有实施落点且有断言",
               "每组含 Δ=0 同相控制臂（sweep 内）"],
    # zthl 路线（2026-10-01；条目对齐 zthl-adapter 计划 §3 的 ZH 任务名）
    "ZH1": ["H1a failover 链增强落刀 + 回归绿", "H1b 技能仓仅增量（不动既有门禁语义）",
            "H2 ACP AIC/ACS 协议验证（2026-09-25 完成）",
            "H3 zthl/eventbus.py 创建 + 单元测试通过 + 消费方级验证（丢事件后状态不漂移）",
            "H4 gk_self_check 10 项 + audit --all + RED 攻击管线独立运行"],
    "ZH2": ["H6 Gate 0-8 各闸在纯 ZTHL 环境运行通过", "H7 FAILOVER_CHAIN 保留 + MoA Provider Router",
            "H8 CX1-CX3 压缩自研", "H9 EventBus 上 AIP 消息路由（ZH2 验证门禁）",
            "H10 AMP 日志雏形写入 amp/*.log", "H11 L1-L10 review + ECC 审计链"],
    "ZH3": ["H13 BrowserSkill 消费端集成（bsk CLI）", "H14a acps_sdk 四模块集成",
            "H14b 4 类 subagent AIC 身份 + ACS 能力描述", "H14c ATR 轻量注册（文件锁，零服务依赖）",
            "H14d AIP Direct RPC（EventBus 上消息路由）", "H14e ADP 轻量发现（JSON + 关键词）",
            "H14f AMP 六类日志完整输出"],
    "ZH4": ["H17 E2E 10 项场景全绿", "H18 CLI hook 适配器（zthl wrap）",
            "H19 架构/安装/配置/ACP 文档", "H20 Apache 2.0 / MIT 捐赠准备"],
}

# 进入节点的门禁（对齐 gk_advance.py _GATES_JSON + 状态机门禁）
_GATES = {
    # 2026-10-28（A4 裁定）：4 站规范名
    "ECO-RESEARCH": "cycle start（ECO-DOC 回绕）；扫描 + 深读同一次研究动作",
    "ECO-EDIT": "ECO-RESEARCH → ECO-EDIT 必须有 plan-refinement checkpoint",
    "ECO-VERIFY": "ECO-EDIT → ECO-VERIFY 必须先 adjudicate（F1-F7 密封）",
    "ECO-DOC": "ECO-VERIFY → ECO-DOC 必须先 audit --all",
    # 2026-10-28（A4 收尾）：旧站名门禁文本已删除（`_GATES` 只按规范名取值）。
    "STAGE_0": "R 序列起点（discover 初始化/worktree 恢复；无前置 stage，2026-09-05 补登记）",
    "STAGE_1": "STAGE_0→1 worktree 注册 + r_phase 匹配",
    "STAGE_2": "STAGE_1→2 无未提交/stash/CI 触发 + detect-changes 范围",
    "STAGE_3": "STAGE_2→3 CI 绿 + 非空 diff",
    "STAGE_4": "STAGE_3→4 交叉审查完成 + PR 合规",
    "STAGE_5": "STAGE_4→5 PR 合并验证",
    "DONE": "STAGE_5 完成（PR 合并验证通过 → 终站收尾，无下一站；2026-09-05 补登记）",
    "RED-EXPLOIT": "RED-CONSTRAINTS 约束枚举完整",
    "RED-POSTEX": "RED-EXPLOIT 全部攻击向量已执行",
    "RED-REPORT": "RED-POSTEX reflect 完成",
    "RED-DIFF": "RED-COVERAGE 完成（差分契约模型就绪：RED_DIFF_CONTRACT 或 state.gate_data.srb.contract_json）",
    "RED-INTEGRITY": "RED-DIFF 完成（产品代码完整性模式扫描：RED_INTEGRITY_TARGET 指向目标分支代码根）",
    "RED-AIG": "RED-INTEGRITY 完成（A9：AIG_BIN + GK_KVM_IMAGE 就绪，样本只在 KVM 沙箱内跑）",
    "ECO-EDIT-PLUGIN": "ECO-SCAN-PLUGIN 完成（前置产物齐备，循环 A 顺序门禁）",
    "ECO-DOC-PLUGIN": "ECO-EDIT-PLUGIN 双文档收敛方案已定",
    "MIGRATE-VERIFY": "MIGRATE-ANALYZE 完成（统一入口+cap+load_status 三连已过）",
    "MIGRATE-AUDIT": "MIGRATE-VERIFY 通过（契约白名单无 Blindness）",
    "SRB-VERIFY": "SRB-ANALYZE 完成（契约模型就绪）",
    "SRB-AUDIT": "SRB-VERIFY 通过（契约守卫无 Blocking）",
    # w2a-p2 路线（2026-10-12）
    "W2A-P2": "w2a-p2 序列起点/终点（单站；计划 META phases=W2A-P2；无前置 stage）",
    # zthl 路线（2026-10-01）
    "ZH1": "zthl 序列起点（计划 META project_type=zthl-adapter；无前置 stage）",
    "ZH2": "ZH1 完成（Core 独立可运行 + EventBus 单测通过）",
    "ZH3": "ZH2 完成（三层治理链独立运行 + ACP 数据输出）",
    "ZH4": "ZH3 完成（记忆 / BrowserSkill / ACP 增强落地）",
}

# 节点绑定安全网（六类安全网映射，references/security-measures.md §4）
_SAFETY = {
    "ECO-EDIT": ["序列节点引导", "门禁(adjudicate)", "运行时"],
    "ECO-RESEARCH": ["序列节点引导", "运行时"],
    "ECO-VERIFY": ["文档审查引擎", "运行时"],
    "ECO-DOC": ["文档审查引擎"],
    # 2026-10-28（A4 收尾）：旧站名 safety 键已删除（`_SAFETY` 只按规范名取值）。
    "STAGE_2": ["wasm+ci", "运行时"],
    "STAGE_3": ["门禁", "文档审查引擎"],
    # 2026-09-05 standard 全站 safety 补齐全（原仅 STAGE_2/3 实配，其余落默认）
    "STAGE_0": ["运行时"],
    "STAGE_1": ["门禁", "运行时"],
    "STAGE_4": ["门禁", "运行时"],
    "STAGE_5": ["门禁", "运行时"],
    "DONE": ["运行时"],
    "RED-EXPLOIT": ["门禁(--force 红队许可)", "运行时"],
    "ECO-SCAN-PLUGIN": ["序列节点引导", "加载安全网", "manifest 治理层"],
    "ECO-EDIT-PLUGIN": ["序列节点引导", "运行时"],
    "ECO-DOC-PLUGIN": ["文档审查引擎", "运行时"],
    "MIGRATE-ANALYZE": ["加载安全网", "manifest 治理层", "运行时"],
    "MIGRATE-VERIFY": ["加载安全网", "运行时"],
    "MIGRATE-AUDIT": ["加载安全网", "运行时"],
    "SRB-ANALYZE": ["加载安全网", "manifest 治理层", "运行时"],
    "SRB-VERIFY": ["加载安全网", "运行时"],
    "SRB-AUDIT": ["加载安全网", "运行时"],
    # w2a-p2 路线（2026-10-12）：单站 = 起点，引导 + 门禁 + 运行时三项齐
    "W2A-P2": ["序列节点引导", "门禁", "运行时"],
    # zthl 路线（2026-10-01）：ZH1 = 序列起点（引导 + 门禁 + 运行时）；ZH2-ZH4 = 门禁 + 运行时
    "ZH1": ["序列节点引导", "门禁", "运行时"],
    "ZH2": ["门禁", "运行时"],
    "ZH3": ["门禁", "运行时"],
    "ZH4": ["门禁", "运行时"],
}

# 前置产物检查项（模板 §2：G 的检查项）——node_guard 用 ctx 校验
_PRECONDITIONS = {
    "codebase_map": {"key": "context_file", "label": "代码库地图 (subagent-context.json 签名有效)"},
    "baseline": {"key": "baseline_status", "label": "基线 (gitnexus 索引 baseline_status 四态: current|reusable|stale|unavailable)"},
    "source_docs": {"key": "source_docs", "label": "源文档 (计划引用文档可读)"},
    "narrow_tasks": {"key": "narrow_tasks", "label": "窄任务清单 (gate_data.narrow_tasks[] 非空)"},
}

# ─── 插件生态节点（2026-08-29 实装；五元组口径见 references/sequence-node-safety-net-template.md）──────────
# 循环 A = 插件自维护（ECO 双文档同步）；循环 B = 上岗任务执行（cmd_migrate 三连）。
# G 谓词做真实检查（manifest 登记 / 加载安全网 / cap 白名单），存量产物经 ctx 注入；
# 缺失任一 → fail-closed 阻断（对齐 SN 五元组 D 分量）。
_PLUGIN_DEFAULT_PID = "bashpy-migrate"
# 2026-10-27 简化（owner：「插件 a/b 模式也要简化修正」）：原为 A/B/C 六套常量 + 两个并行
#   if 分支，B/C 唯一差异只是 pid 与节点前缀 ⟹ 收成一张 profile 表；节点 id 一字不改
#   （不动历史 state / 既有测试断言）。`caps` 以**相位**（ANALYZE/VERIFY/AUDIT）为键，
#   由节点后缀推导，不再逐节点写死。
_PLUGIN_PROFILES = {
    "plugin-a": {"pid": _PLUGIN_DEFAULT_PID, "nodes": ("ECO-SCAN-PLUGIN", "ECO-EDIT-PLUGIN", "ECO-DOC-PLUGIN"), "caps": {}},
    "plugin-b": {"pid": _PLUGIN_DEFAULT_PID, "nodes": ("MIGRATE-ANALYZE", "MIGRATE-VERIFY", "MIGRATE-AUDIT"),
                 "caps": {"ANALYZE": "analyze", "VERIFY": "verify", "AUDIT": "audit"}},
    "plugin-c": {"pid": "swe-rb", "nodes": ("SRB-ANALYZE", "SRB-VERIFY", "SRB-AUDIT"),
                 "caps": {"ANALYZE": "analyze", "VERIFY": "verify", "AUDIT": "audit"}},
}
_PLUGIN_NODE_TO_PROFILE = {n: r for r, p in _PLUGIN_PROFILES.items() for n in p["nodes"]}
_PLUGIN_NODES = tuple(_PLUGIN_NODE_TO_PROFILE)
_PLUGIN_A_NODES = _PLUGIN_PROFILES["plugin-a"]["nodes"]

# 被依赖模块函数注入点（安全网 R1: 测试只 patch 这些模块级名，不 patch 被依赖模块全局）
_GET_MANIFEST = None   # gk_plugin_manifest.get_manifest
_CHECK_CAP = None      # gk_plugin_manifest.check_capability
_LOAD_STATUS = None    # gk_bashpy_loader.load_status


def _plugin_deps() -> None:
    """惰性绑定被依赖模块函数到注入点（首次调用绑定；测试 R1 预先 patch 即跳过）。"""
    global _GET_MANIFEST, _CHECK_CAP, _LOAD_STATUS
    if _GET_MANIFEST is None or _CHECK_CAP is None:
        from gk_plugin_manifest import check_capability, get_manifest
        _GET_MANIFEST = get_manifest
        _CHECK_CAP = check_capability
    if _LOAD_STATUS is None:
        from gk_bashpy_loader import load_status
        _LOAD_STATUS = load_status


def _plugin_guard(node_id: str, ctx: dict) -> dict:
    """插件生态节点 G 谓词（真实检查 + 存量产物 ctx 注入，fail-closed）。

    ctx 可选：pid（默认 bashpy-migrate）、taxonomy_ok、migration_issues_ok、
    edit_plan、doc_synced、entry_ok、analyze_ok、verify_ok。
    缺失检查项 → 视为未就绪（保守 fail-closed）。
    """
    _plugin_deps()
    pid = ctx.get("pid") or _PLUGIN_DEFAULT_PID
    missing, fix, checks = [], [], {}

    m = _GET_MANIFEST(pid) if _GET_MANIFEST else None
    if m is None:
        missing.append(f"manifest 登记缺失: {pid}")
        fix.append(f"gk_plugin_manifest 登记 {pid}（Definition 74 未登记入口无法获得能力）")
    elif m.get("disabled"):
        missing.append(f"manifest 被管理性关闭: {pid}")
        fix.append("disabled=False 后再上岗")
    checks["manifest"] = bool(m and not m.get("disabled"))

    try:
        source = (_LOAD_STATUS() if _LOAD_STATUS else {}).get("source", "error")
    except Exception:
        source = "error"
    if source not in ("release", "release_unverified", "dev"):
        missing.append(f"加载安全网 load_status={source}（须 ∈ {{release, dev}}）")
        fix.append("修复加载源（发布包 SHA256 pin / dev 源码；missing/hash_mismatch/error 阻断）")
    checks["load_status"] = source

    route = _PLUGIN_NODE_TO_PROFILE.get(node_id)
    prof = _PLUGIN_PROFILES.get(route or "")
    if prof is None:
        return {"ok": False, "missing": [f"未登记的插件节点: {node_id}"],
                "fix": ["在 _PLUGIN_PROFILES 登记该节点（profile 表 = 唯一源）"],
                "checks": {}, "pid": pid}
    if route == "plugin-c" and pid != prof["pid"]:
        missing.append(f"循环 C 需 pid=swe-rb（当前 {pid}）")
        fix.append("ctx 传 pid='swe-rb'（SWE-RB 上岗任务环）")
    if prof["caps"]:
        cap = prof["caps"].get(node_id.rsplit("-", 1)[-1], "")
        c = _CHECK_CAP(pid, cap) if (m and cap and _CHECK_CAP) else {"ok": False}
        if not c.get("ok"):
            missing.append(f"cap 白名单: {pid}.{cap} 未登记")
            fix.append(f"manifest intercept 补 {cap}（能力最小化 §6.3）")
        checks["cap"] = c.get("capability", cap)
        if not ctx.get("entry_ok"):
            missing.append("统一入口未就绪 (hook R0.4 _plugin_bare_call)")
            fix.append("确认 pre_tool_hook Gate R0.4 拦截一切裸调用（CLI/cap 双门禁）")
    elif route == "plugin-a":
        if not ctx.get("taxonomy_ok"):
            missing.append("分类学计数基线缺失 (bashpy-problem-taxonomy.md §2)")
            fix.append("audit --bomb 计数登记分类学 §2 基线（漂移 → 循环 A 更新）")
        if not ctx.get("migration_issues_ok"):
            missing.append("插件权威源 migration-issues.md 不可读")
            fix.append("确认 zthl-bashpy-migrate/docs/migration-issues.md 存在")

    if node_id == "ECO-EDIT-PLUGIN" and not ctx.get("edit_plan"):
        missing.append("双文档收敛方案缺失 (edit_plan)")
        fix.append("ECO-EDIT 输出插件+技能双文档各一份方案")
    if node_id == "ECO-DOC-PLUGIN" and not ctx.get("doc_synced"):
        missing.append("双文档未同步 (doc_synced)")
        fix.append("ECO-DOC 双文档同步 + 分类学 §2 计数更新（不同构 → fail-closed 拦截）")
    if node_id in ("MIGRATE-VERIFY", "SRB-VERIFY") and not ctx.get("analyze_ok"):
        missing.append("analyze 产物缺失 (last_analyze/contract.json)")
        fix.append("先跑 ANALYZE（契约提取）")
    if node_id in ("MIGRATE-AUDIT", "SRB-AUDIT") and not ctx.get("verify_ok"):
        missing.append("verify 未通过 (verify_result)")
        fix.append("先跑 VERIFY（契约守卫，防 Blindness）")
    return {"ok": len(missing) == 0, "missing": missing, "fix": fix,
            "checks": checks, "pid": pid}


def _node_defaults(node_id: str) -> dict:
    """节点注册默认值推导（route/next/prev 由 ROUTES 推导）。

    2026-10-28（A4）：旧 ECO 站名先归一（`canon_eco`）再查路线 ⟹ 历史调用面不因
    5→4 站合并而 UNKNOWN_NODE。
    """
    node_id = canon_eco(node_id)
    for route, meta in _ROUTES.items():
        nodes = meta["nodes"]
        if node_id in nodes:
            idx = nodes.index(node_id)
            nxt = nodes[idx + 1] if idx + 1 < len(nodes) else (nodes[0] if meta.get("loop") else "(cycle complete)")
            prv = nodes[idx - 1] if idx > 0 else "(cycle start)"
            return {
                "id": node_id, "route": route, "route_name": meta["name"],
                "next": nxt, "prev": prv, "loop": meta.get("loop", False),
                "gate": _GATES.get(node_id, "顺序门禁"),
                "checklist": _CHECKLISTS.get(node_id, []),
                "safety": _SAFETY.get(node_id, ["序列节点引导"]),
                "registered": True,
            }
    return {"id": node_id, "registered": False}


def register_check(node_id: str) -> dict:
    """注册校验：节点是否在 NODE_REGISTRY（未知节点 → 拦截点）。"""
    info = _node_defaults(node_id)
    if not info["registered"]:
        return {"ok": False, "error": f"UNKNOWN_NODE: '{node_id}' 未注册 — advance 未知节点会污染状态机",
                "known_routes": {r: m["nodes"] for r, m in _ROUTES.items()}}
    return {"ok": True, "node": info}


# ─── G 谓词：前置产物齐备性检查（模板 §2）────────────────────────────────────
# C5 (2026-09-06): STAGE_3 首项 round-log 门禁——L1-L10 交叉审查 ≥2 轮 + 轮间红队挖洞
# 从 checklist 文字项升级为可判定项。宿主判定节点 = STAGE_4（advance 出 STAGE_3 时守卫，
# 此时轮次已跑完可判）；证据 = gate_data.subagent_history 审查点检计数 + red 动作/红 finding
# （确定性引擎从 state 注入，agent 不自证，对齐 narrow_tasks 注入先例）。advisory 二分由
# GK_GUARD_STRICT 承担（=1 硬阻断 / 降级 advisory），本函数只产出 missing 项。
_REVIEW_TASK_RE = re.compile(r"crossrev|plan-refinement|plan_refine|交叉审查|code[- ]?review|review|质询", re.I)
_RED_ACT_RE = re.compile(r"\bred\b|红队|RED-|redteam", re.I)


def round_log_from_gate_data(gd: dict) -> dict:
    """STAGE_3 round-log 确定性提取：≥2 轮审查点检 + 轮间红队挖洞证据。

    审查点检 = subagent_history task 含审查关键字（crossrev/plan-refinement/review…）；
    轮间扩展 = 同窗口存在 red 动作（subagent task 含 red）或 gate_data.ecc_findings
    source=red（红队挖洞产出，含 C3/S1-S3 候选）。返回 {"status": ready|pending, ...}。
    """
    gd = gd or {}
    hist = gd.get("subagent_history") or []
    hist = hist[-20:] if isinstance(hist, list) else []
    reviews = [e for e in hist if _REVIEW_TASK_RE.search(str(e.get("task", "")) or "")]
    red_acts = [e for e in hist if _RED_ACT_RE.search(str(e.get("task", "")) or "")]
    ecc_red = [f for f in (gd.get("ecc_findings") or [])
               if str((f.get("source") or "")).lower() == "red"]
    rounds = len(reviews)
    inter_red = bool(red_acts or ecc_red)
    ready = rounds >= 2 and inter_red
    return {
        "status": "ready" if ready else "pending",
        "rounds": rounds,
        "inter_red": inter_red,
        "review_tasks": [str(e.get("task", ""))[:80] for e in reviews[:4]],
        "red_hits": len(red_acts) + len(ecc_red),
        "detail": ("" if ready else
                   ("审查轮次=" + str(rounds) + "（需 ≥2）" if rounds < 2 else "")
                   + ("" if inter_red else "（缺轮间红队挖洞证据）")),
    }


# ─── P0 ledger：审查节点出口完整性（2026-09-07 b1g，㊴/㊵ 收敛缺省；合并 C5 出站守卫）───
# 出口锚点 = 审查节点的"下一节点"（advance 出口单咽喉消费，防节点绕过/只跑部分审查就出站）：
#   standard  STAGE_3→STAGE_4 → 锚 STAGE_4 = C5 round-log（既有）
#   standing  ECO-VERIFY→ECO-DOC → 锚 ECO-DOC = round-log + audit --all 记录
#   （_GATES["ECO-DOC"]="ECO-VERIFY → ECO-DOC 必须先 audit --all" 从 checklist 文字升级为可判定项）
# 证据全部由调用方从 state 确定性注入（agent 不自证，对齐 narrow_tasks/C5 注入先例）。
# GK_GUARD_STRICT 二分（=1 硬阻断 / 降级 advisory）由消费端（advance 出口）承担——本函数只产出 missing。
# 2026-10-28（E2，6 臂质询回流）：原 `_AUDIT_FIVE_DOMAIN_KEYS` 3 键 + `any` = fail-open
#   （只跑 `audit --state` 一域即可出站）；且 `audit_result` 零生产者却仍被采信。
#   现收敛为「**有生产者**的域必须全部落盘」（all-of）：state / docs 两域。
#   memory / crossr / report / depth 四域**无生产者**（`audit --memory/--crossr` 只 echo
#   不落盘）⟹ 不纳入 required（纳入即恒假），生产者缺口登记审计署计划 §26.10-E2，待补。
_AUDIT_PRODUCED_EVIDENCE_KEYS = ("audit_state_result", "audit_docs_result")

# ─── AUDIT 证据消费者登记表（2026-10-28，B3a；**只登记，不改任何消费行为**）───
# 两栏禁混（第三轮质询 G2）：
#   domain="audit" = 本署派发域消费点（判据 / 出口 / 视图 / 自检联动）
#   domain="eco"   = 只消费证据键、**不属** AUDIT 派发的 ECO 路线消费点
# kind="reader"   = 函数体内直接读 `audit_state_result` / `audit_docs_result`
# kind="delegate" = 经单一事实源 `audit_all_recorded` / `report_evidence_ok` 或 CLI 转调消费
# arm             = 已实存的**行为臂**（键缺失 ⟹ 判决翻转；先落臂再引用，幻影载体由不变量臂否决）
# 不变量 = scripts/test_gk_audit_consumers.py：正向（载体 + 臂实存）/ 反向（读点无遗漏）。
# 写方禁列：`gatekeeper-cli.sh cmd_audit` / `audit --all` 聚合器是生产者，不是消费者。
AUDIT_EVIDENCE_CONSUMERS = (
    {"id": "review_exit_gate", "domain": "audit", "kind": "delegate",
     "file": "gk_node_guard.py", "symbol": "review_exit_gate",
     "arm": "test_eco_doc_ready_rounds_red_and_audit_all"},
    {"id": "report_evidence_ok", "domain": "audit", "kind": "delegate",
     "file": "gk_node_guard.py", "symbol": "report_evidence_ok",
     "arm": "test_standard_有相位_仅state域_拒"},
    {"id": "guard_cli_inject", "domain": "audit", "kind": "delegate",
     "file": "gk_node_guard.py", "symbol": "_main",
     "arm": "test_cli_guard_eco_doc_injects_audit_all"},
    {"id": "audit_link_view", "domain": "audit", "kind": "reader",
     "file": "gk_views.py", "symbol": "cmd_audit_link",
     "arm": "test_missing_result_not_run"},
    {"id": "redteam_findings", "domain": "audit", "kind": "reader",
     "file": "gk_views.py", "symbol": "cmd_redteam_findings",
     "arm": "test_collect_three_sources"},
    {"id": "cli_audit_link", "domain": "audit", "kind": "delegate",
     "file": "gatekeeper-cli.sh", "symbol": "audit-link",
     "arm": "test_with_summary"},
    {"id": "audit_findings_adapter", "domain": "audit", "kind": "reader",
     "file": "gk_audit_findings.py", "symbol": "collect",
     "arm": "test_state_check_failure_registers_finding"},
    {"id": "eco_prereq_heuristic", "domain": "eco", "kind": "delegate",
     "file": "gk_advance.py", "symbol": "_eco_prereq_heuristic",
     "arm": "test_eco_audit_prereq_single_domain_missing"},
    # E25 B3a（2026-10-30，一轮六臂质询 WARN）：**动态域读点**必须与字面读点同入登记。
    #   `gk_audit_registry.register/dual_read` 的键集由 `domains` 形参驱动（`for k in domains`），
    #   字面键正则（`_READ_RE`）对其是盲区 ⟹ 原「反向读点无遗漏」= over-claim。
    #   **只登记**：本轮不改 `gk_audit_registry` 的任何读取语义。
    {"id": "registry_dual_read", "domain": "audit", "kind": "dynamic_reader",
     "file": "gk_audit_registry.py", "symbol": "dual_read",
     "arm": "test_reverse_no_unregistered_dynamic_domain_reader"},
    {"id": "registry_register", "domain": "audit", "kind": "dynamic_reader",
     "file": "gk_audit_registry.py", "symbol": "register",
     "arm": "test_reverse_no_unregistered_dynamic_domain_reader"},
)


def audit_all_recorded(gd: dict, state_file: str = "") -> bool:
    """audit --all 记录判据单一事实源（2026-09-07 批③ ② 接线统一；2026-10-28 E2 收紧）。

    语义：`_AUDIT_PRODUCED_EVIDENCE_KEYS` **全部**落盘才为真（原 `any` 语义 = 单域放行）。
    历史别名 `gd.audit_result` 自 2026-10-28 起**不再采信**：全仓零生产者（仅测试构造），
    E1 已封 `set-nested` / `update-gate-data` 写面 ⟹ 采信它只可能来自篡改/回放。
    消费方 = node_guard 出口谓词（ECO-DOC 前置）+ gk_advance ECO-VERIFY advisory/l9_gatechain
    （`_eco_prereq_heuristic` 单点委托）+ `report_evidence_ok` —— 防判据双轨漂移。

    **B3b（2026-10-28，owner 裁「密封 sidecar 登记 + auto 双读」）**：传入 `state_file` 时
    追加**审计署登记双读**（`gk_audit_registry.dual_read`）——登记存在则要求
    `domain -> sha256(证据)` 与登记一致且封印完好；登记缺失（auto）不拦。
    双读导入失败 ⟹ **fail-loud 返 False**（「无法校验」不得判成「一致」，同 G4 纪律）。
    """
    if not isinstance(gd, dict):
        return False
    if not all(bool(gd.get(k)) for k in _AUDIT_PRODUCED_EVIDENCE_KEYS):
        return False
    if state_file:
        try:
            import gk_audit_registry as _REG  # 延迟导入：registrar 亦被 CLI 独立调用
            return bool(_REG.dual_read(state_file, gd).get("ok"))
        except Exception:
            return False
    return True


def report_evidence_ok(state: dict, state_file: str = "") -> bool:
    """`audit --report` **签发前置判据**的单一事实源（2026-10-01 落刀）。

    finding `ECC-DD4FF260119F`：原判据内联在 `gatekeeper-cli.sh::cmd_audit --report`，
    且写死 `project_type == 'standing'` ⟹ 新路线 `zthl-adapter`（非 standard/standing）
    即便五域证据已落盘也恒被判「无证据」⟹ `audit --all` 的 report 域恒失败。
    现按 owner 令「不内联 `gatekeeper-cli.sh`」把规则上收至此（CLI 侧只调用、不复刻）。

    语义：
      `standard` 路线 = **相位标记 且 证据落盘**——① `AUDIT-STATE` ∈ `audit_phases_completed`
      **且** ② `audit_all_recorded(gd)`。
      **E8（2026-10-28，6 臂质询）**：`audit_phases_completed` 在**进入**相位时即 append
      （`gk_advance.py:322-326`）⟹ 相位标记**不能单独**作签发证据（`advance AUDIT-STATE`
      后未真跑审计即可空过）；本判据改为「标记 + 持久化证据」双条件。
      非 standard 路线（standing / zthl-adapter / …，本无 AUDIT-STATE 相位）只看 ②。
    """
    if not isinstance(state, dict):
        return False
    gd = state.get("gate_data") or {}
    if not isinstance(gd, dict):
        return False
    has_ev = audit_all_recorded(gd, state_file)
    phases = state.get("audit_phases_completed") or []
    if isinstance(phases, (list, tuple)) and "AUDIT-STATE" in phases:
        return has_ev
    if gd.get("project_type", "") == "standard":
        return False
    return has_ev


def review_exit_gate(node_id: str, gd: dict, state_file: str = "") -> dict:
    """审查节点出口完整性 ledger 谓词（P0 ledger 合并 C5 出站守卫）。

    node_id ∈ {STAGE_4, ECO-DOC}：round-log（≥2 轮审查 + 轮间红队）为公共项；
    ECO-DOC 另叠 audit --all 记录前置 = **有生产者的两域证据**（`audit_state_result` +
    `audit_docs_result`）**同时**落盘（2026-10-28 E2 收紧：原 `any` 单域放行 + `audit_result`
    历史形态均已废除）。
    返回 {"ok": bool, "status": ready|pending, "node":..., "missing": [...], "round_log":...,
          "audit_all": bool|None, "detail": str}。
    """
    gd = gd or {}
    rl = round_log_from_gate_data(gd)
    missing = []
    if rl.get("status") != "ready":
        missing.append("审查 ledger 未齐（" + (rl.get("detail") or "round-log pending") + "）")
    audit_all = None
    if node_id == "ECO-DOC":
        audit_all = audit_all_recorded(gd, state_file)
        if not audit_all:
            missing.append("audit --all 记录缺失（ECO-AUDIT→ECO-DOC 前置：须 audit_state_result + "
                           "audit_docs_result 两域同时落盘，且与审计署登记摘要一致；"
                           "auto：无登记不拦）")
    ready = not missing
    return {"ok": ready, "status": "ready" if ready else "pending", "node": node_id,
            "missing": missing, "round_log": rl, "audit_all": audit_all,
            "detail": "; ".join(missing)}


def node_guard(node_id: str, ctx: dict | None = None) -> dict:
    """G 谓词：前置产物齐备性检查。

    ctx 可选字段（由调用方注入）：
      context_file  : subagent-context.json 路径（存在 + 有签名 → 视为已刷新）
      baseline      : gitnexus 索引存在标记（bool）
      source_docs   : source_docs 检查结果（list[str] 缺失清单，空 = 齐备）
      narrow_tasks  : gate_data.narrow_tasks 条目数（int ≥1 视为已下发）
    插件生态节点（ECO-*-PLUGIN / MIGRATE-*）另见 _plugin_guard：ctx 用 pid/taxonomy_ok/
      migration_issues_ok/edit_plan/doc_synced/entry_ok/analyze_ok/verify_ok。

    返回：{"ok": bool, "node": <节点元数据|None>, "missing": [...], "fix": [...],
          "info": [...], "checks": {...}}
      （2026-09-10 修正：此前未注册节点/插件节点两条早返回路径缺 "info"、未注册路径缺 "node"
        → JSON 契约不一致，消费方 .get('info') 取到 None；现三路径字段齐备）
    """
    info = _node_defaults(node_id)
    if not info["registered"]:
        return {"ok": False, "node": None, "error": f"UNKNOWN_NODE: '{node_id}'",
                "missing": ["node_registration"], "info": [], "checks": {},
                "fix": [f"注册节点: python3 scripts/gk_node_guard.py register --node {node_id}"]}
    ctx = ctx or {}
    if node_id in _PLUGIN_NODES:
        r = _plugin_guard(node_id, ctx)
        return {"ok": r["ok"], "node": info, "missing": r["missing"], "fix": r["fix"],
                "info": r.get("info", []), "checks": r.get("checks"), "pid": r.get("pid")}
    missing, fix, info_notes = [], [], []
    # 1. 代码库地图 — 实存 + 签名新鲜（2026-09-04 A2：sig 实存且不早于 context 公钥轮换点，
    #    防「只验存在不验签名新鲜度」的存在性假绿——密钥轮换后未 context --update 重签 → 判定缺失）
    cf = ctx.get("context_file") or ""
    if cf and Path(cf).exists():
        fs = _context_signature_fresh(Path(cf))
        if not fs["ok"]:
            missing.append(f"{_PRECONDITIONS['codebase_map']['label']} ({fs['reason']})")
            fix.append("bash gatekeeper-cli.sh context --update")
    else:
        missing.append(_PRECONDITIONS["codebase_map"]["label"]); fix.append("bash gatekeeper-cli.sh context --update")
    # 2. 基线 — baseline_status（gitnexus status → current|reusable|stale|unavailable，CLI **单点**）：
    #    **白名单**判据（2026-09-21 R16/C2′+L4）：
    #      current|reusable → 齐备（内容一致即**可复用**，不必逼一轮全量 analyze）；
    #      stale|unavailable → 判缺 + 引导经**单一入口** `context --update` 刷新。
    #    ⚠ 白名单外的值一律 fail-closed，且必须报**真因**（值是啥），**禁报"未注入"**——
    #      原实现把不认识的值穿透到「存在性兜底已撤销」支，报 `baseline_status 未注入`，
    #      而状态其实**已注入**、只是值不认识 ⟹ 判据指向**错误方向**（H3，同 R12 族）。
    #    ⚠ `baseline`(bool) 存在性兜底**已废除**（同批）：原 `elif not ctx.get("baseline")` 下
    #      `{"baseline": true}` 无 status 仍过门 = **假绿**（F-REV-76 撤销的兜底以 bool 形态残留）；
    #      现该键**不参与判据**，不再豁免。
    #    ⚠ fix 文案走**单一入口**：裸调 `analyze --embeddings` 违 `_gx_analyze_embeddings`
    #      头注释「凡走 analyze --embeddings 一律经此（禁各处直调）」（N1）。
    _BS_REUSE = ("current", "reusable")
    _BS_ANALYZE = ("stale", "unavailable")
    bs = ctx.get("baseline_status")
    if bs in _BS_REUSE:
        pass
    elif bs in _BS_ANALYZE:
        missing.append(f"{_PRECONDITIONS['baseline']['label']} ({bs} — 需刷新基线)")
        fix.append("bash gatekeeper-cli.sh context --update（单一入口，含 analyze 与残留自愈臂）")
    elif bs is None or bs == "":
        missing.append(f"{_PRECONDITIONS['baseline']['label']} (baseline_status 未注入 — 存在性兜底已撤销，F-REV-76)")
        fix.append("bash gatekeeper-cli.sh node-guard <node>（CLI 自动注入 gitnexus status；勿手传 ctx）")
    else:
        missing.append(f"{_PRECONDITIONS['baseline']['label']} (baseline_status 值不在白名单: {bs!r})")
        fix.append("bash gatekeeper-cli.sh node-guard <node>（CLI 自动注入四态；勿手传 ctx）")
    # 3. 源文档 — 契约：ctx.source_docs = **缺失清单**（空 list = 齐备），由 CLI `node-guard
    #    --source-docs <逗号分隔路径>` 查磁盘可读性后注入（见 gatekeeper-cli.sh cmd_node_guard）。
    #    2026-09-10 修正（P1+P2，用户定案）：原判据 `if "source_docs" not in ctx or ctx.get(...)`
    #    语义正确但后果缺陷——自动 advance 路径不传该参数 → 恒 missing（advisory 永久噪音 +
    #    GK_GUARD_STRICT=1 恒 BLOCK 陷阱）；且缺失清单细节被丢弃（模板 §2 要求"列缺失清单"）。
    #    现：未声明（键缺失）→ info 跳过（自动路径无源，不该恒判缺）；声明且缺失非空 → missing
    #    并回显具体路径；声明且为空 → 齐备。
    sd = ctx.get("source_docs")
    if "source_docs" not in ctx:
        info_notes.append(f"{_PRECONDITIONS['source_docs']['label']} (计划未声明 source_docs → 跳过检查)")
    elif sd:
        _sd_list = sd if isinstance(sd, list) else [str(sd)]
        missing.append(f"{_PRECONDITIONS['source_docs']['label']}: 缺失 {len(_sd_list)} 项 {_sd_list[:5]}")
        fix.append("确认计划引用的 source_docs 全部可读（META source_docs 声明逗号分隔路径）")
    # 4. 窄任务清单
    if not ctx.get("narrow_tasks"):
        missing.append(_PRECONDITIONS["narrow_tasks"]["label"]); fix.append("拆分窄任务清单 (模板 §4) 登记 gate_data.narrow_tasks[]")
    # C5 (2026-09-06): STAGE_4 出站守卫 = STAGE_3 首项 round-log 判定（≥2 轮 + 轮间红队）。
    # P0 (2026-09-07 b1g): 谓词扩展至 standing 审查出口 ECO-DOC（ECO-AUDIT→ECO-DOC）——
    # round-log + audit --all 记录前置（review_exit_gate 单源承载，消费端=advance 出口单咽喉）。
    # ctx.round_log/audit_all 由 guard CLI 从 state 确定性注入（round_log_from_gate_data）；
    # 未注入 → 保守 pending。
    rl = ctx.get("round_log")
    if node_id == "STAGE_4":
        if not isinstance(rl, dict) or rl.get("status") != "ready":
            why = ("round_log 未注入（guard CLI 缺 state）" if not isinstance(rl, dict)
                   else ("审查轮次=" + str(rl.get("rounds")) + "（需 ≥2）" if rl.get("rounds", 0) < 2
                         else "缺轮间红队挖洞证据"))
            missing.append("STAGE_3 round-log 未齐（" + why + "）")
            fix.append("STAGE_3 内完成 ≥2 轮 L1-L10 交叉审查（轮间红队挖洞）——证据=subagent_history "
                       "审查点检 + red 动作/红 finding；advisory 或 GK_GUARD_STRICT=1 硬阻断")
    elif node_id == "ECO-DOC":
        # P0 ledger：standing ECO-AUDIT→ECO-DOC 出口（ECO-AUDIT = standing 交叉审查节点，
        # 出站须 round-log 齐 + audit --all 记录；防"只跑部分审查/跳过审查就出站"）。
        if not isinstance(rl, dict) or rl.get("status") != "ready":
            why = ("round_log 未注入（guard CLI 缺 state）" if not isinstance(rl, dict)
                   else ("审查轮次=" + str(rl.get("rounds")) + "（需 ≥2）" if rl.get("rounds", 0) < 2
                         else "缺轮间红队挖洞证据"))
            missing.append("ECO-AUDIT 审查 ledger 未齐（" + why + "）")
            fix.append("ECO-AUDIT 内完成 ≥2 轮全量交叉审查（轮间红队挖洞）——证据=subagent_history "
                       "审查点检 + red 动作/红 finding；advisory 或 GK_GUARD_STRICT=1 硬阻断")
        if not ctx.get("audit_all"):
            missing.append("audit --all 记录缺失（ECO-AUDIT→ECO-DOC 前置：须 audit_state_result + "
                           "audit_docs_result 两域同时落盘）")
            fix.append("先跑 bash gatekeeper-cli.sh audit --state --docs（两域证据落盘 gate_data）")
    checks = {"round_log": rl if isinstance(rl, dict) else {"status": "unavailable"},
              "audit_all": ctx.get("audit_all")}
    return {"ok": len(missing) == 0, "node": info,
            "missing": missing, "fix": fix, "info": info_notes, "checks": checks}


# ─── 流程总运行线路（地铁总运行路线，Phase 3.5d route_template 实装）─────────
def _owner_consistency(route: str, meta: dict) -> str:
    """`owner` 的**读侧消费点**（D7-B E4，2026-10-28 6 臂质询）。

    病象：`owner` 只有产点（`_ROUTES.owner` / `_HINT_PHASES.owner`）+ `route_map` 透传，
    `gatekeeper-cli.sh` 全文零命中 ⟹ 派发归属退化为**装饰标签**（与本计划判删
    `offline_human` / I-1 / I-3 的标准自相矛盾）。此处把它变成可机检契约：
      · 节点 hint 声明了 owner ⟹ 路线必须登记 owner（防半迁移）；
      · 两者都存在 ⟹ 必须相等（防归属漂移）。
    **fail-loud（2026-10-28 质询，5 臂共识）**：gk_advance 不可导入时**不得**返回空串
    （= 判「一致」，fail-open）—— 返回 `route_owner_unchecked` 让调用方 fail-closed。
    → 错误串（空串 = 一致或不适用）。
    """
    own = str(meta.get("owner") or "")
    try:
        import gk_advance as _A  # 延迟导入：gk_advance 依赖本模块，顶层导入成环
    except Exception:
        return ("route_owner_unchecked: gk_advance 不可导入，无法校验路线 %s 的 owner 契约"
                "（fail-loud：禁把「无法校验」判成「一致」）" % (route,))
    hints = getattr(_A, "_HINT_PHASES", {}) or {}
    for n in meta.get("nodes") or []:
        ho = str((hints.get(n) or {}).get("owner") or "")
        if not ho:
            continue
        if not own:
            return ("route_owner_missing: 节点 %s 声明 owner=%s，路线 %s 未登记 owner"
                    % (n, ho, route))
        if ho != own:
            return "route_owner_mismatch: 路线 %s owner=%s，节点 %s owner=%s" % (
                route, own, n, ho)
    return ""


def route_map(route: str | None = None) -> dict:
    """总运行线路图。route=None → 全部路线；否则单路线 + 车站播报所需信息。"""
    if route:
        meta = _ROUTES.get(route)
        if not meta:
            return {"ok": False, "error": f"UNKNOWN_ROUTE: '{route}'", "known": sorted(_ROUTES)}
        _oerr = _owner_consistency(route, meta)
        if _oerr:
            return {"ok": False, "error": _oerr}
        return {"ok": True, "route": route, "name": meta["name"], "nodes": meta["nodes"],
                "loop": meta.get("loop", False),
                **({"owner": meta["owner"]} if meta.get("owner") else {})}
    return {"ok": True, "routes": {r: m for r, m in _ROUTES.items()}}


def station_announcement(node_id: str, current: str | None = None) -> dict:
    """单节点车站播报：当前站 + 下一站预报 + 进入门禁 + checklist（Phase 3.5d 注入形态）。"""
    info = _node_defaults(node_id)
    if not info["registered"]:
        return {"ok": False, "error": f"UNKNOWN_NODE: '{node_id}'"}
    return {
        "ok": True,
        "station": node_id,
        "route": info["route"],
        "route_name": info["route_name"],
        "prev": info["prev"],
        "current": current or node_id,
        "next": info["next"],
        "gate": info["gate"],
        "checklist": info["checklist"],
        "safety": info["safety"],
        "announced_at": datetime.now(timezone.utc).isoformat(),
    }


# ─── CLI ───
def _auto_context_file() -> str:
    """L9 CLI 编排注入：subagent-context.json 实存路径（技能目录，签名文件伴生）。"""
    skill = Path(__file__).resolve().parent.parent
    cf = skill / "references" / "subagent-context.json"
    return str(cf) if cf.exists() else ""


# F-REV-76（2026-09-16，用户裁定）：原 `_auto_baseline()`（.gitnexus/gitnexus.json 实存 → True）
# **已删** —— 它是「存在性兜底」的注入端（老索引/硬崩索引只要文件在就过门）。基线判定现只认
# `baseline_status`（CLI 由 `_gitnexus_baseline_status` 调 gitnexus status 注入，见 cmd_node_guard）。


def _keys_dir() -> Path:
    """context/audit Ed25519 密钥目录（对齐 CLI _AUDIT_KEY_DIR = <SKILL_DIR>/.keys）。"""
    return Path(__file__).resolve().parent.parent / ".keys"


def _context_signature_fresh(ctx_file: Path) -> dict:
    """codebase_map 签名新鲜度谓词（2026-09-04 A2 实装）。

    subagent-context.json 由 _sign_raw 用 context 私钥签名（24h 轮换），`.sig` = 原始 Ed25519 字节。
    密钥轮换（pub mtime 更新）后未 `context --update` 重签 → sig mtime < pub mtime → stale。
    此前 node_guard codebase_map 只验文件存在不验签名新鲜度 → 密钥轮换后 guard 假绿
    （SCR F2↔F3 耦合：A 必须把『签名新鲜』下沉到 guard）。全量密码学验签仍走 CLI
    （_CONTEXT_PUB_KEY openssl pkeyutl），此处为确定性文件级新鲜判定（guard 保持零外部依赖）。

    返回 {"ok": bool, "reason": str}；reason ∈ {ok, sig_missing, sig_stale_after_key_rotation}。
    """
    sig = Path(str(ctx_file) + ".sig")
    if not sig.exists():
        return {"ok": False, "reason": "sig_missing"}
    pub = _keys_dir() / "context_ed25519.pub"
    if pub.exists() and sig.stat().st_mtime < (pub.stat().st_mtime - 1.0):
        return {"ok": False, "reason": "sig_stale_after_key_rotation"}
    return {"ok": True, "reason": ""}


def missing_source_docs(docs, root: str = "") -> list:
    """源文档磁盘可读性检查 → 缺失清单（空 list = 齐备）。

    F-REV-15 (2026-09-10)：相对路径按 **仓根**（root = MAIN_REPO_WSL）解析，而非调用方 cwd。
    根因：`cmd_advance` 不 cd，cwd 随调用点漂移（实测同一相对路径在主仓目录判 OK、在技能目录
    判 missing）→ 计划声明相对路径会被误判缺，重演 P1 的"advisory 永久噪音 + GK_GUARD_STRICT=1
    恒 BLOCK"陷阱。绝对路径原样判定；root 为空 → 退回原样判定（对齐修复前行为）。
    """
    out = []
    for p in (docs or []):
        p = str(p).strip()
        if not p:
            continue
        cand = p
        if root and not os.path.isabs(p):
            cand = os.path.join(root, p)
        if not os.path.isfile(cand):
            out.append(p)
    return out


def _main():
    p = argparse.ArgumentParser(description="序列节点安全网承载（SN=⟨G,B,C,T,D⟩ + 总运行线路 + 车站播报）")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("route-map"); sp.add_argument("--route", default=None)
    sp = sub.add_parser("announce"); sp.add_argument("--node", required=True); sp.add_argument("--current", default=None)
    sp = sub.add_parser("guard"); sp.add_argument("--node", required=True); sp.add_argument("--state-file", default=""); sp.add_argument("--ctx", default=""); sp.add_argument("--pid", default="")
    sp = sub.add_parser("register"); sp.add_argument("--node", required=True)
    # 2026-10-28（A4）：旧站名 → 4 站规范名单源查询（bash 侧 monitor schema 查找回退用）
    sp = sub.add_parser("canon"); sp.add_argument("--node", required=True)
    # F-REV-15 (2026-09-10)：source_docs 磁盘检查 + ctx 合并（供 cmd_node_guard 委托，bash 不再内嵌 python）
    sp = sub.add_parser("source-docs")
    sp.add_argument("--source-docs", required=True)
    sp.add_argument("--root", default="")
    sp.add_argument("--ctx", default="")

    a = p.parse_args()
    out = {}
    exit_code = 0
    if a.cmd == "route-map":
        out = route_map(a.route)
    elif a.cmd == "announce":
        out = station_announcement(a.node, a.current)
    elif a.cmd == "guard":
        ctx = {}
        if a.ctx:
            try:
                ctx = json.loads(a.ctx)
            except json.JSONDecodeError:
                ctx = {}
        if a.state_file and Path(a.state_file).exists():
            try:
                d = json.loads(Path(a.state_file).read_text(encoding="utf-8"))
                gd = d.get("gate_data", {})
                ctx.setdefault("narrow_tasks", len(gd.get("narrow_tasks", [])))
                # C5 (2026-09-06): STAGE_4 守卫注入 round-log（state 确定性提取，agent 不自证）
                # P0 (2026-09-07 b1g): 谓词扩展——ECO-DOC（standing ECO-AUDIT→ECO-DOC 出口）
                # 同注入 round-log + audit --all（2026-10-28 E2：有生产者两域 all-of）判据。
                if a.node in ("STAGE_4", "ECO-DOC"):
                    ctx.setdefault("round_log", round_log_from_gate_data(gd))
                    if a.node == "ECO-DOC":
                        ctx.setdefault("audit_all", audit_all_recorded(gd, a.state_file))
            except Exception:
                pass
        # 2026-09-01 L9 深检实装：CLI 编排注入（正本清源）——ctx 由 CLI 从 state/磁盘推导，
        # agent 不再自证。codebase_map → subagent-context.json 实存（+ 签名新鲜度）。
        # F-REV-76（2026-09-16）：baseline **不再**按 .gitnexus 实存自动注入 True（存在性兜底 =
        # 假绿）；改由 CLI 注入 `baseline_status`（gitnexus status 单一事实源，见 cmd_node_guard）。
        ctx.setdefault("context_file", _auto_context_file())
        if a.pid:
            ctx["pid"] = a.pid
        out = node_guard(a.node, ctx)
        exit_code = 0 if out.get("ok") else 2
    elif a.cmd == "register":
        out = register_check(a.node)
        exit_code = 0 if out.get("ok") else 2
    elif a.cmd == "canon":
        out = {"node": a.node, "canon": canon_eco(a.node)}
    elif a.cmd == "source-docs":
        ctx = {}
        if a.ctx:
            try:
                ctx = json.loads(a.ctx)
            except json.JSONDecodeError:
                ctx = {}
        ctx["source_docs"] = missing_source_docs(a.source_docs.split(","), a.root)
        out = ctx
    print(json.dumps(out, ensure_ascii=False))
    sys.exit(exit_code)


if __name__ == "__main__":
    _main()

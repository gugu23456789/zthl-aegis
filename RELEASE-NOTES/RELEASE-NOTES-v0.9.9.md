# ZTHL Aegis v0.9.9 — 发布说明

> 2026-11-09。本版把未发布的 **v0.9.8.10** 内容、红队/ECC 闭环，以及 **pytest 91 红清零 /
> 自动清单登记表 / 路由基线 fail-loud / 红先模版 20 形态** 一并发布；功能行为不变，
> 门禁与额度银行只做安全收口。

## 1. 红队能力

- **4 API 角色并发**：scanner / exploiter / auditor 三路并发，reporter 在三份报告完成后汇总
  （任务前缀 `RED-SCOPE:` / `RED-EXPLOIT:` / `RED-POSTEX:` / `RED-REPORT:` 映射角色）。
- **确定性只读站并发**：`gk_red_parallel.sh` 以 4 workers 跑 14 个只读 phase；
  `RED-REPORT` / `advance` 状态推进仍串行（防 state 写竞态）。
- **治理契约**：新增 `references/governance-contract.json` + `RED-GOV` 10 条向量
  （BANK-01..03 / PATH-01..04 / CONC-01..03）。
- **能力边界**：本版强化的是**自红队**能力（只作用于本仓与授权工作树），对外部系统保持零主动
  探测；后续将安装「防止对外部项目渗透」的自动化安全护栏（出网目标域 / 动作面 / 速率硬限制）。

## 2. ECC finding 闭环

- 红队 finding 按正路转换：`_red_attacks.red_report` → 临时 state `_guard_precheck` →
  `gk_finding.upsert_red_findings`（内含 `_precheck_degrade`）→ `amend-title` 刷锚 → `close(tests)`。
- 本批 5 条：`RED-BANK-01` / `RED-SEAL-01` / `RED-LOCK-01`（tests 证据）、
  `RED-PATH-01`（TargetPathScope 21 passed）、`RED-QUOTA-01`（review:trust-boundary-env-local）。
- **ECC 预检盲点修复**：`gk_ecc_review` 支持 `file.py::symbol`（含 `Class.method` 逐段存在性）；
  预检实测抓到 C3/C5 行锚漂移并用 `[刷锚]` 重钉。

## 3. 额度银行

- `REJECTED_CAP=120`；审计投影 `view_bank_actions(gd,state_file)` 并入 append-only journal，
  121 次拒改后仍能读到 bank 阻断。
- `append + seal` 改为事务：seal 失败回滚账本/封印/链（`_rollback_ledger`）。
- `C:/` 与 `/mnt/c/` 双形态锁键折叠为宿主原生同一把锁（`_canonical_host_path`）。
- **CAP 未退役**：`RAISE_DAILY_CAP` 仍为活跃硬闸（默认 6、UTC 日切、命中 fail-loud）。

## 4. 门禁 / JSON / 看门狗 / 沙箱（v0.9.8.10 内容）

- linked worktree 按 `.git` 的 `gitdir:` 认领（名字无关），恢复 Gate3/Gate4/额度计费。
- 14 处手工拼 JSON 转 `gk_json.py build`；19 处残差入指纹台账（新增/改动必红）。
- 看门狗阈值单源（`gk_watchdog.py` 常量）；`_accept_cli.sh` 不再写第二份缺省。
- 红队 16 站 dry-run、敌意 JSON 往返、沙箱 enforced/OOM/超时验证。
- Windows 全量测试：cwd=`scripts/` + xdist（`-n 4 --dist loadfile`）。

## 5. 验证

- `test_gk_red_findings_fix.py`：4 passed
- 账本/JSON/审计：165 passed；额度全套：74 passed
- `test_gk_ecc_review.py`：6 passed；`TargetPathScope`：21 passed；声明式额度：18 passed
- `finding reconcile`：ok=true，anomalies=[]
- 全量回归：见本版 CI/本地 `pytest -q -n 4 --dist loadfile` 结果

## 6. 本批收口（2026-11-09）

- **pytest 91 红清零**：91 项失败全部修复；关联 32 个测试文件 865 passed / 1 位置依赖
  （worktree 内 `subagent_unlogged` 计数差异，主树不复现）。
- **自动清单登记表**：新增 `scripts/gk_list_registry.py` 扫描 64 项裁决面清单 →
  `references/list-registry.json`；`--check` 漂移即红（`test_gk_list_registry.py` 4 臂）。
- **路由基线 fail-loud**：`check_route_center_alignment` ⑦ 的五处 fail-open
  （meta / 章节 / 单元格缺失、`MAIN_REPO_WSL` 无字面量）改为 fail-loud；7 臂红先测试。
- **红先模版 12→20**：新增 8 形态（fail-open→fail-loud、生成物同步、高风险子集、双副本、
  消费方接线、空值/缺失、快照污染、篡改翻红）；`gk_red_arm_gen` 增加
  `classify` / `scaffold` / `promote`（红→绿都过才回灌）；`_redfirst_cli` 沙箱补 rev 版登记表。
- **finding_arms 漂移归零**：134 条台账 `--check` 0 漂移。

## 7. 明确不做

- 不升级 `openai`（3.3.1 → 3.46.0 候选，需重生成锁 + 新 venv 实测）。
- 不关闭历史 13 条结构性 RED backlog（`RED-MIGRATE-*` / `RED-INTEGRITY-*` / 污染检测等），
  需独立修复批，禁无证据批量 close。
- **只强化自红队，不把渗透能力外扩**：本版强化的是对自身工程链路的红队自检；对外部项目保持零
  主动探测，sapper 仅作只读参考。未来将安装「防止对外部项目渗透」的自动化安全护栏
  （出网目标域 / 动作面 / 速率硬限制），把这条边界做成机检。

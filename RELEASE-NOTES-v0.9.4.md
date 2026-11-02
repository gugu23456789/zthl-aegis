# ZTHL Aegis v0.9.4 — 发布说明

> 发布日期：2026-11-02
> 基线：v0.9.3（`980945d0`）
> 本说明为人工撰写，覆盖本次发布的功能、修复、开源面调整与升级注意事项。

---

## 1. 概览

v0.9.4 是一次**发布面整理 + 红队/审计可运行性 + MoA 防失败**的版本：

- 补齐红队 10 个缺失的 monitor schema，红队 16 站首次全绿；
- 把「节点注册 → schema 载体」纳入包完整性硬门，CI/release 自动拦截缺件；
- MoA 增加臂数断言与有界自动补救，避免 6 臂被默认归属剪成 1 臂；
- 安装器修复重复安装后 manifest 覆盖面丢失的问题；
- 重写元数据中枢，撤掉旧仓库/旧路径/旧机制；
- 公开面撤出早期审计报告与内部安全记录，统一补 DOC-META。

本次验证：`ci_smoke` **226 passed**，`package-integrity` **0 error**，`doc-align` 交叉引用 **PASS**。

---

## 2. 亮点

### 2.1 红队 16 站可完整运行

此前 `monitor-schemas/` 只覆盖 16 个红队站中的 6 个。`advance RED-HOOK` 会因
`no schema for RED-HINT` 被银行 monitor 判 0.5 拦停，后续各站同样无法通过。

本版补齐：

`RED-HINT / RED-HOOK / RED-PY / RED-POISON / RED-REGISTRY / RED-GHOST /
RED-COVERAGE / RED-DIFF / RED-INTEGRITY / RED-AIG`

实测红队链：

```
[1/16] RED-SCOPE … [16/16] RED-AIG  全部 ok
failed_step = null
```

### 2.2 schema 缺口变成发布硬门

`gk_package_integrity.py` 新增 `monitor_schema` 检查：

- 覆盖 `standing / standard / audit / red` 四条核心路线的全部节点；
- 缺 `monitor-schemas/<NODE>.json` ⟹ **error**；
- CI 的 `package-integrity` job 与 release 预检都会跑；
- 新增 `test_real_repo_covers_all_route_nodes` 防回归。

### 2.3 MoA：显式臂数断言 + 有界自动补救

- 默认仍保持安全语义：`task_bound` 只聚合同任务、多批默认分节；
- 新增 `degraded:true`：只聚合 1 条且排除了异任务时不再静默；
- 新增 `--expect N`：实际 references 数不符 ⟹ `EXPECTED_ARMS_MISMATCH`，rc=1；
- 新增 `--auto-remediate`（opt-in）：仅在 `--expect` 不足、`suspect_count=0`、
  且缺口可由 task/批边界解释时，自动放宽一次并记录
  `auto_remediation: {applied, before, after}`；
- `--html` 模式在 error 时也返回 rc=1；
- `/gk-refine` 的聚合命令已固定带 `--allow-cross-task --allow-cross-batch --expect 6 --auto-remediate`。

实测 6 臂：`before=1 → after=6`，rc=0。

### 2.4 安装器：重复安装不再丢卸载覆盖面

修复 `install.sh` 的 manifest 覆盖问题：此前重复安装（文件全部相同）会把清单写成空，
导致 `uninstall.sh` 无法删除任何文件。

现口径：**本次写入 ∪ 旧 v2 清单**，并新增「重装 → 卸载」往返测试与钩子覆盖面变更测试。

---

## 3. 新增

- 红队 10 个 monitor schema（见 §2.1）。
- `gk_package_integrity.py`：
  - 钩子 wrapper / 装卸对称检查；
  - `_CMD_REG` 命令注册 → 函数定义检查；
  - 插件 manifest（id/intercept/write-undo/builtin 源）检查；
  - monitor schema 覆盖检查。
- CI 新增 `package-integrity` job；`release.yml` 在打包前执行同一扫描。
- MoA：`degraded`、`--expect`、`--auto-remediate`。
- README（中/英）新增「配置审计署（决策模型）」：端点、密钥目录、think-mode、
  temperature、seed、timeout、model-version 与 `produce`/`sweep` 示例。
- 公开参考文档统一 `DOC-META`（title/type/owner/status/updated）。
- 文档路线图：
  - 全平台支持（长期）；
  - 决策模型统一配置与 provider 适配器。

## 4. 修复

- `gk_chain.py --dry-run`：旧实现给每步注入 `advance --check`，而 `--check` 不推进 state，
  导致 standing 链在 `ECO-VERIFY` 假失败（`ECO sequential violation`）。
  现改为**只打印计划、不执行、零 state 写**；单站校验请直接
  `gatekeeper-cli.sh advance <node> --check`。
- `install.sh` manifest 重复安装覆盖问题（见 §2.4）。
- `gk_doc_align.py` 交叉引用检查：
  - `#` 锚点必须紧贴 `.md`，修复树形图 `SKILL.md   # Agent` 误报；
  - 新增主机绝对路径检测（`/mnt/...`、`/home/...`、`/root/...`、`<home>`）；
  - 公开包裁剪的私仓文档缺失时不再误报；
  - `meta-routing-protocol.md` / `architecture-overview.md` 纳入检查范围。
- `meta-routing-protocol.md` 重写：删除旧仓库、旧绝对路径、旧机制、失效命令
  （如 `advance R1-T1`），修正 META 字段数与 `project_type` 口径。
- `xspi-defense.md` 公开版清理：内部记忆挂件记录整段撤出公开面；`T5-*` 标注为内部任务编号；
  删除内部计划/迁移组件指涉。
- `paper-review` 主脚本注释去标识，并升级 loader pin 到 `0.1.0.post34`（逻辑零变更）。

## 5. 开源面调整

### 5.1 撤出公开包

- `references/security-measures.md`（内部安全记录）；
- 全部 **30 份** `references/ecc-audit-YYYYMMDD.md` 早期审计报告（逐日快照，含内部证据/路径/失败基线）；
- 既有私仓项保持不变（`docs/`、`.keys/`、`paper-venues/`、`ecc-finding-*` 等）。

### 5.2 转入公开包

- 收敛评估器整族：`gk_convergence_evaluator.py`、`gk_convergence_estimator.py`、
  对应测试、`references/convergence-evaluator.md`；
- 序列节点安全网模板：私仓保留正本，公开副本由 `oss_scrub export` 按
  `GK-PUBLIC:CUT-*` 标记自动脱敏生成（不维护第二份手写副本）；
  其中 §1b 机制对账表在公开版改为**概述表述**（不含逐字引文与外部文件名）。

### 5.3 保持闭源（owner 裁定）

- `paper-review` 整族（脚本、loader、spec、会议档案、测试、agent family）——
  README 已改为「私仓内置、公开包不随附」，与白名单和开源前置计划一致。

### 5.4 导出验证

```
export: 753 files copied, 988 excluded, 6 private blocks stripped
SCRUB OK — tree is publishable
```

公开树中 `ecc-audit-*`、`security-measures.md`、`docs/` 均为 0；`xspi-defense.md`
公开版不含 `zthl`/`卫星计划`/`AMP ash`/§7。

反查词门禁改为**文件 × 词**豁免（配置 = `references/oss-export-whitelist.json`
的 `forbidden_exemptions`，每条带 reason）：MoA 生产件可带 κ 记号，其余反查词在其
所在文件里照常拦截；未列出的文件命中原词表仍拒发。

## 6. 文档

- `references/meta-routing-protocol.md`：650+ 行 → 约 370 行。
  - META 字段修正为 **11 项**（补 `edit_budget_declared`）；
  - 路由函数改为 `resolve_plan` / `resolve_repo`（`gk_route_center.py`）；
  - `project_type` 改为「`standard` vs 非 standard」的开放字符串口径；
  - 删除双循环飞轮、SkillOpt epoch 同构、插件双循环等过时段落；
  - 红队 16 站与 monitor schema 硬门写入相位表；
  - 推送白名单改为现行托管站 + `GK_PUSH_REMOTE_ALLOW`；
  - `block_log` 上限改为实际值 24。
- `references/standard-maintenance-module.md`：修正 4 制品口径、行号锚改符号锚，
  新增工程模板/安全网总览。
- `references/prm-monitor-methodology.md`：新增 MoA 归属/批边界/失败补救章节。
- `references/superagent-comparison.md`：补充对 OPCAP 的参考边界。
- 公开参考文档 `DOC-META` 覆盖：24 份公开文档中 22 份具备；
  其余 2 份为生成物（`README.md` 索引、`cli-protocol.md` docgen 输出）。

## 7. 安装与升级

### 7.1 升级已有安装

```bash
bash install.sh --force
```

- `--force` 会覆盖已存在文件并保留 `.bak-<UTC>` 备份；
- manifest 现在会并入旧清单，重复安装后卸载仍能清理干净；
- 如需调整钩子覆盖面：

```bash
bash install.sh --force --hook-profile safe   # Edit|Write|SearchReplace|RunCommand
bash install.sh --force --hook-profile full   # 全部工具
bash install.sh --force --hook-profile off    # 摘除本仓钩子条目
```

### 7.2 卸载

```bash
bash uninstall.sh --dest <安装目录> --yes
```

只删除 manifest 记录的文件与本仓钩子条目；用户文件、其他钩子、`~/.gatekeeper/cron`
均不动。

## 8. 行为变更与兼容性

| 变更 | 影响 | 处理 |
|:--|:--|:--|
| `gk_chain.py --dry-run` 不再执行 `advance --check` | 演练只打印命令 | 单站校验改用 `advance <node> --check` |
| `security-measures.md` 不再随公开包 | 公开文档链接失效 | 使用私仓版本；公开文档不再引用 |
| 30 份 `ecc-audit-*` 不再随公开包 | 公开面不再有逐日审计快照 | 需要审计证据请跑 `audit --report` 生成新报告 |
| `meta-routing-protocol.md` §4 口径变化 | `project_type` 不再宣称三值穷举 | 自定义标签可直接使用 |
| MoA 默认归属不变 | 多问题 6 臂仍需显式跨任务/跨批 | 使用 `--allow-cross-task --allow-cross-batch --expect 6` 或 `--auto-remediate` |
| 红队新增 10 个 schema | 无行为破坏 | 原有 6 站 schema 不变 |

## 9. 验证

- `ci_smoke`：**226 passed**
- `package-integrity`：`ok=True errors=0 warnings=3`
- `doc-align` 交叉引用：**PASS**
- `test_oss_scrub + test_pack_release + test_gk_package_integrity`：40 passed
- 红队链：**16/16 ok**
- 审计链：4/4 ok（审计面 17/21 matches，4 项不可复现已登记 finding）
- 6 臂 MoA：`reference_count=6`；自动补救 `before=1 → after=6`
- 导出：`SCRUB OK`（753 files / 988 excluded / 6 private blocks stripped）

## 10. 已知限制

- 决策模型端点未内置：未设 `GK_AUDIT_OUTCOME_ENDPOINT` 时只返回 advisory，
  不伪造 success/fail；当前主状态库有 224 条未决 raise。
- `paper-review` 仍为私仓能力，公开包不随附。
- 全平台支持（macOS 硬门、Windows 转硬门、GNU-only shim）仍在路线图，未在本版完成。
- 审计面 4 项不可复现（`subagent_reports` / `block_log` / `ecc_findings_closed_loop` /
  `ledger_conflicts`）为既有债务，本版未收敛。
- 早期审计报告已撤出公开包；如需对外展示审计证据，请重新生成报告。

## 11. 附件

- 发布包：`dist/zthl-aegis-v0.9.4.zip`
- SHA256：以 Release 附件/构建日志为准（确定性打包，同一提交可复算）。

# ZTHL Aegis v0.9.6.14

**发布日期**：2026-11-05 ｜ **类型**：维护版（内联载荷下沉 + 文档纠错 + 发布安全网）

## 亮点

- **内联载荷下沉**：`cmd_monitor` 的两类内联块（ECC 信封 / 311 行落库载荷）迁至独立模块，
  内联 Python 载荷计数 **96 → 88**；等价性由 `gk_monitor_fixture` 的 stdout + state 双产物
  对比（`equivalent=true`）守护。
- **发布预检安全网**：`gk_release_preflight` 五项机检（参数契约 / 资产四件套 / 文档事实块 /
  常驻功能覆盖 / 7 个发布资产），CI 与 release 两个 workflow 均接入。
- **文档纠错**：撤除两个从未并入主线却被登记为“已发布功能”的条目（状态 WAL、MCP 加载器），
  常驻功能覆盖从 23 项校正为 **18 项**；Super-agent 对照按一手材料重写。

## 变更明细

### 代码

- 新增 `scripts/gk_monitor_payload.py`（311 行落库载荷逐字搬运）、`gk_monitor_envelope.py`、
  `gk_monitor_fixture.py`（build/extract/run/compare/selfcheck）。
- 新增 `scripts/gk_budget_snap.py`、`gk_key_meta.py`（编辑预算快照 / 密钥元数据与指纹校验）。
- `state_lock` 的取锁预算可由 `GK_STATE_LOCK_TIMEOUT` 注入（非法值回落 5s；不允许用 env 关闭超时）。

### 文档

- 插件段新增「源码仓库」列，并把公开面口径改为「只自带 1 个加载器」；`git-workflow` 与
  `paper-review` 一样改为**载体缺失即不登记**。
- 新增「单人部署形态：不假装存在第二个机构」，与 **OPCAP（人轴）** 组成「形态 + 度量」两半论证。
- `credit-economy.md` 新增 §0「为什么要显式建模」：表外负债 ↔ 隐式状态、化债 ↔ 显式账本。
- `superagent-comparison.md` 按 `dsh-superagent-prototype` 一手材料重写（五原语 / Mandate /
  accept mode / attention budget / 30 分钟上限 / OS 用户全权），并附**更正记录**说明上一版三处错误。
- `flows-a-b-c.md` 撤除；`game-path-audit.md` 打退役标记并留在私仓、不随包导出；
  `ecc-impact-v7.md` 移出公开面。`doc_align` 新增 `retired_doc_export` 项守这条。

### 发布面

- 7 个资产：源码包、`SHA256SUMS`、`manifest.json`、`PROVENANCE.json`、`SBOM.cdx.json`、
  两份额外基准。
- 公开树由 `oss_scrub export` 机检生成（去标识 + 白名单 + 反向检索），本次同时清理了
  历史遗留的 `__pycache__` 与已不在源码树的旧脚本。

## 升级说明

- 命令与 state 契约不变；`migrate` / `plugin` / `audit` 等入口行为不变。
- 若你此前依赖 `gk_mcp_loader` 或 `gk_state_wal`：它们**从未随主线发布**（本次只是撤掉
  文档中的误登记），工具面拦截仍由写面 / 出网 / 工具面三道闸承担。

## 配套

- `zthl-bashpy-migrate` **0.4.0**：`verify` 支持产物对比（归一化器按 `module:function` 注入）、
  `audit` 支持挂载仓库级断言（`--mount`，以退出码为准）。

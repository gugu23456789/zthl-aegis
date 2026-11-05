# ZTHL Aegis v0.9.6.14

**发布日期**：2026-11-05 ｜ **类型**：维护版（内联载荷下沉 + 文档纠错 + 发布安全网）

## 亮点

- **内联载荷下沉**：`cmd_monitor` 的两类内联块（ECC 信封 / 311 行落库载荷）迁至独立模块，
  内联 Python 载荷计数 **96 → 88**；等价性由 `gk_monitor_fixture` 的 stdout + state 双产物
  对比（`equivalent=true`）守护。
- **发布预检安全网**：`gk_release_preflight` 五项机检（参数契约 / 资产四件套 / 文档事实块 /
  常驻功能覆盖 / 7 个发布资产），CI 与 release 两个 workflow 均接入。
- **MCP 加载器回归主线并升级**：`gk_mcp_loader` 补回源码，且改为**按符号面探测**适配不同
  MCP SDK 版本（不按版本号猜）；`list_tools()` 的五类载荷（对象 / 字典 / `{"tools":…}` /
  分页 / pydantic `ListToolsResult`）统一归一，入口 `verify` / `connect` / `health-only` / `sdk-info`。
- **文档纠错**：上一版把两个**实际存在于主线**的机制误判为“未实现”并撤除登记——状态 WAL 在
  `gk_satellite`（分片 append + 索引叶），MCP 写面闸在 `pre_tool_hook`（`MCP_WRITE_VERBS`）；
  常驻功能覆盖回到 **21 项**；Super-agent 对照按一手材料重写。

## 变更明细

### 代码

- 新增 `scripts/gk_monitor_payload.py`（311 行落库载荷逐字搬运）、`gk_monitor_envelope.py`、
  `gk_monitor_fixture.py`（build/extract/run/compare/selfcheck）。
- 新增 `scripts/gk_budget_snap.py`、`gk_key_meta.py`（编辑预算快照 / 密钥元数据与指纹校验）。
- 补回 `scripts/gk_mcp_loader.py` + `scripts/test_gk_mcp_loader.py`（30 条臂）：修掉对已下线
  `BROWSER_*` 常量的导入；`sdk-info` 探测 `ClientSession`/`stdio_client`/`sse_client`/`FastMCP`/`Tool`
  的实际可解析面；`connect --tools` 支持离线核对（`--tools` 仅限 connect，避免承诺面恒假红）。
- 修 `test_gk_monitor_decision` 的陈旧断言：`monitor_last` 已随载荷下沉迁入 `gk_monitor_payload.py`，
  改为「CLI 判后端接线 / 载荷模块判留痕」，CI 快速门恢复。
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
- `gk_mcp_loader` 本轮回归主线，但**仍是独立脚本**（`python3 scripts/gk_mcp_loader.py <cmd>`）：
  `_CMD_REG` 在受保护区，不新增 `mcp` 子命令；hook 侧消费点属后续工作。
- 早期名字 `gk_state_wal` 并未单独成文件——状态 WAL 实际由 `gk_satellite` 承担。

## 配套

- `zthl-bashpy-migrate` **0.4.0**：`verify` 支持产物对比（归一化器按 `module:function` 注入）、
  `audit` 支持挂载仓库级断言（`--mount`，以退出码为准）。

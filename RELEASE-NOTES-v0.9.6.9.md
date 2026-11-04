# v0.9.6.9 发布说明

本版是**路由一致性 + 导出面**修复，外加自述文档补齐；运行契约向后兼容，无新增外部依赖。

## 路由一致性（本版重点）

- **显式 `STATE_FILE` 与计划声明域冲突改为 fail-closed**（`STATE_DOMAIN_EXPLICIT_CONFLICT`）：
  此前域解析（1b）不区分显式注入态，启动块又无条件采用 `source=state_domain` 的结果
  ⟹ 显式指定的 state 被静默替换成域 state（实测：wtA 的写面被判到 wtB），且无任何 WARN。
  现语义：同路径幂等放行；不同路径报错并由 error 通道停机。`discover --plan` 的域解析基址
  在显式态下改用 `$STATE_FILE`，两处 `resolve-state` 补传 `STATE_FILE_EXPLICIT`，与 discover
  既有的 `STATE_DOMAIN_EXPLICIT_CONFLICT` 口径对齐。
- **双形态路径（方案 C）**：路由中枢与写面判定对 `C:\x` ↔ `/mnt/c/x` 做等价比较，
  不再把任一侧写成唯一合法形态（跨 WSL / 原生 Windows 调用不再互相阻断）。
- **内联载荷棘轮**：`gk_bomb_inventory --public-baseline` 冻结时把 `file` 相对化，
  公开面基线不再携带本机绝对路径。

## 安全

- **Gate R0.20（非交互凭据闸）**：`git push` 走 https remote 且命令内未声明
  `GIT_TERMINAL_PROMPT=0`、或 host 属易弹窗名单（atomgit.com）时直接拦停，
  避免 agent 触发宿主登录弹窗；`GK_ALLOW_INTERACTIVE_GIT=1` 显式放行。

## CI / 供应链

- `release.yml` 恢复完整链路：SBOM、PROVENANCE、doc-coverage、archive preflight、bench，
  修正上一版缺 SBOM/PROVENANCE 资产的问题。

## 自述文档

- 新增 `references/credit-economy.md`：信用分 / 额度银行正本 —— 载体与封印、非对称定价、
  与 ECC-FINDING 的"禁计价"边界、分权矩阵、失败模式、"已落刀 / 默认关执行档"，
  以及三张闭环图（三角内循环 / 提额全生命周期 / finding 多来源闭环）。
- 架构自述（`references/architecture-overview.md`）新增压缩版经济回路图 + references 文件地图登记。
- README / README.en：经济行补 `gk_credit_ledger` 与正本链接；常驻功能表新增"信用分账本"。
- README / SECURITY：用途与负责任使用边界声明。
- `references/resident-features.json` 登记信用分账本与 finding 禁计价边界，纳入发布门覆盖检查。

## 导出面

- 新增排除：`moa-6arm-rerun.html` / `moa-after.html`（含真实批次数据与 κ 记号，
  与 `moa-chain-*.html` 同族运行档案）；`dist/`（构建产物，可由 CI 重建）。
- 本版导出：794 files / 1054 excluded / 6 private blocks stripped；`SCRUB OK`。

## 已知限制

- 排除面能力（`phase-probe`、`paper-review`）在公开包**不可用**，属发布面设计而非缺陷。
- 信用分默认**只读观测**：N 门默认 advisory（`GK_CREDIT_FLOOR_ENFORCE=1` 才阻断）；
  outcome 后端需显式配置（`GK_AUDIT_OUTCOME_ENDPOINT`），未配置只返回 advisory。

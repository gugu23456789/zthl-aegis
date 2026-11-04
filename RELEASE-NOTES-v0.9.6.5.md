# v0.9.6.5 发布说明

本版修复 Zenodo 自动归档的三处缺陷，并补上手动静默重试用工作流；不改变运行时契约。

## 自动归档修复

- **空日期 400**：旧记录携带 `dates: [{"type":"issued","date":""}]`，整体回写元数据时 Zenodo 报
  `metadata.dates: Invalid date provided.`。现逐项过滤空 `date` 条目（全空则删键）。
- **残留草稿**：上次失败会留下未发布的草稿，再次 `newversion` 被
  `files.enabled: Please remove all files first` 拒绝。现先按 `links.latest_draft` 定位，
  取不到再按 `conceptrecid` 检索 state≠`done` 的草稿并复用。
- **元数据继承错误**：新版本标题会继承上一版（实测仍写 `ZTHL Aegis v0.9.6.2`），
  许可证被落成默认 `cc-by-4.0`。现由脚本确定性写入：
  - 标题 = `ZTHL Aegis <version>`；
  - 许可证 = `other-open`（Mulan PSL v2 不在 Zenodo 内置列表），并在描述末尾追加
    「许可：Mulan Permissive Software License v2（https://license.coscl.org.cn/MulanPSL2）」，
    幂等（已含 `MulanPSL2` 则不重复追加）。

## 新增

- `.github/workflows/zenodo-archive.yml`：`workflow_dispatch` 手动补档/重试，输入已存在的 tag，
  下载该 Release 的 5 个附件后重跑归档；失败直接可见（不 `continue-on-error`）。
- 单测扩到 7 臂：跳过 / 缺附件 / 全流程 / newversion 失败 / dry-run / 复用草稿 / 按 concept 检索草稿。

## 已知限制

- 已发布的旧记录（如 v0.9.6.4 → `23935725`）的标题与许可需在 Zenodo 页面手动修正一次；
  本脚本只创建新版本，不回改历史记录。
- 自动归档依赖仓库 secret（`ZTHL` → 环境变量 `ZENODO_TOKEN`），scope 需含
  `deposit:write` 与 `deposit:actions`。
- 公开包只包含 `references/` 子集，`docs/` 与部分内部文档不随包导出；发布门按此口径豁免。

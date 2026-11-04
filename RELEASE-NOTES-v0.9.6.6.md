# v0.9.6.6 发布说明

本版只修 Zenodo 归档的草稿判据，不改变运行时契约。

## 修复

- `gk_zenodo_sync.py` 的草稿识别此前用「`state != done`」：`conceptrecid` 检索返回的条目**可能
  不带 `state` 字段**，导致把**已发布记录**当成草稿，上传时报
  `403 Bucket is locked for modifications.`（v0.9.6.5 的 release 归档即因此失败）。
- 现改为保守判据：草稿必须显式是未发布态（`submitted=false`，或 `state` ∈
  `{unsubmitted, inprogress}`），且**永不等于记录本身**；主流程再加一道硬保护。
- 单测补到 8 臂（新增「无 state 的已发布记录不得当草稿」）。

## 说明

- 归档失败不会阻断发版（`continue-on-error`），补档用
  `zenodo-archive` 工作流（`workflow_dispatch`，输入已存在的 tag），无需重发版本。

## 已知限制

- Zenodo 历史记录 `23935725`（对应 v0.9.6.4）的标题与许可仍是旧值，需在页面手动修正；
  脚本只创建新版本，不回改历史记录。
- 公开包只包含 `references/` 子集，`docs/` 与部分内部文档不随包导出；发布门按此口径豁免。

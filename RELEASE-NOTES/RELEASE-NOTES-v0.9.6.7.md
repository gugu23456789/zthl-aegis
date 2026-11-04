# v0.9.6.7 发布说明

本版把存档校验接入 CI 与发包预检，并取消归档步骤的失败吞没；不改变运行时契约。

## CI / 发包预检

- `gk_zenodo_sync.py` 新增 `--check-archive`：**离线**校验 `references/archive.json`
  （`schema == gk-archive-meta/1`、`concept_doi` 形如 `10.5281/zenodo.<digits>`、
  `zenodo_record` 空或纯数字、`swhid` 为字符串）。
- `ci.yml`：smoke job 增加该离线校验（阻断、确定性，不依赖网络）。
- `release.yml`：pack 之前新增 **archive preflight**（阻断）——先离线校验，再用
  `--dry-run` 解析 Concept DOI 到 Zenodo 最新记录；解析不到就不发包。
- `--dry-run` 允许 `dist` 尚未产出（预检阶段），只报告 `missing`；真跑仍严格要求 5 个附件。

## 取消失败吞没

- 移除 `archive to Zenodo` 步骤的 `continue-on-error: true`。依据
  `references/ci-pipeline-template.md` §7.1/§8：吞失败 = 假绿 = 无防御
  （v0.9.6.5 的 `403 Bucket is locked` 即因此被隐藏）。
- 未配置 token 时脚本仍以 `skipped` 退出 0（配置态，不是失败）。

## 文档

- `references/ci-pipeline-template.md` §5 新增「外部存档预检」条目，含本次假绿教训。

## 已知限制

- Zenodo 历史记录 `23935725`（v0.9.6.4）标题/许可仍是旧值，需手动修正；脚本不回改历史记录。
- 归档失败会让 release job 变红，`sync-main` 随之跳过——需用 `zenodo-archive` 工作流补档后再对齐。

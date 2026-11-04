# v0.9.6.1 发布说明

本版是 v0.9.6 的维护补丁：把本地快照回收工具纳入发布面，不改变运行时契约。

## 新增

- `scripts/gk_snapshot_gc.py`：回收发布链在本地产出的整树快照
  （`zthl-public-snapshot-<日期>-v<N>`，约 30 MB/份）。
  - 只处理 `--root` 下以 `--prefix` 开头的目录；
  - 永远保留按 mtime 最新的 `--keep` 份（默认 2）；
  - 其余仅在 mtime 早于 `--min-age-days`（默认 7 天）时才删；
  - **默认 dry-run**，加 `--apply` 才真删；输出 JSON，退出码 0（正常）/ 2（参数或根目录非法）。
- `scripts/test_gk_snapshot_gc.py`：5 条用例（保留最新、年龄阈值、keep 保护、坏 root、非匹配目录不动），
  已并入 `scripts/ci_smoke.sh` 的 fast pytest 列表。

## 说明

- 本地自动回收由维护者的 `git-workflow push` 钩子驱动（当前仓存在该脚本时执行，失败只告警不阻断推送），
  不进入 CI —— 快照只存在于维护者本机。
- 发布面门禁、PROVENANCE / SBOM / attestation 口径与 v0.9.6 一致，无变化。

## 已知限制

- 公开包只包含 `references/` 子集，`docs/` 与部分内部文档不随包导出；发布门按此口径豁免。
- 旧指纹下标定的 `S`（相位步长）仍需在线上指纹上重探；探针不可解时返回 `resolved=false`。

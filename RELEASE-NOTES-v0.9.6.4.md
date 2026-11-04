# v0.9.6.4 发布说明

本版把 Zenodo 归档自动化，并修正自述文档中的元数据路由 DAG；不改变运行时契约。

## 存档自动化

- 新增 `scripts/gk_zenodo_sync.py`（纯标准库）：Release 发布后自动在 Zenodo 建新版本 ——
  解析最新 record → `newversion` → 清掉继承的旧文件 → 上传同一组 5 个附件 → 更新
  `version`/`publication_date` → `publish`。Concept DOI 因此始终指向最新版本。
- `release.yml` 新增 `archive to Zenodo` 步骤（`continue-on-error`）：未配置 token 时脚本
  自行跳过，存档失败不阻断发版。Concept recid 从 `references/archive.json` 的 Concept DOI 解析。
- 单测 `scripts/test_gk_zenodo_sync.py`（5 臂：跳过 / 缺附件 / 全流程 / newversion 失败 / dry-run），
  已并入 `ci_smoke.sh`；`resident-features.json` 相应登记 `zenodo-sync`。

## 文档修正

- README 新增「存档与引用」：Concept DOI 以可点击链接直接渲染，附引用格式。
- README「元数据路由（DAG）」按 S3 后的真实写路径重画：删除不存在的
  `侧车 → 热叶/manifest`、`热叶 → state`、`压缩器 → manifest 交换` 三条边，
  补上 `写者 → claim 台账` 与 `GC → 侧车/state` 的实际边；`references/state-storage.md`
  同步改为「内联 ∪ 冷侧车，GC 是唯一索引删除者」。

## 已知限制

- 自动归档依赖仓库 secret（`ZTHL` → 环境变量 `ZENODO_TOKEN`），scope 需含
  `deposit:write` 与 `deposit:actions`；token 失效时该步只记录失败，不阻断发版。
- 公开包只包含 `references/` 子集，`docs/` 与部分内部文档不随包导出；发布门按此口径豁免。

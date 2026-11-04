# v0.9.6.2 发布说明

本版是 v0.9.6.1 的发布链补丁：`main` 与最新 tag 自动对齐，不改变运行时契约。

## 新增

- `release.yml` 增加 `sync-main` 作业（`needs: release`，`contents: write`）：
  - tag 比 `main` 新（tag 打在侧支或游离提交上）⟹ **快进** `main` 到该 tag；
  - `main` 比 tag 新（发布后又有提交）⟹ 只写 job summary 告警，不改写历史；
  - 两者已分叉 ⟹ 作业失败，交人工处理。
  - 结果写入 GitHub Actions job summary，发布记录即可看到同步状态。

## 说明

- `GITHUB_TOKEN` 推送 `main` 不会触发其他 workflow；快进目标是 tag 提交本身，
  其 CI 已在 tag 上执行过，无需重跑。
- 打包内容、PROVENANCE / SBOM / attestation 口径与 v0.9.6.1 一致，无变化。

## 已知限制

- `sync-main` 只能把 `main` 前移到已在 tag 上的提交；“main 领先 tag”仍需人工决定是否发版。
- 公开包只包含 `references/` 子集，`docs/` 与部分内部文档不随包导出；发布门按此口径豁免。

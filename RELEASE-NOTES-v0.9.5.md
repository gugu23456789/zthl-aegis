# v0.9.5 发布说明

本版主线：把 state 写路径从 O(S) 降到 O(delta)，并补齐发布链的来源可核验性。

## 性能（S1–S4）

- **WAL + checkpoint**：`scripts/gk_state_wal.py` 接管写路径，读序 WAL → state；每 200 条或 1 MB
  触发 checkpoint，进程退出 flush，尾部坏行可修复。写放大从 128–512x 降到 < 1.3。
- **行星写面收口（S3）**：卫星 `append` 停更内联热索引（`INLINE_INDEX_WRITES=False`），读面
  `index_entries` 为「内联 ∪ 冷侧车」并集；batch=1 写放大 252.8x → 1.61x。
- **gate 写面收口（S4）**：`set_nested` 改走 WAL，新增 `set_nested_batch`（一轮多叶 = 一条 WAL
  记录，非法叶整批零写）；`set_nested` 1975x → 1.35x，`update_gate_data` 1230x → 1.42x。

## 基准与门禁（S5）

- 新增 `gk_bench_compare.py`：版本基线对比（容差 1.25）；失败写、崩溃校验、`.tmp` 残留为硬红，
  发布门 wall 默认 WARN。
- `references/bench-baseline.json` 为滚动基线；`ci.yml` 增加 `bench-quick`，新增 `bench-nightly.yml`。

## 来源与可核验性

- 包内新增 `PROVENANCE.json`（source repo/commit/tag、导出策略与工具 sha256、排除面），并被
  `SHA256SUMS` 覆盖；`release-manifest.json` 增加 `source` / `export` / `provenance_sha256`。
- 新增 CycloneDX 1.5 `SBOM.cdx.json`；构建走 Sigstore attestation（SLSA provenance）。
- 新增根目录 `PROVENANCE.md`：核验顺序、两种 DOI（Concept/Version）口径、SWH/Zenodo 存档说明。

## 开源面

- 公开：`gk_phase_stats.py`（相位统计核心）、`gk_model_probe.py`（通用指纹/S 解析器）、
  `references/oss-hooks.md`、`references/oss-moa-phase-provenance.md`。
- 闭源（不随包）：臂设计、仿真与 runner；`gk_crossfull_two_phase.py` 及其测试已从公开面移除。

## 已知限制

- `system_fingerprint` 换代后旧 `S=2` 取证失效，探针按契约返回 `resolved=false`；下游继续按
  unadjusted，不套用旧 S。
- 公开树只导出 `references/` 子集，`doc-release --strict` 在公开面会报「文件缺失」，发布门仅记录不阻断。

# v0.9.6.12 发布说明

本版把「只有推 tag 才会暴露的跨文件契约漂移」前移到**日常 CI**，并把发布资产固定为 **7 个**。
运行契约无其它变更。

## 发布预检安全网（本版重点）

新增 `scripts/gk_release_preflight.py`，在**打包前**执行五项 fail-loud 判据：

1. **参数契约**：workflow 中 `pack_release.py` 用到的 flag ⊆ 脚本 parser
   （v0.9.6.8–v0.9.6.10 连续三版即败在这里：传了 `--source-*` 而脚本不认）；
2. **产物契约**：夹具真跑一次打包，必须产出 zip / SHA256SUMS / release-manifest.json /
   PROVENANCE.json 四件套，且 `PROVENANCE.source`（repo/commit/tag）可核；
3. **事实块**：`gk_docgen_facts.py check` 必须 PASS；
4. **覆盖门**：常驻功能自述覆盖（`gk_doc_features.py --skip-facts`）；
5. **资产契约**：publish 步必须挂载 7 个资产。

接线：
- `.github/workflows/ci.yml` 新增 `preflight` job ⟹ push/PR 阶段就红，不必等到发版；
- `.github/workflows/release.yml` 在 pack 之前增加同名预检步。

## 发布资产：5 → 7

- 核心 5：zip、`SHA256SUMS`、`PROVENANCE.json`、`SBOM.cdx.json`、`release-manifest.json`
- 基准 2：`dist/bench/release.json`、`dist/bench/release-compare.json`
- 基准步仍为 `continue-on-error`（CI 抖动大）；文件缺失时降级为 5 个，但**挂载点必须存在**，
  禁止静默缺项（发布前由预检第 5 项断言）。

## CI 模版

- §5 新增「发布流水线契约预检」「导出期文档自洽」两节；
- §8 新增红线：workflow ↔ 脚本参数契约不得靠人记，必须做成打包前机检。

## 验证

- 本地 `gk_release_preflight.py`：5/5 PASS；
- `test_gk_release_preflight.py` + `test_pack_release.py`：13 passed（新增 5 臂）。

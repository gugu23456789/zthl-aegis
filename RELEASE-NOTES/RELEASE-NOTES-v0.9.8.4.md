# ZTHL Aegis v0.9.8.4 — 发布说明

> 2026-11-08。本版是 v0.9.8.3 发布前的**最后一条既有债修复**：`ci_smoke.sh` 快速门在公开树
> 跑出 `test_gk_ecc_sink.py` 2 条红（`KeyError: 'satellite_index'`）。
> 代码功能与 v0.9.8.3 相同，本版只修测试口径；与 v0.9.8.3 一并发布。

## 1. 为什么发这个补丁

`gk_satellite` 的 **S3 写侧**（早于本次合并）已改为「只落片 + 侧车，停写内联热索引」：
`append()` 返回 `inline_skipped: true`，reason「S3: 写侧只落片 + 侧车（内联热索引停写）」。
索引唯一落点因此是 `<state>.satellite-index.jsonl` 侧车（读面由 `gk_satellite` 合并侧车兜住）。

`test_gk_satellite.py` 早已按 S3 更新（3 条 `inline_skipped` 断言），但
**`test_gk_ecc_sink.py` 漏改**，仍在断言 `gate_data.satellite_index` ⟹ 恒 `KeyError`。
这是合并前就存在的既有红，`--changed` 定向验收未覆盖到；本次公开 CI 复验把它暴露出来。

## 2. 变更

- `scripts/test_gk_ecc_sink.py`：新增 `_sidecar_entries(st)` 解析侧车，
  两处断言（单臂叶子、同批双臂互不覆盖）从「查内联 state 键」改为「查侧车条目」。
  **断言强度不降**：仍验证「索引真实落盘 + per-arm 不覆盖 + 叶子字段（kind/records）」。

## 3. 验证

- `scripts/test_gk_ecc_sink.py`：8 passed。
- 私仓 `gk_release_preflight.py`：8/8 PASS。
- 公开树复验（v0.9.8.3 内容 + 本补丁）：`gk_release_preflight.py` 8/8 PASS；
  `ci_smoke.sh` 全绿（含 `(skip: not in this tree)` 显式列出私仓专属测试）。

## 4. 与 v0.9.8.3 的关系

两版可视为同一次发布：v0.9.8.3 修「导出树自洽 + 快速门适配导出面」，
v0.9.8.4 修「快速门内的既有测试口径债」。对外建议直接使用 v0.9.8.4。

# v0.9.8 — 人评结构锚 + p_meta 冻结 + MoA 链路修正 + 相关性基准

## 人评优化

- **结构锚**：人评散文默认要求可回查的证据形态 —— `path:line`（支持行号区间与 Windows 路径）、
  `SOURCES:` 段，或真实存在的 `ECC-*` finding id；落 `evidence:strong|weak` facet。
- **ECC 身份锚**：引用台账内**真实存在**的 finding id 可替代 token 重叠；id 须经已知集合校验，
  伪造 id 不放行。
- 基准实测：共享词汇的赞美/提问/反对类硬负例误放 **4 → 0**，正例误拒 **0**。

## MoA 链路参数修正

- `moa-aggregate --chain --out` 现正确透传，链式运行可产出 Markdown 聚合报告。
- 移除现场代理量（投毒词命中率 / 人机分差 / 缺陷产率）对 ledger κ 的覆盖；κ 只取实测通道，
  避免误折扣把一致度压到阈值以下导致弃权。
- `p_meta` 通道：人评 divergence 在 adjudicate 时**冻结**到批，跨批 ≥3 时取中位数参与折扣；
  单批只观测不扣分。

## 修复

- `tilt` / `tilt-state` / `p_meta` 纳入标量 facet 命名空间，消除同批重跑后新旧 tilt 并存。
- `_state_write` 增加写后回读校验：落盘不一致时写 `<state>.write-error` 并返回 rc=3，
  不再静默丢写。

## Benchmark

- 新增 `scripts/gk_bench_relevance.py`：40+ 人评样本、8 类（含良性硬负例与多种攻击形态）、
  4 个判决臂、τ 扫描，输出 `core` 与 `known_gap` 分账。
- 结论：tokenizer 子词、BM25+、BM25F 在本闸门上无收益（tokenizer 误放 24，BM25 变体无 τ
  可清零），生产保持 4-gram + 结构锚。

## CI

- `bench-nightly` 取消定时触发，full 基准改为本地运行；保留手动入口供发版前复核。

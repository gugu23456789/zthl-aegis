# v0.9.6.10 发布说明

本版把「每次发版都要手工改自述文档」的返工消灭掉；其余为导出面收尾。运行契约零变更。

## 导出管道自动化（本版重点）

- `oss_scrub.py export` 收尾会在**导出树内**执行 `gk_docgen_facts.py --write`：
  `GK-FACTS` / `GK-REFS` 按**发布集**重生成；脚本不在导出面时 `DOCFACTS SKIP`，
  执行失败则 **fail-loud 退出 1**（不允许把漂移块发出去）。
- `gk_docgen_facts.py`：`references/*.md` 清单由「只认 git 索引」改为
  **git 优先、无 git 按目录回退**。原实现在导出树（非 git 仓库）返回空 ⟹
  README 索引被清空（实测少 59 行）。
- 效果：本次发版**无需在目标仓手工 `--write`**；同一导出树同步到公开仓后
  事实块字节级一致（references 计数 28 = 28）。

## 导出面收尾

- 回灌两份**公开面自有**文档（`oss-hooks.md`、`oss-moa-phase-provenance.md`）到私仓超集，
  统一 references 计数；架构文件地图补齐两条；provenance 的 κ 记号按 MoA 同族豁免。
- 新增排除：`moa-6arm-rerun.html` / `moa-after.html`（含真实批次数据与 κ 记号）、
  `dist/`（构建产物，可重建）。本版导出：796 files / 1054 excluded / 6 private blocks stripped。

## 已知限制

- `oss_scrub.py`（含反查词表）本身不进公开包 ⟹「导出期自动重生成」只在私仓发布流程生效；
  公开仓侧的 `gk_docgen_facts.py` 已含目录回退，行为一致。
- 信用分默认**只读观测**：N 门默认 advisory（`GK_CREDIT_FLOOR_ENFORCE=1` 才阻断）。

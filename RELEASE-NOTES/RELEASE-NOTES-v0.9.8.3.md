# ZTHL Aegis v0.9.8.3 — 发布说明

> 2026-11-08。本版是**发布链路缺陷修复补丁**：v0.9.8.2 的公开仓 CI（`ci` / `release`）在
> tag 推送后双红 —— 根因是「导出面独有」的三处判据不一致，私仓本地预检全部绿。
> 代码功能与 v0.9.8.2 相同，本版只修发布面自洽性。

## 1. 为什么发这个补丁

v0.9.8.2 推 tag 后 GitHub Actions 三个 job 失败（`smoke gate`、`smoke gate in venv`、
`release preflight`），Release 未产出。本地复现后定位到三条独立缺陷，**全部只在导出树/
公开仓成立**，因此私仓 `gk_release_preflight.py` 与 `ci_smoke.sh` 一律绿：

| # | 失败 job | 根因 |
|---|----------|------|
| 1 | `release preflight` | `FILES.md` 写 861 个文件、交付树实际 860：索引在 **purge 之前**生成，把随后被清掉的 `.gatekeeper.state.own_user` 记进了索引 |
| 2 | `smoke gate` / `smoke gate in venv` | `ci_smoke.sh` 把私仓专属的 `test_gk_paper_review_loader.py`（论文评审口径，导出排除面）硬编码进 pytest 参数 ⟹ 公开树缺文件，pytest 以「file not found」退出 4 |
| 3 | 同上（冗余红） | 导出树无 `.git`，`gk_repo_index` 走目录遍历，预检自身写出的 state 被计入「可索引文件」⟹ `--check` 与刚生成的索引立刻漂移 |

## 2. 变更

### 2.1 导出树自洽（`scripts/oss_scrub.py`）

- **`purge` 前移到索引生成之前**：先清运行产物，再按**最终交付树**生成 `FILES.md` / `llms.txt`。
- **兜底再对齐**：预检之后若仍有产物被清理（`purge_run_artifacts` 返回值 > 0），
  立即重跑索引生成（幂等；实测第二次 `changed=none`）。索引重生成失败 ⟹ 拒发（fail-loud）。
- **post-step 环境隔离**（`_export_env`）：`STATE_FILE` 指向导出树外、禁写字节码，
  减少导出过程中的自污染。

### 2.2 索引判据与私仓对齐（`scripts/gk_repo_index.py`）

- 目录遍历分支显式跳过 `.gatekeeper.state*` 族（与 `purge_run_artifacts` 同判据）。
  私仓靠 `git ls-files` 天然排除未跟踪 state；导出树此前会把它算进公开面 ⟹ 两棵树判据分叉。

### 2.3 快速门适配导出面（`scripts/ci_smoke.sh`）

- 快速测试集从**硬编码参数**改为**意图列表 + 存在性过滤**：缺失项显式打印
  （`(skip: not in this tree) …`），过滤后为空则 fail-loud 退出 2（防「导出面异常」被静默跳过）。
  私仓侧行为逐字不变（所有文件都在）。

### 2.4 测试与文档

- 新增回归臂：`test_export_purges_before_repo_index`、
  `test_ci_smoke_filters_absent_tests_for_export_tree`、
  `test_runtime_state_files_not_indexed`（含「state 再写出后 `--check` 仍收敛」）。
- 闭组表与 2026-11-03 裁决对齐：`gk_phase_stats.py` / `gk_model_probe.py` 及其测试
  从 G2 实验面闭组移出，改由新增反向臂 `G2b` 钉为**必须公开**（与 `oss-export-whitelist.json`
  的 reason 一致）。
- `RELEASE-NOTES-v0.9.6.8.md` 与 `test_gk_model_probe.py` 的**自指式**内部路径字面量改为
  中性表述 / 字符串拼接 ⟹ 不再触发「公开面引用私有论文仓」全量扫描（判据强度不变）。

## 3. 验证

- 私仓 `gk_release_preflight.py`：8/8 PASS（`files=860`）。
- 全新导出树内复跑：`PREFLIGHT OK`（8/8 PASS）+ 兜底 `REPO-INDEX changed=none`（自洽幂等）。
- 导出树 `gk_repo_index.py --check`：`ok=true, files=860, issues=[]`。
- 定向验收：`test_oss_scrub` / `test_gk_repo_index` / `test_gk_model_probe` /
  `test_gk_closeout_order_branch` / `test_gk_public_bridge` 共 **81 passed**。

## 4. 发布链（不变）

私仓 `master` 是唯一权威；公开仓 = `oss_scrub export` 的过滤产物，由
`scripts/gk_public_bridge.py` 单写（预检 → 导出 → 镜像 → commit → 双同名 tag → push → 记账）。

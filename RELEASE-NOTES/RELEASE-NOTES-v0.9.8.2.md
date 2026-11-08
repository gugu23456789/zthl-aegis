# ZTHL Aegis v0.9.8.2 — 发布说明

> 2026-11-08。本版是**发布链路治理 + 回收通道补全**：私仓正式确立为唯一权威，
> 公开仓改由单向发布桥从 `oss_scrub export` 的过滤快照生成，两仓 tag 首次同名双打。

## 1. 变更

### 1.1 发布链路（新增）

- **`scripts/gk_public_bridge.py`**：私仓 → 公开仓单向桥。一条命令完成
  `发布预检 → oss_scrub 过滤导出 → 整树镜像 → 公开仓 commit → 双 annotated tag →
  push（永不 force）→ release-line 记账`。
  - 缺省 **dry-run**，`--apply` 才落刀；`--no-push` 可只做本地提交与打 tag。
  - 安全闸：版本已存在、公开工作副本脏、公开非 `main`、私仓非 clean `master`、
    远端不在白名单、预检/导出失败、导出 0 文件 ⟹ 一律拒（零写）。
  - `docs/oss/release-line.json` 记录 `版本 ↔ 私仓 commit ↔ 公开 commit ↔ 导出文件数`；
    `docs/` 在导出排除面内 ⟹ 账本仅存私仓。
- **`gk_public_bridge.py audit`**：双仓 tag 对账，输出 `IN_SYNC / DRIFT` 与差异清单。

### 1.2 回收通道（补全）

- **`apply-worktree --reclaim --all-branches`**：新增游离分支回收面。判据 fail-closed：
  已并入基线 HEAD（`merge-base --is-ancestor`）**或**全部提交 patch 等价（`git cherry`）；
  未满足者保留并列入 `loose_branch_guarded`。检出中的分支与 `master/main` 永不删。
- **`--path` 可重复**：多棵 worktree 可一次指名（原 CLI 为单值，后一条静默覆盖前一条）。
- **`--reclaim --branches` 多 flag 形态修复**：第二解析循环与 usage 补登记。

### 1.3 门禁（扩展）

- **Gate R0.17 覆盖回收侧**：裸 `git worktree remove|prune`、`git branch -d|-D` 一律拦，
  统一指向 `apply-worktree --reclaim --path <dir> --branches` 标准通道。

### 1.4 主线合并

- 并入 `agent/perf-m1-wal` 历史分支：bench nightly workflow、`gk_phase_stats.py`、
  `gk_state_wal.py`（旧实现归档）、`PROVENANCE.md` 与对应测试；冲突文件取私仓已发布版，
  `gk_json_utils.py` 保留 WAL 接线（`scripts/test_gk_state_wal.py` 12 passed）。
- 回收全仓已并入/等价分支 37 条、失效 worktree 2 棵（先归档后删）。

### 1.5 文档

- `SKILL.md` / `references/architecture-overview.md` 事实块与 `FILES.md` / `llms.txt`
  索引按活文件重生成（preflight `docgen` / `repo_index` 全绿）。

### 1.6 仓间权威对齐（一次性）

- 公开仓此前存在 18 份私仓缺失的发布说明（`v0.9.5`–`v0.9.8`）与 `.github/workflows/
  zenodo-archive.yml`（Zenodo 手动补档）。按「私仓唯一权威」原则**回收进私仓**
  （`cp -n`，不覆盖既有文件），此后由导出单向携带，公开仓不再保留无源文件。
- 公开仓残留的运行期产物（`.gatekeeper.state.*`、`.pytest_cache/`、`__pycache__/`）与
  已按白名单排除的脚本（`crossfull_two_phase`）在下次同步中清除。

## 2. 发布纪律（不变）

- 私仓 `master` 是唯一发布源；公开仓内容 = 导出快照，不允许反向回灌。
- 发版三步仍为：`gk_self_check.py`（full）→ `gk_release_preflight.py` →
  `oss_scrub.py export`（导出树内自动重跑预检）。

## 3. 验证

- `gk_release_preflight.py`：8/8 PASS（pack_contract、pack_fixture、docgen、doc_features、
  release_assets、workflow_paths、repo_index、vendor_artifact）。
- `test_gk_public_bridge.py` 10 passed；`test_gk_closeout_order_branch.py` 10 passed；
  `test_gk_worktree_reclaim*.py` + `test_gk_state_wal.py` 全绿。
- 公开仓 CI（`release.yml`）：tag push 后打包 7 资产并发布 Release。

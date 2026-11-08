# ZTHL Aegis v0.9.8.3 — 发布说明

> 2026-11-08。本版覆盖 **v0.9.8.1 之后的全部变更**（43 个 commit），并修复发布面缺陷。
> 说明由 `scripts/gk_release_notes.py` 从 git 历史生成草稿，再经两轮检测（发布面禁词 + 计划/实现
> 混淆；语句与事实核对）后人工定稿。

## 1. 门禁与钩子（已落地）

| 变更 | 行为 |
|---|---|
| hook 存活检测 | `self-check` 新增一项：`hooks.json` 注册态 + `.gatekeeper.hook.log` 最近的 `INVOKE event=PreToolUse` + 宿主开机时间，三面比对；不存活则 WARN 并提示去 Trae Settings → Hooks 开启（"注册 ≠ 被执行"） |
| 主树只读闸 | 编辑类工具落点在**主检出根** ⟹ `MAIN_TREE_READONLY` 直接 BLOCK；先于 state 解析执行，补 Gate 3 在"无活动 worktree 时活动面=主树"的缺口 |
| worktree 生命周期单一入口 | R0.17 由"建树/搬树"扩到**回收侧**：裸 `git worktree remove\|prune`、`git branch -d\|-D` 一律 BLOCK，改走 `apply-worktree --reclaim` |
| 就近 state 认领 | 要求目标含 `stage`：缺 stage 的 finding 副产物不再误拦 home 目录编辑 |
| 主仓守卫 | 空模式不得 match-all（B1），并补环境无关测试 |

`references/oss-hooks.md` 已同步上述三条（R0.17 回收侧、主树只读闸、存活核验）。

## 2. 子代理（已落地）

- 新增 **research-408** 报告角色：按 `references/research-408.md` 的四轴 + 八段组织文字报告，
  只读 evidence；联网须 `--web` **逐次显式授权**，角色/档位只给能力上限。
- 角色白名单改读 `subagent_runner.ROLE_TOOLS` **单源**（去双源），`--web` 贯通派发。
- 准入接 408 帧判定（`generic` 场景 fail-loud，不静默降级）。
- 事实块「子代理角色 = 9」由 docgen 自动生成，已含 research-408；`references/README.md` 已登记该文档。

## 3. MoA 与收敛（已落地）

- `NO_CONVERGENCE` 信号可见化；`switch_to=M` 时补 M 项。
- 批 → state 自动解析 + 平台自适应打开器。
- 人评输入框去掉测试示例句，改中性格式提示。
- 收敛判据正本 `references/convergence-evaluator.md` 的 C2 行（连续 K 轮 `r̂ ≥ r_min` ⟹ 早停转 M）
  与实现一致，无漂移。

## 4. 修复

- **熵门 B3**：ECO 分支只统计 ECO 域记录，ECC 校准不再污染熵值。
- **crossfull L6**：以 JSON `ok` 为准，rc 仅记诊断；多行 JSON 解析修复；T* 未冻按正本降为 warn。
- **bench 口径**：写放大拆为 `amp/payload` 与 `amp/state` 两个可解释指标；崩溃注入覆盖 512KB。
- **apply-worktree**：`--reclaim --branches` 多 flag 形态可用（第二解析循环 + usage）。
- **导出面三缺陷**（本版新增修复，详见 §6）。
- **合并 perf 分支**：并入 `agent/perf-m1-wal` 的 bench nightly workflow、`gk_phase_stats.py`、
  `gk_state_wal.py` 与对应测试；`gk_json_utils.py` 保留 WAL 接线（冲突文件取私仓已发布版）。
- **文档落点约定**（`CONVENTIONS.md`）：新增「文档与复评产物落点」表与收尾三查
  （分析报告、臂报告入库；原始 JSON 不入库；MoA `-rN.md`/`-rN.html` 入库；`moa-chain-*.html` 不入库）。

## 5. 性能（本机实测，full 档）

同机、同场景、同口径 `wall/ops/p95` 可比；对照 2026-11-03 的 WAL 期基线：

| scenario | ops/s 11-03 → 本版 | 倍数 | p95 ms 11-03 → 本版 |
|---|---:|---:|---:|
| w1-p1024-s131072 | 44.81 → 74.08 | 1.65× | 12.03 → 18.12 |
| w8-p1024-s131072 | 73.24 → 257.05 | 3.51× | 321.09 → 44.00 |
| w32-p1024-s131072 | 73.94 → 299.69 | 4.05× | 1324.27 → 279.00 |
| w1-p65536-s131072 | 41.22 → 76.32 | 1.85× | 13.98 → 10.06 |
| w8-p65536-s131072 | 65.03 → 210.35 | 3.23× | 360.20 → 69.77 |
| w32-p65536-s131072 | 63.29 → 287.02 | 4.54× | 1403.59 → 270.21 |
| w1-p1024-s524288 | 31.51 → 89.64 | 2.84× | 23.47 → 8.90 |
| w8-p1024-s524288 | 41.44 → 215.05 | 5.19× | 701.14 → 61.61 |
| w32-p1024-s524288 | 41.96 → 263.87 | 6.29× | 2374.89 → 271.16 |
| w1-p65536-s524288 | 29.04 → 85.78 | 2.95× | 28.94 → 10.45 |
| w8-p65536-s524288 | 39.94 → 202.87 | 5.08× | 737.70 → 73.14 |
| w32-p65536-s524288 | 41.15 → 256.16 | 6.23× | 2067.14 → 305.83 |

- 并发档（8/32 写者）吞吐 **3.2–6.3 倍**，p95 下降 **4–8 倍**；单写者档 1.6–3.0 倍。
- 单写者 p1024 的 p95 由 12.03 升至 18.12 ms；其余单写档 p95 下降（如 23.47 → 8.90）。
- `amp/state` = 0.01–0.03（每次逻辑写只落极少字节，append 语义，而非全量重写）。
  旧基线里的 `write_amp` 128–512 是 `state/payload` 比值（旧口径），**不可直接比**。
- 崩溃注入 20/20 通过（`checksum_ok` 全真、无残留 tmp）。
- 另两项：`gate` quick 3 场景 ok；`satellite` quick ok（b1 场景 amp 16.48 / b10 场景 2.48，批次越大批量写越省）。
- 发布门自检 `gk_bench_release` = ok（`doc-release --strict` + `ci-security-lint` 全 PASS）。

## 6. 发布链路与导出面（本版修复 4 处）

| 缺陷 | 后果 | 修法 |
|---|---|---|
| 索引在 purge **之前**生成 | `FILES.md` 写 861、交付树 860 ⟹ 公开 `repo_index` 恒 FAIL | `purge` 前移 + 兜底后重对齐索引 |
| `ci_smoke.sh` 硬编码私仓专属测试 | 公开树 file-not-found ⟹ `smoke gate` 双红 | 意图列表 + 存在性过滤（缺失显式打印；全缺 fail-loud） |
| 导出树无 `.git`，预检自写的 state 被计入索引 | `--check` 与刚生成的索引立刻漂移 | 索引遍历跳过 `.gatekeeper.state*` 族 |
| `test_gk_ecc_sink` 仍断言内联 `satellite_index` | S3 已停写内联、改侧车 ⟹ `KeyError`（既有债） | 断言改查 `.satellite-index.jsonl` 侧车 |

另有两条发布门自身的漂移修复：`gk_doc_release --strict` 在干净环境恒红 ——
（a）论文目录不存在被算 WARN（无法检测 ≠ 发现漂移，改 SKIP，且不回显本机路径）；
（b）`test_gk_sdk_parity` 类"显式标注待建"的臂名被判成文实分裂（否定上下文豁免词补 待建/未落地/TBD）。

单向发布桥 `scripts/gk_public_bridge.py` 本版新增：预检 → 过滤导出 → 整树镜像 → commit →
两仓同名 annotated tag → push（永不 force）→ `docs/oss/release-line.json` 记账。默认 dry-run。

## 7. SDK 化：**计划推进，未进入实施**

`gk-sdk/1` 计划（`docs/plans/2026-11-05-sdk-ification-plan.md`，不随公开包发布）已落到 **R21**；
第四轮（6 臂 / 2 簇，agreement 0.7857）与第五轮（6 臂 / 5 簇）复评均为 **NO_CONVERGENCE**，
各簇代表裁决一致要求**拆分**，仍待 R22+ 修订后复评。**复评通过前不进入实施**。

已落地的是**门级对齐与只读审计面**（`gk_sdk_gate_align.py` + 对应测试）；
S2 验收项 `test_gk_sdk_parity`（in-process 与 CLI 字段等价对拍）**尚未建**，
因此「in-process 与 CLI 行为分叉」风险按 **未消解** 计，不作为已缓解项。

## 8. 文档与索引

- `gk_docgen_facts.py --write`：`SKILL.md` / `references/architecture-overview.md` 事实块；
- `gk_repo_index.py --write`：`FILES.md` / `llms.txt`（文件数由生成器写在 `FILES.md` 首部，随树自动变）；
- 新增 `references/oss-hooks.md` 三条（见 §1）、`gk_release_notes.py`（本说明的生成与检测工具）；
- `docs/` 全目录属导出排除面：内部计划、复评报告、交接文档**不随公开包发布**。

## 9. 验证

- 私仓与公开树 `gk_release_preflight.py`：8/8 PASS；
- 公开树 `ci_smoke.sh`：276 passed（正确跳过 1 个私仓专属测试并显式打印）；
- 导出树自洽：`PREFLIGHT OK` + 兜底 `REPO-INDEX changed=none`（幂等）；
- 定向验收：`test_oss_scrub` / `test_gk_repo_index` / `test_gk_model_probe` /
  `test_gk_ecc_sink` / `test_gk_closeout_order_branch` / `test_gk_public_bridge` 全绿；
- `gk_doc_release --strict`：PASS（facts / align / claims）。

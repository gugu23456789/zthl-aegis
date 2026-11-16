# ZTHL Aegis v0.10.0 — 发布说明

> 2026-11-16 发布。本版覆盖 v0.9.9 之后的 **256 个提交**，
> 主线是**治理面收口**：唯一路由链 + worktree 热池、合并前置闸不可绕过、计划定稿门、
> 审计启停与红队运行时；同时把发版预检从 9 项扩到 15 项，并修正 benchmark 对比口径。

## 1. 路由与 worktree 热池

- **唯一路由链** `pick_active_worktree`：state 提示必须存活且在 `git worktree list` 内；
  否则按 cwd → 池槽租约 → 主树（只读）四级回落，全空 `NO_ROUTE` fail-loud。
- `route-check` 区外自检：悬空 state / 失效 `worktrees_extra` ⟹ rc=3，并接入 CLI 分派。
- **热池派发**：refs 文件直写，0 子进程；实测 235–650 ms（原 1.5–2 s）。
- worktree 独占归属 + 提交身份双键（Session/Worktree trailer）；编辑即续期（节流 ttl/2）。
- 池大小硬上限 1..8；TTL 自动回收走 cron + `--trash`，回收前先归档。
- 路由复位事务化：删树前 `state.worktree→fallback` 且两桶 `worktrees_extra` 同写摘除，
  写失败拒删；`route-check` 端到端覆盖。
- 默认域双写按 route-root 收窄，治 pytest 临时树污染真 state（存量 8 条已解绑）。

## 2. 合并前置闸（R0.24 / R0.25）

- **不可绕过**：Git 层 + 受保护区/事实块/暂存面三道防线 + 唯一入口。
- R0.24-b 判据扩面：主 ref 任何前进都要票据；单条直接提交不再放行；删除一律拒；
  old=ZERO 引导放行。
- 新增 `--cleanup-source-remote`：归档 → 删远端源分支 → `ls-remote` 校验，与合并前置闸对偶。
- 闸① 改双向复算（单向冲突降 WARN）；闸② 识别归档 rename；等价补丁 WARN（勿造无内容 merge）。
- 提交面清 `GIT_AUTHOR_*` / `GIT_COMMITTER_*`，堵 env 伪造作者。
- R0.25 注释模版**编辑时**注入面：新增 def/class 缺意图注释 ⟹ stderr 推骨架命令（放行式）。

## 3. 计划定稿门 `plan_status`

- 计划 META 新增 `plan_status: draft|frozen`；缺省按 `frozen` 处理。
- 指针绑定计划未定稿 ⟹ hook 不跟随域指针，回主 state（避免按草案路由写面）。
- 域 state 种子盒 + 全量计划回填（18 份显式 draft，其余 frozen）。
- `gk_route_center.plan_is_draft` 为唯一判据；hook 侧不复制 META 解析。

## 4. 审计与红队运行时

- 审计 4B 自适应启停：E1–E8 全部落地。E8 的 start→health→stop 已由**外部通道**验毕
  （sidecar 记 `launcher=external`；`startup=5.31s`），不再以「实机三臂对比」作为口径；
  T3/T4 生命周期租约单源；T5 60 s tick 作业体 + 1 min 调度入口（sidecar 前进 + rc/reason 日志）。
- 红队运行时沙盘：E1/E3/E4 骨架 → E2/E5/E6（有界并行 / 崩溃恢复 / 清场）→ 场景层剧本
  6 / 10 / 13 / 14 条；诱饵旋转门、隔离、限流（一次诱饵访问只记一笔违约）。
- `cron dead-man` 由恒 WARN 升级为 FAIL 并接入审计；安全网总表退役，改由
  `references/violation-charter.md` 承载。
- 额度违约在额度银行落地为「冷却期封顶 + 审计只读投影」；提额账本 seal 读侧 fail-loud。

## 5. 文档与索引生成器

- `gk_list_registry.py`：裁决面清单扫描 → `references/list-registry.json`，`--check` 漂移即红。
- `gk_repo_index.py`：`FILES.md` / `llms.txt` 生成器 + 漂移门，移动端与抓取入口不再手写。
- `gk_doc_release.py` / `doc-align`：检查器计数 31→32；模板登记表共享审计层。
- 本次版本准备刷新：`FILES.md`（951 文件）、`list-registry.json`（70 条）。

## 6. 测试与性能

- 统一入口 `scripts/run_tests.sh`：平台感知解释器 + 并行/串行两清点 + 低资源默认。
- 篡改检测整仓克隆改用 tar 管道（跳过构建缓存）。
- 回收前置闸 327 s → 5 s（claims realpath 记忆化）；合并闸 45 s → 11 s（blob 批取）。
- 新增 `scripts/gk_bench_runtime.py`：路由决策 / 计划指针 / 速率闸（quick）+
  合并闸全扫（full）。

## 7. 发版预检与 benchmark（本批新增）

发版预检从 9 项扩到 **15 项**，新增：

- `doc_align`（只 FAIL 判红，WARN 放行）
- `list_registry`（清单漂移）
- `package_integrity`（命令/插件/钩子注册面）
- `ci_security_lint`（最小权限 / SHA pin / run 注入）
- `release_notes`（`--version` 给定时要求说明文件存在，并跑 C1/C2）
- `bench_baseline`（基线不得过期，且必须带 `amp_per_state` 口径）

benchmark 修正：

- `gk_bench_compare`：p99 改读 `latency.p99_ms`（兼容旧顶层键）；两侧都有
  `amp_per_state` 时用它比较，只有单侧存在才判 `probe_mismatch`。
- quick 场景收成 full 同名子集：state `w1/w8-p1024-s131072`；
  satellite `finding/history-n1000-b100-p1024`。
- 发布前性能门从仅 state 扩到 state + gate + satellite。
- 基线在当前 HEAD 重采；夜间作业接入 runtime bench，release bench 不再让夜间恒红。
- 导出树自洽：`oss_scrub export` 在公开树内以 `--release` 跑 doc_align，并按导出集
  重生成 `list-registry.json`（66 条），公开面预检不再因排除面文档缺席而恒红。

## 8. 明确不做 / 未完成

- **不打 tag**：并发/会话互操作主线未收口，本版停在可发版状态。
- **RED 存量按两类分别处置**（2026-11-16 复核，替代旧版「13 条结构性 RED backlog」的笼统说法）：
  - 主台账（当前发布判据面）：104 条，**open 1**，且是 MoA 聚合批的自动记录，非缺陷。
  - 审计署域 state 存量 37 条 open **未回流**（该域最后实质更新 11-01）。其中 `RED-*` 10 条是
    `phase-probe` 的**扫描计数**，不是待修缺陷：当前实测仍在增长（inline `python3 -c` 87→88、
    `2>/dev/null` 827→873、fd 重定向 172→176）⟹ 属结构性度量，本版**不做清零承诺**。
  - 其余 `ECC-*` 里含会话分片/审计关账等实质缺口（如 `ECC-4EFF0600B0B2`），正属未收口主线，
    按主线节奏处理，不在本版宣称已关闭。
- 不在本版收紧 anchor 锚漂移存量（当前 164/688 WARN，属既有债，不阻断发版）。
- 不把红队能力外扩到外部项目；仍然只做自红队与授权工作树。

## 9. 验证

- `test_gk_bench_compare.py`：15 passed（含 p99 嵌套 / amp_per_state 双侧回归 3 臂）
- `test_gk_release_preflight.py`：25 passed（含新增 6 项门、导出面判据、WARN 不判红）
- `test_gk_public_bridge.py`：17 passed（含 askpass 净化臂）
- `test_gk_bench_smoke.py`：4 passed（含 runtime 热点 smoke）
- `gk_release_preflight.py --version v0.10.0`：**15/15 PASS**；
  跨环境时 ratio 自动降级 WARN（本机基线 Windows，WSL 侧只留硬失败）

## 10. 发布面修正（重建 tag 前纳入）

v0.10.0 首次推送公开仓后，`ci` 与 `release` 两个工作流转红。本版在重建 tag 前把根因修掉，
因此 v0.10.0 的最终树已包含下列修正：

- **预检把公开树当私仓审**：`doc_align` 的降级判据写成「有没有 `.git`」，而公开工作副本本身是
  git 仓（有 `.git`、无 `docs/`）⟹ 4 项导出排除面被误判 FAIL。现按 **`docs/` 是否随包** 判定。
- **依赖缺失被判违规**：CI 镜像无 PyYAML，`gk_ci_security_lint.py` 返回的 issues 只有
  `{"error": ...}`、没有 `workflow` 键 ⟹ 预检把「环境能力不足」记 WARN 跳过，真实违规仍判 FAIL；
  且 **WARN 不再让整条预检判红**（此前公开树全项 PASS、仅一项 WARN 仍 rc=1）。
- **内联载荷棘轮**：`gatekeeper-cli.sh` 的内联 Python 载荷回到 88 条（上限 88）：`cmd_commit`
  的 warnings 合并下沉为 `gk_json_utils.py merge-warnings`，`cmd_push` 两处 `time` 计算改用
  shell 算术；受保护区五段 `lost_lines=0`（合并闸校验）。
- **合并闸解释器解析**：Windows 上 `python3` 常是 Microsoft Store 的 0 字节「应用执行别名」桩，
  `command -v` 命中但执行必失败 ⟹ 钩子 fail-closed 拒绝一切 ref 更新（打 tag 被拒）。现钩子
  shim 与 `gk_accept_py` 都先验证解释器**真能执行**再采纳。
- **发布桥不再弹 IDE 密码框**：Trae 把 `GIT_ASKPASS` 指向自己的弹窗脚本，桥的子进程继承它后
  git 缺凭据就弹框挂住。现固定剔除 askpass 并置 `GIT_TERMINAL_PROMPT=0` ⟹ 缺凭据立即失败。

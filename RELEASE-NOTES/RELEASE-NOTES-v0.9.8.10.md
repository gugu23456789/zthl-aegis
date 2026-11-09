# ZTHL Aegis v0.9.8.10 — 发布说明

> 2026-11-09。本版一次性收口四件事：**门禁免计费绕过修复**、**手工拼 JSON 批次 2**（14 处转换 +
> 19 处残差指纹台账）、**看门狗阈值单源**、**红队 JSON/沙箱防爆验证**。功能行为不变。

## 1. 门禁/额度银行绕过（本次最先修，用户质询）

现场（实测）：`_resolve_state_by_target_path("…/worktrees/spz-gatekeeper-json2/gatekeeper-cli.sh")`
返回 `None` —— 旧判定只认目录名**恰好等于技能名**的 `worktrees/<技能名>`。`-json` 等副本不匹配 ⟹
回退 cwd 判定（cwd 也在 worktree ⟹ None）⟹ hook 判 `scope_out` 直接 `exit 0` ⟹
**Gate3（写面归属）/ Gate4（pre-tool-check）/ edit_budget 计费整链不执行**。
账本证据：`edit_budget.sessions[*].billed_files` 无任何本次 JSON 文件，`used_total` 未涨。

修法：`_skill_linked_worktree_state()` 按 **`.git` 文件里的 `gitdir:`** 判定（归一后必须落在
`<技能仓>/.git/worktrees/` 下），名字无关；别的仓的 linked worktree 不认领（防误伤）。
回归：`TestTargetPathScope` **16 passed**（含正/负两臂）。修复后本会话 `used 9→13`，
`gk_watchdog.py`、`_accept_cli.sh` 均真实入账 —— 额度银行恢复工作。

## 2. 手工拼 JSON：33 处逐条审计

| 处置 | 数量 | 内容 |
|:--|:--|:--|
| 转 `gk_json.py build` | 14 | 域路由冲突 ×2、域错误通用、`conv --show-state` ×2、guard-edit worktree、cron script not found、search 结果、session 源 state、session 成功回显、paper-review 拦截、coder 派发、audit docs/state 兜底 ×2 |
| 残差入指纹台账 | 19 | 守卫启动期 ×2（SKILL_DIR 已判不可信，不能依赖 gk_json）、discover 回显 ×3（owner/bind 片段拼接，需独立重构）、固定枚举/已转义/字面量兜底 ×14（逐条写明原因） |

- `gk_json.build` 扩展：**嵌套键**（`repo_paths.skill=`）与**原样 JSON 片段**（`k:=<json>`）；
  片段非法即抛错（绝不产出非法 JSON）。
- 残差守护：`test_xplat_harness.py::_RESIDUAL_SPLICES` 以「归一化整行 sha1」为键。
  **新增拼接 ⟹ 必红；残差行被改动 ⟹ 必红**（强制重新审计）；修好一条必须删对应键。
  这不是放宽判据，是把无法一次改完的存量钉成不可误改的审计面。

## 3. 看门狗阈值单源（防多源漂移）

- 缺省集中在 `gk_watchdog.py`（`DEFAULT_WALL_S/IDLE_S/MIN_FREE_MB/INTERVAL_S`）；
- `_accept_cli.sh` 只在显式设 `ACCEPT_WATCHDOG_WALL_S/IDLE_S` 时才透传，否则不再写第二份缺省；
- 内存闸与启动前硬闸**共用** `ACCEPT_MIN_FREE_MB`（不再两套阈值）；
- 回归：`test_thresholds_are_single_source`（签名缺省 == 模块常量）+
  `test_accept_cli_wires_runtime_watchdog`（禁止 `:-2700`/`:-180` 第二份缺省）。

## 4. 红队面（用户令：16 站启动 / 沙箱完整性 / 打击 JSON / 沙箱内试 OOM）

新 `scripts/test_gk_red_json_sandbox.py`（**12 passed / WSL 9.96s**）：

- `gk_chain run red --dry-run` → `ok:true, total:16`，`RED-SCOPE … RED-AIG` 全规划可启动；
- `gk_json.build` 敌意值（`C:\...\U` 炸弹 / 引号反斜杠 / 换行 / HTML / 20k 超长 / 中文 emoji）
  ⟹ 全部 JSON 往返成功；非法原样片段 ⟹ `ValueError`（拒绝产出非法 JSON）；
- `gk_sandbox.run`：`enforced=True`；128MB 上限内申请 300MB ⟹ `MemoryError`（rc=1），
  宿主存活；超时 1s ⟹ `timed_out=True`（rc=-1）。Windows venv 实测同一组结果
  （Job Object：`{"ok":true,"rc":1,"enforced":true}`）。
- 已知边界：POSIX 侧 `max_proc` 未实现（仅 Windows Job Object 有进程数上限）——登记不宣称。

## 5. Windows 全量测试加速（实测口径）

Windows 侧从**仓根**跑 pytest 会被 worktree 里的 `.keys`（WSL symlink）触发
`WinError 1920` 收集失败。正确跑法 = **cwd 落在 `scripts/`** + xdist：

```
cd <worktree>\scripts
<venv>\Scripts\python.exe -m pytest -q -n 4 --dist loadfile
```

实测（本版改动面 5 文件）：`62 passed in 8.33s`（Windows venv，xdist 4 workers）。
全量请按机器核数把 `-n` 调到 `adaptive_workers` 给的上限（本机 WSL 切片 f=1 → 8）。

## 6. 依赖版本检查（只读，未升级）

- pins ↔ PyPI latest 实测（2026-11-09）：`pytest 9.2.0`、`pytest-xdist 3.8.0`、
  `cryptography 50.0.2`、`pyyaml 6.0.3`、`zizmor 1.32.0`、`pywin32 312`、`anyio 4.16.0`
  **均已是最新**；唯一候选 = **`openai 3.3.1 → 3.46.0`**。
- 纪律：升级需要重生成哈希锁并在新 venv 实测，**本轮不擅自改锁/不安装**；
  Dependabot 分支的 `pip ci-deps` 仍是红（与本次无关），留待按锁重生成流程处理。
- 结论：**无必须立即升级的安全项**；`openai` 候选登记，待用户批准后按「重生成锁 → 新 venv 实测 → 发版」执行。

## 7. 验证汇总

- Hook：`TestTargetPathScope` 16 passed；`test_gk_json` + `test_xplat_harness` + `test_gk_watchdog`
  **40 passed / 28s**；`test_gk_red_json_sandbox` **12 passed / 10s**（Windows 同组沙箱实测通过）。
- JSON：14 处转换全部 `bash -n` 通过；`gk_json.py` 18 passed（含嵌套/原样片段/Win 路径转义）。

## 8. 明确不做

- discover 三处回显的片段拼接重构（需与 owner/bind 字段同批改，单独批次做）。
- 机器级跨进程令牌、运行期信号回写公式（避免过度设计）。
- 不改 `.wslconfig`；不改 408 公式系数（仍标注「本机 WSL 5 核/5GB 的工程妥协，不具普遍性」）。

## 9. 与 v0.9.8.9 的关系

v0.9.8.9 = 公开面发布门根因修复 + 存量测试红清理。
v0.9.8.10 = 门禁计费修复 + JSON 批次 2/残差台账 + 看门狗单源 + 红队防爆验证。

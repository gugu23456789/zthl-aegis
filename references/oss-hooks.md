# 技能的 Hook：契约、门禁与安装安全网

本文件面向**开源使用者**：说明本技能注册的 PreToolUse 钩子做什么、输入输出契约是什么、装了哪些门禁、怎么安全安装/卸载，以及它在业界同类机制里的位置。事实源 = `scripts/pre_tool_hook.py` / `scripts/pre_tool_hook_wrapper.sh` / `scripts/gk_hook_manage.py` / `install.sh`；不写宣传语。

---

## 1. 一句话

一个**工具调用前的强制层**：agent 每次调用工具（Read/Write/Edit/RunCommand/Glob/Grep/…）前，宿主把调用载荷交给本 hook；hook 读治理 state，按门禁链决定**放行（exit 0）**或**拦截（exit 2，stderr 回给 agent）**。拦截不依赖 agent 自觉。

## 2. 注册链路

```
宿主 hooks.json（PreToolUse, matcher=*）
   └─ scripts/pre_tool_hook_wrapper.sh      # 解释器/路径归一后 exec
        └─ scripts/pre_tool_hook.py         # stdin JSON → 门禁链 → exit code
```

- 注册由 `install.sh` 完成（默认开）：`bash install.sh`；跳过用 `--no-hooks`。
- profile：`safe`（默认，`Edit|Write|SearchReplace|RunCommand`）/ `full`（`*`）/ `off`（摘除本技能条目）。
- 注册**只增删指向本技能 wrapper 的条目**，用户已有条目逐字保留；细节见 §6。
- 安装后可核验：`python3 scripts/gk_hook_manage.py status --json`。

## 3. 输入 / 输出契约

**stdin（PreToolUse）**：

```json
{"tool_name":"SearchReplace",
 "tool_input":{"file_path":"...","old_str":"...","new_str":"..."},
 "cwd":"..."}
```

**退出码**（与 Claude Code / VS Code Copilot 的 PreToolUse 形态对齐，源码自述）：

| 退出码 | 语义 |
|--:|:--|
| `0` | ALLOW：继续调用工具 |
| `2` | BLOCK：**不执行**；stderr 回给 agent（含改法提示） |
| 其它 | 非阻断错误：工具照常执行（fail-open 仅限本类） |

**失败语义**：门禁链 **fail-closed**（任一必需判据不可判 ⟹ 拒）；state 不可解析、路径解析失败等都在拦截侧。每次 BLOCK 追加到当日 `hook-block/<YYYYMMDD>.jsonl`（取证面，见 §7）。

## 4. 门禁清单

### 4.1 治理状态 / 路径 / 预算（Gate 0–9）

| Gate | 拦截什么 |
|:--|:--|
| 0 | 裸 `Task` 派 gatekeeper 子 agent（必须走受管入口） |
| 1 / 1b | 阶段必须活跃（非 IDLE/DONE）；审查节点判据与 CLI 同源（`gk_review_nodes`） |
| 2 | 声明的工作树必须**真实存在** |
| 3 | 写类工具的 `file_path` 必须落在活跃工作树内 |
| 4 | CLI `pre-tool-check` 必须通过（含 edit 预算扣减/保护区行号） |
| 5 / 6 / 7 | `Read` / `Glob|Grep` / `LS` 的目标必须在工作树内 |
| 8 | 保护区行号级判定（见 `references/security-measures.md`） |
| 9 | 提问挂起闸：无人时段 / 纯确认型 `AskUserQuestion` → BLOCK |

### 4.2 危险命令与跨平台解析（R0 家族）

| Gate | 拦截什么 |
|:--|:--|
| R0.1–R0.4 | 危险命令 / 脚本扫描 / 插件裸调 / 引号陷阱（各自独立正则，互不复用） |
| R0.6 | **蓝色大肥鱼与 PowerShell**：POSIX 语义命令在 PowerShell 上会变形 |
| R0.7 | **蓝色大肥鱼与 WSL**：Windows/WSL 双向路径与解释器形态错配 |
| R0.12 | **蓝色大肥鱼与 PowerShell 别名**：`ls`/`rm` 等别名语义不同 |
| R0.13 | **蓝色大肥鱼与 PowerShell 解析器**：POSIX 控制语法（`for … do … done`）在 PS 上 ParserError |
| R0.14 | **蓝色大肥鱼与章鱼浏览器**：浏览器出网必须走统一 `_prior_art_fetch`（单出网口） |
| R0.15 | **蓝色大肥鱼与主树**：绕过工作树直接 `git` 改主树 |
| R0.16 | **蓝色大肥鱼与配好的解释器**：`-m pytest` 必须用 `ACCEPT_PY` 解析出的解释器 |
| R0.17 | **worktree 建树单一入口闸**：手搓 worktree 建树/搬树 → BLOCK，强制走 `apply-worktree`（2026-10-28） |
| R0.18 | **蓝色大肥鱼与章鱼浏览器工具面**：`install_browser`（下载 Chromium）与 `browser_record_*`（写录像/技能）默认 BLOCK；`GK_MCP_ALLOW_BROWSER_INSTALL=1` / `GK_MCP_ALLOW_BROWSER_RECORD=1` 显式放行；本地读/UI 保持放行 |

**治理范围**：技能目录恒在范围内；已登记项目由 `.gatekeeper.scopes.json` 的 `governed_projects[]` 决定。cwd 在范围外 ⟹ 放行（不做治理），这是既定语义，不是漏拦。

### 4.3 MCP 与浏览器出网（R0.14）

`octop-browser`（TencentCloud）的 MCP 工具带 `browser_` 前缀，R0.14 已按**前缀精确集**覆盖：

- `MCP_EGRESS_TOOLS` = `browser_navigate` / `browser_open` / `browser_new_tab` / `browser_replay_run` …（外加裸动词 `navigate` / `fetch` / `http_get` 等）；
- `MCP_EGRESS_SEALED_TOOLS` = `browser_eval_js`（JS 内 `fetch` = 残余出网 ⟹ 直接封）；
- `browser_open` 走 `urls`（列表）时逐个取 URL 判域；放行后由 `gk_evidence.record_egress` 记账（`via=mcp-browser`）。

**注意边界**：开源仓里提供的是**门禁与证据**（`pre_tool_hook.py` + `gk_evidence.py`），**不是** octop-browser 的 MCP 配置本身。`mcp.json` / `mcpServers` 的 octop-browser 条目与 venv 属宿主级配置（owner 手工维护），仓内只在 `references/skill-ports/…/spz_gatekeeper_r_sequence.yaml` 记录“工具名与 `MCP_EGRESS_TOOLS` 精确集比对”的检查口径。

**MCP 安全网现状（2026-11-03 复核）**：

| 层 | 状态 |
|:--|:--|
| 写面闸 | **已落**：`MCP_WRITE_VERBS` / `_mcp_inner_tool` / `GK_MCP_WRITE_GATE`（`ECC-BC63B84B28AB` 已闭） |
| 出网闸 | **已落**：R0.14（含 octop-browser `browser_*` 前缀精确集、`urls`、sealed `browser_eval_js`） |
| 工具面闸 | **已落**：R0.18（`install_browser` / `browser_record_*` 默认 BLOCK；`GK_MCP_ALLOW_BROWSER_INSTALL/RECORD=1` 显式放行；本地读/UI 放行） |
| 加载安全网 | **未实装**：早期原型（`gk_mcp_loader` 的 `verify`/`connect`/`health-only`）**未并入主线**，仓内无该脚本，`gatekeeper-cli.sh` 也无 `mcp` 命令；工具面实际拦截由下面三行（写面/出网/工具面闸）承担 |

**配置本身算不算遗漏**：宿主级 `mcp.json`（`%APPDATA%\Trae CN\User\mcp.json`）与 octop-browser 的本机 venv **不应**原样入库（不可移植、含本机路径）。早期曾补过 `mcp_manifest.example.json` 与最小加载验证，但该原型**未并入主线**，模板随之撤出（否则模板会指向不存在的 `verify`）；工具面拦截仍由写面/出网/工具面三道闸承担。

## 5. 「蓝色大肥鱼」系列是什么

它是**跨平台/解析器对抗门禁**的代号家族（源码里 `_blue_fat_fish_*` / `BLUE_FAT_FISH_*_GATE_NAME`）。共同点：不是拦“危险意图”，而是拦**在另一套运行时里会静默变形或直接报错**的命令形态——PowerShell 别名、WSL 路径、POSIX 控制语法、主树直改、解释器错配、浏览器多出网口。名字取「蓝色大肥鱼」，仅作标识。

同族还有一个**只读探针**：[`scripts/gk_watch.py`](../scripts/gk_watch.py)（Bluefin Watch / `state --watch`）——两侧各跑一次，输出同一套规范化快照并互比，把 `path_forms`、`worktree_git_view`、`line_endings`、`case_sensitivity`、`interpreter` 等分叉变成可判定的 `issues[]`。

**为什么算特色**：多数 hook 只做“命令黑名单”；这一族把**同一份技能跑在两个宿主/两套解释器**时的真实故障模式（别名、路径、换行、大小写、解析器）做成了确定性门禁，并且每条都有测试臂与真实误报样本。

## 6. 安装安全网（为什么敢写用户级 `hooks.json`）

[`gk_hook_manage.py`](../scripts/gk_hook_manage.py) 的契约：

| 条款 | 实现 |
|:--|:--|
| 只读探测 | `status` 零副作用；分类 `registered / absent / foreign / unparseable / bad_shape / error` |
| 非破坏合并 | 只增删指向本技能 wrapper 的条目；用户条目逐字保留 |
| 写前备份 | `.bak-<UTC>` |
| 原子写 | 同目录临时文件 + `os.replace` |
| 校验先于写入 | 目标 `hooks.json` 不可解析 ⟹ **拒写**（exit 3，零写入） |
| 写后回读 | 校验失败 ⟹ exit 4（不谎报成功） |
| 可逆 | `uninstall` 只摘本技能条目；同时识别旧版 `pre_tool_hook.py` 形态 |

退出码：`0` 成功 / `2` 参数错 / `3` 目标不可解析（fail-closed）/ `4` 写后校验失败。

## 7. 业界对照：算什么等级

按**能力面**分档（不是厂商排名）：

| 档 | 形态 | 代表 | 本技能 |
|:--|:--|:--|:--|
| L1 | 单一事件本地钩子 | git hooks / pre-commit | 超越：不是单事件，而是按工具+state 判 |
| L2 | agent 工具前钩子 | Claude Code / Copilot 的 PreToolUse（exit 2） | **对齐契约**，并加门禁链与治理范围 |
| L3 | 带状态机/范围/安装安全网的治理层 | 本技能 | **在此档**：state 相位 + worktree + 保护区 + 预算 + 跨平台对抗门禁 + 可逆安装 |
| L4 | 策略引擎/准入控制 | OPA / Kyverno / SLSA 类 | 未达：无策略 DSL、无通用准入/供应链证明（本地有 ed25519/封印，但不是 SLSA 级证明）、沙箱仅覆盖 subagent 派发 |

**判断**：在“开源技能包”这个圈层里属于**少见的一档**——多数开源技能只发 `SKILL.md`（靠 agent 自觉），带强制层、可逆安装与取证日志的是少数；但放到通用策略引擎/准入控制里，它是**轻量级、领域专用**的实现，不应宣称“企业级策略引擎”。

**已知短板**（按源码与仓内取证）：
1. **仅 PreToolUse**：没有 PostToolUse，拿不到“工具返回字符数/结果面”（仓内 A-8 已证伪该数据源），因此无法做结果级审计。
2. **解析是正则/启发式**，不是完整 shell/PowerShell 语法树；对抗样本靠测试臂兜底，不是形式化保证。
3. **hook 层不沙箱化任意工具调用**；沙箱在 **subagent 派发层**（`scripts/suagent_sandbox.sh`，mem/time/proc 硬上限，`GK_SANDBOX_SUBAGENT` 默认开，包装器缺失 **fail-closed**，仅 `GK_SANDBOX_FAIL_OPEN=1` 显式降级）。
4. **签名/封印在“决策与账本”层，不在 hook 代码层**：`gk_audit_state` 的 `ed25519_sig`、`gk_budget_ledger._seal_with_chain` 为审计证据/额度账本提供签名与封印链；但 **hook 安装器/钩子代码本身不做代码签名**，安装安全网只保证“非破坏 / 原子 / 回读”。
5. **每次调用一个 python 子进程**：有固定开销（仓内有 phase 探针与性能臂在盯）。

## 8. 快速上手

```bash
bash install.sh                        # 默认注册 safe profile
bash install.sh --no-hooks             # 只复制，不动 hooks.json
bash install.sh --hook-profile full    # 匹配全部工具
bash install.sh --hook-profile off     # 只摘除本技能条目
python3 scripts/gk_hook_manage.py status --json   # registered / absent / foreign / unparseable
bash uninstall.sh                      # 按 .spz-manifest 回收
```

## 9. 证据与测试

- `scripts/test_pre_tool_hook.py`：门禁行为臂（含 host config 路由）。
- `scripts/test_protected_region_reachability.py`：保护区行号级可达性。
- `scripts/test_gk_q2_hint_selfconsistency.py`：Q2 自洽（提示与判据一致）。
- `scripts/test_gk_q3_persistent_block_log.py`：BLOCK 持久日志四臂。
- `scripts/test_eco_integration.py`：CLI 侧 pre-tool-check / guard-edit 同窗。
- 误报率口径与六类安全网表：`references/security-measures.md`。

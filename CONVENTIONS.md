# SPZ Gatekeeper Skill — Git 管理规范

## 为什么有这个仓库

`spz-gatekeeper-r-sequence` 技能文件跨会话修改频繁。本地 git 仓库用于追踪变更、协调双会话编辑、提供回退点。**无 remote，纯本地。**

## 提交规范

| 前缀 | 用途 | 示例 |
|:---|:---|:---|
| `feat(R7.7):` | 新功能/管道变更 | `feat(R7.7): reasoning_effort 参数` |
| `fix(skill):` | 修复 | `fix(skill): pre_tool_check path escaping` |
| `docs:` | 文档/注释 | `docs: 更新 stage-1-code.md pre-tool-check` |
| `refactor:` | 重构 | `refactor: 提取 _collect_hard_evidence` |

## 双会话协调

两个会话（"修复会话"和"API 会话"）可能同时修改同一文件不同位置。

1. **commit 前先 status** — `git status --short` 确认无意外冲突
2. **同一分支** `master` — 不创建 feature 分支，简单线性历史
3. **commit 消息写清楚范围** — 让对方（和未来的自己）知道改了哪些文件

## 当前历史

```
13aaedd feat(R7.7): v4.18  set-key command for centralized API key management
cc62e79 feat(R7.7): v4.18  MiMo v2.5 provider fallback + response_format + score normalize
b83dd44 feat(R7.7): v4.18  exit code 主通信 + STAGE_0 schema 修复 + 编码转义文档
5250298 docs: 添加 CONVENTIONS.md git 管理规范
a0eaf6d feat(R7.7): v4.18  API reasoning_effort+balance+pre_tool_check hardening
4e072bb feat(R7.7): v4.18  session startup checklist (STAGE 0) with R5 bare-run
d13fe45 feat: initial SPZ Gatekeeper R-Phase Pipeline v3.x
```

## API Key 管理

| Provider | Key 名称 | 存储位置 | CLI 命令 |
|:--|:--|:--|:--|
| DeepSeek | `DEEPSEEK_API_KEY` | Windows User 环境变量 | `set-key deepseek sk-xxx` |
| MiMo | `MIMO_API_KEY` | Windows User 环境变量 | `set-key mimo sk-...`（`tp-*` 属已弃 Token Plan 版，勿用） |

**轮换流程**: `bash gatekeeper-cli.sh set-key <provider> <new-key>` → 同时更新 WSL env + Windows User env (持久化)

**读取优先级**: WSL env → PowerShell User scope → PowerShell Process scope

**持久化方式**: PowerShell `SetEnvironmentVariable("...", "User")` → 注册表 `HKCU\Environment`（等同于系统设置→环境变量手动添加）

## 架构原则: 文档是 CLI 的输出, 不是输入

- 规则文档 = CLI 执行历史的可读快照 (给人读, 不给 agent 读)
- rejected_edits buffer = CLI 自动拦截 (存在 gate_data 中, 不需要新文件)
- 数据流: CLI → state/gate_data → 最后一步回写 → 规则文档
- 详见 `references/stage-6-r6-flow.md §架构原则`

## 何时 commit

- 每个安全的工作单元结束时（不强制 PR/审批）
- 跨会话切换前（减少对方 rebase 成本）
- 不需要 commit 的：测试输出、IDE 配置、临时调试脚本（已加 .gitignore）

## 文档与复评产物落点（硬约定，2026-11-08）

依据：`docs/analysis/subagent/sub-1794105259-46-12184.md`（408 帧调研）与 `docs/analysis/` 两份 408 先例。
目标：产物**自包含、可追溯、只有一份**；不把运行期数据当仓库资产，也不让未跟踪文件挡住 ff 合并。

| 产物 | 落点 | 入库 | 说明 |
|:--|:--|:--|:--|
| 分析报告 | `docs/analysis/YYYY-MM-DD-<topic>.md` | 是 | 自包含：结论 + 证据 + 可证伪实验 |
| 408 分析报告 | `docs/analysis/YYYY-MM-DD-<topic>-408.md` | 是 | 头部注明 `GK_RESEARCH_FRAME=408` |
| 臂报告 | `docs/analysis/subagent/sub-<id>.md` | 是 | `.gitignore` 只再包含 `*.md` |
| 臂原始 JSON | `docs/analysis/subagent/sub-<id>.json` | 否 | 已忽略；**不得**作为唯一证据锚 |
| MoA 聚合快照 | `docs/analysis/YYYY-MM-DD-<topic>-rN.md` | 是 | 内嵌各臂结论，自包含 |
| 同日聚合页快照 | 同名 `-rN.html` | 是 | 与 `2026-11-06-sdk-moa-v12.html` 先例一致 |
| chain 运行期页 | `moa-chain-*.html` | 否 | 每次 chain 重写，含本地批指纹/路径 |
| 报告类 bulk | — | — | **不进** state 卫星（`KIND_SUFFIX` 无 report 类） |

**流程约束**

1. 主树落盘后**立即** `git add` 入库；worktree 只作中间稿——纯 `--ff-only` 不携带未跟踪文件。
2. 同一路径只允许一份：跨 worktree 同名不同 sha 视为缺陷，须合并为单份。
3. 禁止把 gitignored 的 `*.json` 当唯一证据锚；必须引用时，相邻给出重跑命令。
4. 收尾时 `git status --short docs/analysis` 必须为空，且 `self-check` 的
   `docs_analysis_untracked` 不得为 `WARN`。

```bash
# 收尾三查
git status --short docs/analysis
git ls-files docs/analysis | grep -E 'subagent/.*\.json$'   # 期望空
git check-ignore -v docs/analysis/subagent/x.json            # 期望命中 .gitignore
```

## 测试解释器（硬约定，2026-10-27 起由 Gate R0.16 机检）

本仓测试**必须**跑在「配好的解释器」上；基线（`scripts/_accept_baseline.txt`）绑定解释器，换解释器结果不可比。

**「配好的解释器」= 单源 `scripts/gk_accept_py.py`**（四处消费者共用，禁各自写死路径）：
环境变量 `ACCEPT_PY` → `scripts/_accept_py.local`（**本机私有**，已 gitignore，一行解释器路径）→ `python3`。
公开 clone 没有 `_accept_py.local` ⟹ 缺省走系统 `python3`；维护者本机把隔离 venv 写进该文件即可。

| 场景 | 唯一正确姿势 |
|:--|:--|
| 日常改动面验收 | `bash scripts/_accept_cli.sh <test.py> [...]`（解释器取上述单源） |
| 需要裸跑 pytest | `"$ACCEPT_PY" -m pytest <files>`（先确定解释器，再显式写全路径） |
| red-first 复现 | `bash scripts/_redfirst_cli.sh <rev> <test.py> "<-k expr>"`（`REDFIRST_PY` 覆盖，缺省同上） |

- **禁止**：在解释器未确定时裸跑 `python -m pytest` / `python3 -m pytest` / `pytest`（不同解释器的路径语义与依赖面不同，结果不可比）。
- 门禁：Gate R0.16【蓝色大肥鱼与配好的解释器之间不得不说的故事】对「与配好的解释器不一致」的 `-m pytest` 调用 **BLOCK**；
  确需其他解释器时在**段首**声明 `GK_ALLOW_ANY_PYTEST=1`。
- 逃生舱只用于诊断，不得用于验收读数。

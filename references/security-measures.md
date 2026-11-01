# SPZ Gatekeeper Security Measures

三层安全防护体系。A/B 随仓库开源，C 是 GitHub 平台配置建议。
**2026-08-28 8 域安全评估**：权威总索引 = `docs/plans/2026-08-28-security-hardening-assessment.md` §13（投毒/窄任务/确定性管道/zthl/元数据路由/bridge/红队等保/高威胁 + 引用链），本文件为其"安全网总表"承载。

---

## A. 代码级防护（随代码开源）

| 措施 | 文件 | 说明 |
|:--|:--|:--|
| V11/V12 整数溢出修复 | `spz.cc` | `uint64_t` 接收 ZSTD 返回值 + `numeric_limits<size_t>::max()` 溢出检查，防止 wasm32 上 sentinel 检查失效和 reserve 截断 |
| V5/V6 state 锁 | `scripts/gk_json_utils.py`（python 侧单持） | **2026-09-25 选项 A（用户裁定「唯一锁持有者 = python」）**：锁资源仍是 `<state>.lock`，但改由 `state_lock()`（可重入 flock + 5s 超时）获取；原 `gatekeeper-cli.sh _with_state_lock()` **已拆除**（bash 只覆盖 2 入口，python 侧 ~15 写通道全无锁 ⟹ 9 agent 并行下读-改-写丢更新）。`_state_write` / `_state_checksum_write` 在 python 载荷内持锁 |
| V9/V10 变量修复 | `gatekeeper-cli.sh` | `cmd_appeal` 中 `g`→`$gate`，STAGE_2 monitor 中 `$evidence` 定义 |
| V1-V4 命令注入修复 | `gatekeeper-cli.sh` | `sys.argv[1]` 替代内嵌字符串，PowerShell `${safe_key}` 转义，gitnexus 调用引号转义 |
| pre_tool_check 路径验证 | `gatekeeper-cli.sh` | realpath 符号链接解析 + junction/mount point 检测 + protected region 行号级拦截 |
| SHA256 state 校验 | `gatekeeper-cli.sh` | `_state_checksum_verify` exit 1 on mismatch，阻止篡改 state 文件 |
| F8.1 远端验证门禁 | `gatekeeper-cli.sh` `_verify_remote()` | push 前实时校验 remote URL，阻止推送到错误远端 |
| F8.1 IDE hook 多级门禁 | `~/.trae-cn/hooks.json`（Trae 全局根目录，catch-all 单入口 → `pre_tool_hook_wrapper.sh` → `pre_tool_hook.py`） | Gate 0-4: Task 拦截、stage 活跃检查、worktree 存在、路径范围、CLI pre-tool-check |
| amend 检测 | `gatekeeper-cli.sh` | 阻止 `git commit --amend` 绕过 CI trigger 注册 |
| detect-changes 门禁 | `gatekeeper-cli.sh` | STAGE_1→2 范围检查 + STAGE_2 monitor 证据集成 |
| L1-L9 交叉审查 | `gatekeeper-cli.sh` + `stage-3-review.md` | 9 层审查在推送前执行（代码实现 + 文档流程双重保障） |
| docgen 自动文档生成 | `gatekeeper-cli.sh docgen` | 从代码注释自动生成 cli-protocol.md，防止文档漂移 |

---

## B. 机制级防护（文档化安全策略，随仓库开源）

| 措施 | 位置 | 说明 |
|:--|:--|:--|
| 供应链审查前置 | `project_rules.md` §升级铁律 | 任何依赖升级前必须审查 CVE + 供应链风险 |
| 论文期冻结 | `project_rules.md` 约束 | 审稿期间禁止升级依赖 |
| 安全网关全覆盖 | `project_rules.md` 约束 I | 所有工具调用经过 guard-edit + pre_tool_check |
| 死代码三关检测 | `SKILL.md §死代码检测` | context→rg 生产入口→plan table 验证 |
| 凭证轮换 | `set-key` 命令 | 每个 R-phase 新 token，旧 token 立即失效 |
| SHA 固定 Action | `.github/workflows/` | 所有第三方 Action 固定到 commit SHA，防标签 force-push |
| CODEOWNERS | `.github/CODEOWNERS` | `.github/` 目录修改需安全团队审批 |
| zizmor 静态扫描 | CI workflow | GitHub Actions 安全扫描器，检测缓存投毒/pwn request |
| Harden-Runner | CI workflow | Runner 出站流量监控，检测异常连接 |
| game-path-audit | `references/game-path-audit.md` | 6 条攻击路径追踪 + 供应链攻击升级场景 |
| §8.8 经验管理层规格 | `references/prm-monitor-methodology.md` | 四层记忆金字塔 + 质量控制机制设计 |
| **项目入库自动化门禁（域 5）** | `scripts/gk_project_register.py` + CLI `project-register` | **（2026-08-28 实装）**scopes 注册表（`.gatekeeper.scopes.json`）从手动编辑改为受控命令：marker 白名单/state 路径/机密目录黑名单输入合规 → flock+`_checksum`+os.replace 原子登记 → `--read-repo` 别名联动 `subagent_runner.REPO_ROOTS`（动态注入）→ `audit_log[]` 不可抵赖留痕；`seal` 升级存量手动注册表；RED-REGISTRY-01..08 红队检测闭环 |

---

## C. GitHub 平台级防护（仓库设置中开启，不在代码中）

| 措施 | GitHub 位置 | 说明 |
|:--|:--|:--|
| Branch Protection Rules | Settings → Branches → main | 要求 PR reviews + status checks + admin enforcement |
| CODEOWNERS enforcement | Settings → Branches → Require review from Code Owners | `.github/` 修改需安全团队批准 |
| Secret Scanning | Settings → Code security → Secret scanning | 自动检测泄露的 API key |
| Push Protection | Settings → Code security → Push protection | 阻止包含密钥的推送 |
| Dependency Graph | Settings → Code security → Dependencies | 自动追踪依赖漏洞 |
| Dependabot alerts | Settings → Code security → Dependabot | 依赖漏洞自动告警 |
| Workflow permissions | Settings → Actions → General → Workflow permissions | 默认 read-only，最小权限 |
| OIDC trusted publishing | Settings → Environments → 配置 OIDC | 无 Token 的可信发布 |
| Environment protection rules | Settings → Environments → production | 发布需审批 + 部署分支限制 |
| GitHub Advanced Security | 需 GitHub Enterprise 或 public repo | Code scanning + Secret scanning + Dependabot |
| Code scanning (zizmor) | Settings → Code security → Code scanning | 持续扫描 Actions 安全 |

---

## 漏洞修复记录

| 编号 | 严重度 | 修复 commit | 分支 |
|:--:|:--|:--|:--|
| V1-V4 | 🔴 CRITICAL / 🟠 HIGH | 已在之前 commit 修复 | main |
| V5-V6 | 🟡 MEDIUM | `24ad937` (flock) | main |
| V7 | 🟡 MEDIUM | 文档化（本地仓库，无远端） | — |
| V8 | 🟢 LOW | 假阳性，无需修复 | — |
| V9-V10 | 🟡 MEDIUM | `c1c4237` | main |
| V11-V12 | 🟡/🔴 | `ef74272` | feature/spz-gatekeeper-2.0.2-r5.1 |

---

## 安全网分类汇总（六类，2026-08-27 系统性清点）

> 所有安全网按"防护阶段"归六类。清点驱动：H-SLSN 实施完成（ECC-8570E847C7C1）后的系统性梳理。

### 1. 加载类安全网（Loading）— 插件/模块/技能加载时校验

| 安全网 | 位置 | 作用 |
|:--|:--|:--|
| gk_bashpy_loader SHA256 pin | `scripts/gk_bashpy_loader.py` | 插件发布包哈希固定，dev 回退审计，hash_mismatch 拦截 |
| gk_plugin_manifest cap 白名单 | `scripts/gk_plugin_manifest.py` | 插件子命令能力白名单（manifest intercept 单一事实源） |
| cmd_migrate 统一入口 | `gatekeeper-cli.sh migrate` | 插件功能唯一入口（analyze/verify/audit + status/check/upgrade/rollback） |
| **H-SLSN 技能加载安全网** | `scripts/pre_tool_hook.py` | **（新 2026-08-27）**双条件激活（hook 生效 + 技能调用）→ 引导内置 cmd，回环拦截 + 状态循环防死循环 |
| pre_tool_hook R0.4 插件裸调拦截 | `scripts/pre_tool_hook.py` | 插件裸调用（CLI/-m/-c/eval/bash-c/升级脚本）→ 硬 BLOCK |

### 2. 文档审查引擎调用安全网（Doc Review Engine Call）— 文档-代码一致性确定性审查

| 安全网 | 位置 | 作用 |
|:--|:--|:--|
| docgen | `gatekeeper-cli.sh docgen` | 从代码注释自动生成 cli-protocol.md，防文档漂移 |
| audit --docs（C1-C5） | `scripts/gk_audit_docs.py` | 5 项确定性检查（命令数/注册表/文件树/META 阶段/分类学结构） |
| doc-align | `gatekeeper-cli.sh doc-align` | 文档一致性 + 漂移**单一入口**（23 项确定性检查器）。**[F-REV-42 2026-09-13] `monitor --align` 已收敛为委托 doc-align 插件（gk_doc_align.py 单一实现）；L9 三态归位 `monitor --local`（单源 self-check #14-16）** |
| self-check | `scripts/gk_self_check.py` | rg 误用 / heredoc 错误 / tool_config 一致性 / 上下文签名 |
| **审查层四件套覆盖（E4）** | `gk_self_check.check_review_layer_coverage`（#20）+ `doc-align cross_review_matrix`（共享 `REVIEW_LAYERS`/`REVIEW_LAYER_MATRIX` 单源） | **（2026-09-05 C1）**L1-L10(+PR) 每层 CLI 入口/文档锚点/红队向量族/测试文件必配面，bare/thin/实配（A4 三面模式）；`skill_command_count` 漂移 WARN→FAIL（A8） |

### 3. 运行时安全网（Runtime）— 状态/并发/可观测

| 安全网 | 位置 | 作用 |
|:--|:--|:--|
| SHA256 state 校验 | `gatekeeper-cli.sh _state_checksum_verify` | 篡改阻断 + 诊断 hint |
| state 锁（flock，唯一持有者 = python） | `scripts/gk_json_utils.py state_lock` | 多 agent 并行读-改-写互斥（原 `gatekeeper-cli.sh _with_state_lock` 于 2026-09-25 选项 A 拆除；python 侧全覆盖） |
| GK_DBG_LOG 插桩 | `gatekeeper-cli.sh` / `scripts/` | heredoc 异常不吞错（stderr 追加 + 兜底 JSON） |
| dry_run 零副作用契约 | `scripts/gk_*.py` | --check 不写任何文件（Paperclip pre-heartbeat 依赖） |
| subagent 预算分层 | `scripts/subagent_runner.py` | token/item/max_turns 三层预算 + 硬限直通 |
| **A7 appeal 错误码三分流 + sentinel 迁移** | `gk_appeal.py` + `cmd_appeal` | **（2026-09-05）**环境缺失/传输/解析 vs 实质否决三分流（APPEAL_ENV_UNAVAILABLE / APPEAL_API_UNAVAILABLE / APPEAL_RESPONSE_INVALID → RETRYABLE 不落永久）；score==-1 哨兵迁移写 `appeal_repair_log`（真实 DENIED score∈[0,1] 不误吞） |
| **A8 聚合器掩蔽分流 + tests 环境 SKIP** | `cmd_self_check` + `gk_self_check.py` | **（2026-09-05）**python 崩溃/不可解析才兜底（显式 `python_aggregator` WARN 承载），退出码非 0 但输出可解析 = 真实发现并入 issues；pytest 不可用 → SKIP + 安装引导（env≠实质） |
| **租户隔离（A6 域 token 门）** | `gk_self_check.check_tenant_isolation`（#19，doc-align 共用） | **（2026-09-05）**scopes 租户根双形态重复/嵌套 = 跨租户读取面/域边界虚置检测 |

### 4. 序列节点启发式引导安全网（Sequence-Node Heuristic Guidance）— 引导 agent 走正规序列

> **2026-08-27 新增统一模板**：`references/sequence-node-safety-net-template.md` — 序列节点安全网
> 五元组 SN=⟨G,B,C,T,D⟩ + 前置产物清单（代码库地图/基线/源文档/窄任务清单）+ 名称精确/输入完整。
> 暴露驱动：subagent 读不全（read 分页/截断无提示）+ 名称歧义投毒（plan-refine vs plan-refinement）+ 基线未刷新。

| 安全网 | 位置 | 作用 |
|:--|:--|:--|
| **H-SLSN**（同上） | `scripts/pre_tool_hook.py` | 技能会话期间绕过内置 cmd → 引导 + 回环拦截；**2026-08-27 全名化：Skill 精确匹配 + 旧名/未知名拦截（投毒点关闭）** |
| WSL 引号陷阱引导 | `scripts/pre_tool_hook.py _wsl_quoting_trap` | **（2026-10-30 口径校正）**双引号载荷 = **PS 宿主语义**（自己展开 `$`/`$( )`/反引号、`<` 当重定向，**与 5.1/7.x 版本无关**）→ 拦截 + wslsh 引导；单引号内嵌引号 = PS **5.1** native-arg mangling（**7.3+ 已修**，判据保留以兼容历史脚本/`wsl.exe` 直调） |
| **PS 宿主解析改写（Gate R0.6 / 蓝色大肥鱼与powershell之间不得不说的故事）** | `scripts/pre_tool_hook.py _blue_fat_fish_ps_story` | **（2026-09-14）独立一类**（与 W1 平行、互不复用正则 —— W1 建模为「一种命令形态 `wsl bash -c`」，本闸建模为「PS 宿主会改写**任意**命令串」）：**P1** bash/sh/zsh `-…c…` 的**双引号**载荷含 `$`（PS 先展开 ⟹ 变量被吞）/**P2** `<<` 非单引号区（PS 无 heredoc 重定向）/**P3** 反引号非单引号区（PS 转义符）→ **BLOCK**；**P4** `-c`/`-e` 载荷含 `[...]`（类型字面量，机理未完全复现）→ **WARN**。三例实证见 assessment F-REV-55 |
| **wsl 家族引号·编码陷阱（Gate R0.7 / 蓝色大肥鱼与wsl之间不得不说的故事）** | `scripts/pre_tool_hook.py _blue_fat_fish_wsl_story` | **（2026-09-14）独立一类**：覆盖 R0.1/R0.6 均不认的 **wsl 家族入口** —— **W1** `wslsh -c "…"` 双引号载荷含 `$`/反引号（**关键**：wslsh 的"落临时 .sh"只保护 wsl.exe 命令行层，**PS 层在其之前就展开**）→ **BLOCK**；**W2** `wsl -e\|--exec\|-- … -c "…"`（R0.1 正则未覆盖形态）含内嵌引号/`$(`/`${` → **BLOCK**；**W3** `WSLENV` 敏感条目缺 `/u`（WSL 会对未标 `/u` 的值做路径翻译）→ **WARN**；**W4** `wsl … bash <Windows 路径>`（WSL 不认 `C:\…`）→ **WARN**。对象实读 = `~/.trae/bin/wslsh.ps1` + `scripts/gk_env_inject.{sh,py}`；见 assessment F-REV-56 |
| **PS 别名劫持（Gate R0.12 / 蓝色大肥鱼与PowerShell别名之间不得不说的故事）** | `scripts/pre_tool_hook.py _blue_fat_fish_ps_alias_story` | **（2026-10-10）独立一类**（与 R0.6/R0.7 平行、互不复用正则）：**命令位别名 + POSIX 专属旗标** → **BLOCK**。PS 会话里 `ls/cat/rm/cp/mv/echo/curl/wget/ps/kill/head/tail/sort/mkdir…` 皆是 cmdlet 别名（实测 `ls -d` ⟹ `Get-ChildItem -Depth`，`-Depth` 只收整数 ⟹ 报错/静默错值）；判据 = 段首 token（按 `;&\|`/换行 切、引号内置空）属别名表 **且** 其后 `-<字母>` 与该别名的 POSIX-only 字母集相交（或 `ps aux`/`kill -9` 整 token 特判）；豁免 = `wsl/wslsh/bash/sh/zsh` 前缀。finding ECC-3D144703E751 / 红先 `TestPSAliasStory` |
| **PS POSIX 控制语法（Gate R0.13 / 蓝色大肥鱼与PowerShell解析器之间不得不说的故事）** | `scripts/pre_tool_hook.py _blue_fat_fish_ps_posix_story` | **（2026-10-10）独立一类**：PS 上直接跑 POSIX 控制语法（`for\|while\|until … do … done` / `if … then … fi` / `case … esac`）⟹ ParserError（实测 `Missing statement body in do loop`）→ **BLOCK**；判据 = 引号内置空后同时出现首/中/尾关键字；豁免 = `wsl/wslsh/bash/sh/zsh` 前缀；与 R0.12 共用 `_ps_alias_strip_quoted`。finding ECC-3D144703E751 / 红先 `TestPSPosixSyntaxStory` |
| **Gate R0.14 单出网口闸 / 蓝色大肥鱼与章鱼浏览器之间不得不说的故事** | `scripts/pre_tool_hook.py _egress_identity` | **（2026-10-10）**浏览器 MCP 的**导航/取网**动词（navigate/goto/fetch/request/…）归一 + **普适 BLOCK**：契约 = **一切出网走 `subagent_runner._prior_art_fetch`**（见 `scripts/gk_evidence.py`；浏览器出网 = 无台账第二通道）；白名单**精确等值**（click/type/dom_tree/screenshot 属本地页面操作**不收**）；位点**先于** `scope_out`；逃生舱 `GK_MCP_EGRESS_GATE=0`（`ECC-6007804DD7BD`）。**（2026-10-11）扩 octop-browser**（TencentCloud/octop-browser）：其 MCP 工具名带 `browser_` 前缀，与裸动词精确集不匹配 ⟹ `browser_navigate`/`browser_open`/`browser_new_tab`/`browser_replay_run` 曾**整体漏网** ⟹ 按精确名补入出网集、`browser_eval_js` 补入封禁集、`_egress_url` 增读 `urls`（`ECC-96B2214FA16B`） |
| plan-refinement 统一入口 | `gatekeeper-cli.sh plan-refinement` | 计划质询强制 CLI（preflight + subagent 点检 + 审计留痕），禁止裸跑 Skill；**2026-08-27 全名化：plan-refine → plan-refinement（旧名移出 _CMD_REG → dispatch 未知命令拦截）** |
| pre-tool-check 引导 | `gatekeeper-cli.sh pre-tool-check` | 工具调用前置门禁（stage/worktree/路径/保护区） |
| **窄任务清单机制** | 模板 §4.1 + `gate_data.narrow_tasks[]` + `scripts/gk_narrow_route.py` | 节点前置：窄任务单一职责/输入有界/可验证/可并行；**（2026-08-28 路由实装）**清单条目可带 tier 字段 → `cmd_monitor --subagent` 命中即透传 `SUBAGENT_TIER`（test_gk_narrow_route 10 用例）；**（2026-08-28 下发前三连闸）**`--check-poison`（强注入 fail-closed，TestPoisonCheck 5）+ `--check-schema`（格式/复杂度：id 必填/tier∈1-4/≤20 条目/≤8KB 条目/≤64KB 清单，TestSchemaValidation 9）+ 档位路由（越界不参与） |
| **gk_node_guard 节点安全网承载** | `scripts/gk_node_guard.py` | **（2026-08-27 实装）**NODE_REGISTRY 节点注册（advance 未知节点硬阻断）+ node_guard 前置产物 G 谓词 + route_map 总运行线路（Phase 3.5d route_template 实装）+ station_announcement 车站播报（注入 advance hint） |
| **subagent 4 档梯度** | `scripts/subagent_runner.py SUBA_TIERS` + `--tier` | 4 档（mini/light/standard/heavy），默认 tier 3 中间档；**六维梯度：token/item/turns/`max_output_tokens`（**2026-08-28 上调** 4000/8000/16000/32000）/`timeout`（单次 API 超时 150/180/240/360s）/文件上限（30MB 总硬限）**；**（2026-08-28 上调理由）**token_budget（40K/80K/200K/400K）= 输入+输出（含 thinking）累计总预算 — thinking=high 单轮 2-4K，原 20K 档 3-6 轮即近硬限，中途 hard-block 截断；max_output_tokens 含 thinking，原 2000 可见输出被饿死；`_ECC_BOUNDS`（ECC 报告字段界限随档位缩放：conclusion 800-3000 / evidence 5-15，与 thinking 解耦不变）；CLI `plan-refinement --tier N` 透传；重试链（DS 重试→MiMo 降级）为 CLI 层统一机制不随档位 |
| **MoA 聚合器（ECC references → 主 agent 聚合）** | `scripts/gk_moa_aggregate.py` + CLI `moa-aggregate` | **（2026-08-28 实装，对齐 zthl-adapter governance/moa/）**pre_check 投毒清洗（跨租户/指令注入/角色伪装红action）+ **suspect 异常标记层**（no_evidence/no_conclusion/budget_*/zero_findings/hmac_unverified → 主 agent 降权交叉验证）+ audit 溯源 + inject 聚合指引锁死；3 个 max-tier subagent 同时输出 → 全部保留独立 reference（不二次截断），主 agent（aggregator）融合裁决 |
| **序列节点红队攻击面（RED-ROUTE）** | `scripts/_red_attacks.py red_route()` | **（2026-08-28 新增）**总线路（route_map）/车站播报/前置 G 谓词组件完整性 + 车站伪造 + advance_log 未知节点转移（序列逆转 RED-ROUTE-05/07）+ 窄任务清单投毒（RED-ROUTE-09）+ **档位路由防篡改（RED-ROUTE-10/11/12：SUBAGENT_TIER 越界映射/绝对赋值/无保底映射）** + **（2026-08-28 二扩）RED-ROUTE-13/14 档位预算漂移（CLI env 兜底 vs SUBA_TIERS 单一事实源）** |
| **投毒攻击面（RED-POISON）** | `scripts/_red_attacks.py red_poison()` | **（2026-08-28 强化）**窄任务清单 8 类注入向量（显式/条件/合规事实/虚假先例/重复凸显/Unicode 混淆）+ state 字段（subagent_history/block_log）零宽/BOM 隐写残留；参考 OWASP LLM Top10 LLM01/04 + MITRE ATLAS + 用户 8 类投毒清单；深层语义判定归 zthl-harness（登记） |
| **元数据路由注册表（RED-REGISTRY）** | `scripts/_red_attacks.py red_registry()` | **（2026-08-28 新增，域 5）**scopes `_checksum` 缺失/失配（篡改检测）+ 孤儿登记（state 缺失）+ 机密目录投毒 + read_repo 别名冲突 + 非法 marker 注入 + 无 audit_log；配套 `project-register` CLI（register/list/remove/seal） |
| **高威胁幽灵攻击（RED-GHOST）** | `scripts/_red_attacks.py red_ghost()` | **（2026-08-28 新增，域 8）**SUBA_TIERS 预算域越界（OWASP LLM10 资源耗尽）+ ECC conclusion 超界（撑爆聚合上下文）+ 递归/自复制诱导 + 无 HMAC 报告进入聚合面 |
| **审计覆盖缺口（RED-COVERAGE）** | `scripts/_red_attacks.py red_coverage()` | **（2026-08-28 新增，域 3/4/5）**2026-08-28 新增安全措施是否入审计序列（project-register/三连闸/聚合器/节点安全网接线存在性）——翻新即失守防回归 |
| **产品完整性（RED-INTEGRITY，第 15 阶段）** | `scripts/_red_attacks.py red_integrity()` | **（2026-09-04）**产品代码 fail-open/fail-closed 模式审计（P1 catch-all→null 静默降级 / P2 能力缺失降级 / P3 校验失败未 fail-closed / P4 探针-执行分裂 / P5 哨兵特判），候选交 L10b 裁决 |
| **RED-INTEGRITY S1-S3 门卫自代码裁定链（C3）** | 同上 `red_integrity()` | **（2026-09-05）**bash/python 裁定链静默 fail-open：S1 `\|\| echo` 空壳兜底（A8 家族）/ S2 `echo -1` 哨兵（A7 家族）/ S3 py score `-1` 默认（appeal/adjudicate/monitor 相邻族）。**有界聚合安全网**：只计数 + 样例≤8 / 文件 `GK_RED_SELF_MAX_KB`（默认 8192）超限显式 `RED-INTEGRITY-SELF-SKIP` INFO / 单行 ≤65536 跳过 / 确定性（重复运行同一 finding 集 → I9 `evidence_hash` 去重防 state 膨胀）——适配对齐 A8 聚合器输出契约分流 + I9 写回去重先例 |

### 5. 门禁安全网（Gates）— 工具调用/阶段切换硬门禁

| 安全网 | 位置 | 作用 |
|:--|:--|:--|
| pre_tool_hook Gate 0-8 + R0.1-R0.4 | `scripts/pre_tool_hook.py` | Task 拦截 / 危险命令 / 脚本扫描 / 插件裸调 / stage / worktree / 路径 / CLI pre-tool-check / 技能自维护防裸跑 |
| guard-edit | `gatekeeper-cli.sh guard-edit` | PROTECTED_REGION 保护区 + 行号级精确拦截 |
| advance 三路径门禁 | `gatekeeper-cli.sh advance` | 路径/状态/门禁验证（_state_checksum_verify 入口） |
| F8.1 远端验证 | `gatekeeper-cli.sh _verify_remote` | push 前远端 URL 白名单校验 |
| Gate 8 技能自维护 | `scripts/pre_tool_hook.py _gate8_*` | 技能代码写操作须 open finding 或活跃 R-phase |

### 6. WASM 与 CI 安全网（WASM & CI）— 编译/CI 管线

| 安全网 | 位置 | 作用 |
|:--|:--|:--|
| wasm-pre-check（P0-P7 --auto-fix） | `gatekeeper-cli.sh pre-check wasm` | WASM 构建预检 + 自动修复（auto-fix 安全网雏形，W9 通用化待 R-T8） |
| wasm32 sentinel / 溢出检查 | `spz.cc`（V11/V12） | wasm32 reserve 截断 + sentinel 校验 |
| CI：zizmor / SHA pin / Harden-Runner | `.github/workflows/` | Actions 安全扫描 / 固定 commit SHA / 出站流量监控 |
| actionlint / CMake / CTest | CI 管线 | workflow 语法检查 / 构建测试验证 |

---

## 新鲜度检测与回流（2026-09-05）

> **检测结论**：本总表此前停更于 2026-08-28 口径；2026-09-05 A7/A8 批次 + C1-C3（评估 §15）机制已回流登记（上表 cat 2/3/4）。
> **适配判定（C3 扫描器安全网）**：C3 为确定性引擎阶段子扫描（非插件加载/非序列节点/非迁移分类）→ 不适用 plugin-loading-test-framework（加载五源分流）、sequence-node-safety-net-template（SN 五元组）、bashpy-problem-taxonomy；适配 = **运行时输出契约分流（A8 先例）** + **I9 evidence_hash 去重防 state 膨胀** + 有界聚合/文件上限/行长上限/确定性（本表 RED-INTEGRITY S1-S3 行）。三份领域模板无机制面变更，无需更新。
> **C2 说明**：ECC-FINDING family/cover_layers/gap（`finding register --family/--cover-layers/--gap`）为 E2 缺陷族元数据扩展，非安全网，归评估 §15.2 C2 行。
> **C8 追加（2026-09-05，f7 L10b 爆破修复）**：ECC 裁决契约绑定 = `<state>.finding-journal.jsonl` append-only 第二副本锚（register/verify/close 全量入账 + `basis_ref` 绑定 evidence_hash）+ `finding reconcile` 重放对账状态机 + self-check #21 `finding_journal_reconcile`（无 journal 前序事件的 closed/fixed/rejected = 伪造裁决候选；journal 缺失/state 回滚/记录被删均显式异常）。**C8b（同日）**：advance 余烬导出把 journal 嵌入 `.gatekeeper.ember.<phase>.json` 的 `finding_journal` 字段（第二副本锚入余烬不可烧失）。定位：**人威胁缓解——L10b 从"可信单点"降级为"留痕+可重放+可质询"的审计可见角色**（防"人工裁决输出被全部篡改无痕"）。
> **C10 + A3 追加（2026-09-05，ember-replay-audit，plan-refinement SCR 收敛 sub-1788622220-32-23687）**：ember 快照回判 = `cmd_replay --ember [phase]`（§12 决策重放统一入口）读 `.gatekeeper.ember.<phase>.json`——**slice 基准 + 相位作用域 + pre-C8 epoch 豁免**（防跨相位合法 closure 误报/旧快照全量假阳性）——跑 archived finding reconcile（`gk_finding.reconcile_pair` 单源）+ self-check #22 `ember_replay_audit`；**A3 最小 seal（同批前置）**：余烬导出以 Ed25519 audit key 签规范化 payload（`gatekeeper-cli.sh::ember 导出块`），读侧 `verify_seal` 验签（invalid 阻断 / 缺签 integrity-unverified 降级标注 best-effort）；新增 `ember list/get/verify`（get_state_history 同构只读面）。痕迹独立对象（`--out` 写 ember_replay_report），不并入 audit --report（防自指回环）。定位：**审计重放从"仅 live 声明字段重查"扩展到"时间旅行回判存档快照"**（F7 协调篡改面经 seal 收敛为可检出；"审计报告=余烬之一"闭环经 replay 可复读）。
> **C10 不适配判定（2026-09-05，同 C3 f5 先例，回应 H-SLSN 加载网质询）**：C10 的 ember/replay 为**常驻内置脚本**（CLI 显式路径调用，同 `_replay.py`/`gk_audit_*`），非按需加载插件/技能/序列节点 → **不适用 H-SLSN 加载网 / plugin-loading-test-framework / sequence-node-safety-net-template**（无 manifest cap/五源分流/SN 五元组需求）；已在本文档总表登记 + self-check #22 接线即为其"安全网留痕"。若未来 gk_ember_replay 插件化/按需加载才须走 loader 协议。
> **C9 追加（2026-09-06，PR-SCORE 双盲评分锚定，plan-refinement SKILL.md 8.2.1）**：双盲评分（主 agent F1-F7 + 7 维 vs subagent 自评）产物锚定——**禁止只落会话/计划文本**（事后可改无锚，评估 §15.6 ⑨ 人威胁面收口）：`pr-score seal --plan <计划> --score <score.json>` → 独立快照 `.prscore-<plan>.json`（plan 同目录**入库可 diff**）+ 计划 `<!-- PR-SCORE -->` 区块 + **A3 seal**（复用 gk_ember_replay `verify_seal`/`canonical_bytes` 单源；无 audit key fail-loud）；防覆盖（区块已存在拒绝重写）+ `pr-score verify`（seal 验签 + 区块↔快照字段一致性）+ self-check **#24 `pr_score_anchor`**（无快照 SKIP）+ doc_freshness(C6) 守护接口登记（C6 挂起）。首锚 dogfood：2026-08-28-security-hardening-assessment（2026-09-06，主 agent 单侧评分，双盲 subagent 对照待真实质询产生）。定位：**双盲评分从"会话产物"升级为"git 可审计 + seal 可验 + 快照可回判"的双副本锚**（评分被篡改/伪造 → verify 检出）。
> **C4/C5/C6 追加（2026-09-06，§15.6 ⑳）**：**C4 RED-META-01/02 越权读探测** = self-check #25 `red_meta_read`——01 归一单源启发式（直读 `.gatekeeper.scopes.json` 代码点枚举，无 `_gx_norm_path` 调用 = warn 高嫌疑）；02 registry↔scopes 双源交叉复验（#19 只见 scopes 内部，gitnexus registry 路径嵌套 scopes 根 = 越权读面候选；V3 反向显性化）——candidate findings 交 L10b 裁决（WARN 非门禁）｜**C5 STAGE_3 round-log 门禁** = node_guard STAGE_4 出站守卫（gk_node_guard `round_log_from_gate_data`：≥2 轮审查点检 + 轮间红队挖洞证据齐全才 ok；缺失 advisory / GK_GUARD_STRICT=1 硬阻断）｜**C6 doc_freshness 检查器**（doc-align 新检查器：本总表须含最近登记批次时间戳字面 + ≥1 机制登记行，停更即 FAIL——⑧ 停更 11 天无检查器发现的修复）+ project_rules **3 盲区族红旗**（环境当门禁红/崩溃当实质、双形态嵌套根跨租户读面、子检查器 FAIL 被 exit 0 掩盖）。
> **㉑ 三视图梳理登记（2026-09-06，§15.6 ㉑）**：C1-C10 加固机制 × 既有检测器做**检测范围/检测机制/数据流向**三视图映射（观察待办，非承诺队列）。即时结论：audit--hook = 结构存在性断言无行为级验证（覆盖窄于宣称）；monitor --local = L9 确定性车道需 master state；实证旧审查机制三类滞后（机制层/检测器层/双实现漂移面，前两类已修，双实现见下）。
> **㉒ A7 monitor 裁定侧守卫缺口登记（2026-09-06，§15.6 ㉒）**：RED-INTEGRITY-08 逐项定性——**gk_monitor_api + bash _monitor_api 双侧真洞**：LLM 返回合法 JSON 但缺 `overall_score` → -1 哨兵 → BLOCKED **落盘 monitor_scores + ok:true**（A7 假否决相邻族；cmd_appeal/gk_appeal 同款 schema 守卫缺失，gk_adjudicate 良态）。RED-INTEGRITY-06 抽样 45 处定性：S1 单行判定过包含（多为 enrichment/advisory 显式空标记兜底），漏多行/printf/`|| true` 形态 → S1 范围注记。**monitor 双侧守卫已实装（§15.6 ㉔）；S1 分级待定案**。
> **㉓ appeal 薄壳改造登记（2026-09-06，§15.6 ㉓，bashpy）**：cmd_appeal 降为 bash 薄壳（env/API_KEY 解析 + 委托 + JSON 透传 + fail-closed），域逻辑单源收拢 **gk_appeal.py**——D3/A7-sentinel/粘性否决/mediation/记录写回/schema 守卫不再双打；endpoint/model 解析链 `--base/--model` → env → deepseek 默认（原 twin 硬编码 deepseek 与 bash ${API_BASE} 两源统一）；A7 错误码对齐 legacy（APPEAL_API_UNAVAILABLE/APPEAL_RESPONSE_INVALID RETRYABLE 不落记录）+ 粘性/FOREIGN 补 `allowed/reason` 兼容字段。bashpy-migrate pin 0.2.3 在位验证；test_gk_appeal 23 + 全量 pytest 1408 绿。
> **㉔ monitor schema 守卫实装 + 三视图映射登记（2026-09-06，§15.6 ㉔）**：monitor 裁定侧闭合 ㉒ 真洞——gk_monitor_api + bash _monitor_api 均补 `overall_score` schema 守卫（缺/非数值 → 失败链/`MONITOR_RESPONSE_INVALID` RETRYABLE，未落 -1/BLOCKED，与 cmd_appeal/gk_appeal 同构）；test_gk_monitor_api +1、bash -n OK、全量 pytest 1409 绿。三视图映射产出（范围/机制/数据流向 C1-C10×检测器）：加固集中于写路径数据面（journal/ember/seal/reconcile），检测器集中于静态/存在性断言面——**运行面行为级检测器 = 下轮 L 层首要缺口**（audit--hook 无行为级端到端；monitor --local 需 master state）。
> **㉕ 管道接线三点 + 评估器落点定案（2026-09-06，§15.6 ㉕）**：实证修正——hook 拦截事件管道已通（hook_block_log → 余烬 prev_entry/gate_data_full → history 归档 → HOOK-05/06 实时读），缺**回放消费端 + E2 登记端**：(a) ember replay 增 hook_block_log slice 回判；(b) monitor --local L9 FAIL → 自动 E2 register；(c) audit--hook 行为级 payload 回放 harness（纯本地确定性，落测试层/E4）。**落点修正（同日用户质询）**：E1-E4 家族 = **计划质询（plan-refinement SCR）协议的子集评估器**——决策/收敛层复用质询统一入口（对象=REVIEW_LAYERS 矩阵，SCR+F1-F7+审计留痕+PR-SCORE/A3 锚继承），不新建平行收敛 CLI（F4/F1 反重复）；确定性件降为**证据探针**（audit --coverage 只产变更面事实、E2 finding gap、E4 #20、hook payload harness、hook_block_log 回判），home 不变。子集化新扩展 = plan-refinement 增"审查层矩阵对象 + 证据注入"任务模式（登记待定案）。**接线推进（§15.6 ㉖）**：(a) 已实装（reconcile 增 hook_block 切片一致性回判 +5 测试）；(c) 盘点=行为测试已大部存在（R0.2/R0.3/R0.4），剩余为矩阵补缺；(b) 待定。
> **㉗ 子集化质询收敛登记（2026-09-06，§15.6 ㉗）**：plan-refinement 质询 v2.2 收敛——E1-E4 挂既有确定性检查面（doc-align/self-check/monitor，check_cross_review_matrix 同构），禁新 CLI/新派工通道/全 LLM 评分/定性覆盖主张；审查层矩阵对象（E1-E4 ∩ C1-C7 空白矩阵 + pairwise 去相关列）与证据注入任务模式规格**落独立 references/*.md** + doc_freshness 守护 + [ASSUMPTION]/回退/成本三件套；F2/F5/F6 待 §15 尾段续读复评 sealed。**(c) 补缺**：`_wsl_quoting_trap` +8 行为单测补齐（盘点唯一真缺口）。
> **㉘ 子集化第二跑 sealed 登记（2026-09-06，§15.6 ㉘）**：窄工件（e1e4-subset-convergence.md）全读后 **SEALED-PASS（条件性）**，F1-F7 全 ok、F2/F5/F6 关闭。定稿：落点 = doc-align run_all sibling 检查器（check_cross_review_matrix 同构）；规格单文件 references/e1e4-evaluator-matrix.md；绑定句（cell FAIL/WARN→仅 E2 finding 登记 family=EVAL-MATRIX→SCR 质询，检查器只产证据）；A1-A5 三件套；pairwise 六对 disjoint；回退三态；E1 cell GK_ALLOW_NO_DETECT 条件化；数据流 E2→journal(C8)→ember→replay(C10) 零新管道。subagent 读证机制注记：截断=token/item 预算硬停（200k/411k hard）；plan-refinement 默认中间档、无按体积自动升档（--tier 显式）；修复=窄工件+≤tier2/80K+0-API 降级链；自动升档/切片续读 = 观察待办。
> **㉙ 规格落盘 + 检查器实装登记（2026-09-06，§15.6 ㉙）**：① 规格单文件 references/e1e4-evaluator-matrix.md（E1-E4×REVIEW_LAYER_MATRIX 矩阵对象契约/pairwise 六对 disjoint/绑定句→E2 finding→SCR/WAD/A1-A5/回退三态/`EVAL-MATRIX 追加` 守护行）；architecture-overview 文件地图同步（新增 references 文件必须登记，否则 audit_docs declared/actual 对账 FAIL——纪律注记）。② `check_eval_matrix` 实装挂 doc-align run_all（结构 lint + E4 单源共享 + 反建设 A4），TestEvalMatrix 9 用例；全量 1431 passed / 0 failed；ruff 无 F。③ 证据注入任务模式 = 待下批（契约 §2 已 sealed）。
> **㉚ ③ 证据注入任务模式实装登记（2026-09-06，§15.6 ㉚，E1-E4 全链落地）**：注入点 = cmd_plan_refinement task 组装（`gatekeeper-cli.sh::cmd_plan_refinement`）；evidence 契约真实位置 = `scripts/subagent_runner.py` 的 evidence 段（file:line_range）。触发单源 gk_doc_align（is_eval_matrix_object：任务含「审查层矩阵」/「E1-E4」| basename e1e4-evaluator-matrix.md | force/GK_EV_MATRIX_EVIDENCE）；inject_preflight_evidence 未触发原样返回。bash 注入段仅触发注入【preflight 证据摘要】(a)doc-align 状态 (b)round-log (c)E2 family=EVAL-MATRIX finding + 入口 file:line（inspect 动态行号，单源失败 N/A 不阻塞）。A4 合规无新 CLI；TestPreflightEvidenceInjection 6 用例；全量 1437 passed / 0 failed；ruff 新 F=0；bash e2e 受 IDE hook 拦截未实跑（pytest 子进程锁 CLI 契约）。
> **㉛ 交叉审查车道绑定 + API key 判定全链（2026-09-06，§15.6 ㉛，用户质询"L2-L5 绕过 + IDLE 裸跑 + API key 误报"）**：**hook Gate 1b（新）**——交叉审查车道节点绑定：IDLE/DONE review 形态 BLOCK（kind=review 留痕入 hook_block_log）；active 非审查节点 + subagent/LLM 车道（--crossrev / monitor --subagent / monitor --api / plan-refinement）→ BLOCK（对齐 CLI CROSSREVIEW_NODE_BINDING：standard STAGE_3|AUDIT-CROSSR / standing ECO-READ|ECO-AUDIT；GK_DEGRADE_REVIEW=1 显式豁免）；确定性证据车道（audit --crossr/doc-align/self-check/monitor --local/audit --red 等 0-API）任意 active 阶段放行。TestReviewNodeBinding 14 用例；test_pre_tool_hook 109 passed。**API key 误报根修（CLI env_integrity）**——旧实现只看 WSL env（bash-only）→ 忽略 PowerShell User/Process 边界回退 → 有 key 误报 MISSING → agent 错误断言"无 key"跳过 L2/后R 双独立 subagent 车道；改走 `_resolve_api_key` 全链（GATEKEEPER→DEEPSEEK→PS User→Process）+ `_validate_api_key`（SET/INVALID/MISSING 三态）；实测 WSL env unset 仍 API_KEY=OK(deepseek)。判定源唯一化 = env_integrity + _resolve_api_key（SKILL.md Red Flag 已纠正：--local 不代表无 key）。
> **㉜ E1 audit --coverage 实装（2026-09-06，§15.6 ㉜，变更面证据探针非收敛 CLI）**：[gk_audit_coverage.py](../scripts/gk_audit_coverage.py)（main(argv=None) #23 对齐）：文件面 git diff --name-status + 符号面 gitnexus detect-changes（可降级）→ 组件分类 → 11 层需求映射 → NO-DETECT 零变更层标注 → digest。A4 合规扩展 cmd_audit（无新 _CMD_REG 命令）；test_gk_audit_coverage 21 passed + test_pre_tool_hook 109 passed（共 130）；bash -n OK；CLI 端到端实测 skill 仓 HEAD~3 NO-DETECT [L3,L4,L5,PR] 证据正确。**至此 E1-E4 四评估器全落地（E1/E2 C2/E3 C5/E4 C1 #20）**。
> **㉝ ㉕(b) L9 FAIL→E2 register 实装（2026-09-06，§15.6 ㉝，㉕ 接线三点全闭环）**：cmd_monitor --align（L9 三件承载）汇总后任一 `l9_*` FAIL → 自动 gk_finding register（family=MONITOR-LOCAL, cover_layers=L9）→ finding-journal(C8)→余烬→replay 闭环；register 幂等；仅 l9_* FAIL 触发；GK_L9_AUTO_E2=0 关闭。E2E 双态冒烟：坏态 entropy 0.9 → 自动登记 1 条 open + journal 1 行；好态 0 登记。定位：L9 门禁失败从"仅报告"升级为"可审计 finding 留痕 + 可回放"（C8/C10 证据链闭环）。
> **㉞ standing 交叉审查同源 + 全量扩展机制 runbook（2026-09-06，§15.6 ㉞）**：实证 standing 与 stage-3 交叉审查 = **同一套 L1-L10（单源 stage-3-review.md）**，standing 审查节点 = ECO-READ/ECO-AUDIT（2026-09-04 L2 --crossrev 实证）；定案**不新增 worktree/state**（standing META worktree_needed:false），advance STAGE_0→ECO-READ 即合法审查节点。**runbook 固化**（stage-3-review.md 新增段）：承认此前只跑映射表"主命令"列、丢弃每层扩展点已实装机制（L1 git-workflow/concurrency、L3 pdg、L5 taint、L6 v3、L7 supply、L10 red+bomb…）；执行序 0-13 钉死（E1 前置→L3 先行→L2 crossrev→L4/L5 人工→L6→L7/L8→L9(㉕b)→L10→质询→后R 双独立→E2 处置）。**全量实跑中（确定性+非确定性）**。
> **㉟ standing 全量 L1-L10 实跑记录（2026-09-06，§15.6 ㉟，ECO-READ 节点）**：确定性全机制（E1 coverage/L1 crossr/L3 pr+pdg(TAINTED 0)/L6 doc-align 0/L7 hook 6/6+supply/L8/L9 align(advisory)/L10 red stations=15+bomb write_guard）全绿级；非确定性 L2 --crossrev + plan-refinement 质询实跑通过（spec 吻合、SCR kept/slashed 处置、runbook 三件套补录）；E2 register ECC-0EB59C9CE707（RED-TAXONOMY/L10，L10b 裁决队列）→ journal(C8)。产物 docs/analysis/2026-09-06-standing-full-crossreview.md。遗留：gatechain marker 名实错位/后R 双独立(合并域) defer/PR-SCORE 重锚/L10b 裁决。
> **㊱ ECO-EDIT ruff F 24 清零 + red write_guard 8 L10b 裁决（2026-09-06，§15.6 ㊱，ECO-EDIT 节点）**：ruff --select F 24 清零（prod 8 + test 16）RUFF_EXIT=0 + 回归 474 passed 零破坏。**L10b 裁决 ECC-0EB59C9CE707 = bomb write_guard 8 函数逐项取证 → 8× EXEMPT（无真缺口）**：唯一 check 语义入口（advance --check、node-guard/plan-refinement --check-only、docgen --check）均不触达这批 bash 写入者；_write_gate_data 调用方已在守卫内 / _verify_remote 纯读（扫描器误归属）/ cmd_push 写仅真实失败路径 / cmd_cron+cmd_audit 写属 by-design 簿记·持久化域且无 --check / monitor 函数调用在 advance 守卫内。机械补守卫会引未定义 dry_run 变量误阻断写入 → 8 函数头防御注记 `[write_guard 裁决 2026-09-06 EXEMPT]`（零行为变更）+ E2 close（verify_source=adjudicated-writeguard-exempt）。遗留 ④⑤ 关闭；**遗留 ① 更正（用户澄清）**：last_release_check = 对比静态基线 vs 最新版本判定"增量刷新 or 重建基线"的决策输入（gitnexus 元数据中枢入库建基线，避免重复生成、平时仅增量刷新核查），非名实错位——① 收口注记，无代码改动。
> **㊲ ECO-AUDIT 域门禁推进 + 后R 双独立登记（2026-09-06，§15.6 ㊲，ECO-AUDIT 节点）**：adjudicate(stage=ECO-EDIT F1-F7 PASS 0.95)→advance ECO-EDIT→ECO-AUDIT ok→plan-refinement 质询 seal(F1/F4/F7 ok, F2/F3/F5/F6 suspect)→全量 pytest 1472 passed(F3 关)→audit 五域串行聚合落盘 ok(证实 --all 并行 parse failed=竞态)→**后R 双独立** #1=sub-1788713923-426-5975(EXEMPT 证据锚定视角) + #2=sub-1788714386-531-16387(seal 前置时序视角)，车道互斥/覆盖矩阵不相交。**[ASSUMPTION] EXEMPT 永续前提**：(a) 三命令无 --check 为核证事实，框架新增 check 入口须重评 EXEMPT；(b) _verify_remote 误归属=扫描器启发式局限，bomb 复报属预期→登记核对非重新裁决；(c) 回归以全量 1472 为准。**seal 前置拆分**：pre=doc-align+doc_freshness(C6 登记后)；post=self-check #24+pr-score verify；seal=最后写者。**阻断点**：audit --all 并发 bug(E2 ECC-F78E1B1EF083 open/CLI-DEFECT)、C6 doc_freshness 登记挂起、PR-SCORE 重锚首锚区块轮换/审批待定。
> **㊳ 全量交叉审查复验(7ade96f..HEAD)+bomb 789 归因+seal 阻断详细登记（2026-09-07，§15.6 ㊳，ECO-AUDIT 节点）**：确定性车道全绿（E1 coverage ok / L1 crossr rejected=0 / L6 doc-align PASS / L7 hook ok / L8 self-check PASS(API_KEY=OK(deepseek)) / L9 monitor 1.0 PASS / L10 red 15 match + bomb 复扫计数一致(write_guard 8 EXEMPT 维持,dangerous 2)）；质询+后R 双独立已跑；ruff 0+pytest 1472+bash -n → **修复未引入错误/新漏洞**。**789 归因**：基线 2026-08-27=667→789(+122：inline+35 swallow+33 fd+11 case_sensitive 43=新检测器类别 danger 0)；7362 行/48 cli commits 复现旧模式=再引入门禁缺失+batch8 未完成(inline 224→174→209 回退)。**write_guard vs gitnexus**：bash 路径=函数体子串启发式(无 AST/调用图，误归属根因)，python 路径=真 AST；gitnexus 图级多语言但 16 语言无 bash——融合=调用点定位修复+python 侧图核证+复报豁免注册(ECC-8A6793D923ED)。**E2 7 open 下一轮集中**：F78E1B1EF083(audit--all 并发)/7F97632CAFA0(C6 挂起)/3E10D111D382(PR-SCORE 轮换)/35E1926F483D(--report AUDIT-STATE 替代)/E75A3C2E8FE6(standing 编辑预算/冲突控制)/C66D7831EF73(789 归因+防再引入 gate)/8A6793D923ED(write_guard×gitnexus 融合)。**［更正注记 2026-09-07：㊳"修复未引入错误/新漏洞"=确定性车道子集口径，L2/L3/L4/L5 与 L10 全量扩展未跑——全量验证待 P0 ledger+批① 补跑后以 ledger 为准。］**（E2 处置单归属更正→㊶）
> **㊴ runbook→交叉审查统一启动入口定案 + A/B/C 质询（2026-09-07，§15.6 ㊴，正交评估器 sub-1788745839）**：runbook 唯一作用=并行编排；gitnexus 调用路径唯一（_run_gitnexus，禁重复实现）；A/B/C 作为质询项跑严格质询。**质询结论 F1/F3 ok 其余 suspect**；五项事实核证为真；slashed=平行 ledger 消费点(合并 C5 node_guard round_log)/python 再实现 node 探测；kept=P1 唯一 spawner(_run_gitnexus PATH→Windows→/usr/bin/node)+唯一 argv 层(_gitnexus_cmd export env)+删 pdg_check 硬编码；P2 预算 enforcement(G1 注入+hook BLOCK kind=budget+flock 扣减经 CLI 单写者+GK_BUDGET_OVERRIDE 逃生舱)；P3 融合批。**收敛缺省**：ledger 校验=advance 出口单咽喉+node_guard 谓词扩展，hook 只守车道；预算 ECO-EDIT 缺省 15(GATEKEEPER_EDIT_BUDGET 覆盖)［漂移修正 ㊵：改为 standing 节点注入 remaining=调度器 current_lr（cosine 退火上限 max_lr=4，现 ECO-AUDIT=2）］，guard-edit/pre-tool-check 经 state-patch(flock)扣 1，advance 注入即重置；7E2 序=C6 登记→write_guard×gitnexus 取证→789 防再引入→audit--all→--report→standing 预算→PR-SCORE。实现押下一轮；gitnexus ProgramData 身份缓存被拒需固化(入 P1)。E2 单归属更正→㊶。
> **㊵ ABC 质询结果漂移检测 + 批次路线图（2026-09-07，§15.6 ㊵）**：漂移检测 6 项——5 锚点**无漂移**（G1 gatekeeper-cli.sh / pdg_check 硬编码 d: node / pre_tool_hook 仅快照 / 7×E2 全在 state open / stage=ECO-AUDIT scheduler cosine max_lr=4 current_lr=2 edit_budget=null）；**漂移 1 项已修正**＝㊴ 预算缺省"15"与 SkillOpt cosine 上限 4 冲突 → standing 节点预算＝advance 注入 remaining=调度器 current_lr（现 ECO-AUDIT=2，GATEKEEPER_EDIT_BUDGET 覆盖），guard-edit/pre-tool-check 经 state-patch(flock) 扣 1，advance 注入即重置。**批次路线图（修正版 ㊶，去重单归属）**：批①=AST 互补(write_guard×gitnexus)+**6 项 E2** 按序(①C6 登记 7F97632CAFA0→②融合取证 8A6793D923ED→③audit--all 并发 F78E1B1EF083→④--report 替代 35E1926F483D→⑤standing 预算 E75A3C2E8FE6=P2→⑥PR-SCORE 轮换 3E10D111D382)+P0 ledger/P1 单路径/P2 工程；批②=**C66D7831EF73 单归属**（逐行 blame 归因+新增代码防再引入 gate（bomb 漂移检测接入 CI/self-check），依赖批①融合取证后 close）；批③=盘点可处理的新引入项，余下划入 batch8 剩余待办。
> **㊶ 38/39/40 计划去重漂移检测（2026-09-07，§15.6 ㊶，串查 ㊳/㊴/㊵）**：重复项判定+单归属——①E2 7 项三记录重复列示 → 批①6=7F97632CAFA0(C6 前置)/8A6793D923ED(融合)/F78E1B1EF083(audit--all)/35E1926F483D(--report)/E75A3C2E8FE6(预算=P2)/3E10D111D382(PR-SCORE 延后)；批②1=C66D7831EF73(789 归因+防再引入 gate，依赖批①②融合取证)→ **批①计数 7→6（C66 去双归槽）**；②standing 编辑预算跨 ㊳/㊴/E75A 重复 → 收敛以 E75A+P2 为准；③write_guard EXEMPT/误归属跨 ㊱/㊳/㊴ → 主记录=㊱，其余引用；④P0 ledger 定义仅 ㊴，无重复；⑤漂移核验：E2 id 与 state open 7 一致、scheduler current_lr=2 一致、预算=current_lr(cap4) 一致。
> **㊷ 批①-2 write_guard×gitnexus 融合取证 + 复报豁免注册（2026-09-07，§15.6，ECC-8A6793D923ED）**：取证结论——(i) bash 误归属根因实证 = 插件 `_bash_write_guard_issues` 函数体子串匹配（`any(w in body)`）+ `extract_functions` 花括号平衡切片无引号/注释感知 → 兄弟函数注释中的写函数名落入相邻切片（`_verify_remote` 纯读因 cmd_push 段注释含 `_state_write` 被记名，0 真调用点）；(ii) gitnexus 16 语言无 bash → gatekeeper-cli.sh 无法图级调用点核证，融合只能落「插件上游调用点定位（循环 B 记录）」或「技能侧豁免注册」；python 侧 gk_*.py 已真 AST 无此局限。**落点 = 复报豁免注册**（bashpy-problem-taxonomy §2.5 新表，8×EXEMPT 函数→行号→裁决依据→复报处置=核对非重裁决，背书 ㊲ [ASSUMPTION](a)(b)），技能仓内零代码改动；插件调用点定位修复记为上游需求。E2 close（verify_source=adjudicated-writeguard-exempt-registered）。
> **㊸ 批①-4 audit --report standing 签名判据替代（2026-09-07，§15.6，ECC-35E1926F483D）**：audit --report 签名门槛旧判据只认 standard AUDIT-STATE 相位（`audit_phases_completed`），standing 序列（ECO-* 无此相位）+ history 空 → 硬拒 Cannot sign audit report（实测复现）。修复 = 判据扩展：`AUDIT-STATE in phases` OR（`project_type=standing` AND gate_data 含 ≥1 五域证据落盘 audit_state_result/audit_docs_result/audit_memory_result）——五域证据=等价证据已收集判据。实证：standing state 判据复算 verdict=yes → audit --report --type performance --force 冒烟 ok:true 生成报告；bash -n OK；受影响套件 141 passed（冒烟产物 ecc-audit-*.md gitignored 但污染文件地图检查 → 已删后 86 passed 全绿）。E2 close（verify_source=fix-audit-report-standing-evidence）。**2026-10-28 E2 追改**：该「≥1 域」口径已收紧为「相位 + 有生产者两域 all-of」（见 ㊻ 同批注）。
> **㊹ 批①-5 standing 编辑预算 enforcement（2026-09-07，§15.6，ECC-E75A3C2E8FE6=P2，㊴/㊵ 收敛缺省实装）**：三面落地——① **注入**（scripts/gk_advance.py `_run_nonstandard` standing 成功路径）：advance 进入节点时注入 `edit_budget={max,used:0,remaining}`，remaining = `GATEKEEPER_EDIT_BUDGET` 显式覆盖，否则调度器 `current_lr`（cosine 退火，上限 max_lr=4，2026-09-07 ECO-AUDIT=2）；dry_run 零副作用不注入；standard 语义不变（回归锚 test_standard_edit_budget_semantics_unchanged）。② **扣减/阻断**（gatekeeper-cli.sh pre_tool_check edit 分支 G1）：BLOCK 对全 project_type 生效（remaining=0 拒，GK_BUDGET_OVERRIDE=1 逃生）；**扣减仅 standing**（remaining≥1 → 放行扣 1，经 `_state_write` flock 单写者；standard remaining 由 advance 快照控制不在 edit 放行处扣）。③ **hook kind=budget 留痕**（scripts/pre_tool_hook.py Gate4）：CLI pre-tool-check 失败且含 edit_budget → `_CALL_KIND="budget"`（_block_log_snapshot/audit --hook 可按 kind 区分）。**E2E 冒烟全链**：注入 2 → run1 扣至 1 → run2 扣至 0 → run3 BLOCK exhausted → override 放行不扣；state 恢复 checksum OK。**相邻缺陷修复（同批）**：`cmd_finding` 写类子命令（register/close/verify）后补 `_state_checksum_write`——根因 gk_finding.save_findings 直写 state 不重算 `_checksum` → 每次 E2 处置破坏 state checksum（guard-edit/advance 误报 TAMPERED）；实测 close 后 checksum 保持匹配。测试：test_gk_advance +5（注入/override/dry_run/standard 回归）、test_pre_tool_hook+test_gk_finding 等 266 passed；bash -n OK。E2 close（verify_source=p2-standing-budget-enforced）。
> **㊺ 批①-6 PR-SCORE 重锚轮换路径（2026-09-07，§15.6，ECC-3E10D111D382，C9 追加）**：首锚后重锚门禁——旧行为：plan 已含 `<!-- PR-SCORE -->` 区块即 `pr_score_block_exists` 硬拒且**无任何显式重锚通道**（首锚错误/评分迭代需整锚重做或违规手改）。修复 = **显式 --rotate 轮换路径（人工审批）**：`pr-score seal --plan <p> --score <s> --rotate` → 写快照前探测既有区块（防半态：先写快照才发现冲突）；rotate 时旧快照 `_archive_snapshot` 归档为 `.prscore-<plan>.<sealed_at>.json`（跨平台安全名：Windows 禁 `:`，时间戳冒号替换 `-`；归档内容=旧锚全文保留，verify 仍读当前）+ 新区块 `_replace_block` 原位替换（`re.sub` count=1，git 历史保旧锚，不自制归档系统）；**注入失败半态回滚** = 删已写新快照（`snapshot_rolled_back:true`，归档不移回——旧锚不因回滚丢失）。不带 --rotate 保持硬拒（防静默覆盖锚）。测试：test_gk_pr_score +3（rotate 归档+原位替换+verify anchored / rotate 首锚=plain inject / 注入失败回滚删快照+归档保留）；**实现缺陷修复（跨平台）**：归档名原含 ISO 时间戳 `:` → Windows os.rename OSError → 静默丢归档，消毒正则放宽为 `[^0-9A-Za-z._-]→-`。15 passed 全绿；bash -n OK；CLI usage 已含 `--rotate` 文档。E2 close（verify_source=pr-score-rotate-sealed-path）。
> **㊻ 批①-P0 ledger 审查出口强制门禁（2026-09-07，§15.6，㊴/㊵ 收敛缺省实装；合并 C5 出站守卫）**：standing 审查节点（ECO-AUDIT）此前**无任何出口 ledger 门禁**——出站仅 advisory 提示（_eco_prereq_heuristic），"只跑部分审查/跳过审查就 advance ECO-DOC" 无强制拦（㊳ 更正注记：确定性子集口径曾被泛化为全量）。实装：① **谓词单源** [gk_node_guard.py](../scripts/gk_node_guard.py) `review_exit_gate(node, gd)`——STAGE_4（C5 既有）与 ECO-DOC（P0 扩展）共用 round-log（≥2 轮审查+轮间红队）判据，ECO-DOC 另叠 `_GATES["ECO-DOC"]` audit --all 记录前置（**2026-10-28 E2 起 = 有生产者两域 all-of**：`audit_state_result` + `audit_docs_result`；原「五域证据任一落盘 / legacy `audit_result`」已废，单域不再放行）；node_guard("ECO-DOC") + guard CLI state 注入 round_log/audit_all 扩展（`node-guard ECO-DOC --check-only` 只读核对面）。② **出口单咽喉消费** [gk_advance.py](../scripts/gk_advance.py) `_run_nonstandard`：standing ECO-AUDIT→ECO-DOC 出口判 ledger——`GK_GUARD_STRICT=1` 硬阻断（state 不推进，防节点绕过）；默认 advisory（ok 放行 + `ledger_advisory` 附核对，二分语义对齐 standard C5）。hook Gate 1b 只守车道不担 ledger（㊴ 定案）。**验证**：node-guard ECO-DOC --check-only 实测 live state round_log ready（11 轮）+ audit_all true；test_gk_node_guard +5、test_gk_advance +3；**相邻既有漂移修复**：test_gk_c47_ext test_pass_fresh_total fixture 仍写 2026-09-06 而 RECENT_BATCH_TS 已 bump 2026-09-07（b1a C6 登记遗留）→ fixture 对齐 09-07。全量 pytest **1487 passed** / ruff F 0 / doc-align doc_freshness PASS。
> **㊼ 批② bomb 789 归因 + 防再引入 gate（2026-09-07，§15.6，ECC-C66D7831EF73）**：**blame 归因产物** `docs/analysis/2026-09-07-bomb-789-blame.md`（内部 docs，不随公开包导出）——函数级逐 token git -S 归因（_state_write/_write_gate_data/monitor/cmd_push/cmd_cron/cmd_audit → 各自引入 commit），inline 209 回退归因 batch3a/DS 大改 commit；**诚实边界**：case_sensitive/swallow/fd/danger 类别计数 = 插件扫描器模式类无唯一 token → 逐行/category blame 权威复跑属插件循环 B/CI 域，技能侧只守确定性面。**taxonomy §2 补录**（bashpy-problem-taxonomy.md）：2026-09-07 观测注记——667→789(+122)、inline 209 回退、swallow+33/fd+11/danger 0、**case_sensitive 43 = 新检测器类别循环 A 基线补录项**。**self-check #26 `check_bash_write_drift`**（gk_self_check.py）：确定性防再引入 gate——① FAIL 硬：EXEMPT 注记数≠8（§2.5 注册表静默删改）或 EXEMPT-8 函数名消失（注册表↔代码漂移）；② WARN advisory：新增**未登记顶层 bash 写函数**候选（写 token 归属函数 ∉ _KNOWN_BASH_WRITERS 注册表 → L10b 裁决队列）。归属算法 = 顶层函数序段划分 + 注释跳过 + 头部自归属（规避 bash 无 AST 切片歧义，同 ㊷ 根因收敛）；EXEMPT 注记按行号存在性断言（早前实证 8 注记行）。**验证**：真实仓库 self-check **PASS**（注记 8/8、候选 0）；test_gk_self_check +5（注册表完好 PASS / 注记删改 FAIL / 函数消失 FAIL / 新写函数 WARN / 文件缺失 FAIL）73 passed。E2 close（verify_source=bomb-drift-gate-registered）。
> **C11 追加（2026-09-13，XSPI 三面防线实装，F-REV-32 ⑰ / F-REV-10 覆盖面追记 / F-REV-21 追记 / F-REV-8 归属指纹 / F-REV-35）**：XSPI（跨会话存储型提示注入，arXiv:2606.04425）的"从交互中心转向**状态中心**安全"三面加固——**(i) 注入源形态**：[subagent_runner._check_foreign_content](../scripts/subagent_runner.py) 由"只认 `C:\Users\<n>\`"改为「自有用户名白名单（`_OWN_USER`）+ 用户根形态归一（`\`→`/`：`<d>:/Users/` / `/mnt/<d>/Users/` / `\\?\<d>:\Users\` / UNC `//host/Users/` / POSIX `/home/<n>/`）+ 误报豁免窄集（Windows 系统名 / POSIX 容器通用名）+ URL 负向断言」，修"自家日常写 `C:/` 与 `/mnt/c/` 却只检 `C:\`"的漏检面（F-REV-35 ①）。**(ii) 输出侧值域收窄**：`_VERDICT_VOCAB=("PASS","WARN","BLOCKED")` + `_VERDICT_ALIASES` 归一 + `_normalize_verdicts()`（bool→PASS/BLOCKED；越界**保留原值**截 64 字符并记 `vocab_violations`，禁静默改写）；`EccOutput.vocab_violations` 与 CLI 两份 `O()` HMAC 同构（`TestEccModelParity` 守护）+ 聚合器 `_suspect_flags` 增 `vocab_violation` 联动降权 —— verdicts 是持久载波（→`adjudicate_records.verdicts_json`→appeal/audit/聚合器回读），闭词表使自由文本注入无处安放。**(iii) 回读点归属指纹**：`gk_moa_aggregate.task_fingerprint`（空白归一 sha256 前 12）+ `collect_entries` 缺省按**最近一条任务指纹**绑定 / `--task` 显式锚 / `--allow-cross-task` 才放开，`trace.attribution` 落产物留痕 + MD「归属校验」行 —— 闭合 XSPI 的 **re-read gap**（回读点不再因"内容源自自家存储"而默认可信）。**定位**：F-REV-10 入站门（`--task` = 一切持久产物源头）覆盖生命周期**前半段**（unsafe persistent write），C11 补**后半段**（malicious downstream reactivation）。**验证**：test_subagent_runner_extract 123→137、test_gk_moa_aggregate +8、全量 **1760 passed**；`doc-align` **ok:true/issues:0**。**待办**：外来守卫单源化（四份 → 一份确定性实现 + 三薄壳，F-REV-35）；`gate_data.task_pipeline[]` 自身 TTL/失效（F-REV-21 追记）。
> **C11+ A1 追加（2026-09-13，F-REV-41 聚合器字段链修复）**：C11(ii) 声称的"聚合器 `_suspect_flags` 增 `vocab_violation` 联动降权"经复核为**实装但零生效假绿** —— CLI 写 `gate_data.subagent_history[]` 的 entry 字段白名单**不含** `vocab_violations`（及 `verdicts`/`budget_*`/`hmac_status`）⇒ 读侧 `vocab_violation`/`budget_*`/`hmac_unverified` 三标记**永不触发**；`hmac_status` 亦因 `_hmac_unverified` 从不落库而**恒 `verified_at_write`**（无 key 未验签也标已验证）；`render_md` 又漏渲染 `suspect`。**已修**：entry 补 8 字段 + `GK_HMAC_VALID` 注入 + hmac 分态映射 + MD 补 suspect；写入口结构回归 `TestMoaSuspectFieldWhitelist`。detail 见 assessment §15.6 F-REV-41（`docs/plans/2026-08-28-security-hardening-assessment.md`，内部 docs）。**教训**：跨"写入口白名单"的字段链须有**写入口结构回归**，仅读侧单测会漏（F-REV-31 空洞断言同族）。



> **C12 追加（2026-09-25，hook-xenv §15.3-Q3 落刀）**：**持久化块日志** = 误报率列分母标注源——`scripts/pre_tool_hook.py _record_block_persistent`：BLOCK 记录（ts/tool/target/cmd/kind/reason）append `<state 同目录>/hook-block/<YYYYMMDD>.jsonl`（O_APPEND 单写原子、按天滚动、有意 fail-quiet——取证副产品不阻断门禁）。动因：state ring `hook_block_log` 24 条/30min TTL **结构性产不出长期率**（判别臂 30 块压测 ring=24 vs 持久=30，`test_gk_q3_persistent_block_log.py` 四臂留痕）⟹ §13.1 分母候选①出局、改挂持久源。同批落 **四列网表节**（下节）+ doc_freshness 四列守护（bump 2026-09-25）。

## 安全网四列网表（层 / 判据 / 误报率口径 / 守方）

> **唯一事实源声明**：本节 = 安全网四列视图的**唯一**承载（§13.1/Q3 裁决：另建表 = 双主）。
> **行清单以上方六类表为准**（本节不重复"位置/作用"列，只补四列）；行集 = 运行时强制面（hook/CLI/管道/测试/文档五层），
> 纯 CI/平台行（A/C 区 GitHub 配置）暂不入四列（无运行时计数源，接源后补）。
> **误报率口径总式**：误拦数 / `hook-block/<YYYYMMDD>.jsonl` 同窗总数（Q3-① 持久源；标注 = 人工复核采样，首窗 2026-09-25 起）。

| 安全网（六类表行锚） | 层 | 判据 | 误报率口径 | 守方 |
|:--|:--|:--|:--|:--|
| R0.1-R0.4 危险命令/脚本扫描/插件裸调/引号陷阱 | hook 层（工具调用前，进程内） | 命令串正则命中危险模式（`_blue_fat_fish_*` 家族各自正则） | 持久源总式（kind=block 分列）——首窗未采 | `test_gk_q2_hint_selfconsistency`（Q2 自洽臂）+ `test_pre_tool_hook` |
| Gate 0-8（stage/worktree/路径/保护区/预算/自维护） | hook 层 | state 相位 / worktree 归属 / 路径前缀 / 保护区行号 / edit_budget 余量 | 持久源总式（kind=block\|budget\|review\|escalation\|ask 分列）——首窗未采 | `test_pre_tool_hook` + `test_eco_integration`（P0-3） |
| CLI pre-tool-check / guard-edit | CLI 层（子进程门） | realpath / 保护区行号级 / EDIT 预算扣减 | 持久源总式（Gate 4 转发同窗）——首窗未采 | `test_eco_integration` + audit --hook |
| plan-refinement L2 入站门（provenance/投毒/schema 三连闸） | 管道层（入队前） | `--task` 专名接地 + `--check-poison` + `--check-schema` | **口径未接**（拦截无自动标注源；质询臂人工留痕）——Q3 残留 | §0.1 留痕字段 + `test_gk_narrow_route` |
| 红先登记表 `_redfirst_cli --finding` | 测试层 | 登记表命中（未登记 die，:100） | N/A（判别器非拦截器） | `references/red-arm-templates.json` 单源 + `test_gk_c47_ext` |
| doc_freshness（C6，本检查器） | 文档层 | RECENT_BATCH_TS 字面 + 机制登记行 + 四列网表/唯一事实源 | N/A | `test_gk_c47_ext::TestDocFreshnessC6` |
| **持久化块日志（Q3-① 新增）** | 取证层 | 每次 BLOCK（`_CALL_IN_SCOPE`）append 当日 jsonl | **自身即分母源**（非拦截器，N/A） | `test_gk_q3_persistent_block_log` 四臂 |
| MoA 聚合器 suspect 标记层 | 聚合层 | `suspect_flags`（budget_*/zero_findings/vocab_violation/hmac_unverified） | **口径未接**（降权标记无自动标注源）——Q3 残留 | `test_gk_moa_aggregate` |

## 经济门运维开关与 success 端点契约（2026-10-31）

**三个开关默认全关**（缺省 = 只测量、不阻断、不联网）。开启属于**运维裁定**，不是配置项调优：

| 开关 | 缺省 | 开启后行为 | 判据落点 |
|:--|:--|:--|:--|
| `GK_ENTROPY_RAISE_ENFORCE` | `0` | 提额驱动熵 `> T_BLOCK` 时**阻断** `advance`（`rejected_edits` 驱动的越线**本来就硬阻断**，不受此开关影响） | `gk_advance._entropy_enforced` |
| `GK_CREDIT_FLOOR_ENFORCE` | `0` | N 门命中（相对激活基线的负向容差越界）时**阻断**；无签名基线 ⟹ 只 advisory（禁拿 `score()` 绝对值当判据） | `gk_advance`（两处收口）+ `gk_econ_baseline.resolve` |
| `GK_AUDIT_OUTCOME_ENDPOINT` | 未设 | 未设 ⟹ `gk_audit_outcome sweep` 只回 `advisory=endpoint_unset`（**不联网、不伪造 success**）；设了才逐条把未决 `raise` 交给决策后端 | `gk_audit_outcome.sweep`，由 `audit --state --all` 聚合后触发 |

**决策后端契约**（自建或内网服务，需实现两个端点）：

```
GET  <endpoint>/health          → 200 + JSON（存活探测；gk_audit_outcome probe 用）
POST <endpoint>/v1/systemone    → 200 + JSON
  request : {"…raise 结构化字段…", "think_mode": "auto|on|off", …}
  response: {"choice": "success|fail|overspend", "confidence": 0..1,
             "probabilities": {...}, "model": "<model_version>"}
```

判据：`choice` 必须落在词表内、`model` 非空（否则 `model_version_unknown` 拒落）；落账后**强制**
`verify_seal(require_ed25519=True)` —— 封印验不过则 `seal_verify_failed`（行已写，如实报"written"）。
失败、超时、词表越界一律具名错误，**不回退成 success**；`sweep` 单条失败不中断其余条目。

**`monitor --api` 的分数来源（2026-10-31 起，owner 裁定 A）**：与上面**同一个决策后端**同一端点，
但用 `gate_stage` typed-choice 问题（`choice ∈ pass|fail|uncertain`）：
`pass→PASS/score=confidence`、`fail→FAIL/score=1−confidence`、`uncertain→WARN/0.5`。
该分**只作 advisory**（`monitor_history`，不参与 `_bank_monitor_gate`；后者只认 `--local` 的
确定性 `passed/total`），且未配 `GK_AUDIT_OUTCOME_ENDPOINT` 时只回 `advisory=endpoint_unset`
（**不联网、不伪造、不回落到旧的 v4-flash PRM 车道**）。旧车道仅在 `GK_MONITOR_API_LEGACY=1`
下可用（逃生舱），且**标注为逐步移除（sunset）**：它的模型来自常量 `DS_MODEL_CRITIC`
（v4-flash 族）与固定 `FAILOVER_CHAIN`，硬编码不可按端点配置；校准读数攒够或 30 天窗口结束
即删除。最近一条 monitor 结果会投影进 subagent 条目的
`machine_check.monitor_last`（`{score,verdict,mode,ts}`），供与 `human_calibration_log`
配对做相关性校准——在跑出读数之前**不得**把它当门禁。

## 参考来源

- SkillOpt arXiv:2605.23904 — 优化器安全模式
- PRM Survey arXiv:2510.08468 — 过程奖励模型
- Bridge §6.2 Q2 — "Can the agent score without doing the work?"
- Mini Shai-Hulud 事件 (2026-05) — 供应链攻击升级场景
- Adnan Khan — GitHub Actions 缓存投毒研究
- Neciu Dan — 10 项 GitHub Actions 防御
- SWE-PRM arXiv:2509.02360 — 专用 PRM 实时纠偏

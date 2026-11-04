# References Index

Public documentation surface. The index below is **auto-generated** from the exported file set
(the exclusion face is `oss-export-whitelist.json`); do not hand-edit the block between the markers.

Citation discipline:

- Cross-document references use **symbol anchors** (file, command or section name), never line numbers.
- Historical line numbers are not kept in the public tree.

<!-- GK-REFS:START（由 scripts/gk_docgen_facts.py 生成，勿手改） -->
> 公开面共 **27** 份文档（本索引自动生成；出包范围 = `oss-export-whitelist.json`）。

### 1. Architecture and routing

| Document | Purpose |
|:--|:--|
| [architecture-overview.md](architecture-overview.md) | ZTHL Aegis（SPZ Gatekeeper）— 架构自述 |
| [extension-registry.md](extension-registry.md) | Extension Registry — Gatekeeper Skill 扩展注册表 |
| [flows-a-b-c.md](flows-a-b-c.md) | 流程路由 |
| [meta-routing-protocol.md](meta-routing-protocol.md) | META 路由协议 — 工作发现 + 仓库路由 + 阶段推进 |
| [state-storage.md](state-storage.md) | State 存储与回收（ZTHL Aegis） |
| [superagent-comparison.md](superagent-comparison.md) | 与 DeepSeek Harness Super-agent 的架构对照（2026-11-02） |

### 2. Execution and CLI

| Document | Purpose |
|:--|:--|
| [cli-protocol.md](cli-protocol.md) | CLI Protocol — Gatekeeper Command Reference & PRM Monitor |
| [convergence-evaluator.md](convergence-evaluator.md) | 收敛评估器（Convergence Evaluator）—— 机制正本 |
| [plan-writing-safety-net.md](plan-writing-safety-net.md) | 计划写入安全网（Plan-Writing Safety Net，简称 **PW-SN**） |
| [prm-monitor-methodology.md](prm-monitor-methodology.md) | PRM Monitor：方法论与交叉审查 |
| [stages.md](stages.md) | Stage Guide (0–5) |

### 3. Safety and security

| Document | Purpose |
|:--|:--|
| [plugin-loading-test-framework.md](plugin-loading-test-framework.md) | 插件加载安全网协议 + 插件导入测试安全网框架 |
| [security-incident-response.md](security-incident-response.md) | 密钥泄露应急处置流程（BP.08.05 对照） |
| [trae-cross-user-leakage-report.md](trae-cross-user-leakage-report.md) | Trae IDE 跨用户上下文注入漏洞报告 |
| [xspi-defense.md](xspi-defense.md) | XSPI 污染攻防机制正本（跨站/间接提示注入） |

### 4. Findings and history

| Document | Purpose |
|:--|:--|
| [ecc-impact-20260609-gitnexus.md](ecc-impact-20260609-gitnexus.md) | ECC-IMPACT-20260609-gitnexus |
| [ecc-impact-v7.md](ecc-impact-v7.md) | ECC-IMPACT: 飞轮 v7 实施计划裁定 |
| [ecc-write-spec.md](ecc-write-spec.md) | ECC 写入规范（正本） |
| [game-path-audit.md](game-path-audit.md) | Gatekeeper 游戏路径审计 — 6 条路径追踪 |

### 5. Templates

| Document | Purpose |
|:--|:--|
| [ci-pipeline-template.md](ci-pipeline-template.md) | CI 标准管线模板（通用） |
| [sequence-node-safety-net-template.md](sequence-node-safety-net-template.md) | 序列节点安全网模板（Sequence-Node Safety Net Template） |
| [standard-maintenance-module.md](standard-maintenance-module.md) | 标准维护模块（自愈层） |
| [wasm-engineering-template.md](wasm-engineering-template.md) | WASM 工程标准模板（通用） |

### 9. Other

| Document | Purpose |
|:--|:--|
| [credit-economy.md](credit-economy.md) | 信用分与额度银行（Credit Economy） |
| [oss-hooks.md](oss-hooks.md) | 技能的 Hook：契约、门禁与安装安全网 |
| [oss-moa-phase-provenance.md](oss-moa-phase-provenance.md) | MoA 相位/污染 provenance（公开口径） |
| [research-408.md](research-408.md) | Research 408 — 计算机 408 四轴优化分析 |

<!-- GK-REFS:END -->

## Reading order

1. `architecture-overview.md` — what the system is.
2. `meta-routing-protocol.md` — how work is routed.
3. `stages.md` — how a change moves through gates.
4. `cli-protocol.md` — commands used at each step.
5. Remaining documents are topic references: review, safety nets, security, findings, CI and WASM.

## Historical Memory (DEPRECATED)

> Stage documents used to repeat a "historical memory" preamble. It is deprecated: the CLI now
> handles stage execution deterministically. Use `cli-protocol.md` for current commands and
> `architecture-overview.md` for the component map. Design provenance remains in the private
> repository.

# Agent Loop 分层条款（两层 loop · 暗依赖红线 · DSH 对齐）

> 生效日 2026-11-08。触发原因：一句「不自研 loop」被读成「这个技能本身就是 loop，怎么还说不搞 loop」——
> 表述歧义。本条款把两层 loop 显式切开：**A 层是技能本体，B 层是 SDK 内部**。混称一律视为缺陷。

## 0. 一句话判据

技能=编排/治理 loop（A 层），跑在 SDK 的 LLM tool-call 循环（B 层）**之上**。
「不自研」永远只指 B 层；讲 A 层时禁用「不自研」三个字。

## 1. 两层定义

| 层 | 是什么 | 谁实现 | 状态 |
| --- | --- | --- | --- |
| **A 编排/治理 loop** | scan→fix→verify→advance、R 序列、审计链（`gk_chain run audit`）、红队链、六臂质询、finding 台账 | **本仓自实现**（`scripts/*`） | 保留，不替换、不外包 |
| **B SDK LLM tool-call loop** | 模型调用 → 工具调度 → 结果回填 → 再调用，即 `openai-agents` 的 `Runner.run` 那层 | 第三方 SDK | 长期按 **DSH 等价插件模块**替换 |

判据：**换掉 B 层，A 层的语义必须一字不变**。如果某段逻辑的删除/替换会改变 scan→fix→verify 的推进规则，它就在 A 层，不许挪。

## 2. 术语红线（写文档/写作/汇报时）

- ✅ 「不自研 SDK 内部的 LLM tool-call 循环（B 层），按 DSH 等价插件模块替换」
- ✅ 「A 层编排 loop 是技能本体，继续仓内自实现」
- ❌ 「不自研 loop」（歧义，禁止）
- ❌ 「削减对 openai 依赖 ⟹ 削减 loop」（把依赖面收缩误读成本体收缩，禁止）

## 3. 暗依赖红线（B 层不得下沉到非 LLM 路径）

非 LLM 入口**不得**在模块级 `import openai` / `import agents`。判据：只要这条命令的输出不依赖模型，
它就不该因为装不上 SDK 而跑不起来。

- 先例 1：`scripts/gk_suba_tiers.py`（2026-10-08，纯数据下沉）
- 先例 2：`scripts/gk_role_regions.py`（2026-11-08）—— `gatekeeper-cli.sh --role` 的角色白名单校验
  只需一张表；下沉后 `ROLE_TABLE_UNREADABLE` 的修复不再需要 openai。
- 违反示例：把角色表写回 `subagent_runner.py` 顶层（该模块顶层 `import openai` ⟹ 整条 `--role` 路径被 SDK 绑架）。

## 4. 依赖面（B 层仍在用时的硬约束）

- **钉版**：`openai==3.3.1` / `openai-agents==0.22.0` / `pydantic==2.13.4`（与 `scripts/suagent_py311.sh` 一致）。
- **锁**：`requirements-runtime.txt`（`uv pip compile --universal --generate-hashes`）+ `requirements-ci.txt`，
  CI 一律 `--require-hashes` + `PIP_ONLY_BINARY=:all:`。**必须 `--universal`**：
  单平台解析会把 `pywin32` 这类 win32 专属传递依赖写成无条件要求 ⟹ Linux 直接装不上（2026-11-08 实发事故）。
- **不迁国产平替包**：openai / openai-agents 无对等物，硬迁=自研 SDK（违反 §1）。国产杠杆只有三个：
  国产镜像（腾讯云 PyPI，哈希不变⟹可行）、内容哈希锁、国产模型端点（换 base_url，不动 A 层）。

## 5. 与 DSH 对齐的验收形状

替换 B 层时按这四条验收，缺一条即不算对齐：

1. A 层入口签名不变（`gatekeeper-cli.sh` 子命令、`gk_chain` 站名、JSON 回包字段）；
2. 工具白名单/权限仍由 A 层裁决（B 层只负责"调模型+跑工具"，不新增授权面）；
3. 断网/无 key 时可降级到非 LLM 路径（对应 §3 红线）；
4. `scripts/test_agents_sdk.py` 这类 SDK 契约测试仍可跑（它是 B 层替换的安全网，不是待删产物）。

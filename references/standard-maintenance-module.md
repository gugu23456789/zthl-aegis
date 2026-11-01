# 标准维护模块（自愈层）

> **性质**：R-T7.13c「4 制品」第 4 件（前 3 件 = [`ci-pipeline-template.md`](ci-pipeline-template.md)、[`wasm-engineering-template.md`](wasm-engineering-template.md)、`sequence-node-safety-net-template.md`〔公开包不随附〕）。本文件定义**「坏了怎么被发现、谁负责修」**这一层，前 3 件定义「长什么样才算对」。
> **边界原则**：本模块**只登记实存能力**。batch8 规划里的自愈闭环若在本仓未接线，一律标 `未接线`，**不写成已具备** —— 门禁文档写空头承诺，等于给假绿背书。
> **最后核对**：2026-10-31（逐项 grep 实证，见 §4 缺口表）。

---

## 0. 与前 3 件的分工

| 制品 | 回答的问题 | 失败时的动作 |
|:--|:--|:--|
| ci-pipeline-template | CI 管线长什么样 | 红了按 `stage-2-ci.md` 诊断 |
| wasm-engineering-template | WASM 工程约定 | 按 PRE/P2 约定改 |
| sequence-node-safety-net-template | 序列节点安全网 | 按节点门禁拦 |
| **standard-maintenance-module（本件）** | **上述约定本身失效时，怎么被发现、谁修** | **发现 → 归属 → 修复 → 回归** |

一句话：前 3 件是**被检查的对象**，本件是**检查者与修复者的编成**。

---

## 1. 实存能力（已接线，可直接调用）

### 1.1 `ci-diagnose` —— CI 失败的**取数**层

CLI 面（`gatekeeper-cli.sh`，无 LLM、纯取数）：

```
bash gatekeeper-cli.sh ci-diagnose list [COUNT]        # 列最近 workflow_runs
bash gatekeeper-cli.sh ci-diagnose fetch <RUN_ID>      # 下载日志到 /tmp/ci_logs/
```

- **注册面**：`valid_tools` 白名单内（`gatekeeper-cli.sh:4206`），tier2/tier3 子代理工具包含它（`gk_suba_tiers.py:61,73`）⟹ **子代理可自主取 CI 日志**，不需人转贴。
- **视图层**：`gk_views.py:203` 提供定宽表渲染；`:222` 给出 fetch 用法提示。
- **接线**：`subagent_runner.py:1056` → `_gatekeeper_cli("ci-diagnose", action, run_id)`。
- **节点归属**：`gk_node_guard.py:142` 把 `ci-diagnose (CI 红时)` 登记为 **STAGE_2** 的能力项。

### 1.2 STAGE 归属

| STAGE | 本模块提供的能力 | 载体 |
|:--|:--|:--|
| STAGE_1（code） | 模板符合性 —— 产出物对不对得上前 3 件模板 | 前 3 件模板 + `doc-align` |
| STAGE_2（CI） | CI 红了的**诊断取数** | `ci-diagnose` list/fetch |

---

## 2. 未接线能力（batch8 规划有、本仓无）

> 这一节是本文件的核心价值：**把「规划里有」与「仓里有」分开**。
> 下表每一项都 grep 实证过（见 §4 命令）。未接线 ≠ 否定其价值，而是
> **当前不能当作已有门禁来依赖**。

| 能力 | batch8 出处 | 本仓实态 | 影响 |
|:--|:--|:--|:--|
| **actionlint** 自动校验 | 「workflow 即代码——改动后必须 actionlint/zizmor 校验」 | **仅注释提及**（`ci-pipeline-template.md` 原则行、`gk_doc_align.py:73`），无自动化检查接线 | workflow 改动**无**机器校验门 |
| **zizmor** 静态分析 | 同上 | 仅注释提及（`gk_doc_align.py:73`、`gk_self_check.py:1443`） | 同上 |
| **Auto-Fix 自愈循环**（≤3 次） | 「CI 失败自动诊断→修复循环（≤3 次）」 | **不存在**。`ci-diagnose` 只取数，无修复回路 | CI 红仍需人/子代理介入修 |
| **结构化失败摘要**（T45） | 「T45 结构化失败摘要」 | **不存在**（`_check_ci.sh` 仅 shebang，11 字节） | 失败信息靠人读原始日志 |
| **WASM 标准维护模块**（PRE.10 错配 + P2 符号前缀） | batch8 WASM 自愈层 | **本仓零命中**（`PRE.10` grep 0 处）—— 属 spz2glb/WASM 项目范围，非本仓 | 本模块不覆盖 WASM 自愈 |

### 2.1 `_check_ci.sh` 的实态

`scripts/_check_ci.sh` = **11 字节，仅 `#!/bin/bash`**（无换行结尾，故 `wc -l` 报 0）。
即：**它是个桩，不是检查器**。任何引用它当作「CI 检查」的地方都是假锚。

---

## 3. STAGE_1/2 如何引用本模块

- **STAGE_1**：产出物须符合前 3 件模板 ⟹ 见各模板自身 §0 适用边界；本模块不重复其内容，只声明「模板符合性由 STAGE_1 门禁承载」。
- **STAGE_2**：CI 红时的取数入口 = `ci-diagnose list` → `ci-diagnose fetch <RUN_ID>`；诊断后的修复循环**目前无自动化载体**，由执行者（人或子代理）按 `stage-2-ci.md` 的诊断流程推进。

---

## 4. 缺口的复核命令（可复算）

```bash
# 逐项实证（在仓根执行）；输出为 0 / 仅注释命中 = 未接线
grep -rn "actionlint" scripts/ gatekeeper-cli.sh | grep -v "^#"   # 期望：仅注释
grep -rn "zizmor"     scripts/ gatekeeper-cli.sh | grep -v "^#"   # 期望：仅注释
grep -rn "PRE.10"     scripts/ gatekeeper-cli.sh                  # 期望：0 命中
wc -c scripts/_check_ci.sh                                        # 期望：11（纯 shebang）

# ci-diagnose 实存确认
grep -n "ci-diagnose" gatekeeper-cli.sh | head                    # 期望：L4206 valid_tools + L7629 定义
```

**缺口补齐时的义务**：把 §2 表中对应行从「未接线」改「已接线」并**填上载体坐标**，
且同批新增红臂（无臂不算接线 —— T10 的教训：代码在、臂缺 ⟹ 假绿）。

---

## 5. 本文件自身的维护契约

- 被 STAGE_1 / STAGE_2 指南引用（公开包 = [`stages.md`](stages.md)；T5 出口判据）。
- §2 缺口表是**活的**：每接线一项，改一行并补臂。
- **禁**把 §2 的项直接删掉当作「已解决」——必须改成「已接线 + 载体坐标」，否则缺口史丢失，下轮又会有人按 batch8 规划误以为已具备。

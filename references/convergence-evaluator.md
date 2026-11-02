# 收敛评估器（Convergence Evaluator）—— 机制正本

<!-- DOC-META
title: 收敛评估器（Convergence Evaluator）—— 机制正本
type: reference
owner: spz-gatekeeper-r-sequence
status: public
updated: 2026-11-02
-->

> **本文件是收敛评估器机制的「唯一事实源」（正本）。**
> 落点 = `references/`（**开源面**）。**禁**把机制正本放进 `docs/plans/`（该目录**不开源**）。
> 实现：`scripts/gk_convergence_estimator.py`（**数学核**）+ `scripts/gk_convergence_evaluator.py`（**质询轮次循环早停编排**）。
> 改本文件 = 改机制口径（**本体层** ⟹ 须走门禁：batch → 质询 → seal → adjudicate → 协议版本号 bump，或**用户显式授权**）。
>
> **术语边界（2026-10-27，用户显式授权）**：本正本**只用机制词**（μ / r̂ / N* / 谓词编号 / 网关三态），
> **不引入**任何未公开稿件的自造术语、章节名或复现包文件名。理由：本文件在开源面，逐行"对齐论文用词"
> 等于把未公开稿件的术语指纹写进公开面（可反查到作者）。机制↔稿件术语的映射在**不随包发布**的一侧维护。


## §1 范围

本机制覆盖**两条消费链**：

| # | 消费链 | 触发点 | 判决 |
|:--|:--|:--|:--|
| C1 | **standing 序列前置门** | `plan-refinement` 入队前（`pre-check convergence` / T4） | `N*_hi > GK_CONV_MAX_ROUNDS` ⟹ `BLOCK`（`CONVERGENCE_BUDGET_EXCEEDED`） |
| C2 | **质询轮次循环早停** | 迭代审查（6 臂质询等）每轮结束 | 连续 K 轮 `r̂ ≥ r_min` ⟹ `NO_CONVERGENCE` 早停 → **转 M（机制修复）** |

> C2 的动机：**A8/RCA** 预期下，「分数不增长 / μ 不衰减」= **基础设施缺陷**，此时继续改计划文本 =
> **空转烧钱**（四轮实测 ≈14M+ tok）；须在**第 1-2 轮**即预判并早停。

## §2 量纲与公式（单一事实源）

```text
μ_n   = μ_{n−1} − a_n + b_n            # 存量递推（μ = open + in_progress 计数）
a_n   = 第 n 轮「首次离开 open 集」的不同 fid 数（**去重**；fixed+closed 不双计）
        #   **离开存量 = 解析 ∪ 归档清除**：epoch 事件声明的 `purged_fids`（配额归档 /
        #   代数清除）**同计**，且计入该 epoch **所闭合的那一轮**（= 该 epoch 之前那一轮），
        #   与解析共用同一去重集（同一 fid 解析 ∪ 归档**只计一次**）。`ECC-8B7F130A20A2`
b_n   = 第 n 轮 register 事件数
μ̂₀   = |{f : f.status ∈ {open, in_progress}}| − 测量 finding（白名单，见 §3-D9）
r̂    = (μ_N / μ_0)^{1/N}               # = 相邻轮 μ_n/μ_{n−1} 的**几何均值**（stock 比）
r̂ < 1 ⟹ N* = ⌈ ln(μ̂₀ / μ_tgt) / ln(1 / r̂) ⌉
r̂ ≥ 1 ⟹ N* = ∞                         # 自锁；须外部熔断（冻结扩张 b→0）
N*_hi = N*(r̂ + δ)   /   N*_lo = N*(r̂ − δ)      # δ = GK_CONV_DELTA（默认 0.1）
```

**判据量唯一 = `r̂`（stock 轴）。** **禁**另造 flow 轴（如早期草案的 `ρ̂`）—— 那是撞口径的
第二事实源（已登记 `ECC-CC9123D0876E`）。逐轮 step ratio `μ_n/μ_{n−1}` **同属 stock 族**，
非新轴。

**存量口径 = 未清偿义务（2026-10-22，owner 令）。** finding 是**记名 IOU**（一笔待偿还的修复/审查
工作量），故 `μ` 是**队列里的未平债**，不是总体样本；解析与归档清除同属「离开存量」（§3-D2），
不得把「全量并表 / 累计开单」当作 `μ̂₀` 或任何比率的**分母**。结算面
（`realized / outstanding / unbacked`，口径见内部计划——`docs/` 不随开源包发布）与 `r̂`
**分母不同、不可合并**。本条只钉口径解释，不改公式。

## §2b A8 适用条件登记（P1–P7 → 公理归属；2026-10-22）

`r̂`（§2）只在若干前提下有意义。论文把这组前提称作 **P1–P7**；它们**不是新公理、也不是新网**，
而是 **A8 的 G 参数簇**（模板纪律：SN 是 H-SLSN 的参数实例化，不新增不存在参数）。
G1–G5 机检由**消费方复现包**执行（不随本仓发布）。

| 谓词 | 含义 | 归属 | 缺失/未评估的具名后果 |
|:--|:--|:--|:--|
| P1 | 冻结 epoch（窗口不被配额归档/迁移改写） | A8 前提（epoch 口径，`ECC-8B7F130A20A2`） | 轮切分不确定；当前 stock 通道**数据支持但机制未接** |
| P2 | 共源账本（state 账与 journal 同源） | A8 前提（§3-D6 的同源前提） | 不同源 ⟹ `MU_BACKCAST_NEGATIVE` |
| P3 | ≥2 个正轮次 | A8 前提（D7 的充分条件） | 单轮 ⟹ `RATES_DEGENERATE_SINGLE_ROUND` |
| P4 | 存量比平稳（非 ramp / 非 level shift） | A2/RCA 适用性（准入判定） | 拒绝 ⟹ `abstain`（**不是** block） |
| P5 | κ 污染未越界 | A8-④ 杠杆上界（κ/φ(κ) 轴，§3-D9 同族） | 未评估 ⟹ 只能是 `asserted`，禁写 enforced |
| P6 | 相位筛（phase screening） | **无公理——缺口**（现为 0 权重 flag，缺省 True，**未实装**） | 不得在对外表述中当 enforced；属已知未实装 |
| P7 | n_eff（有效样本量） | A8-④ / §5b 档位建议 | 同 P5 |

**两条硬纪律**：

1. **连言不得越界**：论文写 `P1--P7` 时必须限定在「该通道实际评估的那几条」——
   单序列通道只有 **P3–P4** 可评估；`not_applicable` 必须给结构理由（无臂 / 无批次 / 无轮次对齐）。
2. **Prop 3 样本下限不是谓词**：`μ_0 ≥ ln(1/α)/I(ρ)` 是 A8 的**认证前提**（Chernoff 界
   `P(emit|r=1) ≤ e^{-μ_0·I(ρ)}` 的可用性条件），不是第 8 个谓词。低于 floor 时 horizon 一律
   withheld（`abstain/below_certification_floor`），不得作为 emit 见证。

## §3 定义（实现决策，显式登记；禁默默自创）

| # | 定义 |
|:--|:--|
| **D1** | **「轮」切分** = finding journal 的 **epoch 标记**（`gk_finding._EPOCH_EVENT`）；无 epoch ⟹ 整段算一轮（输出 `rounds_basis`） |
| **D2** | **「消解」** = 事件 `to ∈ {fixed, closed, rejected}`（离开 open 集）；计 `a` 时按 `fid` **去重、只记首次**。**归档清除同属离开存量**（`ECC-8B7F130A20A2`）：epoch 声明的 `purged_fids` 计入该 epoch **所闭合的那一轮**，与解析**共用同一去重集**（同一 fid 解析 ∪ 归档**只计一次**）；journal 无 `purged_fids` ⟹ 逐字向后兼容 |
| **D3** | **`N*_lo`**：`r̂ − δ` 落在开区间 `(0,1)` 之外 ⟹ **不可定义** ⟹ 输出 `null` + reason（不夹逼、不臆造） |
| **D4** | **`verdict`**：`r̂ ≥ 1` ⟹ `"block"`；否则 `"pass"` |
| **D5** | **`μ_tgt = 0`**（清空）：几何衰减**渐近**不达 0 ⟹ `N* = ∞`（数学推论，非选择） |
| **D6** | **μ 序列反推**：由末轮 `μ_N`（= state 当前 open 计数）按递推**反向**重建；`mus[0]` = 第 1 轮**之前**。⚠ 前提 = state 账与其 journal **同源**；出现负值 ⟹ 报 `MU_BACKCAST_NEGATIVE`（**禁夹逼**） |
| **D7** | **单轮/无 epoch** ⟹ `r̂` 不可成形 ⟹ 报 `RATES_DEGENERATE_SINGLE_ROUND`（显式降级，**禁默 1、禁静默放行**） |
| **D8** | **`μ̂₀ == 0`** ⟹ 具名降级 `NO_OPEN_FINDINGS`（**输入面为空**；域隔离/迁移/清理后常见）。**严格区分**于 `MU_BACKCAST_NEGATIVE`（= 账与 journal **不同源**） |
| **D9** | **测量 finding 白名单**：`root_key` 前缀 `moa-agg:` / `noconv:` 的 finding **不计入 μ̂₀** —— 防「衡量行为抬高被衡量量」（登记 `ECC-8398D1A11883`）。前缀**单源** = `gk_convergence_estimator._MEASUREMENT_ROOT_PREFIXES` |

## §4 C1 门三态

| 态 | 条件 | 输出 |
|:--|:--|:--|
| `pass` | `N*_hi ≤ GK_CONV_MAX_ROUNDS` | 放行 |
| `warn` | `T*` 未冻（`T_NOT_FROZEN`）｜estimator 不可用（`CONV_GATE_UNAVAILABLE`）｜`r̂ ≥ 1`（自锁，`CONV_GATE_WARN_NO_FREEZE`） | 只 WARN、**不阻断**（禁自锁拒一切） |
| `block` | `N*_hi > GK_CONV_MAX_ROUNDS`（门**恒启用**，无独立总开关） | `CONVERGENCE_BUDGET_EXCEEDED` |

**前提门（C3）**：`T*` 未冻结 ⟹ **拒出 `N*`**。producer = `gate_data.t_star`
（`freeze_t_star`/`load_t_star` 唯一读写点；CLI `t-star freeze|show`）。

**fail-soft**：state/journal 不可读 ⟹ `ok:false` 且**不阻断**入队（只 WARN）。
**stdout 契约**：`json.dumps(..., separators=(",", ":"))` 紧凑分隔符 —— bash 侧以
`*'"action":"block"'*` 精确子串匹配（改回默认分隔符 ⟹ 门静默空转）。

## §5 C2 质询轮次循环早停

**判据（用户 2026-10-05 裁定 = 参数化）**：

```text
step_ratios(mu) = [ μ_n / μ_{n−1} | prev > 0 ]        # 逐轮 stock 比（prev==0 跳过；负值 ⟹ undefined）
verdict:
  ratios 含负值                         ⟹ UNDEFINED
  len(ratios) < K                      ⟹ INSUFFICIENT_ROUNDS（禁臆断）
  末尾 K 个 ratios **全 ≥ r_min**       ⟹ NO_CONVERGENCE
  否则                                  ⟹ CONVERGING
```

- **`r_min`**（默认 **0.9**，区间 **[0.9, 1.0]** 可调）：`0.9` = 次临界（近不自锁，慢收敛）；`1.0` = 数学发散（自锁）。
- **`K`**（默认 **2**）：滞回轮数，抗单轮噪声。
- **"连续 K 轮"语义** = 末尾 K 个 **step ratio** 全 ≥ `r_min`（`≥` 含等号）。
- **触发后果**：落 finding（`root_key` 前缀 `noconv:`，与 MoA 侧 `convergence_finding` **同台账**、
  幂等合并）+ 产出 `switch_to = "M"` ⟹ 按 §11 三向分流**强制转机制修复**，
  **禁**再以「改计划文本」结案。

## §5b 档位建议（`tier_recommendation`；2026-10-03 加，2026-10-08 补 η_tier 实算 + 启动前预测 + 消费面）

> **由来**：2026-10-03 用户裁定「升档应由收敛评估器**提前算**」⟹ `gate()` 输出 `tier_recommendation`。
> 2026-10-08（finding `ECC-46C8BF837715`，closed）补齐三处半成品：η_tier **实算**（非文档常数）+
> **启动前预测** + **消费面**。**本条即该机制的「归位」**（2026-10-03 实装时**漏记本正本**）。

- **只建议、不改档**：本机制输出 `action ∈ {raise, hold, unknown}`（`unknown` = 评估不可用，fail-soft）；
  **落档**由消费面决定（见下）。
- **判据**（任一命中 ⟹ `raise`）：
  1. `r̂ ≥ 1`（自锁）⟹ `reason=CONV_R_SELF_LOCK`；
  2. `N*_hi > max_rounds` ⟹ `reason=N_STAR_EXCEEDS_MAX_ROUNDS`；
  3. **启动前预测**：上一次 subagent 运行 `budget_status ∈ {hard, item_exceeded, max_turns}`
     ⟹ `reason=LAST_RUN_BUDGET_<STATUS>`（当前档预算被 cap 截停 ⟹ 升档有据；即「tier3 cap 低于
     真实成本」根因的**门侧预测**）。
- **η_tier 单源**：`eta_tier` = `scripts/gk_suba_tiers.tier_gain(cur, cur+1)` —— **live `SUBA_TIERS`** 比值
  （3→4 = T10 定义的唯一「工具面恒等」对）。**禁**抄计划文档的历史常数表（该表已漂移：记 3→4
  `g_token=2.0×`，实网 `1,000,000→3,000,000 = 3.0×`）。`SUBA_TIERS` 本体亦**迁入该系统轻量模块**
  （`subagent_runner` 顶层 `import openai/agents` 属重依赖，评估器无法低成本取用）。
- **`prediction` 块**：`{from_tier, to_tier, at_top, eta_tier, last_budget_status, predicted_raise_pays, basis}`；
  已处最高档 ⟹ `at_top=True`、`predicted_raise_pays=False`（无法再升，须提额/收束）。
- **消费面** = `gatekeeper-cli.sh::cmd_plan_refinement`：`action=raise` ⟹ ① stderr `GATEKEEPER-WARN`
  （**不污染** stdout JSON 契约）；② **自动换挡**（`tier = min(max(SUBA_TIERS), 当前+1)`，留痕
  `GK_DBG_LOG`）。**默认开**（2026-10-08 用户裁定「自动换挡默认开」）⟹ 档位自动跟随启动前预测上移；
  已处最高档 ⟹ **无法再升**（须提额/收束，仍出 WARN）。
- **kill switch**：`GK_AUTO_TIER`（**默认 `1`**；设 `0` 显式关闭 ⟹ 退化为只告警 opt-out）。

## §6 开关（kill switch）

| env | 默认 | 作用 |
|:--|:--|:--|
| `GK_CONV_DELTA` | `0.1` | `N*_hi/lo` 的 δ |
| `GK_CONV_MU_TGT` | `1` | 目标残留 μ |
| `GK_CONV_MAX_ROUNDS` | `3` | 允许轮次（C1 判决阈值） |
| `GK_CONV_R_MIN` | `0.9` | C2 早停阈值（区间 [0.9,1.0]） |
| `GK_CONV_K_ROUNDS` | `2` | C2 滞回轮数 K |
| `GK_CONV_EARLY_STOP` | `1` | C2 早停开关（`0` ⟹ 只出 verdict、**不落 finding**；已实装） |

## §7 归属

`moa-aggregate --emit-finding/--convergence/--mu` 三 flag 的**生产者** = 内部计划（Infra-1，
`docs/plans/` 不随开源包发布）；**本机制 = 消费者**（只读其产物 finding）。归属判据见同一内部计划。

**聚合 finding 形态扩展（2026-10-06）**：`moa-agg:` finding 由「一行计数台账」扩为**带分类与
载体**的实质记录 —— `facets` 落 `classification:plan-error|infra-defect|unknown` 与
`carrier:P|L|M`，`source_note` 落**详情文本**（簇代表 / 成员臂 / 三组分布）。分类判据 =
`gk_moa_aggregate.py::assess_findings`（确定性、零 LLM）；细节见内部计划（不随包发布）。**`root_key` 前缀与幂等语义不变** ⟹
本机制（消费者）零回归。

## §8 变更史

- **2026-10-05（Infra-2）**：本正本建立 —— 机制正本自内部计划 subplan **迁出**至 `references/`（开源面）；新增 §5 C2 质询轮次循环早停（编排层
  `gk_convergence_evaluator.py`）；C2 判据 = 参数化 `r̂ ≥ r_min 连续 K 轮`。
- 关联登记：`ECC-1F540718AEE5`（轮次不收敛空转 → 应早停）、`ECC-CC9123D0876E`（ρ 撞口径）、
  `ECC-8398D1A11883`（μ 污染）。
- **2026-10-06（W2/W4）**：**污染轴 κ/φ(κ) 接入** —— 新增 κ 跨轮样本单一事实源
  `references/moa-kappa-ledger.json`（普查 **11 批**；旧判据「n=4」为正则口径缺陷，只匹配
  `(a/b, c/d)` 双元组、漏记 `κ=2/2` 单值形态）与估计器 `scripts/gk_moa_kappa.py`
  （`estimate_p_tilt` 对数-对数 OLS / `phi` / `cumulative_leverage`）。**当前 `[UNFITTED]`**：
  `κ_tilt` 零膨胀（显式非零仅 2 点 < 3）+ 全批未记 `n_events` ⟹ 具名拒估，不产点估计。
  **轴分离不变**：κ 轴（分母 = 攻击事件数）与 μ 轴（分母 = 修订动作）**不可合成**（[ASSUMPTION-5]）。
  杠杆效应实证（线性上界 + 检出塌陷 + 边界门）与 OPCAP 接口见
  `references/sequence-node-safety-net-template.md §1 A8-④`（结算面细节在内部计划，不随包发布）。
- **2026-10-08**：新增 **§5b 档位建议（`tier_recommendation`）** —— 回写 2026-10-03 实装但**漏记本正本**
  的机制（**消正本缺口**）；并补 η_tier **实算**（`scripts/gk_suba_tiers.tier_gain`，`SUBA_TIERS` 迁入该
  轻量单源模块）+ **启动前预测**（`subagent_history[-1].budget_status`）+ **消费面**（`cmd_plan_refinement`
  / `GK_AUTO_TIER`）。finding `ECC-46C8BF837715`（**closed**）。
- **2026-10-08（续）**：`GK_AUTO_TIER` **默认 `0` → `1`**（自动换挡**默认开**，用户裁定；`0` 为显式 opt-out）
  —— 承「启动前预测命中 ⟹ 档位应自动跟随上移」；已处最高档仍只出 WARN（`at_top`）。
- **2026-10-22**：新增 **§2b A8 适用条件登记** —— 把 P1–P7 收口为 **A8 的 G 参数簇**
  （**不新建网**，旧名 PASN 废止）；G1–G5 机检由消费方复现包执行（不随本仓发布）。
  Prop 3 样本下限（`μ_0 ≥ ln(1/α)/I(ρ)`）同时接进 `decide_admitted`，低于 floor 一律 withheld。
  口径纪律：P1–P7 是**连言**，未评估项只能标 `asserted`，不得写成 enforced；单序列通道
  可评估 P3–P4，其余须给 `not_applicable` 的结构理由（无臂/无批次/无轮次对齐）。
- **2026-10-27（用户显式授权）**：本正本**去稿件指纹** —— 删除对具体未公开稿件的指涉、
  复现包文件名与 `docs/plans/` 悬空路径（开源包不含 `docs/`）；首部新增「术语边界」。
  **公式 / 判据 / D1–D9 / 三态门 / kill switch 全部未改** ⟹ 机制口径零变更。

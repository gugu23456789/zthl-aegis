# ECC 写入规范（正本）

**状态**: 生效（2026-09-28）。**依据**: `docs/plans/2026-09-28-edit-gate-ecc-convergence-plan.md` §3。
**机检**: `monitor-schemas/ECC-WRITE.json` · `gk_finding.register`（写入边界 fail-loud）·
`gk_self_check.check_ecc_form`（只读体检）· `scripts/test_gk_ecc_source_spec.py`。

---

## 1. 为什么要这份规范：两个「ECC」不是一个东西

仓库里有两个族**共用 `ECC` 词根**，语义、生命周期、落点全不同。历史上因同名被混用，
台账里出现了无法按来源分面的脏数据（实测 base state 92 条：规范 `source` 仅 4 种，
其余 ≈44 条为散文/空/私名）。

| | **`ECC-FINDING`**（本规范的唯一对象） | **`EccOutput`**（**不**受本规范约束） |
|:--|:--|:--|
| 是什么 | **持久缺陷台账条目** | **subagent 单次调用输出** |
| 落点 | `state.gate_data.ecc_findings[]` | `docs/analysis/subagent/*.json` |
| 生命周期 | `open → verify → close`（跨会话存活） | 一次调用即产即用（**易失**） |
| 写通道 | `gatekeeper-cli.sh finding register` | `subagent_runner` 自行 print（`EccOutput` 模型） |
| 完整性 | state `_checksum` + `.finding-journal.jsonl` 第二副本 | Pydantic 校验 + HMAC 签名 + JWT |
| id 形态 | `ECC-<12HEX>` | 无（用 `subagent_id`） |
| 消费方 | `audit --state` · `self-check` · `ember replay` | MoA 聚合器 / 计划质询 |

> **判定口径（覆盖范围）**：`ECC-FINDING` = **除 subagent 输出以外的全部产出场景**。
> 已知产出者（2026-09-28 实测）：`manual`（人/主 agent）·
> `crossr`/`crossrev`（交叉审查；**当前走 P0-3 `shadow_extract`「只产不写」**，转正后才入册）·
> `red`（红队，走 `gk_finding.upsert_red_findings` 而非 register CLI）· `review`（审查层）·
> `audit` · `monitor`（L9 gate FAIL 自动 E2）· `subagent-promoted`（`--from-report` 显式提升）。
> **夜间作业（`gk_cron_night_batch.py`）不写台账** —— 其设计即「只读 / 零副作用 / 0 API」，
> 夜间信号以 cron 报告 + `.gatekeeper.no-ask` 待办形态遗留（**未入册**，属已知覆盖缺口）。

## 2. `ECC-FINDING` 字段规范

> 单一事实源 = `gk_finding.register` 的新建分支（`ECC-` + uuid hex 前 12 大写）；下表与代码逐字段对表。

| 字段 | 必填 | 约束 | 机检点 |
|:--|:--|:--|:--|
| `id` | 自动 | `ECC-<12HEX>` | 生成侧 |
| `title` | ✅ | 非空；**须含可复查事实**（命令+stdout 或锚） | 形式（人判内容） |
| `source` | ✅ | ≤32 字符、无空白，∈ `manual\|crossr\|crossrev\|red\|review\|audit\|monitor\|prose\|subagent-promoted` | `register` **fail-loud** |
| `source_note` | — | 长文本出处（时间线/探针/复算命令），`--source-file` 通道 | 无约束 |
| `status` | 自动 | 新建 = `open`；生命周期 `verify` / `close` / `reopen` | 状态机 |
| `created_at` | 自动 | 登记时间 | — |
| `family` | — | 缺陷族名 | — |
| `cover_layers` | red/review 必填 | ∈ 已登记审查层（`REVIEW_LAYERS` 单源） | 缺失 → `gap=true` + warnings |
| `gap` | 自动/可显式 | 缺省 = `source ∈ {red,review}` 且 `cover_layers` 空 | — |
| `cover_warnings` | 自动 | 覆盖告警文本 | — |
| `root_key` | — | 根因**指纹**：无空白、≤64 字符；有则按根因合并 | `register` fail-loud |
| `anchors[]` | — | 行锚 `path:line` 或符号锚 `path::symbol`；去重保序 | 归一（单源） |
| `facets[]` | — | 侧面标签；去重保序 | 归一（单源） |
| `closure_oracle` | — | ∈ `{"", mechanical, judgment}`；`""` = 未分类（合法） | `register` fail-loud + `check_ecc_form` |
| `evidence_hash` | 自动 | `title + root_key + family + anchors` 的确定性指纹 | 生成侧 |
| `release_state` | — | ∈ `none\|provisional\|release_approved\|release_rejected`（默认 `none`） | `register` fail-loud |
| `severity` | — | ∈ `info\|low\|medium\|high\|critical`；合并**只升不降** | `register` fail-loud |
| `owner` | — | 责任域 token（如 `skill.<plan>`），无空白、≤120 | `register` fail-loud |
| `provenance` | — | ∈ `trusted\|untrusted`（默认 `trusted`；污点扫描可升为 `untrusted`） | `register` fail-loud |
| `declassified` | 自动 | 默认 `false` | — |
| `taint[]` | 自动 | 写入时污点扫描（`title + source_note + family`），只升不降 | 生成侧 |
| `quarantined` | 自动 | `taint` 非空且 `provenance=untrusted` | 生成侧 |

> `prose`（2026-10-16 新增）用于散文结论转换；它**不是**审查层 finding，不因缺 `cover_layers` 标 `gap`。
> `severity` / `owner` 是审计适配器的可选结构化字段，存量条目不回填。

## 3. 命令面（唯一写通道）

```bash
# ① 常规登记（短 token 来源 + 长文本出处分离）
bash gatekeeper-cli.sh finding register "<标题含可复查事实>" manual \
     --source-file /tmp/evidence.md          # 长文 → source_note（**不**污染 source）
     --family <族> --root-key <指纹> --anchor scripts/x.py::<symbol> \
     --facet <侧面> --closure-oracle mechanical

# ② 从 subagent 报告**显式提升**（只抽允许字段；禁整份报告入册）
bash gatekeeper-cli.sh finding register --from-report docs/analysis/subagent/<rep>.json

# ③ 生命周期
bash gatekeeper-cli.sh finding verify <id> true | finding close <id> <来源> | finding status
```

`--from-report` 的**允许抽取字段**（其余键**一律丢弃**）：`title`（别名 `summary`）· `family` ·
`anchors` · `facets` · `root_key` · `closure_oracle` · `cover_layers`；并附
`source_note = "promoted from <文件名> sha256=<前16位>"` 留痕来源。

## 4. `EccOutput`（subagent）与台账的边界

> 单一事实源 = `subagent_runner.EccOutput`（Pydantic）；下表的字段名与该模型逐字对表。

- **内容面固定 4 字段**（这是「4 字段输出」的准确含义）：
  `conclusion: str` · `evidence: list[Evidence]` · `findings: {worked, failed, not_tried}` ·
  `next_steps: list[str]`。
- **身份面（必填）**：`mode`（默认 `subagent`）· `subagent_id` · `nonce` · `timestamp` · `task`。
- **运行面**：`confidence ∈ {high, medium, low}` · `tools_used` · `guardrail` · `turns` ·
  `total_items` · `access_violations`。
- **预算面**：`token_budget` · `total_tokens` · `item_budget` · `budget_status`。
- **评分/质询面**：`overall_score` · `verdicts` · `vocab_violations` · `seven_dim_score` ·
  `challenges` · `slashed` · `kept` · `assertions` · `tool_call_count`。
- **runner 侧机检（确定性写入，非 LLM 自述）**：`gx_status` · `verification` ·
  `evidence_anchor` · `token_usage`。
- **签名/透传**：`hmac` · `jwt_token` · `agent_payload`。
- **落盘与提升**：签名 + JWT 后整份落 `docs/analysis/subagent/*.json`，**不得**直接进台账；
  要变台账条目**必须**经 `--from-report`（白名单字段：`title` / `summary` / `family` /
  `anchors` / `facets` / `root_key` / `closure_oracle` / `cover_layers`）或人工总结后走 ①。
  任何「把整份报告塞进 `ecc_findings[]`」的写法都违反本规范。
- **落盘矩阵（2026-10-31 收口）**：三条产出通道同构 —— **文件 + 卫星 `history` 片 + 索引**，
  缺一即「对接断裂面」（不得只留结论）：

  | 通道 | 谁产 | 文件落点 | 卫星片/索引 |
  |:--|:--|:--|:--|
  | `monitor --subagent`（含红队四角色 `RED-SCOPE\|RED-EXPLOIT\|RED-POSTEX\|RED-REPORT`） | CLI 落库段 | `docs/analysis/subagent/<subagent_id>.json` + `.md` | `history` 片 + `satellite_index.<batch>.<subagent_id>`（CLI 落库段） |
  | 审计内嵌 LLM 车道（`audit --crossr` 注解 / `audit --report` 报告生成） | `gk_ecc_sink` | `docs/analysis/audit/<batch>/<arm>.json` + `.md` | `history` 片 + `satellite_index.audit-<batch>.<arm>` |
  | 计划质询（`monitor --subagent --role plan-refinement`） | 同 `monitor` 通道 | `docs/analysis/subagent/<subagent_id>.json` + `.md` | 同 `monitor` 通道 |

  `gk_ecc_sink` 的**入片 projection 是摘要**（`conclusion` 上限 4000 字符 + 机检面三键），
  全量留文件；原始输出非法 JSON 时 **fail-loud** 且原文落 `<arm>.invalid.txt`（不丢证据）。
  审计车道落盘失败**不阻断**审计本身，但必须在 `GK_DBG_LOG` 留 `[ecc-sink] WARN`。
- **机检字段语义边界（2026-10-01，`ECC-728F04A3AB48`）**：`verification` **仅
  plan-refinement 模式有义**（必需字段 `constraint_matrix` / `verification_checklist` 的机检结论）；
  其余模式一律 `{"status":"n/a","retried":false}`，**禁**当「已机检通过」消费。
  `evidence_anchor` 与 `gx_status` 则**全模式**有义。

## 5. 安全网

| 层 | 实现 | 行为 |
|:--|:--|:--|
| 写入边界 | `gk_finding.register` | `source` 空/超长/含空白/不在白名单 → **fail-loud 拒写** |
| 只读体检 | `gk_self_check.check_ecc_form` | `closure_oracle`/`root_key` 违规 → **FAIL**；**存量** `source` 非规范 → **WARN（不 FAIL，不追责）** |
| 形式审计 | `monitor-schemas/ECC-WRITE.json` | 三类 `structural_checks` |
| 行为臂 | `scripts/test_gk_ecc_source_spec.py` | 新写 fail-loud + 存量 WARN 分级 + 提升通道只抽白名单 |

> **增量收口纪律**（用户 2026-09-28 裁定）：**存量 WARN、新写 fail-loud**。历史条目**不追责、
> 不洗数据** —— 用新规去 FAIL 存量等于让机检恒红；改写历史又需要人为裁决归属，两者都不可接受。

## 6. 新增来源的流程

1. 在 `gk_finding._ECC_SOURCES` **单一行**登记新 token（这是唯一登记点）。
2. 若要参与「缺陷族审查层覆盖」强制，加入 `_COVER_REQUIRED_SOURCES`。
3. 在本文件 §1 的产出者表补一行（谁写、走什么通道）。
4. `monitor-schemas/ECC-WRITE.json` 的 `scope.ECC-FINDING` 同步列举。

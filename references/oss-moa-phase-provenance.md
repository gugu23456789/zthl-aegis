# MoA 相位/污染 provenance（公开口径）

本文件定义 MoA 污染折扣的**来源契约**：没有 provenance 的折扣，公开引用一律按 **unadjusted** 处理。事实源 = `scripts/gk_moa_aggregate.py::cluster_references` 的 `consensus` 字段。

## 1. 输出字段

| 字段 | 类型 | 含义 |
|:--|:--|:--|
| `pollution_tilt` | float | 实际应用的污染落地率 κ_tilt（夹逼到 [0,1]） |
| `adjusted` | bool | 是否应用了折扣（`pollution_tilt > 0`） |
| `adjustment_verified` | bool | 折扣是否带**完整 provenance** |
| `pollution_provenance` | dict/null | 验证通过时回显 provenance；否则 `null` |

**公开引用规则**：`adjustment_verified=false` ⟹ 即使 `adjusted=true`，也**必须**按 `unadjusted` 报告（`agreement` 或明确标注“已折扣但未验证”）。

## 2. Provenance schema

```json
{
  "fingerprint": "bc19ba97cbe016479903222bb1578db6",
  "S": 2,
  "N": 200,
  "batch_id": "R5",
  "measured_at": "2026-11-03T00:00:00Z",
  "method": "behavioral | fingerprint-table",
  "source": "gk_model_probe.resolve"
}
```

必需键（缺一即 `adjustment_verified=false`）：`fingerprint` / `S` / `N` / `batch_id` / `measured_at`。

## 3. 口径

1. **同指纹内才可复用 `S`**：`fingerprint` 变 ⟹ 旧 `S`、旧相位格、旧批次一律不续用。
2. **`S` 不得按 alias 推断**：模型名可换后端不换名；`gk_model_probe.resolve` 解析不出 ⟹ `resolved=false`，**不得**回落 `S=2`。
3. **`S` 解析失败的批次**：`adjustment_verified` 必须为 `false`，不得填 provenance。
4. **公开可用的仪器**：
   - 检验：`scripts/gk_phase_stats.py::phase_invariance_test`（纯置换检验，调用方注入 outcomes/labels）；
   - 解析：`scripts/gk_model_probe.py::resolve`（fingerprint 表或行为序列）。
5. **仍闭源的部分**：臂设计/题面夹具/真实 runner（`gk_phase_probe.py`、`gk_phase_confound_sim.py`、`gk_stride_reprobe.py`）。公开包能**验证**，不能**采集**。
6. **当前指纹状态（2026-11-03）**：线上 `bc19ba97…`；`S=2` 取证于 `aeb564…` ⟹ 已失效；金标/准确率/熵三种重探均 `resolved=false`。

## 4. 示例

```python
import gk_moa_aggregate as M
import gk_model_probe as P

meta = {"model": "deepseek-flash", "system_fingerprint": "bc19ba97cbe016479903222bb1578db6"}
res = P.resolve(meta=meta, known_strides={"bc19ba97cbe016479903222bb1578db6": 2})
prov = ({"fingerprint": res["fingerprint"], "S": res["stride"], "N": 200,
         "batch_id": "R5", "measured_at": "2026-11-03T00:00:00Z"}
        if res["resolved"] else None)
cons = M.cluster_references(refs, pollution_tilt=0.4, provenance=prov)["consensus"]
# res["resolved"] is False ⟹ prov=None ⟹ adjustment_verified=False ⟹ 公开按 unadjusted
```

## 5. 与公开面的关系

- `oss-hooks.md` 的同批原则：**能验证的公开、能采集的闭源**。
- 公开包不含 `pollution_tilt` 的生成器；调用方必须自带 provenance，否则输出只具“未验证折扣”的审计价值。

## 6. 指纹换代：什么适用、什么失效

| 对象 | 是否受指纹变化影响 | 说明 |
|:--|:--|:--|
| 单元/回归测试 | **不受影响** | 测的是逻辑（置换检验、折扣公式、fail-loud 契约），不绑定具体模型 |
| 旧 `S` 取证（`aeb564…` 上测得 `S=2`） | **失效** | `S` 是 per-model/后端量；换指纹 ⟹ 旧 S、旧相位格、旧批次不得续用 |
| `stride_S_freshness` | **必须 FAIL** | 它就是“旧取证不适用新指纹”的机检表达 |
| 探针本身（臂设计闭源） | **仍适用** | 它是重测仪器；本次在新模型上“信号低于检出限” |
| NIAH 任务/观测量 | **可能需要换** | 对新模型太简单（金标/准确率饱和）⟹ 是任务难度不匹配，不是测试坏 |

> **测试套件不因模型换代而失效；失效的是“在旧指纹上标定的 S 与相位参数”。新指纹下必须重测 S；重测不出时，探针按契约返回 `resolved=false`，下游继续按 unadjusted，而不是套用旧的 `S=2`。**

## 7. 实测记录（2026-11-03）

**指纹时间线**：`aeb56401ca74e127821c4f9126dcb669`（`S=2` 取证）→ `e72d3c7f663d3e1383b00b3884cb4501`（曾钉定）→ **`bc19ba97cbe016479903222bb1578db6`（实测线上）**。

| 轮次 | 配置（私仓探针；工具闭源，记录公开） | 调用 | 结果 | 结论 |
|:--|:--|--:|:--|:--|
| 1 | `--long --pairs 200`，gold 观测 | 32 | `L=0..15` 准确率全 1.0、logprob 全 0.0 | 天花板，无方差；`resolved=false` |
| 2 | `--long --pairs 200`，entropy，`lengths=16`，`repeats=4` | 64 | `S=2` p=0.934；`S=3` p=0.266 | 不显著；`resolved=false` |
| 3 | `--long --pairs 300`，entropy，`lengths=32`，`repeats=3`，`concurrency=8` | 96 | 最强候选 `S=3` p=0.101；`S=2` p=0.304；`[24,32,128]` underpowered | 不显著；`resolved=false` |

- 三轮均 `missing=0`（API 可达）；`p` 为置换检验值；多候选下 Bonferroni 阈值更严（表内未做校正）。
- **结论**：`bc19…` 下 `S` 未解析；不得回填 `PINNED.stride_S`；公开 MoA 保持 `adjustment_verified=false`（unadjusted）。
- 公开包可复现的部分：`scripts/gk_phase_stats.py::phase_invariance_test`（给 outcomes/labels 即可复算 p）。**臂设计与 runner 不在公开包**，因此上表的原始观测无法由公开包重采。

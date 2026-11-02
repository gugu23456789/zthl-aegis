#!/usr/bin/env python3
"""`SUBA_TIERS` **单一事实源** + `η_tier`（档位增益系数）**实算**。

由来（finding `ECC-46C8BF837715`，2026-10-08）：`SUBA_TIERS` 原内联于 `subagent_runner.py`
（该文件顶层 `import openai / agents` ⟹ **重依赖**），而 η_tier 只作为**常数**活在计划文档
（`docs/plans/2026-09-14-convergence-evaluator-subplan.md §1.2 / §8.19.2`）⟹ 两处漂移
（表记 `g_token(3→4)=2.0×`，实网 `1,000,000 → 3,000,000 = 3.0×`）。

本模块 = **轻量**（零第三方依赖）⟹ 收敛评估器可低成本 `import` 并**实算** η_tier，
终结「常数抄表 ⟹ 漂移」。`subagent_runner` 改为**从此处 import**（名字不变 ⟹ 既有引用零回归）。

（下表逐字自 `subagent_runner.py` 迁出；注释块随迁。）
"""
# ─── 4 档梯度表（2026-08-27 建档，2026-08-28 补输出上限，2026-08-28 补超时/重试，
#     2026-09-11 token 类全套 ×2.5）───
# token_budget:    L2 任务级 token 总预算 = 输入+输出（含 thinking）累计合计（_BudgetHooks
#                   on_llm_end 累加 usage.total_tokens；soft=ratio×budget, hard=budget）。
#                   ⚠️ 2026-09-11 ×2.5 后 tier4 = 1,000,000 = DeepSeek 满上下文窗口
#                   （输入+输出共享 1M），故 tier4 的 hard 限实际由上下文窗口先触底；
#                   max_output_tokens 最高 80,000 仍 < 384K 单次输出上限。
# item_budget:     L3 合并预算（turns×工具调用）；max_turns = item_budget//5（main 推导）
# max_output_tokens: 单次响应输出上限（每次 LLM 调用的 max_tokens，含 thinking）。
#                    --tier 且未显式设 SUBAGENT_MAX_TOKENS 时自动采用
#                    （CLI plan-refinement 显式 16000 / paper-review 显式 20000 覆盖档位值；
#                    档位实值见下表：10000/20000/40000/80000，单一事实源 = 本表）。
# timeout:         单次 API 调用超时上限（秒）— 随档位缩放：档位越高任务越重，允许更长的
#                   续读/多轮窗口（对齐 Hermes reference_timeout 语义：per-call 可配）。
# max_file_bytes:  read 工具单文件读取硬上限（30MB 总硬上限，tier 越低越保守）
#                   ⚠️ 2026-09-11：本字段**不随 ×2.5 缩放**（受 30MB 总硬上限约束）。
# tools:           工具白名单（tier 越高工具越全）
SUBA_TIERS = {
    # 2026-08-28 梯度上调（用户质询 L151 是否过低）：
    # ① token_budget 为输入+输出（含 thinking）累计硬限 — v4-flash thinking=high 单轮
    #    常耗 2-4K，原 20K/50K/120K/250K 对多轮任务（窄任务 3-6 轮 / plan-refinement
    #    读 138KB 计划≈35K/次）贴近上限 → 风险=中途 hard-block 截断分析 → 结论不可信；
    # ② max_output_tokens 含 thinking — 原 2000 时 thinking 消耗后可见输出被饿死；
    # ③ timeout 为单次 API 调用上限 — thinking=high 慢时 120s 偏紧。
    # 上调后 ≈1.6-2x（仍是硬限，软限 ratio 触发 WARN，成本可控）。_ECC_BOUNDS 不变
    # （报告内容字段有界，与 thinking 消耗解耦）。
    # 2026-09-11 二次上调（用户指令"档位全部翻 2.5 倍，下限抬到 8000"）：
    # token_budget / item_budget / max_turns / max_output_tokens / timeout 五项 ×2.5；
    # max_file_bytes 不动（30MB 总硬上限）；非 --tier 回落下限 800→8000（见 L1490）。
    1: {"token_budget": 100000,  "item_budget": 375,  "max_turns": 100,  "max_output_tokens": 10000,
        "timeout": 375,
        "max_file_bytes": 10 * 1024 * 1024,
        # 2026-08-30 低档位补全（用户质询"各档位的工具限制太小了"）：tier1 原仅 search,read，
        # 连 read_repo 都没有 → 低档位任务无法读注册仓库/论文源 → 补全三件套。
        # 2026-11-01（owner 裁定）：`search`/`read_bridge` 已合并（→ code_search / read_repo），
        #   全档位同步；低档位也要有检索工具 ⟹ tier1 补 code_search。
        "tools": "code_search,read,read_repo,read_doc,json_extract,json_read,json_write"},
    2: {"token_budget": 200000,  "item_budget": 750,  "max_turns": 200,  "max_output_tokens": 20000,
        "timeout": 450,
        "max_file_bytes": 20 * 1024 * 1024,
        "tools": "read,read_repo,code_search,read_doc,json_extract,json_read,json_write"},
    # 2026-10-03（用户裁定「tier3/4 系数放大 + 预算 ×2」）：全维 ×2。
    #   依据 = A8/RCA 残差收敛（r̂≥1 ⟹ 外部熔断：预算闸门，
    #   references/sequence-node-safety-net-template.md:65）+ η_tier（3→4 是唯一「工具面恒等」相邻档，
    #   docs/plans/2026-09-14-convergence-evaluator-subplan.md:203）。
    #   实测触发点：tier3（cap 500K）单臂成本当量 676,013 已 hard 截停（sub-1791039236-413-22693）。
    3: {"token_budget": 1000000, "item_budget": 4000, "max_turns": 800,  "max_output_tokens": 80000,
        "timeout": 1200,
        "max_file_bytes": 30 * 1024 * 1024,
        "tools": "read,read_repo,code_search,gitnexus,read_doc,gx_context,gx_impact,gx_query,gx_detect_changes,gx_trace,gx_guide,ci-diagnose,json_extract,json_read,json_write"},
    # 2026-09-26（`ECC-A2ECF8371F96`）：tier4 ×1.5 上调 1,000,000 → 1,500,000。
    # 口径 = **成本当量**（`miss + hit×_PRICE_HIT_RATIO + completion×_PRICE_OUTPUT_RATIO`，
    #   见 `_BudgetHooks.on_llm_end`）—— **非 raw token**（raw = 请求级 total_tokens 含缓存命中
    #   重发量，只作量级参考，**禁止与该 cap 直接比**）。基准（2026-09-26 实测本仓）：单臂
    #   plan-refinement 质询成本当量 **1,146,006** 已 > 1M ⟹ `budget_status=hard` 截停分析 ⟹
    #   原硬限低于真实成本中位；本次 +31% margin，待多臂补课成本数据到位后**再标定**。
    #   （注：hook-xenv §15.1 台账列的是 **raw** 1,259,506，属口径错误 —— 不可直接比。）
    # 2026-10-03（同上 ×2）：1,500,000 → 3,000,000（含 item/turns/out/timeout 全维 ×2）。
    4: {"token_budget": 3000000, "item_budget": 8000, "max_turns": 1600, "max_output_tokens": 160000,
        "timeout": 1800,
        "max_file_bytes": 30 * 1024 * 1024,
        "tools": "read,read_repo,code_search,gitnexus,read_doc,gx_context,gx_impact,gx_query,gx_detect_changes,gx_trace,gx_guide,ci-diagnose,json_extract,json_read,json_write"},
}
DEFAULT_TIER = 3


# ── 2026-10-10（`ECC-A34A8540151B`）：**provider 单次输出硬上限**（钳制档位值）──
# 病因：`SUBA_TIERS[tier].max_output_tokens` 可超所用模型硬上限（实测 tier4=160000 打 MiMo
#   → `400 Param Incorrect: max_tokens is too large: 160000 ... at most 131072`）。
#   回归源 = 2026-10-03 撤销 plan-refinement 的 16000 硬覆盖后，档位值**直通**模型。
# 单源 = 本表；实测锚 = `docs/plans/2026-09-22-mimo-v26-output-probe-subplan.md`
#   （MiMo flash/pro/ultraspeed 均 ≤131072；DeepSeek 有效域 [1, 393216]）。
# ⚠ 未知 provider ⟹ **不钳制**（fail-open：不因表缺而误伤）；显式 env `SUBAGENT_MAX_TOKENS` 仍可覆盖。
MODEL_MAX_OUTPUT_TOKENS = {"deepseek": 393216, "mimo": 131072}
# 推断提示（子串匹配，小写）：(hay, provider) —— 顺序敏感（`xiaomimimo` 先于 `mimo`）。
_PROVIDER_HINTS = (("xiaomimimo", "mimo"), ("mimo", "mimo"), ("deepseek", "deepseek"))


def provider_of(api_base: str = "", api_model: str = "") -> str:
    """从 `api_base` / `api_model` 推断 provider token（键同 `MODEL_MAX_OUTPUT_TOKENS`）；未知 ⟹ ''。"""
    blob = ("%s %s" % (api_base or "", api_model or "")).lower()
    for hint, name in _PROVIDER_HINTS:
        if hint in blob:
            return name
    return ""


def clamp_max_output_tokens(value, provider: str = ""):
    """把单次输出上限钳到 provider 硬上限。

    provider 未知 / 值不可解析 ⟹ **原值返回**（fail-open：不误伤）；否则 `min(value, cap)`。
    """
    cap = MODEL_MAX_OUTPUT_TOKENS.get((provider or "").strip().lower())
    try:
        v = int(value)
    except (TypeError, ValueError):
        return value
    return min(v, cap) if cap else v

# η_tier 的 6 个分量 ↔ `SUBA_TIERS` 字段（**唯一映射**；`_GAIN_DIMS` 顺序 = 文档 §1.2 记号序）。
_GAIN_DIMS = ("token_budget", "item_budget", "max_turns", "max_output_tokens", "timeout", "max_file_bytes")
_GAIN_ALIAS = {"token_budget": "g_token", "item_budget": "g_item", "max_turns": "g_turns",
               "max_output_tokens": "g_out", "timeout": "g_timeout", "max_file_bytes": "g_file"}


def tier_gain(frm, to) -> dict:
    """η_tier 的**实算**（6 维）—— 分量 = 高档值 ÷ 低档值，取自 **live `SUBA_TIERS`**（非抄文档常数）。

    finding `ECC-46C8BF837715` 的修复点：原 η_tier 只在计划文档里是常量表，随 2026-09-26（tier4 ×1.5）
    与 2026-10-03（两档 ×2）**漂移**（表记 3→4 `g_token=2.0×`，实网 `1,000,000→3,000,000 = 3.0×`）。
    → `{"g_token": .., "g_item": .., "g_turns": .., "g_out": .., "g_timeout": .., "g_file": ..}`；
    档位不存在 ⟹ `KeyError`（fail-loud，禁静默）。
    """
    a, b = SUBA_TIERS.get(int(frm)), SUBA_TIERS.get(int(to))
    if not a or not b:
        raise KeyError("unknown tier: %r/%r" % (frm, to))
    out = {}
    for d in _GAIN_DIMS:
        va, vb = a.get(d), b.get(d)
        out[_GAIN_ALIAS[d]] = (vb / va) if (va not in (None, 0) and vb is not None) else None
    return out


# 3→4（唯一「工具面恒等」相邻档；T10 的采集对）的实算增益 —— 供收敛评估器零成本取用。
TIER_GAIN_34 = tier_gain(3, 4)


if __name__ == "__main__":
    # B6（2026-10-27，RED-MIGRATE-INLINE）：模块自有 CLI（取代内联 import 薄壳）。
    import sys as _sys

    if _sys.argv[1:] == ["max-tier"]:
        print(max(SUBA_TIERS))
    else:
        print("usage: gk_suba_tiers.py max-tier", file=_sys.stderr)
        _sys.exit(2)

#!/usr/bin/env python3
"""缓存 / 用量观测（W2A §6.3(6) ④；`ECC-F0D3F78E9F58`）。

移植 dsh-context（Apache-2.0）host/usage 归因的**形状**：`UsageLike{input, cacheRead,
cacheWrite, output}` + `tokenCountOf` 消毒（`src/host/foldMetering.ts`）。dsh-context
**假定** provider usage 已归一；raw→桶的映射它**不提供**（spec §6.3(6) **P1**）⟹ 本模块**自建**
（每 vendor 一表）。

逐调用记录 §6.3(6) 红线 ②③④：
  * `cache-hit / cached tokens` 作**协变量**（归一桶 + 命中率）；
  * 注入长度 `L` 对齐 provider 的 **token 块**边界（消 (ii) 与 stride `S` 的别名）；
  * 跨轮 **cache 失效点**（warm 之后 cache-read 下坠）。

纯只读观测层（无 API、无 CLI）——喂它 runner 已经落盘的 raw 逐调用 usage 即可；产物经
`cache_covariate()` 交 `gk_moa_aggregate` 作协变量。**禁**直接执行（技能内置 cmd 路由）。
"""
BUCKETS = ("input", "uncached", "cacheRead", "cacheWrite", "output")

# raw provider field -> normalized bucket.  Dotted key walks nested objects.
# P1: these tables are OURS (dsh-context reads usage already normalized).
PROVIDER_USAGE_MAP = {
    "deepseek": {                       # prompt_tokens = hit + miss
        "prompt_cache_hit_tokens": "cacheRead",
        "prompt_cache_miss_tokens": "uncached",
        "prompt_tokens": "input",
        "completion_tokens": "output",
    },
    "openai": {
        "prompt_tokens_details.cached_tokens": "cacheRead",
        "prompt_tokens": "input",
        "completion_tokens": "output",
    },
    "anthropic": {
        "cache_read_input_tokens": "cacheRead",
        "cache_creation_input_tokens": "cacheWrite",
        "input_tokens": "input",
        "output_tokens": "output",
    },
}


def token_count_of(value):
    """A provider usage bucket as a billed count, or `None` when unreadable.

    `dsh-context`'s `tokenCountOf` port: fractions round, negatives clamp to 0,
    NaN/inf/non-numeric read as absent (never propagate a poison figure downstream).
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        f = float(value)
        return None if (f != f or f in (float("inf"), float("-inf"))) else max(0, round(f))
    if isinstance(value, str) and value.strip():
        try:
            f = float(value)
        except ValueError:
            return None
        return None if (f != f or f in (float("inf"), float("-inf"))) else max(0, round(f))
    return None


def _dig(obj, dotted):
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def normalize_usage(provider, usage):
    """Raw provider usage -> `{bucket: int}` (missing / unreadable buckets = 0)."""
    table = PROVIDER_USAGE_MAP.get(provider)
    if table is None:
        raise ValueError("unknown provider %r (add a PROVIDER_USAGE_MAP row)" % provider)
    out = {b: 0 for b in BUCKETS}
    for raw, bucket in table.items():
        n = token_count_of(_dig(usage if isinstance(usage, dict) else {}, raw))
        if n is not None:
            out[bucket] = max(out[bucket], n) if bucket == "input" else out[bucket] + n
    return out


def block_alignment(l, block):
    """Align the injected length `l` (tokens, F2) to the provider's `block` granularity.

    `residue = l mod block`; `crossed` marks a filler that moves the content across a
    block boundary (the (ii) alias risk against the compression stride).  `block<=1`
    disables alignment.
    """
    if block <= 1:
        return {"aligned": l, "residue": 0, "crossed": False}
    return {"aligned": (l // block) * block, "residue": l % block, "crossed": (l % block) != 0}


# 二条件 (a)「极高缓存命中」的**可判定**口径（2026-10-17）：
#   · warm-up 前 `warmup_rounds` 轮不计（首轮必 miss，短会话里会系统性拉低均值）；
#   · 稳态样本不足 `min_steady` ⟹ **UNKNOWN**（不冒充「极高」或「不达标」）；
#   · `>= extreme` = EXTREME（极高）、`>= target` = PASS、否则 BELOW_TARGET。
CACHE_TARGET_DEFAULT = 0.90
CACHE_EXTREME_DEFAULT = 0.95
CACHE_STEADY_MIN_CALLS = 20


def _ratio(rows):
    denom = sum(r["uncached"] + r["cacheRead"] for r in rows)
    return round(sum(r["cacheRead"] for r in rows) / denom, 4) if denom else None


def observe(calls, block=8, stride=4, warmup_rounds=3, target=CACHE_TARGET_DEFAULT,
            extreme=CACHE_EXTREME_DEFAULT, min_steady=CACHE_STEADY_MIN_CALLS):
    """Normalize a call sequence; return `(rows, summary)`.

    `calls` = raw per-call records `{turn?, provider, l, usage, outcome?}`; `l` is the
    injected filler length in TOKENS (phase = `l mod S`).

    2026-10-17（二条件 (a)）：summary 增 `warmup_cache_hit_ratio` / `steady_cache_hit_ratio`
    （前 `warmup_rounds` 轮剔除）+ `cache_target` / `cache_status`；稳态样本 < `min_steady`
    或零分母 ⟹ `cache_status=UNKNOWN`（**禁**把短会话 warm-up 均值读成「极高」）。
    """
    rows, invalidation = [], []
    prev_read = None
    for i, rec in enumerate(calls):
        provider = rec.get("provider", "")
        usage = normalize_usage(provider, rec.get("usage", {}))
        l = int(rec.get("l", 0))
        row = {"turn": rec.get("turn", i), "provider": provider, "l": l,
               "phase": (l % stride) if stride > 0 else None}
        row.update(usage)
        a = block_alignment(l, block)
        row.update({"aligned_L": a["aligned"], "residue": a["residue"],
                    "block_crossed": a["crossed"]})
        denom = row["uncached"] + row["cacheRead"]
        row["cache_hit_ratio"] = round(row["cacheRead"] / denom, 4) if denom else None
        if "outcome" in rec:
            row["outcome"] = rec["outcome"]
        # cross-turn invalidation: a cache read that drops after a warm turn
        if prev_read is not None and row["cacheRead"] < prev_read:
            invalidation.append({"turn": row["turn"], "from": prev_read, "to": row["cacheRead"]})
        prev_read = row["cacheRead"]
        rows.append(row)

    tot = {b: sum(r[b] for r in rows) for b in BUCKETS}
    warm = rows[:max(0, int(warmup_rounds))]
    steady = rows[max(0, int(warmup_rounds)):]
    steady_ratio = _ratio(steady)
    if steady_ratio is None or len(steady) < int(min_steady):
        cache_status = "UNKNOWN"
    elif steady_ratio >= extreme:
        cache_status = "EXTREME"
    elif steady_ratio >= target:
        cache_status = "PASS"
    else:
        cache_status = "BELOW_TARGET"
    summary = {
        "calls": len(rows),
        "totals": tot,
        "cache_hit_ratio": _ratio(rows),
        "warmup_rounds": max(0, int(warmup_rounds)),
        "warmup_calls": len(warm),
        "warmup_cache_hit_ratio": _ratio(warm),
        "steady_calls": len(steady),
        "steady_cache_hit_ratio": steady_ratio,
        "cache_target": target,
        "cache_extreme": extreme,
        "cache_status": cache_status,
        "invalidation_points": invalidation,
        "block_crossings": sum(1 for r in rows if r["block_crossed"]),
    }
    return rows, summary


def cache_covariate(rows):
    """The red-line ② covariate carrier: per-call `cache_hit_ratio` (+ `outcome` link).

    A plain, serializable series the MoA aggregate can consume as a covariate
    (mediation probe, spec §6.3(6) ②).  No causal claim -- recorded only.
    """
    return [{"turn": r["turn"], "cache_hit_ratio": r["cache_hit_ratio"],
             **({"outcome": r["outcome"]} if "outcome" in r else {})} for r in rows]

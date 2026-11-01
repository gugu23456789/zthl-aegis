"""RCA 污染调控函数 φ(κ, n) 的**可估框架**（W2，2026-10-06）。

单一事实源 = `references/moa-kappa-ledger.json`（κ 跨轮样本）。
理论依据 = `docs/plans/2026-09-14-convergence-evaluator-subplan.md §7 [ASSUMPTION-5]`：

  · κ = (κ_cap, κ_tilt) = (识破假前提数 / 污染样本数, 被带偏数 / 污染样本数) ∈ [0,1]²（**紧集** ⟹ φ 自动有界）。
  · **逐轮污染注入效应**：

        φ(κ, n) = (1 − κ_cap) · κ_tilt · n^(−p_tilt)

      ─ (1 − κ_cap) = **逃逸率**（未被检出、留在上下文里的那部分）
      ─ κ_tilt      = 已**落地**的带偏率
      ─ n^(−p_tilt) = 单次注入在系统成熟度 `n`（攻击事件数）下的**杠杆衰减**

  · **累积杠杆**：

        Λ(N) = Σ_{n=1..N} φ = (1 − κ_cap) · κ_tilt · Σ n^(−p_tilt)

      ─ `p_tilt > 1` ⟹ **有界**（ζ 收敛）⟹ 不爆炸
      ─ `p_tilt = 1` ⟹ ~ ln N（对数）
      ─ `p_tilt < 1` ⟹ ~ N^(1−p_tilt)（**次线性**）—— **默认先验**与 arXiv:2602.13320「MCP 鞅：失真线性、非指数」同向；
        **非绝对排除**指数：本公理 = **可拟合先验**，可被后续样本推翻（不写成绝对律）。

  · **拟合入参** `p_tilt = − d ln κ_tilt / d ln n_events`（对数-对数 OLS 斜率；单源记录在 ledger `n_events`）。

**`[UNFITTED]` 纪律**（对齐本仓「⟦未验证⟧」）：数据不足或退化时**不猜**，返回具名 reason、不产点估计。

**现状（2026-10-06 普查，n=11 批）**：`p_tilt` **不可估** ——
  ① **κ_tilt 零膨胀**：11 批中显式记 tilt 者 5 批，其中仅 **2** 批 > 0（< min_nonzero=3）⟹ `ZERO_INFLATED_INSUFFICIENT_NONZERO`；
  ② **全批未记 `n_events`**（拟合自变量缺失）⟹ 即便非零点够也多走 `MISSING_EVENT_COUNT`。
⟹ 本框架**就位但输出 `[UNFITTED]`**；解封须在**采样侧**补两项（见 `references/moa-kappa-ledger.json` `note`）。

**装配状态（2026-10-06 更新，A 批）**：`batch_tilt` 已由 `gk_moa_aggregate.aggregate()` 消费（批级乘性折扣）；
`phi` / `cumulative_leverage` **仍零消费者**（`[UNFITTED]` ⟹ 只是**假设层**，**不得**据其硬阻断）。

**三通道 κ（A′，2026-10-06）**：污染 = `p_in` 输入 / `p_art` 产物 / `p_meta` 测量，遍及 **G1/G2/G3 与人类评审**；
合成落地率 `tilt_total = 1 − Π(1 − κ_tilt_i)`（缺通道按 0）；ledger 可选 `channels` 字段，legacy `cap/tilt` 视作 `p_in`。
**接通（2026-10-06 晚）**：`p_meta`/`p_art` 现可由**真实观测面**派生 `κ_tilt`（`derive_channels`：
`divergence`→`p_meta` / `defect_rate`→`p_art`），经 `batch_tilt(..., divergence=, defect_rate=)` 与
ledger 通道**合成** ⟹ 不再退化为纯 P-in；观测缺失则不落该通道（**不冒充已覆盖**）。
"""
import json
import math
import os

_LEDGER_DEFAULT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "references", "moa-kappa-ledger.json")


def load_ledger(path=None):
    """读 κ 样本 ledger → `samples[]`（单一事实源）。"""
    with open(path or _LEDGER_DEFAULT, encoding="utf-8") as fh:
        return json.load(fh).get("samples", [])


def _ratio(v):
    """`[num, den]` → 比值（den=0 ⟹ `None`）；亦接受**直接浮点**（派生通道 `{"tilt": 0.3}`）。"""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    num, den = v
    return (num / den) if den else None


def kappa(sample):
    """样本 → `(κ_cap, κ_tilt)`（分母 0 ⟹ `None`）。"""
    return _ratio(sample["cap"]), _ratio(sample["tilt"])


_CHANNELS = ("p_in", "p_art", "p_meta")   # 污染三通道：输入 / 产物 / 测量（遍及 G1/G2/G3 与人类评审）


def kappa_channels(sample):
    """样本 → `{通道: (κ_cap, κ_tilt)}`。ledger 可给 `channels` 字段（`cap` 可选、`tilt` 必备）；
    缺则 legacy `cap/tilt` 视作 `p_in`。派生通道只给 `tilt` ⟹ `cap=None`（观测缺失，不猜）。"""
    ch = sample.get("channels")
    out = {}
    if isinstance(ch, dict):
        for k in _CHANNELS:
            pair = ch.get(k)
            if isinstance(pair, dict) and (pair.get("cap") is not None or pair.get("tilt") is not None):
                out[k] = (_ratio(pair.get("cap")), _ratio(pair.get("tilt")))
    if not out and "cap" in sample and "tilt" in sample:
        out["p_in"] = kappa(sample)
    return out


def combined_tilt_of(tilts):
    """由**一组 κ_tilt** 合成 `tilt_total = 1 − Π(1 − κ_tilt_i)`（`None` 跳过；全 `None` ⟹ `None`）。"""
    ts = [t for t in tilts if t is not None]
    if not ts:
        return None
    prod = 1.0
    for t in ts:
        prod *= (1.0 - max(0.0, min(1.0, float(t))))
    return round(1.0 - prod, 4)


def combined_tilt(sample):
    """**三通道合成落地率** `tilt_total`（缺通道按 0 ⟹ 不影响；全缺 ⟹ `None`）。"""
    return combined_tilt_of([t for (_c, t) in kappa_channels(sample).values()])


def derive_channels(*, divergence=None, defect_rate=None, poison_rate=None):
    """从**真实观测面**派生通道 κ_tilt（**只给 tilt**；κ_cap 观测缺失 ⟹ 不猜、留 `None`）。

    · **p_in**   ← `poison_rate`（输入通道投毒率 = 命中投毒词的 ref 数 / ref 总数）
    · **p_meta** ← `divergence`（双盲 `|agent − human|` = **测量被带偏度**）
    · **p_art**  ← `defect_rate`（缺陷产物率 = 缺陷 finding 数 / 产物数）

    `None` ⟹ **不落该通道**（不冒充已覆盖）。返回值形态与 ledger `channels` 同构，可直接并入。
    """
    ch = {}
    if poison_rate is not None:
        ch["p_in"] = {"tilt": round(float(poison_rate), 4)}
    if divergence is not None:
        ch["p_meta"] = {"tilt": round(float(divergence), 4)}
    if defect_rate is not None:
        ch["p_art"] = {"tilt": round(float(defect_rate), 4)}
    return ch


def batch_tilt(batch_id, path=None, *, divergence=None, defect_rate=None, poison_rate=None):
    """按**批 id** 取**批级合成** κ_tilt：ledger 样本 **+ 实时观测派生**（接通三通道）。

    ⚠ **批级、全臂、三通道**：污染 = `p_in` 输入 / `p_art` 产物 / `p_meta` 测量，
    遍及 **G1/G2/G3 与人类评审**；G3 只是**明确投毒**（不作污染判据）。
    · **通道级 merge**（2026-10-06 修）：ledger 与 live **按通道**合并，**live 覆盖同通道**；
      修前是「ledger 通道 ⊕ live 全量**拼接**」⟹ 同通道被计两次（如 ledger `p_in` + live `p_in`
      双计）。合成 `tilt_total = 1 − Π(1 − κ_tilt_i)`（缺者跳过）。
    · 批不在 ledger 但有实时观测 ⟹ 只用实时观测；两者皆无 ⟹ `None`（**零回归**）。
    `None` ⟹ 调用方须退化为无折扣。
    """
    live = derive_channels(divergence=divergence, defect_rate=defect_rate,
                           poison_rate=poison_rate)
    for s in load_ledger(path):
        if s.get("batch") == batch_id:
            merged = {c: t for (c, (_cap, t)) in kappa_channels(s).items()}
            for c, v in live.items():
                if v.get("tilt") is not None:
                    merged[c] = v["tilt"]
            return combined_tilt_of(list(merged.values()))
    return combined_tilt_of([v["tilt"] for v in live.values()
                             if v.get("tilt") is not None]) if live else None


def _ols_slope(xs, ys):
    """最小二乘斜率；`x` 全等 ⟹ `None`（不可辨）。"""
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    den = sum((x - mx) ** 2 for x in xs)
    if den == 0:
        return None
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / den


def estimate_p_tilt(samples, *, min_nonzero=3):
    """拟合 `p_tilt = − d ln κ_tilt / d ln n_events`（对数-对数 OLS）。

    两类数据缺口**分别具名**（不并成一个模糊的 insufficient）：
      · 非零 κ_tilt 点 < `min_nonzero` ⟹ `ZERO_INFLATED_INSUFFICIENT_NONZERO`
      · 非零点中缺 `n_events` 者 < `min_nonzero` ⟹ `MISSING_EVENT_COUNT`

    2026-10-26（D 子计划 §14.4-5）：取数改走 `kappa_channels` 的 **p_in** 通道（单源）——
    原 `kappa(s)` 读顶层 `cap`/`tilt`，对**只给 `channels`** 的样本抛 `KeyError`（三通道
    ledger 行无法参与拟合）。缺 p_in 通道的样本按「无观测」跳过（不猜）。
    """
    nonzero, with_events = 0, []
    for s in samples:
        _cap, tilt = kappa_channels(s).get("p_in", (None, None))
        if tilt is None or tilt <= 0:
            continue
        nonzero += 1
        if s.get("n_events"):
            with_events.append((float(s["n_events"]), tilt))
    if nonzero < min_nonzero:
        return {"ok": False, "unfitted": True,
                "reason": "ZERO_INFLATED_INSUFFICIENT_NONZERO",
                "n_nonzero": nonzero, "min_nonzero": min_nonzero}
    if len(with_events) < min_nonzero:
        return {"ok": False, "unfitted": True, "reason": "MISSING_EVENT_COUNT",
                "n_with_events": len(with_events), "min_nonzero": min_nonzero}
    slope = _ols_slope([math.log(n) for n, _ in with_events],
                       [math.log(t) for _, t in with_events])
    if slope is None:
        return {"ok": False, "unfitted": True, "reason": "DEGENERATE_EVENT_COUNTS"}
    return {"ok": True, "p_tilt": -slope, "n_points": len(with_events)}


def phi(sample, n_events, *, p_tilt=None):
    """逐轮污染注入效应 `φ(κ, n) = (1 − κ_cap)·κ_tilt·n^(−p_tilt)`。"""
    cap, tilt = kappa(sample)
    if cap is None or tilt is None:
        return {"ok": False, "unfitted": True, "reason": "KAPPA_UNDEFINED"}
    if not n_events or n_events <= 0:
        return {"ok": False, "unfitted": True, "reason": "N_EVENTS_INVALID"}
    if p_tilt is None:
        return {"ok": False, "unfitted": True, "reason": "P_TILT_UNFITTED"}
    return {"ok": True, "phi": (1.0 - cap) * tilt * (n_events ** (-p_tilt)),
            "escape": 1.0 - cap, "tilt": tilt, "p_tilt": p_tilt}


def cumulative_leverage(sample, n_rounds, *, p_tilt=None):
    """`Λ(N) = Σ_{n=1..N} φ`；`p_tilt>1` ⟹ `bounded=True`（不爆炸），`p_tilt<1` ⟹ 次线性。"""
    cap, tilt = kappa(sample)
    if cap is None or tilt is None:
        return {"ok": False, "unfitted": True, "reason": "KAPPA_UNDEFINED"}
    if p_tilt is None:
        return {"ok": False, "unfitted": True, "reason": "P_TILT_UNFITTED"}
    total = (1.0 - cap) * tilt * sum(math.pow(n, -p_tilt) for n in range(1, int(n_rounds) + 1))
    return {"ok": True, "leverage": total, "bounded": p_tilt > 1.0, "p_tilt": p_tilt}

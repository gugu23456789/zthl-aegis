#!/usr/bin/env python3
"""T2 收敛评估器（**数学核**；单一事实源 = `references/convergence-evaluator.md` —— 机制正本，**禁放 docs/plans**）。

**口径（2026-09-14 用户裁定：F-REV-62 → 候选 (iii-a) 去重 fid + 候选 (i) stock 比）**：

    μ_n = μ_{n−1} − a_n + b_n            # 存量递推（μ = open + in_progress 计数）
    a_n = 第 n 轮**首次离开 open 集**的不同 fid 数（**去重**；同一 fid 的 fixed+closed 不双计）
    b_n = 第 n 轮 register 事件数
    μ̂₀ = |{f : f.status ∈ {open, in_progress}}|     # **当前**残留（= 预测起点 `μ_N`）
    r̂  = (μ_N / μ_0)^{1/N}               # **stock 比** = 相邻轮间 μ_n/μ_{n−1} 的几何均值
    r̂ < 1 ⟹ N* = ⌈ ln(μ̂₀ / μ_tgt) / ln(1 / r̂) ⌉
    r̂ ≥ 1 ⟹ N* = ∞ + verdict="block"（须外部熔断：冻结扩张 b→0）
    N*_hi = N*(r̂ + δ) / N*_lo = N*(r̂ − δ)      # δ = GK_CONV_DELTA（默认 0.1）

⚠ **口径变更史（禁再混口径）**：初版实现 = `r̂ = b̄/ā` 且 `a` 按**事件**计数（同一 fid 的
`verify`→`fixed` 与 `close`→`closed` **双计**）⟹ `r̂` 会依赖"记账风格"，且在 r7 journal
实测得 `r̂=0.714` 而主 state 得 `1.812`（同式不同义）⟹ **F-REV-62（high）**。现口径下
`a` 去重 + `r̂` 走 stock 轴 ⟹ 语义 = "**残留缺陷的轮间衰减率**"，与 §1.1 `γ`/`μ`、§1.2 `ρ` 对齐。

**前提门（§1 C3）**：`T` 未冻结 ⟹ 拒出 `N*`，报 `T_NOT_FROZEN`。
  producer = `gate_data.t_star`（本模块 `freeze_t_star`/`load_t_star` 为**唯一读写点**；
  CLI `t-star freeze|show` 调本模块写、`evaluate`/`gate` 读）⟹ **机器可读落点**（F-REV-57 处置）。

**fail-soft（判据 8）**：state/journal 不可读 ⟹ `ok:false` 且**不阻断**入队（T4 只 WARN）。

**实现决策（规格未定处，显式登记；禁默默自创）**：
  - **D1「轮」切分** = finding journal 的 **epoch 标记**（`gk_finding._EPOCH_EVENT`，`register()`
    在代际初启时自动打一枚）；**无 epoch ⟹ 整段算一轮**（输出 `rounds_basis` 标明）。
  - **D2「消解」** = 事件 `to ∈ {fixed, closed, rejected}` 使 finding 离开 open 集；
    **计 a 时按 `fid` 去重、只记首次**（= 用户裁定 (iii-a)）。`rejected` 计入（同属离开 open 集）。
  - **D3 `N*_lo`**：`r̂ − δ` 落在 `(0,1)` 之外 ⟹ **不可定义** ⟹ 输出 `null` + reason
    （F-REV-61 修复：初版三元**反相**）。
  - **D4 `verdict`**：`r̂ ≥ 1` ⟹ `"block"`（判据 2 钉定）；否则 `"pass"`。
  - **D5 `μ_tgt = 0`（§1"清空"）**：几何衰减**渐近**不达 0 ⟹ `N* = ∞`（数学推论，非选择）。
  - **D6 `μ` 序列反推** = 由**末轮** `μ_N`（= state 当前 open 计数）按递推**反向**重建
    `μ_0..μ_N`；`mus[0]` = 第 1 轮**之前**。⚠ 前提 = state 的 findings 账与其 journal **同源**
    （同一代际、同一批 fid）：出现负值 ⟹ 二者**不自洽** ⟹ 显式报 `MU_BACKCAST_NEGATIVE`（禁夹逼）。
    **实测成因（F-REV-63，2026-09-14 订正）**：**journal 无保留上限、从不裁行**（与
    `removed=0` 的备份逐行 diff 一致；**F-REV-51 是 `task_pipeline` 的上限，与 journal 无关**
    —— 早期 hint 引它是**误归因**）。负值的实际来源：① **域隔离后新 finding 只落域化 state**
    ② **无锁 RMW 丢更新**（`load→mutate→save` 无 flock，并发会话 last-writer-wins）
    ③ 迁移期 `reanchor` 入 journal 但 state 侧未落账。三类都会给出"journal 有事件、state 无记录"。
  - **D7 单轮/无 epoch ⟹ `r̂` 不可成形**：报 `RATES_DEGENERATE_SINGLE_ROUND`（**显式降级，
    禁默 1、禁静默放行** —— stock 比对需 ≥2 轮才有轮间比）。
  - **D8 `μ̂₀ == 0` ⟹ 具名降级（A6-T2 ②，2026-09-15）**：该 state 无 `open`/`in_progress`
    finding ⟹ 报 `NO_OPEN_FINDINGS`，**前置**于 `mu_series` 反推。与 `MU_BACKCAST_NEGATIVE`
    **严格区分**：前者 = **输入面为空**（域隔离后 base state / 迁移期 / 清理后），
    后者 = **账与 journal 不同源**（两账不自洽）。**禁**把前者退化为后者的间接信号。

**⚠ 已知结构性缺口（F-REV-63）**：本模块**只认传入的那一个 `state_file`，没有任何域概念** ——
而域隔离治理（ECC-C98BDE1D2B3B）之后新 finding 落 `.gatekeeper.state.<repo>.<plan>`，base state
的 `gate_data.ecc_findings` 为空 ⟹ 门在"当前上下文对应域 ≠ 传入 state"时**结构性看不到 findings**。
正解方向 = **域解析**（由 `gk_route_center.resolve-state` 决定传哪个 state；**禁**跨域聚合 —— 把不同域
的 finding 相加会重演跨仓污染），**跨代际**则须用 **ember 余烬快照**（每份内嵌导出时刻的整份
journal + `gate_data_full`，`gk_ember_replay.py`）取"同源历史对"。
**处置进度（A6-P2 分册）**：**A6-T1**（域解析接线）已落；**A6-T2**（2026-09-15）已实装
—— CLI 侧 `_conv_state_path()` 取数中枢（`resolve-state`，`error` ⟹ fail-closed）+ 本节 **D8**；
**A6-T3**（ember 同源对 thin 适配）单独排期。**本模块自身仍不解析域**（域由 CLI 侧中枢决定后传入）。
"""
import argparse
import hashlib
import json
import math
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import gk_finding  # noqa: E402
import gk_state  # noqa: E402
# η_tier / SUBA_TIERS 单源（**轻量**模块；finding `ECC-46C8BF837715`）：评估器**实算**档位增益，
#   禁抄计划文档的常数表（原表随 2026-09-26/10-03 档位调整已漂移，见 §27.1）。
from gk_suba_tiers import SUBA_TIERS, tier_gain  # noqa: E402

DELTA_DEFAULT = 0.1
# 2026-10-19（论文 §3.3 交付规则）：r=1 边界的点估计约 50% 误发视界 ⟹ 交付规则加 margin：
#   emit iff r_hat < 1 - tau；abstain iff 1 - tau <= r_hat < 1；block iff r_hat >= 1。
#   τ 默认 0.02（论文 Monte-Carlo：r=1 误发 <=2.6e-3，r=0.95 检出 100%）。
#   band 内**弃权而非 block**：点估计在边界附近无法区分"衰减"与"自锁"，正是 margin 要消掉的误差。
TAU_DEFAULT = 0.02
MU_TGT_DEFAULT = 1
MAX_ROUNDS_DEFAULT = 3
OPEN_STATUSES = ("open", "in_progress")
# ② μ 白名单（2026-10-05，RCA 参数轮 `d8c0cfd1bb29` arm-2 独立命中）：**测量装置自身**落的
#   finding（MoA 聚合裁决 / 收敛判定）**不得计入 μ̂₀** —— 否则"衡量行为抬高被衡量量"
#   （μ 台账被测量污染）。前缀由 `gk_moa_aggregate.emit_aggregate_finding` /
#   `convergence_finding` **单源**给出（改前缀须同步此处，禁第二处硬编码）。
_MEASUREMENT_ROOT_PREFIXES = ("moa-agg:", "noconv:")
RESOLVED_TO = ("fixed", "closed", "rejected")
T_STAR_KEY = "t_star"
GATE_WARN = "CONV_GATE_WARN"
GATE_WARN_NO_FREEZE = "CONV_GATE_WARN_NO_FREEZE"
GATE_WARN_UNAVAILABLE = "CONV_GATE_UNAVAILABLE"
# 2026-10-19：margin band 内的**弃权**（非自锁）——门只 WARN，不 block。
GATE_WARN_ABSTAIN = "CONV_GATE_ABSTAIN"
ERR_NEAR_BOUNDARY = "R_WITHIN_MARGIN_BAND"
ERR_BUDGET = "CONVERGENCE_BUDGET_EXCEEDED"
ERR_NOT_FROZEN = "T_NOT_FROZEN"
# A6-T2 ②（2026-09-15）：μ̂₀ == 0 的**具名降级**（替代落到 MU_BACKCAST_NEGATIVE 的**间接信号**）。
# 语义严格区分：本码 = 该 state **零 open/in_progress finding** ⟹ 无收敛评估输入面（域化/迁移后常见）；
# MU_BACKCAST_NEGATIVE = **账与 journal 不同源**（真不同源仍须报 —— J19 回归臂）。
ERR_NO_OPEN_FINDINGS = "NO_OPEN_FINDINGS"


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _env_float(name, default):
    try:
        return float(os.environ.get(name) or default)
    except (TypeError, ValueError):
        return float(default)


def _env_int(name, default):
    try:
        return int(os.environ.get(name) or default)
    except (TypeError, ValueError):
        return int(default)


# ── T* 冻结登记（producer；机器可读落点）────────────────────────────────────
def t_star_sha(strings):
    return hashlib.sha256("\n".join(strings).encode("utf-8")).hexdigest()[:16]


def load_t_star(state_file):
    """读 `gate_data.t_star`（未冻结/不可读 ⟹ None）。"""
    data = gk_state._read_state(state_file)
    if "error" in data:
        return None
    rec = (data.get("gate_data") or {}).get(T_STAR_KEY)
    return rec if isinstance(rec, dict) and rec.get("strings") else None


def freeze_t_star(state_file, strings, source="", force=False):
    """写冻结登记。**冻结语义 = 此后不改**：已有登记且 sha 不同 ⟹ 拒绝（除非 force）。"""
    strings = [s for s in (strings or []) if s]
    if not strings:
        return {"ok": False, "error": "T_STAR_EMPTY", "hint": "至少一条 T* 串原文"}
    old = load_t_star(state_file)
    new = {"frozen_at": _now(), "source": source, "strings": strings,
           "sha256": t_star_sha(strings)}
    if old and old.get("sha256") != new["sha256"] and not force:
        return {"ok": False, "error": "T_STAR_ALREADY_FROZEN",
                "hint": f"已冻结 sha={old.get('sha256')}（frozen_at={old.get('frozen_at')}）；"
                        "改串须显式 --force（违 §1-C3 可比前提则须同时作废采集窗口）",
                "existing": old}
    import gk_state_patch  # 单一写点：复用既有 sanctioned writer（不新开写路径）
    res = gk_state_patch.cmd_update_gate_data(state_file, json.dumps({T_STAR_KEY: new}, ensure_ascii=False))
    return {"ok": res.get("ok", False), "error": res.get("error"), "t_star": new,
            "checksum": res.get("checksum")}


# ── 速率估计（finding_journal 实测）──────────────────────────────────────────
def rounds_of(events):
    """按 epoch 标记切轮（D1）；无 epoch ⟹ 单轮；空流 ⟹ []。"""
    rs, cur = [], []
    for e in events:
        if e.get("event") == gk_finding._EPOCH_EVENT:
            if cur:
                rs.append(cur)
                cur = []
        else:
            cur.append(e)
    if cur:
        rs.append(cur)
    return rs


def rates(events):
    """**逐轮** `a`（去重消解）/ `b`（登记）—— 口径 = 用户 2026-09-14 裁定（F-REV-62 → (iii-a)）。

    - `b_n` = 第 n 轮 `register` 事件数。
    - `a_n` = 第 n 轮**首次离开 open 集**的**不同 `fid`** 数：同一 fid 的后续消解事件
      （`verify` 写 `to=fixed` 之后 `close` 又写 `to=closed`）**不再计数** ⟹ 对齐 §1.2
      「第 n 轮**真正消解**的缺陷（**项**/轮）」。
    - `a_n` **含归档清除**（ECC-8B7F130A20A2）：epoch 事件声明的 `purged_fids`
      （`gk_finding.epoch(..., purged_fids=[...])` = 配额归档 / 代数清除）**同属离开存量**，
      计入该 epoch **所闭合的那一轮**，且与 `to ∈ RESOLVED_TO` **共用同一去重集**
      （同一 fid 解析 ∪ 归档只计一次）。journal 无 `purged_fids` ⟹ 行为**逐字不变**。

    ⚠ 该口径与初版实现（按**事件**计数）不同 —— 初版会让同一 fid 双计、`Σa > Σb` 可达，
    导致 `r̂` 依赖"记账风格"（见 F-REV-62）。
    """
    rs = rounds_of(events)
    a, b, seen = [], [], set()
    # 列 B（ECC-8B7F130A20A2）：epoch 事件声明的 `purged_fids`（配额归档 / 代数清除，
    # `gk_finding.epoch(..., purged_fids=[...])`）同属**离开存量** —— 但该事件既无 `to`
    # 也无 `fid` 字段 ⟹ 原 `rounds_of` 切分会把它整条丢掉 ⟹ 零入账 ⟹ μ 反推结构性负值
    # （base 实测 μ0 = −147，此前被误归因为"账↔journal 不同源"）。
    # 归属 = 该 epoch **所闭合的那一轮**（= `rounds_of` 切分里该 epoch **之前**的那一轮）；
    # **前导 epoch**（该轮尚无任何累计事件、`rounds_of` 亦不 append）不闭合任何轮 ⟹ 不入账
    # （禁臆造轮号）。`idx` 的自增时机与 `rounds_of` 的 append 时机**一一对应**（同语义复制）。
    purged_by_round = {}
    idx, open_round = -1, False
    for e in events:
        if e.get("event") == gk_finding._EPOCH_EVENT:
            if open_round:          # 仅当该轮已累计事件才闭合（对齐 `rounds_of` 的 `if cur:`）
                purged_by_round.setdefault(idx, set()).update(
                    str(x) for x in (e.get("purged_fids") or []) if str(x))
            open_round = False
        elif not open_round:
            idx += 1
            open_round = True
    for i, r in enumerate(rs):
        na = 0
        # 归档清除与 `to ∈ {fixed,closed,rejected}` **共用同一去重集** `seen` ⟹ 同一 fid
        # 既解析又 purge **只计一次**（对齐 F-REV-62 去重纪律：`a` 的单位 = distinct fid）。
        # `sorted` 仅为确定性（计数与序无关）。
        for fid in sorted(purged_by_round.get(i, ())):
            if fid not in seen:
                seen.add(fid)
                na += 1
        for e in r:
            if e.get("to") in RESOLVED_TO:
                # 键形归一（str）：purge 侧已 `str(x)` ⟹ 解析侧必须同键形，否则同一 fid 会因
                # 类型不同而绕过 `seen` **双计**（违「共用同一去重集」，F-REV-62 去重纪律）。
                fid = str(e.get("fid"))
                if fid not in seen:
                    seen.add(fid)
                    na += 1
        a.append(na)
        b.append(sum(1 for e in r if e.get("event") == "register"))
    n = len(rs)
    basis = "epoch" if any(e.get("event") == gk_finding._EPOCH_EVENT for e in events) \
        else "no_epoch_single_round"
    return {"rounds": n, "a": a, "b": b,
            "a_bar": (sum(a) / n) if n else 0.0,
            "b_bar": (sum(b) / n) if n else 0.0,
            "rounds_basis": basis, "a_unit": "distinct_fid_first_exit"}


def mu_series(a, b, mu_end):
    """按递推 `μ_n = μ_{n−1} − a_n + b_n` 由**末轮** `μ_N` 反推全序列（D6）。

    返回 `mus`（长度 = 轮数 + 1；`mus[n]` = 第 n 轮末残留，`mus[0]` = 第 1 轮**之前**）。
    ⚠ 反推依赖 state 的 findings 账与 journal **同源**（同一代际的同一批 fid）：若出现
    `mus[i] < 0` ⟹ 二者不自洽 ⟹ 序列**不可用**（调用方须**显式降级**，禁夹逼/禁取绝对值）。
    ⚠ **与 journal 的"保留上限"无关**：journal 是纯 append-only、**从不裁行**（实测
    `removed=0`；F-REV-51 的保留上限作用于 `task_pipeline`，**不是** journal）⟹ 早期把负值
    归因于"journal 裁头"是**误归因**（见 F-REV-63）。
    """
    mus = [0] * (len(a) + 1)
    mus[-1] = mu_end
    for i in range(len(a) - 1, -1, -1):
        mus[i] = mus[i + 1] + a[i] - b[i]
    return mus


def stock_ratio(mus):
    """`r̂ :=` 相邻轮间比 `μ_n / μ_{n−1}` 的**几何均值**（= `(μ_N / μ_0)^{1/N}`）—— 口径 (i)。

    边界语义（禁臆造）：
      - `μ_{n−1} == 0` ⟹ **无可衰减存量** ⟹ 该轮**不构成观测**（**跳过**，禁按 1 计）；
      - `μ_n == 0` ⟹ 该轮**清空** ⟹ `r̂ = 0`（返回 `full_clearance_in_round`）；
      - 负值 ⟹ 反推失灵（调用方已挡）⟹ `None`；
      - **无任何有效相邻对** ⟹ `None`（即"单轮"或"全程存量皆为 0"）。
    """
    if len(mus) < 2:
        return None, "stock_ratio_needs_ge2_rounds"
    logs = []
    for i in range(len(mus) - 1):
        prev, cur = mus[i], mus[i + 1]
        if prev < 0 or cur < 0:
            return None, "stock_ratio_undefined_negative_mu"
        if prev == 0:
            continue
        if cur == 0:
            return 0.0, "full_clearance_in_round"
        logs.append(math.log(cur / prev))
    if not logs:
        return None, "stock_ratio_no_valid_pair"
    return math.exp(sum(logs) / len(logs)), "ok"


def n_star(r_hat, mu0, mu_tgt):
    """§1 修正式。返回 (N* 或 None(=∞), reason)。None 一律配 reason，禁静默。"""
    if mu_tgt <= 0:
        return None, "mu_tgt_zero_asymptotic_clear"      # D5：几何衰减渐近不达 0
    if mu0 <= mu_tgt:
        return 0, "at_or_below_target"
    if r_hat >= 1:
        return None, "r_ge_1_self_lock"
    if r_hat <= 0:
        return 0, "no_new_defects"
    return math.ceil(math.log(mu0 / mu_tgt) / math.log(1.0 / r_hat)), "ok"


# δ 灵敏度带之外的**近似区间**（2026-10-07，用户裁定「加回评估器」+「避免绝对化/避免被随意推翻」）：
# delta-method，**仅报告**，提示"估计离边界多远"，**不改写 verdict**（近似区间当绝对裁决会被随机波动推翻）。
R_CI_Z = 1.96          # ~95%（近似，非精确覆盖率）
R_CI_LEVEL = 0.95


def r_interval(r_hat, mu_start, mu_end, rounds, z=R_CI_Z):
    """`r̂` 的 delta-method 近似区间（**仅报告**，调用方**不得**据它翻 verdict）。

    `Var(ln r̂) ≈ (1/N²)(1/μ_N + 1/μ_0)`（`μ_N`=当前残留=`mus[-1]`，`μ_0`=窗口起点=`mus[0]`）。
    端点计数任一 ≤ 0、或轮数 < 2 ⟹ 不可定义（`None` + reason），**禁臆造**。
    """
    if r_hat is None:
        return {"lo": None, "hi": None, "level": None, "basis": "no_point_estimate"}
    if rounds < 2 or mu_start <= 0 or mu_end <= 0:
        return {"lo": None, "hi": None, "level": None,
                "basis": "undefined_needs_two_positive_endpoints"}
    se = math.sqrt((1.0 / (rounds ** 2)) * (1.0 / mu_end + 1.0 / mu_start))
    return {"lo": round(r_hat * math.exp(-z * se), 6),
            "hi": round(r_hat * math.exp(z * se), 6),
            "level": R_CI_LEVEL, "basis": f"delta_method_ln_r_N{rounds}"}


def classify_r(r_hat, tau=TAU_DEFAULT):
    """三判决单一事实源（2026-10-19 交付规则）。

    emit    = r̂ < 1 − τ（有限视界）
    abstain = 1 − τ ≤ r̂ < 1（margin band：点估计不足以区分衰减与自锁）
             或 r̂ 不可成形（前提未满足）
    block   = r̂ ≥ 1（自锁，须外部熔断）
    """
    if r_hat is None:
        return "abstain", "precondition_unmet_no_stock_ratio"
    if r_hat >= 1.0:
        return "block", "r_ge_1_self_lock"
    if r_hat >= 1.0 - tau:
        return "abstain", "r_within_margin_band"
    return "emit", "ok"


def count_mu0(findings):
    """μ̂₀ = `open+in_progress` 计数，**排除测量 finding**（② 白名单，2026-10-05）。

    测量装置（MoA 聚合裁决 / 收敛判定）自身落的 finding **不计入 μ̂₀** —— 防"衡量行为抬高
    被衡量量"。单源前缀见 `_MEASUREMENT_ROOT_PREFIXES`。
    """
    return sum(1 for f in findings
               if f.get("status") in OPEN_STATUSES
               and not str(f.get("root_key", "") or "").startswith(_MEASUREMENT_ROOT_PREFIXES))


# ── 主评估 ──────────────────────────────────────────────────────────────────
def evaluate(state_file):
    delta = _env_float("GK_CONV_DELTA", DELTA_DEFAULT)
    tau = _env_float("GK_CONV_TAU", TAU_DEFAULT)
    mu_tgt = _env_int("GK_CONV_MU_TGT", MU_TGT_DEFAULT)
    out = {"ok": False, "delta": delta, "tau": tau, "mu_tgt": mu_tgt}
    ts = load_t_star(state_file)
    # 正本 §4（2026-11-06 规格对齐）：`T*` 未冻属 **warn（只 WARN、不阻断）**，不是 error。
    #   仍拒出 `N*`（`n_star*` = null），但 `r̂`/μ 序列照常可算 ⟹ 跨轮评估不被前提门整段掐死。
    t_frozen = bool(ts)
    data = gk_state._read_state(state_file)
    if "error" in data:
        out.update({"error": "STATE_UNREADABLE", "hint": str(data.get("error"))[:200]})
        return out
    try:
        # 读侧 union（遗漏⑤）：溢出片里的 finding 仍参与 μ 计算的台账存量。
        findings = gk_finding.load_findings_union(state_file)
        events = gk_finding._journal_events(state_file)
    except Exception as e:  # noqa: BLE001 — 依赖不可用必须 fail-soft（判据 8）
        out.update({"error": GATE_WARN_UNAVAILABLE, "hint": f"journal 不可读：{type(e).__name__}"})
        return out
    rt = rates(events)
    if rt["rounds"] < 2:
        # D7：stock 比对需 ≥2 轮才有 μ 轮间比 ⟹ 显式降级（禁默 1、禁静默放行）。
        out.update({"error": "RATES_DEGENERATE_SINGLE_ROUND", "rates": rt,
                    "hint": "无 ≥2 轮（epoch）⟹ μ 轮间比不可成形（stock 口径）"})
        return out
    mu0 = count_mu0(findings)
    if mu0 == 0:
        # A6-T2 ②（2026-09-15）：**显式前置校验 / 具名降级**。
        # μ̂₀ = 0 ⟹ 该 state 无 open/in_progress finding ⟹ 收敛评估**无输入面**
        # （域隔离后 base state / 迁移期 / 清理后均落到这里）。原实现会一路算到
        # `mu_series` 出负值再报 MU_BACKCAST_NEGATIVE —— 那是"账与 journal 不同源"的
        # **间接信号**，把两种不同故障混为一谈（J19 要求二者可区分且各自具名）。
        out.update({"error": ERR_NO_OPEN_FINDINGS, "rates": rt, "mu0": 0,
                    "hint": "该 state 无 open/in_progress finding ⟹ 收敛评估无输入面"
                            "（域化/迁移后常见）；**非**'账与 journal 不同源'"})
        return out
    mus = mu_series(rt["a"], rt["b"], mu0)
    if any(m < 0 for m in mus):
        # 反推为负 ⟹ state 的 findings 账与其 journal **不同源**（F-REV-63：域隔离后新 finding
        # 落域化 state / 无锁 RMW 丢更新 / 迁移期 reanchor 未落 state；**非** journal 裁头 ——
        # journal 纯 append-only、从不裁行）⟹ 反推不可用（禁夹逼）。
        out.update({"error": "MU_BACKCAST_NEGATIVE", "rates": rt, "mu_series": mus,
                    "hint": "μ 反推出现负值 ⟹ state 的 findings 账与其 journal 不同源"
                            "（域隔离/并发丢更新/迁移分叉；非 journal 裁头）⟹ r̂ 不可成形"})
        return out
    r_hat, r_reason = stock_ratio(mus)
    if r_hat is None:
        out.update({"error": r_reason.upper(), "rates": rt, "mu_series": mus,
                    "hint": "μ 序列无有效相邻对（单轮 / 存量恒 0 / 负值）⟹ stock 比不可定义"})
        return out
    # 2026-10-19 交付规则：三判决（emit / abstain / block）—— margin band 不发射视界。
    verdict, v_reason = classify_r(r_hat, tau)
    if verdict == "emit":
        n, n_reason = n_star(r_hat, mu0, mu_tgt)
        n_hi, _ = n_star(r_hat + delta, mu0, mu_tgt)
        n_lo_raw, n_lo_raw_reason = n_star(r_hat - delta, mu0, mu_tgt)
        # D3：`r̂ − δ` 落在开区间 (0,1) 之外 ⟹ `N*` 不可定义 ⟹ 输出 null（不夹逼、不臆造）。
        # **F-REV-61 修复（2026-09-14，口径质询 arm-2 `sub-b928e91a22e6` 独立命中代码↔规格反相）**：
        # 原三元 `None if (0 < r̂−δ < 1) else (None if r̂−δ >= 1 else n_lo_raw)` **反相** ——
        # 恰好把**唯一可定义区间** (0,1) 判成 None，而越界侧 (r̂−δ ≤ 0) 却返回 0（臆造）。
        if 0 < r_hat - delta < 1:
            n_lo, n_lo_reason = n_lo_raw, n_lo_raw_reason
        else:
            n_lo, n_lo_reason = None, "n_lo_undefined_outside_open_interval_0_1"   # D3
    else:
        n, n_reason = None, v_reason
        n_hi = n_lo = None
        n_lo_reason = "not_emitted"
    ci = r_interval(r_hat, mus[0], mus[-1], rt["rounds"])
    out.update({
        "ok": True, "t_star_sha": (ts or {}).get("sha256"), "t_star_frozen_at": (ts or {}).get("frozen_at"),
        "rates": rt, "a_bar": rt["a_bar"], "b_bar": rt["b_bar"], "r_hat": r_hat,
        "r_hat_basis": f"stock_geometric_mean({rt['rounds']} rounds)",
        "mu_series": mus, "mu0": mu0, "n_star": n, "n_star_reason": n_reason,
        "n_star_hi": n_hi, "n_star_lo": n_lo, "n_star_lo_reason": n_lo_reason,
        # 近似区间（**仅报告**）：`r_ci_straddles_one` 只标"估计贴边界"，**不翻 verdict**。
        "r_ci": ci,
        "r_ci_straddles_one": bool(ci["lo"] is not None and ci["lo"] <= 1.0 <= ci["hi"]),
        "r_emit_max": round(1.0 - tau, 6),
        "infinite": n is None,
        "abstain": verdict == "abstain",
        "self_locked": r_hat >= 1.0,
        "verdict": "pass" if verdict == "emit" else verdict,
    })
    if not t_frozen:
        out.update({"gate": "warn", "warn": ERR_NOT_FROZEN,
                    "n_star": None, "n_star_hi": None, "n_star_lo": None,
                    "n_star_reason": ERR_NOT_FROZEN,
                    "n_star_lo_reason": "not_emitted_T_NOT_FROZEN",
                    "infinite": True})
    else:
        out.setdefault("gate", "pass")
    return out


def _last_budget_status(state_file):
    """读 `gate_data.subagent_history[-1].budget_status`（**启动前预测**的观测输入）。

    取值域（`subagent_runner`）：`ok` / `soft` / `hard` / `item_exceeded` / `max_turns`。
    缺失 / 异常 ⟹ `""`（**禁臆造**；预测块据此判 `predicted_raise_pays=False`）。
    """
    try:
        with open(state_file, encoding="utf-8") as f:
            d = json.load(f)
        hist = ((d.get("gate_data") or {}).get("subagent_history") or [])
        if hist and isinstance(hist[-1], dict):
            return str(hist[-1].get("budget_status") or "")
    except Exception:  # noqa: BLE001 — 只读预测输入，缺失不得阻断门（fail-soft，对齐判据 8）
        pass
    return ""


def _tier_prediction(state_file, current_tier=None):
    """**升档启动前预测**（finding `ECC-46C8BF837715`）：升一档的**实算** η_tier + 是否值得升。

    - `eta_tier` = `gk_suba_tiers.tier_gain(cur, cur+1)` —— **live `SUBA_TIERS`** 比值（3→4 是
      T10 定义的唯一「工具面恒等」对）；**非**计划文档的常数表。
    - `last_budget_status` = 上一次 subagent 运行的预算结局；`hard`/`item_exceeded`/`max_turns`
      表示本档被 cap 截停 ⟹ **升档有据**（正是 §26.1「tier3 cap 低于真实成本」的门侧预测）。
    - 已处最高档 ⟹ `at_top=True`、`predicted_raise_pays=False`（无法再升，须提额/收束）。

    只读；异常 ⟹ 最简 `{ok:False}`（fail-soft，不阻断门）。
    """
    lbs = _last_budget_status(state_file)
    try:
        _cur = int(current_tier) if current_tier else 3
    except (TypeError, ValueError):
        _cur = 3
    _top = max(SUBA_TIERS)
    _pays = lbs in ("hard", "item_exceeded", "max_turns")
    if _cur >= _top:
        return {"ok": True, "from_tier": _cur, "to_tier": _cur, "at_top": True, "eta_tier": {},
                "last_budget_status": lbs, "predicted_raise_pays": False,
                "basis": "live SUBA_TIERS 比值 + subagent_history[-1].budget_status"}
    try:
        eta = tier_gain(_cur, _cur + 1)
    except Exception as e:  # noqa: BLE001 — 档位缺失（不应）⟹ 显式标注，不阻断门
        return {"ok": False, "error": type(e).__name__}
    return {"ok": True, "from_tier": _cur, "to_tier": _cur + 1, "at_top": False, "eta_tier": eta,
            "last_budget_status": lbs, "predicted_raise_pays": _pays,
            "basis": "live SUBA_TIERS 比值 + subagent_history[-1].budget_status"}


def _tier_rec(ev, max_rounds, state_file=None, current_tier=None):
    """由收敛指标给出**升档建议**（2026-10-03 用户裁定「升档应由收敛评估器提前算」）。

    **只建议、不改档** —— 落档须人工/序列批准（T10 口径见 convergence-evaluator-subplan §4）。
    判据：`r̂≥1`（自锁，须外部熔断）或 `N*_hi > max_rounds`（当前档轮次不够）⟹ `raise`。

    2026-10-08（finding `ECC-46C8BF837715`）：**加装启动前预测** ——
      ① `eta_tier` 由 `gk_suba_tiers.tier_gain` **实算**（live `SUBA_TIERS`，非文档常数）；
      ② 按 `subagent_history[-1].budget_status` 预测「升档是否划算」：上一次被 cap 截停
         ⟹ 本档预算不足 ⟹ **升级判据 `raise`**（把 §26.1 的根因变成**门侧预测**）。
      **仍只建议、不改档**；消费面见 `gatekeeper-cli.sh::cmd_plan_refinement`（`GK_AUTO_TIER`）。
    """
    if not ev.get("ok"):
        return {"action": "unknown", "reason": ev.get("error") or "EVALUATION_UNAVAILABLE"}
    if ev.get("abstain"):
        # margin band：不是自锁，不该触发升档；等下一轮观测。
        rec = {"action": "hold", "reason": ERR_NEAR_BOUNDARY}
    elif ev.get("infinite"):
        rec = {"action": "raise", "reason": "CONV_R_SELF_LOCK"}
    else:
        n_hi = ev.get("n_star_hi")
        if n_hi is not None and n_hi > max_rounds:
            rec = {"action": "raise", "reason": "N_STAR_EXCEEDS_MAX_ROUNDS", "n_star_hi": n_hi}
        else:
            rec = {"action": "hold", "reason": "WITHIN_BUDGET"}
    if state_file:
        pred = _tier_prediction(state_file, current_tier)
        rec["prediction"] = pred
        if rec["action"] != "raise" and pred.get("predicted_raise_pays"):
            rec["action"] = "raise"
            rec["reason"] = "LAST_RUN_BUDGET_%s" % (pred.get("last_budget_status") or "").upper()
    return rec


def gate(state_file):
    """T4 门判决（bash 侧只分支，不做算术）。三态 + 判据 5/6 契约。

    2026-10-03（用户裁定「升档由收敛评估器提前算」）：新增 `tier_recommendation` ——
    评估器在门侧**提前**给出升档建议（只建议、不改档；落档须人工/序列批准），判据见 `_tier_rec`。
    """
    max_rounds = _env_int("GK_CONV_MAX_ROUNDS", MAX_ROUNDS_DEFAULT)
    try:
        ev = evaluate(state_file)
    except Exception as e:  # noqa: BLE001 — 判据 8 fail-soft：依赖不可用不得锁死序列
        return {"max_rounds": max_rounds, "action": "warn", "warning": GATE_WARN_UNAVAILABLE,
                "error": GATE_WARN_UNAVAILABLE,
                "tier_recommendation": {"action": "unknown", "reason": "EVALUATION_UNAVAILABLE"},
                "detail": {"ok": False, "error": type(e).__name__, "hint": str(e)[:160]}}
    res = {"max_rounds": max_rounds, "action": "pass", "warning": "", "error": "", "detail": ev,
           "tier_recommendation": _tier_rec(ev, max_rounds, state_file)}
    if not ev.get("ok"):
        err = ev.get("error")
        # A′ 判序：T 未冻是**第一前提**，优先于降级原因（detail 仍保留真实降级错误）。
        if err == ERR_NOT_FROZEN or (err and not load_t_star(state_file)):
            res.update({"action": "warn", "warning": GATE_WARN_NO_FREEZE, "error": ERR_NOT_FROZEN})
        else:
            res.update({"action": "warn", "warning": GATE_WARN_UNAVAILABLE, "error": err or GATE_WARN_UNAVAILABLE})
        return res
    if ev.get("warn") == ERR_NOT_FROZEN:
        # A′：T 未冻 = warn（不阻断）；stdout 契约仍须报 NO_FREEZE，不得退化成 UNAVAILABLE。
        res.update({"action": "warn", "warning": GATE_WARN_NO_FREEZE, "error": ERR_NOT_FROZEN})
        return res
    if ev.get("abstain"):
        # margin band：只 WARN，不 block（既不发射视界，也不宣称自锁）。
        res.update({"action": "warn", "warning": GATE_WARN_ABSTAIN,
                    "error": ERR_NEAR_BOUNDARY})
        return res
    if ev.get("infinite"):
        res.update({"action": "warn", "warning": GATE_WARN_NO_FREEZE,
                    "error": "CONV_R_SELF_LOCK"})   # 判据 5：N*=∞ 例外（不静默拒一切）
        return res
    n_hi = ev.get("n_star_hi")
    if n_hi is not None and n_hi > max_rounds:
        res.update({"action": "block", "error": ERR_BUDGET, "warning": GATE_WARN,
                    "n_star_hi": n_hi})
    else:
        res["n_star_hi"] = n_hi
    return res


def _emit(obj, code=0):
    # **跨语言契约**（F-REV-59）：bash 侧 T4 门用 `*'"action":"block"'*` 精确子串匹配本 stdout
    # ⟹ 此处必须**紧凑分隔符**（无空格）。若改回默认 `json.dumps`（`": "` 带空格），
    # bash 的 case 会**静默不命中**、T4 门全分支空转（连 WARN 都不出）。
    # 守卫测试：test_cli_gate_stdout_matches_bash_contract。
    print(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))
    return code


def main(argv=None):
    ap = argparse.ArgumentParser(description="T2 收敛评估器（子计划2 §1）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_ev = sub.add_parser("evaluate"); p_ev.add_argument("state_file")
    p_ga = sub.add_parser("gate"); p_ga.add_argument("state_file")
    p_sh = sub.add_parser("show"); p_sh.add_argument("state_file")
    p_fr = sub.add_parser("freeze"); p_fr.add_argument("state_file")
    p_fr.add_argument("--strings", default="", help="以 | 分隔的 T* 串原文")
    p_fr.add_argument("--source", default="")
    p_fr.add_argument("--force", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "evaluate":
        return _emit(evaluate(a.state_file))
    if a.cmd == "gate":
        return _emit(gate(a.state_file))
    if a.cmd == "show":
        return _emit({"ok": True, "t_star": load_t_star(a.state_file)})
    if a.cmd == "freeze":
        return _emit(freeze_t_star(a.state_file, a.strings.split("|"), a.source, a.force))
    return 2


if __name__ == "__main__":
    sys.exit(main())

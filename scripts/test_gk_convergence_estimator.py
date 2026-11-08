"""T2 收敛评估器测试（子计划2 §3 判据 2/3/4/8 + §1-C3 前提门 + T4 门三态）。

**口径（2026-09-14 用户裁定；F-REV-62 → 候选 (iii-a) 去重 fid + 候选 (i) stock 比）**：
- `a` 按 **`fid` 去重**：同一 finding 的 `verify`→`fixed` 与 `close`→`closed` **只计一次**消解；
- `r̂` = **stock 比**（μ 轮间衰减率的几何均值），**非**"新增/消解"的 flow 比。

**口径史（禁再混口径；三处教训均已落成断言）**：
1. **F-REV-58（已订正）**：初版断言「`Σa ≤ Σb` ⟹ `r̂ ≥ 1` 恒成立 ⟹ 中段不可达」= **过度断言**，
   被口径质询 arm-2（`sub-b928e91a22e6`）证伪 —— 同一 fid 可产 `to=fixed` + `to=closed`
   两条消解事件；本机 r7 journal 实测 `r̂ = 0.714 < 1`。
2. **F-REV-61（已修）**：`n_lo` 三元曾与自述 D3 **反相**（把唯一可定义区间判 `None`、越界侧臆造 `0`）。
3. **F-REV-62（已修）**：真根因 = `a` 的**计数单位**未钉定 + 实现偏离 §1.2 ⟹ 现钉为"去重 fid"。

分三层：① **算术层**直测判据 2 的量（`n_star(0.5, 8, 1) == 3`）；② **单位层**直测
`mu_series` / `stock_ratio` 边界；③ **集成层**走**真实 `evaluate()` 路径**（去重守卫 + 降级路径）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_convergence_estimator as est   # noqa: E402
import gk_finding                        # noqa: E402


def _sf(tmp_path, name="s.json"):
    return str(tmp_path / name)


def _reg(sf, n, prefix="f", start=0):
    return [gk_finding.register(sf, f"{prefix}{i}", "review")["id"] for i in range(start, start + n)]


# ── ① 算术层（判据 2 真正钉的量）────────────────────────────────────────────
def test_n_star_spec_example():
    """判据 2：r̂=0.5、μ̂₀=8、μ_tgt=1 ⟹ N* = ⌈ln(8/1)/ln2⌉ = 3。"""
    assert est.n_star(0.5, 8, 1)[0] == 3


def test_n_star_r_ge_1_is_infinite():
    """判据 2：r̂=1 ⟹ N*=∞（None）且 verdict="block"。"""
    assert est.n_star(1.0, 8, 1)[0] is None
    assert est.n_star(1.3, 8, 1)[0] is None


def test_n_star_at_or_below_target_is_zero():
    assert est.n_star(0.5, 1, 1)[0] == 0
    assert est.n_star(0.5, 0, 1)[0] == 0


def test_mu_tgt_zero_is_asymptotic_clear():
    """§1"μ_tgt = 0 时为清空"：几何衰减渐近不达 0 ⟹ N*=∞（D5）。"""
    n, reason = est.n_star(0.5, 8, 0)
    assert n is None and reason == "mu_tgt_zero_asymptotic_clear"


# ── ② 集成层：自洽构造 ──────────────────────────────────────────────────────
def test_not_frozen_gate(tmp_path):
    """A′（正本 §4）：T 未冻 = warn（只 WARN、不阻断）；仍拒出 N*，但保留判决面。"""
    sf = _sf(tmp_path)
    ids = _reg(sf, 8)
    gk_finding.epoch(sf, reason="r2")
    for i in ids[:4]:
        gk_finding.verify(sf, i, True)
    r = est.evaluate(sf)
    assert r["ok"] is True and r["gate"] == "warn" and r["warn"] == "T_NOT_FROZEN"
    assert r["n_star"] is None and r["n_star_hi"] is None
    assert r["verdict"] in ("pass", "abstain", "block")
    assert r["r_hat"] == 0.5


def test_freeze_then_evaluate(tmp_path):
    """冻结后可评估（**stock 口径**：构造 2 轮 ⟹ μ 序列 [0, 8, 4] ⟹ r̂ = (4/8) = 0.5）。"""
    sf = _sf(tmp_path)
    ids = _reg(sf, 8)
    assert est.freeze_t_star(sf, ["串A", "串B", "串C"], source="t")["ok"] is True
    assert est.load_t_star(sf)["sha256"]
    gk_finding.epoch(sf, reason="r2")
    for i in ids[:4]:
        gk_finding.verify(sf, i, True)
    r = est.evaluate(sf)
    assert r["ok"] is True and r["t_star_sha"]
    assert r["rates"]["a"] == [0, 4] and r["rates"]["b"] == [8, 0]
    assert r["mu_series"] == [0, 8, 4] and r["mu0"] == 4
    assert r["r_hat"] == 0.5 and r["n_star"] == 2          # ⌈ln(4/1)/ln 2⌉ = 2
    assert r["r_hat_basis"].startswith("stock_geometric_mean")
    for k in ("n_star", "n_star_hi", "n_star_lo", "verdict", "infinite"):
        assert k in r


def test_freeze_is_sticky(tmp_path):
    """冻结语义 = 此后不改：同 sha 幂等、异 sha 拒绝（除非 force）。"""
    sf = _sf(tmp_path)
    _reg(sf, 1)
    assert est.freeze_t_star(sf, ["A", "B"], source="t")["ok"] is True
    assert est.freeze_t_star(sf, ["A", "B"], source="t")["ok"] is True
    bad = est.freeze_t_star(sf, ["A", "C"], source="t")
    assert bad["ok"] is False and bad["error"] == "T_STAR_ALREADY_FROZEN"
    assert est.freeze_t_star(sf, ["A", "C"], source="t", force=True)["ok"] is True


def test_rounds_split_by_epoch(tmp_path):
    """D1：按 epoch 标记切轮；无 epoch ⟹ 单轮（rounds_basis 标明）。"""
    sf = _sf(tmp_path)
    ids = _reg(sf, 2)
    assert est.rates(gk_finding._journal_events(sf))["rounds"] == 1
    gk_finding.epoch(sf, reason="r2")
    gk_finding.verify(sf, ids[0], True)
    rt = est.rates(gk_finding._journal_events(sf))
    assert rt["rounds"] == 2 and rt["rounds_basis"] == "epoch"
    assert rt["b"] == [2, 0] and rt["a"] == [0, 1]


# ── 红先（ARC：归档/代数清除感知；ECC-8B7F130A20A2）────────────────────────────
def test_a_counts_epoch_purged_fids(tmp_path):
    """**红先臂（ECC-8B7F130A20A2）**：归档/代数清除是「离开存量」——epoch 事件声明的
    `purged_fids` 须计入 `a_n`（与 `to∈{fixed,closed,rejected}` 去重）。

    归属口径：某 epoch 声明的 `purged_fids` 计入它**所闭合的那一轮**（epoch 之前那一轮的 `a`）。

    HEAD 行为：`rates()` 只认 `to∈{fixed,closed,rejected}` ⟹ purged 完全不计 ⟹ 本臂
    **必红**（这正是 base 实测 μ 反推 `-147` 的结构性成因：449 register − 246 res，而
    epoch 已声明 381 条 purge 却零入账）。
    """
    sf = _sf(tmp_path)
    ids = _reg(sf, 3)
    est.freeze_t_star(sf, ["A"], source="t")
    gk_finding.epoch(sf, reason="archive", purged_fids=ids[:2])
    gk_finding.verify(sf, ids[2], True)
    rt = est.rates(gk_finding._journal_events(sf))
    assert rt["rounds"] == 2 and rt["rounds_basis"] == "epoch"
    assert rt["b"] == [3, 0], rt["b"]
    assert rt["a"] == [2, 1], "epoch purged_fids 未计入 a_n（应=2，实际=%r）" % (rt["a"],)


def test_a_purged_deduped_with_resolution(tmp_path):
    """**红先臂（去重）**：同一 fid 既 resolve 又被 purge ⟹ **只计一次**（对齐 F-REV-62 去重纪律）。

    若实现未去重，第 1 轮会得 3（resolve 1 + purge 2）而非 2；本臂钉住「不得双计」。
    """
    sf = _sf(tmp_path)
    ids = _reg(sf, 3)
    gk_finding.verify(sf, ids[0], True)                                   # 第 1 轮 resolve id0
    gk_finding.epoch(sf, reason="archive", purged_fids=[ids[0], ids[1]])  # 边界：purge id0(与 res 重)/id1
    gk_finding.verify(sf, ids[2], True)                                   # 第 2 轮 resolve id2
    rt = est.rates(gk_finding._journal_events(sf))
    # 第 1 轮 a = {id0 resolved} ∪ {id0, id1 purged} = 2（id0 不双计）；第 2 轮 a = 1
    assert rt["a"] == [2, 1], rt["a"]


def test_single_round_is_degenerate(tmp_path):
    """**D7**：单轮（无 epoch）⟹ stock 比无轮间对 ⟹ 显式降级（禁默 1、禁静默放行）。"""
    sf = _sf(tmp_path)
    _reg(sf, 2)
    est.freeze_t_star(sf, ["A"], source="t")
    r = est.evaluate(sf)
    assert r["ok"] is False and r["error"] == "RATES_DEGENERATE_SINGLE_ROUND"
    assert r["rates"]["rounds"] == 1


def test_mu_series_backcast_units():
    """**D6**：μ 由末轮反推（`μ_{n−1} = μ_n + a_n − b_n`）；单位级直测。"""
    assert est.mu_series([0, 4], [8, 0], 4) == [0, 8, 4]
    assert est.mu_series([2, 0], [3, 1], 1) == [-1, 0, 1]


def test_stock_ratio_units():
    """**stock 比**：几何均值；`prev == 0` 的对**跳过**（无可衰减存量）；`cur == 0` ⟹ r̂ = 0（清空）。"""
    assert est.stock_ratio([0, 8, 4])[0] == 0.5          # 跳过 (0,8) 对
    assert est.stock_ratio([8, 4])[0] == 0.5
    assert est.stock_ratio([8, 12])[0] > 1               # 扩张
    assert est.stock_ratio([4, 0])[0] == 0.0             # 清空
    assert est.stock_ratio([0])[0] is None               # 无对
    assert est.stock_ratio([0, 0])[0] is None            # 全跳过 ⟹ 无有效对


def test_mu0_zero_reports_no_open_findings(tmp_path):
    """**J19 主臂（A6-T2 ②，2026-09-15）**：`μ̂₀ == 0` ⟹ **具名降级 `NO_OPEN_FINDINGS`**，
    且**不得**返回 `MU_BACKCAST_NEGATIVE`。

    语义边界（本条存在的理由）：`μ̂₀ == 0` = **输入面为空**（域隔离后 base state / 迁移期 /
    清理后）；`MU_BACKCAST_NEGATIVE` = **账与 journal 不同源**。二者**不同故障**，原先都用
    后者表达 ⟹ 把"没输入"误报成"两账打架"（J19 要求可区分）。
    """
    import json as _json
    sf = _sf(tmp_path)
    ids = _reg(sf, 3)
    for i in ids:                       # state 侧全部消解 ⟹ 当前 open = 0 ⟹ μ̂₀ = 0
        gk_finding.verify(sf, i, True)
        gk_finding.close(sf, i, "review")
    est.freeze_t_star(sf, ["A"], source="t")
    jp = sf + gk_finding._JOURNAL_SUFFIX
    lines = [{"ts": "t1", "event": "register", "fid": ids[0]},
             {"ts": "t1", "event": "register", "fid": ids[1]},
             {"ts": "t1", "event": "register", "fid": ids[2]},
             {"ts": "t2", "event": gk_finding._EPOCH_EVENT, "reason": "r2"},
             {"ts": "t3", "event": "verify", "fid": ids[0], "to": "fixed"}]
    with open(jp, "w", encoding="utf-8") as f:
        f.write("\n".join(_json.dumps(e) for e in lines) + "\n")
    r = est.evaluate(sf)
    assert r["ok"] is False
    assert r["error"] == "NO_OPEN_FINDINGS"          # 具名降级
    assert r["error"] != "MU_BACKCAST_NEGATIVE"      # 禁退化到"账↔journal 不同源"
    assert r["mu0"] == 0
    assert "mu_series" not in r                      # 前置：未进入 μ 反推


def test_mu_backcast_negative_is_explicit(tmp_path):
    """**D6 守卫 + J19 回归臂**：state 的 findings 账与其 journal **不同源** ⟹ μ 反推为负
    ⟹ 显式报 `MU_BACKCAST_NEGATIVE`（禁夹逼）。

    ⚠ 归因订正（F-REV-63）：**不是** "journal 被保留上限裁头" —— journal 纯 append-only、
    从不裁行（实测 `removed=0`；F-REV-51 的上限作用于 `task_pipeline`）。本用例构造的是
    **首轮只有消解、没有登记**（= 该批 fid 的 register 不在本 journal 覆盖范围内）⟹ 二者不同源。

    ⚠ **J19 回归臂改造（2026-09-15）**：原版让 state 侧 `open = 0`（`μ̂₀ = 0`），那会**先**
    撞新增的 `NO_OPEN_FINDINGS`（D8）⟹ 本条降级为"输入面为空"，**测不到** D6。故改为
    **`μ̂₀ = 1`（留 1 条 open）**、轮 2 记 3 条登记 ⟹ `μ_1 = 1 − 3 + 0 = −2 < 0` ⟹ 真·负反推。
    """
    import json as _json
    sf = _sf(tmp_path)
    ids = _reg(sf, 4)                   # 留 1 条不消解 ⟹ 当前 open = 1 ⟹ μ̂₀ = 1 ≠ 0
    for i in ids[:3]:
        gk_finding.verify(sf, i, True)
        gk_finding.close(sf, i, "review")
    est.freeze_t_star(sf, ["A"], source="t")
    # 第 1 轮 3 条消解（a=3,b=0）→ epoch → 第 2 轮 3 条登记（a=0,b=3）
    # ⟹ μ_2 = 1、μ_1 = 1 − 3 + 0 = −2（负）、μ_0 = −2 − 0 + 3 = 1 ⟹ 反推不可用。
    jp = sf + gk_finding._JOURNAL_SUFFIX
    lines = [{"ts": "t1", "event": "verify", "fid": ids[0], "to": "fixed"},
             {"ts": "t1", "event": "close", "fid": ids[1], "to": "closed"},
             {"ts": "t1", "event": "verify", "fid": ids[2], "to": "rejected"},
             {"ts": "t2", "event": gk_finding._EPOCH_EVENT, "reason": "r2"},
             {"ts": "t3", "event": "register", "fid": "g-new-1"},
             {"ts": "t3", "event": "register", "fid": "g-new-2"},
             {"ts": "t3", "event": "register", "fid": "g-new-3"}]
    with open(jp, "w", encoding="utf-8") as f:
        f.write("\n".join(_json.dumps(e) for e in lines) + "\n")
    r = est.evaluate(sf)
    assert r["ok"] is False and r["error"] == "MU_BACKCAST_NEGATIVE"
    assert r["mu_series"] == [1, -2, 1]


def test_missing_state_failsoft(tmp_path):
    """判据 8：state 不可读 ⟹ ok:false 且不阻断（T4 侧降 WARN）。"""
    r = est.evaluate(str(tmp_path / "nope.json"))
    assert r["ok"] is False
    assert r["error"] in ("T_NOT_FROZEN", "STATE_UNREADABLE")


def test_dedup_a_ignores_second_resolution_event(tmp_path):
    """**F-REV-62 修复守卫（用户裁定 = (iii-a) 去重 fid）**：同一 fid 的 `verify`→`fixed`
    与 `close`→`closed` **只计一次消解** ⟹ `r̂` 不再依赖"记账风格"。

    对照（初版按**事件**计数）：同构造会得 `a=8`（双计）而仅 `verify` 时 `a=4` ⟹ 同义不同值。
    构造：轮 1 登记 8；轮 2 对 4 个走**完整闭环**（verify + close）
    ⟹ `a = [0, 4]`、`b = [8, 0]`、μ 序列 `[0, 8, 4]`、`r̂ = 0.5`、`N* = ⌈ln4/ln2⌉ = 2`。
    """
    sf = _sf(tmp_path)
    ids = _reg(sf, 8)
    est.freeze_t_star(sf, ["A"], source="t")
    gk_finding.epoch(sf, reason="r2")
    for i in ids[:4]:
        gk_finding.verify(sf, i, True)          # to=fixed
        gk_finding.close(sf, i, "review")       # to=closed（同一 fid 的第二条消解事件，**不计**）
    r = est.evaluate(sf)
    assert r["rates"]["a_unit"] == "distinct_fid_first_exit"
    assert r["rates"]["a"] == [0, 4], "去重失效：同一 fid 的第二条消解事件被重复计入"
    assert r["mu_series"] == [0, 8, 4] and r["r_hat"] == 0.5
    assert r["n_star"] == 2 and r["infinite"] is False and r["verdict"] == "pass"


def test_stock_ratio_expansion_is_infinite(tmp_path):
    """μ **扩张**（只登记不消解）⟹ `r̂ > 1` ⟹ `N* = ∞` + `verdict="block"`（自锁口径）。"""
    sf = _sf(tmp_path)
    _reg(sf, 4)
    est.freeze_t_star(sf, ["A"], source="t")
    gk_finding.epoch(sf, reason="r2")
    _reg(sf, 4, prefix="g")                     # 轮 2 只增不减 ⟹ μ: [0, 4, 8]
    r = est.evaluate(sf)
    assert r["mu_series"] == [0, 4, 8] and r["r_hat"] == 2.0
    assert r["infinite"] is True and r["verdict"] == "block"


def test_stock_ratio_no_progress_is_one(tmp_path):
    """μ **净不变** ⟹ `r̂ = 1` ⟹ `N* = ∞`（"零进展"按自锁处理，不臆造有限轮数）。"""
    sf = _sf(tmp_path)
    ids = _reg(sf, 2)
    est.freeze_t_star(sf, ["A"], source="t")
    gk_finding.epoch(sf, reason="r2")
    gk_finding.verify(sf, ids[0], True)         # 轮 2：消解 1 + 登记 1 ⟹ 净 0
    _reg(sf, 1, prefix="g")
    r = est.evaluate(sf)
    assert r["mu_series"] == [0, 2, 2] and r["r_hat"] == 1.0
    assert r["infinite"] is True and r["verdict"] == "block"


def test_n_lo_null_outside_open_interval(tmp_path):
    """**F-REV-61 边界**：`r̂ − δ` 越界 ⟹ `N*_lo = null` + D3 reason（此前越界侧会**臆造 0**）。"""
    sf = _sf(tmp_path)
    ids = _reg(sf, 8)
    est.freeze_t_star(sf, ["A"], source="t")
    gk_finding.epoch(sf, reason="r2")
    for i in ids[:4]:
        gk_finding.verify(sf, i, True)          # μ: [0,8,4] ⟹ r̂ = 0.5 ⟹ r̂−δ = 0.4 ∈ (0,1)
    r = est.evaluate(sf)
    assert r["n_star_lo"] == 2 and r["n_star_lo_reason"] == "ok"
    os.environ["GK_CONV_DELTA"] = "0.9"         # r̂−δ = −0.4 ≤ 0 ⟹ 越界 ⟹ null（旧实现返回 0）
    try:
        r2 = est.evaluate(sf)
        assert r2["n_star_lo"] is None
        assert r2["n_star_lo_reason"] == "n_lo_undefined_outside_open_interval_0_1"
    finally:
        os.environ.pop("GK_CONV_DELTA", None)



# ── ③ T4 门三态（判据 5/6/8）────────────────────────────────────────────────
def test_gate_not_frozen_warns(tmp_path):
    sf = _sf(tmp_path)
    _reg(sf, 2)
    g = est.gate(sf)
    assert g["action"] == "warn" and g["warning"] == "CONV_GATE_WARN_NO_FREEZE"


def test_gate_self_lock_warns_not_blocks(tmp_path):
    """判据 5 例外：`N* = ∞`（μ 净扩张 ⟹ `r̂ > 1`）⟹ WARN（**不静默拒一切**，防序列自锁）。"""
    sf = _sf(tmp_path)
    _reg(sf, 4)
    est.freeze_t_star(sf, ["A"], source="t")
    gk_finding.epoch(sf, reason="r2")
    _reg(sf, 4, prefix="g")                     # 轮 2 只增不减 ⟹ μ: [0,4,8] ⟹ r̂ = 2 > 1
    g = est.gate(sf)
    assert g["action"] == "warn" and g["warning"] == "CONV_GATE_WARN_NO_FREEZE"
    assert g["error"] == "CONV_R_SELF_LOCK"


def test_gate_block_when_budget_exceeded(tmp_path, monkeypatch):
    """判据 5：`N*_hi > 允许轮次` ⟹ BLOCK `CONVERGENCE_BUDGET_EXCEEDED`。

    **真实路径（不再打桩）** —— 口径裁定后 `r̂ < 1` 在真实 journal 上**可达**（`[0,8,4]` ⟹ `r̂ = 0.5`
    ⟹ `N* = 2`、`N*_hi = 3`），故把 `GK_CONV_MAX_ROUNDS` 降到 `1` 即可**端到端**触发 BLOCK 分支
    ⟹ 该分支**生产可达**（F-REV-58 初版"生产不可达"的结论随口径订正一同作废）。
    """
    sf = _sf(tmp_path)
    ids = _reg(sf, 8)
    est.freeze_t_star(sf, ["A"], source="t")
    gk_finding.epoch(sf, reason="r2")
    for i in ids[:4]:
        gk_finding.verify(sf, i, True)
    monkeypatch.setenv("GK_CONV_MAX_ROUNDS", "1")
    g = est.gate(sf)
    assert g["action"] == "block" and g["error"] == "CONVERGENCE_BUDGET_EXCEEDED"
    assert g["n_star_hi"] == 3 and g["detail"]["r_hat"] == 0.5


def test_gate_unavailable_warns(tmp_path, monkeypatch):
    """判据 8：估器异常 ⟹ WARN CONV_GATE_UNAVAILABLE（不阻断入队）。"""
    sf = _sf(tmp_path)
    _reg(sf, 1)

    def _boom(sf_):
        raise RuntimeError("journal unreadable")

    monkeypatch.setattr(est, "evaluate", _boom)
    g = est.gate(sf)
    assert g["action"] == "warn" and g["warning"] == "CONV_GATE_UNAVAILABLE"


# ── ④ 跨语言契约（F-REV-59）──────────────────────────────────────────────────
def test_cli_gate_stdout_matches_bash_contract(capsys):
    """**契约守卫（F-REV-59）**：bash 侧 T4 门用精确子串匹配本 stdout。

    `gatekeeper-cli.sh` 的 case 分支写死 `*'"action":"block"'*` / `*'"action":"warn"'*`
    （**无空格**）。若 `_emit` 退回默认 `json.dumps`（`": "` 带空格），bash 侧**全分支不命中**
    ⟹ T4 门静默空转（连 WARN 都不出）、而函数层测试全绿 ⟹ 典型"绿灯下的空转"。
    本测试把**跨语言字符串契约**钉住：两处任一改动都会先红。
    """
    est._emit({"action": "warn", "warning": "X"})
    out = capsys.readouterr().out
    assert '"action":"warn"' in out, f"紧凑分隔符契约被破坏（bash case 将不命中）：{out!r}"
    est._emit({"action": "block", "error": "Y"})
    out = capsys.readouterr().out
    assert '"action":"block"' in out, f"紧凑分隔符契约被破坏（bash case 将不命中）：{out!r}"


def test_gate_stdout_contract_real_states(tmp_path, monkeypatch, capsys):
    """真实三态的 stdout 均须含 bash 侧匹配串（含 fallback 的 `estimator_unavailable`）。"""
    sf = _sf(tmp_path)
    _reg(sf, 2)

    est._emit(est.gate(sf))                       # ① T* 未冻结
    out = capsys.readouterr().out
    assert '"action":"warn"' in out and "CONV_GATE_WARN_NO_FREEZE" in out

    def _boom(sf_):
        raise RuntimeError("boom")

    monkeypatch.setattr(est, "evaluate", _boom)
    est._emit(est.gate(sf))                       # ② 依赖异常
    out = capsys.readouterr().out
    assert '"action":"warn"' in out and "CONV_GATE_UNAVAILABLE" in out

    monkeypatch.undo()
    ids = _reg(sf, 8)                             # 补齐多轮构造（口径裁定后 r̂<1 真实可达）
    est.freeze_t_star(sf, ["A"], source="t")
    gk_finding.epoch(sf, reason="r2")
    for i in ids[:4]:
        gk_finding.verify(sf, i, True)
    monkeypatch.setenv("GK_CONV_MAX_ROUNDS", "1")
    est._emit(est.gate(sf))                       # ③ 预算超限（**真实路径**，非打桩）
    out = capsys.readouterr().out
    assert '"action":"block"' in out and "CONVERGENCE_BUDGET_EXCEEDED" in out


# ── ⑤ 近似区间（2026-10-07；**仅报告**，非判决门）──────────────────────────────
def test_r_interval_units():
    """delta-method 区间：几何衰减 ⟹ 区间夹 r̂ 且 < 1；端点非正/单轮 ⟹ 不可定义（禁臆造）。"""
    ci = est.r_interval(0.8, 1000, 68.72, 12)
    assert ci["lo"] < 0.8 < ci["hi"] and ci["hi"] < 1.0
    assert ci["level"] == 0.95 and ci["basis"].startswith("delta_method")
    assert est.r_interval(None, 1000, 68.72, 12)["lo"] is None
    assert est.r_interval(0.5, 0, 4, 2)["basis"] == "undefined_needs_two_positive_endpoints"   # μ_0 = 0
    assert est.r_interval(0.5, 8, 4, 1)["basis"] == "undefined_needs_two_positive_endpoints"   # 单轮


# ── ⑥ τ margin 交付规则（2026-10-19；论文 §3.3）──────────────────────────────
def test_classify_r_margin_band():
    """三判决边界：emit < 1−τ；abstain ∈ [1−τ,1)；block ≥ 1；None ⟹ abstain。"""
    assert est.classify_r(0.5)[0] == "emit"
    assert est.classify_r(0.97)[0] == "emit"          # 1−0.02 = 0.98
    assert est.classify_r(0.98)[0] == "abstain"
    assert est.classify_r(0.99)[0] == "abstain"
    assert est.classify_r(1.0)[0] == "block"
    assert est.classify_r(1.02)[0] == "block"
    assert est.classify_r(None)[0] == "abstain"
    assert est.classify_r(0.97, tau=0.05)[0] == "abstain"
    assert est.classify_r(0.97, tau=0.0)[0] == "emit"


def test_evaluate_margin_band_abstains_and_gate_warns(tmp_path, monkeypatch):
    """r̂=0.95 落在 margin band ⟹ 不发射视界；门只 WARN（非自锁）、升档建议 hold。

    构造：轮 1 登记 20；轮 2 消解 1 ⟹ μ=[0,20,19] ⟹ r̂=0.95。
    用 GK_CONV_TAU=0.05 使 0.95 恰好落在 band 边界 [0.95,1)（小样本避免 finding spillover）。
    """
    monkeypatch.setenv("GK_CONV_TAU", "0.05")
    sf = _sf(tmp_path)
    ids = _reg(sf, 20)
    est.freeze_t_star(sf, ["A"], source="t")
    gk_finding.epoch(sf, reason="r2")
    gk_finding.verify(sf, ids[0], True)
    r = est.evaluate(sf)
    assert r["ok"] is True and abs(r["r_hat"] - 0.95) < 1e-9
    assert r["tau"] == 0.05 and r["r_emit_max"] == 0.95
    assert r["verdict"] == "abstain" and r["abstain"] is True
    assert r["n_star"] is None and r["n_star_reason"] == "r_within_margin_band"
    assert r["infinite"] is True and r["self_locked"] is False
    g = est.gate(sf)
    assert g["action"] == "warn" and g["warning"] == "CONV_GATE_ABSTAIN"
    assert g["error"] == "R_WITHIN_MARGIN_BAND"
    assert g["tier_recommendation"]["action"] == "hold"


def test_r_interval_straddles_one_is_non_binding(tmp_path):
    """**非绝对门**：区间跨 1 时只**报告** `r_ci_straddles_one`，**不改写 verdict**（仍按点估计 r̂）。"""
    assert est.r_interval(1.0, 1000, 1000, 12)["lo"] < 1.0 < est.r_interval(1.0, 1000, 1000, 12)["hi"]
    sf = _sf(tmp_path)
    ids = _reg(sf, 8)
    est.freeze_t_star(sf, ["A"], source="t")
    gk_finding.epoch(sf, reason="r2")
    for i in ids[:4]:
        gk_finding.verify(sf, i, True)
    r = est.evaluate(sf)
    assert r["ok"] is True and "r_ci" in r and "r_ci_straddles_one" in r
    assert r["verdict"] == "pass" and r["n_star"] == 2            # 判决仍按点估计 r̂ = 0.5
    assert r["r_ci"]["lo"] is None                                # 该路径 μ_0 = 0 ⟹ 区间不可定义
    assert r["r_ci_straddles_one"] is False                       # 不可定义 ⟹ 不误标跨 1


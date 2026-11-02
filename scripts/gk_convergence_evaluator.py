#!/usr/bin/env python3
"""收敛评估器（**质询轮次循环早停**编排层）。

**单一事实源 = `references/convergence-evaluator.md`**（机制正本，**禁放 docs/plans** —— 该目录不开源）。
本模块是 `gk_convergence_estimator.py`（数学核：`rates`/`mu_series`/`stock_ratio`/`n_star`/`evaluate`/`gate`）
之上的**薄编排**：只负责「逐轮 stock 比 + 末尾 K 轮滞回 ⟹ NO_CONVERGENCE 早停 + 转 M」，
**不重写任何公式** —— `r̂` 一律 `estimator.stock_ratio`（架构 A，用户 2026-10-05 裁定）。

**判据（用户 2026-10-05 裁定 = 参数化）**：`r̂ ≥ r_min 连续 K 轮 ⟹ NO_CONVERGENCE`。
`r̂` 沿用 §12.6 单源口径（= stock 比 μ_n/μ_{n−1}，**不新造 flow 轴 ρ̂**）；
`r_min`/`K` 走 env（`GK_CONV_R_MIN` 默认 0.9 / `GK_CONV_K_ROUNDS` 默认 2；区间 [0.9, 1.0] 可调）。

**触发后果（§11 三向分流升级判据）**：`NO_CONVERGENCE` ⟹ 落 finding（`root_key` 前缀 `noconv:`）+
产出 `switch_to="M"` —— 强制转**机制修复**，**禁**再以「改计划文本」结案（防空转烧钱）。

kill switch：`GK_CONV_EARLY_STOP=0` ⟹ 只出 verdict、**不落 finding**（拟设）。
"""
import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import gk_convergence_estimator as E  # noqa: E402
import gk_finding  # noqa: E402

R_MIN_DEFAULT = 0.9
K_ROUNDS_DEFAULT = 2
# 复用 Infra-1b `gk_moa_aggregate.convergence_finding` 的同一 root_key 前缀 ⟹ 同 plan 幂等合并
# （单一台账，禁镜像）。改前缀须三处同步（本模块 / moa_aggregate / estimator 白名单）。
NO_CONV_PREFIX = "noconv:"
VERDICT_NC = "NO_CONVERGENCE"
VERDICT_OK = "CONVERGING"
VERDICT_SHORT = "INSUFFICIENT_ROUNDS"
VERDICT_UNDEF = "UNDEFINED"


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


def step_ratios(mu_seq):
    """逐轮 stock 比 `μ_n / μ_{n−1}`（**stock 轴**，与 §1.2 对齐；不新造 flow 轴）。

    返回 `(ratios, reason)`：
      - 任一 `μ < 0` ⟹ `(None, "negative_mu")`（反推失灵，不可定义）；
      - `μ_{n−1} == 0` ⟹ 该对**不构成观测** ⟹ **跳过**（禁按 1 计）；
      - 无任何 `prev > 0` 的有效对 ⟹ `([], "no_valid_pair")`；
      - 正常 ⟹ `(ratios, "ok")`。
    """
    mus = [float(x) for x in mu_seq]
    if any(m < 0 for m in mus):
        return None, "negative_mu"
    ratios = [mus[i] / mus[i - 1] for i in range(1, len(mus)) if mus[i - 1] != 0]
    if not ratios:
        return [], "no_valid_pair"
    return ratios, "ok"


def round_loop_verdict(mu_seq, *, r_min=None, k_rounds=None):
    """质询轮次循环判定：末尾 K 个 step ratio **全 ≥ r_min** ⟹ `NO_CONVERGENCE`。

    `r_hat` = `estimator.stock_ratio`（几何均值，**单源**；仅作参考量，判决用末尾 K 轮）。
    """
    r_min = _env_float("GK_CONV_R_MIN", R_MIN_DEFAULT) if r_min is None else float(r_min)
    k = _env_int("GK_CONV_K_ROUNDS", K_ROUNDS_DEFAULT) if k_rounds is None else int(k_rounds)
    mus = [float(x) for x in mu_seq]
    ratios, reason = step_ratios(mus)
    out = {"mu": mus, "r_min": r_min, "k_rounds": k, "step_ratios": ratios, "reason": reason,
           "r_hat": None, "r_hat_reason": None, "trailing_k": None}
    if ratios is None:
        out["verdict"] = VERDICT_UNDEF
        return out
    r_hat, r_reason = E.stock_ratio(mus)
    out["r_hat"], out["r_hat_reason"] = r_hat, r_reason
    trailing = ratios[-k:] if k > 0 else []
    out["trailing_k"] = trailing
    if len(ratios) < k:
        out["verdict"] = VERDICT_SHORT
    elif all(x >= r_min for x in trailing):
        out["verdict"] = VERDICT_NC
    else:
        out["verdict"] = VERDICT_OK
    return out


def no_convergence_finding(state_file, plan, mu_seq, *, r_min=None, k_rounds=None, batch=""):
    """判定 + （仅 `NO_CONVERGENCE` 时）落 finding + 产出 `switch_to="M"`。

    幂等：`root_key = "noconv:" + sha256(plan)[:16]`（与 Infra-1b **同台账**，二次调用合并）。
    """
    v = round_loop_verdict(mu_seq, r_min=r_min, k_rounds=k_rounds)
    out = {"ok": True, **v}
    if v["verdict"] != VERDICT_NC:
        return out
    if (os.environ.get("GK_CONV_EARLY_STOP") or "1") == "0":
        out["suppressed"] = True
        return out
    _p = str(plan or "").strip()
    root_key = NO_CONV_PREFIX + hashlib.sha256((_p or "-").encode("utf-8")).hexdigest()[:16]
    anchors = ["plan:" + (_p or "-")]
    if batch:
        anchors.append("batch:" + str(batch))
    r_hat_s = ("%.3f" % v["r_hat"]) if v.get("r_hat") is not None else "None"
    title = "审查轮次不收敛: plan=%s r̂=%s trailing=%s（r̂≥%.2f 连续%d轮）" % (
        _p or "-", r_hat_s, v.get("trailing_k"), v["r_min"], v["k_rounds"])
    rec = gk_finding.register(state_file, title, "review", root_key=root_key, anchors=anchors,
                              source_note="RCA 循环早停 verdict=%s r̂=%s r_min=%.2f K=%d"
                                          % (VERDICT_NC, r_hat_s, v["r_min"], v["k_rounds"]))
    out["finding"] = rec
    out["switch_to"] = "M"
    return out


def _emit(obj, code=0):
    print(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))
    return code


def main(argv=None):
    ap = argparse.ArgumentParser(description="收敛评估器（质询轮次循环早停）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("loop")
    p.add_argument("--mu", required=True, help="μ 序列，逗号分隔")
    p.add_argument("--state", default="")
    p.add_argument("--plan", default="")
    p.add_argument("--batch", default="")
    p.add_argument("--r-min", type=float, default=None)
    p.add_argument("--k", type=int, default=None)
    p.add_argument("--emit-finding", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "loop":
        mu = [int(x) for x in a.mu.split(",") if x.strip() != ""]
        if a.emit_finding:
            return _emit(no_convergence_finding(a.state, a.plan, mu,
                                                r_min=a.r_min, k_rounds=a.k, batch=a.batch))
        return _emit(round_loop_verdict(mu, r_min=a.r_min, k_rounds=a.k))
    return 2


if __name__ == "__main__":
    sys.exit(main())

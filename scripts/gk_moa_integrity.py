#!/usr/bin/env python3
"""gk_moa_integrity.py — MoA 完整性 + 臂间离散检测器（消融 vs 正规可显著区分）。

动机（2026-10-14 六窄任务质询裁定）：`gk_task_gate.submit --expand-groups` 在
`gate_data.narrow_tasks[]` 不足 3×K 时**曾静默回退同名复制**（`group_tasks:false`）
⟹「3 组 MoA」被静默降级成 3×K 个**同题**样本（组别只剩 index 标签）= 假 MoA。
入口侧现已 fail-closed，但**产物侧无任何可观测判据**能自证「这批臂真的按组分化」——
本模块补两个纯函数检测器（0 网络 / 0 写盘 / stdlib only）+ 一个硬件自适应并发助手。

① `pipeline_integrity(records, expected_groups, expected_arms)`
     只吃已落盘的 arm 记录（`gate_data.task_pipeline[]` / dispatch 记录）——解析每条
     `full_task` 里的 `【本臂窄任务（G#｜id=…）】` 标记（与 `gk_task_gate._group_expand_records`
     同源格式），量：valid_markers / distinct_full_tasks / distinct_narrow_ids /
     distinct_groups / narrow_hit_rate。
     退化签名（`degenerate`） = 标记缺失 或 distinct_groups < expected_groups 或
     distinct_full_tasks < arms ⟹ `verdict=FAIL` + `circuit_break`（计划熔断候选）。
     这是"假 MoA"的**可观测量**：消融模式（同题 ⟹ 1 组）与正规模式（分组 ⟹ 3 组）在此
     判据上**必然分离**（组数不同，零调参）。

② `arm_dispersion(scores_by_group, perms)`
     between-group vs within-group 离散 + one-way ANOVA F + **置换** p。固化 s2 手算
     （控制同题 sd≈2.09 / 处理分组 sd≈11.32，Δphase≈11.1，F(5,5) p<0.01）。
     `delta_phase = max(group_mean) - min(group_mean)`；`between_sd`/`within_sd` 给出
     两轴离散（组内≈组间 ⟹ 组标签无解释力 ⟹ p→1；组间≫组内 ⟹ p→0）。

③ `adaptive_workers(n, cap, reserve, min_free_mb)`
     按 `os.cpu_count()` + 可选空闲内存下限自适应当前并发度（粗粒度「核数→槽位」，
     与既有 `gk_hub_scheduler` 的并发/OOM 闸**同向互补**；非 CPU 时钟周期级细粒度）。
     探测失败一律给**保守**值（≥1），不静默放大。

本模块**不**替代 `gk_hub_scheduler`（跨进程槽位/内存准入）——它只做**单进程内**的
work-item 并发度选值供调用方使用。禁装包（stdlib only）。

CLI:
  integrity  --state <f> [--expect-groups 3] [--expect-arms N]   # FAIL ⟹ 退出码 2
  dispersion --scores '{"G1":[...],"G2":[...],"G3":[...]}' [--perms 4000]
  workers    --n <N> [--cap N]
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
# s5.5：硬件自适应并发度 **唯一源 = 中枢 gk_hub_scheduler**（本模块不再自算 —— 禁第二实现）
from gk_hub_scheduler import adaptive_workers, visible_cpus  # noqa: E402

# 与 gk_task_gate._group_expand_records 的逐字格式同源：
#   "【本臂窄任务（G1｜id=nt-g1-1）】"（（U+FF08 / ）U+FF09 / ｜U+FF5C）
_ARM_MARK_RE = re.compile("\u3010\u672c\u81c2\u7a84\u4efb\u52a1"
                          "\uff08(G\\d+)\uff5cid=([^\uff09]*)\uff09\u3011")

_ALPHA_DEFAULT = 0.05   # 置换 p 显著性阈值（统计约定；env `GK_MOA_ALPHA` 可覆盖）


# ── 无硬编码：策略量一律 env 单源（换设备/换机器不靠改代码）─────────────────────
def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, ""))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, ""))
    except (TypeError, ValueError):
        return default


def _registered_ids(narrow_tasks):
    """已登记窄任务 id 集合（list[dict|str] / JSON 串）；不可用 ⟹ None（不启用接地校验）。"""
    if not narrow_tasks:
        return None
    if isinstance(narrow_tasks, str):
        try:
            narrow_tasks = json.loads(narrow_tasks)
        except (json.JSONDecodeError, ValueError):
            return None
    if not isinstance(narrow_tasks, (list, tuple)):
        return None
    out = set()
    for t in narrow_tasks:
        tid = str((t.get("id") if isinstance(t, dict) else t) or "")
        if tid:
            out.add(tid)
    return out or None


def _records_from_state(state_file: str) -> list:
    with open(state_file, encoding="utf-8") as f:
        d = json.load(f)
    return ((d.get("gate_data") or {}).get("task_pipeline") or [])


def _narrow_from_state(state_file: str) -> list:
    """同源读 `gate_data.narrow_tasks[]`（供 CLI 默认**接地**校验）；不可用 ⟹ []。"""
    try:
        with open(state_file, encoding="utf-8") as f:
            d = json.load(f)
        return (d.get("gate_data") or {}).get("narrow_tasks") or []
    except (OSError, json.JSONDecodeError, ValueError):
        return []


def parse_arm_marker(full_task: str) -> tuple:
    """从臂 `full_task` 抽 `(组标签, 窄任务 id)`；无标记 ⟹ `("", "")`。"""
    m = _ARM_MARK_RE.search(str(full_task or ""))
    if not m:
        return "", ""
    return m.group(1), m.group(2)


def pipeline_integrity(records: list, expected_groups: int = None,
                       expected_arms: int = None, batch: str = None,
                       narrow_tasks=None) -> dict:
    """MoA 完整性判据（纯函数）。返回 JSON-ready dict（含 degenerate/verdict/circuit_break）。

    `batch` 给定 ⟹ 只复核该批（`submit` 落的 `gate_data.task_pipeline[].batch` 键，= 批基础 id）；
    `None` ⟹ 全量。**分批复核**是必须的：同一条 state 会并存多个历史批（含消融的同题批），
    全量聚合会把正规批**混批**拖成 FAIL ⟹ 消融/正规须按批并排取数。

    `narrow_tasks` 给定 ⟹ 启用**接地校验**：每条臂嵌入的 id 必须 ∈ 已登记清单，否则
    `ungrounded_narrow_id`（防「只在 full_task 里贴伪造 `【…（G1｜id=FAKE）】`」冒充分组）。
    `expected_groups` 缺省走 env `GK_MOA_EXPECT_GROUPS`（默认 3）——**无硬编码**。
    """
    expected_groups = int(_env_int("GK_MOA_EXPECT_GROUPS", 3)
                          if expected_groups is None else expected_groups)
    all_recs = [r for r in (records or []) if isinstance(r, dict)]
    recs = all_recs
    batch_found = True
    if batch is not None:
        recs = [r for r in all_recs if str(r.get("batch") or "") == str(batch)]
        batch_found = bool(recs)
    arms = len(recs)
    groups, ids, fts = [], [], []
    valid = 0
    for r in recs:
        ft = str(r.get("full_task") or "")
        fts.append(ft)
        g, nid = parse_arm_marker(ft)
        if g:
            valid += 1
            if g not in groups:
                groups.append(g)
            if nid and nid not in ids:
                ids.append(nid)
    dft = len(set(fts))
    exp_arms = arms if expected_arms is None else int(expected_arms)
    hit = (len(ids) / exp_arms) if exp_arms else 0.0

    reg = _registered_ids(narrow_tasks)
    ungrounded = sorted(nid for nid in ids if reg is not None and nid not in reg)

    reasons = []
    if batch is not None and not batch_found:
        reasons.append("batch_not_found")            # 批次号打错 ⟹ NO_DATA，不误触熔断
    else:
        if arms == 0:
            reasons.append("no_arms")
        if valid < arms:
            reasons.append("missing_arm_marker")
        if len(groups) < expected_groups:
            reasons.append("insufficient_groups")
        if arms and dft < arms:
            reasons.append("duplicate_full_task")
        if ungrounded:
            reasons.append("ungrounded_narrow_id")
    degenerate = bool(reasons) and "batch_not_found" not in reasons
    # FAIL = 假 MoA 的硬签名（无臂/无标记/缺组/伪造 id）；仅「臂数不足预期但组齐」等软化记 WARN。
    fail = any(x in reasons for x in ("no_arms", "insufficient_groups",
                                      "missing_arm_marker", "ungrounded_narrow_id"))
    verdict = "FAIL" if fail else ("WARN" if degenerate else "OK")
    if "batch_not_found" in reasons:
        verdict = "NO_DATA"
    return {
        "check": "moa_integrity",
        "arms": arms,
        "valid_markers": valid,
        "distinct_full_tasks": dft,
        "distinct_narrow_ids": len(ids),
        "distinct_groups": len(groups),
        "groups": sorted(groups),
        "narrow_hit_rate": round(hit, 4),
        "expected_groups": expected_groups,
        "expected_arms": exp_arms,
        "batch": batch,
        "batch_found": batch_found,
        "grounded": reg is not None,
        "ungrounded_narrow_ids": ungrounded[:12],
        "reasons": reasons,
        "degenerate": degenerate,
        "verdict": verdict,
        "circuit_break": verdict == "FAIL",
    }


def _f_stat(group_lists: list):
    """One-way ANOVA F（between/within MS 之比）。退化（<2 组 / 无组内自由度）⟹ None。"""
    allv = [x for g in group_lists for x in g]
    n_total, k = len(allv), len(group_lists)
    if n_total == 0 or k < 2:
        return None
    grand = sum(allv) / n_total
    between = within = 0.0
    for g in group_lists:
        m = sum(g) / len(g)
        between += len(g) * (m - grand) ** 2
        within += sum((x - m) ** 2 for x in g)
    dfb, dfw = k - 1, n_total - k
    if dfw <= 0:
        return None
    msb, msw = between / dfb, within / dfw
    if msw == 0:
        return math.inf if msb > 0 else 0.0
    return msb / msw


def arm_dispersion(scores_by_group: dict, perms: int = 4000, seed: int = 12345) -> dict:
    """臂间离散检测：between vs within + ANOVA F + 置换 p。

    `scores_by_group` = `{"G1":[...], "G2":[...], ...}`（空组丢弃）。p 用**置换检验**
    （打乱组标签重算 F，双尾无假定）——与 `gk_phase_probe.perm_p` 同思想，此处为组标签版。
    显著性阈值 = env `GK_MOA_ALPHA`（默认 0.05）。非数值分数 ⟹ 干净报错（不抛栈崩）。
    """
    raw = [list(v) for v in (scores_by_group or {}).values() if v]
    try:
        group_lists = [[float(x) for x in g] for g in raw]
    except (TypeError, ValueError):
        return {"check": "arm_dispersion", "error": "non_numeric_score",
                "verdict": "INVALID", "k": len(raw),
                "n": sum(len(g) for g in raw)}
    n_total = sum(len(g) for g in group_lists)
    if len(group_lists) < 2 or n_total < 2:
        return {"check": "arm_dispersion", "k": len(group_lists), "n": n_total,
                "f": None, "p": 1.0, "delta_phase": 0.0,
                "between_sd": 0.0, "within_sd": 0.0, "verdict": "UNDER-POWERED"}
    f_obs = _f_stat(group_lists)

    # between/within 离散（根方差）
    allv = [x for g in group_lists for x in g]
    grand = sum(allv) / n_total
    between = within = 0.0
    means = []
    for g in group_lists:
        m = sum(g) / len(g)
        means.append(m)
        between += len(g) * (m - grand) ** 2
        within += sum((x - m) ** 2 for x in g)
    dfb, dfw = len(group_lists) - 1, n_total - len(group_lists)
    between_sd = math.sqrt(between / dfb) if dfb > 0 else 0.0
    within_sd = math.sqrt(within / dfw) if dfw > 0 else 0.0

    # 置换 p
    labels = [i for i, g in enumerate(group_lists) for _ in g]
    rng = random.Random(seed)
    ge = 0
    for _ in range(max(1, int(perms))):
        rng.shuffle(labels)
        perm = [[] for _ in group_lists]
        for lab, x in zip(labels, allv):
            perm[lab].append(x)
        fp = _f_stat(perm)
        if fp is not None and f_obs is not None:
            if fp == math.inf and f_obs == math.inf:
                ge += 1
            elif fp >= f_obs:
                ge += 1
    p = (ge + 1) / (max(1, int(perms)) + 1)
    return {
        "check": "arm_dispersion",
        "k": len(group_lists),
        "n": n_total,
        "f": f_obs,
        "p": p,
        "delta_phase": max(means) - min(means),
        "between_sd": between_sd,
        "within_sd": within_sd,
        "alpha": _env_float("GK_MOA_ALPHA", _ALPHA_DEFAULT),
        "verdict": ("SEPARATED"
                    if p < _env_float("GK_MOA_ALPHA", _ALPHA_DEFAULT)
                    else "NOT_SEPARATED"),
    }


# ────────────────────────── CLI ──────────────────────────
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="MoA 完整性 + 臂间离散检测器")
    sub = ap.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("integrity", help="判 task_pipeline 的组分化完整性（FAIL ⟹ rc=2）")
    i.add_argument("--state", required=True)
    i.add_argument("--expect-groups", type=int, default=0,
                   help="期望组数；缺省 0 ⟹ env GK_MOA_EXPECT_GROUPS（默认 3）")
    i.add_argument("--expect-arms", type=int, default=0)
    i.add_argument("--batch", default="",
                   help="只复核该批（task_pipeline[].batch 键 = 批基础 id）；缺省 ⟹ 全量")

    d = sub.add_parser("dispersion", help="between/within 离散 + ANOVA F + 置换 p")
    d.add_argument("--scores", required=True, help='JSON: {"G1":[...],"G2":[...]}')
    d.add_argument("--perms", type=int, default=4000)

    w = sub.add_parser("workers", help="硬件自适应并发度")
    w.add_argument("--n", type=int, required=True)
    w.add_argument("--cap", type=int, default=0)

    args = ap.parse_args(sys.argv[1:] if argv is None else argv)
    if args.cmd == "integrity":
        # 默认**接地**：从同一 state 读已登记 narrow_tasks ⟹ 校验臂 id 非伪造。
        out = pipeline_integrity(_records_from_state(args.state),
                                 args.expect_groups or None, args.expect_arms or None,
                                 batch=args.batch or None,
                                 narrow_tasks=_narrow_from_state(args.state))
    elif args.cmd == "dispersion":
        try:
            scores = json.loads(args.scores)
        except (json.JSONDecodeError, ValueError) as e:
            out = {"check": "arm_dispersion", "error": "bad_json", "detail": str(e)}
        else:
            out = arm_dispersion(scores, perms=args.perms)
    else:
        out = {"workers": adaptive_workers(args.n, cap=args.cap or None)}
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 2 if out.get("circuit_break") is True else 0


if __name__ == "__main__":
    raise SystemExit(main())

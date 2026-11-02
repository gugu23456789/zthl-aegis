#!/usr/bin/env python3
"""gk_covert_warden.py — T4 隐蔽事件通道 warden（§4 T4 / §5 / §9.6 Q4；`ECC-F3A27EB08725`）
============================================================================================
Whispering Agents（**AAAI-26**，`arXiv:2508.02188`）指出「禁通信」**不保独立性**：臂可经
**可观测事件**隐蔽耦合 —— 三轴 **Covert Event Channel**：**Storage / Timing / Behavioral**；
安全属性 **IND-STAT / IND-INT**（对 LLM 级 warden 不可见）。本仓相关性降权**只对显式相关有效**。

三轴检测（**启发式 + 功效门**，非 LLM 级语义判定）：
  · **Storage**   `scan_storage(state_file)` —— 共享面 Unicode 隐写残留（零宽/BOM/RLI），
                  复用 `_red_attacks._UNICODE_SUSPECT`（**单源**）。
  · **Timing**    `ind_stat(times)`          —— 臂间完成时刻**时序独立性**：间隔过于规则
                  （CV < `_TIMING_CV_MIN`）⟹ `DEPENDENT`；`n < _MIN_N` ⟹ **`UNDER_POWERED`**。
  · **Behavioral** `ind_int(arms)`           —— 臂间**结构去重**：证据锚集合 Jaccard ≥ `_INT_TAU`
                  ⟹ `DEPENDENT`。

纪律（对齐 `phase_probe` 功效规则）：**`UNDER_POWERED` 是一等结论** —— 未检出**不得**读作
"无隐蔽通道"（低功效 ≠ 无效应）。本模块**只报信号**，判定/降权消费方 = `moa-aggregate`。
"""
from __future__ import annotations

import json
from pathlib import Path

_MIN_N = 6              # 观测数 < 6 ⟹ 功效不足（UNDER_POWERED）
_TIMING_CV_MIN = 0.05   # 间隔 CV < 5% ⟹ 过于规则（疑似时序可编码）
_INT_TAU = 0.9          # 证据锚 Jaccard ≥ 0.9 ⟹ 结构重复（疑似行为耦合）
_PORTABLE_SUSPECT = ["\u200b", "\u200c", "\u200d", "\ufeff", "\u202e", "\u200f"]


def _unicode_suspect() -> list:
    """单源：优先复用 `_red_attacks._UNICODE_SUSPECT`；不可导入则用等价常量兜底。"""
    try:
        from _red_attacks import _UNICODE_SUSPECT
        return list(_UNICODE_SUSPECT)
    except Exception:  # noqa: BLE001 — 边界：兜底不改语义
        return list(_PORTABLE_SUSPECT)


def _load_state(state_file):
    try:
        d = json.loads(Path(state_file).read_text(encoding="utf-8", errors="replace"))
        return d if isinstance(d, dict) else {}
    except Exception:  # noqa: BLE001 — 边界：不可读 ⟹ 空
        return {}


def scan_storage(state_file: str) -> dict:
    """Storage 轴：state 的 arm-bearing 字段里 Unicode 隐写残留扫描。"""
    d = _load_state(state_file)
    gd = d.get("gate_data") or {}
    if not isinstance(gd, dict):
        gd = {}
    hits = []
    for field in ("subagent_history", "block_log", "narrow_tasks"):
        rows = gd.get(field) or []
        if not isinstance(rows, list):
            continue
        for i, e in enumerate(rows):
            blob = json.dumps(e, ensure_ascii=False)
            for ch in _unicode_suspect():
                if ch in blob:
                    hits.append({"field": field, "idx": i,
                                 "char": ch.encode("unicode_escape").decode("ascii")})
                    break
    return {"axis": "storage", "hits": hits,
            "verdict": "DEPENDENT" if hits else "INDEPENDENT"}


def ind_stat(times) -> dict:
    """Timing 轴 IND-STAT：臂间完成时刻的时序独立性（启发式 + 功效门）。"""
    ts = [float(t) for t in (times or []) if isinstance(t, (int, float))]
    n = len(ts)
    if n < _MIN_N:
        return {"axis": "timing", "n": n, "verdict": "UNDER_POWERED",
                "hint": "观测数 %d < %d ⟹ 功效不足，**禁读作无隐蔽通道**" % (n, _MIN_N)}
    gaps = [ts[i + 1] - ts[i] for i in range(n - 1)]
    mean = sum(gaps) / len(gaps)
    if mean == 0:
        return {"axis": "timing", "n": n, "cv": 0.0, "verdict": "DEPENDENT",
                "hint": "零间隔（全同刻）⟹ 同步信号"}
    var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    cv = (var ** 0.5) / mean
    dep = cv < _TIMING_CV_MIN
    return {"axis": "timing", "n": n, "cv": round(cv, 4),
            "verdict": "DEPENDENT" if dep else "INDEPENDENT",
            "hint": ("间隔 CV<%.2f ⟹ 过于规则（疑似时序可编码）" % _TIMING_CV_MIN) if dep else ""}


def ind_int(arms) -> dict:
    """Behavioral 轴 IND-INT：臂间结构去重（证据锚集合 Jaccard ≥ `_INT_TAU`）。"""
    pairs, aset = [], []
    for a in (arms or []):
        if not isinstance(a, dict):
            continue
        anc = a.get("anchors") or a.get("evidence_anchors") or []
        aset.append((a, set(str(x) for x in anc)))
    for i in range(len(aset)):
        for j in range(i + 1, len(aset)):
            ai, si = aset[i]
            aj, sj = aset[j]
            u = si | sj
            if not u:
                continue
            jac = len(si & sj) / len(u)
            if jac >= _INT_TAU:
                pairs.append({"a": ai.get("subagent_id"), "b": aj.get("subagent_id"),
                              "jaccard": round(jac, 3)})
    n = len(aset)
    return {"axis": "behavioral", "n": n, "pairs": pairs,
            "verdict": "DEPENDENT" if pairs else ("UNDER_POWERED" if n < _MIN_N else "INDEPENDENT")}


def scan(state_file: str, *, arms=None) -> dict:
    """三轴总扫：Storage / Timing / Behavioral（`arms` 缺省从 state.subagent_history 取）。"""
    if arms is None:
        arms = (_load_state(state_file).get("gate_data") or {}).get("subagent_history") or []
    arms = [a for a in (arms or []) if isinstance(a, dict)]
    ts = [a.get("ts") for a in arms if isinstance(a.get("ts"), (int, float))]
    storage = scan_storage(state_file)
    timing = (ind_stat(ts) if ts else
              {"axis": "timing", "n": 0, "verdict": "UNDER_POWERED",
               "hint": "无 `ts` 字段 ⟹ 时序不可测（功效不足）"})
    behavioral = ind_int(arms)
    axes = [storage.get("verdict"), timing.get("verdict"), behavioral.get("verdict")]
    if "DEPENDENT" in axes:
        overall = "DEPENDENT"
    elif "UNDER_POWERED" in axes:
        overall = "UNDER_POWERED"
    else:
        overall = "INDEPENDENT"
    return {"storage": storage, "timing": timing, "behavioral": behavioral,
            "overall": overall,
            "note": "T4 隐蔽事件通道（Storage/Timing/Behavioral）；UNDER_POWERED ≠ 无通道"}


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="T4 covert warden（Storage/Timing/Behavioral）")
    ap.add_argument("cmd", choices=["scan"])
    ap.add_argument("state")
    a = ap.parse_args(argv)
    print(json.dumps(scan(a.state), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

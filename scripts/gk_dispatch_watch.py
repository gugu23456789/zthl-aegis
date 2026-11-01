#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gk_dispatch_watch.py — coder / 质询 **通用进度探测** 单源（F4，2026-10-15）。

背景（用户令「给探针做自动化 / 取代手轮询」）：下发后的进度此前只能由主 agent **手轮询**
（反复读 state / 查 worktree）。本模块给出一条 **0-API 只读** 的统一探测面，coder（落刀）与
质询（批）共用，CLI 出口 = `gatekeeper-cli.sh monitor --watch <target>`（挂既有命令，
**零新增 `_CMD_REG`**）。

对象自动判三类（`classify_target`）：
  · `pipeline`    —— 流水线批号 `pr-<epoch>-<hex>`（`gate_data.task_pipeline[].batch`）
  · `aggregation` —— 聚合指纹批 12-hex（`gate_data.subagent_history[].batch_id`）
  · `worktree`    —— coder worktree 路径（接收裁决 **复用** `gk_receive_check.check`，禁第二实现）

纪律：
  · **纯只读**（不写 state、不联网）；
  · 不可判定 ⟹ `done=None`（UNKNOWN），**禁**默认熔断（对齐 R3 / convergence-evaluator「缺样本禁默认熔断」）；
  · 批号双轨（`pr-*` vs 12-hex）**不静默**：未命中 ⟹ `found=false` + 可用批号清单（R6 / ECC-449948814679）。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 流水线批号 = `pr-<epoch>-<hash>`（`gk_task_gate.make_id`）
_PIPELINE_RE = re.compile(r"^pr-\d+-[0-9a-f]+$")
# 聚合指纹批 = 12-hex（`gk_moa_aggregate.compute_batch_id`）
_AGG_RE = re.compile(r"^[0-9a-f]{12}$")


def classify_target(target) -> str:
    """target → `'pipeline'|'aggregation'|'worktree'|''`（空 = 不可判）。"""
    t = str(target or "").strip()
    if not t:
        return ""
    if _PIPELINE_RE.match(t):
        return "pipeline"
    if _AGG_RE.match(t):
        return "aggregation"
    if os.path.isdir(t):
        return "worktree"
    if "/" in t or "\\" in t or os.sep in t:
        return "worktree"          # 路径形态但不存在 ⟹ 交 check 报越界/不存在（不静默）
    return ""


def _load(state_file: str) -> dict:
    try:
        with open(state_file, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001 — 不可读 ⟹ 空（调用方按 found=false 处理）
        return {}


def _pipeline_records(state_file: str, batch) -> list:
    gd = (_load(state_file).get("gate_data") or {})
    return [r for r in (gd.get("task_pipeline") or [])
            if str(r.get("batch") or "") == str(batch)]


def _aggregation_entries(state_file: str, batch_id) -> list:
    gd = (_load(state_file).get("gate_data") or {})
    return [e for e in (gd.get("subagent_history") or [])
            if str(e.get("batch_id") or "") == str(batch_id)]


def _available_batch_ids(state_file: str) -> list:
    """可用批号清单（**两轨都列**，便于纠正拼错的批号；不静默）。"""
    gd = (_load(state_file).get("gate_data") or {})
    seen = {}
    for r in (gd.get("task_pipeline") or []):
        b = str(r.get("batch") or "")
        if b:
            seen[b] = seen.get(b, 0) + 1
    for e in (gd.get("subagent_history") or []):
        b = str(e.get("batch_id") or "")
        if b:
            seen[b] = seen.get(b, 0) + 1
    return sorted(seen)


def snapshot(state_file: str, target, *, kind: str = "auto", main_repo: str = "",
             skill_dir: str = "", master: str = "master", expect: int = 0) -> dict:
    """纯只读进度快照。`done` = True / False / None（None = UNKNOWN，禁默认熔断）。"""
    k = classify_target(target) if kind in ("", "auto") else str(kind)
    if k == "pipeline":
        recs = _pipeline_records(state_file, target)
        by = Counter(str(r.get("status") or "") for r in recs)
        pend = by.get("pending", 0)
        return {"target": str(target), "kind": "pipeline", "found": bool(recs),
                "total": len(recs), "by_status": dict(by), "pending": pend,
                "done": bool(recs) and pend == 0, "report_files": [],
                "available_batch_ids": [] if recs else _available_batch_ids(state_file)}
    if k == "aggregation":
        es = _aggregation_entries(state_file, target)
        files = [str(e.get("report_file") or e.get("output_file") or "") for e in es]
        files = [f for f in files if f]
        _exp = int(expect or 0)
        # 期望臂数不可推导（批 size 由派发侧决定，state 无存）⟹ 无 `expect` 一律 UNKNOWN（禁默认熔断）。
        done = (len(es) >= _exp) if _exp > 0 else None
        return {"target": str(target), "kind": "aggregation", "found": bool(es),
                "runs": len(es), "expect": _exp, "done": done, "report_files": files,
                "available_batch_ids": [] if es else _available_batch_ids(state_file)}
    if k == "worktree":
        import gk_receive_check as rcv
        _mr = main_repo or str(Path(__file__).resolve().parent.parent)
        _sd = skill_dir or os.environ.get("SKILL_DIR", "") or _mr
        res = rcv.check(str(target), _mr, state_file, _sd, master)
        rc = res.get("rc")
        # rc=1（有 diff）/rc=2（越界·分叉）= 有结论的终态 ⟹ done；rc=0（无 diff）= 尚未落刀；
        # rc=3 = 不可判 ⟹ None（禁默认熔断）。
        done = None if rc == 3 else (rc in (1, 2))
        return {"target": str(target), "kind": "worktree", "found": bool(res.get("alive")),
                "done": done, "receive_check": res, "report_files": [],
                "available_batch_ids": []}
    return {"target": str(target), "kind": "unresolved", "found": False, "done": None,
            "report_files": [], "available_batch_ids": _available_batch_ids(state_file)}


def _line(snap: dict) -> str:
    if snap["kind"] == "pipeline":
        return ("[watch] pipeline %s: total=%d pending=%d by_status=%s done=%s"
                % (snap["target"], snap["total"], snap["pending"],
                   json.dumps(snap["by_status"], ensure_ascii=False), snap["done"]))
    if snap["kind"] == "aggregation":
        return ("[watch] aggregation %s: runs=%d expect=%d report_files=%d done=%s"
                % (snap["target"], snap["runs"], snap["expect"],
                   len(snap["report_files"]), snap["done"]))
    if snap["kind"] == "worktree":
        _rc = (snap.get("receive_check") or {}).get("rc")
        return ("[watch] worktree %s: receive_check rc=%s files=%d done=%s"
                % (snap["target"], _rc,
                   len((snap.get("receive_check") or {}).get("files") or []), snap["done"]))
    return ("[watch] unresolved %r: available_batch_ids=%s"
            % (snap["target"], snap["available_batch_ids"]))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="coder/质询 通用进度探测（只读）")
    p.add_argument("--state", required=True, help="state 文件")
    p.add_argument("--target", required=True,
                   help="pr-<epoch>-<hex> | 12-hex 聚合指纹 | worktree 路径")
    p.add_argument("--kind", default="auto",
                   choices=["auto", "pipeline", "aggregation", "worktree"])
    p.add_argument("--expect", type=int, default=0,
                   help="aggregation 批的期望臂数（>0 才可判 done；缺省 = UNKNOWN，不熔断）")
    p.add_argument("--interval", type=float, default=10.0, help="轮询间隔秒（default 10）")
    p.add_argument("--iterations", type=int, default=0,
                   help="最大轮询次数（0 = 不限，受 --max-wait 约束）")
    p.add_argument("--max-wait", type=float, default=1800.0, help="总时限秒（default 1800）")
    p.add_argument("--main-repo", default="")
    p.add_argument("--skill-dir", default="")
    p.add_argument("--master", default="master")
    a = p.parse_args(argv)

    t0 = time.time()
    i = 0
    snap = None
    while True:
        snap = snapshot(a.state, a.target, kind=a.kind, main_repo=a.main_repo,
                        skill_dir=a.skill_dir, master=a.master, expect=a.expect)
        i += 1
        print(_line(snap), flush=True)
        if snap["done"] is True:
            break
        if a.iterations and i >= a.iterations:
            break
        if a.max_wait and (time.time() - t0) >= a.max_wait:
            break
        time.sleep(max(0.0, a.interval))

    print(json.dumps({"watch": True, "iterations": i, **snap}, ensure_ascii=False))
    # 退出码：done True ⟹ 0；UNKNOWN（None，含未命中/不可判）⟹ 3（fail-loud，禁默认熔断）；
    #   done False ⟹ 1（已轮询但未完成 / 超时）。
    if snap["done"] is True:
        return 0
    if snap["done"] is None:
        return 3
    return 1


if __name__ == "__main__":
    sys.exit(main())

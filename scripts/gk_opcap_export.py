#!/usr/bin/env python3
"""OPCAP 行为面**只读**导出器（判据5 载体，2026-10-24）。

口径（`opcap_evidence.py` 入口与本模块**同源**，**不另立第二套语义**）：
  · **借款** = `<state>.budget-log.jsonl` 中 `source=code-fix` 的记录（一次 code-fix 授予 = 一笔 loan）；
  · **结算** = 按记录 `reason` 里的 `ECC-xxxxxxxxxxxx` 找到背书 finding，按其状态分三桶：
      `realized`（fixed/closed）/ `outstanding`（open 等未结）/ `unbacked`（找不到该 finding）；
  · **结算比** = `realized / n_loans` —— **禁止**拿 finding 计数当分母（会混两本账）；
  · **x8** = finding 的 register→close 时延（中位/极值），仅在 `realized` 上另报一份。

纪律：
  · **只读**：不写 state / 账本 / 任何文件；不调 `state-patch`；
  · **回放禁自报**：全部数字从 append-only 账本与 state 现场重算；
  · **轴分离**：只产人轴（OPCAP）读数，不喂 μ/κ 轴、不改 MoA 权重。

用法：
  python3 scripts/gk_opcap_export.py --state <state> [--pretty]
"""
import argparse
import datetime
import json
import os
import re
import sys
from pathlib import Path

ECC_RE = re.compile(r"ECC-[0-9A-F]{12}")
CLOSED = ("fixed", "closed")
SCHEMA_VERSION = "opcap-1"
# 判据5（2026-11-16 裁定 B）：x3/x4 **本地化载体**（只读，复用既有日志，不新增埋点）。
#   · x3 分子 = credit-ledger `kind=exempt` 行；分母 = hook 日志 `INVOKE event=PreToolUse` 行；
#   · x4 分子 = budget-log 提额事件（下列 source）；分母 = state `_advance_log` 推进条数。
OVERRIDE_SOURCES = ("advance_env", "state_patch_set_nested", "code-fix", "override")


def _ts(s):
    if not s:
        return None
    try:
        return datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


def _hours(a, b):
    if not a or not b:
        return None
    return round((b - a).total_seconds() / 3600.0, 4)


def _median(vals):
    v = sorted(x for x in vals if x is not None)
    n = len(v)
    if not n:
        return None
    return v[n // 2] if n % 2 else round((v[n // 2 - 1] + v[n // 2]) / 2.0, 4)


def _budget_path(state_file: str) -> Path:
    return Path(str(state_file) + ".budget-log.jsonl")


def read_budget_events(state_file: str):
    """坏行跳过（同 `gk_budget_ledger` C4 口径）；缺文件 ⟹ 空。"""
    p = _budget_path(state_file)
    out = []
    if not p.exists():
        return out
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(r, dict):
            out.append(r)
    return out


def load_findings(state_file: str) -> dict:
    """台账视图（`id -> finding`）：**读侧 union**（主台账 ⊕ finding 溢出片）。

    ECC-CD6B34C8EB95：旧实现只读 `gate_data.ecc_findings`，一旦 open 集越线溢出到
    `<state>.finding-archive.jsonl`，溢出条目在 opcap 视图里**消失** ⟹ 结算桶/闭环时延
    算在残缺台账上（同一 state 两套视图）。单源 = `gk_finding.load_findings_union`。
    """
    try:
        _d = str(Path(__file__).resolve().parent)
        if _d not in sys.path:
            sys.path.insert(0, _d)
        from gk_finding import load_findings_union
        fs = load_findings_union(state_file) or []
    except Exception:  # noqa: BLE001 — 边界：单源不可用 ⟹ 回落主台账（不静默变空）
        with open(state_file, "r", encoding="utf-8") as f:
            d = json.load(f)
        fs = ((d.get("gate_data") or {}).get("ecc_findings")) or []
    out = {}
    for f in fs:
        if isinstance(f, dict) and f.get("id"):
            out.setdefault(str(f["id"]), f)
    return out


def close_instant(f):
    return _ts(f.get("verified_at")) or _ts(f.get("closed_at"))


def x8(findings):
    rows = []
    for f in findings.values():
        if str(f.get("status") or "") not in CLOSED:
            continue
        rows.append({"id": f.get("id"), "created_at": f.get("created_at"),
                     "closed_at": f.get("verified_at") or f.get("closed_at"),
                     "latency_hours": _hours(_ts(f.get("created_at")), close_instant(f))})
    lat = [r["latency_hours"] for r in rows]
    rows.sort(key=lambda r: (r["latency_hours"] is None, r["latency_hours"]))
    return {"n_closed": len(rows), "median_hours": _median(lat),
            "min_hours": min((v for v in lat if v is not None), default=None),
            "max_hours": max((v for v in lat if v is not None), default=None),
            "rows": rows}


def loans(events, by_id):
    rows = []
    n_degrade = 0
    for rec in events:
        if rec.get("kind") == "degrade":
            n_degrade += 1
        if str(rec.get("source") or "") != "code-fix":
            continue
        m = ECC_RE.search(str(rec.get("reason") or ""))
        fid = m.group(0) if m else None
        f = by_id.get(fid) if fid else None
        if f is None:
            bucket = "unbacked"
        elif str(f.get("status") or "") in CLOSED:
            bucket = "realized"
        else:
            bucket = "outstanding"
        rows.append({"ts": rec.get("ts"), "finding": fid, "bucket": bucket,
                     "to_max": rec.get("to_max"),
                     "latency_hours": _hours(_ts(f.get("created_at")), close_instant(f)) if f else None})
    n = len(rows)
    realized = [r for r in rows if r["bucket"] == "realized"]
    lat = [r["latency_hours"] for r in realized]
    return {
        "n": n,
        "realized": len(realized),
        "outstanding": sum(1 for r in rows if r["bucket"] == "outstanding"),
        "unbacked": sum(1 for r in rows if r["bucket"] == "unbacked"),
        # 结算比的分母**只是借款数**：finding 计数不进分母（会混两本账、随台账轮转漂移）。
        "settlement_ratio": round(len(realized) / n, 4) if n else None,
        "n_degrade_events": n_degrade,
        "rows": rows,
    }, {"n": len(realized), "median_hours": _median(lat),
        "min_hours": min((v for v in lat if v is not None), default=None),
        "max_hours": max((v for v in lat if v is not None), default=None)}


def _count_ledger_kind(state_file: str, kind: str):
    """`<state>.credit-ledger.jsonl` 中 `kind` 的行数；账本缺失 ⟹ `None`（无载体，不造 0）。"""
    p = Path(str(state_file) + ".credit-ledger.jsonl")
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    n = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict) and rec.get("kind") == kind:
            n += 1
    return n


def _count_hook_invokes():
    """hook 日志中 `INVOKE event=PreToolUse` 行数（与 `check_tool_cfg` 同一格式）。

    真实行形态 = `<ts> INVOKE event=PreToolUse tool=… cwd=…`（**行首是时间戳**，2026-11-16
    实测）⟹ 用子串判据而非 `startswith`。日志缺失 ⟹ `None`（无载体）。
    只认 `PreToolUse`：`event=?` 是单测直调 main 的记录，不是真实派发（同 `check_tool_cfg`）。
    """
    p = Path(os.environ.get("GK_HOOK_LOG")
             or (Path(__file__).resolve().parent.parent / ".gatekeeper.hook.log"))
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    return sum(1 for ln in lines if "INVOKE event=PreToolUse" in ln)


def _advance_count(state_file: str) -> int:
    """推进条数（x4 分母）：**单源 = `gate_data._advance_log`**，兼容旧顶层形态。

    2026-11-16 实测：真实 state 的 `_advance_log` 在 `gate_data` 下（顶层为 0）⟹ 只读顶层
    会把分母恒判 0、x4 永远不可用。state 不可读 ⟹ 0。
    """
    try:
        d = json.loads(Path(state_file).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    if not isinstance(d, dict):
        return 0
    log = d.get("_advance_log")
    if not isinstance(log, list):
        log = (d.get("gate_data") or {}).get("_advance_log")
    return len(log) if isinstance(log, list) else 0


def export(state_file: str) -> dict:
    if not state_file or not Path(state_file).exists():
        return {"ok": False, "error": "no_state_file"}
    findings = load_findings(state_file)
    events = read_budget_events(state_file)
    loan_stats, realized_x8 = loans(events, findings)
    out = {"ok": True, "schema_version": SCHEMA_VERSION, "source_state": state_file,
           # 只作上下文（口径显式），**从不**当分母。
           "n_findings_in_view": len(findings),
           "n_open": sum(1 for f in findings.values() if str(f.get("status") or "") == "open"),
           "loans": loan_stats, "realized_x8": realized_x8,
           "x8_register_to_close": x8(findings)}
    # 判据5 裁定 B（2026-11-16）：x3/x4 本地化载体（只读计数，缺失报 None 不造数）。
    #   分母**统一用** hook `INVOKE event=PreToolUse`（机会数）；`advances` 只作上下文
    #   ——实测 `_advance_log` 被裁剪到最近 5 条（`gk_advance` 上限 10），拿它当分母会恒失真。
    _inv = _count_hook_invokes()
    out["x3_ack_injected"] = {"exempt": _count_ledger_kind(state_file, "exempt"),
                              "gate_invokes": _inv}
    out["x4_overrides"] = {"events": sum(
        1 for r in events if str(r.get("source") or "") in OVERRIDE_SOURCES),
        "gate_invokes": _inv, "advances": _advance_count(state_file)}
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_opcap_export.py")
    ap.add_argument("--state", required=True)
    ap.add_argument("--pretty", action="store_true")
    ns = ap.parse_args(argv)
    out = export(ns.state)
    print(json.dumps(out, ensure_ascii=False, indent=2 if ns.pretty else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())

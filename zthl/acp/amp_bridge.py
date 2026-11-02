"""AMP 兼容层 —— 采集层（既有事实源 → 规范 Body）。

唯一源
------
计划 §2.7「AMP 兼容层设计」的**六类日志 × ZTHL 数据源**映射表：

| AMP 日志 | 数据源 | 本模块入口 |
|:--|:--|:--|
| heartbeat | `gk_self_check.py` 自检状态 | `heartbeat()` |
| access | hook 判定（`pre_tool_hook`，承接原 `block_log` 语义）+ `_advance_log` | `access()` |
| metrics | access 窗口汇总（原计划指向 `gk_worker` 线程池 → 实测 0 调用点，改用可观测的 access 面）| `metrics()` |
| audit | `<state>.finding-journal.jsonl` 裁决事件 + `human_resolutions` | `audit()` |
| system | 自检 FAIL/WARN（运行环境与关联服务状态，自由格式） | `system()` |
| message | AIP 消息净化（`message_guard.py`）+ H14d 路由 | `message()` —— **seam，ZH3 前不产出** |

纪律：本模块只**读**既有事实源，不新建第二事实源（对齐 H3 设计第 3 条）。
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Optional

from . import amp

__all__ = [
    "aic", "access", "heartbeat", "metrics", "audit", "system", "message",
    "uptime_seconds", "percentile",
]


def aic() -> str:
    return os.environ.get("GK_AIC", "").strip() or amp.DEFAULT_AIC


# ── heartbeat ────────────────────────────────────────────────────────────────
def uptime_seconds() -> Optional[int]:
    """系统运行时长（秒）。`CLOCK_BOOTTIME` → Windows `GetTickCount64` → `/proc/uptime`。"""
    if hasattr(time, "CLOCK_BOOTTIME"):
        try:
            return int(time.clock_gettime(time.CLOCK_BOOTTIME))
        except OSError:
            pass
    try:
        import ctypes
        return int(ctypes.windll.kernel32.GetTickCount64() / 1000)  # type: ignore[attr-defined]
    except Exception:
        pass
    try:
        return int(float(Path("/proc/uptime").read_text().split()[0]))
    except Exception:
        return None


def heartbeat(self_check: Optional[dict] = None) -> dict:
    """`HeartbeatBody`：仅 `uptimeSeconds`；自检摘要落 `attributes`（存活事实在本体）。"""
    body: dict = {}
    up = uptime_seconds()
    if up is not None:
        body["uptimeSeconds"] = up
    attrs: dict = {"zthl.self_check.ok": True}
    if isinstance(self_check, dict):
        checks = self_check.get("checks") or []
        bad = [c.get("field") or c.get("name") or "?"
               for c in checks if isinstance(c, dict) and c.get("status") != "PASS"]
        attrs.update({
            "zthl.self_check.issues": int(self_check.get("issues") or 0),
            "zthl.self_check.total": len(checks),
            "zthl.self_check.nonpass": bad[:20],
        })
    return {"log_type": "heartbeat", "body": body, "attributes": attrs}


# ── access ───────────────────────────────────────────────────────────────────
# 判定 → 响应码：0 = OK（对齐 spec §5.4.1「RPC: 0 (OK)」）；非 0 = 拦截面退出码。
def access(tool: str, decision: str, exit_code: int = 0, reason: str = "",
           duration_ms: Optional[float] = None,
           trace_id: Optional[str] = None) -> dict:
    """一次工具调用 → `AccessBody`。判定落 `attributes`（body 保持规范纯净）。"""
    body: dict = {
        "request": {"method": tool or "", "route": tool or ""},
        "response": {"statusCode": 0 if decision == "allow" else int(exit_code or 2)},
    }
    if duration_ms is not None:
        body["durationMs"] = round(float(duration_ms), 3)
    if decision != "allow":
        body["error"] = {"code": int(exit_code or 2),
                         "message": (reason or decision)[:200]}
    return {
        "log_type": "access",
        "body": body,
        "attributes": {"zthl.decision": decision, "zthl.exit_code": int(exit_code or 0)},
        "trace_id": trace_id or amp.new_trace_id(),
        "span_id": amp.new_span_id(),
        "severity": "INFO" if decision == "allow" else "WARN",
    }


# ── metrics ──────────────────────────────────────────────────────────────────
def percentile(values: list, q: float) -> Optional[float]:
    """最近秩百分位（`q` ∈ [0,1]）；空列表 → `None`。"""
    if not values:
        return None
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round(q * (len(s) - 1)))))
    return float(s[k])


def metrics(window_minutes: int = 5) -> Optional[dict]:
    """窗口汇总 → `MetricsBody`。无 access 记录 ⟹ `None`（不产出空指标）。"""
    if window_minutes <= 0:
        return None
    recs = amp.query("access", since=f"{window_minutes}m", limit=100000)
    if not recs:
        return None
    lat, ok, total = [], 0, 0
    for r in recs:
        total += 1
        if (r.get("attributes") or {}).get("zthl.decision") == "allow":
            ok += 1
        d = (r.get("body") or {}).get("durationMs")
        if isinstance(d, (int, float)):
            lat.append(float(d))
    span = max(1.0, float(window_minutes) * 60.0)
    win = {"window": f"PT{window_minutes}M",
           "successRate": round(100.0 * ok / total, 3) if total else 100.0,
           "requestTotal": total,
           "requestPerSecond": round(total / span, 4)}
    for name, q in (("p90LatencyMs", 0.90), ("p95LatencyMs", 0.95), ("p99LatencyMs", 0.99)):
        v = percentile(lat, q)
        if v is not None:
            win[name] = round(v, 3)
    if lat:
        win["avgLatencyMs"] = round(sum(lat) / len(lat), 3)
    return {"log_type": "metrics", "body": {"windowMetrics": [win]},
            "attributes": {"zthl.metrics.source": "amp/access.log"}}


# ── audit ────────────────────────────────────────────────────────────────────
#: finding-journal 事件 → 结果状态（`AuditBody.result.status` 仅 success/failure/unknown）
_AUDIT_STATUS = {
    "register": "success", "verify": "success", "close": "success", "reopen": "success",
    "release": "success", "declassify": "success", "merge": "success",
    "amend-title": "success", "accept_ack": "success", "precheck_ack": "success",
    "route_drift": "failure", "conflict_dedupe": "unknown",
    "conflict_converge": "unknown", "conflict_converge_repair": "unknown",
    "dup_suspect": "unknown", "prune_duplicate": "unknown", "epoch": "unknown",
}


def audit(entry: dict) -> dict:
    """一条 finding-journal 事件 → `AuditBody`（actor = 本机 agent 服务身份）。"""
    ev = str(entry.get("event") or "unknown")
    fid = str(entry.get("fid") or "")
    status = _AUDIT_STATUS.get(ev, "unknown")
    body = {
        "actor": {"id": aic(), "type": "service", "name": "zthl-core"},
        "action": {"name": f"finding.{ev}", "type": "finding"},
        "target": {"type": "finding", "id": fid or "-"},
        "result": {"status": status},
    }
    reason = entry.get("reason") or entry.get("detail") or entry.get("title")
    if reason:
        body["result"]["reason"] = str(reason)[:200]
    ts = entry.get("ts")
    out = {"log_type": "audit", "body": body,
           "attributes": {"zthl.event": ev},
           "correlation_id": fid or None}
    if isinstance(ts, str) and "T" in ts:      # journal ts = ISO 8601 UTC，可直接复用
        out["timestamp"] = ts
    return out


# ── system ───────────────────────────────────────────────────────────────────
def system(self_check: Optional[dict] = None) -> Optional[dict]:
    """自检 FAIL/WARN → `system`（自由格式 body，原文置 `rawBody`）。无非 PASS 项 ⟹ `None`。"""
    if not isinstance(self_check, dict):
        return None
    bad = [c for c in (self_check.get("checks") or [])
           if isinstance(c, dict) and c.get("status") != "PASS"]
    if not bad:
        return None
    raw = [{"check": c.get("field") or c.get("name"), "status": c.get("status"),
            "detail": str(c.get("detail") or "")[:300]} for c in bad[:20]]
    return {
        "log_type": "system",
        "body": {"component": "zthl-core", "module": "gk_self_check",
                 "rawBody": raw,
                 "tags": {"issues": str(int(self_check.get("issues") or 0))}},
        "severity": "WARN",
    }


# ── message（seam）────────────────────────────────────────────────────────────
def message(*_args, **_kwargs) -> None:
    """`MessageBody` 采集**未接线**：AIP 消息面 = 计划 ZH3-H14d（`message_guard.py` +
    消息路由）。此前 AIP 消息不存在 ⟹ 恒 `None`，避免产出幻影记录（H14f 接线点）。"""
    return None


def read_journal(state_file: str, limit: int = 0) -> list:
    """读 `<state>.finding-journal.jsonl`（只读；缺失 → `[]`）。`limit>0` 取尾部。"""
    p = Path(str(state_file) + ".finding-journal.jsonl")
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    if limit and limit > 0:
        lines = lines[-limit:]
    out = []
    for line in lines:
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def existing_audit_keys(log_dir: Optional[Path] = None) -> set:
    """已落盘的 audit `correlationId+action.name+timestamp` 组合（幂等去重键）。

    `LogRecord.logId` 由源端生成 ⟹ 采集侧以**源事件自然键**去重，避免重跑重复入账。
    """
    root = Path(log_dir) if log_dir else amp.amp_dir()
    keys = set()
    try:
        lines = (root / "audit.log").read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return keys
    for line in lines:
        try:
            r = json.loads(line)
        except ValueError:
            continue
        body = r.get("body") or {}
        keys.add((r.get("correlationId", ""), (body.get("action") or {}).get("name", ""),
                  r.get("timestamp", "")))
    return keys


def journal_natural_key(entry: dict) -> tuple:
    return (str(entry.get("fid") or ""), f"finding.{entry.get('event') or 'unknown'}",
            str(entry.get("ts") or ""))


def collect_audit(state_file: str, *, dry_run: bool = False) -> dict:
    """把 journal 中**尚未入 AMP** 的事件写成 audit 记录（幂等）。返回统计。"""
    seen = existing_audit_keys()
    added, skipped = 0, 0
    for entry in read_journal(state_file):
        key = journal_natural_key(entry)
        if key in seen:
            skipped += 1
            continue
        if not dry_run:
            amp.emit(**audit(entry))
        added += 1
    return {"ok": True, "added": added, "skipped": skipped, "journal": f"{state_file}.finding-journal.jsonl"}


def collect_all(state_file: str, self_check: Optional[dict] = None,
                window_minutes: int = 5) -> dict:
    """一次性采集 heartbeat / metrics / audit / system（message 为 seam，不产出）。"""
    out: dict[str, Any] = {}
    hb = amp.emit(**heartbeat(self_check))
    out["heartbeat"] = bool(hb)
    try:
        m = metrics(window_minutes)
        out["metrics"] = bool(m and amp.emit(**m))
    except Exception:
        out["metrics"] = False
    sysrec = system(self_check)
    out["system"] = bool(sysrec and amp.emit(**sysrec))
    out["audit"] = collect_audit(state_file)
    out["message"] = None       # seam：ZH3-H14d
    out["dir"] = str(amp.amp_dir())
    return out

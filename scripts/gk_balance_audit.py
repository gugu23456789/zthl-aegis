#!/usr/bin/env python3
"""gk_balance_audit.py — 余额采样 + token 异常/缓存崩溃判定（advisory，2026-11-04）。

用户口径（「余额检查命令需要改造一下，需要用于随机或者定期。检查是否存在 token 异常
消耗 / 缓存命中突然崩溃？subagent 那边应该已经有类似的东西了？」）：

- **输入**：DeepSeek `/user/balance` 响应（stdin）+ 上次采样台账；可选 subagent 的
  `token_usage.calls` 文件。
- **单源（2026-11-04 用户质询「双源漂移」后收敛）**：
  · 余额解析**只**走 `gk_views.parse_balance`（bal 视图 + `balance_format.py` 同源）；
  · 逐调用 usage 提取/展开**只**走 `gk_cache_observe.extract_calls` / `flatten_calls`
    （`gk_phase_probe` 同源）；缓存判定**只**走 `gk_cache_observe.observe()`。
  本模块**不**再自带任何 `balance_infos` / `usage_calls` 解析。
- **判定**（只报告、不改任何 gate、不阻断）：
  · `INSUFFICIENT_BALANCE`  余额 ≤ `GK_BALANCE_MIN_CNY`（默认 2.0）
  · `UNEXPECTED_ZERO`       上一样本 > 0，本次 ≤ 0
  · `DROP_FAST`             消耗速率 > `GK_BALANCE_MAX_CNY_PER_H`（默认 10.0 CNY/h）
  · `SPARSE_SAMPLES`        两次采样间隔 > `GK_BALANCE_MAX_GAP_H`（默认 24h，速率不判）
  · `CACHE_COLLAPSE`        稳态命中率 < target（`cache_status=BELOW_TARGET`）
  · `CACHE_INVALIDATION`    逐调用 cacheRead 出现回落点（上下文被反复重建）
  · `CACHE_UNKNOWN`         稳态样本不足（不冒充「崩溃」，只记不可判）
- **调度友好**：幂等只读（除本机台账）；`--jitter N` 先随机 sleep ≤N 秒（把采样时刻打散，
  避免固定时刻撞上同一个缓存窗口/限流）；`--record` 追加一行 JSON 到台账（原子 + 截尾）。
- **台账**：默认 `~/.gatekeeper/balance-history.jsonl`（`GK_BALANCE_HISTORY` 可覆盖），
  超过 `MAX_LINES` 行时**整文件原子重写**保留尾部，避免无限增长。

退出码：0 = 正常（即使有 finding，advisory 不阻断）；1 = `--strict` 且存在 high findings；
2 = 输入不可解析（拿不到余额/用量时**不猜**）。
"""
import json
import os
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_cache_observe as cache_observe  # noqa: E402
import gk_views  # noqa: E402 — 余额解析单源

MAX_LINES = 5000
DEFAULT_MIN_CNY = 2.0
DEFAULT_MAX_CNY_PER_H = 10.0
DEFAULT_MAX_GAP_H = 24.0
HIGH = "high"
MEDIUM = "medium"
INFO = "info"


# ── 快照 ───────────────────────────────────────────────────────────────────
def history_path(explicit: str = "") -> Path:
    p = explicit or os.environ.get("GK_BALANCE_HISTORY", "")
    return Path(p) if p else Path.home() / ".gatekeeper" / "balance-history.jsonl"


def parse_balance(resp, ts: float | None = None) -> dict:
    """`resp` → 台账快照。**解析委托 `gk_views.parse_balance`**（禁第二份 `balance_infos`）。

    本函数只做"解析结果 → 台账行"的**投影**（加 `ts`、把 total 定型为 float），
    不复刻任何余额语义（求和/不可用归零都在单源里）。
    """
    p = gk_views.parse_balance(resp)
    return {"ts": round(time.time() if ts is None else ts, 3),
            "total": float(p.get("total") or 0.0),
            "currency": p.get("currency") or "",
            "available": p.get("available")}


def read_history(path: Path) -> list:
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue  # 半写行跳过（台账不是事实源）
                if isinstance(d, dict) and "total" in d:
                    out.append(d)
    except OSError:
        return []
    return out


def record(path: Path, snap: dict) -> dict:
    """追加一行；超限则整文件原子重写保留尾部。返回 `{ok, path, lines}`。"""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        rows = read_history(path)
        rows.append(snap)
        truncated = max(0, len(rows) - MAX_LINES)
        rows = rows[-MAX_LINES:]
        tmp = path.with_name(path.name + ".tmp-%d" % os.getpid())
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
        os.replace(tmp, path)
        return {"ok": True, "path": str(path), "lines": len(rows), "truncated": truncated}
    except OSError as e:
        # 台账写不进不得影响余额查询本身（advisory）
        return {"ok": False, "path": str(path), "error": "%s: %s" % (type(e).__name__, e)}


# ── 判定 ───────────────────────────────────────────────────────────────────
def _f(env: str, default: float) -> float:
    try:
        v = float(os.environ.get(env, "") or default)
    except (TypeError, ValueError):
        return default
    return v if v == v else default  # NaN → 默认


def evaluate(prev, cur, min_cny: float, max_per_h: float, max_gap_h: float) -> list:
    """余额连续性判定（纯函数，便于测）。返回 finding 列表（`kind/severity/reason/evidence`）。"""
    out = []
    cur_total = float(cur.get("total") or 0)
    if cur_total <= min_cny:
        out.append({"kind": "INSUFFICIENT_BALANCE", "severity": HIGH,
                    "reason": "余额 ≤ 阈值", "evidence": {"total": cur_total, "min": min_cny}})
    if not prev:
        out.append({"kind": "NO_BASELINE", "severity": INFO,
                    "reason": "首次采样（无历史可比）", "evidence": {"total": cur_total}})
        return out
    prev_total = float(prev.get("total") or 0)
    gap_h = max(0.0, (float(cur.get("ts") or 0) - float(prev.get("ts") or 0)) / 3600.0)
    if prev_total > 0 and cur_total <= 0:
        out.append({"kind": "UNEXPECTED_ZERO", "severity": HIGH,
                    "reason": "余额从正数归零（耗尽/被清空，需人工确认）",
                    "evidence": {"prev": prev_total, "cur": cur_total}})
    if gap_h <= 0:
        return out
    if gap_h > max_gap_h:
        out.append({"kind": "SPARSE_SAMPLES", "severity": INFO,
                    "reason": "采样间隔过大，不判速率", "evidence": {"gap_h": round(gap_h, 2)}})
        return out
    burn = (prev_total - cur_total) / gap_h
    if burn > max_per_h:
        out.append({"kind": "DROP_FAST", "severity": HIGH,
                    "reason": "余额消耗速率超阈值（疑似 token 异常消耗/死循环/重试风暴）",
                    "evidence": {"cny_per_h": round(burn, 3), "max": max_per_h,
                                 "gap_h": round(gap_h, 3),
                                 "prev": prev_total, "cur": cur_total}})
    return out


def load_usage_payload(path: str):
    """读 subagent 产物 → **原始载荷**（JSON 或 JSONL）；不可读 ⟹ None（不猜）。

    解析**不在本模块**：交给 `gk_cache_observe.extract_calls`（与 `gk_phase_probe` 同源）。
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        calls = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if isinstance(d, dict):
                calls.append(d)
        return calls
    return _extract_calls(data)


def _extract_calls(data) -> list:
    """单源委托：解析规则**只**在 `gk_cache_observe.extract_calls`（禁第二份）。"""
    return cache_observe.extract_calls(data)


def cache_health(payload, provider: str = "") -> tuple:
    """→ (findings, summary)。**单源**：提取/展开/判定全部委托 `gk_cache_observe`。

    `payload` 可为 subagent 产物（`{"token_usage": {"calls": [...]}}`，calls 是**扁平**
    provider 原生 usage）、`{"usage_calls": [...]}`、纯列表或单条 `{"usage": {...}}`。
    provider 缺失时由 `infer_provider` 按字段名推断；推不出 ⟹ 丢弃 ⟹ 具名 UNKNOWN。
    """
    calls = cache_observe.extract_calls(payload)
    if not calls:
        return ([{"kind": "CACHE_UNKNOWN", "severity": INFO,
                  "reason": "无可用 token_usage 记录（拿不到就说不准，不猜）",
                  "evidence": {"calls": 0}}], {})
    if all(isinstance(c, dict) and "usage_calls" in c for c in calls):
        records = calls
    else:
        records = [{"length": 0, "provider": provider, "usage_calls": calls}]
    flat = cache_observe.flatten_calls(records)
    if not flat:
        return ([{"kind": "CACHE_UNKNOWN", "severity": INFO,
                  "reason": "usage 字段无法归属到任何 provider（不硬塞默认厂商）",
                  "evidence": {"calls": len(calls)}}], {})
    _rows, summary = cache_observe.observe(flat)
    findings = []
    status = summary.get("cache_status")
    if status == "BELOW_TARGET":
        findings.append({"kind": "CACHE_COLLAPSE", "severity": HIGH,
                         "reason": "稳态缓存命中率低于阈值（上下文被反复重建 / prompt 前缀不稳定）",
                         "evidence": {"steady_cache_hit_ratio": summary.get("steady_cache_hit_ratio"),
                                      "target": summary.get("cache_target"),
                                      "steady_calls": summary.get("steady_calls")}})
    elif status == "UNKNOWN":
        findings.append({"kind": "CACHE_UNKNOWN", "severity": INFO,
                         "reason": "稳态样本不足，不判缓存崩溃",
                         "evidence": {"calls": summary.get("calls"),
                                      "steady_calls": summary.get("steady_calls")}})
    inv = summary.get("invalidation_points") or []
    if inv:
        findings.append({"kind": "CACHE_INVALIDATION", "severity": MEDIUM,
                         "reason": "逐调用 cacheRead 出现回落（缓存失效点）",
                         "evidence": {"points": inv[:5], "count": len(inv)}})
    return findings, summary


# ── 输出 ───────────────────────────────────────────────────────────────────
def render(out: dict) -> str:
    snap = out.get("snapshot") or {}
    lines = ["Balance: %s %s%s" % (snap.get("total"), snap.get("currency") or "",
                                   "" if snap.get("available") is not False else " (unavailable)")]
    for f in out.get("findings") or []:
        lines.append("[%s] %s — %s %s" % (f.get("severity", "?"), f.get("kind"),
                                          f.get("reason", ""),
                                          json.dumps(f.get("evidence") or {}, ensure_ascii=False)))
    cache = out.get("cache")
    if cache:
        lines.append("Cache: status=%s steady=%s invalidation=%d" % (
            cache.get("cache_status"), cache.get("steady_cache_hit_ratio"),
            len(cache.get("invalidation_points") or [])))
    return "\n".join(lines)


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="余额采样 + token/缓存异常判定（advisory）")
    ap.add_argument("--stdin", action="store_true", help="从 stdin 读 balance 响应 JSON")
    ap.add_argument("--history", default="")
    ap.add_argument("--record", action="store_true", help="把本次快照写入台账")
    ap.add_argument("--audit", action="store_true", help="与上一个快照比较")
    ap.add_argument("--usage", default="", help="subagent token_usage 文件（JSON/JSONL）")
    ap.add_argument("--jitter", type=float, default=0.0, help="先随机 sleep 0..N 秒")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true", help="存在 high finding 时退出 1")
    a = ap.parse_args(argv)

    if a.jitter > 0:
        time.sleep(random.uniform(0, a.jitter))
    resp = {}
    if a.stdin:
        raw = sys.stdin.read()
        try:
            resp = json.loads(raw) if raw.strip() else {}
        except ValueError as e:
            print(json.dumps({"error": "BALANCE_UNPARSEABLE", "detail": str(e)}, ensure_ascii=False))
            return 2
        if not isinstance(resp, dict):
            print(json.dumps({"error": "BALANCE_UNPARSEABLE", "detail": "top-level not object"},
                             ensure_ascii=False))
            return 2

    snap = parse_balance(resp)
    hist = history_path(a.history)
    findings = []
    if a.audit or a.strict:
        rows = read_history(hist) if a.audit else []
        findings += evaluate(rows[-1] if rows else None, snap,
                             _f("GK_BALANCE_MIN_CNY", DEFAULT_MIN_CNY),
                             _f("GK_BALANCE_MAX_CNY_PER_H", DEFAULT_MAX_CNY_PER_H),
                             _f("GK_BALANCE_MAX_GAP_H", DEFAULT_MAX_GAP_H))
    cache = None
    if a.usage:
        payload = load_usage_payload(a.usage)
        if payload is None:
            findings.append({"kind": "CACHE_UNKNOWN", "severity": INFO,
                             "reason": "usage 文件不可读（不猜）",
                             "evidence": {"path": a.usage}})
        else:
            cfind, cache = cache_health(payload)
            findings += cfind
    rec = record(hist, snap) if a.record else None
    out = {"snapshot": snap, "findings": findings, "advisory_only": True,
           "history": str(hist), "recorded": rec, "cache": cache}
    print(json.dumps(out, ensure_ascii=False) if a.json else render(out))
    if a.strict and any(f.get("severity") == HIGH for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

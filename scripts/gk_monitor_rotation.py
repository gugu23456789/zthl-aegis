#!/usr/bin/env python3
"""gk_monitor_rotation.py — monitor **事件驱动 + 旋转门**（A+B，2026-11-11）。

病象（用户裁定）：「monitor 防护当前是没什么用的闲置状态」——`--api` 的分数只进 advisory，
没人调用就零作用；`--local` / `--subagent` 也只在人工阶段被调。要"有用"，必须由**攻击信号**
驱动，且检测面轮转（动态攻防旋转门），而不是定时全量重跑（那只会烧 token）。

分工（判据单源，本模块不复制）：
  · 信号 = `gk_threat.events_all()`（per-sid 违约台账，窗口内）；
  · 隔离 = `gk_threat.check`（由 hook 执行；本模块只 triage，不替代它）；
  · 诱饵轮转 = `gk_canary.rotate/maybe_rotate`（退役世代仍参与判定 ⟹ 旧地图必暴露）；
  · LLM 裁决 = `gk_monitor_decision.run`（既有决策后端；endpoint 未配 ⟹ advisory，不联网）。

行为契约：
  · **无新信号 ⟹ `activated=false`，零 API / 零 LLM**；只做周期轮转检查；
  · 有信号 ⟹ 确定性 triage（level 0..3）→ 达到 `GK_MONITOR_THREAT_API_LEVEL`（默认 2）才升级；
  · 每事件只消费一次（游标 `last_ts`）；一次最多消费 20 条（brief 有界）；
  · 预算：滚动 1h 内 LLM 调用 ≤ `GK_MONITOR_API_PER_HOUR`（默认 3），超限只留 deterministic 分；
  · `--dry-run` ⟹ 只读：不轮转、不调 LLM、不推进游标、不落审计行。

存储（侧挂主 state，均被 `.gitignore` 覆盖）：
  · `<state>.threat.monitor.json` —— 游标 + 预算（临时件 + `os.replace` 原子写）；
  · `<state>.threat.monitor.jsonl` —— 每次激活一行（append-only 审计面）。

边界：不对外部主体做任何动作；真实 DDoS 仍只走既有准入控制（`gk_sandbox` 限额）。

用法：
  python3 gk_monitor_rotation.py run --repo <仓根> [--state <state>] [--dry-run]
  python3 gk_monitor_rotation.py status [--state <state>]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_canary as canary      # noqa: E402
import gk_threat as threat      # noqa: E402

try:                            # Linux/WSL 才有 flock；Windows 退化为无锁（见报告"剩余风险"）
    import fcntl
except ImportError:             # pragma: no cover
    fcntl = None

BRIEF_MAX = 20
LEVEL_NAMES = ("normal", "low", "medium", "high")
_VERDICT = {0: ("SKIP", 0.5), 1: ("WARN", 0.5), 2: ("FAIL", 0.25), 3: ("FAIL", 0.0)}


def _env_int(name: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


def _cursor_path(state=None) -> Path:
    st = threat.state_file(state)
    return st.with_name(st.name + ".threat.monitor.json")


def _log_path(state=None) -> Path:
    st = threat.state_file(state)
    return st.with_name(st.name + ".threat.monitor.jsonl")


def _load_cursor(p: Path) -> dict:
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_cursor(p: Path, data: dict) -> None:
    try:
        tmp = p.with_name(p.name + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, p)
    except OSError:
        pass          # 游标失败不影响本次 triage（最坏是重复消费一次，不会漏）


def _append_log(p: Path, rec: dict) -> None:
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


_NO_LOCK = object()


def _acquire_lock(st: Path):
    """单消费者锁（cron 重叠 / 人工与定时同时跑 ⟹ 不重复消费、不双花 LLM 预算）。

    `flock(LOCK_EX|LOCK_NB)`：拿不到 ⟹ `None`（调用方回 `reason=locked`，**不**静默双跑）。
    无 fcntl（Windows）⟹ 返回哨兵，退化为无锁；该缺口在 408 报告的剩余风险里登记。
    """
    if fcntl is None:
        return _NO_LOCK
    p = st.with_name(st.name + ".threat.monitor.lock")
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        f = open(p, "a+")
        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return f
    except OSError:
        return None


def _release_lock(f) -> None:
    if f is _NO_LOCK:
        return
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        f.close()
    except Exception:  # noqa: BLE001 — 释放失败不得影响本次结论
        pass


def triage(events: list[dict]) -> dict:
    """确定性分档（0=normal / 1=low / 2=medium / 3=high）—— **不调 LLM**。"""
    per_sid: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    for e in events or []:
        per_sid[str(e.get("sid") or "?")] = per_sid.get(str(e.get("sid") or "?"), 0) + 1
        by_kind[str(e.get("kind") or "?")] = by_kind.get(str(e.get("kind") or "?"), 0) + 1
    total = len(events or [])
    quarantined = sum(1 for n in per_sid.values() if n >= threat.quarantine_at())
    if total == 0:
        level = 0
    elif quarantined >= 2 or total >= 6:
        level = 3
    elif quarantined >= 1 or total >= 3:
        level = 2
    else:
        level = 1
    verdict, score = _VERDICT[level]
    return {"level": level, "name": LEVEL_NAMES[level], "verdict": verdict, "score": score,
            "total": total, "per_sid": per_sid, "by_kind": by_kind,
            "quarantined_sids": quarantined}


def brief(events: list[dict]) -> dict:
    evs = (events or [])[-BRIEF_MAX:]
    return {"count": len(events or []), "shown": len(evs),
            "events": [{"ts": e.get("ts"), "sid": e.get("sid"), "kind": e.get("kind"),
                        "detail": str(e.get("detail") or "")[:160]} for e in evs]}


def run(repo: str = "", state=None, dry_run: bool = False, endpoint=None,
        now: float | None = None, max_api_per_hour: int | None = None) -> dict:
    """消费新违约信号；无信号 ⟹ 零调用。返回可直接落审计的摘要。

    单消费者：拿不到锁 ⟹ `activated=False, reason=locked`（并发 cron 不双跑）。
    """
    now = time.time() if now is None else float(now)
    st = threat.state_file(state)
    lock = _acquire_lock(st)
    if lock is None:
        return {"ok": True, "activated": False, "reason": "locked", "api_calls": 0,
                "rotation": {}, "window_s": threat.window_s()}
    try:
        return _run_impl(repo, st, now, dry_run, endpoint, max_api_per_hour)
    finally:
        _release_lock(lock)


def _run_impl(repo: str, st: Path, now: float, dry_run: bool, endpoint,
              max_api_per_hour) -> dict:
    cur = _load_cursor(_cursor_path(st))
    since = float(cur.get("last_ts") or (now - threat.window_s()))
    evs = [e for e in threat.events_all(state=str(st), window=threat.window_s(), now=now)
           if float(e.get("ts") or 0) > since]
    evs.sort(key=lambda e: float(e.get("ts") or 0))

    # 周期轮转（无信号也检查；dry-run 一律不写）
    if dry_run:
        rotation = {"rotated": False, "reason": "dry_run"}
    elif repo:
        rotation = canary.maybe_rotate(
            repo, min_interval_s=_env_int("GK_CANARY_ROTATE_S", 21600, 0), now=now)
    else:
        rotation = {"rotated": False, "reason": "no_repo"}

    if not evs:
        return {"ok": True, "activated": False, "reason": "no_signal", "api_calls": 0,
                "rotation": rotation, "cursor": since, "window_s": threat.window_s()}

    tri = triage(evs)
    b = brief(evs)
    api_runs = [float(t) for t in (cur.get("api_runs") or [])
                if now - float(t) < 3600]
    cap = (_env_int("GK_MONITOR_API_PER_HOUR", 3, 0) if max_api_per_hour is None
           else max(0, int(max_api_per_hour)))
    api_level = _env_int("GK_MONITOR_THREAT_API_LEVEL", 2, 0)
    ep = (endpoint if endpoint is not None
          else os.environ.get("GK_AUDIT_OUTCOME_ENDPOINT", "")).strip()

    mon = {"ok": True, "mode": "--local", "verdict": tri["verdict"], "score": tri["score"],
           "violations": [], "advisory": ""}
    api_calls = 0
    if tri["level"] >= api_level:
        if not ep:
            mon["advisory"] = "endpoint_unset"
        elif len(api_runs) >= cap:
            mon["advisory"] = "budget_exhausted"
        elif not dry_run:
            try:
                import gk_monitor_decision as MD
                mon = MD.run("THREAT-TRIAGE", ep, worktree=str(repo or ""), branch="",
                             evidence=b,
                             timeout=_env_int("GK_MONITOR_THREAT_TIMEOUT", 30, 1))
                api_calls = 1
                api_runs.append(now)
            except Exception as e:  # noqa: BLE001 — 边界：决策后端不可用 ⟹ 保留确定性分
                mon["advisory"] = "decision_unavailable: %s: %s" % (type(e).__name__, e)

    out = {"ok": True, "activated": True, "level": tri["level"], "name": tri["name"],
           "verdict": mon.get("verdict") or tri["verdict"],
           "signals": {"count": tri["total"], "by_kind": tri["by_kind"],
                       "per_sid": tri["per_sid"]},
           "quarantined_sids": tri["quarantined_sids"], "brief": b,
           "api_calls": api_calls, "monitor": mon, "rotation": rotation,
           "cursor": float(evs[-1].get("ts") or now), "window_s": threat.window_s()}

    # 中/高等级 ⟹ **立即**旋转（旧地图作废）；仍受 60s debounce，防命中风暴里反复重建。
    # 若周期轮转已在本轮完成（rotation.rotated=True），保留它 —— 否则会把自己的成果报成 debounced。
    if tri["level"] >= 2 and repo and not dry_run:
        r2 = canary.maybe_rotate(repo, min_interval_s=canary.ROTATE_DEBOUNCE_S,
                                 on_hit=True, now=now)
        if r2.get("rotated") or not (rotation or {}).get("rotated"):
            out["rotation"] = r2

    if not dry_run:
        _save_cursor(_cursor_path(st), {
            "last_ts": out["cursor"], "api_runs": api_runs,
            "last": {"ts": round(now, 3), "level": tri["level"], "verdict": out["verdict"],
                     "rotation_gen": (out.get("rotation") or {}).get("generation")}})
        _append_log(_log_path(st), {
            "ts": round(now, 3), "level": tri["level"], "count": tri["total"],
            "api_calls": api_calls, "verdict": out["verdict"],
            "generation": (out.get("rotation") or {}).get("generation")})
    return out


def status(state=None, now: float | None = None) -> dict:
    now = time.time() if now is None else float(now)
    st = threat.state_file(state)
    cur = _load_cursor(_cursor_path(st))
    runs = [float(t) for t in (cur.get("api_runs") or []) if now - float(t) < 3600]
    return {"ok": True, "state": str(st), "cursor": cur.get("last_ts", 0),
            "api_runs_1h": len(runs), "last": cur.get("last", {}),
            "api_per_hour": _env_int("GK_MONITOR_API_PER_HOUR", 3, 0),
            "threat_window_s": threat.window_s(),
            "rotation_period_s": _env_int("GK_CANARY_ROTATE_S", 21600, 0)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="monitor 事件驱动 + 诱饵旋转门")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("run")
    p.add_argument("--repo", default="")
    p.add_argument("--state", default="")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--endpoint", default=None)
    p.add_argument("--max-api-per-hour", type=int, default=None)
    p = sub.add_parser("status")
    p.add_argument("--state", default="")
    ns = ap.parse_args(argv)
    if ns.cmd == "run":
        out = run(ns.repo, state=ns.state or None, dry_run=ns.dry_run,
                  endpoint=ns.endpoint, max_api_per_hour=ns.max_api_per_hour)
    else:
        out = status(state=ns.state or None)
    print(json.dumps(out, ensure_ascii=False))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())

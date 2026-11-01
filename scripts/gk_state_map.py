#!/usr/bin/env python3
"""gk_state_map.py — state 地图 + 隔离 state 归档（TTL 判据），**只读优先、默认 dry-run**。

为什么需要它（用户 2026-10-31 提问）
=======================================================================
现场有 **1 个 base + 79 个隔离 `.gatekeeper.state.<token>`**，而 CLI 只有一个
`state --clean-isolated [--force]`：**看不见**（无大小/年龄/形态/卫星占用）、**判据粗**
（不区分当前 state / live claim / TTL）、**动作不可逆**（`rm -f`）。
本模块给出一张**可读地图** + 一条**可逆归档**通道：

  · `build_map()`      —— 每个活体 state 一行：形态 / 可写 / 字节 / 年龄 / 相位 / finding 数 /
                          卫星片占用 / 是否当前 state / 是否被 live claim 持有；
  · `reclaim_plan()`   —— **只提建议**（零写盘）：谁满足 TTL 可归档、谁被跳过、为什么；
  · `apply_archive()`  —— 把选中 state **连同旁挂件**整体 `os.replace` 到
                          `<skill>/.trae/state-archive/<utc-ts>/`（可逆：写 `manifest.json` 记原路径），
                          **永不 `rm`** ⟹ 误判也能搬回。

TTL 判据（单源，禁各处自定）
=======================================================================
一个隔离 state **可归档** 当且仅当**全部**成立：
  1. 形态 ∈ `domain` / `legacy_plan`（`base` / `worktree_local` 永不归档 —— 前者是主台账，
     后者属于别的 worktree，不归本仓管）；
  2. **不是**当前 `STATE_FILE`（按 realpath 比，防软链/相对路径绕过）；
  3. 最近修改时间早于 `ttl_days`（默认 7 天；`mtime` 单源，不读业务字段）；
  4. 不被 **live write claim** 覆盖（`gk_write_claims.live()`；台账不可判 ⟹ **fail-closed 全拒**）。
片（`<state>.history-archive.jsonl` 等）随 state 一起搬 —— 它们是该 state 的卫星，不能孤儿化。
"""
import json
import os
import shutil
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

DEFAULT_TTL_DAYS = 7.0
ARCHIVE_REL = os.path.join(".trae", "state-archive")
# 归档对象形态（base 是主台账、worktree_local 属他仓 ⟹ 都不动）
ARCHIVABLE_FORMS = ("domain", "legacy_plan")


def _now_ts() -> float:
    return time.time()


def _read_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:  # noqa: BLE001 — 边界：坏 state 不崩（地图要能显示病灶）
        return {}


def sidecars(state_file: str) -> list:
    """该 state 的旁挂件（`<basename>.<suffix>`；卫星片 / journal / 侧车 / 锁）。

    前缀**带尾点** ⟹ 不会把别的 state（`.gatekeeper.state.<other>`）误收进来。
    """
    d = os.path.dirname(os.path.abspath(state_file)) or "."
    base = os.path.basename(state_file)
    prefix = base + "."
    out = []
    try:
        names = os.listdir(d)
    except OSError:
        return []
    for n in sorted(names):
        if n.startswith(prefix) and os.path.isfile(os.path.join(d, n)):
            out.append(os.path.join(d, n))
    return out


def _live_claim_shards(base: str):
    """被 live write claim 覆盖的**规范化路径**集合；台账不可判 ⟹ `None`（fail-closed）。

    归一单源 = `gk_write_claims._canon`（双宿主 + 相对路径补全 + casefold）—— 本模块不另写
    比较口径，否则「已登记在用」会被判成可归档（误搬 active state）。
    """
    try:
        import gk_write_claims as WC
        lives = WC.live()
    except Exception:  # noqa: BLE001 — 边界：不可判 ⟹ 调用方全拒
        return None
    canon = getattr(WC, "_canon", lambda p, b="": os.path.realpath(p).replace("\\", "/").lower())
    out = set()
    for c in lives:
        for p in (c.get("paths") or []):
            try:
                out.add(canon(str(p), base))
            except Exception:  # noqa: BLE001 — 边界：单条坏路径不废整张台账
                continue
    return out


def _norm(p: str) -> str:
    return os.path.realpath(os.path.abspath(p))


def _claim_state(state_file: str, claims, base: str) -> bool:
    """state 本体或其任一旁挂件被 live claim 覆盖 ⟹ True（视为在用）。"""
    if claims is None:
        return True   # fail-closed：台账不可判时一律当「在用」
    try:
        import gk_write_claims as WC
        canon = getattr(WC, "_canon", lambda p, b="": _norm(p).replace("\\", "/").lower())
    except Exception:  # noqa: BLE001
        canon = lambda p, b="": _norm(p).replace("\\", "/").lower()  # noqa: E731
    for p in [state_file] + sidecars(state_file):
        try:
            if canon(p, base) in claims:
                return True
        except Exception:  # noqa: BLE001
            continue
    return False


def build_map(skill_dir: str, current: str = "", ttl_days: float = DEFAULT_TTL_DAYS,
              now: float = None, extra_roots=None) -> dict:
    """只读地图：`{ok, summary, states[]}`（零写盘）。"""
    import gk_state_forms as GSF
    import gk_satellite as SAT
    now = _now_ts() if now is None else float(now)
    cur = _norm(current) if current else ""
    roots = list(extra_roots or [])
    try:
        roots = roots or GSF.worktree_state_roots(skill_dir)
    except Exception:  # noqa: BLE001 — 边界：worktree 根探测失败不阻断地图
        roots = []
    claims = _live_claim_shards(skill_dir)
    states, summary = [], {"base": 0, "domain": 0, "legacy_plan": 0,
                           "worktree_local": 0, "bytes": 0, "sidecar_bytes": 0,
                           "open_findings": 0, "archivable": 0}
    for p in GSF.iter_live_states(skill_dir, extra_roots=roots):
        form = GSF.state_form(p, skill_root=skill_dir)
        try:
            size = os.path.getsize(p)
            mtime = os.path.getmtime(p)
        except OSError:
            size, mtime = 0, 0.0
        data = _read_json(p)
        gd = data.get("gate_data") or {}
        findings = gd.get("ecc_findings") or []
        opens = [f for f in findings if isinstance(f, dict)
                 and f.get("status") in ("open", "rejected")]
        sc = sidecars(p)
        sc_bytes = sum((os.path.getsize(x) for x in sc if os.path.isfile(x)), 0)
        sat = {s["kind"]: s["bytes"] for s in SAT.shards(p) if s["exists"]}
        is_cur = bool(cur) and _norm(p) == cur
        age_days = round((now - mtime) / 86400.0, 2) if mtime else None
        row = {
            "path": p, "name": os.path.basename(p), "form": form,
            "writable": form in GSF.WRITABLE_FORMS,
            "current": is_cur,
            "bytes": size, "mtime": mtime, "age_days": age_days,
            "r_phase": data.get("r_phase"), "stage": data.get("stage"),
            "project_type": data.get("project_type"),
            "findings": len(findings), "open_findings": len(opens),
            "sidecars": [os.path.basename(x) for x in sc],
            "sidecar_bytes": sc_bytes, "satellites": sat,
            "claimed": _claim_state(p, claims, skill_dir),
        }
        row["archivable"], row["reclaim_reason"] = _verdict(row, ttl_days)
        states.append(row)
        summary[form] = summary.get(form, 0) + 1
        summary["bytes"] += size
        summary["sidecar_bytes"] += sc_bytes
        summary["open_findings"] += len(opens)
        summary["archivable"] += 1 if row["archivable"] else 0
    summary["states"] = len(states)
    return {"ok": True, "ttl_days": ttl_days, "summary": summary, "states": states}


def _verdict(row: dict, ttl_days: float) -> tuple:
    """单行归档裁决 → (是否可归档, 具名理由)。**单源**：地图与归档计划共用本函数。"""
    if row["form"] not in ARCHIVABLE_FORMS:
        return False, "形态 %s 不在可归档集（只动 %s）" % (
            row["form"], "/".join(ARCHIVABLE_FORMS))
    if row["current"]:
        return False, "当前活动 state（禁归档）"
    if row["claimed"]:
        return False, "被 live write claim 覆盖（在用）"
    age = row.get("age_days")
    if age is None:
        return False, "mtime 不可读"
    if age < ttl_days:
        return False, "未过 TTL（%.2f 天 < %.2f 天）" % (age, ttl_days)
    return True, "过 TTL（%.2f 天）且非当前、无 live claim" % age


def reclaim_plan(skill_dir: str, current: str = "", ttl_days: float = DEFAULT_TTL_DAYS,
                 now: float = None) -> dict:
    """归档计划（**零写盘**）：`{ok, ttl_days, plan[], skipped[]}`。"""
    m = build_map(skill_dir, current=current, ttl_days=ttl_days, now=now)
    plan, skipped = [], []
    for r in m["states"]:
        if r["archivable"]:
            plan.append({"path": r["path"], "age_days": r["age_days"],
                         "bytes": r["bytes"], "sidecars": r["sidecars"],
                         "reason": r["reclaim_reason"]})
        elif r["form"] in ARCHIVABLE_FORMS:
            skipped.append({"path": r["path"], "reason": r["reclaim_reason"]})
    return {"ok": True, "ttl_days": ttl_days, "plan": plan, "skipped": skipped,
            "plan_bytes": sum(x["bytes"] for x in plan)}


def apply_archive(skill_dir: str, current: str = "",
                  ttl_days: float = DEFAULT_TTL_DAYS, now: float = None,
                  dry_run: bool = True, only: list = None) -> dict:
    """把计划内 state **连同旁挂件**搬到 `<skill>/.trae/state-archive/<utc-ts>/`。

    **可逆**：只 `os.replace` 移动（不 `rm`），并写 `manifest.json` 记 `src → dst`；
    同批次内任一文件移动失败 ⟹ 该 state 记 `failed`（已移动的保留，manifest 逐条如实记）。
    `dry_run=True`（缺省）⟹ 只返回计划，零写盘。
    """
    p = reclaim_plan(skill_dir, current=current, ttl_days=ttl_days, now=now)
    if only:
        want = {_norm(x) for x in only}
        p["plan"] = [x for x in p["plan"] if _norm(x["path"]) in want]
    if dry_run or not p["plan"]:
        return dict(p, dry_run=True, applied=0)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest_root = os.path.join(skill_dir, ARCHIVE_REL, stamp)
    os.makedirs(dest_root, exist_ok=True)
    moves, applied = [], 0
    for item in p["plan"]:
        src = item["path"]
        if current and _norm(src) == _norm(current):
            continue   # 双保险（计划阶段已排除）
        files = [src] + [os.path.join(os.path.dirname(src), s) for s in item["sidecars"]]
        state_ok = True
        for f in files:
            if not os.path.isfile(f):
                continue
            dst = os.path.join(dest_root, os.path.basename(f))
            try:
                os.replace(f, dst)
            except OSError as e:  # noqa: BLE001 — 边界：跨设备/权限 ⟹ 回落 copy+unlink
                try:
                    shutil.copy2(f, dst)
                    os.unlink(f)
                except OSError as e2:  # noqa: BLE001
                    state_ok = False
                    moves.append({"src": f, "dst": "", "ok": False,
                                  "error": "%s / %s" % (e, e2)})
                    continue
            moves.append({"src": f, "dst": dst, "ok": True})
        if state_ok:
            applied += 1
    manifest = {"ts": stamp, "skill_dir": skill_dir, "ttl_days": ttl_days,
                "moves": moves, "note": "可逆归档：把 dst 的 basename 搬回 src 即恢复"}
    with open(os.path.join(dest_root, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    return {"ok": True, "dry_run": False, "applied": applied, "dest": dest_root,
            "moves": len(moves), "failed": [m for m in moves if not m["ok"]]}


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="state 地图 / 隔离 state 归档（默认 dry-run）")
    ap.add_argument("cmd", nargs="?", default="reclaim", choices=("map", "reclaim"),
                    help="map = 只读地图；reclaim = 归档计划（缺省 dry-run）")
    ap.add_argument("--skill-dir", default="")
    ap.add_argument("--current", default="")
    ap.add_argument("--ttl-days", type=float, default=DEFAULT_TTL_DAYS)
    ap.add_argument("--apply", action="store_true", help="真正移动（缺省只出计划）")
    a = ap.parse_args(argv)
    root = a.skill_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if a.cmd == "map":
        print(json.dumps(build_map(root, current=a.current, ttl_days=a.ttl_days),
                         ensure_ascii=False))
    else:
        print(json.dumps(apply_archive(root, current=a.current, ttl_days=a.ttl_days,
                                       dry_run=not a.apply), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""gk_bench_compare.py — benchmark 版本基线对比（S5 / M5）。

口径：
  · **基线** = 上一版本的 full/quick 结果 + 环境指纹（`gk-bench-baseline/v1`）；
  · **当前** = 本轮 quick（CI）或 full（夜间）的三份 JSON；
  · **回归判定**（ratio ≤ `--tolerance`，缺省 1.25）：state 写放大 / p99、卫星写放大、
    gate 写放大；基线里为 `null` 的指标（如 read 的 write_amp）跳过；
  · **硬失败**：任一场景 `success_ops < total_ops`、崩溃 `checksum_ok` 不全、`tmp_left > 0`；
  · 发布门 wall（doc-release / security-lint）缺省只 **WARN**（CI 抖动大），
    `--strict-release` 才升为失败。
  · 新增场景没有基线 ⟹ WARN（不阻断），避免新基准一上来就红。

用法：
  python3 scripts/gk_bench_compare.py --baseline references/bench-baseline.json \
      --state cur-state.json --satellite cur-sat.json --gate cur-gate.json \
      --release cur-rel.json --json
  python3 scripts/gk_bench_compare.py --init-baseline references/bench-baseline.json \
      --state full-state.json --satellite full-sat.json --gate full-gate.json \
      --release rel.json
"""
import argparse
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _env() -> dict:
    return {"os": platform.platform(), "python": platform.python_version(),
            "machine": platform.machine(), "cpu_count": os.cpu_count()}


def _git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True,
                                       stderr=subprocess.DEVNULL).strip()
    except Exception:                       # noqa: BLE001 — 非 git 环境
        return ""


# 2026-11-08（owner 裁定「性能掉了要能区分原因」）：机制模块 —— 改动它们会直接改变
#   bench 探针测到的物理行为（写路径/锁/卫星/claim），是「机制变化」的判据面。
_MECH_MODULES = (
    "scripts/gk_json_utils.py", "scripts/gk_state.py", "scripts/gk_satellite.py",
    "scripts/gk_state_patch.py", "scripts/gk_write_claims.py", "gatekeeper-cli.sh",
)


def _changed_since(base_head: str, repo: str = ".") -> list:
    """基线 commit → HEAD 改过的文件（无基线/无 git ⟹ 空）。"""
    if not base_head:
        return []
    try:
        out = subprocess.check_output(
            ["git", "-C", repo, "diff", "--name-only", "%s..HEAD" % base_head],
            text=True, stderr=subprocess.DEVNULL)
    except Exception:                       # noqa: BLE001 — 非 git / 基线不可达
        return []
    return [x.strip() for x in out.splitlines() if x.strip()]


def _has_amp_state(bench: dict) -> bool:
    for s in (((bench or {}).get("state") or {}).get("scenarios") or []):
        if "amp_per_state" in s:
            return True
    return False


def _commits_since(base_head: str, repo: str = ".") -> int:
    """基线 commit 到 HEAD 的提交数（无基线/无 git ⟹ 0）。"""
    if not base_head:
        return 0
    try:
        out = subprocess.check_output(
            ["git", "-C", repo, "rev-list", "--count", "%s..HEAD" % base_head],
            text=True, stderr=subprocess.DEVNULL)
        return int(out.strip() or 0)
    except Exception:                       # noqa: BLE001 — 基线不可达
        return 0


def diagnose(res: dict, baseline: dict, current: dict, repo: str = ".") -> dict:
    """把 violations 归因成三类（2026-11-08，owner 裁定）。

    · `probe_mismatch`：两侧**口径字段**不同（如 `amp_per_state` 只在一侧存在）⟹ ratio 不可比，
      先统一口径再判回归（治「新机制与测试不匹配」）。
    · `mechanism_change`：基线以来**机制模块**有改动 ⟹ 先确认是否为有意变更；有意则重采基线。
    · `regression`：机制未变 + 口径一致 + 仍超阈 ⟹ 真退化（未优化/写放大回退），须定位。
    """
    base_head = (baseline or {}).get("git_head", "")
    changed = _changed_since(base_head, repo)
    mech = [m for m in _MECH_MODULES if m in changed]
    bb = ((baseline or {}).get("benchmarks") or {})
    cb = ((current or {}).get("benchmarks") or current or {})
    amp_state_mismatch = _has_amp_state(bb) != _has_amp_state(cb)
    items = []
    for v in res.get("violations", []):
        metric = str(v.get("metric", ""))
        if metric.startswith("state.write_amp") and amp_state_mismatch:
            kind = "probe_mismatch"
            hint = ("两侧写放大口径字段不一致（`amp_per_state` 仅一侧存在）⟹ 该 ratio 不可比；"
                    "先统一 bench 口径（或重采基线）再判回归")
        elif mech:
            kind = "mechanism_change"
            hint = ("基线以来机制模块有改动（%s）⟹ 先核对变更是否有意；有意则重采基线，"
                    "无意即为回归" % ", ".join(mech))
        else:
            kind = "regression"
            hint = "机制未变且口径一致 ⟹ 判为性能退化，须定位到具体写路径"
        items.append(dict(v, kind=kind, hint=hint))
    counts = {}
    for it in items:
        counts[it["kind"]] = counts.get(it["kind"], 0) + 1
    return {"baseline_head": base_head, "changed_modules": mech,
            "probe_mismatch": amp_state_mismatch,
            "items": items, "counts": counts}



def _ratio(label: str, scenario: str, base, cur, tol: float, res: dict,
           soft: bool = False) -> None:
    if base in (None, 0) or cur is None:
        return
    if float(cur) > float(base) * float(tol):
        item = {
            "metric": label, "scenario": scenario,
            "baseline": base, "current": cur,
            "detail": "%.2fx > %.2fx（baseline × %.2f）"
                      % (float(cur) / float(base), float(tol), float(tol)),
        }
        (res["warnings"] if soft else res["violations"]).append(item)


def compare(baseline: dict, current: dict, tolerance: float = 1.25,
            strict_release: bool = False, only=None, no_ratio: bool = False) -> dict:
    res = {"ok": True, "tolerance": tolerance, "violations": [], "warnings": []}
    bb = (baseline or {}).get("benchmarks") or {}
    sections = set(only) if only else {"state", "satellite", "gate", "release"}

    # state：写放大 / p99 / 失败数 / 崩溃残留
    if "state" in sections:
        bs = ((bb.get("state") or {}).get("scenarios") or [])
        cs = ((current.get("state") or {}).get("scenarios") or [])
        cur_state = {s.get("scenario"): s for s in cs if s.get("scenario")}
        for b in bs:
            name = b.get("scenario")
            c = cur_state.get(name)
            if not c:
                res["violations"].append({"metric": "state.scenario", "scenario": name,
                                          "detail": "当前结果缺该场景"})
                continue
            _ratio("state.write_amp", name, b.get("write_amp"), c.get("write_amp"),
                   tolerance, res, no_ratio)
            _ratio("state.p99_ms", name, b.get("p99_ms"), c.get("p99_ms"),
                   tolerance, res, no_ratio)
            if int(c.get("success_ops", 0) or 0) < int(c.get("total_ops", 0) or 0):
                res["violations"].append({
                    "metric": "state.failed", "scenario": name,
                    "current": int(c.get("total_ops", 0) or 0) - int(c.get("success_ops", 0) or 0),
                    "detail": "存在失败写（应 0）"})
        crash = (current.get("state") or {}).get("crash") or []
        if crash:
            bad_ck = [x for x in crash if not x.get("checksum_ok")]
            residue = sum(int(x.get("tmp_left") or 0) for x in crash)
            if bad_ck:
                res["violations"].append({"metric": "state.crash.checksum",
                                          "current": len(bad_ck),
                                          "detail": "崩溃后 checksum 不完整"})
            if residue:
                res["violations"].append({"metric": "state.crash.tmp_left",
                                          "current": residue,
                                          "detail": "崩溃后 .tmp 永久残留 > 0"})

    # satellite / gate：写放大 + ok
    for key, label in (("satellite", "satellite.write_amp"),
                       ("gate", "gate.write_amp")):
        if key not in sections:
            continue
        bmap = {s.get("scenario"): s
                for s in ((bb.get(key) or {}).get("scenarios") or [])
                if s.get("scenario")}
        for c in ((current.get(key) or {}).get("scenarios") or []):
            name = c.get("scenario")
            if not c.get("ok", True):
                res["violations"].append({"metric": label + ".ok", "scenario": name,
                                          "detail": "场景自身失败"})
            if name not in bmap:
                res["warnings"].append({"metric": label, "scenario": name,
                                        "detail": "无基线（新增场景）"})
                continue
            _ratio(label, name, bmap[name].get("write_amp"), c.get("write_amp"),
                   tolerance, res, no_ratio)

    # release：发布门 wall 只 WARN（CI 抖动），--strict-release 才判红
    if "release" in sections:
        bres = {r.get("name"): r
                for r in ((bb.get("release") or {}).get("results") or [])}
        for c in ((current.get("release") or {}).get("results") or []):
            name = c.get("name")
            b = bres.get(name)
            if not b:
                res["warnings"].append({"metric": "release", "scenario": name,
                                        "detail": "无基线"})
                continue
            if float(c.get("wall_s") or 0) > float(b.get("wall_s") or 0) * tolerance:
                item = {"metric": "release.wall_s", "scenario": name,
                        "baseline": b.get("wall_s"), "current": c.get("wall_s"),
                        "detail": "超出容差 %.2f" % tolerance}
                (res["violations"] if strict_release else res["warnings"]).append(item)

    # state/satellite/gate 顶层 ok
    for key in ("state", "satellite", "gate"):
        if key not in sections:
            continue
        cur = current.get(key) or {}
        if cur and not cur.get("ok", True):
            res["violations"].append({"metric": key + ".ok", "detail": "报告 ok=false"})

    # 2026-11-08（owner 裁定「旧 benchmark 隔几个版本要评估是否过时」）：
    #   基线年龄 = `git_head` 到 HEAD 的提交数；超过 `stale_after_commits`（基线字段，
    #   缺省 150）⟹ WARN 建议重采。只提示、不阻断：过时 ≠ 结果错，但对比意义在衰减。
    base_head = (baseline or {}).get("git_head", "")
    age = _commits_since(base_head)
    limit = int((baseline or {}).get("stale_after_commits", 150) or 150)
    if age and age > limit:
        res["warnings"].append({
            "metric": "baseline.stale", "baseline": limit, "current": age,
            "detail": "基线已落后 %d 个提交（阈值 %d）⟹ 建议重采："
                      "`gk_bench_compare.py --init-baseline references/bench-baseline.json ...`"
                      % (age, limit)})

    res["ok"] = not res["violations"]
    return res


def _sanitize(obj):
    """去掉本地运行目录（`state_dir`/`source_dir`）：基线会随公开包导出，禁带本机路径。"""
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items()
                if k not in ("state_dir", "source_dir")}
    if isinstance(obj, list):
        return [_sanitize(v) for v in obj]
    return obj


def _write_baseline(path: str, current: dict) -> dict:
    base = {
        "schema": "gk-bench-baseline/v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "git_head": _git_head(),
        "environment": _env(),
        "benchmarks": {k: _sanitize(current.get(k))
                       for k in ("state", "satellite", "gate", "release")
                       if current.get(k) is not None},
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(base, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return base


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_bench_compare.py")
    ap.add_argument("--baseline", default="references/bench-baseline.json")
    ap.add_argument("--state", default="")
    ap.add_argument("--satellite", default="")
    ap.add_argument("--gate", default="")
    ap.add_argument("--release", default="")
    ap.add_argument("--init-baseline", default="",
                    help="用当前结果写基线（不比对）")
    ap.add_argument("--tolerance", type=float, default=1.25)
    ap.add_argument("--strict-release", action="store_true")
    ap.add_argument("--only", default="",
                    help="只比对这些段（逗号分隔：state,satellite,gate,release）")
    ap.add_argument("--no-ratio", action="store_true",
                    help="跨环境运行时把 ratio 降级为 WARN（硬失败仍判红）")
    ap.add_argument("--diagnose", action="store_true",
                    help="对超阈项归因：probe_mismatch（口径不匹配）/ mechanism_change / regression")
    ap.add_argument("--json", action="store_true")
    ns = ap.parse_args(argv)

    current = {}
    for key in ("state", "satellite", "gate", "release"):
        p = getattr(ns, key)
        if p:
            current[key] = _load(p)

    if ns.init_baseline:
        if not current:
            print("没有任何 --state/--satellite/--gate/--release 输入", file=sys.stderr)
            return 2
        base = _write_baseline(ns.init_baseline, current)
        out = {"ok": True, "baseline": ns.init_baseline,
               "benchmarks": sorted(base["benchmarks"])}
        print(json.dumps(out, ensure_ascii=False, indent=2) if ns.json else
              "OK baseline=%s (%s)" % (ns.init_baseline, ", ".join(out["benchmarks"])))
        return 0

    if not os.path.isfile(ns.baseline):
        print("基线不存在: %s（先 --init-baseline）" % ns.baseline, file=sys.stderr)
        return 2
    only = [x.strip() for x in str(ns.only).split(",") if x.strip()] or None
    baseline = _load(ns.baseline)
    res = compare(baseline, current, ns.tolerance, ns.strict_release,
                  only=only, no_ratio=ns.no_ratio)
    if ns.diagnose:
        res["diagnosis"] = diagnose(res, baseline, current)
    if ns.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print("ok=%s violations=%d warnings=%d"
              % (res["ok"], len(res["violations"]), len(res["warnings"])))
        for v in res["violations"]:
            print("  FAIL %s %s: %s" % (v.get("metric"), v.get("scenario", ""),
                                        v.get("detail", "")))
        for w in res["warnings"]:
            print("  WARN %s %s: %s" % (w.get("metric"), w.get("scenario", ""),
                                        w.get("detail", "")))
        dg = res.get("diagnosis") or {}
        for it in dg.get("items", []):
            print("  [%s] %s %s — %s" % (it.get("kind"), it.get("metric"),
                                          it.get("scenario", ""), it.get("hint", "")))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

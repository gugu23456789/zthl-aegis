#!/usr/bin/env python3
"""判据5「判定式载体」—— OPCAP 基线四环（写 / 读 / 比对 / 阈值），2026-10-27。

缺口（审计署 §23.2 / §26.4）：`gk_opcap_export` 只产**读数**；基线本体与判定式**零实现**
（`x4` 已随上游 v47/v48 删除、`x3` 零载体）⟹ 判据5 无法机检、**禁判 PASS**。

本模块只落**载体**，不造合成基线：
  · **写** `write()`：现场 `gk_opcap_export.export()` + 独立基线 sidecar + Ed25519 封印 + D3a 链；
  · **读** `read()`：真验签 + 链校验（`require_chain` 可严格）；
  · **比对** `compare()`：逐轴 `x3` / `x4` / `x8` ⟹ `ok | regressed | unavailable`；
  · **阈值** `finalize()` / `gate()`：**FAIL > INCOMPLETE > PASS**。

硬纪律：
  · 缺载体轴（`x3` no_carrier / `x4` removed_upstream）与样本不足（< 20）一律 `INCOMPLETE`；
  · 任何恶化（x8 中位超出容差、x3/x4 数值上升）⟹ `FAIL`；
  · **只读 state**：除基线 sidecar（+ 封印/链）外不写任何文件。
"""
import argparse
import datetime
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import gk_budget_ledger as B  # noqa: E402 — 封印 + D3a 链单源
import gk_opcap_export as OP  # noqa: E402 — 读数单源

SCHEMA = "opcap-baseline-1"
MIN_SAMPLES = 20          # §26.4：基线本体需 ≥20 真实样本；不足只落载体、不判 PASS
AXES = ("x3", "x4", "x8")
EPS = 1e-9


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def baseline_path(state_file: str) -> str:
    return str(state_file) + ".opcap-baseline.json"


def _x3_metric() -> dict:
    # x3 = acknowledge-injected 计数（门禁绕行率）：唯一留痕是 credit-ledger 的 `exempt` 行，
    #   但 opcap §1 禁把额度事件直接当 OPCAP 评分，且「计数 vs 率」分母未裁 ⟹ 不造载体。
    return {"status": "no_carrier", "value": None, "unit": "count",
            "note": "only trace = credit-ledger exempt rows; unit (count vs rate) unresolved"}


def _x4_metric() -> dict:
    # x4 = override 率：上游 v47/v48 已删除 `x4_override()`，改报零事件上界；
    #   本仓无「机会数」载体 ⟹ 只登记状态，不计算。
    return {"status": "removed_upstream", "value": None, "unit": "rate",
            "note": "removed in upstream v47/v48; zero-event upper bound needs opportunity counts"}


def metrics_from_export(snap: dict) -> dict:
    """把 `gk_opcap_export.export()` 的快照折成**判据5 三轴**形状。"""
    x8 = (snap or {}).get("x8_register_to_close") or {}
    med = x8.get("median_hours")
    return {
        "x3": _x3_metric(),
        "x4": _x4_metric(),
        "x8": {"status": "available" if med is not None else "no_data",
               "median_hours": med, "max_hours": x8.get("max_hours"),
               "n_closed": x8.get("n_closed")},
    }


def _samples(snap: dict) -> dict:
    lo = (snap or {}).get("loans") or {}
    x8 = (snap or {}).get("x8_register_to_close") or {}
    return {"closed_findings": int(x8.get("n_closed") or 0),
            "loans": int(lo.get("n") or 0)}


def write(state_file: str, out: str = "", key_dir: str = "", reason: str = "") -> dict:
    """**写环**：现场导出 ⟹ 基线 sidecar + 封印 + 链。"""
    snap = OP.export(state_file)
    if not snap.get("ok"):
        return {"ok": False, "error": snap.get("error") or "export_failed"}
    out = out or baseline_path(state_file)
    samples = _samples(snap)
    weak = samples["closed_findings"] < MIN_SAMPLES or samples["loans"] < MIN_SAMPLES
    rec = {"schema": SCHEMA, "created_at": _now(), "source_state": str(state_file),
           "metrics": metrics_from_export(snap), "samples": samples,
           "weak": weak, "min_samples": MIN_SAMPLES, "reason": str(reason or "")[:200]}
    raw = (json.dumps(rec, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    try:
        Path(out).write_bytes(raw)
    except OSError as e:
        return {"ok": False, "error": "write_failed: %s" % e}
    seal, err = B._seal_with_chain(Path(str(out) + ".seal"), raw, key_dir)
    if err:
        return {"ok": False, "error": err}
    return {"ok": True, "baseline": out, "record": rec,
            "seal": {"mode": seal.get("mode"), "sha256": seal.get("sha256"),
                     "seq": seal.get("seq")}}


def read(path: str, key_dir: str = "", require_chain: bool = False) -> dict:
    """**读环**：真验签 + 链校验。缺文件 ⟹ `baseline_missing`（禁默认放行）。"""
    p = Path(path)
    if not p.exists():
        return {"ok": False, "error": "baseline_missing"}
    ver = B.verify_seal_at(p, Path(str(p) + ".seal"), key_dir, require_chain=require_chain)
    if not ver.get("ok"):
        return {"ok": False, "error": "seal:%s" % ver.get("reason")}
    try:
        rec = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return {"ok": False, "error": "unreadable: %s" % e}
    if not isinstance(rec, dict) or rec.get("schema") != SCHEMA or not isinstance(rec.get("metrics"), dict):
        return {"ok": False, "error": "invalid_baseline"}
    return {"ok": True, "record": rec, "seal": ver}


def _axis_cmp(name: str, b: dict, c: dict) -> dict:
    bs, cs = (b or {}).get("status"), (c or {}).get("status")
    if name in ("x3", "x4"):
        if bs == "available" and cs == "available":
            bv, cv = b.get("value"), c.get("value")
            if isinstance(bv, (int, float)) and isinstance(cv, (int, float)):
                return {"status": "regressed" if cv > bv + EPS else "ok",
                        "baseline": bv, "current": cv, "comparable": True}
        return {"status": cs or bs or "unavailable", "comparable": False}
    # x8：中位时延（相对容差）
    if bs == "available" and cs == "available":
        bm, cm = b.get("median_hours"), c.get("median_hours")
        if isinstance(bm, (int, float)) and isinstance(cm, (int, float)):
            limit = bm * (1.0 + float(b.get("_x8_rel_tol") or 0.0)) + EPS
            return {"status": "regressed" if cm > limit else "ok",
                    "baseline": bm, "current": cm, "comparable": True}
    return {"status": "unavailable", "comparable": False}


def compare(base_metrics: dict, cur_metrics: dict, *, x8_rel_tol: float = 0.0) -> dict:
    """**比对环**（纯函数）：逐轴给 `ok | regressed | unavailable` + 总判决。"""
    axes = {}
    b8 = dict((base_metrics or {}).get("x8") or {})
    b8["_x8_rel_tol"] = x8_rel_tol
    for name in AXES:
        src = b8 if name == "x8" else (base_metrics or {}).get(name)
        axes[name] = _axis_cmp(name, src, (cur_metrics or {}).get(name))
    reasons = ["%s:%s" % (n, a["status"]) for n, a in axes.items() if a["status"] != "ok"]
    if any(a["status"] == "regressed" for a in axes.values()):
        verdict = "FAIL"
    elif any(a["status"] != "ok" for a in axes.values()):
        verdict = "INCOMPLETE"
    else:
        verdict = "PASS"
    return {"verdict": verdict, "axes": axes, "reasons": reasons}


def finalize(cmp_verdict: str, weak: bool) -> str:
    """**阈值环**：FAIL > INCOMPLETE > PASS；样本弱 ⟹ 永不放行。"""
    if cmp_verdict == "FAIL":
        return "FAIL"
    if cmp_verdict == "INCOMPLETE" or weak:
        return "INCOMPLETE"
    return "PASS"


def gate(state_file: str, baseline: str, key_dir: str = "",
         x8_rel_tol: float = 0.0, current: dict = None) -> dict:
    """端到端判决：读基线 → 现场导出（或注入）→ 比对 → 阈值。"""
    b = read(baseline, key_dir=key_dir)
    if not b.get("ok"):
        return {"ok": False, "error": b.get("error")}
    if current is None:
        snap = OP.export(state_file)
        if not snap.get("ok"):
            return {"ok": False, "error": snap.get("error") or "export_failed"}
        current = metrics_from_export(snap)
    cmp = compare(b["record"].get("metrics") or {}, current, x8_rel_tol=x8_rel_tol)
    weak = bool(b["record"].get("weak"))
    reasons = list(cmp["reasons"]) + (["insufficient_samples"] if weak else [])
    return {"ok": True, "verdict": finalize(cmp["verdict"], weak),
            "axes": cmp["axes"], "reasons": reasons,
            "baseline": baseline, "x8_rel_tol": x8_rel_tol,
            "samples": b["record"].get("samples")}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_opcap_baseline.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("write")
    w.add_argument("--state", required=True)
    w.add_argument("--out", default="")
    w.add_argument("--key-dir", default="")
    w.add_argument("--reason", default="")
    r = sub.add_parser("read")
    r.add_argument("--baseline", required=True)
    r.add_argument("--key-dir", default="")
    r.add_argument("--require-chain", action="store_true")
    g = sub.add_parser("gate")
    g.add_argument("--state", required=True)
    g.add_argument("--baseline", required=True)
    g.add_argument("--key-dir", default="")
    g.add_argument("--x8-rel-tol", type=float, default=0.0)
    ns = ap.parse_args(argv)
    if ns.cmd == "write":
        out = write(ns.state, out=ns.out, key_dir=ns.key_dir, reason=ns.reason)
    elif ns.cmd == "read":
        out = read(ns.baseline, key_dir=ns.key_dir, require_chain=ns.require_chain)
    else:
        out = gate(ns.state, ns.baseline, key_dir=ns.key_dir, x8_rel_tol=ns.x8_rel_tol)
    print(json.dumps(out, ensure_ascii=False))
    if not out.get("ok"):
        return 1
    return 1 if out.get("verdict") == "FAIL" else 0


if __name__ == "__main__":
    sys.exit(main())

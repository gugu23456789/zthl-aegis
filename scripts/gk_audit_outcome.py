#!/usr/bin/env python3
"""gk_audit_outcome.py — 审计署 `outcome` producer（交付门 D2 骨架，2026-10-21）。

缺口（D2 立项时点）：`gk_credit_ledger.append` 会校验 outcome 三参数（判据4a）并封印，但
**没有生产者** —— 无人把待审 `raise` 变成 `success` / `fail` / `overspend`。

本模块 = 生产端骨架（**决策后端可替换**，默认本地 StartLux-Decision `/v1/systemone`）：

  raise 行（credit-ledger）
      └─> typed choice 问题（三选项 = `OUTCOME_KINDS`，带 criteria）
            └─> `POST <endpoint>/v1/systemone`（`think_mode` 透传 = AutoThink 自适应思考）
                  └─> 解析 `answers.outcome.choice` + `confidence` + `probabilities`
                        └─> `gk_credit_ledger.append(kind=choice, ref=raise_id,
                              model_version / temperature / seed, key_dir)` + 真验签

**fail-closed（禁默造 outcome）**：raise 不存在 / 非 raise 行 / 后端不可达 / 决策不在三态 /
模型版本不可判 ⟹ 一律**不写账本**，返回 `ok:false` + 可判 `error` 前缀。

**三参数口径**：`temperature` = 采样温度（本协议不采样，固定 0.0；模型内部的 calibration
temperature 属于模型/协议版本，随 `model_version` 一起留痕）；`seed` = 固定 0（无采样，
保留字段以满足判据4a 的离线复算三元组）。

CLI::

  python3 gk_audit_outcome.py produce --state <state> --raise-id <id> \
      --endpoint http://127.0.0.1:8090 [--think-mode auto] [--temperature 0.0] \
      [--seed 0] [--model-version <v>] [--key-dir <dir>] [--dry-run]
"""
import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import gk_credit_ledger as CL  # noqa: E402

PRODUCER = "gk_audit_outcome/1"
QUESTION_ID = "outcome"
CRITERIA = {
    "success": "the audited change landed and its declared verification passed",
    "fail": "the audited change failed, was reverted, or its verification did not pass",
    "overspend": "the audited change exceeded its declared edit/credit budget",
}
THINK_MODES = ("auto", "never", "always", "hybrid", "plain", "think")
DEFAULT_TEMPERATURE = 0.0
DEFAULT_SEED = 0


class BackendError(RuntimeError):
    """后端不可达 / 非 JSON / 缺答案 —— 一律 fail-closed。"""


def build_request(raise_rec, think_mode="auto"):
    """构造 `/v1/systemone` 的 typed choice 请求（单一事实源：`OUTCOME_KINDS`）。"""
    return {
        "state": {"raise": raise_rec},
        "questions": {
            QUESTION_ID: {
                "type": "choice",
                "instructions": ("Classify what the audit evidence shows about this raise "
                                 "(a budget increase request recorded in the credit ledger)."),
                "criteria": dict(CRITERIA),
            }
        },
        "think_mode": think_mode,
        "return_details": True,
    }


def _post_json(url, payload, timeout=30):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", "replace")[:500]
        except OSError:
            detail = ""
        raise BackendError("http_%s: %s" % (e.code, detail))
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise BackendError(str(e))
    try:
        return json.loads(raw)
    except ValueError as e:
        raise BackendError("invalid_json: %s" % e)


def probe(endpoint, timeout=5.0):
    """读 `/health`：`kind` = `instant` / `autothink`（Instant 拒绝 `think_mode=auto`）。"""
    url = str(endpoint).rstrip("/") + "/health"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {"ok": False, "error": "backend_error: %s" % e}
    return {"ok": True, "kind": str(data.get("kind") or ""),
            "model": str(data.get("model") or ""), "health": data}


def parse_response(payload):
    """→ `{ok, decision, confidence, probabilities, thought}` 或 `{ok:false,error}`。"""
    answers = payload.get("answers") if isinstance(payload, dict) else None
    ans = answers.get(QUESTION_ID) if isinstance(answers, dict) else None
    if not isinstance(ans, dict):
        return {"ok": False, "error": "backend_error: missing_answer"}
    decision = ans.get("choice")
    if decision not in CL.OUTCOME_KINDS:
        return {"ok": False, "error": "invalid_decision: %r" % (decision,)}
    try:
        conf = float(ans.get("confidence") or 0.0)
    except (TypeError, ValueError):
        conf = 0.0
    probs = ans.get("probabilities")
    details = ans.get("details") if isinstance(ans.get("details"), dict) else {}
    thought = details.get("thought") if isinstance(details.get("thought"), dict) else {}
    return {"ok": True, "decision": decision, "confidence": conf,
            "probabilities": probs if isinstance(probs, dict) else {},
            "thought": thought}


def produce(state_file, raise_id, *, endpoint, key_dir="", think_mode="auto",
            temperature=DEFAULT_TEMPERATURE, seed=DEFAULT_SEED, model_version="",
            dry_run=False, timeout=30):
    """把一条 `raise` 交给决策后端分类，并（非 dry-run 时）落 outcome 行 + 真验签。"""
    if not state_file:
        return {"ok": False, "error": "no_state_file"}
    if think_mode not in THINK_MODES:
        return {"ok": False, "error": "invalid_think_mode: %r" % (think_mode,)}
    recs, _ = CL.read_records(state_file)
    target = next((r for r in recs if str(r.get("id")) == str(raise_id)), None)
    if target is None:
        return {"ok": False, "error": "raise_not_found: %r" % (raise_id,)}
    if target.get("kind") != "raise":
        return {"ok": False, "error": "not_a_raise: kind=%r" % (target.get("kind"),)}
    request = build_request(target, think_mode)
    url = str(endpoint).rstrip("/") + "/v1/systemone"
    try:
        resp = _post_json(url, request, timeout=timeout)
    except BackendError as e:
        return {"ok": False, "error": "backend_error: %s" % e}
    parsed = parse_response(resp)
    if not parsed["ok"]:
        return parsed
    mv = (str(model_version or "") or str(resp.get("model") or "")).strip()
    if not mv:
        return {"ok": False, "error": "model_version_unknown"}
    try:
        temp = float(temperature)
        sd = int(seed)
    except (TypeError, ValueError):
        return {"ok": False, "error": "invalid_model_params"}
    reason = "systemone choice=%s conf=%.4f p=%s" % (
        parsed["decision"], parsed["confidence"],
        json.dumps(parsed["probabilities"], sort_keys=True))
    if dry_run:
        return {"ok": True, "dry_run": True, "decision": parsed["decision"],
                "confidence": parsed["confidence"], "model_version": mv,
                "temperature": temp, "seed": sd, "request": request}
    wrote = CL.append(state_file, parsed["decision"], source="gk_audit_outcome",
                      reason=reason, key_dir=key_dir, ref=str(raise_id),
                      model_version=mv, temperature=temp, seed=sd)
    if not wrote.get("ok"):
        return {"ok": False, "error": "ledger_append_failed: %s" % wrote.get("error")}
    ver = CL.verify_seal(state_file, key_dir=key_dir, require_ed25519=True)
    if not ver.get("ok"):
        return {"ok": False, "error": "seal_verify_failed: %s" % ver.get("reason"),
                "written": True, "record": wrote.get("record")}
    return {"ok": True, "record": wrote.get("record"), "decision": parsed["decision"],
            "confidence": parsed["confidence"], "model_version": mv,
            "seal": ver, "score": wrote.get("score")}


def sweep(state_file, *, endpoint="", key_dir="", limit=5, timeout=30.0, dry_run=False):
    """对**未决 raise** 批量产出 outcome（2026-10-31，§9.7 待决③的触发面）。

    - 未配置 endpoint ⟹ **只返回 advisory**（不联网、不伪造 success）；
    - 已有 `ref == id` outcome 行的 raise 不重复调用（一债一票，`CL.append` 亦会拒）；
    - 单条失败只记入 `results`，不回滚、不中断其余条目（审计报告可读）。
    """
    if not state_file:
        return {"ok": False, "error": "no_state_file"}
    try:
        recs, _ = CL.read_records(state_file)
    except Exception as e:
        return {"ok": False, "error": "ledger_unreadable", "detail": str(e)}
    done = {str(r.get("ref")) for r in recs
            if r.get("kind") in CL.OUTCOME_KINDS and r.get("ref")}
    pending = [str(r.get("id")) for r in recs
               if str(r.get("kind") or "") == "raise" and r.get("id")
               and str(r.get("id")) not in done]
    if not endpoint:
        return {"ok": True, "advisory": "endpoint_unset", "pending": len(pending),
                "pending_ids": pending[:20],
                "hint": "设置 GK_AUDIT_OUTCOME_ENDPOINT 后才会产出 success/fail（不伪造）"}
    results = []
    for rid in pending[:max(0, int(limit))]:
        try:
            out = produce(state_file, rid, endpoint=endpoint, key_dir=key_dir,
                          timeout=timeout, dry_run=dry_run)
        except Exception as e:
            out = {"ok": False, "error": "produce_exception: %s" % e}
        results.append({"raise_id": rid, "ok": bool(out.get("ok")),
                        "decision": out.get("decision"), "error": out.get("error")})
    return {"ok": True, "attempted": len(results), "pending_before": len(pending),
            "limit": limit, "results": results}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_audit_outcome.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("produce", help="classify one raise and append an outcome row")
    p.add_argument("--state", required=True)
    p.add_argument("--raise-id", required=True)
    p.add_argument("--endpoint", required=True)
    p.add_argument("--key-dir", default="")
    p.add_argument("--think-mode", default="auto", choices=THINK_MODES)
    p.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE)
    p.add_argument("--seed", type=int, default=DEFAULT_SEED)
    p.add_argument("--model-version", default="")
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--dry-run", action="store_true")
    # 2026-10-31（§9.7 待决③）：批量触发未决 raise（未配 endpoint 只出 advisory）
    sw = sub.add_parser("sweep", help="produce outcomes for pending raises")
    sw.add_argument("--state", required=True)
    sw.add_argument("--endpoint", default="")
    sw.add_argument("--key-dir", default="")
    sw.add_argument("--limit", type=int, default=5)
    sw.add_argument("--timeout", type=float, default=30.0)
    sw.add_argument("--dry-run", action="store_true")
    ns = ap.parse_args(argv)
    if ns.cmd == "sweep":
        out = sweep(ns.state, endpoint=ns.endpoint, key_dir=ns.key_dir,
                    limit=ns.limit, timeout=ns.timeout, dry_run=ns.dry_run)
        print(json.dumps(out, ensure_ascii=False))
        return 0 if out.get("ok", True) else 1
    think_mode = ns.think_mode
    resolved = ""
    if think_mode == "auto":
        # Instant 模型对 `think_mode=auto` 返回 422（README「Instant models never think」）⟹
        # 按 /health 的 kind 降级为 never；降级事实写进结果与 stderr，不静默改语义。
        info = probe(ns.endpoint)
        if info.get("ok") and info.get("kind") == "instant":
            think_mode = "never"
            resolved = "instant->never"
            print("note: backend kind=instant; think_mode auto -> never", file=sys.stderr)
    out = produce(ns.state, ns.raise_id, endpoint=ns.endpoint, key_dir=ns.key_dir,
                  think_mode=think_mode, temperature=ns.temperature, seed=ns.seed,
                  model_version=ns.model_version, dry_run=ns.dry_run, timeout=ns.timeout)
    if resolved:
        out["think_mode"] = think_mode
        out["think_mode_resolved"] = resolved
    print(json.dumps(out, ensure_ascii=False))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())

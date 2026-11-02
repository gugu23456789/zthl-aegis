#!/usr/bin/env python3
"""gk_monitor_decision.py — `monitor --api` 的**决策后端**通道（复用审计署同一个 `/v1/systemone`）。

> 注：`scripts/gk_monitor_api.py` 是**旧的 PRM 车道**（v4-flash + FAILOVER_CHAIN，保留为
> `GK_MONITOR_API_LEGACY=1` 逃生舱）；本模块是新主路径，两者不共用 prompt/解析。

为什么改为调决策模型（owner 2026-10-31 裁定 A）
=======================================================================
旧 `--api` 的病不在「有没有分」，在**分不可校准**：同一模型族自评、无人类裁决对照、生产零记录
（base state `monitor_history=0`）。裁决 = 保留为**纯观测**，但分数改由**审计署的决策后端**产出
（与 `gk_audit_outcome` **同一端点、同一 typed-choice 协议**）：
  · 一个后端、一套 transport、一套 fail-closed 语义（禁第二实现）；
  · 分数进 `monitor_history` 后可与 `human_calibration_log` 配对算相关性（唯一转正路径）。

契约（与 `gk_audit_outcome` 同形）
=======================================================================
`POST <endpoint>/v1/systemone`，body =
`{"state": {stage, worktree, branch, evidence}, "questions": {"gate_stage": {type:"choice",
  instructions, criteria}}, "think_mode":"auto", "return_details":true}`
response = `{"answers": {"gate_stage": {"choice": "pass|fail|uncertain", "confidence": 0..1,
                                      "probabilities": {...}, "details": {...}}}}`

映射（**投影，非门禁**）：`pass → PASS / score=confidence`；`fail → FAIL / score=1-confidence`；
`uncertain → WARN / score=0.5`。`score` 只作 advisory，**不参与** `_bank_monitor_gate`
（那里只认 `--local` 的确定性 passed/total）。

未配置 `GK_AUDIT_OUTCOME_ENDPOINT` ⟹ 只回 `advisory=endpoint_unset`（不联网、不伪造分数、
**不回落** v4-flash）。
"""
import argparse
import json
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

QUESTION_ID = "gate_stage"
CHOICES = ("pass", "fail", "uncertain")
VERDICT = {"pass": "PASS", "fail": "FAIL", "uncertain": "WARN"}
# 校准最小样本（2026-10-31，owner 裁定 A）：n < MIN_N ⟹ 不可谈转正（只证明仪器能跑）。
MIN_N = 20
# 转正门槛（**advisory，需 owner 复核**）：Spearman ≥ 0.6 且 裁决一致率 ≥ 0.7。
PROMOTE_RHO = 0.6
PROMOTE_AGREE = 0.7


def build_request(stage: str, worktree: str = "", branch: str = "",
                  evidence: dict = None, think_mode: str = "auto") -> dict:
    """构造 `gate_stage` typed-choice 请求（判据文案只在这里）。"""
    return {
        "state": {"stage": stage or "", "worktree": worktree or "", "branch": branch or "",
                  "evidence": evidence or {}},
        "questions": {
            QUESTION_ID: {
                "type": "choice",
                "instructions": ("Judge whether the work performed for this pipeline stage "
                                 "satisfies the stage's gate requirements, using only the "
                                 "supplied evidence (evidence is ground truth; any state "
                                 "claims not backed by evidence must not be treated as done)."),
                "criteria": {
                    "pass": "stage requirements are met and the evidence supports it",
                    "fail": "requirements are unmet, or the evidence contradicts the claims",
                    "uncertain": "evidence is insufficient to decide either way",
                },
            }
        },
        "think_mode": think_mode,
        "return_details": True,
    }


def project(choice: str, confidence: float) -> dict:
    """决策后端的 choice/confidence → monitor 形状（`score/verdict`）。未知 choice 抛错。"""
    c = str(choice or "").strip().lower()
    if c not in CHOICES:
        raise ValueError("invalid_choice: %r（合法：%s）" % (choice, list(CHOICES)))
    try:
        conf = max(0.0, min(1.0, float(confidence)))
    except (TypeError, ValueError):
        conf = 0.0
    score = conf if c == "pass" else (1.0 - conf if c == "fail" else 0.5)
    return {"choice": c, "verdict": VERDICT[c], "score": round(score, 4),
            "confidence": conf}


def parse_response(payload: dict, model: str = "") -> dict:
    """解析 typed-choice 回包；缺答案 / 非法 choice 一律具名失败（不猜、不默认 PASS）。"""
    answers = payload.get("answers") if isinstance(payload, dict) else None
    ans = answers.get(QUESTION_ID) if isinstance(answers, dict) else None
    if not isinstance(ans, dict):
        return {"ok": False, "error": "backend_error: missing_answer"}
    try:
        proj = project(ans.get("choice"), ans.get("confidence"))
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    probs = ans.get("probabilities")
    return {"ok": True, "mode": "--api", "provider": "systemone",
            "model": str(model or (payload or {}).get("model") or ""),
            "verdict": proj["verdict"], "score": proj["score"],
            "confidence": proj["confidence"], "choice": proj["choice"],
            "violations": [], "next_action": "",
            "probabilities": probs if isinstance(probs, dict) else {}}


def run(stage: str, endpoint: str = "", worktree: str = "", branch: str = "",
        evidence: dict = None, timeout: float = 30.0) -> dict:
    """调用决策后端；`endpoint` 为空 ⟹ advisory（不联网）。"""
    ep = (endpoint or "").strip()
    if not ep:
        return {"ok": True, "mode": "--api", "provider": "unset",
                "advisory": "endpoint_unset", "stage": stage,
                "score": None, "verdict": "SKIP", "violations": [], "next_action": "",
                "hint": "设置 GK_AUDIT_OUTCOME_ENDPOINT 后才会产出 score（不伪造、不回落到 v4-flash）"}
    try:
        import gk_audit_outcome as AO
    except Exception as e:  # noqa: BLE001 — 边界：单源 transport 不可用 ⟹ 具名失败
        return {"ok": False, "error": "transport_unavailable: %s" % (e,)}
    url = ep.rstrip("/") + "/v1/systemone"
    try:
        resp = AO._post_json(url, build_request(stage, worktree, branch, evidence),
                             timeout=timeout)
    except Exception as e:  # noqa: BLE001 — 边界：后端不可达/非 JSON 一律 fail-closed
        return {"ok": False, "error": "backend_error: %s" % (e,), "verdict": "UNKNOWN",
                "score": None}
    out = parse_response(resp)
    out["stage"] = stage
    return out


def _rank(xs):
    """平均秩（并列取均秩；Spearman 需它，禁直接对原值排序）。"""
    order = sorted(range(len(xs)), key=lambda i: xs[i])
    ranks = [0.0] * len(xs)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and xs[order[j + 1]] == xs[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks


def spearman(xs, ys):
    """Spearman ρ；样本 <2 或某侧方差为 0 ⟹ `None`（**不猜 0**）。"""
    if len(xs) != len(ys) or len(xs) < 2:
        return None
    rx, ry = _rank(xs), _rank(ys)
    n = len(rx)
    mx, my = sum(rx) / n, sum(ry) / n
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    dx = math.sqrt(sum((a - mx) ** 2 for a in rx))
    dy = math.sqrt(sum((b - my) ** 2 for b in ry))
    if dx == 0 or dy == 0:
        return None
    return round(num / (dx * dy), 4)


def verdict_of(score):
    """分数 → 三档裁决（人类侧与 monitor 侧**同一阈值**，否则一致率无意义）。"""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return ""
    return "PASS" if s >= 0.75 else ("WARN" if s >= 0.5 else "FAIL")


def _load(state_file: str) -> dict:
    try:
        with open(state_file, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:  # noqa: BLE001 — 边界：state 不可读 ⟹ 空（calibrate 会报 n=0）
        return {}


def calibrate(state_file: str, min_n: int = MIN_N) -> dict:
    """monitor 分 ↔ 人类裁决的**校准读数**（只读；同 stage 优先、否则按序对齐）。

    配对规则（保守，禁猜）：两侧各取**数值型**记录，按时间序尾部对齐；两侧都带 `stage`
    且不相等 ⟹ 该对作废并计入 `unmatched`（不重排、不硬凑）。
    返回 `promotable` 只是**门槛提示**（n≥min_n 且 ρ≥0.6 且一致率≥0.7），不是开关。
    """
    gd = (_load(state_file).get("gate_data") or {})
    mons = [m for m in (gd.get("monitor_history") or [])
            if isinstance(m, dict) and isinstance(m.get("score"), (int, float))]
    hums = [h for h in (gd.get("human_calibration_log") or [])
            if isinstance(h, dict) and isinstance(h.get("human_score"), (int, float))]
    k = min(len(mons), len(hums))
    pairs, unmatched = [], 0
    for m, h in zip(mons[len(mons) - k:], hums[len(hums) - k:]):
        ms = str(m.get("stage") or m.get("to") or "")
        hs = str(h.get("stage") or "")
        if ms and hs and ms != hs:
            unmatched += 1
            continue
        mv = str(m.get("verdict") or "") or verdict_of(m["score"])
        hv = verdict_of(h["human_score"])
        pairs.append({"stage": ms or hs, "monitor": m["score"], "human": h["human_score"],
                      "monitor_verdict": mv, "human_verdict": hv})
    rho = spearman([p["monitor"] for p in pairs], [p["human"] for p in pairs])
    agree = (round(sum(1 for p in pairs if p["monitor_verdict"] == p["human_verdict"])
                   / float(len(pairs)), 4) if pairs else None)
    n = len(pairs)
    promotable = bool(n >= min_n and rho is not None and rho >= PROMOTE_RHO
                      and agree is not None and agree >= PROMOTE_AGREE)
    return {"ok": True, "n": n, "spearman": rho, "agreement": agree,
            "min_n": min_n, "promotable": promotable,
            "unmatched": unmatched, "monitor_total": len(mons), "human_total": len(hums),
            "pairs": pairs[-5:],
            "note": "读数只证明仪器可跑；synthetic 样本不能证明模型可用（须真实样本 + owner 复核）"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="monitor --api 的决策后端通道（复用审计署 /v1/systemone）")
    ap.add_argument("cmd", nargs="?", default="run", choices=("run", "calib"))
    ap.add_argument("--stage", default="")
    ap.add_argument("--worktree", default="")
    ap.add_argument("--branch", default="")
    ap.add_argument("--endpoint", default="")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--state", default="", help="calib 用：读 monitor_history + human_calibration_log")
    ap.add_argument("--api-key", default="", help="保留参数（决策后端不走该 key；防旧调用方断链）")
    a = ap.parse_args(argv)
    if a.cmd == "calib":
        out = calibrate(a.state)
    else:
        out = run(a.stage, endpoint=a.endpoint, worktree=a.worktree, branch=a.branch,
                  timeout=a.timeout)
    print(json.dumps(out, ensure_ascii=False))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Gatekeeper Reflect
==================
Extracted from gatekeeper-cli.sh cmd_reflect (L3271-3360).
Full alignment: rejected_edits, best snapshot, human_calibration_log, cross-R history,
               API call with failover.

Usage:
  python3 scripts/gk_reflect.py --stage STAGE_0 [--api-key KEY]
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
from gk_state import _read_state, DEFAULT_STATE_FILE
from gk_json_utils import update_state


def _persist_reflect_result(stage: str, state_path: str):
    """Write rejected_patterns to state (bash L3359-3371).

    2026-09-25（选项 A / `ECC-567E8C847F16`）：改**锁内增量重放**（`update_state`）。
    原「先 read 后 write」的窗口跨了 **LLM API 调用（秒级）**⟹ 并发写者必丢更新；
    而整段持锁又会「锁内等 API」饿死他人（`-w 5` 超时）。本增量（append + 清标志）
    与读到的 state 内容**无关** ⟹ 可安全延后到 API 之后再原子重放。
    """
    def _mut(d):
        gd = d.setdefault("gate_data", {})
        gd.setdefault("rejected_patterns", []).append({
            "stage": stage,
            "analysis": "reflect completed",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": "gk_reflect.py",
        })
        gd["needs_analysis"] = False
        return d
    return update_state(state_path, _mut)


def reflect(
    stage: str,
    api_key: str = "",
    state_path: str = DEFAULT_STATE_FILE,
) -> dict:
    """Reflect: analyze rejected edits, best snapshot, human calibration log."""
    if not stage:
        return {"error": "reflect <stage> required", "ok": False}

    state = _read_state(state_path)
    if "error" in state:
        return {"error": state["error"], "ok": False}

    gd = state.get("gate_data", {})

    # Read rejected edits (last 5)
    rej = gd.get("rejected_edits") or []
    recent_rej = rej[-5:] if len(rej) > 5 else rej

    # Read best snapshot
    best = gd.get("best", {})

    # Read human calibration log (last 5)
    cl = gd.get("human_calibration_log") or []
    recent_cl = cl[-5:] if len(cl) > 5 else cl

    # Read cross-R history
    history = state.get("history", [])
    cross_r_context = ""
    if history:
        recent_h = history[-3:]
        cross_r_context = "## Cross-R Phase History\n"
        for h in recent_h:
            rp = h.get("r_phase", "?")
            b = h.get("best", {})
            rc = h.get("rejection_count", 0)
            mss = h.get("monitor_scores_summary", {})
            cross_r_context += f"- {rp}: best_score={b.get('score', 'N/A')}, rejections={rc}, scores={mss}\n"

    # Static mode (no API)
    if not api_key:
        return {
            "ok": True,
            "rejected_edits": recent_rej,
            "best": best,
            "human_calibration": recent_cl,
            "guidance": "Analyze rejected edits against best snapshot. Focus on patterns: which violations repeat? Which stage has most rejections?",
            "mode": "static",
        }

    # API mode: call LLM for dynamic reflection
    system_prompt = """You are a code review optimizer for the SPZ Gatekeeper R-sequence pipeline. Analyze rejected edits, best snapshot, and human calibration log to provide actionable improvement guidance. Output ONLY JSON: {"pattern_analysis":"...","stage_ranking":"...","recommendations":["..."],"summary":"..."}"""

    user_prompt = f"""STAGE: {stage}

REJECTED EDITS (last 5): {json.dumps(recent_rej)}

BEST SNAPSHOT: {json.dumps(best)}
{cross_r_context}

HUMAN CALIBRATION (last 5): {json.dumps(recent_cl)}
Provide:
1. Pattern analysis — which violations repeat across rejected edits?
2. Stage ranking — which stage has most rejections?
3. Specific improvement recommendations for next attempts

Output only JSON."""

    try:
        resp = requests.post(
            "https://api.deepseek.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "deepseek-flash",
                "reasoning_effort": "medium",
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            },
            timeout=60,
        )
        resp.raise_for_status()
        result = resp.json()
        guidance = result.get("choices", [{}])[0].get("message", {}).get("content", "")

        if guidance:
            try:
                parsed = json.loads(guidance)
                # Write rejected_patterns to state (bash L3359-3371)
                _persist_reflect_result(stage, state_path)
                return {
                    "ok": True,
                    "rejected_edits": recent_rej,
                    "best": best,
                    "human_calibration": recent_cl,
                    "guidance": parsed,
                    "mode": "api",
                }
            except json.JSONDecodeError:
                _persist_reflect_result(stage, state_path)
                return {
                    "ok": True,
                    "rejected_edits": recent_rej,
                    "best": best,
                    "human_calibration": recent_cl,
                    "guidance": guidance,
                    "mode": "api_raw",
                }

    except requests.exceptions.RequestException:
        pass

    # Fallback to static mode
    return {
        "ok": True,
        "rejected_edits": recent_rej,
        "best": best,
        "human_calibration": recent_cl,
        "guidance": "API unavailable. Analyze rejected edits against best snapshot.",
        "mode": "static_fallback",
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Gatekeeper Reflect")
    parser.add_argument("--stage", required=True, help="Stage name")
    parser.add_argument("--api-key", default="", help="API key")
    parser.add_argument("--path", default=DEFAULT_STATE_FILE, help="State file path")

    args = parser.parse_args()

    result = reflect(
        stage=args.stage,
        api_key=args.api_key,
        state_path=args.path,
    )

    print(json.dumps(result, indent=2, ensure_ascii=False))
    sys.exit(0 if result.get("ok", False) else 1)


if __name__ == "__main__":
    main()

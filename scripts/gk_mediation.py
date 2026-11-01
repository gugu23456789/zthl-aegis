#!/usr/bin/env python3
"""gk_mediation.py — P2-Mediation #4 上下文构造（batch8 批次 2 剩余，2026-08-26）。

替代 cmd_appeal 的 mediation_context 内联 python3（L2865 语义等价）：
读取 STATE_FILE 的 sealed agent score + human calibration log，输出 mediation 摘要 JSON。
失败/无 state → {}（对齐原 except 分支）。

用法: python3 gk_mediation.py <state_file>
"""
import json
import sys


def main(argv: list[str]) -> int:
    if len(argv) < 1:
        print("{}")
        return 0
    try:
        with open(argv[0], encoding="utf-8") as f:
            s = json.load(f)
    except Exception:  # noqa: BLE001 — 原内联 except: print('{}')
        print("{}")
        return 0
    gd = s.get("gate_data", {})
    sealed = gd.get("_sealed_agent_score", {})
    cl = gd.get("human_calibration_log", [])
    last = cl[-1] if cl else {}
    ct = last.get("checklist_total", 0)
    out = {
        "agent_score": sealed.get("score", "N/A"),
        "agent_verdicts": sealed.get("verdicts", {}),
        "human_score": last.get("human_score", "N/A"),
        "human_verdicts": last.get("verdicts_json", {}),
        "divergence": last.get("divergence", "N/A"),
        "flag": last.get("flag", ""),
        "change_items": last.get("change_items", 0),
        "checklist": "{}/{}".format(last.get("checklist_passed", 0), ct) if ct else "N/A",
    }
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

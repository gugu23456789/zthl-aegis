#!/usr/bin/env python3
"""
Gatekeeper Adjudicate -- Human scoring + cross-validation
=========================================================
**单一事实源**（R17 双源合并，2026-09-28 落刀）：`gatekeeper-cli.sh:cmd_adjudicate` 的
三段内联实现（原段 A2–A11/A14）已删，CLI 侧改**真 argv 薄调用**本文件。
  内容锚（裸行号已废除）：内联段历史全函数体 sha256[:8] = 622d2df2 @ 基准 commit fd0452a；
  覆盖表（段 A1–A14）= docs/plans/2026-09-21-review-runtime-subplan.md §4.4.1a。

契约（§4.4.2 R17-R6 / A13 / R8 / R9）：
  · 本文件**只读 state、不写 state**（`--path` 仅供读取）；state 落盘 = CLI `_state_write` 单点。
  · 输出信封 = **保留旧键 + 新增键**（owner 裁定 2026-09-28）——
    旧键 `{ok,decision,score,verdicts,recorded_to,cross_validation}`（值与内联逐字等价）
    ∪ 新键 `{monitor_score,divergence,flag?,entry}`（`entry` 供 CLI 回写 state，**禁** CLI 重建）。
  · `--ts` = `entry.timestamp` 的**唯一来源**（R8）；生产路径由 CLI 注入 `date -u`（单点声明）。

Usage:
  python3 scripts/gk_adjudicate.py --verdicts '{"F1":"PASS",...}' --score 0.9 [--decision "..."]
      [--stage "..."] [--verdicts-file <json>] [--concessions-file <json>] [--impact <path>]
      [--ts <ISO8601>] [--json-compact] [--path <state>]

Exit codes:
  0 = OK (JSON output with result)
  1 = Error (JSON output with error field)；含**缺必填参**（保真内联 A5 报文 + rc1）
  2 = Usage error (JSON output with error/kind/usage field)；未知 flag、--score 非数值/越界
      R17（§4.4.4-R9）：argparse 错误路径**一律输出 JSON 信封**（覆盖 `ArgumentParser.error()`）。
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Import shared state manager
sys.path.insert(0, str(Path(__file__).parent))
from gk_state import _read_state, DEFAULT_STATE_FILE


# argparse 对「必需参数缺失」**只产一条**规范消息（`_parse_known_args` 内的唯一调用点，
# 以模块自己的 gettext 常量生产）⟹ 判据从散串 `"required" in message` 改为**前缀锚**。
# 原散串判据的实测反例（ECC-8C29EDF15C74）：`--score required` 是**类型错**（rc 应为 2），
# 但报文 `argument --score: invalid float value: 'required'` 含 "required" ⟹ 被误判 rc1。
# 取 gettext 值而非硬编码英文：本地化时判据与 argparse 同步（不因语言而失配）。
_REQUIRED_MSG_PREFIX = argparse._("the following arguments are required: %s").split("%s")[0]


class _JsonArgumentParser(argparse.ArgumentParser):
    """把 argparse 的三类失败面收敛回 JSON（覆盖 `error()`）。

    缺必填参     → rc=1（**保真**内联 A5 的 `rc1 + JSON`，不改 rc）
    未知 flag    → rc=2（**行为变更**：内联 A3 为 `*) break` **静默吞 rc0**，已实测 oracle O4）
    类型/范围错  → rc=2（**行为变更**：内联 A5 仅判 `-z` 空值、无类型校验）
    `kind` / `usage` / `exit_code` 为**增量字段**（对既有消费者无破坏）。

    rc 分派为**结构判据**：仅当报文以 argparse 自身的「必需参数缺失」规范前缀开头才是
    口径 A（rc1），其余一律 rc2 —— 不再受报文正文里出现 "required" 字样影响。
    """

    def error(self, message):
        code = 1 if message.startswith(_REQUIRED_MSG_PREFIX) else 2
        print(json.dumps({
            "ok": False,
            "error": message,
            "kind": "argparse",
            "usage": self.format_usage().strip(),
            "exit_code": code,
        }, ensure_ascii=False))
        sys.exit(code)


_VERDICT_SCORES = {"PASS": 1.0, "OK": 1.0, "WARN": 0.6, "SUSPECT": 0.6,
                   "FAIL": 0.2, "BLOCKED": 0.2, "REJECT": 0.2}


def score_from_verdicts(verdicts, *, abstain="exclude"):
    """Pre-registered score mapping: PASS/OK=1.0, WARN=0.6, FAIL/BLOCKED=0.2.

    `abstain="exclude"` drops ABSTAIN from the denominator; `"zero"` counts it as 0.
    Unknown values are ignored (never silently mapped to PASS).
    """
    vals = []
    for v in (verdicts or {}).values():
        s = str(v or "").strip().upper()
        if s == "ABSTAIN":
            if abstain == "zero":
                vals.append(0.0)
            continue
        if s in _VERDICT_SCORES:
            vals.append(_VERDICT_SCORES[s])
    return round(sum(vals) / len(vals), 4) if vals else 0.0


def _score_in_0_1(text: str) -> float:
    """`--score` 的类型 + 范围单点（内联 A5 只判 `-z` 空值 ⟹ 无校验）。"""
    try:
        v = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid float value: {text!r}")
    if not (0.0 <= v <= 1.0):
        raise argparse.ArgumentTypeError(f"score must be 0.0-1.0, got {v}")
    return v


def _loads_tolerant(text: str):
    """JSON 容错解析（A4/A10 面 R4）：原内联 `tr -d '\\n\\r'` + `.strip(chr(0))` 的等价面。

    `--verdicts-file` 的**正面夹具**含 BOM/NUL 填充（见 R17 `adjudicate_verdicts_file` 臂），
    故此处吸收 NUL；BOM 由读取侧 `utf-8-sig` 承担。空文本 ⟹ `{}`（保真内联默认）。
    """
    if text is None:
        return {}
    t = text.replace("\x00", "").strip()
    if not t:
        return {}
    return json.loads(t)


def _read_json_arg(inline: str, file_path: str):
    """`--X-file` **优先于** `--X`（保真内联 A4 的覆盖语义）；文件侧 `utf-8-sig` 吸收 BOM。"""
    if file_path:
        with open(file_path, "r", encoding="utf-8-sig") as f:
            return _loads_tolerant(f.read())
    return _loads_tolerant(inline)


def adjudicate(
    verdicts: dict,
    score: float,
    decision: str = "pending",
    stage: str = "",
    concessions: dict = None,
    blind: bool = False,
    checklist: list = None,
    change_items: int = 0,
    constraint_level: str = "",
    impact: str = "",
    ts: str = "",
    state_path: str = DEFAULT_STATE_FILE,
) -> dict:
    """Execute adjudicate logic: validate, cross-validate, build envelope + entry.

    **纯函数面**：只读 `state_path`，**不写** state（R17-R6）；`entry` 经返回体回传 CLI。
    """
    if concessions is None:
        concessions = {}
    if checklist is None:
        checklist = []

    if not isinstance(verdicts, dict):
        return {"error": "--verdicts must be a JSON object", "ok": False}
    if not isinstance(concessions, dict):
        return {"error": "--concessions must be a JSON object", "ok": False}

    # Validate score range
    if not (0.0 <= score <= 1.0):
        return {"error": "score must be 0.0-1.0", "ok": False}

    # Read state
    state = _read_state(state_path)
    if "error" in state:
        return {"error": state["error"], "ok": False}

    # F-16: Block adjudicate in IDLE/DONE state
    current_stage = state.get("stage", "IDLE")
    if current_stage in ("IDLE", "DONE"):
        return {"error": "Cannot adjudicate in IDLE/DONE state", "ok": False}

    # R2a: Gate -- non-PASS verdicts without concessions explanation -> reject
    warnings = [k for k, v in verdicts.items()
                if v not in ("ok", "OK", "Ok", "PASS", "Pass", "pass")]
    missing = [w for w in warnings
               if w not in concessions or not str(concessions.get(w, "")).strip()]
    if missing:
        return {"error": "non-PASS verdicts require --concessions explanation",
                "missing": missing, "ok": False}

    # Determine stage for cross-validation
    if not stage:
        stage = current_stage

    # Cross-validation: compare with sealed agent score or monitor scores
    gd = state.get("gate_data", {})
    sealed = gd.get("_sealed_agent_score", {})

    if sealed and sealed.get("sealed"):
        # NoneType fix (2026-08-08) 搬迁自内联 A8 子锚（L9038-9042@6d6127d1）：
        # score 为 null 时 `.get('score',-1)` 返回 None（key 存在则默认值不生效）⟹ `None >= 0` 崩。
        _sc = sealed.get("score")
        mon_score = _sc if isinstance(_sc, (int, float)) else -1
    else:
        ms = state.get("monitor_scores", {})
        ms_entry = ms.get(stage, {})
        mon_score = ms_entry.get("score", -1)

    # Calculate divergence
    human_score = float(score)
    div = abs(human_score - mon_score) if mon_score >= 0 else -1
    flag = ""
    if div > 0.2 and mon_score >= 0:
        flag = "HUMAN_OVERSCORE" if human_score > mon_score else "HUMAN_UNDERSCORE"

    # Calculate checklist scores (PlanningBench style)
    checklist_passed = 0
    checklist_total = 0
    if checklist:
        checklist_total = len(checklist)
        checklist_passed = sum(1 for i in checklist
                               if str(i.get("status", "")).upper() in ("PASS", "OK"))

    # impact 追加（A10 保真：`[ -f ]` 前置 —— 不存在的路径**不**建新文件）
    recorded_to = ""
    if impact and os.path.isfile(impact):
        with open(impact, "a", encoding="utf-8") as f:
            f.write("\n<!-- DECISION score=%s verdicts=%s decision=%s -->\n"
                    % (score, json.dumps(verdicts, ensure_ascii=False), decision))
        recorded_to = impact

    # Build calibration entry（**回传 CLI**；本文件不落盘 —— R17-R6）
    entry = {
        "timestamp": ts or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "stage": stage,
        "human_score": human_score,
        "monitor_score": mon_score if mon_score >= 0 else None,
        "divergence": round(div, 2) if div >= 0 else None,
        "flag": flag if flag else None,
        "verdicts_json": verdicts,
        "decision": decision,
        "concessions": concessions,
        "checklist_total": checklist_total,
        "checklist_passed": checklist_passed,
        "change_items": change_items,
        "constraint_level": constraint_level,
        "blind": blind,
    }

    # 输出信封：**保留旧键**（值与内联等价）+ **新增键**（A13/R7 owner 裁定 2026-09-28）
    res = {
        "ok": True,
        "decision": decision,
        "score": str(score),
        "verdicts": verdicts,
        "recorded_to": recorded_to,
        "cross_validation": {
            "monitor_score": mon_score if mon_score >= 0 else None,
            "divergence": round(div, 2) if div >= 0 else None,
        },
        "monitor_score": mon_score if mon_score >= 0 else None,
        "divergence": round(div, 2) if div >= 0 else None,
        "entry": entry,
    }
    if flag:
        res["cross_validation"]["flag"] = flag
        res["flag"] = flag
    return res


def main():
    parser = _JsonArgumentParser(description="Gatekeeper Adjudicate")
    parser.add_argument("--verdicts", default=None, help="JSON verdicts string")
    parser.add_argument("--verdicts-file", dest="verdicts_file", default="",
                        help="JSON verdicts file（BOM/NUL 容错；优先于 --verdicts）")
    parser.add_argument("--score", default=None, type=_score_in_0_1, help="Score 0.0-1.0")
    parser.add_argument("--score-from-verdicts", dest="score_from_verdicts",
                        action="store_true", help="Use the pre-registered verdict→score map")
    parser.add_argument("--abstain-zero", dest="abstain_zero", action="store_true",
                        help="With --score-from-verdicts, count ABSTAIN as 0.0")
    parser.add_argument("--decision", default="pending", help="Decision text")
    parser.add_argument("--stage", default="", help="Stage name")
    parser.add_argument("--concessions", default="", help="JSON concessions string")
    parser.add_argument("--concessions-file", dest="concessions_file", default="",
                        help="JSON concessions file（BOM/NUL 容错；优先于 --concessions）")
    parser.add_argument("--blind", action="store_true", help="Blind mode")
    parser.add_argument("--checklist", default="", help="JSON checklist string")
    parser.add_argument("--change-items", dest="change_items", type=int, default=0, help="Change items count")
    parser.add_argument("--constraint-level", dest="constraint_level", default="", help="Constraint level")
    parser.add_argument("--impact", default="", help="Impact file path（存在才追加 DECISION 注释）")
    parser.add_argument("--ts", default="", help="entry.timestamp 定源（ISO8601；缺省 now()）")
    parser.add_argument("--json-compact", dest="json_compact", action="store_true", help="紧凑 JSON 输出")
    parser.add_argument("--path", default=DEFAULT_STATE_FILE, help="State file path（**只读**）")

    args = parser.parse_args()

    # 缺必填参：**保真**内联 A5 —— rc1 + JSON，报文与内联逐字一致（禁走 argparse 的 rc2 无 JSON）。
    if args.verdicts is None and not args.verdicts_file:
        print(json.dumps({"ok": False, "error": "--verdicts or --verdicts-file required",
                          "kind": "argparse", "exit_code": 1}, ensure_ascii=False))
        sys.exit(1)
    if args.score is None and not args.score_from_verdicts:
        print(json.dumps({"ok": False, "error": "--score required (0.0-1.0)",
                          "kind": "argparse", "exit_code": 1}, ensure_ascii=False))
        sys.exit(1)

    # Parse JSON arguments（容错面 R4：BOM/NUL；错误面显式 JSON + rc1，禁静默）
    try:
        verdicts = _read_json_arg(args.verdicts, args.verdicts_file)
        concessions = _read_json_arg(args.concessions, args.concessions_file)
        checklist = _loads_tolerant(args.checklist) if args.checklist.strip() else []
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        print(json.dumps({"ok": False, "error": f"invalid JSON argument: {e}"}, ensure_ascii=False))
        sys.exit(1)
    if not isinstance(checklist, list):
        checklist = []

    if args.score_from_verdicts:
        args.score = score_from_verdicts(
            verdicts, abstain="zero" if args.abstain_zero else "exclude")

    result = adjudicate(
        verdicts=verdicts,
        score=args.score,
        decision=args.decision,
        stage=args.stage,
        concessions=concessions,
        blind=args.blind,
        checklist=checklist,
        change_items=args.change_items,
        constraint_level=args.constraint_level,
        impact=args.impact,
        ts=args.ts,
        state_path=args.path,
    )

    if args.json_compact:
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    sys.exit(0 if result.get("ok", False) else 1)


if __name__ == "__main__":
    main()

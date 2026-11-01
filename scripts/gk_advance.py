#!/usr/bin/env python3
"""
Gatekeeper Advance — State Machine Core (batch8 R-T6 Phase 7)
==============================================================
Migrates `cmd_advance` bash state machine (gatekeeper-cli.sh L2224-3024) to a
standalone Python module. Reuses the gk_gate_* series (project_type/appeal/
adjudicate/entropy/checksum) as their final form per batch8 plan L487-489.

Contract (semantic-equivalent to bash heredoc):
  - non-standard (standing/analysis): {"ok":true,"from":...,"to":...,"mode":"direct",...}
    or {"ok":false,"error":...,"hint":...} on gate block
  - standard: {"allowed":true,...} / {"allowed":false,...}
  - --check: dry-run — zero side effects. Paperclip pre-heartbeat gate calls
    this mode for advance state inspection (zthl-adapter plan ZH2 H4/H9).

Environment evidence (collected by bash caller, injected via --env-json):
  worktree_exists, wt_registered, r_phase_in_path, uncommitted, stash_count,
  ci_trigger, detect_changes, diff_files, plan_backup_exists, merge_check,
  gn_up_to_date, gn_stale, edit_used
Monitor result (bash cmd_monitor): {"score":0.9,"verdict":"PASS","mode":"local"}
check-changes result (bash cmd_check_changes, normalized):
  {"doc_changes":N,"code_changes":N,"unpushed_commits":N,"entropy_rate":R,"push_needed":bool}

Usage:
  python3 scripts/gk_advance.py <to_stage> [--check] [--force]
    [--state-file F] [--skill-dir D] [--env-json '...'] [--monitor-json '...']
    [--cc-json '...'] [--remote-json '"..."'] [--extras-json '...']

Exit codes: 0 = decided (allowed or blocked), 1 = usage error.
"""
import hashlib
import json
import math
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from gk_node_guard import audit_all_recorded, canon_eco, route_map  # 判据单源（批③ ②；2026-10-28 E2：有生产者两域 all-of）
# R2（2026-09-22）：state 序列化单一事实源 —— 勿再内联 json.dump 直写 state。
from gk_json_utils import dump_state, state_lock, two_legs_report

# ─── 常量（对齐 bash: CRITICAL_STAGES L250 / ECO_ORDER L2307）───
CRITICAL_STAGES = {"STAGE_3", "STAGE_4"}
# 2026-10-28（A4 裁定）：standing 常驻序列 5 站合并为 4 站。
#   ECO-SCAN + ECO-READ → ECO-RESEARCH（扫描与深读同一次研究动作）
#   ECO-AUDIT → ECO-VERIFY（审计即验证），其 checklist 与 ECO-DOC 的 docgen 门合并为
#   「VERIFY/DOC」复合门（先 audit --all，再 docgen，再回 RESEARCH）。
# 旧站名继续作为**别名**接受（历史 state / ember 文件名 / 既有测试夹具不破）。
ECO_ORDER = ["ECO-RESEARCH", "ECO-EDIT", "ECO-VERIFY", "ECO-DOC"]
# 别名表与 canon_eco **单源在 gk_node_guard**（L38 导入），此处不重复定义。


CRITICAL_TRANSITIONS = [
    "STAGE_0→STAGE_1", "STAGE_1→STAGE_2", "STAGE_2→STAGE_3",
    "STAGE_3→STAGE_4", "STAGE_4→STAGE_5", "STAGE_5→DONE",
]


def _derive_valid_transitions() -> list:
    """由 `gk_node_guard.route_map("standard")` 的节点表相邻对派生**合法转换单一真源**。

    2026-10-31（T9 owner 裁定的附带防线）：T9 的真实风险是「**删一半**」——只删
    `_structural_gates` 的分支却忘了 `CRITICAL_TRANSITIONS`（或反之），会让 monitor 白名单
    与可 advance 的边**漂移**：前者留下永不触发的死门，后者漏掉应监控的边。两种都静默。

    故「合法转换」**派生**自节点表，不另立手写清单（那会变成第三个真源、直接复制漂移）；
    下方 module-load 断言 `CRITICAL_TRANSITIONS ⊆ VALID_STANDARD_TRANSITIONS`。
    ⚠ 本断言只保证「monitor 白名单不含非法边」；「`_structural_gates` 是否漏了分支」由
    `test_gk_advance_transition_table.py` 的 AST 臂守（那是另一半，必须成对）。
    """
    rm = route_map("standard")
    if not rm.get("ok"):
        raise RuntimeError(
            "转换表白名单派生失败：gk_node_guard.route_map('standard') 返回 "
            f"{rm}。节点表是 standard 转换的唯一真源，不可读即无法校验。")
    nodes = rm["nodes"]
    return [f"{a}→{b}" for a, b in zip(nodes, nodes[1:])]


VALID_STANDARD_TRANSITIONS = _derive_valid_transitions()

_ILLEGAL_CRITICAL = [t for t in CRITICAL_TRANSITIONS
                     if t not in VALID_STANDARD_TRANSITIONS]
if _ILLEGAL_CRITICAL:
    raise RuntimeError(
        "转换表不自洽：CRITICAL_TRANSITIONS 含**非法转换** "
        f"{_ILLEGAL_CRITICAL}；合法集（由 NODE_REGISTRY['standard']['nodes'] 派生）"
        f"= {VALID_STANDARD_TRANSITIONS}。"
        "多半是「删一半」——改了 _structural_gates 分支或 CRITICAL_TRANSITIONS，"
        "却未同步 NODE_REGISTRY['standard']['nodes']（或反之）。")

_SYS_SETUP = False


def _setup_sys_path():
    """Make sibling gk_* modules importable (aligned with gk_audit_state.py)."""
    global _SYS_SETUP
    if not _SYS_SETUP:
        _script_dir = Path(__file__).resolve().parent
        if str(_script_dir) not in sys.path:
            sys.path.insert(0, str(_script_dir))
        _SYS_SETUP = True


def _now_iso() -> str:
    return datetime.now().isoformat()


def _load_state(state_file: str) -> dict:
    """Read state file. Returns error dict on failure."""
    try:
        with open(state_file, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"error": "state_file_not_found"}
    except json.JSONDecodeError as e:
        return {"error": "json_decode_error", "detail": str(e)}


def _write_state(state_file: str, d: dict):
    """Atomic write + checksum update (semantic-equal to bash _state_write).
    newline='\\n' avoids CRLF drift (2026-08-21 lesson)."""
    gd = json.dumps(d.get("gate_data", {}), sort_keys=True)
    d["_checksum"] = hashlib.sha256(gd.encode()).hexdigest()[:16]
    dump_state(state_file, d)


def _verify_checksum(state_file: str) -> dict:
    """Reuse gk_gate_checksum.verify_checksum (D1 BLOCK on tamper)."""
    _setup_sys_path()
    try:
        from gk_gate_checksum import verify_checksum
        return verify_checksum(state_file)
    except ImportError:
        # Fallback: identical algorithm inline (checksum = sha256(gate_data)[:16])
        d = _load_state(state_file)
        if "error" in d:
            return {"error": "STATE_FILE_UNREADABLE", "file": state_file}
        saved = d.get("_checksum", "")
        gd = json.dumps(d.get("gate_data", {}), sort_keys=True)
        computed = hashlib.sha256(gd.encode()).hexdigest()[:16]
        if saved and saved != computed:
            return {"error": "STATE_FILE_TAMPERED", "saved": saved, "computed": computed}
        return {"ok": True, "checksum": computed}


def _project_type(state_file: str) -> str:
    _setup_sys_path()
    try:
        from gk_gate_project_type import get_project_type
        return get_project_type(state_file)
    except ImportError:
        return "standard"


# ────────────────────────────────────────────────────────────────────
# Gate helpers (shared by both branches)
# ────────────────────────────────────────────────────────────────────

def _check_appeal(d: dict) -> str:
    """读内存 dict 的申诉阻断 —— 单源 `gk_gate_appeal.check_appeal_dict`（X1 多源，2026-10-31）。

    原实现在此**复制**了一份判定，只读单值 `gate_data.appeal_required` ⟹ 第二阻断源写入
    `gate_data.appeal_blocks` 时本读点看不见（fail-open），且与 bash G-17 / escalate G-17
    构成三份实现。现统一委托单源模块。
    """
    _setup_sys_path()
    from gk_gate_appeal import check_appeal_dict
    return check_appeal_dict(d)


def _mark_appeal_block(d: dict, to_stage: str, entropy_rate: float) -> None:
    """熵门阻断写点 —— 单源 `gk_gate_appeal.add_block`（`entropy` 源，镜像旧 scalar）。"""
    _setup_sys_path()
    from gk_gate_appeal import add_block
    add_block(d.setdefault("gate_data", {}), "entropy", to_stage,
              entropy_rate=entropy_rate)


def _clear_appeal_block(d: dict, to_stage: str) -> None:
    """--force 人类终裁放行：清除 gate_data 的 appeal 阻塞标记与 appeal_denied_gates
    中的对应 gate，防止同一 gate 在下一次 advance 时被永久拦截（fail-closed 不一致）。
    （2026-08-31 RED-DIFF standing 质询定案：appeal DENIED + 用户 --force 终裁 → 放行）

    L2 审查修正（2026-08-31）：按实际被驳回 gate（appeal_required 记录的 ar）清除，
    而非 to_stage——appeal 目标 ≠ 本次 force 推进目标时（如 appeal 阻在 STAGE_3、
    force 推进到 STAGE_4），仍须清除 STAGE_3 的阻塞标记，否则下次到 STAGE_3 永久拦截。

    X1（2026-10-31）：`--force` = 人类终裁，清**全部来源**（`appeal_blocks` 多源 + 旧 scalar），
    并按所有被清 gate 同步剔除 `appeal_denied_gates`（原只剔单值 ar）。
    """
    _setup_sys_path()
    from gk_gate_appeal import clear_blocks, iter_blocks
    gd = d.setdefault("gate_data", {})
    cleared = {g for _s, g, _r in iter_blocks(gd)}
    clear_blocks(gd)  # gate=None, source=None → 全清
    cleared.add(to_stage)
    d["appeal_denied_gates"] = [g for g in d.get("appeal_denied_gates", [])
                                if g not in cleared]


def _compute_entropy(d: dict, stage: str, state_file: str = "") -> float:
    """Entropy rate — 统一走 gk_gate_entropy.compute_entropy_from_dict
    (2026-08-23: 消除与 gk_gate_entropy.py 的重复实现，单一事实源)。

    2026-10-31（owner 令「修接线缺口」）：原签名只收 `(d, stage)` 且调用未传
    `state_file` ⟹ 第三支「当日提额条数」恒 0（实测 2 raise：0.0 vs 0.667），
    只有 bash `cmd_monitor` 看得到。现显式透传；缺省 `""` 保持旧调用面零回归。
    """
    _setup_sys_path()
    from gk_gate_entropy import compute_entropy_from_dict
    return compute_entropy_from_dict(d, stage, state_file)


def _entropy_guard(d: dict, stage: str, state_file: str = ""):
    """→ `(rate, error|None)`：账本封印失效 ⟹ **具名 fail-loud**，不按 0 放行。

    2026-10-31（§9.4 额外缺口①）：`count_raises` 直接改/删 `.budget-log.jsonl` 可把熵与
    CAP 计数清零；此处把 `RAISE_LEDGER_SEAL_INVALID` 转成显式 JSON 错误（含 `ok/allowed`
    两种分支形状），绝不让异常落到 traceback 或被 `except → 0` 吞掉。
    """
    try:
        return _compute_entropy(d, stage, state_file), None
    except Exception as e:
        if getattr(e, "code", "") == "RAISE_LEDGER_SEAL_INVALID":
            return 0.0, {
                "ok": False, "allowed": False, "error": "RAISE_LEDGER_SEAL_INVALID",
                "detail": str(e),
                "hint": "提额账本封印缺失/失效（`<state>.budget-log.jsonl.seal`）；"
                        "拒绝按 0 计熵。先用 `budget-ledger verify --state ...` 定位并恢复封印。",
            }
        raise


def _credit_floor_eval(d: dict, state_file: str = "") -> dict:
    """N 门（信用分下限）评估 —— **只认基线后的 Δ**，默认 advisory（2026-10-31）。

    单源：基线由 `gk_econ_baseline.resolve` 解析（credit 签名基线权威、`econ_enabled_at` 仅
    legacy 回退；两者不一致 ⟹ `drift`）。无基线 ⟹ **不得**按 `score()` 绝对值判（一开即锁）。
    `GK_CREDIT_FLOOR_ENFORCE=1` 才执行阻断；否则只落 `credit_advisories`（审计可读）。
    """
    try:
        from gk_econ_baseline import resolve
        from gk_credit_ledger import delta_since
        from gk_econ_params import N
        b = resolve(state_file) if state_file else {
            "ok": True, "reason": "no_state", "source": "none", "ts": "",
            "cutoff_id": "", "drift": False}
        if not b.get("ok"):
            return {"baseline": b, "hit": False,
                    "advisory": b.get("reason") or "baseline_invalid"}
        delta = delta_since(state_file, b.get("ts", ""), b.get("cutoff_id", "")) if state_file else None
        if delta is None:
            return {"baseline": b, "hit": False, "advisory": "baseline_missing"}
        hit = delta <= -int(N)
        return {"baseline": b, "score_delta": delta, "threshold": -int(N),
                "hit": hit, "advisory": "credit_floor_hit" if hit else ""}
    except Exception as e:
        return {"hit": False, "advisory": "credit_unreadable", "detail": str(e)}


def _entropy_enforced(rate: float, base_rate: float) -> bool:
    """熵是否**执行**阻断（2026-10-31，owner 裁定方向）。

    第三支（当日提额）已接线（测量面），但它尚未参数化为「经济调控」（免费额度/成本/
    每日上限，见 `docs/plans/2026-10-31-credit-economic-control-plan.md`）。在参数裁定前：
      · 越线**完全由提额驱动**（base ≤ 0.5）⟹ 默认只测量不阻断，显式
        `GK_ENTROPY_RAISE_ENFORCE=1` 才执行；
      · 越线**本身已由 rejected_edits 驱动**（base > 0.5）⟹ 既有硬阻断**零变更**。
    """
    if rate <= 0.5:
        return False
    _setup_sys_path()
    from gk_econ_params import T_BLOCK
    if rate <= T_BLOCK:
        return False
    if base_rate <= T_BLOCK and os.environ.get("GK_ENTROPY_RAISE_ENFORCE", "0") != "1":
        return False
    return True


def _appeal_block_response(appeal_req: str, to_stage: str) -> dict:
    """Map appeal gate result to bash-equivalent JSON response."""
    if appeal_req.startswith("blocked:"):
        req_stage = appeal_req[len("blocked:"):]
        return {"ok": False, "error": "appeal_required", "blocked_gate": req_stage,
                "hint": f"Run 'appeal {req_stage} <your notes>' to challenge the entropy block"}
    if appeal_req.startswith("denied:"):
        denied_stage = appeal_req[len("denied:"):]
        return {"ok": False, "error": "appeal_denied", "blocked_gate": denied_stage,
                "hint": f"Appeal was DENIED. Run 'escalate {denied_stage} <reason>' to generate human review report"}
    return {"ok": False, "error": "appeal_gate_error", "detail": f"unexpected: {appeal_req}"}


def _entropy_block_response(entropy_rate: float, to_stage: str) -> dict:
    return {"ok": False, "error": "entropy_high", "violation_rate": entropy_rate,
            "threshold": 0.5, "action": "appeal_required",
            "hint": f"Run 'appeal {to_stage} <your notes>' to challenge this block"}


# ────────────────────────────────────────────────────────────────────
# Non-standard branch (standing/analysis): ECO / ECC / AUDIT / RED
# ────────────────────────────────────────────────────────────────────

def _eco_ecc_boundary(current: str, to: str) -> dict:
    """I6: ECO→ECC cross-type boundary protection + ECC→ECO reverse."""
    from_eco = current.startswith("ECO-")
    to_ecc = to.startswith("ECC-")
    if to_ecc and not from_eco:
        return {"ok": False, "error": f"ECC-* requires prior ECO cycle. Current stage: {current}"}
    if from_eco and current != "ECO-DOC" and to_ecc:
        return {"ok": False, "error": f"Only ECO-DOC can advance to ECC-*. Current: {current}"}
    from_ecc = current.startswith("ECC-")
    to_eco = to.startswith("ECO-")
    if from_ecc and to_eco:
        return {"ok": False, "error": "ECC→ECO reverse not allowed. Advance to R-T* or complete cycle."}
    return {"ok": True}


def _eco_sequence(current: str, to: str) -> dict:
    """R2b: ECO phase sequential ordering gate (ECO-DOC wraps to ECO-RESEARCH).

    2026-10-28（A4）：站名先归一到 4 站规范名。合并后**同一规范站**内的旧站名互转
    （如 `ECO-SCAN → ECO-READ`）视为站内幂等动作，直接放行。
    """
    if not (current.startswith("ECO-") and to.startswith("ECO-")):
        return {"ok": True}
    cur_c, to_c = canon_eco(current), canon_eco(to)
    if cur_c == to_c:
        return {"ok": True}
    cur_idx = ECO_ORDER.index(cur_c) if cur_c in ECO_ORDER else -1
    tgt_idx = ECO_ORDER.index(to_c) if to_c in ECO_ORDER else -1
    if cur_idx >= 0 and tgt_idx >= 0:
        expected_idx = cur_idx + 1
        if expected_idx >= len(ECO_ORDER):
            expected_idx = 0
        if tgt_idx != expected_idx:
            expected_phase = ECO_ORDER[expected_idx] if expected_idx < len(ECO_ORDER) else ""
            return {"ok": False,
                    "error": f"ECO sequential violation: {current} → {to} not allowed. Expected next: {expected_phase}",
                    "sequence": " ".join(ECO_ORDER)}
    elif cur_idx >= 0 or tgt_idx >= 0:
        return {"ok": False,
                "error": f"ECO phase mismatch: '{current}' or '{to}' not in standard sequence",
                "sequence": " ".join(ECO_ORDER)}
    return {"ok": True}


def _history_entries(d: dict, state_file: str = "") -> list:
    """`subagent_history` **统一读面**（卫星计划对齐，`ECC-2EC7FD463D29` 读侧半场）。

    写侧溢出已把条目落 `history` 卫星片；读侧若仍只读 `gate_data.subagent_history`，
    即「写卫星、读 base」= 读分裂（溢出后 live 变空 ⟹ 前置误判）。
    单源 = `gk_moa_aggregate.history_union`（禁第二实现）；缺片 fail-loud 冒泡。
    `state_file` 为空 ⟹ 逐字保持 live-only（既有单测直调口径）。
    """
    live = (d.get("gate_data") or {}).get("subagent_history") or []
    if not state_file:
        return live
    import gk_moa_aggregate as _MA
    merged, _info = _MA.history_union(state_file, d)
    return merged


def _plan_ref_checkpoint(d: dict, state_file: str = "") -> str:
    """ECO-READ → ECO-EDIT must have plan-refinement subagent checkpoint."""
    sh = _history_entries(d, state_file)
    if not sh:
        return "NONE"
    task = sh[-1].get("task", "")
    return "plan-refinement" if "plan-refinement" in task else "NO_PLAN_REFINEMENT"


def _check_adjudicate(d: dict, ptype: str = "standard", state_file: str = "") -> str:
    """Reuse gk_gate_adjudicate.check_adjudicate logic (F1-F7 double-blind chain).

    ptype == "standing": 常驻序列豁免 plan-refinement 前置与 F1-F7 维度检查
    （standing 非计划质询，adjudicate 仅需有效裁决记录即可）。
    """
    gd = d.get("gate_data", {})
    if ptype != "standing":
        sh = _history_entries(d, state_file)
        if not sh:
            return "no_plan_refinement_checkpoint"
        if "plan-refinement" not in str(sh[-1].get("task", "")):
            return "no_plan_refinement_checkpoint"
    cl = gd.get("human_calibration_log") or []
    f1_f7 = [f"F{i}" for i in range(1, 8)]
    for entry in reversed(cl):
        if entry.get("stage", "") not in ("ECO-EDIT", ""):
            continue
        verdicts = entry.get("verdicts_json") or {}
        if not isinstance(verdicts, dict):
            return "verdicts_invalid"
        if ptype != "standing":
            missing = [k for k in f1_f7 if k not in verdicts]
            if missing:
                return "missing_verdicts:" + ",".join(missing)
        score = entry.get("human_score")
        if not isinstance(score, (int, float)) or not (0 <= score <= 1):
            return "score_invalid"
        decision = str(entry.get("decision", "") or "")
        if not decision.strip() or decision.strip().lower() == "pending":
            return "decision_pending"
        return "ok"
    return "no_eco_edit_entry"


def _ecc_incremental(d: dict, current: str) -> str:
    """P3-Incremental #6+#7: ECC phase advance — incremental, not full re-eval."""
    gd = d.get("gate_data", {})
    eco_pass = gd.get("eco_completions", {}).get("ECO-EDIT", {})
    eco_passed = bool(eco_pass.get("completed_at"))
    cl = gd.get("human_calibration_log") or []
    if eco_passed:
        eco_ts = eco_pass.get("completed_at", "")
        for entry in reversed(cl):
            entry_stage = entry.get("stage", "")
            if not entry_stage.startswith("ECC-"):
                continue
            ci = entry.get("change_items", 0)
            ct = entry.get("checklist_total", 0)
            clv = entry.get("constraint_level", "")
            entry_ts = entry.get("timestamp", "")
            valid_clv = ("H1", "H2", "M1", "M2", "L1", "L2")
            has_incremental = any([ci > 0, ct > 0, clv in valid_clv])
            stage_match = (entry_stage == current or entry_stage == "")
            ts_ok = True
            if eco_ts and entry_ts:
                try:
                    from datetime import datetime as _dt
                    eco_dt = _dt.fromisoformat(eco_ts.replace("Z", "+00:00"))
                    ent_dt = _dt.fromisoformat(entry_ts.replace("Z", "+00:00"))
                    ts_ok = (ent_dt >= eco_dt)
                except Exception:
                    pass
            if has_incremental and stage_match and ts_ok:
                return "incremental_ok"
            elif has_incremental and not stage_match:
                return f"stage_mismatch:{entry_stage}"
            elif has_incremental and not ts_ok:
                return "stale_adjudicate"
        return "needs_incremental"
    for entry in reversed(cl):
        if entry.get("stage", "") in (current, ""):
            return "ok"
    return "missing"


def _audit_order(d: dict, to: str) -> dict:
    """AUDIT phase ordering enforcement."""
    if to.startswith("AUDIT-") and to != "AUDIT-REPORT":
        phases = d.setdefault("audit_phases_completed", [])
        phases.append(to)
    if to == "AUDIT-REPORT":
        phases = d.get("audit_phases_completed", [])
        need = {"AUDIT-STATE", "AUDIT-MEMORY", "AUDIT-CROSSR"}
        if not need.issubset(set(phases)):
            return {"ok": False,
                    "error": "AUDIT phase order violation: must complete AUDIT-STATE, AUDIT-MEMORY, and AUDIT-CROSSR before AUDIT-REPORT"}
    return {"ok": True}


# ─── hint 数据（对齐 bash L2511-2569 + L2634-2692）───

_HINT_PHASES = {
    "ECO-RESEARCH": {"phase": "ECO-RESEARCH",
                     "desc": "研究：结构扫描 + 深度阅读 + 交叉审查（A4 合并 ECO-SCAN/ECO-READ；A5 只读前置可跳过）",
                     "available": ["search", "state", "discover", "self-check",
                                   "subagent", "read", "gitnexus context/impact",
                                   "monitor --subagent"],
                     "research_prelude": {
                         "skippable": True,
                         "items": ["问题分解（把本轮要回答的问题列成 1-3 条）",
                                   "外部检索（按需，落证据清单；无外部依赖可跳过）",
                                   "证据清单（产物落卫星片，不阻塞 EDIT）"],
                         "skip_flag": "GK_SKIP_RESEARCH_PRELUDE=1",
                     },
                     "next": "ECO-EDIT", "trigger": "bash gatekeeper-cli.sh advance ECO-EDIT"},
    "ECO-EDIT": {"phase": "ECO-EDIT", "desc": "plan-refinement quality gate: invoke Skill(plan-refinement) for F1-F7 SCR review before advancing",
                 "skill": "plan-refinement (brainstorming→plan-refinement→writing-plans): F1-F7 quality check. After receiving plan-refinement PASS report, return to advance ECO-VERIFY.",
                 "available": ["guard-edit", "pre-tool-check"], "next": "ECO-VERIFY",
                 "trigger": "bash gatekeeper-cli.sh advance ECO-VERIFY"},
    "ECO-VERIFY": {"phase": "ECO-VERIFY",
                   "desc": "验证：审计检查 + 数据采集（A4 合并原 ECO-AUDIT；出口复合门 = audit --all → docgen）",
                   "available": ["self-check", "state", "reflect", "balance", "audit --crossfull"],
                   "next": "ECO-DOC", "trigger": "bash gatekeeper-cli.sh advance ECO-DOC"},
    "ECO-DOC": {"phase": "ECO-DOC", "desc": "文档同步 + Slow Update",
                "available": ["docgen", "search --repo", "gitnexus analyze"],
                "next": "ECO-RESEARCH", "trigger": "bash gatekeeper-cli.sh advance ECO-RESEARCH"},
    # ── 旧站名（2026-10-28 A4 合并前的 5 站）：只作**历史 state / 既有夹具**的读面别名，
    #    advance 时由 canon_eco() 归一到 4 站；不写入新 state。
    "ECO-SCAN": {"phase": "ECO-SCAN", "desc": "（已并入 ECO-RESEARCH）扫描参考项目结构",
                 "available": ["search", "state", "discover", "self-check"],
                 "deprecated": "ECO-RESEARCH",
                 "next": "ECO-EDIT", "trigger": "bash gatekeeper-cli.sh advance ECO-EDIT"},
    "ECO-READ": {"phase": "ECO-READ", "desc": "（已并入 ECO-RESEARCH）深度阅读参考项目 + 交叉审查",
                 "available": ["subagent", "read", "gitnexus context/impact", "monitor --subagent"],
                 "deprecated": "ECO-RESEARCH",
                 "next": "ECO-EDIT", "trigger": "bash gatekeeper-cli.sh advance ECO-EDIT"},
    "ECO-AUDIT": {"phase": "ECO-AUDIT", "desc": "（已并入 ECO-VERIFY）审计检查 + 数据采集",
                  "available": ["self-check", "state", "reflect", "balance", "audit --crossfull"],
                  "deprecated": "ECO-VERIFY",
                  "next": "ECO-DOC", "trigger": "bash gatekeeper-cli.sh advance ECO-DOC"},
    # D7-B（2026-10-27，J1+S1）：审计序列整建制归审计署；hint 透传归属，派发行为不变。
    "AUDIT-STATE": {"phase": "AUDIT-STATE", "desc": "审计当前快照",
                    "owner": "skill.2026-10-04-audit-bureau-plan",
                    "available": ["self-check", "reflect", "state", "search"],
                    "next": "AUDIT-MEMORY", "trigger": "bash gatekeeper-cli.sh advance AUDIT-MEMORY"},
    "AUDIT-MEMORY": {"phase": "AUDIT-MEMORY", "desc": "跨 session 记忆重放",
                     "owner": "skill.2026-10-04-audit-bureau-plan",
                     "available": ["self-check", "reflect", "state", "search"],
                     "next": "AUDIT-CROSSR", "trigger": "bash gatekeeper-cli.sh advance AUDIT-CROSSR"},
    "AUDIT-CROSSR": {"phase": "AUDIT-CROSSR", "desc": "跨 R 趋势分析",
                     "owner": "skill.2026-10-04-audit-bureau-plan",
                     "available": ["self-check", "reflect", "state", "search", "audit --crossfull"],
                     "next": "AUDIT-REPORT", "trigger": "bash gatekeeper-cli.sh advance AUDIT-REPORT"},
    "AUDIT-REPORT": {"phase": "AUDIT-REPORT", "desc": "审计报告生成",
                     "owner": "skill.2026-10-04-audit-bureau-plan",
                     "available": ["self-check", "reflect", "state", "search"],
                     "next": "(cycle complete)", "trigger": "bash gatekeeper-cli.sh discover"},
    "RED-SCOPE": {"phase": "RED-SCOPE", "desc": "红队范围确认",
                  "available": ["self-check", "state", "discover", "search"],
                  "next": "RED-SURFACE", "trigger": "bash gatekeeper-cli.sh advance RED-SURFACE"},
    "RED-SURFACE": {"phase": "RED-SURFACE", "desc": "红队攻击面测绘",
                    "available": ["search", "gitnexus context", "gitnexus impact", "read"],
                    "next": "RED-CONSTRAINTS", "trigger": "bash gatekeeper-cli.sh advance RED-CONSTRAINTS"},
    "RED-CONSTRAINTS": {"phase": "RED-CONSTRAINTS", "desc": "红队约束枚举",
                        "available": ["pre-tool-check", "guard-edit", "state", "audit"],
                        "next": "RED-EXPLOIT", "trigger": "bash gatekeeper-cli.sh advance RED-EXPLOIT"},
    "RED-EXPLOIT": {"phase": "RED-EXPLOIT", "desc": "红队渗透攻击",
                    "available": ["advance bypass", "--force abuse", "audit tamper"],
                    "next": "RED-POSTEX", "trigger": "bash gatekeeper-cli.sh advance RED-POSTEX"},
    "RED-POSTEX": {"phase": "RED-POSTEX", "desc": "红队后期利用评估",
                   "available": ["reflect", "self-check", "audit --state", "audit --memory"],
                   "next": "RED-REPORT", "trigger": "bash gatekeeper-cli.sh advance RED-REPORT"},
    "RED-REPORT": {"phase": "RED-REPORT", "desc": "红队攻击链报告",
                   "available": ["audit --verify", "state"],
                   "next": "RED-HINT", "trigger": "bash gatekeeper-cli.sh advance RED-HINT"},
    "RED-HINT": {"phase": "RED-HINT", "desc": "红队检测 advance hint 注入完整性",
                 "available": ["self-check", "state", "audit --hint"],
                 "next": "RED-HOOK", "trigger": "bash gatekeeper-cli.sh advance RED-HOOK"},
    "RED-HOOK": {"phase": "RED-HOOK", "desc": "红队检测 pre_tool_hook 门禁旁路",
                 "available": ["self-check", "state", "audit --hook"],
                 "next": "RED-PY", "trigger": "bash gatekeeper-cli.sh advance RED-PY"},
    "RED-PY": {"phase": "RED-PY", "desc": "红队检测 Python 自检绕过",
               "available": ["self-check", "state", "audit --self"],
               "next": "RED-POISON", "trigger": "bash gatekeeper-cli.sh advance RED-POISON"},
    # 2026-08-28 红队引擎扩展 4 阶段（_red_attacks.py red_poison/registry/ghost/coverage，
    # audit --red <phase> 确定性扫描，域1/2/4、域5、域8、审计覆盖）——注册为红队序列站点
    "RED-POISON": {"phase": "RED-POISON", "desc": "红队投毒攻击面扫描 (2026-08-28 域1/2/4)",
                   "available": ["self-check", "state", "audit --red poison"],
                   "next": "RED-REGISTRY", "trigger": "bash gatekeeper-cli.sh advance RED-REGISTRY"},
    "RED-REGISTRY": {"phase": "RED-REGISTRY", "desc": "红队元数据路由攻击面扫描 (2026-08-28 域5)",
                     "available": ["self-check", "state", "audit --red registry"],
                     "next": "RED-GHOST", "trigger": "bash gatekeeper-cli.sh advance RED-GHOST"},
    "RED-GHOST": {"phase": "RED-GHOST", "desc": "红队高威胁幽灵攻击面扫描 (2026-08-28 域8)",
                  "available": ["self-check", "state", "audit --red ghost"],
                  "next": "RED-COVERAGE", "trigger": "bash gatekeeper-cli.sh advance RED-COVERAGE"},
    "RED-COVERAGE": {"phase": "RED-COVERAGE", "desc": "红队审计覆盖缺口扫描 (2026-08-28 域3/4/5)",
                     "available": ["self-check", "state", "audit --red coverage"],
                     "next": "(cycle complete)", "trigger": "bash gatekeeper-cli.sh discover"},
}

_CHECKLISTS = {
    "ECO-RESEARCH": ["discover (同步状态)", "state (检查当前阶段)", "self-check (环境完整性检查)",
                     "research-prelude: 问题分解 → 外部检索（按需）→ 证据清单（可跳过：GK_SKIP_RESEARCH_PRELUDE=1）",
                     "monitor --subagent 分析参考项目", "gitnexus context (代码结构360度视图)", "read 参考项目关键文件"],
    "ECO-EDIT": ["guard-edit <file> (编辑权限检查)", "pre-tool-check (门禁验证)", "pytest (测试通过后再 commit)"],
    "ECO-VERIFY": ["self-check (env/gitnexus/key/tests)", "context --update (子agent上下文更新)", "reflect (反思当前进展)", "audit --crossfull (统一启动器: 全量交叉审查一条命令)"],
    "ECO-DOC": ["docgen (文档同步)", "gitnexus analyze --embeddings (更新基线)", "search --repo 确认无遗漏"],
    # 2026-10-28（A4 收尾）：旧站名 checklist 已删除（`_hint_for` 入参由 `_run_nonstandard` 归一）。
    "RED-SCOPE": ["self-check (环境状态)", "state (当前快照)", "discover (项目结构)"],
    "RED-SURFACE": ["search (攻击面搜索)", "gitnexus context (入口点分析)", "gitnexus impact (爆破半径)"],
    "RED-CONSTRAINTS": ["pre-tool-check (门禁枚举)", "guard-edit (保护区域枚举)", "audit --state (状态审计)"],
    "RED-EXPLOIT": ["尝试 advance bypass", "尝试 --force abuse", "audit tamper (篡改检测)"],
    "RED-POSTEX": ["self-check (防御验证)", "reflect (攻击链反思)", "audit --state (状态一致性)"],
    "RED-REPORT": ["audit --verify (完整性验证)", "state (最终快照)"],
    "RED-HINT": ["检查 advance hint JSON 完整性", "验证 checklist/tool_policy/post_check/gates 均注入", "验证 15 阶段 checklist 全覆盖"],
    "RED-HOOK": ["验证 pre_tool_hook.py Gate0-4 存在", "验证 .trae/settings.json matcher 覆盖 CreateFile|DeleteFile", "验证 hook command 经过 WSL 路由", "验证 hook exit code 2 正确阻断"],
    "RED-PY": ["验证 gk_self_check.py 11 项 check 均注册", "验证每个 check 有 try/except 隔离", "验证 cmd_self_check 动态提取 python checks (RED-PY-BASH 修复)", "验证 gitnexus 走项目本地 .gitnexus/run.cjs runner"],
    "RED-POISON": ["audit --red poison (投毒攻击面: 窄任务 8 类注入 + Unicode + 重复凸显)"],
    "RED-REGISTRY": ["audit --red registry (元数据路由: scopes 篡改/孤儿/别名/_checksum/audit_log)"],
    "RED-GHOST": ["audit --red ghost (高威胁: 预算域越界/超界/递归/无签名)"],
    "RED-COVERAGE": ["audit --red coverage (审计覆盖缺口: 新增安全措施入审计/红队序列)"],
    "AUDIT-STATE": ["self-check (环境状态)", "state (当前快照)", "reflect (反射审计结果)"],
    "AUDIT-MEMORY": ["self-check (环境状态)", "reflect (重放分析)", "state (历史记录)"],
    "AUDIT-CROSSR": ["self-check (环境状态)", "state (跨R基线)", "reflect (趋势分析)", "audit --crossfull (统一启动器: 近 N commit 全量串行)"],
    "AUDIT-REPORT": ["self-check (环境状态)", "state (最终快照)", "docgen (报告生成)"],
}

_TOOL_POLICY = {
    "search": "gatekeeper-cli.sh search --repo <name>",
    "review": "gatekeeper-cli.sh monitor --subagent",
    "read": "gitnexus context > rg > Read (优先级递减)",
}

_GATES_JSON = {
    # 2026-10-28（A4）：键用 4 站规范名（旧键 ECO-EDIT->ECO-AUDIT / ECO-AUDIT->ECO-DOC /
    # ECO-DOC->ECO-SCAN 已失效——它们是显示面文本，不参与判定）
    "ECO-EDIT->ECO-VERIFY": "必须先 adjudicate",
    "ECO-VERIFY->ECO-DOC": "必须先 audit --all",
    "ECO-DOC->ECO-RESEARCH": "必须先 docgen",
    "RED-EXPLOIT->RED-POSTEX": "必须先执行所有攻击向量",
    "RED-POSTEX->RED-REPORT": "必须先 reflect",
    "RED-REPORT->RED-HINT": "必须先 red_report 确认无遗漏",
    "RED-HINT->RED-HOOK": "必须先确认 hint JSON 完整",
    "RED-HOOK->RED-PY": "必须先确认 hook 配置正确",
    "RED-PY->RED-POISON": "必须先确认红队攻击序列完成（进入确定性扫描站）",
}


def _hint_for(to_stage: str, d: dict, cc: dict, remote: str, current: str = "") -> tuple:
    """Build hint object + top-level extras (bash L2511-2569 + L2630-2692).

    hint 结构 = 3.5d + 3.5i + RED 扩展（batch8 plan L1293-1297）：
      - RED-HINT/HOOK/PY 三阶段 checklist 条目（_CHECKLISTS）
      - RED 过渡 gates HINT→HOOK→PY→REPORT（_GATES_JSON）
      - tool_policy 引用 gitnexus 统一调用（_TOOL_POLICY）
    bash 语义: "hint":{...} 后直接拼接 ",checklist:[...],current_remote:...,gates:{...}"
    (L2691 hint_json="${hint_json},${_hint_extras}") — checklist/tool_policy 等是
    顶层字段，不在 hint 对象内。返回 (hint, extras)。"""
    hint = dict(_HINT_PHASES.get(to_stage, {}))
    if to_stage.startswith("ECC-"):
        hint = {"phase": to_stage, "desc": "分析审查阶段",
                "available": ["search", "read", "reflect"],
                "next": "next ECC phase", "trigger": "bash gatekeeper-cli.sh advance <next-phase>"}
    elif to_stage.startswith("AUDIT-") and to_stage not in _HINT_PHASES:
        hint = {"phase": to_stage, "desc": "审计重放阶段",
                "available": ["self-check", "reflect", "state", "search"],
                "next": "next audit phase", "trigger": "bash gatekeeper-cli.sh advance <next-phase>"}
    elif to_stage.startswith("RED-") and to_stage not in _HINT_PHASES:
        hint = {"phase": to_stage, "desc": "红队安全审计阶段",
                "available": ["self-check", "audit", "reflect", "state"],
                "next": "next red phase", "trigger": "bash gatekeeper-cli.sh advance <next-phase>"}
    extras = {}
    checklist = _CHECKLISTS.get(to_stage)
    if checklist:
        extras["checklist"] = checklist
    extras["current_remote"] = remote
    extras["tool_policy"] = dict(_TOOL_POLICY)
    extras["post_check"] = "bash gatekeeper-cli.sh self-check"
    # 2026-08-27 序列节点安全网：总运行线路 + 车站播报（gk_node_guard.py 承载）
    # Phase 3.5d route_template 实装形态：route_map = 地铁总运行路线，station = 当前车站播报 + 下一站预报
    try:
        from gk_node_guard import register_check, route_map, station_announcement
        _reg = register_check(to_stage)
        if not _reg.get("ok"):
            extras["node_registration"] = {"ok": False, "error": _reg.get("error")}
        else:
            _rm = route_map(_reg["node"].get("route"))
            _sa = station_announcement(to_stage, current)
            if _rm.get("ok"):
                extras["route_map"] = _rm  # 流程总运行线路（全线路图）
            if _sa.get("ok"):
                extras["station"] = {  # 车站播报：当前站 + 下一站预报
                    "station": _sa["station"], "route": _sa["route"],
                    "prev": _sa["prev"], "next": _sa["next"],
                    "gate": _sa["gate"], "checklist": _sa["checklist"],
                    "safety": _sa["safety"],
                }
    except ImportError:
        pass  # gk_node_guard 缺失时静默降级（hint 不含路线图，不影响 advance 判定）
    extras["gates"] = dict(_GATES_JSON)
    return hint, extras


# ────────────────────────────────────────────────────────────────────
# Standard branch: STAGE_n gate machine
# ────────────────────────────────────────────────────────────────────

def _structural_gates(current: str, to: str, d: dict, env: dict, force: bool) -> tuple:
    """Structural gate checks (bash L2798-2859). Returns (all_ok, gates[]).
    Environment evidence injected via env (missing evidence → conservative FAIL)."""
    gates = []
    all_ok = True
    branch = d.get("branch", "")
    worktree = d.get("worktree", "")
    r_phase = d.get("r_phase", "")

    def fail(g):
        nonlocal all_ok
        all_ok = False
        gates.append(f"FAIL:{g}")

    def warn(g):
        gates.append(f"WARN:{g}")

    if current == "STAGE_0" and to == "STAGE_1":
        if not env.get("worktree_exists", False):
            fail("worktree not found")
        if branch == "main":
            fail("branch is main")
        if not env.get("wt_registered", False):
            fail("worktree not registered in git worktree list")
        rp = r_phase
        if rp:
            rp_lower = rp.lower()
            if rp_lower not in (worktree or "").lower():
                warn(f"worktree path does not contain R-phase '{rp}' — path may be stale from previous phase")
    elif current == "STAGE_1" and to == "STAGE_2":
        uncommitted = env.get("uncommitted", "worktree_missing")
        if uncommitted == "worktree_missing":
            fail("worktree not accessible")
        elif uncommitted:
            fail("uncommitted changes")
        if branch == "main":
            fail("branch is main")
        if not branch:
            fail("branch name empty")
        stash_count = env.get("stash_count", 0)
        if stash_count == "worktree_dead":
            warn("cannot check stash — worktree may be missing")
        elif isinstance(stash_count, int) and stash_count > 0:
            warn(f"{stash_count} stashed changes — may hide uncommitted work")
        trigger_ok = env.get("ci_trigger", 0)
        if int(trigger_ok or 0) < 1:
            fail("CI trigger not registered")
        changed_count = env.get("detect_changes", 0)
        if isinstance(changed_count, int) and changed_count > 20:
            warn(f"detect-changes shows {changed_count} files changed — scope may be too large")
    elif current == "STAGE_2" and to == "STAGE_3":
        diff_files = env.get("diff_files", "")
        if not diff_files:
            fail("no files changed in last commit — --allow-empty bypass detected")
    elif current == "STAGE_3" and to == "STAGE_4":
        if not env.get("plan_backup_exists", False):
            fail("plan backup missing")
        sc = d.get("gate_data", {}).get("sprint_contract", "")
        if not sc:
            fail("sprint_contract missing from gate_data — declare BEFORE reviewing code (scope+dimensions+failure_conditions+pass_standard)")
        gn = d.get("gate_data", {}).get("gitnexus", {}).get("nodes", "")
        if not gn:
            warn("gitnexus baseline missing — run 'monitor --gitnexus STAGE_3'")
    elif current == "STAGE_4" and to == "STAGE_5":
        if not env.get("merge_check", False):
            fail("PR not merged — feature branch not ancestor of origin/main")
        if not env.get("gn_up_to_date", False):
            warn("GitNexus index stale after merge — run gitnexus analyze before retirement")
    elif current == "STAGE_5" and to == "DONE":
        # T9（2026-10-31 owner 裁定：**DONE 节点保留，只并重复门，不删分支**）：
        #   删分支的代价不是怀旧 —— `(STAGE_5, DONE)` 会落入下面的 `FAIL:unknown transition`，
        #   唯一正常出口变成 `advance --force DONE`；而 force 恰是 monitor/entropy 的软化路径
        #   （见 `_monitor_eval` 与熵门），**把例外变成常态**。另需连带改
        #   `NODE_REGISTRY` / route_map / `state.history` / 文档锚。
        #   去重（本处只删这一条）：`gn_stale` WARN 与 `STAGE_4→5` 的 `gn_up_to_date` WARN 是
        #   **同一检查**（§9.1 的 `gitnexus_fresh` ×3），且 4→5 刚检过、STAGE_5 的职责正是
        #   「gitnexus analyze 终态」（只会让索引变 fresh，不会变 stale）⟹ 纯重复，语义仍由 4→5 承载。
        #   **保留** `plan_backup_exists`：虽与 `STAGE_3→4` 同谓词，但**失败时刻不同** ——
        #   3→4 之后跨两个节点，STAGE_5 期间备份可能被删。11877 臂的「零独有谓词 ≠ 零独有
        #   失败时刻」在此成立（§9.1 只统计谓词，未统计时机），删掉即引入假绿。
        if not env.get("plan_backup_exists", False):
            fail("final plan backup missing")
    else:
        # Unknown transition: WARN under --force, FAIL otherwise (bash L2852-2858)
        if force:
            gates.append(f"WARN:forced transition {current}→{to}")
        else:
            all_ok = False
            gates.append("FAIL:unknown transition")
    return all_ok, gates


# 2026-11-01（T7 容量对齐，计划 §2.3）：20 → **120**（= 20 轮 × 6 臂）。
#   原 20 条 ≈ 3 轮，窗口外证据全靠 journal 承载；120 条 ≈ 20 轮 live 上下文仍可解释。
#   熵窗口与本常量**同源**（`gk_gate_entropy._rejected_window`），禁第二份数字。
REJECTED_CAP = 120
# 2026-11-01（T5，计划 §2.2）：归档改名 **journal** —— 原名 `*-archive.jsonl` 落在卫星
#   `*-archive` 命名空间里（`gk_satellite.KIND_SUFFIX` 认知域），易被当成「可回收的卫星片」；
#   而它是**永不回收的证据**（窗口外事件流），语义必须是 journal 而非 archive。
REJECTED_JOURNAL_SUFFIX = ".rejected-edits-journal.jsonl"
# 旧名**只用于识别与迁移提示**（不自动删、不自动搬：可逆归档唯一入口 = `state --archive-isolated`）。
REJECTED_ARCHIVE_SUFFIX = ".rejected-edits-archive.jsonl"
# 上限按**轮次**定价（计划 §2.2）：软线 ≈100 轮 × 6 臂 ≈ 3MB（超过即 WARN）；硬顶 8MB，
#   超限轮转 `-1`（`-1` 覆盖旧 `-1` ⟹ 总量 ≤ 2×8MB = 16MB，永不无界增长）。
#   2026-11-01（质询臂 b/c）：软线原为死常量（WARN 实际走 HARD*0.8=6.4MB）——已接线；
#   口径同步降级为「**有界保留** ≤2×8MB」，不再声称「永不回收」（`-1` 轮转会销毁旧代际）。
JOURNAL_SOFT_BYTES = 3 * 1024 * 1024
JOURNAL_HARD_BYTES = 8 * 1024 * 1024
_JOURNAL_WARNED = set()      # 进程级：同一文件只告警一次（防刷屏）


def _journal_path(state_file: str) -> str:
    return str(state_file) + REJECTED_JOURNAL_SUFFIX


def _journal_write(state_file: str, payload: str) -> None:
    """单次 `O_APPEND` 写整块（T6）+ 软线 WARN（80% 硬顶）+ 超线轮转 `-1`（T5）。

    原实现逐条 `f.write` 循环（E7：写点不在锁内、多条目可交错）。这里改为**一次** `os.write`
    —— `O_APPEND` 下每次 write 的偏移由内核原子定位，多进程/多线程不会互相覆盖。
    轮转用 `os.replace(journal, journal + "-1")`（原子覆盖旧 `-1`，总量有界）。
    """
    path = _journal_path(state_file)
    size = 0
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    if size and size >= JOURNAL_SOFT_BYTES and path not in _JOURNAL_WARNED:
        _JOURNAL_WARNED.add(path)
        sys.stderr.write("REJECTED_JOURNAL_SOFT_LINE path=%s bytes=%d soft=%d hard=%d\n"
                         % (path, size, JOURNAL_SOFT_BYTES, JOURNAL_HARD_BYTES))
    if size + len(payload.encode("utf-8")) > JOURNAL_HARD_BYTES:
        try:
            os.replace(path, path + "-1")
        except OSError as e:
            sys.stderr.write("REJECTED_JOURNAL_ROTATE_FAILED: %s\n" % e)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.write(fd, payload.encode("utf-8"))
    finally:
        os.close(fd)


def _append_rejected(gd: dict, entry: dict, state_file: str = "") -> int:
    """追加拒绝记录；出窗条目**先落 journal 再截断**（补齐 FIFO 缺失的那半机制，2026-11-01）。

    journal = `<state>.rejected-edits-journal.jsonl`（append-only、永不回收；旧名
    `.rejected-edits-archive.jsonl` 只做**存在性提示**，不自动迁移）。读面仍只看 live 窗口
    （不撑大上下文），审计读面见 `audit --state` 的 `fifo_archives`。返回本次出窗条数。
    """
    rej = gd.setdefault("rejected_edits", [])
    rej.append(entry)
    if len(rej) <= REJECTED_CAP:
        return 0
    evicted = rej[:-REJECTED_CAP]
    rej[:] = rej[-REJECTED_CAP:]
    if state_file:
        _legacy = str(state_file) + REJECTED_ARCHIVE_SUFFIX
        if os.path.exists(_legacy) and _legacy not in _JOURNAL_WARNED:
            _JOURNAL_WARNED.add(_legacy)
            sys.stderr.write(
                "REJECTED_JOURNAL_LEGACY_PRESENT path=%s —— 旧归档未自动迁移"
                "（用 `gatekeeper-cli.sh state --archive-isolated` 可逆搬运；本进程只写新 journal）\n"
                % _legacy)
        payload = "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in evicted)
        try:
            _journal_write(state_file, payload)
        except OSError as e:
            sys.stderr.write("REJECTED_EDITS_JOURNAL_FAILED n=%d: %s\n" % (len(evicted), e))
    return len(evicted)


def _read_previous_rejections(d: dict) -> list:
    """T30: Read rejected_edits buffer — feed back as structured context."""
    rej = d.get("gate_data", {}).get("rejected_edits") or []
    if not rej:
        return []
    out = []
    for r in rej[-5:]:
        v = r.get("violations", []) if isinstance(r.get("violations"), list) else []
        out.append({"stage": r.get("stage", ""), "to_stage": r.get("to_stage", ""),
                    "source": r.get("source", "gates"), "violations": v, "count": len(v)})
    return out


def _eco_prereq_heuristic(d: dict, current: str, state_file: str = "") -> dict:
    """启发式安全网（2026-08-26）：advance 被门禁拦截时检查当前 ECO 阶段的前置产物，
    提示「前置节点是否被跳过」。数据源全部读 state gate_data（不写）：
    - ECO-SCAN  前置: release-check 记录（版本确认）
    - ECO-READ  前置: subagent_history（monitor --subagent 审查）+ gitnexus 基线
    - ECO-EDIT  前置: subagent_history 含 plan-refinement 点检 + adjudicate 裁决
    - ECO-AUDIT 前置: audit --all 记录
    - ECO-DOC   前置: docgen 记录
    """
    gd = d.get("gate_data", {})
    sh = _history_entries(d, state_file)
    hcl = gd.get("human_calibration_log") or []
    lrc = gd.get("last_release_check") or 0
    has_plan_ref = any("plan-refinement" in str(e.get("task", "")) for e in sh)
    # 判据单源（批③ ② 接线统一）：五域 *_result 任一落盘 或 历史形态 audit_result——
    # 与 node_guard ECO-DOC 出口谓词同一事实源（写入侧五域 vs 判据侧单字段双轨已收敛）
    has_audit = audit_all_recorded(gd, state_file)
    checks = {
        "ECO-RESEARCH": [("release_check", bool(lrc), f"last_release_check={lrc}",
                          "先跑 gatekeeper-cli.sh release-check（版本确认，循环 A 触发信号）"),
                         ("subagent_review", bool(sh), f"subagent_history={len(sh)} 条",
                          "先跑 gatekeeper-cli.sh monitor --subagent \"ECO-RESEARCH 交叉审查...\"（写入 subagent_history）"),
                         ("gitnexus_baseline", bool(lrc), "release-check 基线",
                          "先跑 release-check + gitnexus analyze（建立基线）")],
        "ECO-EDIT": [("plan_refinement_checkpoint", has_plan_ref,
                      "subagent_history 含 plan-refinement 点检",
                      "先跑 gatekeeper-cli.sh monitor --subagent \"plan-refinement: <task>\"（写入 subagent_history）"),
                     ("adjudicate", any(str(e.get("stage", "")).startswith("ECO-EDIT") for e in hcl),
                      "human_calibration_log", "先跑 gatekeeper-cli.sh adjudicate --verdicts ... --score ...")],
        "ECO-VERIFY": [("audit_all", has_audit,
                        "audit_all_recorded（有生产者两域 all-of：audit_state_result + audit_docs_result）",
                        "先跑 gatekeeper-cli.sh audit --state --docs")],
        "ECO-DOC": [("docgen", bool(gd.get("doc_budget_history")), "doc_budget_history",
                     "先跑 gatekeeper-cli.sh docgen")],
    }
    missing = [{"item": name, "found": found, "evidence": ev, "hint": h}
               for name, found, ev, h in checks.get(canon_eco(current), []) if not found]
    return {"stage": canon_eco(current),
            "missing": missing,
            "verdict": (f"{len(missing)} 个前置产物缺失 — 前置节点可能被跳过（裸跑防护）"
                        if missing else "前置产物齐全")}


def _monitor_eval(d: dict, current: str, to: str, monitor_json: dict,
                  force: bool, dry_run: bool, critical_only: bool = True,
                  state_file: str = "") -> dict:
    """PRM Monitor **测量面**（M1，2026-10-31 owner 签 §9.3）：只出 advisory/finding，永不阻断。

    与 `_bank_monitor_gate` 拆分（原实现两者合一 ⟹ 审计侧测量直接 `allowed=False`）：
      · 本函数 = 测量/留痕（`gate_data.monitor_history`；`dry_run` 零副作用），返回 advisory；
      · 阻断 = `_bank_monitor_gate`，**只认可复算的确定性量**（`--local` 的 passed/total）；
      · `--api` 的 LLM `overall_score` 只 advisory，不得作终局否决键。
    `critical_only=True`：standard 仅 CRITICAL_TRANSITIONS；False：standing/analysis 任意转换。
    """
    transition = f"{current}→{to}"
    if critical_only and transition not in CRITICAL_TRANSITIONS:
        return None
    if monitor_json is None:
        return None
    score = monitor_json.get("score", 0.5)
    try:
        score_f = float(score)
    except (TypeError, ValueError):
        score_f = 0.5
    if score_f > 0.5:
        return None
    adv = {"stage": current, "transition": to, "score": score_f,
           "mode": monitor_json.get("mode", "local"),
           "advisory": "monitor_low_score", "ts": _now_iso()}
    if not dry_run:
        hist = d.setdefault("gate_data", {}).setdefault("monitor_history", [])
        hist.append({**adv, "forced": bool(force)})
        d["gate_data"]["monitor_history"] = hist[-100:]
    return adv


BANK_MONITOR_BLOCKED = "BANK_MONITOR_BLOCKED"


def _deterministic_monitor_score(monitor_json: dict):
    """只取**可离线复算**的确定性分：`--local` 的 `passed/total`（缺字段回退 score）。

    非 local（`--api` = LLM 语义分）⟹ None ⟹ 银行不动作（advisory only，M1 分权）。
    """
    if not isinstance(monitor_json, dict):
        return None
    if str(monitor_json.get("mode", "")).lower() != "local":
        return None
    passed, total = monitor_json.get("passed"), monitor_json.get("total")
    try:
        if total is not None and int(total) > 0 and passed is not None:
            return int(passed) / int(total)
    except (TypeError, ValueError):
        pass
    try:
        return float(monitor_json.get("score", 0.5))
    except (TypeError, ValueError):
        return 0.5


def _bank_monitor_gate(d: dict, current: str, to: str, monitor_json: dict,
                       force: bool, dry_run: bool, state_file: str = "") -> dict:
    """额度银行**二次确认**（M1）：用确定性量执行阻断；`--api` 分数不参与。

    返回 None（放行）或 block response（`BANK_MONITOR_BLOCKED`）。**事件单写**（2026-11-01）：
    block 与 force 各写**一条** `source="bank"` 事件进 `gate_data.rejected_edits`，以
    `outcome=blocked|forced` 区分（`bank_actions` 不再落盘，改读时投影）。
    `force` = 人类终裁：放行但**仍留 forced 事件**（熵按 `outcome` 过滤，见 gk_gate_entropy）；
    `dry_run`：零副作用但如实返回 block。
    """
    score = _deterministic_monitor_score(monitor_json)
    if score is None or score > 0.5:
        return None
    prev = _read_previous_rejections(d)
    if dry_run:
        return {"allowed": False, "blocked_by_bank": True, "reason": BANK_MONITOR_BLOCKED,
                "monitor_score": score, "monitor_mode": "local", "monitor": monitor_json,
                "previous_rejections": prev,
                "hint": "Deterministic local monitor checks failed (dry-run preview)."}
    gd = d.setdefault("gate_data", {})
    # 2026-11-01（T1/T2 事件单写）：唯一落盘点 = `gate_data.rejected_edits`（语义扩为 gate_events，
    #   本期不改名）。原状是**同一事件三写** —— `bank_actions`（cap 100）恒写 + `rejected_edits`
    #   仅 block 写 ⟹ 两集合不等（force 只进前者，E1/E2）。现改为一事件一条，`outcome` 区分
    #   blocked/forced；`bank_actions` 不再落盘，由 `view_bank_actions(gd)` 读时投影（T3）。
    #   `dry_run` 已在上方早退 ⟹ 零写语义不变（T1 臂 3）。
    event = {"stage": current, "to_stage": to, "source": "bank",
             "outcome": "forced" if force else "blocked",
             "score": score,
             "violations": [] if force else [BANK_MONITOR_BLOCKED],
             "timestamp": _now_iso()}
    _append_rejected(gd, event, state_file)
    if force:
        return None
    hint = (f"Deterministic monitor checks failed (local score {score} <= 0.5). "
            "Fix violations, re-run advance. Or use --force (human override).")
    return {"allowed": False, "blocked_by_bank": True, "reason": BANK_MONITOR_BLOCKED,
            "monitor_score": score, "hint": hint, "monitor_mode": "local",
            "monitor": monitor_json, "previous_rejections": prev,
            "prereq_heuristic": _eco_prereq_heuristic(d, current, state_file)}


# ── 预算解耦（2026-09-23 用户裁定：**梯度×2 + agent 池 additive + 单节点硬顶 16**）──────
# 原状 `edit_budget_max = sched_lr`（1..4）= 「一刀 = 一单位」的**固定计数** ⟹ 多文件批次
# （3 文件 × 2 刀）必然撞顶；实测本节点 `max` 长期靠人工 `state-patch` 抬到 6，**高于梯度
# 天花板 `max_lr=4` ⟹ 梯度被绕过**，且每次抬都往 `overrides[]` 写一条审计噪声。
# 现口径：advance 只给**主 agent 基座** = `current_lr × EDIT_BUDGET_PER_LR`（梯度真正生效）；
# `edit_budget` 在本函数/standing 注入处被**重建**（`agents` 随之丢弃 = 池**随节点重置**）。
# 「+ agent 池 additive」不由本文件计算 —— 池是**派发时**（`gatekeeper-cli.sh`
# `_grant_node_budget`，由 `apply-worktree --code-fix` 调用）按 `current_lr`/coder 追加进
# `max`/`remaining`，依据设计 §4「外包后主 agent 还要验收、收口、修 agent 修坏的地方，
# 手改需求**不降反升**」。两处同用本文件的常量，漂移由
# `scripts/test_gk_dispatch_autofill.py::test_budget_constants_match_advance` 机检。
EDIT_BUDGET_PER_LR = 12     # 每单位调度器梯度折算的编辑额度（梯度 1..4 → 12..48，夹硬顶 24）
# 2026-09-23（用户裁定「先提 PER_LR 额度」）：2 → 4，使梯度能真正用满硬顶 16（原 2 只到 8）。
# 2026-10-22（owner 裁定「基础额度翻倍」）：4 → 8 ⟹ 基线 8，lr≥2 即触硬顶 16。
# 2026-10-23（owner 裁定 A+B+C，承「8 额度 4 刀」复盘）：8 → 12、硬顶 16 → 24、外生上限 24 → 32。
#   依据：本机实测 cosine 长期停在 lr=1 ⟹ 每节点实付 **8**，而一个长 standing 节点实测要碰
#   **10–14 个文件** ⟹ 地板才是瓶颈（不是天花板）。改后 lr 1..4 → 12/24/24/24（+50%）。
#   外部对照（2026-10-23 扫描）：SWE-agent 250 steps/instance、OpenHands 500 iterations、
#   Agents SDK 10 turns、LangGraph 25 steps —— 按「写操作占步数 10–20%」折算约 25–100 次写/任务；
#   本仓 24/节点 × 5 节点 ≈ 120，同量级偏上，不再被地板卡死。
#   两语言同源：CLI 侧 `gatekeeper-cli.sh` 的 `_EDIT_BUDGET_PER_LR` 须同改，
#   漂移由 `test_gk_dispatch_autofill.py::test_budget_constants_match_advance` 机检。
EDIT_BUDGET_HARD_CAP = 24   # 单节点硬顶（设计 §4；2026-10-23 16 → 24，仍 ≤ 外生上限）
# §17.2 外生安全上限（owner 裁定 2026-10-07）：**只夹 env 抬额路径**（① `advance_env`
#   `GATEKEEPER_EDIT_BUDGET`）—— 原状「逐字采用」无上界 ⟹ env 传 999 即得 max=999。
#   2026-10-23（owner「天花板同步小幅上抬」）：24 → 32，与硬顶 24 留 8 的逃生舱余量。
#   ⚠ `gk_route_center.DECLARED_HARD_CAP=24`（计划 META `edit_budget_declared` 的封顶）**不同值**：
#     那是「计划能自我声明多少」的反棘轮，本条是「env 最多抬到多少」的逃生命中上限。两者不再同值。
EDIT_BUDGET_CEILING = 32


def _edit_budget(d: dict, env: dict, dry_run: bool) -> dict:
    """Scheduler edit budget (bash L2880-2943). Mutates d. Returns
    {"remaining":N,"max":N,"used":N} or None if budget exhausted."""
    gd = d.setdefault("gate_data", {})
    sched = gd.get("scheduler")
    if sched is None:
        sched_lr = 4
    else:
        step = sched.get("current_step", 0)
        total = sched.get("total_steps", 0)
        max_lr = sched.get("max_lr", 4)
        min_lr = sched.get("min_lr", 0)
        mode = sched.get("mode", "constant")
        # 2026-09-19 ECC-E05F3517A965（S1-c 后半）：原 `min(step,total)` **饱和** ⟹ step ≥ total
        # 后 t ≡ 1 ⟹ lr 恒 min_lr ⟹ 退火**永久失效**（standing 分支早已改回绕式，此处漏改同一病灶）。
        t = (step % total) / total if total > 0 else 1
        if total <= 1:
            lr = max_lr
        elif mode == "constant":
            lr = max_lr
        elif mode == "linear":
            lr = max_lr + (min_lr - max_lr) * t
        elif mode == "cosine":
            lr = min_lr + 0.5 * (max_lr - min_lr) * (1 + math.cos(math.pi * t))
        elif mode == "autonomous":
            lr = 999
        else:
            lr = max_lr
        sched_lr = max(min_lr, round(lr))
    # 2026-09-23 预算解耦：基座 = 梯度 × 每单位额度，封顶单节点硬顶（agent 池由派发侧追加）。
    edit_budget_max = min(sched_lr * EDIT_BUDGET_PER_LR, EDIT_BUDGET_HARD_CAP)
    # 2026-09-19 ECC-E05F3517A965（S1-c 后半）：`edit_count` 的窗口语义**定为 = 本 R-phase**
    # （对齐本函数返 None 时那句「no more edits in this R-phase」）⟹ 归零点 = `r_phase` 切换。
    # 原状：全仓 `edit_count` **只有读点、没有写点**（`--env-json` 也不传 `edit_used`）⟹ `used` 恒 0、
    # `remaining` 恒 == max ⟹ standard 预算形同虚设（本条即为此登记，2026-09-19 用户裁定本轮就改）。
    # 2026-10-23（A 修复位点，实测）：**仅** `r_phase` 做键无效 —— `gk_advance` 只**读** `r_phase`、
    #   **从不推进**它 ⟹ 同一 phase 内进下一节点时 `remaining = max − edit_count` ≤ 0 ⟹ 直接
    #   return None ⟹ 额度耗尽后 advance 救不回来（只能手工 state-patch，绕过梯度）。
    #   现改为 `(r_phase, stage)` 复合键：进新节点 = 新窗口。
    #   ⚠ `_edit_budget` 的调用点在 `d["stage"] = to` **之后** ⟹ 读到的已是**目标节点**，无 off-by-one。
    #   ⚠ 范围：standing 轨不经本函数（其注入面无条件重建 `used=0`），本条只钉 standard 轨。
    _phase = "%s@%s" % (str(d.get("r_phase") or ""), str(d.get("stage") or ""))
    if gd.get("edit_count_phase") != _phase:
        gd["edit_count_phase"] = _phase
        gd["edit_count"] = 0
    edit_used = env.get("edit_used", 0)
    if not isinstance(edit_used, int):
        try:
            edit_used = int(edit_used or 0)
        except (TypeError, ValueError):
            edit_used = 0
    if edit_used <= 0:
        edit_used = gd.get("edit_count", 0)
    edit_remaining = max(0, edit_budget_max - edit_used)
    gd["edit_count"] = edit_used
    # 2026-09-19：`overrides` 是**跨节点台账**（同 S1-b 在 standing 侧修的病灶）—— 整字典赋值会
    # 连带抹掉它；此处显式带过。
    gd["edit_budget"] = {"max": edit_budget_max, "used": edit_used,
                         "remaining": edit_remaining,
                         "overrides": list((gd.get("edit_budget") or {}).get("overrides") or [])}
    if edit_remaining <= 0 and not dry_run:
        return None
    # Budget passes — increment scheduler step
    if sched is not None and not dry_run:
        sched["current_step"] = sched.get("current_step", 0) + 1
        step = sched["current_step"]
        total = sched.get("total_steps", 0)
        max_lr = sched.get("max_lr", 4)
        min_lr = sched.get("min_lr", 0)
        mode = sched.get("mode", "constant")
        t = (step % total) / total if total > 0 else 1
        if total <= 1:
            lr = max_lr
        elif mode == "constant":
            lr = max_lr
        elif mode == "linear":
            lr = max_lr + (min_lr - max_lr) * t
        elif mode == "cosine":
            lr = min_lr + 0.5 * (max_lr - min_lr) * (1 + math.cos(math.pi * t))
        elif mode == "autonomous":
            lr = 999
        else:
            lr = max_lr
        sched["current_lr"] = max(min_lr, round(lr))
        d["gate_data"]["scheduler"] = sched
    return {"remaining": edit_remaining, "max": edit_budget_max, "used": edit_used}


# ────────────────────────────────────────────────────────────────────
# Main flow
# ────────────────────────────────────────────────────────────────────

def _run(state_file: str, to_stage: str, force: bool, dry_run: bool,
         env: dict, monitor_json: dict, cc: dict, remote: str,
         skill_dir: str) -> dict:
    if not to_stage:
        return {"error": "to_stage required"}
    if not Path(state_file).exists():
        return {"allowed": False, "reason": "No state file"}

    # Cross-review: verify state file integrity before any gate checks
    cs = _verify_checksum(state_file)
    if "error" in cs:
        hint = ("checksum mismatch — 诊断：若为隔离 state（discover --plan）且刚跑过 subagent，"
                "可能是写入竞态，用 'state' 查看内容；确认未被外部修改后可："
                "python3 scripts/gk_state.py --checksum-recalc 或删除隔离 state 后重新 discover --plan。"
                "禁止直接改 _checksum 字段绕过门禁。")
        return {"allowed": False, "reason": cs["error"], "hint": hint}

    d = _load_state(state_file)
    if "error" in d:
        return {"allowed": False, "reason": f"STATE_FILE_UNREADABLE ({d['error']})"}

    current_stage = d.get("stage", "IDLE")
    branch = d.get("branch", "")
    worktree = d.get("worktree", "")

    # Cross-review: empty worktree/branch guards
    if not worktree:
        return {"allowed": False, "reason": "EMPTY_WORKTREE"}
    if not branch:
        return {"allowed": False, "reason": "EMPTY_BRANCH"}

    ptype = _project_type(state_file)

    # 2026-08-27 序列节点安全网：节点注册校验（修复 advance 任意未知节点全放行 bypass）
    # 已知节点 = NODE_REGISTRY（ECO-*/STAGE_n/DONE/RED-*/AUDIT-*）+ ECC-* 通配。
    # 未知节点 → 硬阻断（防状态机污染 + 无车站播报）。
    reg = _registered_node(to_stage)
    if not reg.get("ok"):
        return {"ok": False, "error": reg["error"],
                "known": reg.get("known_routes"),
                "hint": "序列节点安全网：未知节点未注册 — 用 gk_node_guard register 校验节点名，或走已注册路线节点"}

    if ptype != "standard":
        return _run_nonstandard(d, state_file, current_stage, to_stage, force,
                                dry_run, cc, remote, ptype, monitor_json, skill_dir)
    return _run_standard(d, state_file, current_stage, to_stage, force, dry_run,
                         env, monitor_json, ptype)


def _registered_node(to_stage: str) -> dict:
    """节点注册校验：to_stage ∈ 注册节点（gk_node_guard.NODE_REGISTRY）或通配前缀。

    2026-10-28（A4）：旧 ECO 站名先归一（`ECO-SCAN/ECO-READ→ECO-RESEARCH`、
    `ECO-AUDIT→ECO-VERIFY`）再查注册表 ⟹ 历史调用面不因站名合并而 UNKNOWN_NODE。
    """
    to_stage = canon_eco(to_stage)
    try:
        from gk_node_guard import register_check
        r = register_check(to_stage)
        if r.get("ok"):
            return {"ok": True, "node": r["node"]}
    except ImportError:
        pass  # gk_node_guard 缺失 → 退化到内建前缀表
    if to_stage.startswith("ECC-"):
        return {"ok": True, "node": {"id": to_stage, "route": "analysis"}}
    if to_stage.startswith(("AUDIT-", "RED-")):
        return {"ok": True, "node": {"id": to_stage, "route": to_stage.split("-")[0].lower()}}
    if to_stage in ("STAGE_0", "STAGE_1", "STAGE_2", "STAGE_3", "STAGE_4", "STAGE_5", "DONE"):
        return {"ok": True, "node": {"id": to_stage, "route": "standard"}}
    return {"ok": False, "error": f"UNKNOWN_NODE: '{to_stage}' 未注册",
            "known_routes": {"standing": ["ECO-RESEARCH","ECO-EDIT","ECO-VERIFY","ECO-DOC"],
                             "standard": ["STAGE_0","STAGE_1","STAGE_2","STAGE_3","STAGE_4","STAGE_5","DONE"],
                             "red": ["RED-SCOPE","RED-SURFACE","RED-CONSTRAINTS","RED-EXPLOIT","RED-POSTEX","RED-REPORT","RED-HINT","RED-HOOK","RED-PY","RED-POISON","RED-REGISTRY","RED-GHOST","RED-COVERAGE","RED-DIFF","RED-INTEGRITY"],
                             "audit": ["AUDIT-STATE","AUDIT-MEMORY","AUDIT-CROSSR","AUDIT-REPORT"],
                             "analysis": ["ECC-*"]}}


BUDGET_LOG_SUFFIX = ".budget-log.jsonl"


def budget_log_append(state_file: str, source: str, reason: str = "", eb: dict = None) -> None:
    """REV-3 §12.7 / REV-5 §13.3：提额**旁挂账本**（append-only）—— 熵第三支 / audit 的**唯一可靠测量面**。

    2026-09-30 owner 裁定 C1–C4：读写**单源**归 `scripts/gk_budget_ledger.py`
    （C1 `kind` 就地过滤 / C2 封印 `seal` / C3 fail-loud / C4 坏行不计入）。
    本函数**保留签名**（advance 调用面不变），只做**委托**；失败落 `GK_DBG_LOG`，**不再静默**（C3）。
    """
    try:
        import sys as _sys
        _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from gk_budget_ledger import append as _append
        _out = _append(state_file, source, reason, eb=eb)
        if not _out.get("ok"):
            _log = os.environ.get("GK_DBG_LOG", "")
            if _log:
                try:
                    with open(_log, "a", encoding="utf-8") as _f:
                        _f.write("%s budget-ledger-append-failed: %s\n"
                                 % (datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                    _out.get("error")))
                except OSError:
                    pass
    except Exception:
        pass


def _resolve_declared_budget(skill_dir: str, env: dict) -> int:
    """C1：从**当前计划 META** 读 `edit_budget_declared`（缺省 0）。

    自举（§3 T1″）：全程走 **python** 路径（`gk_state_route.select_plan_pointer` →
    `gk_route_center.resolve_plan` → `declared_from_meta`），**不经 `gatekeeper-cli.sh`**。
    kill switch `GK_EDIT_BUDGET_DECL=0` ⟹ 恒 0（关闭态逐字退回现状注入）。
    任何异常 ⟹ 0（fail-soft：读不到即视为未声明）。
    """
    if str((env or {}).get("GK_EDIT_BUDGET_DECL", "1")).strip() == "0":
        return 0
    try:
        import gk_state_route
        import gk_route_center
        pp = gk_state_route.select_plan_pointer(str(skill_dir))
        if not pp.get("followed"):
            return 0
        rp = gk_route_center.resolve_plan(plan_file=str(pp.get("plan") or ""),
                                         skill_dir=str(skill_dir))
        return gk_route_center.declared_from_meta(rp.get("meta") or {})
    except Exception:
        return 0


def _run_nonstandard(d: dict, state_file: str, current: str, to: str,
                     force: bool, dry_run: bool, cc: dict, remote: str,
                     ptype: str, monitor_json: dict, skill_dir: str = "") -> dict:
    # 2026-10-28（A4 收尾）：入站先归一到 4 站规范名——否则 alias advance 会把旧站名
    #   写回 state（d["stage"] / eco_completions 键）并绕过按规范名比较的门禁。
    current, to = canon_eco(current), canon_eco(to)
    # I2: appeal_required gate — checked BEFORE any ECO/ECC ordering gates
    appeal_req = _check_appeal(d)
    if appeal_req.startswith("blocked:") or appeal_req.startswith("denied:"):
        if not force:  # --force：人类终裁放行（2026-08-31 RED-DIFF standing 质询定案）
            return _appeal_block_response(appeal_req, to)
        _clear_appeal_block(d, to)  # force 放行：清除 appeal 阻塞标记，防下次 advance 重复拦截
    elif appeal_req.startswith("dangling:"):
        pass  # appeal filed but not yet judged — allow with caution
    elif appeal_req not in ("resolved", "clear"):
        return _appeal_block_response(appeal_req, to)

    # I6: ECO→ECC cross-type boundary protection
    boundary = _eco_ecc_boundary(current, to)
    if not boundary.get("ok"):
        return {"ok": False, "error": boundary["error"],
                "prereq_heuristic": _eco_prereq_heuristic(d, current, state_file)}

    # R2b: ECO phase sequential ordering gate
    seq = _eco_sequence(current, to)
    if not seq.get("ok"):
        return {"ok": False, "error": seq["error"], "sequence": seq.get("sequence"),
                "prereq_heuristic": _eco_prereq_heuristic(d, current, state_file)}

    # ECO-RESEARCH（旧 ECO-READ）→ ECO-EDIT must have plan-refinement subagent checkpoint
    # (2026-08-24: standing 常驻序列豁免 —— 该门禁是计划质询专用，standing 是
    # 常驻治理序列，非计划质询，不应强制 plan-refinement 点检)
    if canon_eco(current) == "ECO-RESEARCH" and canon_eco(to) == "ECO-EDIT" and ptype != "standing":
        pr = _plan_ref_checkpoint(d, state_file)
        if pr != "plan-refinement":
            return {"ok": False,
                    "error": "ECO-READ → ECO-EDIT requires plan-refinement subagent checkpoint. Run: gatekeeper-cli.sh monitor --subagent \"plan-refinement: <task>\"",
                    "hint": "计划质询门禁：必须先执行 plan-refinement subagent 点检（写入 subagent_history）才能推进 ECO-EDIT",
                    "subagent_checkpoint": pr,
                    "prereq_heuristic": _eco_prereq_heuristic(d, current, state_file)}

    # 裁决门禁: ECO-EDIT → ECO-VERIFY（旧 ECO-AUDIT）强制要求 adjudicate
    if canon_eco(current) == "ECO-EDIT" and canon_eco(to) == "ECO-VERIFY":
        adj = _check_adjudicate(d, ptype)
        if adj != "ok":
            return {"ok": False,
                    "error": "ECO-EDIT → ECO-AUDIT requires adjudicate first. Run: adjudicate --verdicts '{\"F1\":\"PASS\",...}' --score <0.0-1.0> --decision '...' --impact <file>",
                    "hint": "adjudicate --verdicts '{\"F1\":\"PASS\",\"F2\":\"WARN\",\"F3\":\"PASS\",\"F4\":\"PASS\",\"F5\":\"WARN\",\"F6\":\"PASS\",\"F7\":\"PASS\"}' --score 0.90 --decision 'WARN: upgrade with verification' --impact references/ecc-impact-*.md",
                    "adj_reason": adj,
                    "prereq_heuristic": _eco_prereq_heuristic(d, current)}

    # P3-Incremental: ECC phase advance
    if current.startswith("ECC-") and to.startswith("ECC-"):
        ecc = _ecc_incremental(d, current)
        if ecc == "missing":
            return {"ok": False, "error": "ECC-* transition requires adjudicate first. Run: adjudicate --verdicts '...' --score <0.0-1.0> --decision '...'"}
        if ecc == "needs_incremental":
            return {"ok": False, "error": "ECO already passed — ECC needs incremental assessment only. Run: adjudicate --verdicts '{\"impact\":\"PASS\"}' --score <0.0-1.0> --decision 'incremental' --change-items <N> --constraint-level H1"}
        if ecc.startswith("stage_mismatch:"):
            mismatch_stage = ecc[len("stage_mismatch:"):]
            return {"ok": False, "error": f"ECC adjudicate stage mismatch: submitted for {mismatch_stage} but current is {current}"}
        if ecc == "stale_adjudicate":
            return {"ok": False, "error": "ECC adjudicate timestamp is before ECO-EDIT completed_at — stale adjudicate not accepted"}

    # R4: Entropy monitor — >0.5 → block advance (hard stop, force human adjudicate)
    # --force：人类终裁放行，熵硬阻断降级为 WARN 注入（2026-08-31 RED-DIFF standing 质询定案）
    entropy_rate, _ent_err = _entropy_guard(d, current, state_file)
    if _ent_err is not None:
        return _ent_err
    _entropy_forced = False  # force 放行时 history 已记录，跳过后续无条件 append（防双记录）
    if _entropy_enforced(entropy_rate, _compute_entropy(d, current)):
        if force:
            _entropy_forced = True
            gd = d.setdefault("gate_data", {})
            gd["entropy_rate"] = entropy_rate
            gd.setdefault("entropy_history", []).append({
                "rate": entropy_rate, "stage": current, "transition": to,
                "ts": _now_iso(), "forced": True})
            gd["entropy_history"] = gd["entropy_history"][-100:]
        else:
            _mark_appeal_block(d, to, entropy_rate)
            if not dry_run:
                _write_state(state_file, d)
            return _entropy_block_response(entropy_rate, to)
    _credit = _credit_floor_eval(d, state_file)
    _baseline = _credit.get("baseline") or {}
    if _credit.get("score_delta") is not None:
        d.setdefault("gate_data", {})["credit_score_delta"] = _credit["score_delta"]
    if _baseline.get("drift") or _credit.get("hit"):
        hist = d.setdefault("gate_data", {}).setdefault("credit_advisories", [])
        hist.append({"code": ("ECON_BASELINE_DRIFT" if _baseline.get("drift")
                              else "CREDIT_FLOOR_HIT"),
                     "score_delta": _credit.get("score_delta"),
                     "threshold": _credit.get("threshold"),
                     "source": _baseline.get("source", ""), "ts": _now_iso()})
        d["gate_data"]["credit_advisories"] = hist[-50:]
        if _credit.get("hit") and os.environ.get("GK_CREDIT_FLOOR_ENFORCE", "0") == "1":
            return {"ok": False, "allowed": False, "error": "CREDIT_FLOOR_HIT",
                    "score_delta": _credit.get("score_delta"),
                    "threshold": _credit.get("threshold"),
                    "hint": "相对激活基线的信用分已跌到 −N；修复后重试，或由 owner 走人工解锁"}
    elif _credit.get("advisory"):
        d.setdefault("gate_data", {})["credit_floor"] = {
            "advisory": _credit["advisory"], "source": _baseline.get("source", ""),
            "ts": _now_iso()}
    d.setdefault("gate_data", {})["entropy_rate"] = entropy_rate

    # Phase 7a (2026-08-23): PRM Monitor 主动阻断 — standing/analysis 分支
    # bash cmd_advance 已收集 monitor_json（熵驱动模式切换 + CRITICAL_STAGES 路由）。
    # critical_only=False：standing 无 STAGE_0-5 转换白名单，任意 advance 触发。
    # M1（2026-10-31 owner 签 §9.3）：测量面只出 advisory/finding（审计侧）；
    # 阻断由额度银行**二次确认**执行，且只认确定性量（--local passed/total；--api 不参与）。
    _monitor_eval(d, current, to, monitor_json, force, dry_run,
                  critical_only=False, state_file=state_file)
    bank_block = _bank_monitor_gate(d, current, to, monitor_json, force, dry_run,
                                    state_file=state_file)
    if bank_block is not None:
        if not dry_run:
            _write_state(state_file, d)
        return bank_block

    # F-15: entropy history — append trend snapshot（force 放行已记录，不重复）
    if not _entropy_forced:
        gd = d.setdefault("gate_data", {})
        gd.setdefault("entropy_history", []).append({
            "rate": entropy_rate, "stage": current, "transition": to,
            "ts": _now_iso()})
        gd["entropy_history"] = gd["entropy_history"][-100:]

    # F-15: check-changes doc budget monitor (non-blocking WARN injection)
    cc_warn = ""
    if cc and cc.get("push_needed"):
        doc_changes = cc.get("doc_changes", 0)
        ent = cc.get("entropy_rate")
        gd["doc_change_warn"] = f"doc_changes={doc_changes},entropy={ent},threshold=2"
        gd.setdefault("doc_budget_history", []).append({
            "doc_changes": doc_changes, "entropy_rate": ent, "threshold": 2,
            "stage": current, "ts": _now_iso()})
        gd["doc_budget_history"] = gd["doc_budget_history"][-100:]
        cc_warn = (f"{doc_changes} uncommitted doc changes "
                   f"(entropy={ent}) — consider committing and pushing to reduce entropy pressure")

    # P0 ledger (2026-09-07 b1g, ㊴/㊵ 收敛缺省): standing 审查节点出口完整性——
    # ECO-VERIFY→ECO-DOC = standing 交叉审查出口（ECO-VERIFY 是 standing 审查节点，runbook
    # L1-L10 全量 + audit --all 之后才可出站）。谓词单源 = gk_node_guard.review_exit_gate
    # （合并 C5 出站守卫，防节点绕过/只跑部分审查就出站）；证据全部从 state 确定性提取
    # （agent 不自证）。GK_GUARD_STRICT=1 → 硬阻断；默认 advisory（ok 仍放行，附 ledger 供核对，
    # 与 standard STAGE_3→STAGE_4 C5 的 strict 二分语义一致）。
    # 2026-10-28（A4 回归修复）：原写死 `current == "ECO-AUDIT"`，站名压缩为 4 站后规范路径
    #   （stage=ECO-VERIFY）恒不命中 ⟹ 门禁静默失效。改用 canon_eco 归一（旧名仍可用）；
    #   同时把 state_file 传给 review_exit_gate，接 B3b 双读。
    _led = None
    if ptype == "standing" and canon_eco(current) == "ECO-VERIFY" and to == "ECO-DOC":
        try:
            from gk_node_guard import review_exit_gate  # 同 scripts 目录，延迟导入防耦合
            _led = review_exit_gate("ECO-DOC", d.get("gate_data", {}), state_file)
        except Exception:
            _led = None  # gk_node_guard 缺失 → 降级：不阻断（与 node_guard 缺失降级先例一致）
        if _led is not None and not _led.get("ok") and os.environ.get("GK_GUARD_STRICT", "") == "1":
            return {"ok": False, "error": "ECO-VERIFY → ECO-DOC review ledger 不齐 (P0)",
                    "ledger": _led,
                    "hint": "补齐 ledger missing 项后重试（审查 ≥2 轮 + 轮间红队 + audit --all 记录）；"
                            "或 GK_GUARD_STRICT=0 降级 advisory 核对后推进"}

    # State write: stage transition + eco_completions
    d["stage"] = to
    eco = d.setdefault("gate_data", {}).setdefault("eco_completions", {})
    eco[current] = {"completed_at": _now_iso(), "transitioned_to": to}

    # 2026-08-31 优化器接线修复（standing 分支）：ECO 周期推进 cosine 调度器
    # 原缺失——_edit_budget 只在 _run_standard 调用，standing 五节点永不推进
    # scheduler.step → cosine 退火失效（用户质询"优化器失效/未接线"根因）。
    # standing 是常驻治理序列：不设 edit_budget 硬上限（pre-tool-check 读 -1 不阻断），
    # 但 current_step/current_lr 必须随 ECO 周期推进（对齐 total_steps=6 五节点+回绕）。
    gd = d.setdefault("gate_data", {})
    sched = gd.get("scheduler")
    if sched is not None and not dry_run:
        sched["current_step"] = sched.get("current_step", 0) + 1
        _step = sched["current_step"]
        _total = sched.get("total_steps", 0)
        _max_lr = sched.get("max_lr", 4)
        _min_lr = sched.get("min_lr", 0)
        _mode = sched.get("mode", "constant")
        if _total <= 1:
            _lr = _max_lr
        else:
            # 回绕（2026-09-01 落地"10 minor 剩余项：scheduler 无回绕"）：
            # standing 常驻序列循环推进，step 每 _total 重置 → cosine 退火每周期重来。
            # 原 min(step,total) 饱和 → step ≥ total 后恒 cos(π)=min_lr（退火永久失效）。
            _t = (_step % _total) / _total
            if _mode == "constant":
                _lr = _max_lr
            elif _mode == "linear":
                _lr = _max_lr + (_min_lr - _max_lr) * _t
            elif _mode == "cosine":
                _lr = _min_lr + 0.5 * (_max_lr - _min_lr) * (1 + math.cos(math.pi * _t))
            elif _mode == "autonomous":
                _lr = 999
            else:
                _lr = _max_lr
        sched["current_lr"] = max(_min_lr, round(_lr))
        gd["scheduler"] = sched

    # 2026-09-07 P2 (ECC-E75A3C2E8FE6, ㊴/㊵ 收敛缺省): standing 编辑预算 enforcement 注入
    # standing 节点预算 = 调度器 current_lr（SkillOpt cosine 退火，上限 max_lr=4）；
    # GATEKEEPER_EDIT_BUDGET 显式覆盖。advance 进入新节点即重置 remaining——
    # 随后每次 pre-tool-check edit 放行经 CLI state-patch(flock) 扣 1（bash 侧消费）。
    # 仅 standing 且非 dry_run 注入（dry_run 零副作用；standard 走 _edit_budget 语义不变）。
    if ptype == "standing" and not dry_run:
        _ov = os.environ.get("GATEKEEPER_EDIT_BUDGET", "").strip()
        try:
            _lr = int(gd.get("scheduler", {}).get("current_lr", 4))
        except (TypeError, ValueError):
            _lr = 4
        # 2026-09-23 预算解耦（用户裁定「梯度×2 + agent 池 additive」）：
        #   无 env 覆盖 → `current_lr × EDIT_BUDGET_PER_LR`（梯度 1..4 → 8..32，夹硬顶 16；
        #   2026-10-22 owner 裁定基础额度翻倍后 lr≥2 即触硬顶），封顶单节点硬顶；
        #   `GATEKEEPER_EDIT_BUDGET` 显式覆盖 → 人工逃生舱 + **§17.2 外生夹取**
        #   （`min(候选, EDIT_BUDGET_CEILING=24)`；候选 ≤24 时语义与旧「逐字采用」等价 ——
        #   `test_gk_edit_budget_overrides::test_advance_override_persists_ledger` 的 max==6 契约仍成立）。
        # REV-3（2026-09-28，owner 裁定 D1=C1）：无 env 覆盖时，C1 计划 META `edit_budget_declared`
        #   优先 —— 权威式子 `max = max(declared, min(current_lr × PER_LR, HARD_CAP))`；
        #   其中 `HARD_CAP=16` **只夹 `current_lr` 项**，`declared` 独立封顶 24（可达 24）。
        if _ov:
            try:
                _budget = int(_ov)
            except (TypeError, ValueError):
                _budget = _lr * EDIT_BUDGET_PER_LR
            # §17.2 外生安全上限（owner 裁定 2026-10-07）：env 抬额路径**夹取**——
            #   原状「逐字采用」无上界（env=999 ⟹ max=999），现 min(候选 max, EDIT_BUDGET_CEILING)。
            #   回落分支（int(_ov) 抛错）同样夹取，防两条子路径口径分裂。
            _budget = min(max(1, _budget), EDIT_BUDGET_CEILING)
        else:
            _declared = _resolve_declared_budget(skill_dir, os.environ)
            _budget = max(1, max(_declared,
                                 min(_lr * EDIT_BUDGET_PER_LR, EDIT_BUDGET_HARD_CAP)))
        # 2026-09-19 P5 §3 T5′ / 计划次序 S1-b：覆盖留痕（注入侧）
        # ① `overrides[]` 是**跨节点台账**（记「哪些节点用过逃生舱、抬到多少」），不是本节点预算的
        #    组成部分 ⟹ advance 重置 remaining 时必须显式带过去。原写法是整字典赋值 ⟹ 连带抹掉台账
        #    （实测：既有一条 state_patch 记录在 advance 后被丢成 []）。
        # ② 仅在 `GATEKEEPER_EDIT_BUDGET` **显式生效**时追加一条：未设该 env 时 `_budget` 取自
        #    scheduler，属「未声明批次」的正常路径而非覆盖事件（否则每节点刷一条，cap=20 窗口全噪声）。
        _ov_ledger = list(gd.get("edit_budget", {}).get("overrides") or [])
        # REV-3 §4 J8：`used_total` = **跨节点累计**（前值 + 本节点已用），单调不减；`used` 每节点归零。
        _prev_eb = gd.get("edit_budget") or {}
        try:
            _used_total = int(_prev_eb.get("used_total") or 0) + int(_prev_eb.get("used") or 0)
        except (TypeError, ValueError):
            _used_total = 0
        gd["edit_budget"] = {"max": _budget, "used": 0, "remaining": _budget,
                             "used_total": _used_total, "overrides": _ov_ledger}
        if _ov:
            # 2026-09-30 G4-e（REV-5 §13.3）：`overrides[]` 降**只读遗留** ⟹ 不再 append（只保留既有值，
            #   见上「_ov_ledger 是跨节点台账」注释）；提额留痕**唯一写入面** = 旁挂 append-only 账本。
            # REV-3 §12.7：注入侧提额（source=advance_env）同步进**旁挂账本**（append-only）。
            budget_log_append(state_file, "advance_env",
                              "GATEKEEPER_EDIT_BUDGET=%s" % _ov, gd["edit_budget"])

    # AUDIT phase ordering enforcement
    audit_gate = _audit_order(d, to)
    if not audit_gate.get("ok"):
        return {"ok": False, "error": audit_gate["error"]}

    if not dry_run:
        _write_state(state_file, d)

    # Hint 数据（bash 侧合并 achievements/audit_result/red_*/i9/auto_audit）
    hint, extras = _hint_for(to, d, cc, remote, current)
    result = {"ok": True, "from": current, "to": to, "mode": "direct",
              "project_type": ptype, "hint": hint}
    result.update(extras)
    # C2③（ECC-75DAED1C537C，2026-09-28）：两腿**只读体积门** —— advance 结果带出占比/余量
    #   （含 warn），防「撞墙才发现」。口径同 gk_json_utils.canon_bytes。
    result["state_size"] = two_legs_report(state_file)
    if cc_warn:
        result["doc_budget_warn"] = cc_warn
    if _led is not None and not _led.get("ok"):
        result["ledger_advisory"] = _led  # P0：默认 advisory（strict=1 已在上方硬阻断）
    return result


def _run_standard(d: dict, state_file: str, current: str, to: str,
                  force: bool, dry_run: bool, env: dict, monitor_json: dict,
                  ptype: str) -> dict:
    # I2: appeal_required gate
    appeal_req = _check_appeal(d)
    if appeal_req.startswith("blocked:") or appeal_req.startswith("denied:"):
        if not force:  # --force：人类终裁放行（2026-08-31 RED-DIFF standing 质询定案）
            return _appeal_block_response(appeal_req, to)
        _clear_appeal_block(d, to)  # force 放行：清除 appeal 阻塞标记，防下次 advance 重复拦截
    elif not appeal_req.startswith("dangling:") and appeal_req not in ("resolved", "clear"):
        return _appeal_block_response(appeal_req, to)

    # R4: entropy 硬阻断 (standard: rejected_edits 数据源)
    # --force：人类终裁放行，熵硬阻断降级为 WARN 注入（2026-08-31 RED-DIFF standing 质询定案）
    entropy_rate, _ent_err = _entropy_guard(d, current, state_file)
    if _ent_err is not None:
        return _ent_err
    if _entropy_enforced(entropy_rate, _compute_entropy(d, current)):
        if force:
            gd = d.setdefault("gate_data", {})
            gd["entropy_rate"] = entropy_rate
            gd.setdefault("entropy_history", []).append({
                "rate": entropy_rate, "stage": current, "transition": to,
                "ts": _now_iso(), "forced": True})
            gd["entropy_history"] = gd["entropy_history"][-100:]
        else:
            _mark_appeal_block(d, to, entropy_rate)
            if not dry_run:
                _write_state(state_file, d)
            return _entropy_block_response(entropy_rate, to)
    _credit = _credit_floor_eval(d, state_file)
    _baseline = _credit.get("baseline") or {}
    if _credit.get("score_delta") is not None:
        d.setdefault("gate_data", {})["credit_score_delta"] = _credit["score_delta"]
    if _baseline.get("drift") or _credit.get("hit"):
        hist = d.setdefault("gate_data", {}).setdefault("credit_advisories", [])
        hist.append({"code": ("ECON_BASELINE_DRIFT" if _baseline.get("drift")
                              else "CREDIT_FLOOR_HIT"),
                     "score_delta": _credit.get("score_delta"),
                     "threshold": _credit.get("threshold"),
                     "source": _baseline.get("source", ""), "ts": _now_iso()})
        d["gate_data"]["credit_advisories"] = hist[-50:]
        if _credit.get("hit") and os.environ.get("GK_CREDIT_FLOOR_ENFORCE", "0") == "1":
            return {"ok": False, "allowed": False, "error": "CREDIT_FLOOR_HIT",
                    "score_delta": _credit.get("score_delta"),
                    "threshold": _credit.get("threshold"),
                    "hint": "相对激活基线的信用分已跌到 −N；修复后重试，或由 owner 走人工解锁"}
    elif _credit.get("advisory"):
        d.setdefault("gate_data", {})["credit_floor"] = {
            "advisory": _credit["advisory"], "source": _baseline.get("source", ""),
            "ts": _now_iso()}
    d.setdefault("gate_data", {})["entropy_rate"] = entropy_rate

    # T30: Read rejected_edits buffer
    previous_rejections = _read_previous_rejections(d)

    # --- PRM Monitor（M1）：测量面 advisory + 银行确定性二次确认 ---
    _monitor_eval(d, current, to, monitor_json, force, dry_run,
                  state_file=state_file)
    bank_block = _bank_monitor_gate(d, current, to, monitor_json, force, dry_run,
                                    state_file=state_file)
    if bank_block is not None:
        if not dry_run:
            _write_state(state_file, d)
        return bank_block

    # --- Structural Gate Checks ---
    all_ok, gates = _structural_gates(current, to, d, env, force)

    # Batch 4: Advance gate log — record gate results for D8 replay
    gd = d.setdefault("gate_data", {})
    gl = gd.setdefault("_advance_log", [])
    gl.append({"timestamp": _now_iso(), "to_stage": to, "all_ok": all_ok,
               "gates_count": len(gates),
               "entropy_rate": max(0.0, min(1.0, entropy_rate))})
    if len(gl) > 10:
        gl[:] = gl[-10:]

    budget = None
    if all_ok:
        budget = _edit_budget(d, env, dry_run)
        if budget is None:
            # edit_budget was already written to d (bash L2913 writes before check)
            eb = d.get("gate_data", {}).get("edit_budget", {})
            all_ok = False
            gates.append(f"FAIL:edit_budget exhausted ({eb.get('used', '?')}/{eb.get('max', '?')}) — no more edits in this R-phase")

    if not all_ok:
        violation_items = [g[len("FAIL:"):] for g in gates if g.startswith("FAIL:")]
        if not dry_run:
            # T30: Rejected-Edit Buffer — record violations on failure
            if violation_items:
                if _append_rejected(d.setdefault("gate_data", {}), {
                        "stage": current, "to_stage": to,
                        "violations": violation_items,
                        "score": None, "source": "gate",
                        "timestamp": _now_iso()}, state_file) > 0:
                    d["gate_data"]["needs_analysis"] = True
            _write_state(state_file, d)
        fail_count = sum(1 for g in gates if g.startswith("FAIL:"))
        return {"allowed": False, "transition": f"{current}→{to}", "stage": current,
                "fail_count": fail_count, "violations": violation_items,
                "previous_rejections": previous_rejections}

    if dry_run:
        return {"allowed": True, "check_only": True, "transition": f"{current}→{to}",
                "stage": current, "fail_count": 0, "violations": [],
                "previous_rejections": previous_rejections}

    # Success: write stage transition (sed+mv 等价) + checksum
    d["stage"] = to
    _write_state(state_file, d)
    return {"allowed": True, "transition": f"{current}→{to}", "stage": to,
            "edit_budget": {"max": budget["max"], "used": budget["used"],
                            "remaining": budget["remaining"]},
            "previous_rejections": previous_rejections}


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(json.dumps({"error": "to_stage required"}))
        return 1
    to_stage = ""
    dry_run = False
    force = False
    state_file = os.environ.get("STATE_FILE", "")
    skill_dir = os.environ.get("SKILL_DIR", "")
    env = {}
    monitor_json = None
    cc = {}
    remote = "unknown"
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--check":
            dry_run = True
        elif a == "--force":
            force = True
        elif a == "--state-file" and i + 1 < len(args):
            state_file = args[i + 1]
            i += 1
        elif a == "--skill-dir" and i + 1 < len(args):
            skill_dir = args[i + 1]
            i += 1
        elif a == "--env-json" and i + 1 < len(args):
            try:
                env = json.loads(args[i + 1])
            except json.JSONDecodeError:
                env = {}
            i += 1
        elif a == "--monitor-json" and i + 1 < len(args):
            try:
                monitor_json = json.loads(args[i + 1])
            except json.JSONDecodeError:
                monitor_json = None
            i += 1
        elif a == "--cc-json" and i + 1 < len(args):
            try:
                cc = json.loads(args[i + 1])
            except json.JSONDecodeError:
                cc = {}
            i += 1
        elif a == "--remote-json" and i + 1 < len(args):
            remote = args[i + 1]
            i += 1
        else:
            to_stage = a
        i += 1

    if "--skill-dir" not in args and skill_dir:
        # C 层收口（2026-09-02）：状态机判定/写入入口直接受 env SKILL_DIR 注入面威胁
        # （python3 gk_advance.py + env SKILL_DIR=/tmp/evil → 判定与状态写入落在攻击者目录）。
        # 复用路由中枢信任门（内容特征 + git 锚定）——不可信 → 回退 __file__ 推导默认（fail-closed）。
        from gk_route_center import _skill_dir_env_trusted
        if not _skill_dir_env_trusted(skill_dir):
            skill_dir = ""
    if not state_file:
        # Fallback: skill dir default state (resolve plan pointer like gk_state)
        _setup_sys_path()
        from gk_state import _resolve_default_state
        state_file = _resolve_default_state()
    if not skill_dir:
        skill_dir = str(Path(__file__).resolve().parent.parent)

    # 2026-09-25（ECC-567E8C847F16 / 选项 A）：`_run` 的「读 state（_verify_checksum +
    # `_load_state`）→ 一长串判据决策 → 多分支写 state」是**一整个 RMW**，8 个 `_write_state`
    # 写点写的是**同一份内存 `d`** ⟹ 「先 read 后 write」窗口内他人写入（edit_budget 扣减 /
    # finding / state-patch）会被整体覆盖回旧值（丢更新）。修法 = **全段持锁**：本文件
    # 0 subprocess / 0 requests / 0 `os.system`，全部依赖（gk_node_guard / gk_gate_* /
    # gk_route_center）均为只读查表 ⟹ 锁内无等待，跨进程互斥到手即放，不饿死他人。
    # （`dump_state` 亦取锁，但 `state_lock` 按 realpath 可重入 ⟹ 锁内再取不自锁。）
    with state_lock(state_file):
        result = _run(state_file, to_stage, force, dry_run, env, monitor_json,
                      cc, remote, skill_dir)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

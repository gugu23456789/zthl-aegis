#!/usr/bin/env python3
"""
Gatekeeper Appeal -- 独立调解逻辑（cmd_appeal 薄壳的 python 核心）
================================
2026-09-06 bashpy 改造：gatekeeper-cli.sh cmd_appeal 降为薄壳（env/密钥解析 + 委托 + JSON 透传），
域逻辑单源收拢到此模块——D3 foreign guard / A7 sentinel 迁移 + schema 守卫 / mediation /
hard evidence / 记录写回，A7 错误码（APPEAL_ENV_UNAVAILABLE / APPEAL_API_UNAVAILABLE /
APPEAL_RESPONSE_INVALID）与 bash 原契约同构。
Endpoint/model 解析链：显式参数 --base/--model → env API_BASE/API_MODEL → deepseek 默认。

Usage:
  python3 scripts/gk_appeal.py --gate ECO-VERIFY --notes "appeal notes" --api-key KEY [--base URL] [--model NAME]

Exit codes:
  0 = OK (JSON output with result)
  1 = Error (JSON output with error field)
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
from gk_state import _read_state, DEFAULT_STATE_FILE
from gk_json_utils import update_state
from gk_gate_appeal import clear_blocks

# Schema directory
SCHEMA_DIR = Path(__file__).parent.parent / "monitor-schemas"


def _detect_foreign_content(notes: str) -> str:
    """D3: 跨租户守卫 —— 单源 `gk_foreign_content`（P2c，2026-10-31）。

    历史缺陷（本函数原实现）：`USERNAME or USER or "HP"` —— WSL 下 `USER=root` ⟹ 自家路径
    `<home>/...` 被判 `foreign_user:HP`（实测），且 `"HP"` 是硬编码进开源版本的
    部署方用户名。现由单源模块多源解析（`GK_OWN_USER` → 缓存 → interop → 路径段）。

    对外契约保持 `'clean' | <reason>`（调用点与本模块单测既有断言零变更）。
    """
    import gk_foreign_content as _fc
    return _fc.check(notes) or "clean"


def _collect_hard_evidence(worktree: str, branch: str) -> dict:
    """Collect hard evidence (from gatekeeper-cli.sh L2531-2534)."""
    evidence = {"commits_ahead": 0, "ci_trigger": "absent", "build_exists": False}

    if worktree and Path(worktree).exists():
        try:
            result = subprocess.run(
                ["git", "-C", worktree, "rev-list", "--count", "HEAD", "^origin/main"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                evidence["commits_ahead"] = int(result.stdout.strip())
        except (subprocess.TimeoutExpired, ValueError):
            pass

        ci_file = Path(worktree) / ".github" / "workflows" / "ci.yml"
        if ci_file.exists():
            try:
                content = ci_file.read_text(encoding="utf-8")
                if branch in content:
                    evidence["ci_trigger"] = "present"
            except Exception:
                pass

        build_file = Path(worktree) / "cpp" / "build" / "CTestTestfile.cmake"
        evidence["build_exists"] = build_file.exists()

    return evidence


def _build_mediation_context(state: dict) -> dict:
    """Build mediation context (from gatekeeper-cli.sh L2498-2529)."""
    gd = state.get("gate_data", {})
    sealed = gd.get("_sealed_agent_score", {})
    cl = gd.get("human_calibration_log") or []
    last_human = cl[-1] if cl else {}

    checklist_total = last_human.get("checklist_total", 0)
    checklist_passed = last_human.get("checklist_passed", 0)

    return {
        "agent_score": sealed.get("score", "N/A"),
        "agent_verdicts": sealed.get("verdicts", {}),
        "human_score": last_human.get("human_score", "N/A"),
        "human_verdicts": last_human.get("verdicts_json", {}),
        "divergence": last_human.get("divergence", "N/A"),
        "flag": last_human.get("flag", ""),
        "change_items": last_human.get("change_items", 0),
        "checklist": f"{checklist_passed}/{checklist_total}" if checklist_total else "N/A",
    }


def _repair_sentinel_denials(state: dict) -> list:
    """A7（2026-09-05）：sentinel 否决迁移——appeal_records 中 score==-1 是解析哨兵（overall_score
    提取默认），不可能是裁判合法输出（裁判输出 0..1）；env/schema 故障误烧成的永久否决在此清除并留
    审计 gate_data.appeal_repair_log，之后可重跑 appeal（无需 --force，不弱化实质否决）。
    返回被修复的 gate 列表；调用方需在返回前持久化（含审计）。"""
    recs = state.get("appeal_records", {}) or {}
    denied = state.get("appeal_denied_gates", []) or []
    chg = []
    for g in list(denied):
        r = recs.get(g)
        if isinstance(r, dict) and r.get("score") == -1:
            if g in denied:
                denied.remove(g)
            recs.pop(g, None)
            chg.append(g)
    if chg:
        from datetime import datetime, timezone as _tz
        gd = state.setdefault("gate_data", {})
        gd.setdefault("appeal_repair_log", []).append({
            "gates": chg, "reason": "sentinel_denied_repaired", "score": -1,
            "time": datetime.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })
    return chg


def _inject_transition_facts(current_stage: str, gate: str, state: dict,
                             env_json: str = "") -> dict | None:
    """F-REV-9 C1（2026-09-08）：进入判据（transition/entry_requires）核验。

    Catch-22 根因：appeal 曾把「gate 完成态 schema requires」当进入门禁判据灌给 judge——
    不进 gate 则永不产生 gate 内完成证据 → 必然驳回死锁。修复：appeal 判据改用
    「从当前阶段进入该 gate」的 transition 判据（复用 gk_advance._structural_gates 单源，
    禁止在 schema json 复制第二份 entry 判据 = 防双源漂移）。

    适用面：gate ∈ STAGE_n 且 current_stage ≠ gate（= advance 跨阶段被拒的申诉，如
    STAGE_3 内被拒后 appeal STAGE_4 → 核验 STAGE_3→4 进入判据）。
    gate == current（= gate 内 monitor 裁定被申诉，完成态要求即裁决对象，合理）或
    standing gate（ECO-*）→ 返回 None（保持原完成态 schema 判据，行为不变）。
    """
    stage_names = {f"STAGE_{i}" for i in range(6)}  # STAGE_0..STAGE_5
    if not current_stage or gate not in stage_names or current_stage not in stage_names \
            or current_stage == gate:
        return None
    try:
        from gk_advance import _structural_gates  # lazy import：仅 standard 跨阶段路径触发
    except Exception as e:  # transition 注入失败 → 降级标注（judge 可见 best-effort 状态）
        return {"transition_unavailable": str(e)}
    env = {}
    if env_json:
        try:
            env = json.loads(env_json)
        except Exception:
            env = {}
    try:
        ok, gates_res = _structural_gates(current_stage, gate, state, env, force=False)
    except Exception as e:  # 核验器异常 → 降级标注，不阻断 appeal（防二次死锁）
        return {"transition_unavailable": str(e)}
    return {"transition": f"{current_stage}→{gate}", "gates": gates_res, "all_ok": ok}


def appeal(
    gate: str,
    notes: str,
    api_key: str,
    worktree: str = "",
    branch: str = "",
    state_path: str = DEFAULT_STATE_FILE,
    base: str | None = None,
    model: str | None = None,
    current_stage: str = "",
    env_json: str = "",
) -> dict:
    """Execute appeal logic: validate, call API, record result.

    base/model 解析链：显式参数 → env API_BASE/API_MODEL → deepseek 默认
    （cmd_appeal 薄壳以 --base/--model 显式传入，防未 export 变量丢失）。"""
    if not gate:
        return {"error": "appeal <gate> <notes> required", "ok": False}

    # Read state
    state = _read_state(state_path)
    if "error" in state:
        return {"error": state["error"], "ok": False}

    # A7: sentinel 否决迁移先于粘性检查——score==-1 的"否决"非裁判输出，修复后允许重跑（审计落档）
    # 2026-09-25（ECC-567E8C847F16 / 选项 A）：落盘改**锁内重放**（`update_state`）。原
    # 「先 read(L195) 后 write」的窗口跨了下方 **LLM API 调用（秒级）**⟹ 并发写者必丢更新；
    # 而整段持锁又会「锁内等 API」饿死他人（`-w 5` 超时）。本增量（去哨兵否决 + append 审计）
    # 与读到的 state 内容无关 ⟹ 可延后原子重放；内存 `state` 仍先就地修复（下方粘性检查依赖它）。
    if _repair_sentinel_denials(state):
        def _repair_mut(d):
            _repair_sentinel_denials(d)
            return d
        update_state(state_path, _repair_mut)

    # D3: Foreign content guard (2 layers)
    foreign_hit = _detect_foreign_content(notes)
    if foreign_hit != "clean":
        return {"error": "FOREIGN_CONTENT_DETECTED", "detail": foreign_hit,
                "action": "BLOCKED", "ok": False, "allowed": False}

    # Check: appeal_denied_gates (fail-closed)
    appeal_denied_gates = state.get("appeal_denied_gates", [])
    if gate in appeal_denied_gates:
        return {"allowed": False, "reason": "APPEAL_DENIED_PERMANENTLY",
                "detail": f"Gate {gate} appeal was previously denied. Use --force to override.",
                "error": "APPEAL_DENIED_PERMANENTLY", "ok": False}

    # Check: appeal already recorded
    appeal_records = state.get("appeal_records", {})
    if gate in appeal_records:
        return {"allowed": False, "reason": "ALREADY_APPEALED",
                "detail": f"Gate {gate} already has an appeal on record. Only one appeal per gate.",
                "error": "ALREADY_APPEALED", "ok": False}

    # Read schema
    schema_file = SCHEMA_DIR / f"{gate}.json"
    schema = ""
    if schema_file.exists():
        schema = schema_file.read_text(encoding="utf-8")

    # F-REV-9 C1（2026-09-08）：进入判据注入——appeal 主判据 = 从当前阶段进入 {gate} 的
    # transition 判据（复用 gk_advance._structural_gates 单源）；完成态 schema requires 降级
    # 为背景参考（Catch-22 根因修复：不再要求"尚未进入的 gate 的完成证据"）。
    # 非适用面（gate==current 的 gate 内 monitor 拒 / standing ECO-* / 无 current_stage）
    # → transition_facts=None，保持原完成态 schema 判据，行为不变。
    transition_facts = _inject_transition_facts(current_stage, gate, state, env_json)
    if transition_facts is not None:
        gate_context = (
            f"进入判据核验（F-REV-9 主判据：当前阶段 {current_stage} → {gate} 的门禁检查）:\n"
            f"{json.dumps(transition_facts, ensure_ascii=False, indent=2)}\n\n"
            f"完成态 schema（背景参考，勿当进入判据——Catch-22 教训：不进 {gate} 则永不产生 "
            f"gate 内完成证据）:\n{schema}"
        )
    else:
        gate_context = f"门禁 schema（gate 内 monitor/裁定判据）:\n{schema}"

    # Build mediation context
    mediation_context = _build_mediation_context(state)

    # Collect hard evidence
    evidence = _collect_hard_evidence(worktree, branch)

    # Build prompts (from L2536-2539)
    appeal_prompt = f"""APPEAL IN PROGRESS: The agent claims the previous monitor ruling was incorrect. Evaluate the appeal fairly. The agent's appeal notes: {notes}. This is the ONLY appeal for this gate. Output: {{"overall_score":...,"appeal_impact":"how appeal affected scoring","is_final":true,"checks":[...]}}
MEDIATION CONTEXT (agent vs human blind scoring):
{json.dumps(mediation_context, indent=2)}
If there is a significant divergence between agent and human scores, explain WHY they disagree and provide a mediated resolution."""

    system_prompt = """You are a PRM appeal judge AND mediator. Given: (1) gate criteria — for a cross-stage advance denial this is the ENTRY criteria into the denied gate (not its completion requirements), (2) state, (3) hard evidence, (4) agent appeal notes, (5) MEDIATION CONTEXT showing sealed agent score vs human score with divergence. Your job: (a) evaluate the appeal, (b) if agent and human scores diverge significantly, explain the root cause of disagreement and propose a mediated resolution. Be fair to both sides — don't simply favor the appellant. IMPORTANT: do not require evidence that can only exist AFTER entering the gate the agent was denied from (Catch-22 anti-pattern)."""

    user_prompt = f"GATE CONTEXT: {gate_context}\n\nSTATE: {json.dumps(state)}\n\nEVIDENCE: {json.dumps(evidence)}\n\n{appeal_prompt}\n\nScore this gate. Output only JSON."

    # Make API call — endpoint/model：显式参数 → env → deepseek 默认（薄壳透传，防未 export）
    endpoint = (base or os.environ.get("API_BASE") or "https://api.deepseek.com/v1").rstrip("/") + "/chat/completions"
    mdl = model or os.environ.get("API_MODEL") or "deepseek-flash"
    try:
        resp = requests.post(
            endpoint,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": mdl,
                "temperature": 0.0,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            },
            timeout=60,
        )
        resp.raise_for_status()
        result = resp.json()
        content = result.get("choices", [{}])[0].get("message", {}).get("content", "")

        # A7：传输/解析失败一律 RETRYABLE + 不落记录（未落记录不烧永久否决机会）
        if not content:
            return {"ok": False, "error": "APPEAL_API_UNAVAILABLE",
                    "reason": "API 无有效内容（HTTP 错误体/认证失败）",
                    "action": "RETRYABLE",
                    "hint": "检查 API_KEY 权限与端点后重试 — 未落记录"}

        # Parse response
        parsed = json.loads(content)

        # A7: schema 守卫——缺 overall_score（坏 JSON/schema 漂移）不得按哨兵 -1 判 DENIED（会误烧
        # 永久否决）；显式 APPEAL_RESPONSE_INVALID + 不落记录（与原 timeout/RequestException 同族）。
        if "overall_score" not in parsed or not isinstance(
                parsed.get("overall_score"), (int, float)):
            return {"error": "APPEAL_RESPONSE_INVALID",
                    "detail": "裁判输出缺 overall_score 字段（schema 漂移/坏 JSON）— 未落记录",
                    "action": "RETRYABLE", "ok": False}

        appeal_score = parsed.get("overall_score", -1)
        appeal_impact = parsed.get("appeal_impact", "")

        verdict = "APPROVED" if appeal_score > 0.5 else "DENIED"

        # Record appeal (from L2564-2608)
        mediation_explanation = parsed.get("appeal_impact", "")
        checks = parsed.get("checks", [])

        _rec = {
            "verdict": verdict,
            "score": appeal_score,
            "impact": appeal_impact,
            "notes": notes,
            "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "mediation_explanation": mediation_explanation[:500],
            "checks": checks[:10] if isinstance(checks, list) else [],
            "mediation_context_snapshot": mediation_context,
        }

        # 2026-09-25（ECC-567E8C847F16 / 选项 A）：本块原为「read(L195) → LLM API → write」的
        # 跨 API RMW（秒级窗口）⟹ 并发写者必丢更新；整段持锁又会「锁内等 API」饿死他人。
        # 待落内容（appealed_gates / I2 清标记 / appeal_records / appeal_denied_gates）全部由
        # **本次判读 + 入参**决定，与读到的 state 内容无关 ⟹ 改**锁内重放**（`update_state`）。
        def _appeal_mut(d):
            if verdict == "APPROVED":  # I2/X1: 只清**本 gate**的阻断源（勿误清其它源）
                _gd = d.setdefault("gate_data", {})
                clear_blocks(_gd, gate=gate)
            d.setdefault("appealed_gates", []).append(gate)
            d["appealed_gates"] = list(set(d["appealed_gates"]))
            d.setdefault("appeal_records", {})[gate] = _rec
            if verdict == "DENIED":  # Write appeal_denied_gates on DENIED (from L2605-2607)
                d.setdefault("appeal_denied_gates", []).append(gate)
                d["appeal_denied_gates"] = list(set(d["appeal_denied_gates"]))
            return d
        update_state(state_path, _appeal_mut)

        return {
            "ok": True,
            "gate": gate,
            "appeal_score": appeal_score,
            "appeal_verdict": verdict,
            "appeal_impact": appeal_impact,
            "is_final": True,
        }

    except requests.exceptions.Timeout:
        return {"ok": False, "error": "APPEAL_API_UNAVAILABLE",
                "reason": "API 无响应（端点不可达/超时）",
                "action": "RETRYABLE",
                "hint": "检查 API_BASE/网络后重试 — 传输问题非实质否决，未落记录"}
    except requests.exceptions.RequestException as e:
        return {"ok": False, "error": "APPEAL_API_UNAVAILABLE",
                "reason": f"API 错误: {str(e)}",
                "action": "RETRYABLE",
                "hint": "检查 API_KEY 权限与端点后重试 — 未落记录"}
    except json.JSONDecodeError:
        return {"ok": False, "error": "APPEAL_RESPONSE_INVALID",
                "reason": "裁判输出非合法 JSON（坏 JSON/schema 漂移）",
                "action": "RETRYABLE",
                "hint": "LLM 输出违约 — 未落记录，重试或登记模型问题"}


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description="Gatekeeper Appeal")
    parser.add_argument("--gate", required=True, help="Gate name")
    parser.add_argument("--notes", required=True, help="Appeal notes")
    parser.add_argument("--api-key", required=True, help="API key")
    parser.add_argument("--worktree", default="", help="Worktree path")
    parser.add_argument("--branch", default="", help="Branch name")
    parser.add_argument("--path", default=DEFAULT_STATE_FILE, help="State file path")
    parser.add_argument("--base", default=None, help="API base URL (default: env API_BASE / deepseek)")
    parser.add_argument("--model", default=None, help="API model (default: env API_MODEL / deepseek-flash)")
    # F-REV-9 C1（2026-09-08）：进入判据注入参数——当前阶段 + transition env（_collect_advance_env 输出）
    parser.add_argument("--current-stage", default="", help="当前阶段（transition 源阶段，advance 被拒场景）")
    parser.add_argument("--env-json", default="", help="transition env 收集 JSON（cmd_appeal 经 _collect_advance_env 产出）")

    args = parser.parse_args(argv)

    result = appeal(
        gate=args.gate,
        notes=args.notes,
        api_key=args.api_key,
        worktree=args.worktree,
        branch=args.branch,
        state_path=args.path,
        base=args.base,
        model=args.model,
        current_stage=args.current_stage,
        env_json=args.env_json,
    )

    print(json.dumps(result, indent=2, ensure_ascii=False))
    sys.exit(0 if result.get("ok", False) else 1)


if __name__ == "__main__":
    main()

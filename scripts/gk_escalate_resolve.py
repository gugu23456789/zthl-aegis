#!/usr/bin/env python3
"""
Gatekeeper Escalate + Resolve
==============================
Extracted from gatekeeper-cli.sh cmd_escalate (L2631-2707) + cmd_resolve (L2710-2793).
Full alignment: D3 foreign content guard, appeal_denied_gates check, gate validation,
               Ed25519 signing.

Usage:
  python3 scripts/gk_escalate_resolve.py escalate --gate ECO-VERIFY --reason "..."
  python3 scripts/gk_escalate_resolve.py resolve --gate ECO-VERIFY --resolution force_advance [--reason "..."]
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from gk_state import _read_state, DEFAULT_STATE_FILE
from gk_json_utils import update_state
from gk_gate_appeal import blocking_gates


def _detect_foreign_content(text: str) -> str:
    """D3: 跨租户守卫 —— 单源 `gk_foreign_content`（P2c，2026-10-31；原为第 2 份副本）。

    对外契约保持 `'clean' | <reason>`（调用点零变更）；本机用户解析不再用 `USER` 兜底
    （WSL 恒 `root` ⟹ 自家路径误判）也不再硬编码 `"HP"`。
    """
    import gk_foreign_content as _fc
    return _fc.check(text) or "clean"


def escalate(
    gate: str,
    reason: str,
    state_path: str = DEFAULT_STATE_FILE,
    main_repo: str = "",
) -> dict:
    """Escalate: generate human-readable report after appeal denied."""
    if not gate:
        return {"error": "escalate <gate> <reason> required", "ok": False}

    state = _read_state(state_path)
    if "error" in state:
        return {"error": state["error"], "ok": False}

    # D3: Foreign content guard
    foreign_hit = _detect_foreign_content(reason)
    if foreign_hit != "clean":
        return {"error": "FOREIGN_CONTENT_DETECTED", "detail": foreign_hit, "action": "BLOCKED", "ok": False}

    # Check: was this gate's appeal denied?
    appeal_denied_gates = state.get("appeal_denied_gates", [])
    if gate not in appeal_denied_gates:
        return {"error": "APPEAL_NOT_DENIED", "detail": f"Gate {gate} has not been denied on appeal. Appeal must be denied BEFORE escalating.", "ok": False}

    # Generate report
    report_path = Path(main_repo if main_repo else ".") / f".gatekeeper_escalation_{gate}_{datetime.now().strftime('%Y%m%d_%H%M')}.md"
    report_content = f"""# Gatekeeper Escalation Report — {gate}

**Generated**: {datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
**Reason**: {reason}

## State Snapshot
```json
{json.dumps(state, indent=2)}
```

## Gate Data
```json
{json.dumps(state.get('gate_data', {}), indent=2)}
```

## Appeal Record
{json.dumps(state.get('appeal_records', {}).get(gate, {}), indent=2)}

---
**Action required**: Human review of escalated PRM monitor decision.
"""

    try:
        report_path.write_text(report_content, encoding="utf-8")
    except Exception as e:
        return {"error": f"Failed to write report: {e}", "ok": False}

    return {
        "escalated": True,
        "gate": gate,
        "report": str(report_path),
        "action": "Review the report and decide whether to --force advance or implement the fix manually.",
        "ok": True,
    }


VALID_GATES = ["ECO-RESEARCH", "ECO-EDIT", "ECO-VERIFY", "ECO-DOC",
               # A4（2026-10-28）：旧站名保留，供存量 state / 历史记录回放
               "ECO-AUDIT", "ECO-SCAN", "ECO-READ",
               "ECC-ANALYSIS", "ECC-IMPACT", "ECC-PLAN", "ECC-FINDING", "ECC-REDTEAM"]
VALID_RESOLUTIONS = ["force_advance", "manual_fix", "dismiss"]


def resolve(
    gate: str,
    resolution: str,
    reason: str = "",
    state_path: str = DEFAULT_STATE_FILE,
) -> dict:
    """Resolve: human final resolution after appeal/escalate."""
    if not gate:
        return {"error": "resolve <gate> <resolution> [reason]", "ok": False}
    if not resolution:
        return {"error": "resolution required: force_advance|manual_fix|dismiss", "ok": False}
    if resolution not in VALID_RESOLUTIONS:
        return {"error": f"resolution must be {'|'.join(VALID_RESOLUTIONS)}", "ok": False}

    state = _read_state(state_path)
    if "error" in state:
        return {"error": state["error"], "ok": False}

    # D3: Foreign content guard
    if reason:
        foreign_hit = _detect_foreign_content(reason)
        if foreign_hit != "clean":
            return {"error": "FOREIGN_CONTENT_DETECTED", "detail": foreign_hit, "action": "BLOCKED", "ok": False}

    # G-09: Validate gate parameter
    if not any(gate.startswith(g) for g in VALID_GATES):
        return {"error": f"Unknown gate: {gate}", "known_gates": VALID_GATES, "ok": False}

    # G-18: Block resolve when appeal permanently denied
    appeal_denied_gates = state.get("appeal_denied_gates", [])
    if gate in appeal_denied_gates:
        return {"error": "APPEAL_DENIED_PERMANENTLY", "detail": f"Gate {gate} appeal was denied. Resolve blocked — use --force to override or re-evaluate.", "action": "BLOCKED", "ok": False}

    # G-17: Block resolve when appeal block exists —— 单源判定（X1 多源，2026-10-31）。
    # 原直读 `gate_data.appeal_required` 是第 3 份实现：看不到 `appeal_blocks` 的新阻断源。
    appeal_gates = blocking_gates(state)
    if appeal_gates and resolution == "force_advance":
        joined = ",".join(appeal_gates)
        return {"error": "APPEAL_REQUIRED_BEFORE_RESOLVE", "detail": f"Gate {joined} has appeal_required flag. Use 'appeal <gate> <notes>' first (LLM mediation). resolve force_advance cannot bypass quality gates.", "action": "BLOCKED", "ok": False}

    # Write resolution
    source = "appeal" if gate in state.get("appeal_records", {}) else "escalate"
    resolution_record = {
        "gate": gate,
        "source": source,
        "resolution": resolution,
        "reason": reason,
        "resolved_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    human_resolutions = state.setdefault("human_resolutions", {})
    human_resolutions[gate] = resolution_record

    # 2026-09-25（ECC-567E8C847F16 / 选项 A）：落盘改**锁内重放**（`update_state`）。
    # 原「read(L126) → 判据 → write」非原子；本增量只写本 gate 的裁定记录，与读到的
    # state 内容无关 ⟹ 可安全原子重放。下方签名段复用同一 `_res_mut`（闭包引用同一个
    # `resolution_record` 对象 ⟹ 第二次重放自动带上 ed25519_sig/hash）。
    def _res_mut(d):
        d.setdefault("human_resolutions", {})[gate] = resolution_record
        return d
    update_state(state_path, _res_mut)

    # Ed25519 signing (audit key) — ghost attack defense
    # 2026-08-13 修复：此前是 sha256 截断假签名（32 hex），audit --state 真验签上线后会误报；
    # 改为 audit 私钥真 Ed25519 签名，与 bash cmd_resolve 字节契约一致（规范化 JSON + 尾换行）。
    # 同时落 ed25519_hash 供自哈希防损坏（ai-audit-trail 三阶段第 2 段）。
    try:
        import base64, hashlib
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        skill_dir = Path(__file__).resolve().parent.parent
        priv_path = skill_dir / ".keys" / "audit_ed25519.pem"
        if priv_path.exists():
            priv = load_pem_private_key(priv_path.read_bytes(), password=None)
            res_json = json.dumps(resolution_record, sort_keys=True)
            payload = res_json.encode() + b"\n"  # 与 bash echo 尾换行契约一致
            sig = base64.b64encode(priv.sign(payload)).decode()
            res_hash = hashlib.sha256(payload).hexdigest()
            resolution_record["ed25519_sig"] = sig
            resolution_record["ed25519_hash"] = res_hash
            human_resolutions[gate] = resolution_record
            update_state(state_path, _res_mut)  # 重放（record 已就地带上签名）
    except Exception:
        pass  # signing failure doesn't block resolution

    return {"ok": True, "resolution": resolution_record}


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Gatekeeper Escalate/Resolve")
    subparsers = parser.add_subparsers(dest="command")

    # escalate
    esc = subparsers.add_parser("escalate")
    esc.add_argument("--gate", required=True)
    esc.add_argument("--reason", default="")
    esc.add_argument("--main-repo", default="")
    esc.add_argument("--path", default=DEFAULT_STATE_FILE)

    # resolve
    res = subparsers.add_parser("resolve")
    res.add_argument("--gate", required=True)
    res.add_argument("--resolution", required=True)
    res.add_argument("--reason", default="")
    res.add_argument("--path", default=DEFAULT_STATE_FILE)

    args = parser.parse_args()

    if args.command == "escalate":
        result = escalate(args.gate, args.reason, args.path, args.main_repo)
    elif args.command == "resolve":
        result = resolve(args.gate, args.resolution, args.reason, args.path)
    else:
        result = {"error": "usage: escalate|resolve", "ok": False}

    print(json.dumps(result, indent=2, ensure_ascii=False))
    sys.exit(0 if result.get("ok", False) else 1)


if __name__ == "__main__":
    main()

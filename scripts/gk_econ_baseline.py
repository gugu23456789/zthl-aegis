#!/usr/bin/env python3
"""经济基线**单源解析**（2026-10-31）—— 防「credit-baseline vs econ_enabled_at」双源漂移。

两个候选口径：
  A) `gk_credit_ledger` 签名基线（`<state>.credit-baseline.json`：`cutoff_id` / `cutoff_ts`，
     Ed25519 签名 + 绑定 state 身份 + append-only 前缀）——**权威**；
  B) `gate_data.econ_enabled_at`（裸 ISO 时间戳，无签名）——**legacy 回退**。

规则（只允许一个真源）：
  1. A 有效 ⟹ 只用 A；B 若存在且与 A 不同 ⟹ `drift=True`（调用方出具名 finding，不静默取一个）；
  2. A 存在但验签/绑定失败 ⟹ **fail-closed**（`ok=False`），**不回退** B ——
     否则「改坏基线 + 改 legacy 时间戳」即可绕过 N 门；
  3. A 缺失 ⟹ 回退 B（legacy）；
  4. 两者都无 ⟹ `source="none"`（N 门只能 advisory，禁止按绝对值判）。
"""
import json
from pathlib import Path


def _legacy_ts(state_file: str) -> str:
    try:
        d = json.loads(Path(state_file).read_text(encoding="utf-8"))
        return str((d.get("gate_data") or {}).get("econ_enabled_at") or "")
    except (OSError, json.JSONDecodeError, TypeError, AttributeError):
        return ""


def resolve(state_file: str, credit_reader=None) -> dict:
    """→ `{source, ts, cutoff_id, legacy_ts, drift, ok, reason}`（`credit_reader` 供测试注入）。"""
    if not state_file:
        return {"source": "none", "ts": "", "cutoff_id": "", "legacy_ts": "",
                "drift": False, "ok": True, "reason": "no_state"}
    import gk_credit_ledger as CL
    reader = credit_reader or CL.read_baseline
    try:
        cr = reader(state_file) or {}
    except Exception as e:                                  # 验签实现异常也按无效处理
        cr = {"present": False, "ok": False, "reason": "baseline_unreadable: %s" % e}
    legacy = _legacy_ts(state_file)
    present, ok = bool(cr.get("present")), bool(cr.get("ok"))
    if present and ok:
        ts = str(cr.get("cutoff_ts") or "")
        cid = str(cr.get("cutoff_id") or "")
        drift = bool(legacy and ts and legacy != ts)
        return {"source": "credit_baseline", "ts": ts, "cutoff_id": cid,
                "legacy_ts": legacy, "drift": drift, "ok": not drift,
                "reason": "baseline_drift" if drift else "ok"}
    if present and not ok:
        return {"source": "credit_baseline", "ts": "", "cutoff_id": "",
                "legacy_ts": legacy, "drift": False, "ok": False,
                "reason": str(cr.get("reason") or "baseline_invalid")}
    if legacy:
        return {"source": "gate_data.econ_enabled_at", "ts": legacy, "cutoff_id": "",
                "legacy_ts": legacy, "drift": False, "ok": True, "reason": "legacy"}
    return {"source": "none", "ts": "", "cutoff_id": "", "legacy_ts": "",
            "drift": False, "ok": True, "reason": "baseline_missing"}

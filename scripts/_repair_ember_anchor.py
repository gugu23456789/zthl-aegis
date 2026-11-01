#!/usr/bin/env python3
"""_repair_ember_anchor.py — 余烬 journal 锚修复（一次性维护工具，ECC-9C207D6FC458，2026-10-04）。

病根：域态（由 carry 建立）导出 ember 时其自身 `<state>.finding-journal.jsonl` 尚未建 ⟹
内嵌 `finding_journal` 为空，而 `gate_data_full.ecc_findings` 非空 ⟹ `gk_ember_replay.
reconcile_ember` 恒判「journal 缺失（state 有 N 条 finding）+ closed 无前序事件 = 伪造裁决
候选」（实测 `.gatekeeper.ember.ECO-SCAN.json` = 14 findings / 0 行；seal 验签通过，**非篡改**）。
导出侧根因已由 C8c 回落修复（gatekeeper-cli.sh）；本工具修复**存量**坏快照。

修复口径：从**权威 live journal**（`<default-state>.finding-journal.jsonl`）取该快照
`fid ∈ findings` 且 `ts <= archived_at` 的事件**原始行**回填 `finding_journal`，标注
`journal_anchor_rebuilt`（留痕），用 `.keys/audit_ed25519.pem` **重签**（A3 seal）后原子写回。

纪律：默认 `--dry-run` 只打印将写入的差异摘要（零写盘）；`--apply` 才落盘。
无可用切片（事件本就不存在）⟹ **拒绝**（禁伪造锚）。同源 canonical 复用 gk_ember_replay。
"""
import argparse
import base64
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gk_ember_replay import canonical_bytes   # noqa: E402  单源：seal 字节契约


def _le(ts, cutoff):
    """ISO 时间戳比较（含时区）；解析失败 → False（不纳入）。"""
    try:
        return datetime.fromisoformat(str(ts)) <= datetime.fromisoformat(str(cutoff))
    except Exception:  # noqa: BLE001 — 边界：非法 ts 不纳入切片
        return False


def slice_journal(journal_path, ids, cutoff):
    """从权威 journal 取 fid∈ids 且 ts<=cutoff 的**原始行**（保 append-only 逐字）。"""
    out = []
    if not os.path.isfile(journal_path):
        return out
    with open(journal_path, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            try:
                e = json.loads(s)
            except ValueError:
                continue
            if str(e.get("fid", "")) in ids and _le(e.get("ts", ""), cutoff):
                out.append(s)
    return out


def rebuild(ember_path, journal_path, key_dir, apply_it):
    with open(ember_path, encoding="utf-8") as f:
        ember = json.load(f)
    if ember.get("finding_journal"):
        return {"ok": True, "skip": "already_anchored", "lines": len(ember["finding_journal"])}
    findings = (ember.get("gate_data_full", {}) or {}).get("ecc_findings", []) or []
    ids = {str(f.get("id")) for f in findings if f.get("id")}
    if not ids:
        return {"ok": True, "skip": "no_findings"}
    cutoff = ember.get("archived_at") or ""
    lines = slice_journal(journal_path, ids, cutoff)
    if not lines:
        return {"ok": False, "error": "no_slice_available",
                "detail": "权威 journal 无该快照 findings 的 ts<=archived_at 事件 ⟹ 拒绝伪造锚",
                "ids": len(ids), "journal": journal_path}
    ember["finding_journal"] = lines
    ember["journal_source"] = journal_path
    ember["journal_anchor_rebuilt"] = {
        "rebuilt_at": datetime.now(timezone.utc).isoformat(),
        "source": journal_path, "lines": len(lines),
        "reason": "ECC-9C207D6FC458: 域态导出空锚存量修复（权威 journal 切片回填 + 重签）",
    }
    # A3 seal 重签（payload 自排除 seal）
    priv_p = os.path.join(key_dir, "audit_ed25519.pem")
    pub_p = os.path.join(key_dir, "audit_ed25519.pub")
    if not (os.path.isfile(priv_p) and os.path.isfile(pub_p)):
        return {"ok": False, "error": "audit_key_missing", "key_dir": key_dir}
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    import hashlib
    priv = load_pem_private_key(open(priv_p, "rb").read(), password=None)
    payload = {k: v for k, v in ember.items() if k != "seal"}
    sig = base64.b64encode(priv.sign(canonical_bytes(payload))).decode()
    ember["seal"] = {"alg": "ed25519", "key": "audit_ed25519",
                     "key_fp": hashlib.sha256(open(pub_p, "rb").read()).hexdigest()[:32],
                     "sig": sig, "signed_at": ember["journal_anchor_rebuilt"]["rebuilt_at"]}
    summary = {"ok": True, "ember": ember_path, "rebuilt_lines": len(lines),
               "findings": len(ids), "journal_source": journal_path, "applied": bool(apply_it)}
    # 自验：把候选写临时文件跑 reconcile_ember 预判（dry-run 即可见修复后 gate），零污染真快照
    import tempfile
    from gk_ember_replay import reconcile_ember
    with tempfile.TemporaryDirectory() as td:
        cand = os.path.join(td, os.path.basename(ember_path))
        with open(cand, "w", encoding="utf-8") as f:
            json.dump(ember, f, ensure_ascii=False, indent=1)
        rec = reconcile_ember(cand, key_dir)
    summary["verify_gate"] = rec.get("gate")
    summary["verify_anomalies"] = (rec.get("reconcile") or {}).get("anomalies")
    if not apply_it:
        return summary
    tmp = ember_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(ember, f, ensure_ascii=False, indent=1)
    os.replace(tmp, ember_path)
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--ember", required=True)
    ap.add_argument("--journal", required=True)
    ap.add_argument("--key-dir", required=True)
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args(argv)
    print(json.dumps(rebuild(a.ember, a.journal, a.key_dir, a.apply), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""gk_discover_archive.py — discover 跨 R 归档（B10h，2026-10-28）

  archive <state_file> <default_state_file> <audit_key_dir> <timestamp>

R 切换时：旧 state → history 追加 prev_entry（cap 100）→ 余烬
`.gatekeeper.ember.<phase>.json`（gate_data_full / finding_journal / seal）→
清空 gate_data 与 monitor_scores 并覆盖写 state。

⚠ 逐字保留旧内联的失败面：
  · state 读失败 / prev_entry 组装抛错 ⟹ **整块中止**（state 不重置，shell `|| true` 吞）
  · 余烬段（含签名）整体 try/except 吞 ⟹ 签名/写盘失败不影响后续 state 重置
  · 归档只在 `prev_entry['r_phase']` 为真时发生（phase 未变不归档）
"""
import base64
import glob
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gk_state import _read_state  # noqa: E402


def _archive_digest(state_file: str) -> dict:
    """FIFO 归档摘要（条数 / 字节 / sha256）——相位快照的旁证，不并入 gate_data。

    余烬 = 相位级整份快照，FIFO 归档 = 窗口级事件流，二者保持分离；快照只带摘要，
    便于事后证明「快照当时窗口外有多少条、内容是否被改动」，不回读正文。
    """
    out = {}
    # 2026-11-01（T5）：`rejected-edits` 归档改名 **journal**；旧名 `-archive` 仍纳入摘要
    #   （存量文件不动 ⟹ 两代都认，否则余烬快照会「假装 0 条」）。
    for _tag, _patterns in (("rejected_edits", (".rejected-edits-journal.jsonl",
                                                ".rejected-edits-archive.jsonl")),
                            ("subagent_history", (".history-archive*.jsonl",))):
        _paths = []
        for _pattern in _patterns:
            _paths.extend(glob.glob(state_file + _pattern))
        _paths = sorted(set(_paths))
        _lines = _size = 0
        _h = hashlib.sha256()
        for _p in _paths:
            try:
                with open(_p, "rb") as _f:
                    for _chunk in iter(lambda: _f.read(65536), b""):
                        _h.update(_chunk)
                        _size += len(_chunk)
                with open(_p, "r", encoding="utf-8", errors="replace") as _f:
                    _lines += sum(1 for _l in _f if _l.strip())
            except OSError:
                continue
        out[_tag] = {"files": len(_paths), "lines": _lines, "bytes": _size,
                     "sha256": _h.hexdigest() if _paths else ""}
    return out


def _resolve_journal(state_file: str, default_state: str):
    """C8c（ECC-9C207D6FC458）：活动 state 的 journal 为空时回落权威 default state 作锚。

    返回 `(lines, source)`；两者皆空时 `source` 仍指向活动 journal（旧式行为，
    不伪造来源）。域态（由 carry 建立、无自身 journal）导出时靠此回落避免空锚。
    """
    _journal_path = state_file + ".finding-journal.jsonl"
    _journal_lines = []
    _journal_source = _journal_path
    if os.path.isfile(_journal_path):
        with open(_journal_path, "r", encoding="utf-8") as _jf:
            _journal_lines = [l.rstrip("\n") for l in _jf if l.strip()]
    if not _journal_lines:
        _fb_path = default_state + ".finding-journal.jsonl"
        if _fb_path != _journal_path and os.path.isfile(_fb_path):
            with open(_fb_path, "r", encoding="utf-8") as _jf:
                _journal_lines = [l.rstrip("\n") for l in _jf if l.strip()]
            if _journal_lines:
                _journal_source = _fb_path
    return _journal_lines, _journal_source


def archive(state_file: str, default_state: str, audit_key_dir: str,
            timestamp: str) -> int:
    s = _read_state(state_file)
    if s.get("error"):
        raise SystemExit(1)
    s.pop("_checksum_warning", None)

    gd = s.get("gate_data", {})
    prev_entry = {
        "r_phase": s.get("r_phase"),
        "completed_at": timestamp,
        "stages_reached": s.get("stage"),
        "best": gd.get("best", {}),
        "rejection_count": len(gd.get("rejected_edits", [])),
        "rejection_patterns": [r.get("violations", []) for r in gd.get("rejected_edits", [])],
        "monitor_scores_summary": {k: v.get("score", 0)
                                   for k, v in s.get("monitor_scores", {}).items()},
        "edit_count": gd.get("edit_count", 0),
        "advance_log": gd.get("_advance_log", [])[-3:],
        "key_rotation_log": gd.get("key_rotation_log", [])[-20:],
        "cron_health": gd.get("cron_health"),
        "human_calibration_summary": [
            {"stage": e.get("stage"), "verdicts": e.get("verdicts_json"),
             "score": e.get("score")}
            for e in (gd.get("human_calibration_log") or [])[-10:]
        ],
        "entropy_history": (gd.get("entropy_history") or [])[-10:],
        "appeal_summary": [
            {"gate": gate, "verdict": rec.get("verdict", ""),
             "decision": rec.get("impact", ""),
             "mediation_explanation": rec.get("mediation_explanation", "")[:200],
             "score": rec.get("score", 0), "time": rec.get("time", "")}
            for gate, rec in s.get("appeal_records", {}).items()
        ] if s.get("appeal_records") else [],
        "appeal_records_full": {k: {kk: vv for kk, vv in v.items()
                                    if kk != "ed25519_sig"}
                                for k, v in s.get("appeal_records", {}).items()}
        if s.get("appeal_records") else {},
        "human_resolutions": {k: {kk: vv for kk, vv in v.items() if kk != "ed25519_sig"}
                              for k, v in s.get("human_resolutions", {}).items()}
        if s.get("human_resolutions") else {},
        "subagent_history_summary": [
            {"task": e.get("task"), "confidence": e.get("confidence"),
             "guardrail": e.get("guardrail"),
             "access_violations": len(e.get("access_violations") or [])}
            for e in (gd.get("subagent_history") or [])[-10:]
        ],
        "block_log": (gd.get("block_log") or [])[-20:],
        "hook_block_log": (gd.get("hook_block_log") or [])[-24:],
        "eco_completions": {
            k: {"completed_at": v.get("completed_at"),
                "transitioned_to": v.get("transitioned_to")}
            for k, v in (gd.get("eco_completions") or {}).items()
        } if gd.get("eco_completions") else {},
        "edit_budget_snapshot": gd.get("edit_budget") or {},
    }

    h = s.get("history", [])
    if prev_entry["r_phase"]:
        h.append(prev_entry)
    if len(h) > 100:
        h[:] = h[-100:]
    s["history"] = h

    if prev_entry["r_phase"]:
        try:
            _ember_dir = os.path.dirname(state_file)
            _phase_safe = re.sub(r"[^A-Za-z0-9_-]", "_", str(prev_entry["r_phase"]))
            _ember = os.path.join(_ember_dir,
                                  ".gatekeeper.ember." + _phase_safe + ".json")
            _journal_lines, _journal_source = _resolve_journal(state_file, default_state)
            _gd_full = s.get("gate_data", {}) or {}
            _gd_source = state_file
            if not _gd_full:
                _gd_fb = default_state
                if _gd_fb != state_file and os.path.isfile(_gd_fb):
                    try:
                        with open(_gd_fb, "r", encoding="utf-8") as _gf:
                            _gd_full = json.load(_gf).get("gate_data") or {}
                        if _gd_full:
                            _gd_source = _gd_fb
                    except Exception:  # noqa: BLE001 — 旧式 `except Exception: _gd_full={}`
                        _gd_full = {}
            _emb = {"archived_at": prev_entry["completed_at"],
                    "r_phase": prev_entry["r_phase"],
                    "gate_data_full": _gd_full,
                    "gate_data_source": _gd_source,
                    "prev_entry_source": state_file,
                    "finding_journal": _journal_lines,
                    "journal_source": _journal_source,
                    "archive_digest": _archive_digest(state_file),
                    "prev_entry": prev_entry}
            try:
                _priv_p = os.path.join(audit_key_dir, "audit_ed25519.pem")
                _pub_p = os.path.join(audit_key_dir, "audit_ed25519.pub")
                if os.path.isfile(_priv_p) and os.path.isfile(_pub_p):
                    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed  # noqa: F401
                    from cryptography.hazmat.primitives.serialization import load_pem_private_key as _lpk
                    _canon = json.dumps(_emb, sort_keys=True, ensure_ascii=False,
                                        separators=(",", ":")).encode("utf-8")
                    with open(_priv_p, "rb") as _pf:
                        _priv = _lpk(_pf.read(), password=None)
                    with open(_pub_p, "rb") as _qf:
                        _pub_bytes = _qf.read()
                    _emb["seal"] = {
                        "alg": "ed25519",
                        "key": "audit_ed25519",
                        "key_fp": hashlib.sha256(_pub_bytes).hexdigest()[:32],
                        "sig": base64.b64encode(_priv.sign(_canon)).decode(),
                        "signed_at": prev_entry["completed_at"],
                    }
            except Exception:  # noqa: BLE001 — 旧式 `except Exception: pass`
                pass
            with open(_ember, "w", encoding="utf-8") as _f:
                json.dump(_emb, _f, ensure_ascii=False, indent=1)
            _files = sorted(glob.glob(os.path.join(
                _ember_dir, ".gatekeeper.ember.*.json")),
                key=os.path.getmtime, reverse=True)
            for _f_old in _files[10:]:
                try:
                    os.remove(_f_old)
                except Exception:  # noqa: BLE001 — 旧式 `except Exception: pass`
                    pass
        except Exception:  # noqa: BLE001 — 旧式整段 `except Exception: pass`
            pass

    s["gate_data"] = {}
    s["monitor_scores"] = {}
    with open(state_file, "w", encoding="utf-8", newline="\n") as f:
        json.dump(s, f, ensure_ascii=False, indent=1)
    return 0


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 5 or args[0] != "archive":
        print("usage: gk_discover_archive.py archive <state> <default_state> "
              "<audit_key_dir> <timestamp>", file=sys.stderr)
        return 2
    return archive(args[1], args[2], args[3], args[4])


if __name__ == "__main__":
    sys.exit(main())

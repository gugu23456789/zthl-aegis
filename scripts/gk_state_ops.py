#!/usr/bin/env python3
"""gk_state_ops.py — state 语义写原语（B10d，2026-10-28，锚 RED-MIGRATE-INLINE）

  reflect-persist <state> <stage> <timestamp>   REFLECT_GUIDANCE env → gate_data.rejected_patterns
  resolve-record  <state> <gate> <resolution> <reason_file> → human_resolutions[gate]
  crossfull-copy  <src> <dst> <worktree>       隔离副本 state（覆写 worktree/branch/stage）
  discover-scheduler <state> <mode> <max_lr> <min_lr> <steps> <ptype> <last_rc> <repo>
                                               discover 内 scheduler/project_type/target_repo 落库
  release-check-record <state>                 RC_OUT env → gate_data._latest_release_check

⚠ 各站均按**旧内联原语义**：裸 `json.dump` 覆盖写（**不持 state_lock、不重算
`_checksum`**）。锁/校验和单源化属另一议题（`gk_json_utils.update_state`），
不在本次迁移内顺带修改。
"""
import ast
import datetime
import json
import os
import sys
import time


def cmd_reflect_persist(args) -> int:
    """guidance（LLM，不可信）经 env 传入；非 JSON ⟹ `{'text': 原文}`。"""
    state_path = args[0] if args else ""
    stage = args[1] if len(args) > 1 else ""
    ts = args[2] if len(args) > 2 else ""
    with open(state_path, encoding="utf-8") as f:
        state = json.load(f)
    gd = state.setdefault("gate_data", {})
    raw = os.environ.get("REFLECT_GUIDANCE", "")
    try:
        analysis = json.loads(raw)
    except Exception:  # noqa: BLE001 — 旧式 `except Exception`
        analysis = {"text": raw}
    gd["rejected_patterns"] = {
        "stage": stage,
        "analysis": analysis,
        "timestamp": ts,
        "source": "cmd_reflect",
    }
    gd["needs_analysis"] = False
    with open(state_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(state, f, ensure_ascii=False, indent=1)
    return 0


def cmd_resolve_record(args) -> int:
    """reason 从文件读入（保留换行）；appeal_records 命中 ⟹ source=appeal。"""
    state_path = args[0] if args else ""
    gate = args[1] if len(args) > 1 else ""
    resolution = args[2] if len(args) > 2 else ""
    reason_path = args[3] if len(args) > 3 else ""
    with open(reason_path, "r") as f:
        _reason = f.read()
    with open(state_path, encoding="utf-8") as f:
        d = json.load(f)
    r = d.setdefault("human_resolutions", {})
    source = "appeal" if gate in d.get("appeal_records", {}) else "escalate"
    r[gate] = {"gate": gate, "source": source, "resolution": resolution,
               "reason": _reason,
               "resolved_at": datetime.datetime.utcnow().isoformat() + "Z"}
    with open(state_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    print(json.dumps({"ok": True, "resolution": r[gate]}))
    return 0


def cmd_crossfull_copy(args) -> int:
    """crossfull 隔离副本：src 全量复制 + 覆写 worktree/branch/stage（写失败静默）。

    读失败（缺/坏）⟹ `d={}`；写盘 `except: pass` 是旧式原语义（rc 恒 0）。
    父 state 只读由 shell 侧 P0-2 哈希断言保证，本命令不触碰 src。
    """
    src = args[0] if args else ""
    dst = args[1] if len(args) > 1 else ""
    wt = args[2] if len(args) > 2 else ""
    try:
        with open(src) as f:
            d = json.load(f)
    except Exception:  # noqa: BLE001 — 旧式 `except: d={}`
        d = {}
    if wt:
        d["worktree"] = wt
        d["branch"] = "dryrun/crossfull"
    _gd = d.get("gate_data") if isinstance(d.get("gate_data"), dict) else {}
    d["stage"] = "ECO-VERIFY" if _gd.get("project_type") == "standing" else "AUDIT-CROSSR"
    try:
        with open(dst, "w") as f:
            json.dump(d, f, indent=1, ensure_ascii=False)
    except Exception:  # noqa: BLE001 — 旧式 `except: pass`
        pass
    return 0


def cmd_discover_scheduler(args) -> int:
    """discover 重建前的字段落库（读侧 `gk_state._read_state`，缺 gate_data ⟹ rc≠0）。"""
    from gk_state import _read_state
    state_path = args[0] if args else ""
    mode = args[1] if len(args) > 1 else ""
    max_lr = ast.literal_eval(args[2] if len(args) > 2 else "0")
    min_lr = ast.literal_eval(args[3] if len(args) > 3 else "0")
    steps = ast.literal_eval(args[4] if len(args) > 4 else "0")
    ptype = args[5] if len(args) > 5 else ""
    last_rc = ast.literal_eval(args[6] if len(args) > 6 else "0")
    repo = args[7] if len(args) > 7 else ""
    d = _read_state(state_path)
    if d.get("error"):
        raise SystemExit(1)
    d.pop("_checksum_warning", None)
    d["gate_data"]["scheduler"] = {"mode": mode, "max_lr": max_lr, "min_lr": min_lr,
                                   "total_steps": steps, "current_step": 0,
                                   "current_lr": max_lr}
    d["gate_data"]["project_type"] = ptype
    d["gate_data"]["last_release_check"] = last_rc
    d["target_repo"] = repo
    with open(state_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    return 0


def cmd_release_check_record(args) -> int:
    """release-check 回写：`last_release_check` 缺失才取 now（setdefault 原语义）。"""
    state_path = args[0] if args else ""
    _rc = os.environ.get("RC_OUT", "")
    d = json.load(open(state_path, encoding="utf-8")) if os.path.exists(state_path) else {}
    d.setdefault("gate_data", {}).setdefault("last_release_check", time.time())
    try:
        d["gate_data"]["_latest_release_check"] = json.loads(_rc)
    except Exception:  # noqa: BLE001 — 旧式「非静默降级」：stderr + raw 保留
        print("[F-REV-20] release-check JSON parse failed; raw kept", file=sys.stderr)
        d["gate_data"]["_latest_release_check"] = {"raw": _rc[:500]}
    with open(state_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    return 0


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    verbs = {"reflect-persist": (cmd_reflect_persist, 3),
             "resolve-record": (cmd_resolve_record, 4),
             "crossfull-copy": (cmd_crossfull_copy, 3),
             "discover-scheduler": (cmd_discover_scheduler, 8),
             "release-check-record": (cmd_release_check_record, 1)}
    if not args or args[0] not in verbs or len(args) - 1 != verbs[args[0]][1]:
        print("usage: gk_state_ops.py reflect-persist <state> <stage> <timestamp>\n"
              "       gk_state_ops.py resolve-record <state> <gate> <resolution> <reason_file>\n"
              "       gk_state_ops.py crossfull-copy <src> <dst> <worktree>\n"
              "       gk_state_ops.py discover-scheduler <state> <mode> <max_lr> <min_lr>"
              " <steps> <ptype> <last_rc> <repo>\n"
              "       gk_state_ops.py release-check-record <state>",
              file=sys.stderr)
        return 2
    return verbs[args[0]][0](args[1:])


if __name__ == "__main__":
    sys.exit(main())

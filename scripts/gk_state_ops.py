#!/usr/bin/env python3
"""gk_state_ops.py — state 语义写原语（B10d，2026-10-28，锚 RED-MIGRATE-INLINE）

  reflect-persist <state> <stage> <timestamp>   REFLECT_GUIDANCE env → gate_data.rejected_patterns
  resolve-record  <state> <gate> <resolution> <reason_file> → human_resolutions[gate]
  crossfull-copy  <src> <dst> <worktree>       隔离副本 state（覆写 worktree/branch/stage）
  discover-scheduler <state> <mode> <max_lr> <min_lr> <steps> <ptype> <last_rc> <repo>
                                               discover 内 scheduler/project_type/target_repo 落库
  release-check-record <state>                 RC_OUT env → gate_data._latest_release_check

2026-11-02（写崩修复）：五站全部改走 `gk_json_utils` 单源写面 ——
  · 已存在 state：`update_state`（`state_lock` 内读-改-写 + 原子替换 + 重算 `_checksum`）；
  · `crossfull-copy`：`write_json_file`（tmp + fsync + os.replace）写副本；
  · `release-check-record`：缺文件时先原子建空 state，再走 `update_state`。
旧实现「裸 `json.dump` 截断写」会在中途崩溃时留下半个 JSON、并发时丢更新，已废除。
"""
import ast
import datetime
import json
import os
import sys
import time

import gk_json_utils as JU


def _update(state_path: str, mutator, *, create: bool = False) -> dict:
    """state 单源 RMW：存在 ⟹ `update_state`；`create` 且缺失 ⟹ 先原子建空 state。"""
    p = str(state_path)
    if not os.path.exists(p):
        if not create:
            return {"error": "state_file_not_found", "path": p}
        with JU.state_lock(p):
            if not JU.dump_state(p, {}):
                return {"error": "write_failed", "path": p}
    return JU.update_state(p, mutator)


def _fail(res: dict) -> int:
    print("[ERROR] %s" % (res.get("error") or res), file=sys.stderr)
    return 1


def cmd_reflect_persist(args) -> int:
    """guidance（LLM，不可信）经 env 传入；非 JSON ⟹ `{'text': 原文}`。"""
    state_path = args[0] if args else ""
    stage = args[1] if len(args) > 1 else ""
    ts = args[2] if len(args) > 2 else ""
    raw = os.environ.get("REFLECT_GUIDANCE", "")
    try:
        analysis = json.loads(raw)
    except Exception:  # noqa: BLE001 — 旧式 `except Exception`
        analysis = {"text": raw}

    def mut(d):
        gd = d.setdefault("gate_data", {})
        gd["rejected_patterns"] = {
            "stage": stage,
            "analysis": analysis,
            "timestamp": ts,
            "source": "cmd_reflect",
        }
        gd["needs_analysis"] = False

    res = _update(state_path, mut)
    return 0 if res.get("ok") else _fail(res)


def cmd_resolve_record(args) -> int:
    """reason 从文件读入（保留换行）；appeal_records 命中 ⟹ source=appeal。"""
    state_path = args[0] if args else ""
    gate = args[1] if len(args) > 1 else ""
    resolution = args[2] if len(args) > 2 else ""
    reason_path = args[3] if len(args) > 3 else ""
    with open(reason_path, "r", encoding="utf-8") as f:
        _reason = f.read()
    rec = {}

    def mut(d):
        r = d.setdefault("human_resolutions", {})
        source = "appeal" if gate in d.get("appeal_records", {}) else "escalate"
        rec.update({"gate": gate, "source": source, "resolution": resolution,
                    "reason": _reason,
                    "resolved_at": datetime.datetime.utcnow().isoformat() + "Z"})
        r[gate] = rec

    res = _update(state_path, mut)
    if not res.get("ok"):
        print(json.dumps({"ok": False, "error": res.get("error", "")}))
        return 1
    print(json.dumps({"ok": True, "resolution": rec}))
    return 0


def cmd_crossfull_copy(args) -> int:
    """crossfull 隔离副本：src 全量复制 + 覆写 worktree/branch/stage。

    读失败（缺/坏）⟹ `d={}`（旧语义保留）；写盘改**原子写 + 重算 checksum**，
    失败 fail-loud（旧实现 `except: pass` 会把「没写成」报成成功）。
    父 state 只读由 shell 侧 P0-2 哈希断言保证，本命令不触碰 src。
    """
    src = args[0] if args else ""
    dst = args[1] if len(args) > 1 else ""
    wt = args[2] if len(args) > 2 else ""
    try:
        with open(src, encoding="utf-8") as f:
            d = json.load(f)
    except Exception:  # noqa: BLE001 — 旧式 `except: d={}`
        d = {}
    if wt:
        d["worktree"] = wt
        d["branch"] = "dryrun/crossfull"
    _gd = d.get("gate_data") if isinstance(d.get("gate_data"), dict) else {}
    d["stage"] = "ECO-VERIFY" if _gd.get("project_type") == "standing" else "AUDIT-CROSSR"
    d["_checksum"] = JU._state_checksum(d)
    try:
        ok = JU.write_json_file(dst, d, indent=JU.STATE_INDENT)
    except Exception as e:  # noqa: BLE001 — mkdir 失败在 write_json_file 的 try 之外
        print("[ERROR] crossfull-copy write failed: %s: %s" % (type(e).__name__, e),
              file=sys.stderr)
        return 1
    if not ok:
        print("[ERROR] crossfull-copy write failed: %s" % dst, file=sys.stderr)
        return 1
    # 冷索引侧车随副本一起走（否则副本只剩内联热索引，冷叶丢失 = 读分裂）。
    src_side = str(src) + ".satellite-index.jsonl"
    dst_side = str(dst) + ".satellite-index.jsonl"
    if not os.path.isfile(src_side):
        try:
            os.remove(dst_side)          # 源无侧车 ⟹ 清掉目标残留，防陈旧冷叶
        except OSError:
            pass
        return 0
    try:
        d = os.path.dirname(os.path.abspath(dst_side))
        if d:
            os.makedirs(d, exist_ok=True)
        tmp = dst_side + ".tmp"
        with open(src_side, "rb") as f:
            raw = f.read()
        with open(tmp, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, dst_side)
    except Exception as e:  # noqa: BLE001 — 副本不完整 ⟹ fail-loud
        print("[ERROR] crossfull-copy sidecar copy failed: %s: %s"
              % (type(e).__name__, e), file=sys.stderr)
        return 1
    return 0


def cmd_discover_scheduler(args) -> int:
    """discover 重建前的字段落库（缺 gate_data ⟹ rc≠0，且原文件零改动）。"""
    state_path = args[0] if args else ""
    mode = args[1] if len(args) > 1 else ""
    max_lr = ast.literal_eval(args[2] if len(args) > 2 else "0")
    min_lr = ast.literal_eval(args[3] if len(args) > 3 else "0")
    steps = ast.literal_eval(args[4] if len(args) > 4 else "0")
    ptype = args[5] if len(args) > 5 else ""
    last_rc = ast.literal_eval(args[6] if len(args) > 6 else "0")
    repo = args[7] if len(args) > 7 else ""

    def mut(d):
        gd = d["gate_data"]          # 缺 gate_data ⟹ KeyError（不写盘，rc≠0）
        gd["scheduler"] = {"mode": mode, "max_lr": max_lr, "min_lr": min_lr,
                           "total_steps": steps, "current_step": 0,
                           "current_lr": max_lr}
        gd["project_type"] = ptype
        gd["last_release_check"] = last_rc
        d["target_repo"] = repo

    try:
        res = _update(state_path, mut)
    except Exception as e:  # noqa: BLE001 — 缺 gate_data / 非法旧 JSON ⟹ 非零退出
        print("[ERROR] discover-scheduler: %s: %s" % (type(e).__name__, e), file=sys.stderr)
        return 1
    return 0 if res.get("ok") else _fail(res)


def cmd_release_check_record(args) -> int:
    """release-check 回写：`last_release_check` 缺失才取 now（setdefault 原语义）。"""
    state_path = args[0] if args else ""
    _rc = os.environ.get("RC_OUT", "")

    def mut(d):
        gd = d.setdefault("gate_data", {})
        gd.setdefault("last_release_check", time.time())
        try:
            gd["_latest_release_check"] = json.loads(_rc)
        except Exception:  # noqa: BLE001 — 旧式「非静默降级」：stderr + raw 保留
            print("[F-REV-20] release-check JSON parse failed; raw kept", file=sys.stderr)
            gd["_latest_release_check"] = {"raw": _rc[:500]}

    res = _update(state_path, mut, create=True)
    return 0 if res.get("ok") else _fail(res)


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

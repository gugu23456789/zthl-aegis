#!/usr/bin/env python3
"""gk_route_check.py — 路由自检（P0-b，2026-11-13）。

事故：`reclaim` 删树后 `state.worktree` 仍指向该路径 ⟹ 写面永远落空、Edit 静默失败。
本命令把「路由是否悬空」变成**可执行的检查**（区外安全闸，与 `premerge` 同层）：

判据（任一不满足 ⟹ FAIL, rc=3）：
  1. `pick_active_worktree` 必须 `ok`（四级链能给出结论；`NO_ROUTE` = 无树可选）
  2. 不得出现 `stale_state`（state 指向的树已不在 `git worktree list` 内）
  3. **顶层** `worktrees_extra`（活动写面允许集的单源：hook Gate 3 / `gk_route_center.active_roots`
     都读它）的每一项必须是**现存目录**（手工白名单残留 ⟹ FAIL）。`gate_data.worktrees_extra`
     是历史误写桶、无消费方 ⟹ 不参与判据（`detach_route` 顺带清，但不作为路由依据）。

输出单 JSON（`ok/decision/route/checks/next`），只读：不写 state、不写 ref。

CLI::
  python3 scripts/gk_route_check.py [--skill-dir <d>] [--state-file <f>] [--repo <p>] [--cwd <p>]
"""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_route_center as R  # noqa: E402


def _load_state(state_file: str) -> dict:
    try:
        with open(state_file, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def check(skill_dir: str = "", state_file: str = "", repo: str = "", cwd: str = "") -> dict:
    skill = skill_dir or str(Path(__file__).resolve().parent.parent)
    sf = state_file or os.path.join(skill, ".gatekeeper.state")
    st = _load_state(sf)
    gd = (st.get("gate_data") or {}) if isinstance(st, dict) else {}
    main_repo = repo or st.get("target_repo") or ""
    # `target_repo` 可能是逻辑名（如 "skill"）而非路径 ⟹ 非目录时回落到技能根（主树）
    if not main_repo or not os.path.isdir(str(main_repo)):
        main_repo = skill
    wts = R._git_worktree_paths(main_repo)
    lease = gd.get("worktree_lease") if isinstance(gd.get("worktree_lease"), dict) else None
    pick = R.pick_active_worktree(state_worktree=str(st.get("worktree") or ""),
                                 cwd=cwd or os.getcwd(), worktrees=wts,
                                 lease=lease, main_repo=main_repo)
    out = {"ok": False, "decision": "FAIL", "state_file": sf, "repo": main_repo,
           "worktrees": wts, "route": pick,
           "checks": {"route_ok": bool(pick.get("ok")),
                      "no_stale_state": not pick.get("stale_state"),
                      "extras_resolvable": True},
           "bad_extras": [], "next": ""}
    bad = [x for x in (st.get("worktrees_extra") or [])
           if x and not os.path.isdir(str(x))]
    out["bad_extras"] = bad
    out["checks"]["extras_resolvable"] = not bad
    if not pick.get("ok"):
        out["next"] = ("四级路由全空 ⟹ `apply-worktree` 派生工作树，或把 state.worktree 复位到主树"
                       "（`state-patch --set-nested worktree \"\\\"<main>\\\"\"`）")
    elif pick.get("stale_state"):
        out["next"] = ("state.worktree 指向已删树（%s）⟹ 复位到存活树；"
                       "`reclaim` 应事务化写回 fallback（本轮修复项）" % pick["stale_state"])
    elif bad:
        out["next"] = ("worktrees_extra 含不存在目录 %s ⟹ 清理该项（手工白名单不得常驻）"
                       % ",".join(bad[:3]))
    else:
        out.update({"ok": True, "decision": "PASS", "next": "路由一致，可编辑"})
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--skill-dir", default="")
    ap.add_argument("--state-file", default="")
    ap.add_argument("--repo", default="")
    ap.add_argument("--cwd", default="")
    a = ap.parse_args(argv)
    out = check(a.skill_dir, a.state_file, a.repo, a.cwd)
    print(json.dumps(out, ensure_ascii=False))
    return 0 if out["ok"] else 3


if __name__ == "__main__":
    sys.exit(main())

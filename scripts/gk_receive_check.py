#!/usr/bin/env python3
"""gk_receive_check.py — `apply-worktree --receive-check` 接收侧**纯检测**单源。

计划正本：`docs/plans/2026-10-02-apply-worktree-hook-boundary-hardening-plan.md`（DRAFT-16，版本随计划正本）§2.2/§2.3/T1。

纪律（与 §0.1 / §2.2 逐字一致）：
  - **纯判定无写盘**：本模块**不写 state**；`surface_review` / `skipped` 等留痕 = **回包字段**（§2.2-3）。
  - **免检面 = 空（全 default-deny）**：任何 diff 均置 `surface_review`。
  - **判定单源**：diff（`--name-status --diff-filter=ACDMRTUXB`，git 状态**全集**）+ 祖先三态 + rc（§2.3 表）
    + `hook_live_from` 运行时派生；合法性**复用** `gk_write_claims.expected_worktrees`（禁自造）。

rc 产者（§2.3 表；判序 = 实现即契约，DRAFT-14 裁决）：
  · `GK_RECEIVE_CHECK=0` ⟹ `skipped(1)`，**短路于一切检测之前**；
  · **不可判 rc=3（fail-loud）**：env 非法值 / `hook_live_from` 派生失败 / `master_sha` 不可解 /
    `expected_worktrees` 异常 / `wt_sha` 不可解 / ancestry 不可判（`--is-ancestor` 返 128）/ `diff` 不可判；
  · rc=2：divergent / 越界（`alive=false`）/ 无公共祖先；rc=1：stale / 可FF非空；rc=0：可FF + 空 diff。
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

_MASTER_REF_DEFAULT = "master"
# rev 14：补 T（typechange）/ C（copy）/ U（unmerged）—— 原 ADMR 会让"防线脚本换 symlink"产出空 diff 假 clean。
# DRAFT-16（§2.2-2 收口，6 臂 MoA P0）：补齐 git 状态**全集** ACDMRTUXB（含 X=unknown / B=broken）——
#   原 ADMRCUT 仍漏 X/B ⟹ 任何 status 都可能被过滤掉而产空 diff 假 clean（防御性全集）。
_DIFF_FILTER = "ACDMRTUXB"
_WRAPPER_REL = ("scripts", "pre_tool_hook_wrapper.sh")


def _run(args, cwd=None):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def _git(repo, *args):
    return _run(["git", "-C", repo, *args])


def _rev_parse(repo, ref):
    r = _git(repo, "rev-parse", "--verify", "--quiet", ref)
    if r.returncode != 0:
        return None
    return r.stdout.strip() or None


def derive_hook_live_from(skill_dir: str) -> str | None:
    """运行时派生主树活体 hook wrapper 路径（**禁硬编码**）；派生失败 ⟹ None（fail-loud 交调用方）。"""
    if not skill_dir or not str(skill_dir).strip():
        return None
    p = Path(str(skill_dir).strip()) / _WRAPPER_REL[0] / _WRAPPER_REL[1]
    return str(p)


def classify_ancestor(repo: str, master_sha: str, wt_sha: str):
    """祖先三态：`('ff'|'stale'|'divergent'|'no_common_ancestor'|'unknown', rc_hint)`。

    `rc_hint=128` ⟹ `--is-ancestor` 返 128（ref/仓不可解 = **不可判**，交调用方判 rc=3）。
    `ff`   = master 是 wt 的祖先（wt 领先 ⟹ 可快进）；
    `stale`= wt 是 master 的祖先（wt 落后）；
    `divergent` = 互不为祖先但**有**公共祖先（真分叉）；
    `no_common_ancestor` = 无公共祖先。
    """
    a = _git(repo, "merge-base", "--is-ancestor", master_sha, wt_sha)
    if a.returncode == 128:
        return "unknown", 128
    if a.returncode == 0:
        return "ff", 0
    b = _git(repo, "merge-base", "--is-ancestor", wt_sha, master_sha)
    if b.returncode == 128:
        return "unknown", 128
    if b.returncode == 0:
        return "stale", 0
    mb = _git(repo, "merge-base", master_sha, wt_sha)
    if mb.returncode != 0 or not mb.stdout.strip():
        return "no_common_ancestor", 0
    return "divergent", 0


def diff_status(repo: str, master_sha: str, wt_sha: str, wt: str = ""):
    """`(--diff-filter=ACDMRTUXB, --name-status)` 相对 `master...wt_sha` ⟹ `(diff_empty, files)`。

    返回 `(None, [])` = **不可判**（git 非零退出）；否则 `(bool, [<status>\\t<path>, ...])`。
    """
    r = _git(repo, "diff", "--name-status", f"--diff-filter={_DIFF_FILTER}",
             f"{master_sha}...{wt_sha}")
    if r.returncode != 0:
        return None, []
    files = [ln for ln in r.stdout.splitlines() if ln.strip()]
    # 2026-10-15 修（`diff_empty` 误报 · F-RCVWTHOOK）：coder 落刀**不提交**（提交归主 agent）⟹
    #   `master...wt_sha` 两端都是 HEAD ⟹ **看不见工作树未提交改动** ⟹ 恒判空 diff 假 clean
    #   （实测 coder-wt ` M scripts/gk_phase_probe.py` 却被报 `diff_empty:true / clean:true`）。
    #   补：并入 wt 的未提交面（工作树 diff HEAD + 暂存 diff --cached）。
    if wt:
        for extra in (("diff", "--name-status", f"--diff-filter={_DIFF_FILTER}", "HEAD"),
                      ("diff", "--name-status", f"--diff-filter={_DIFF_FILTER}", "--cached")):
            rr = _git(wt, *extra)
            if rr.returncode != 0:
                return None, []
            files += [ln for ln in rr.stdout.splitlines() if ln.strip()]
    seen, uniq = set(), []
    for ln in files:
        if ln not in seen:
            seen.add(ln)
            uniq.append(ln)
    return (len(uniq) == 0), uniq


def _expected_worktrees(main_repo: str, state_file: str):
    """**复用生产单源** `gk_write_claims.expected_worktrees`（禁自造第二派生）。"""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from gk_write_claims import expected_worktrees  # noqa: E402
    return expected_worktrees(main_repo, state_file)


def _canon(path: str, repo: str) -> str:
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from gk_write_claims import _canon as _c  # noqa: E402
        return _c(path, repo)
    except Exception:
        return os.path.normpath(str(path))


def check(wt: str, main_repo: str, state_file: str = "",
          skill_dir: str = "", master_ref: str = _MASTER_REF_DEFAULT) -> dict:
    """核心判定。**恒返回**同构回包（`receive_check:true`）；**不抛异常、不写盘**。"""
    out = {
        "receive_check": True, "clean": False, "diff_empty": None,
        "surface_review": False, "rc": None, "skipped": False,
        "stale": False, "divergent": False, "ancestor": None, "alive": None,
        "hook_live_from": "", "master_sha": "", "wt_sha": "", "files": [], "reason": "",
    }

    # ── 回退面：GK_RECEIVE_CHECK=0 ⟹ 跳过 + 留痕 skipped（**非** clean；§2.3/§5）──
    raw_gate = str(os.environ.get("GK_RECEIVE_CHECK", "1"))
    if raw_gate == "0":
        out.update(skipped=True, rc=1,
                   reason="GK_RECEIVE_CHECK=0 ⟹ 跳过检测（留痕 skipped，非 clean）")
        return out
    # ── 不可判态：env 非法值（非缺省 / 非 "0" / 非 "1"）⟹ rc=3 fail-loud（§2.3 臂⑩）──
    if raw_gate not in ("1", "0"):
        out.update(rc=3,
                   reason=f"GK_RECEIVE_CHECK 非法值 {raw_gate!r}（非缺省/非 '0'/非 '1' ⟹ 不可判）")
        return out

    # ── hook_live_from 运行时派生（§2.1）──
    hlf = derive_hook_live_from(skill_dir)
    out["hook_live_from"] = hlf or ""
    if not hlf or not Path(hlf).is_file():
        out.update(rc=3, reason="hook_live_from 派生失败或 wrapper 不存在（不可判）")
        return out

    # ── 判序（rev SCR-4）：不可判（master/state/hook）优先于 alive 判定；越界先于 wt_sha 解析 ──
    master_sha = _rev_parse(main_repo, master_ref)
    if not master_sha:
        out.update(rc=3, reason="master_sha 不可解（不可判）")
        return out
    out["master_sha"] = master_sha

    # ── 合法性：复用 expected_worktrees（越界/非目录 ⟹ rc=2；state 不可解 ⟹ rc=3）──
    if not Path(wt).is_dir():
        out.update(rc=2, alive=False, reason=f"越界/不存在：{wt} 非目录")
        return out
    try:
        exp = _expected_worktrees(main_repo, state_file)
    except Exception as exc:  # noqa: BLE001 — 不可判（state 不可解）⟹ rc=3
        out.update(rc=3, reason=f"expected_worktrees 不可解（不可判）：{exc}")
        return out
    wt_c = _canon(wt, main_repo)
    exp_c = {_canon(x, main_repo) for x in exp}
    if wt_c not in exp_c:
        out.update(rc=2, alive=False,
                   reason="越界：<wt> 不在 expected_worktrees()（alive=false）")
        return out
    out["alive"] = True

    wt_sha = _rev_parse(wt, "HEAD")
    if not wt_sha:
        out.update(rc=3, reason="wt_sha 不可解（worktree HEAD 不可解析 ⟹ 不可判）")
        return out
    out["wt_sha"] = wt_sha

    # ── 祖先三态 ──
    state, hint = classify_ancestor(main_repo, master_sha, wt_sha)
    if hint == 128 or state == "unknown":
        out.update(rc=3, reason="ancestry 不可判（--is-ancestor rc=128）")
        return out
    out["ancestor"] = state
    if state == "no_common_ancestor":
        out.update(divergent=False, rc=2, reason="无公共祖先 ⟹ BLOCK（回包裁决，非强制）")
        return out
    if state == "divergent":
        out.update(divergent=True, rc=2, reason="divergent（真分叉）⟹ BLOCK（回包裁决，非强制）")
        return out
    if state == "stale":
        out.update(stale=True, rc=1, reason="stale（wt 落后）⟹ WARN + rebase 指引")
        return out

    # ── state == 'ff'：diff 判定 ──
    empty, files = diff_status(main_repo, master_sha, wt_sha, wt)
    if empty is None:
        out.update(rc=3, reason="diff 不可判（git diff 非零退出）")
        return out
    out["diff_empty"], out["files"] = empty, files
    if empty:
        out.update(clean=True, rc=0, reason="可FF + diff 空 ⟹ 放行（clean）")
    else:
        out.update(surface_review=True, rc=1,
                   reason=f"可FF + diff 非空（{len(files)} 文件）⟹ WARN + 摘要 + 留痕 surface_review")
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="apply-worktree 接收侧纯检测（只读）")
    p.add_argument("--wt", required=True, help="待检 worktree 路径")
    p.add_argument("--main-repo", default="", help="主树路径（默认 = 本脚本的 repo 根）")
    p.add_argument("--state-file", default="", help="state 文件（供 expected_worktrees）")
    p.add_argument("--skill-dir", default="", help="技能根（派生 hook_live_from）")
    p.add_argument("--master", default=_MASTER_REF_DEFAULT, help="主线 ref（默认 master）")
    args = p.parse_args(argv)

    main_repo = args.main_repo or str(Path(__file__).resolve().parent.parent)
    skill_dir = args.skill_dir or os.environ.get("SKILL_DIR", "") or main_repo
    state_file = args.state_file or os.environ.get("STATE_FILE", "")
    res = check(args.wt, main_repo, state_file, skill_dir, args.master)
    print(json.dumps(res, ensure_ascii=False))
    # DRAFT-16（P2 收口）：rc **全量传导**到进程退出码 —— 原恒 `return 0` ⟹ rc=3（fail-loud）
    # 只存 JSON 字段，shell 调用方按退出码判读时**看不见**不可判。rc 契约为 0/1/2/3 ⟹ 逐字映射。
    return int(res.get("rc") or 0)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""gk_git_workflow_check.py — git-workflow 全量检测器（2026-09-01 实装）

L1 交叉审查扩展实装（此前仅登记）：把 git-workflow 技能的各类检测能力聚合为
确定性 JSON，与 gk_git_concurrency_check.py（并发抢锁六项）一起并入
`audit --crossr`（L1 Git history 层统一入口）。

git-workflow 检测面（对照 git-workflow SKILL.md 模块）：
  push 预检      → dirty_worktree（未提交更改）/ protected_branch（分支保护）/
                    unpushed_commits（推送滞后）
  branch 安全    → protected_branch（保护分支）/ current_branch（当前分支）/
                    stale_commit（最后提交时间）
  worktree       → worktree_status（主 worktree + 孤儿 worktree）
  release 预检   → repo_healthy（HEAD 可解析）
  security 审查  → merge_state（merge/rebase/cherry-pick 半成品）/ hooks_ok（hook 完整性）/
                    loader_pin（git-workflow 加载安全网）

检测项:
  1. repo_healthy      : HEAD 可解析 + rev-list 正常
  2. protected_branch  : 当前分支是否保护分支（main/master/develop/release/production）
  3. detached_head     : HEAD 是否 detached（detached = 不可安全 push/发版）
  4. merge_state       : merge/rebase/cherry-pick/revert 进行中（git-dir/XX_HEAD 存在）
  5. dirty_worktree    : git status --porcelain 非空（未提交/未暂存/未跟踪）
  6. unpushed_commits  : 相对上游分支未推送提交数（@{u}..HEAD）
  7. stale_commit      : 当前分支最后提交距今天数（> 30 = stale 提示）
  8. worktree_status   : worktree 列表（主 worktree 路径 + 孤儿 worktree 数）
  9. hooks_ok          : git-dir/hooks 存在且含关键 hook（pre-push / post-merge）
  10. loader_pin       : git-workflow 加载安全网状态（调用 gk_gitworkflow_loader.py，
                         仅当脚本可达；不可达 = skip，不阻断）
  11. line_ending_pollution : 换行符污染（同文件混合 CRLF/LF + .gitattributes 缺失 +
                          core.autocrlf 配置；2026-09-01 新增）
  12. merge_integrity   : 合并结果硬校验 —— 最近 N 个 merge 的「空合并 / 丢文件」
                          （治静默丢批次；2026-10-01 §15.8 二期，判据复用 gk_git_lease）

输出: JSON {ok, repo, checks, issues, recommendation}
  所有 checks 项: {status: "ok"|"warn"|"info"|"skip", ...detail}
  ok = 无 warn 项；issues = warn 项 key 列表；recommendation = 修复指引。

Exit codes: 0 = 正常输出（无论检测结果），1 = 内部错误。
"""
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

_PROTECTED = ("main", "master", "develop", "release", "production")
_STALE_DAYS = 30
_KEY_HOOKS = ("pre-push", "post-merge", "pre-commit")

_GIT_WORKFLOW_SKILL = os.environ.get(
    "GIT_WORKFLOW_SKILL_DIR",
    str(Path(os.path.expanduser("~/.trae/skills/git-workflow"))),
)


def _git(repo: str, *args: str, timeout: int = 10) -> tuple[int, str, str]:
    """git -C 调用（统一入口约定；Windows/WSL 并发抢锁防线见 SKILL.md Red Flags）。"""
    try:
        r = subprocess.run(["git", "-C", repo, *args],
                           capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return -1, "", str(e)


def _git_dir(repo: str) -> str | None:
    """解析真实 git-dir（worktree 场景下 .git 是指针文件，须走 rev-parse）。"""
    rc, out, _ = _git(repo, "rev-parse", "--git-dir")
    if rc != 0:
        return None
    d = out.strip()
    return d if os.path.isabs(d) else os.path.normpath(os.path.join(repo, d))


def check_repo_healthy(repo: str) -> dict:
    rc, out, _ = _git(repo, "rev-parse", "HEAD")
    if rc != 0:
        return {"status": "warn", "reason": "HEAD unresolvable（非 git 仓库或损坏）"}
    rc2, cnt, _ = _git(repo, "rev-list", "--count", "HEAD")
    return {"status": "ok", "head": out.strip()[:12], "commits": cnt.strip()}


def check_protected_branch(repo: str) -> dict:
    rc, out, _ = _git(repo, "branch", "--show-current")
    if rc != 0 or not out.strip():
        return {"status": "skip", "reason": "detached HEAD 无当前分支"}
    br = out.strip()
    return {"status": "warn" if br in _PROTECTED else "ok",
            "branch": br, "protected_list": list(_PROTECTED)}


def check_detached_head(repo: str) -> dict:
    rc, out, _ = _git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    if rc != 0:
        return {"status": "skip", "reason": "rev-parse failed"}
    detached = out.strip() == "HEAD"
    return {"status": "warn" if detached else "ok", "detached": detached}


def check_merge_state(repo: str) -> dict:
    gd = _git_dir(repo)
    if not gd:
        return {"status": "skip", "reason": "no git dir"}
    markers = ("MERGE_HEAD", "REBASE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD")
    active = [m for m in markers if (Path(gd) / m).exists()]
    return {"status": "warn" if active else "ok", "active_ops": active}


def check_dirty_worktree(repo: str) -> dict:
    rc, out, _ = _git(repo, "status", "--porcelain")
    if rc != 0:
        return {"status": "skip", "reason": "status failed"}
    lines = [l for l in out.splitlines() if l.strip()]
    return {"status": "warn" if lines else "ok",
            "changed_files": len(lines), "sample": lines[:5]}


def check_unpushed_commits(repo: str) -> dict:
    rc, out, _ = _git(repo, "rev-list", "--count", "@{u}..HEAD")
    if rc != 0:
        return {"status": "skip", "reason": "no upstream or rev-list failed"}
    n = out.strip()
    try:
        n = int(n)
    except ValueError:
        return {"status": "skip", "reason": f"unparsable count: {n!r}"}
    return {"status": "warn" if n else "ok", "unpushed": n}


def check_stale_commit(repo: str) -> dict:
    rc, out, _ = _git(repo, "log", "-1", "--format=%at", "HEAD")
    if rc != 0 or not out.strip():
        return {"status": "skip", "reason": "no commit"}
    try:
        age_days = int((datetime.now().timestamp() - int(out.strip())) // 86400)
    except ValueError:
        return {"status": "skip", "reason": "unparsable commit date"}
    return {"status": "warn" if age_days > _STALE_DAYS else "ok",
            "age_days": age_days, "stale_threshold": _STALE_DAYS}


def check_worktree_status(repo: str) -> dict:
    rc, out, _ = _git(repo, "worktree", "list", "--porcelain")
    if rc != 0:
        return {"status": "skip", "reason": "worktree list failed"}
    # 2026-09-22（f5 同批，实测）：`worktree ` 前缀是 **9** 字符，原式 `l[6:]` 从第 7 列切
    # ⟹ `main_worktree` 恒为 `"ee /mnt/..."`（前两字母被吞 + 残留 `ee `）—— 报告里给出的
    # 主 worktree 路径是**错的**（会误导按该路径排查的人）。出口：按前缀长度切。
    paths = [l[len("worktree "):] for l in out.splitlines() if l.startswith("worktree ")]
    branches = [l[len("branch "):] for l in out.splitlines() if l.startswith("branch ")]
    # 孤儿 worktree = 其 branch ref 在 refs/heads 中已不存在
    orphans = []
    for br in branches:
        # 2026-09-22（f5 / ECC-C69048822CD5）**假阳修复**：`worktree list --porcelain` 的
        # `branch` 行给的是**全 ref**（`branch refs/heads/master`），而原式 `l[7:]` 取到的仍是
        # `refs/heads/master` ⟹ 再拼成 `refs/heads/refs/heads/master` ⟹ `show-ref --verify`
        # **恒 rc=1** ⟹ 每个带分支的 worktree 都被判成孤儿。本仓实测：报 4 孤儿
        # （master / standing/xenv-form-fix / dryrun/moa-chain / feature/skill-r-t6），
        # 剥前缀复算后**真孤儿仅 1**（feature/skill-r-t6 —— 其 branch ref 确已不存在）。
        # 出口：先剥 `refs/heads/` 前缀（detached worktree 没有 branch 行，不受影响）。
        if br.startswith("refs/heads/"):
            br = br[len("refs/heads/"):]
        rc2, _, _ = _git(repo, "show-ref", "--verify", "--quiet", f"refs/heads/{br}")
        if rc2 != 0:
            orphans.append(br)
    return {"status": "warn" if orphans else "ok",
            "main_worktree": paths[0] if paths else "",
            "worktree_count": len(paths), "orphan_worktrees": orphans}


def check_hooks_ok(repo: str) -> dict:
    gd = _git_dir(repo)
    if not gd:
        return {"status": "skip", "reason": "no git dir"}
    hooks_dir = Path(gd) / "hooks"
    if not hooks_dir.is_dir():
        return {"status": "info", "reason": "hooks dir missing（未装 hooks 模板）"}
    present = [h for h in _KEY_HOOKS if (hooks_dir / h).exists()]
    return {"status": "warn" if not present else "ok",
            "key_hooks": present}


def check_loader_pin() -> dict:
    """git-workflow 加载安全网状态（可选增强；脚本不可达 = skip 不阻断）。"""
    loader = Path(_GIT_WORKFLOW_SKILL) / "scripts" / "gk_gitworkflow_loader.py"
    if not loader.is_file():
        return {"status": "skip", "reason": "git-workflow loader 不可达（技能未安装）"}
    try:
        r = subprocess.run([sys.executable, str(loader), "status"],
                           capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            return {"status": "skip", "reason": "loader status non-zero"}
        return {"status": "ok", "detail": r.stdout.strip()[:200]}
    except Exception as e:
        return {"status": "skip", "reason": f"loader error: {e}"}


def check_line_ending_pollution(repo: str) -> dict:
    """换行符污染检测（2026-09-01 用户质询：git-workflow 扩展换行符污染检测 → L1）。

    三要素（确定性 0 API，git 只读）：
      1. 单文件混合换行（同文件既有 CRLF 又有 LF）→ 换行符污染（diff 噪声/补丁注入风险面）
      2. .gitattributes 显式换行策略缺失（无 * text=auto / eol 声明）
      3. core.autocrlf 配置（true/input = 转换激活，库内行尾可能被重写）
    采样：git ls-files 前 200 个文本文件读字节判定。纯 CRLF / 纯 LF 均正常。
    """
    # 1. autocrlf 配置
    rc, out, _ = _git(repo, "config", "--get", "core.autocrlf")
    autocrlf = out.strip() if rc == 0 else "unset"
    # 2. .gitattributes 显式策略
    attr = Path(repo) / ".gitattributes"
    has_attr = attr.is_file()
    policy = ""
    if has_attr:
        try:
            policy = attr.read_text(encoding="utf-8", errors="replace")[:200]
        except OSError:
            pass
    # 3. 采样文本文件混合换行
    rc, out, _ = _git(repo, "ls-files", "-z")
    if rc != 0:
        return {"status": "skip", "reason": "ls-files failed"}
    mixed: list[str] = []
    crlf_count = lf_count = 0
    _TEXT_EXT = (".py", ".sh", ".md", ".json", ".yaml", ".yml", ".txt", ".toml",
                 ".cfg", ".ini", ".c", ".h", ".cc", ".cpp", ".js", ".ts", ".html")
    for f in out.split("\0"):
        if not f or f in mixed or len(mixed) >= 20:
            continue
        if not f.lower().endswith(_TEXT_EXT):
            continue
        p = Path(repo) / f
        if not p.is_file():
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        if b"\n" not in data:
            continue
        crlf_ends = data.count(b"\r\n")
        lone = data.count(b"\n") - crlf_ends  # 独立 LF（非 CRLF 一部分）
        if crlf_ends and lone:
            mixed.append(f)
        elif crlf_ends:
            crlf_count += 1
        else:
            lf_count += 1
    warns: list[str] = []
    if mixed:
        warns.append(f"单文件混合换行污染 {len(mixed)}: {mixed[:8]}")
    if not has_attr and autocrlf in ("", "false", "unset"):
        warns.append("无 .gitattributes 且 core.autocrlf 未开启 → 无显式换行策略（漂移/重写风险）")
    return {"status": "warn" if warns else "ok",
            "autocrlf": autocrlf, "has_gitattributes": has_attr,
            "gitattributes_policy": policy[:80],
            "sampled_lf": lf_count, "sampled_crlf": crlf_count,
            "mixed_files": mixed, "issues": warns}


# 技能自仓库既有债务（2026-09-04 L1 降噪）：技能仓库按批次推送/工作区在途属常规态，
# 交叉审查 L1 复核时不应作为阻断性 warn——登记为 info（保留计数，不改其他仓库语义）。
#
# 2026-09-22（f5 / ECC-C69048822CD5）扩表 +3：此三项在**本仓**均为**预期状态**而非缺陷，
# 但此前未被登记 ⟹ `audit --crossr` 对技能仓自身恒定报 `protected_branch / worktree_status /
# hooks_ok` 三条（噪声淹没真信号）。逐项依据（均为实测）：
#   protected_branch ：技能仓**无 PR 流**（单作者、按 R 批直推 master、CI 触发发版）
#                      ⟹ master 就是常规工作分支，非「误推保护分支」；
#   worktree_status  ：crossfull/dryrun 每轮批量建 worktree，历史遗留注册属**工作区在途**
#                      （⚠ 同批已修该 check 的假阳 bug：branch 行是全 ref，原式使孤儿数虚高
#                       4→真 1；余 1 真孤儿 feature/skill-r-t6 经此登记保持**可见**但非阻断）；
#   hooks_ok         ：hooks 由 git-workflow 模板部署到**被治理的目标仓**；技能仓自身由 Trae
#                      hook + 本 CLI 门禁治理（再装 pre-commit/pre-push 会二次门禁）⟹ 预期缺失。
# ⚠ 登记**不等于**修好：三项仍带原 detail/计数 + `self_debt: true` 标记，属**可见**的非阻断项
#   （本仓实测 `.git/hooks` 仅 `*.sample`，未装真 hook —— 该事实不因登记而消失）。
_SELF_DEBT_KEYS = ("dirty_worktree", "unpushed_commits", "protected_branch",
                   "worktree_status", "hooks_ok")
_SELF_ROOT = Path(__file__).resolve().parent.parent


def _is_skill_self_repo(repo: str) -> bool:
    """repo 是否为技能仓库自身（检测器所在仓库）——仅对自身放松常规债务。"""
    try:
        return Path(repo).resolve().as_posix().lower() == _SELF_ROOT.as_posix().lower()
    except OSError:
        return False


def _relax_self_debt(repo: str, checks: dict) -> list[str]:
    """技能自仓库：dirty/unpushed 常规债务 warn→info（既有状态登记，非阻断）。"""
    if not _is_skill_self_repo(repo):
        return []
    relaxed = []
    for k in _SELF_DEBT_KEYS:
        c = checks.get(k)
        if c and c.get("status") == "warn":
            c["status"] = "info"
            c["self_debt"] = True
            c["reason"] = (c.get("reason") or "") + "；技能自仓库既有状态登记（按批次推送/工作区在途），非阻断"
            relaxed.append(k)
    return relaxed


# ── 2026-10-01（§15.8 二期）：合并结果硬校验 `merge_integrity` ────────────────
# 病象（实测，§15.6）：`git merge` 撞孤儿 `index.lock` ⟹ `Unable to write index` ⟹ 索引未写，
#   随后 `git commit` 把 **ours 的旧树** 记成合并结果 ⟹ **空合并**；两次共丢 12 文件，
#   且**事后无法用 `git merge` 补救**（分支已成祖先）。
# 判据**纯历史自证**（无需外部输入）——对最近 N 个 merge 提交 M（双亲 P1=ours / P2=theirs）：
#   `diff --name-only P1 M` 空 且 `diff --name-only P1 P2` 非空 ⟹ 空合并；`--name-status P2 M` 含 `D` ⟹ 丢文件。
# 判据实现**复用** `gk_git_lease.verify_merge_result`（同判据双入口，**不另起第二实现**）。
_MERGE_SCAN_N = 12
# 技能自仓**已知且已修**的空合并（2026-10-01 补正 `3da3b40` 恢复；保留为 §15.6 实证）。
# ⚠ 豁免**仅**对技能自仓 + **须 sha 前缀命中**；非自仓/新出现的空合并一律照报（防「洗白」）。
_MERGE_INTEGRITY_KNOWN_SELF = ("c70551d", "a9da403")


def check_merge_integrity(repo: str, limit: int = None) -> dict:
    """合并结果硬校验（纯历史自证；§15.6 病象 / §15.8 二期）。

    `gk_git_lease` 不可达 ⟹ `skip`（不阻断；与 `loader_pin` 同惯例），reason 里明示「无法评估」。
    """
    n = limit or _MERGE_SCAN_N
    rc, out, _ = _git(repo, "rev-list", "--merges", "-n", str(n), "HEAD")
    if rc != 0:
        return {"status": "skip", "reason": "rev-list --merges failed（非 git 仓或 HEAD 不可解）"}
    sha_list = [s for s in out.split() if s]
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import gk_git_lease as _L
    except Exception as e:  # noqa: BLE001
        return {"status": "skip", "reason": f"gk_git_lease 不可达（{e}）⟹ 无法评估合并完整性"}
    self_repo = _is_skill_self_repo(repo)
    suspects: list[dict] = []
    waived: list[dict] = []
    for m in sha_list:
        rc1, p1, _ = _git(repo, "rev-parse", f"{m}^1")
        rc2, p2, _ = _git(repo, "rev-parse", f"{m}^2")
        if rc1 != 0 or rc2 != 0 or not p1.strip() or not p2.strip():
            continue
        r = _L.verify_merge_result(repo, p1.strip(), p2.strip(), m)
        if r.get("ok"):
            continue
        row = {"commit": m, "verdict": r.get("verdict"),
               "dropped": r.get("dropped") or [],
               "detail": r.get("detail") or r.get("error") or ""}
        if self_repo and any(m.startswith(w) for w in _MERGE_INTEGRITY_KNOWN_SELF):
            waived.append(row)
        else:
            suspects.append(row)
    return {"status": "warn" if suspects else "ok",
            "scanned": len(sha_list), "scan_limit": n,
            "suspects": suspects, "waived_known_self": waived}


def main(argv=None) -> None:
    av = list(sys.argv[1:] if argv is None else argv)
    repo = av[0] if av else os.getcwd()
    checks = {
        "repo_healthy": check_repo_healthy(repo),
        "protected_branch": check_protected_branch(repo),
        "detached_head": check_detached_head(repo),
        "merge_state": check_merge_state(repo),
        "dirty_worktree": check_dirty_worktree(repo),
        "unpushed_commits": check_unpushed_commits(repo),
        "stale_commit": check_stale_commit(repo),
        "worktree_status": check_worktree_status(repo),
        "hooks_ok": check_hooks_ok(repo),
        "loader_pin": check_loader_pin(),
        "line_ending_pollution": check_line_ending_pollution(repo),
        "merge_integrity": check_merge_integrity(repo),
    }
    relaxed = _relax_self_debt(repo, checks)
    flagged = [k for k, v in checks.items() if v.get("status") == "warn"]
    rec = ""
    if not flagged:
        rec = "OK: git-workflow 全量检测无 warn"
    else:
        tips = {
            "protected_branch": "保护分支上勿直接 push/发版 → 走 PR 工作流（git-workflow branch/pr）",
            "detached_head": "detached HEAD → 检出分支再操作（git-workflow branch create/checkout）",
            "merge_state": "存在未完成 merge/rebase/cherry-pick → 先完结再推进",
            "dirty_worktree": "有未提交更改 → 先 commit/stash（git-workflow history backup 兜底）",
            "unpushed_commits": "有未推送提交 → 推送前跑 git-workflow push --precheck",
            "stale_commit": "分支长时间未提交 → 核对是否过期分支（git-workflow branch status --no-expired）",
            "worktree_status": "存在孤儿 worktree → git-workflow worktree cleanup",
            "hooks_ok": "缺关键 hook → 检查 git-workflow templates/hooks 部署",
            "line_ending_pollution": "换行符污染/无显式策略 → 补 .gitattributes（* text=auto + 关键类型 eol=lf）并统一行尾",
            "merge_integrity": "存在「空合并/丢文件」（分支变更未真正并入）→ 用 gk_git_lease verify-merge 复核并按 §15.7 补正恢复",
        }
        rec = "WORKFLOW CHECK: " + ", ".join(flagged) + " — " + "; ".join(
            tips.get(k, "") for k in flagged if tips.get(k))
    print(json.dumps({"ok": not flagged, "repo": repo, "checks": checks,
                      "issues": flagged, "self_repo": _is_skill_self_repo(repo),
                      "self_debt_registered": relaxed,
                      "recommendation": rec}, ensure_ascii=False))


if __name__ == "__main__":
    main()

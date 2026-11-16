#!/usr/bin/env python3
"""gk_merge_cli.py — 本仓**唯一**的合并入口（R0.24，2026-11-13）。

契约:
  - 输入: `--source <branch>`（必填）；`--target`（缺省 master/main）；`--repo`（缺省 = 主仓）
  - 可选: `--cleanup-source-remote`（合并成功后归档 tip + 删远端源分支 + `ls-remote` 校验；
    **预检失败连合并都不做**；保护分支 / `gk-pool/` / 与目标同名一律拒）
  - 输出: stdout JSON `{ok, decision, repo, source, target, gate, commit, source_cleanup, ...}`；
    rc 0=已合并 3=拒绝
  - 失败: 闸①/闸②/冲突/提交任一失败 ⟹ `git merge --abort` 回滚 + 删除票据 + rc 3（fail-closed）

单一事实源: 判据在 `gk_merge_guard.py`（禁第二实现）；票据在 `gk_merge_hook.py`（禁第二实现）。
本模块只做**编排**：单队列锁 → 脏 index 检查 → 闸① → `git merge --no-ff --no-commit`
→ 闸② → 事实块重算 → 签票 → 提交（提交时由 reference-transaction 钩子验票）。

Usage:
  bash gatekeeper-cli.sh merge --source agent/session/<sid> [--target master]
  python3 scripts/gk_merge_cli.py --source <branch> --dry-run
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

try:                                  # Windows 原生解释器无 fcntl ⟹ 降级为无锁（单机串行仍靠人工）
    import fcntl
except ImportError:                   # pragma: no cover — 平台差异，不是逻辑分支
    fcntl = None

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_merge_guard as G  # noqa: E402
import gk_merge_hook as H   # noqa: E402

_FACTS = Path(__file__).resolve().parent / "gk_docgen_facts.py"   # 测试缝（真实生成器）

_BLOCK_HINTS = {
    "MERGE_BUSY": "已有合并在进行（单队列）⟹ 等它结束；确认无残留可删 .git/gatekeeper-merge.lock",
    "MERGE_IN_PROGRESS": "工作区已在 merge 态 ⟹ 先 `git merge --abort` 或收尾 commit",
    "DIRTY_INDEX": "暂存面非空（可能是产物清理）⟹ 先单独提交或 `git restore --staged -- <paths>`",
    "MERGE_FAILED": "git 拒绝合并（冲突/未跟踪文件会被覆盖）⟹ 先解决上述文件再重试",
    "COMMIT_FAILED": "合并提交失败 ⟹ 检查 hook 输出；票据已删除，可重跑本命令",
    "TARGET_NOT_FOUND": "目标分支不存在（--target master|main）",
    "SOURCE_NOT_FOUND": "源分支不存在（拼写 / 先 fetch）",
    "SOURCE_CLEANUP_PROTECTED": "保护分支 / gk-pool 前缀 / 与目标同名 ⟹ 禁止清理远端",
    "SOURCE_CLEANUP_NO_REMOTE": "远端不存在（--remote 拼写 / 未配置 origin）",
    "SOURCE_CLEANUP_CHECKED_OUT": "源分支正被检出 ⟹ 先切走再清理",
    "SOURCE_CLEANUP_NOT_MERGED": "合并后校验失败（源不在 HEAD 祖先链）⟹ 不删远端",
    "SOURCE_CLEANUP_ARCHIVE_FAILED": "归档 ref 写入失败 ⟹ 不删远端（先保证可恢复）",
    "SOURCE_CLEANUP_DELETE_FAILED": "远端删除失败（权限 / 网络 / 保护规则）",
    "SOURCE_CLEANUP_VERIFY_FAILED": "删除后远端仍存在该分支 ⟹ 校验失败",
}


def _git(repo: str, *args) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)


def _block(code: str, **kw) -> dict:
    kw.update({"ok": False, "decision": "BLOCK", "code": code,
               "next": _BLOCK_HINTS.get(code, "")})
    return kw


def _staged_paths(repo: str) -> list:
    r = _git(repo, "diff", "--cached", "--name-only")
    return [x for x in (r.stdout or "").splitlines() if x.strip()]


def _facts_docs(repo: str) -> list:
    """事实块生成器的输出清单（**单源** = `gk_docgen_facts.DOCS`），只保留仓库内存在的。"""
    try:
        import gk_docgen_facts as F
        docs = list(getattr(F, "DOCS", ())) + [getattr(F, "_README", "")]
    except Exception:  # noqa: BLE001 — 生成器不可导入 ⟹ 用同源默认（与 DOCS 同值）
        docs = ["SKILL.md", "references/architecture-overview.md", "references/README.md"]
    return [d for d in dict.fromkeys(docs) if d and (Path(repo) / d).exists()]


# ── 源远端分支清理（2026-11-14，方案 A）──────────────────────────────────
# 病象：合并侧有 R0.24 闸①/闸② + 票据（写 master 的唯一入口），但「删源远端分支」此前是裸
# `git push --delete` ⟹ 治理不对称。本闸 = 合并前置闸的**对偶**：归档 → 判据 → 删除 → 校验，
# 且全部在**同一把单队列锁**内完成（合并成功后立刻收口；预检失败则连合并都不做）。
# 保护名单与 `git-workflow` 的硬编码一致；`gk-pool/` 前缀与 `gk_worktree_reclaim` 的硬保护一致。
_PROTECTED_BRANCHES = frozenset({"main", "master", "develop", "release", "production"})
_PROTECTED_PREFIXES = ("gk-pool/",)


def _cleanup_precheck(repo: str, source: str, target: str, remote: str) -> tuple:
    """合并前预检（fail-fast）：返回 `(plan, block_code)`。

    `remote_exists=False` 属**幂等**：远端已无该分支 ⟹ 跳过删除，但仍归档 + 校验。
    """
    s = str(source or "").strip()
    if not s:
        return None, "SOURCE_NOT_FOUND"
    if s in _PROTECTED_BRANCHES or s.startswith(_PROTECTED_PREFIXES) or s == target:
        return None, "SOURCE_CLEANUP_PROTECTED"
    if _git(repo, "rev-parse", "--verify", "-q", "refs/heads/" + s).returncode != 0:
        return None, "SOURCE_NOT_FOUND"
    if _git(repo, "remote", "get-url", remote).returncode != 0:
        return None, "SOURCE_CLEANUP_NO_REMOTE"
    cur = (_git(repo, "symbolic-ref", "--short", "-q", "HEAD").stdout or "").strip()
    if cur == s:
        return None, "SOURCE_CLEANUP_CHECKED_OUT"
    ls = _git(repo, "ls-remote", "--heads", remote, "refs/heads/" + s)
    return {"remote": remote, "branch": s,
            "remote_exists": bool((ls.stdout or "").strip())}, ""


def _cleanup_after_merge(repo: str, plan: dict, src_sha: str) -> dict:
    """合并成功后收口：归档 tip → 删远端分支 → `ls-remote` 校验（任一步失败即停）。"""
    res = {"ok": True, "remote": plan.get("remote", ""), "branch": plan.get("branch", ""),
           "archived_ref": "", "deleted": False, "verified": False}
    if not src_sha:
        return dict(res, ok=False, code="SOURCE_CLEANUP_NOT_MERGED", detail="源 sha 不可解析")
    if _git(repo, "merge-base", "--is-ancestor", src_sha, "HEAD").returncode != 0:
        return dict(res, ok=False, code="SOURCE_CLEANUP_NOT_MERGED")
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    ref = "refs/gk-archive/merged/%s/%s" % (plan["branch"], ts)
    ar = _git(repo, "update-ref", ref, src_sha)
    if ar.returncode != 0:
        return dict(res, ok=False, code="SOURCE_CLEANUP_ARCHIVE_FAILED",
                    detail=(ar.stderr or "").strip()[:500])
    res["archived_ref"] = ref
    if plan.get("remote_exists"):
        d = _git(repo, "push", plan["remote"], "--delete", plan["branch"])
        if d.returncode != 0:
            return dict(res, ok=False, code="SOURCE_CLEANUP_DELETE_FAILED",
                        detail=(d.stderr or d.stdout or "").strip()[:800])
        res["deleted"] = True
    ls = _git(repo, "ls-remote", "--heads", plan["remote"], "refs/heads/" + plan["branch"])
    if (ls.stdout or "").strip():
        return dict(res, ok=False, code="SOURCE_CLEANUP_VERIFY_FAILED")
    res["verified"] = True
    return res


def run(source: str, target: str = "", repo: str = "", dry_run: bool = False,
        allow_index_deletions: bool = False, message: str = "",
        allow_source_deletions: bool = False, progress=None,
        cleanup_source_remote: bool = False, remote: str = "origin") -> tuple:
    """执行一次受闸合并；返回 `(rc, payload)`。

    `progress(msg)`：**心跳**（走 stderr，不污染 stdout 的 JSON）。调用方空闲超时看的是
    「有没有输出」，不是「跑了多久」⟹ 每步一行比调大超时更可靠（2026-11-13）。
    """
    t0 = time.time()

    def hb(msg: str) -> None:
        if progress:
            progress("[merge] %6.1fs %s" % (time.time() - t0, msg))

    repo = G.norm_repo(repo or G._default_repo())
    tgt = G._target(repo, target)
    out = {"ok": False, "decision": "BLOCK", "repo": repo, "source": source, "target": tgt}
    hb("start source=%s target=%s repo=%s" % (source, tgt, repo))
    if not tgt:
        return 3, dict(out, **_block("TARGET_NOT_FOUND"))
    cd = H.common_dir(repo)
    if not cd:
        return 3, dict(out, **_block("TARGET_NOT_FOUND", detail="git common dir 不可解析"))
    lock_path = os.path.join(cd, "gatekeeper-merge.lock")
    lock_f = open(lock_path, "w")
    try:
        if fcntl is not None:
            fcntl.flock(lock_f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock_f.close()
        return 3, dict(out, **_block("MERGE_BUSY"))
    hb("单队列锁 ok")
    try:
        if _git(repo, "rev-parse", "--verify", "-q", "MERGE_HEAD").returncode == 0:
            return 3, dict(out, **_block("MERGE_IN_PROGRESS"))
        staged = _staged_paths(repo)
        if staged:
            return 3, dict(out, **_block("DIRTY_INDEX", files=staged[:20], count=len(staged)))
        hb("暂存面干净")
        cleanup_plan = None
        if cleanup_source_remote:
            cleanup_plan, why = _cleanup_precheck(repo, source, tgt, remote)
            if why:
                return 3, dict(out, **_block(why))
            out["source_cleanup"] = dict(cleanup_plan, planned=True)
            hb("源远端分支清理预检 ok（%s）"
               % ("远端存在" if cleanup_plan["remote_exists"] else "远端已无"))
        pre = G.check(repo, source, tgt, allow_source_deletions=allow_source_deletions)
        out["gate"] = pre
        hb("闸① %s" % (pre.get("decision") or "BLOCK"))
        if not pre.get("ok"):
            return 3, dict(out, decision=pre.get("decision") or "BLOCK",
                           reasons=pre.get("reasons"))
        if dry_run:
            out.update({"ok": True, "decision": "DRY_RUN"})
            return 0, out
        mg = _git(repo, "merge", "--no-ff", "--no-commit", source)
        if mg.returncode != 0:
            _git(repo, "merge", "--abort")
            return 3, dict(out, **_block("MERGE_FAILED",
                                         detail=(mg.stderr or mg.stdout or "").strip()[:1500]))
        hb("git merge ok（未提交）")
        st = G.check_staged_merge(repo, "HEAD",
                                  allow_index_deletions=allow_index_deletions)
        out["staged_gate"] = st
        hb("闸② %s" % (st.get("decision") or "BLOCK"))
        if not st.get("ok"):
            _git(repo, "merge", "--abort")
            return 3, dict(out, decision=st.get("decision") or "BLOCK",
                           reasons=st.get("reasons"))
        if any(r.get("code") == "FACTS_REBUILD_REQUIRED" for r in pre.get("reasons") or []):
            hb("合并触达事实源 ⟹ 重算 GK-FACTS")
            subprocess.run([sys.executable, str(_FACTS),
                            "--write", "--skill-dir", repo], capture_output=True, text=True)
            # 生成物必须**显式入暂存**：`git commit` 只提交 index，未 add 的重算结果会残留在
            # 工作区 ⟹ 事实块与代码不同步（2026-11-13 实测：合并后 `git status` 恒脏、
            # 下一次合并被 "local changes would be overwritten" 挡死）。清单单源 = 生成器 DOCS。
            _docs = _facts_docs(repo)
            if _docs:
                _git(repo, "add", "--", *_docs)
                hb("事实块入暂存 %d 份" % len(_docs))
        old = (_git(repo, "rev-parse", tgt).stdout or "").strip()
        src_sha = (_git(repo, "rev-parse", source).stdout or "").strip()
        hb("签票 + 提交合并")
        H.write_ticket(cd, "refs/heads/" + tgt, old, src_sha)
        msg = message or ("merge: %s → %s（合并前置闸 R0.24）" % (source, tgt))
        cm = _git(repo, "commit", "-m", msg)
        if cm.returncode != 0:
            try:
                os.unlink(H.ticket_path(cd))
            except OSError:
                pass
            return 3, dict(out, **_block("COMMIT_FAILED",
                                         detail=(cm.stderr or cm.stdout or "").strip()[:1500]))
        try:                              # 钩子已消费；未装钩子时这里兜底清票（防陈旧票重放）
            os.unlink(H.ticket_path(cd))
        except OSError:
            pass
        if cleanup_plan is not None:
            sc = _cleanup_after_merge(repo, cleanup_plan, src_sha)
            out["source_cleanup"] = sc
            hb("源远端分支清理：%s" % ("ok" if sc.get("ok") else sc.get("code")))
        out.update({"ok": True, "decision": "MERGED",
                    "commit": (_git(repo, "rev-parse", "HEAD").stdout or "").strip(),
                    "ahead": pre.get("ahead"), "behind": pre.get("behind")})
        hb("done commit=%s" % out["commit"][:12])
        return 0, out
    finally:
        try:
            if fcntl is not None:
                fcntl.flock(lock_f, fcntl.LOCK_UN)
        finally:
            lock_f.close()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_merge_cli.py", description="受闸合并（唯一入口）")
    ap.add_argument("--source", required=True, help="待合并分支")
    ap.add_argument("--target", default="", help="目标分支（缺省 master/main）")
    ap.add_argument("--repo", default="", help="仓库路径（缺省 = 主仓）")
    ap.add_argument("--dry-run", action="store_true", help="只跑闸①，不动仓库")
    ap.add_argument("--allow-index-deletions", action="store_true",
                    help="显式承认暂存面删除（透传闸②）")
    ap.add_argument("--allow-deletions", action="store_true",
                    help="显式承认 source 的删除属预期清理（透传闸①2）")
    ap.add_argument("--message", default="", help="合并提交信息（缺省自动生成）")
    ap.add_argument("--cleanup-source-remote", action="store_true",
                    help="合并成功后归档 tag-ref 并删除远端源分支（保护分支/gk-pool 拒绝）")
    ap.add_argument("--remote", default="origin", help="远端名（--cleanup-source-remote 用；默认 origin）")
    ap.add_argument("--quiet", action="store_true", help="关闭心跳（默认每步一行到 stderr）")
    ns = ap.parse_args(argv)

    def _progress(msg: str) -> None:
        """心跳走 **stderr**：stdout 必须保持单个 JSON（调用方按 JSON 解析）。"""
        if not ns.quiet:
            sys.stderr.write(msg + "\n")
            sys.stderr.flush()

    rc, payload = run(ns.source, ns.target, ns.repo, ns.dry_run,
                      ns.allow_index_deletions, ns.message, ns.allow_deletions,
                      progress=_progress,
                      cleanup_source_remote=ns.cleanup_source_remote, remote=ns.remote)
    print(json.dumps(payload, ensure_ascii=False))
    return rc


if __name__ == "__main__":
    sys.exit(main())

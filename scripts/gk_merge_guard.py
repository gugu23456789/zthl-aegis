#!/usr/bin/env python3
"""gk_merge_guard.py — 合并前置闸（2026-11-13，owner 令「标准化合并前置闸」）。

来源：master 并发实现「分支合并退化防护」（c9961232 + 4fb5306b，仅 Git 层）；
本版扩为**一道**标准化闸 = Git 层（退化/回退）+ 仓库层不变量（受保护区 / 事实块 / 暂存面）。

闸 ①（merge 前，`--source <branch>`）：
  ①1 source 严格落后 target（无独有提交）⟹ BLOCK `SOURCE_BEHIND_TARGET`
  ①2 source 相对 merge-base 删除、target 仍存在的文件 ⟹ BLOCK `MERGE_DELETES_TARGET_FILES`
     （**确属预期清理**时用 `--allow-source-deletions` 显式声明，降为 WARN 并逐条列出）
  ①3 模拟合并结果丢失 target 路径 ⟹ BLOCK `MERGE_TREE_DROPS_TARGET_PATHS`
  ①4 模拟合并冲突 ⟹ BLOCK `MERGE_CONFLICT`
  ①5 source 独有提交均已在 target 有等价补丁 ⟹ WARN `SOURCE_EQUIVALENT_ONLY`
  ①6 `PROTECTED_REGION` 内容行减少 ⟹ BLOCK `PROTECTED_REGION_SHRINK`
  ①7 合并触达 GK-FACTS 事实源 ⟹ WARN `FACTS_REBUILD_REQUIRED`（合并后必须 `--write`）

闸 ②（merge 进行中，`--staged-merge`；`commit` 检出 MERGE_HEAD 时强制执行）：
  ②1 暂存面带删除 ⟹ BLOCK `STAGED_DELETIONS`（否则 merge 提交把产物清理/误删写进历史）
  ②2 暂存面相对 HEAD 丢路径 ⟹ BLOCK `MERGE_TREE_DROPS_TARGET_PATHS`
  ②3 受保护区内容行减少 ⟹ BLOCK `PROTECTED_REGION_SHRINK`

每条 BLOCK 都带 `next`：给出**可执行**的合法推进方式（不靠手工拼 git 命令）。
只读保证：不写 ref / 不写对象库 / 不改 index（三方合并只在临时目录用 `git merge-file`）。

合并路径枚举（**全部**必须过本闸；2026-11-13 owner 令「不能以任何形式绕过」）:
  · 真合并：`git merge`（含 `--ff-only`）、`git pull`（= fetch + merge）
  · 变基/拣选落地：`git cherry-pick`、`git rebase`、`git am`
  · 直接搬 ref：`git reset --hard <branch>`、`git branch -f master <branch>`、`git update-ref`
  · 远端直推：`git push origin <branch>:master`（既有 Gate R0.21 拦）
  · CLI 面：`commit`（MERGE_HEAD ⟹ 闸②）、`merge`（唯一合法入口：闸①→merge→闸②→提交）
  · **不产生合并**（只读/纯状态，故不设闸）：worktree 回收与池归还、ECC 关单、audit/standing 序列
  三道防线：Agent 面 Gate R0.24 拦裸 merge 家族；Git 面 `reference-transaction` 票据
  （`.git/hooks/reference-transaction` → `scripts/gk_merge_hook.py`）拦人手/脚本；
  CLI 面 `merge` 是本仓唯一的合并入口（内部完成 闸①→merge→闸②→提交）。

CLI::
  python3 scripts/gk_merge_guard.py --source <branch> [--target master] [--repo <path>]
  python3 scripts/gk_merge_guard.py --staged-merge [--repo <path>] [--allow-index-deletions]
  # 0=SAFE/WARN, 3=BLOCK
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# 事实源（与 `gk_docgen_facts.collect()` 的输入同源）：任一变 ⟹ GK-FACTS 必须重算
_FACTS_SOURCES = (
    "gatekeeper-cli.sh", "scripts/gk_chain.py", "scripts/gk_self_check.py",
    "scripts/subagent_runner.py", "scripts/pre_tool_hook.py",
    "references/red-vectors.json", "references/red-intel-sources.json",
)
_PROT_MARK = "PROTECTED_REGION_START::"
_PROT_MARK_END = "PROTECTED_REGION_END::"

_NEXT = {
    "SOURCE_BEHIND_TARGET": "source 无独有提交 ⟹ 直接删分支（`git branch -d <src>`），不要 merge",
    "MERGE_DELETES_TARGET_FILES": "source 删了 target 仍在用的文件 ⟹ 先 `git checkout <target> -- <files>` 落回实现再合并；"
                                  "确属预期清理（如归档搬运旧产物）才加 `--allow-source-deletions` 显式声明",
    "MERGE_TREE_DROPS_TARGET_PATHS": "合并结果会丢 target 路径 ⟹ 属回退形态，先按冲突/删除面修复",
    "MERGE_CONFLICT": "先 `git merge --no-commit` 逐块解决（禁 `-X ours/theirs` 整取单边），再提交",
    "PROTECTED_REGION_SHRINK": "受保护区被合并削弱 ⟹ 恢复 target 版该区域后再合并（门禁自举面禁改）",
    "STAGED_DELETIONS": "暂存面的删除会被 merge 提交带走 ⟹ 先 `git restore --staged -- <paths>` 或单独提交清理；"
                        "确认是有意删除才 `--allow-index-deletions`",
    "FACTS_REBUILD_REQUIRED": "合并后跑 `python3 scripts/gk_docgen_facts.py --write` 再 `check`（否则 audit-docs 红）",
}


def _git(repo: str, *args) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)


def norm_repo(path: str) -> str:
    """仓库路径归一：Windows / WSL / MSYS 三形态 ⟹ 当前解释器**进得去**的形态。

    2026-11-13 R0.24：闸的调用方可能来自 bash（`C:/…`、`/mnt/c/…`、`/c/…`）或 Python，
    而 `git -C <path>` 对形态敏感（WSL git 不认 `C:/…`，Windows git 不认 `/mnt/c/…`）⟹
    同一仓库会被认成两个（`TARGET_NOT_FOUND` 假红，或被当成"另一个仓"绕过）。
    判据 = `git -C <cand> rev-parse --git-dir` 成功才算归一；全败 ⟹ 原样返回（不猜，fail-loud）。
    """
    raw = str(path or "").strip().strip('"').strip("'")
    if not raw:
        return raw
    cands = [raw]
    m = re.match(r"^([A-Za-z]):[\\/](.*)$", raw)
    if m:
        d, rest = m.group(1).lower(), m.group(2).replace("\\", "/")
        cands += ["/mnt/%s/%s" % (d, rest), "/%s/%s" % (d, rest)]
    else:
        m = re.match(r"^/mnt/([A-Za-z])/(.*)$", raw)
        if m:
            cands += ["%s:/%s" % (m.group(1).upper(), m.group(2)),
                      "/%s/%s" % (m.group(1), m.group(2))]
        else:
            m = re.match(r"^/([A-Za-z])/(.*)$", raw)
            if m:
                cands += ["/mnt/%s/%s" % (m.group(1), m.group(2)),
                          "%s:/%s" % (m.group(1).upper(), m.group(2))]
    for c in cands:
        if _git(c, "rev-parse", "--git-dir").returncode == 0:
            return c
    return raw


def _default_repo() -> str:
    """`--repo` 缺省 = **装目标分支的主工作树**（绝不是调用方 cwd / 脚本所在 worktree）。

    2026-11-13：原缺省 `.`（= 脚本所在树）⟹ 在 worktree 里跑 `premerge` 会对着 worktree 自己
    判「已合并」，主树一次都没查（实测假绿）。判据顺序：
      ① `GK_MAIN_REPO`（显式）→ ② `git worktree list` 首项（git 保证主工作树在前）
      → ③ `gk_main_repo.resolve()` → ④ 脚本所在仓（最后兜底，下游仍会 fail-loud）。
    """
    env = (os.environ.get("GK_MAIN_REPO") or "").strip()
    if env:
        c = norm_repo(env)
        if _git(c, "rev-parse", "--git-dir").returncode == 0:
            return c
    here = str(Path(__file__).resolve().parent.parent)
    try:
        r = subprocess.run(["git", "-C", here, "worktree", "list", "--porcelain"],
                           capture_output=True, text=True)
        for line in (r.stdout or "").splitlines():
            if line.startswith("worktree "):
                return norm_repo(line[len("worktree "):].strip())
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import gk_main_repo as M  # noqa: E402
        r2 = M.resolve()
        if r2.get("ok") and r2.get("wsl"):
            return norm_repo(r2["wsl"])
    except Exception:  # noqa: BLE001 — 解析失败由下游 fail-loud（TARGET_NOT_FOUND）
        pass
    return norm_repo(here)



def _ref_exists(repo: str, ref: str) -> bool:
    return _git(repo, "rev-parse", "--verify", "--quiet", ref).returncode == 0


def _target(repo: str, explicit: str = "") -> str:
    if explicit:
        return explicit
    for cand in ("master", "main"):
        if _ref_exists(repo, cand):
            return cand
    return ""


def _count(repo: str, rng: str) -> int:
    r = _git(repo, "rev-list", "--count", rng)
    try:
        return int((r.stdout or "0").strip())
    except ValueError:
        return 0


def _names(repo: str, *args) -> list:
    r = _git(repo, *args)
    if r.returncode != 0:
        return []
    return [x for x in (r.stdout or "").splitlines() if x.strip()]


_BLOB_CACHE = {}
# 只对这些扩展名做 blob 预取/三方模拟（二进制入 .png/.jpg 等 ⟹ 预取纯浪费带宽）
_TEXT_EXT = (".py", ".sh", ".md", ".json", ".txt", ".yml", ".yaml", ".html", ".css", ".js", ".toml")


def _exists_batch(repo: str, rev: str, paths) -> set:
    """**一次** `cat-file --batch-check` 判多路径在 rev 中是否为 blob（存在且非树）。"""
    todo = list(dict.fromkeys(paths or []))
    if not todo:
        return set()
    data = "".join("%s:%s\n" % (rev, p) for p in todo).encode()
    r = subprocess.run(["git", "-C", repo, "cat-file", "--batch-check"],
                       input=data, capture_output=True)
    got = set()
    for p, ln in zip(todo, (r.stdout or b"").decode("utf-8", "replace").splitlines()):
        parts = ln.split()
        if len(parts) == 3 and parts[1] == "blob":
            got.add(p)
    return got


def _prefetch(repo: str, rev: str, paths) -> None:
    """**一次** `git cat-file --batch` 预取多个 blob 到进程内缓存（2026-11-13 提速）。

    实测（WSL + /mnt/c）：单次 `git show` **200–800 ms**，闸①原实现每文件 3 次 show ⟹
    30 个文件就要 20–40 s，正好撞上调用方空闲超时。合并成一个进程后同一批只花一次进程启动。
    """
    todo = [p for p in dict.fromkeys(paths or []) if (repo, rev, p) not in _BLOB_CACHE]
    if not todo:
        return
    if len(_BLOB_CACHE) > 512:               # 一次性 CLI 无需上限；常驻进程防无界增长
        _BLOB_CACHE.clear()
    data = "".join("%s:%s\n" % (rev, p) for p in todo).encode()
    r = subprocess.run(["git", "-C", repo, "cat-file", "--batch"],
                       input=data, capture_output=True)
    buf, pos = r.stdout, 0
    for p in todo:
        nl = buf.find(b"\n", pos)
        if r.returncode != 0 or nl < 0:
            _BLOB_CACHE[(repo, rev, p)] = None
            continue
        header, pos = buf[pos:nl].split(b" "), nl + 1
        if len(header) == 3 and header[1] == b"blob":
            size = int(header[2])
            chunk = buf[pos:pos + size]
            pos += size + 1
            _BLOB_CACHE[(repo, rev, p)] = (None if b"\x00" in chunk[:4096]
                                           else chunk.decode("utf-8", "replace"))
        else:                                  # `<spec> missing` / 非 blob
            _BLOB_CACHE[(repo, rev, p)] = None


def _protected_files(repo: str, rev: str) -> list:
    """**一次** `git grep -l` 列出含 `PROTECTED_REGION_START` 的 .sh/.py（替掉逐文件读取）。"""
    r = _git(repo, "grep", "-l", "-e", _PROT_MARK, rev, "--", "*.sh", "*.py")
    if r.returncode not in (0, 1):
        return []
    return [ln.split(":", 1)[1] for ln in (r.stdout or "").splitlines() if ":" in ln]


def _blob(repo: str, rev: str, path: str):
    """取某 revision 的文本内容；二进制/缺失 ⟹ None（不猜）。带进程内缓存（见 `_prefetch`）。"""
    key = (repo, rev, path)
    if key not in _BLOB_CACHE:
        _prefetch(repo, rev, [path])
    return _BLOB_CACHE.get(key)


def protected_regions(text: str) -> dict:
    """解析 `PROTECTED_REGION_START::name` … `END::name` 区间的内容行（去空行）。"""
    out, cur, buf = {}, None, []
    for ln in (text or "").splitlines():
        s = ln.strip()
        # 标记行允许被注释前缀包裹（`# PROTECTED_REGION_START::gate`），故用 `in` 而非 startswith
        if _PROT_MARK in s:
            cur, buf = s.split(_PROT_MARK, 1)[1].strip(), []
        elif _PROT_MARK_END in s:
            name = s.split(_PROT_MARK_END, 1)[1].strip()
            if cur is not None and name == cur:
                out[cur] = [x for x in buf if x.strip()]
            cur, buf = None, []
        elif cur is not None:
            buf.append(ln)
    return out


def _simulate_merge(repo: str, base: str, ours_rev: str, theirs_rev: str, path: str):
    """三方模拟合并单个文件（`git merge-file`，git≥2.34 可用）。

    返回 (merged_text|None, conflicted: bool)。仅临时目录写盘，不动仓库。
    """
    b = _blob(repo, base, path)
    o = _blob(repo, ours_rev, path)
    t = _blob(repo, theirs_rev, path)
    if o is None and t is None:
        return None, False
    if o is None or t is None:            # 单边新增/删除 ⟹ 无需三方合并
        return (t if o is None else o), False
    with tempfile.TemporaryDirectory() as d:
        po, pb, pt = Path(d, "o"), Path(d, "b"), Path(d, "t")
        po.write_text(o, encoding="utf-8")
        pb.write_text(b or "", encoding="utf-8")
        pt.write_text(t, encoding="utf-8")
        r = subprocess.run(["git", "merge-file", "-p", str(po), str(pb), str(pt)],
                           capture_output=True, text=True)
    conflicted = r.returncode > 0 or "<<<<<<<" in (r.stdout or "")
    return r.stdout, conflicted


def _protected_shrink(repo: str, base: str, tgt: str, src: str, files=None) -> list:
    """合并结果里任一 `PROTECTED_REGION` 的内容行少于 target ⟹ 返回受影响项。"""
    files = files if files is not None else _protected_files(repo, tgt)
    shrunk = []
    for p in files:
        if not p.endswith((".sh", ".py")):
            continue
        tgt_txt = _blob(repo, tgt, p)
        if not tgt_txt or _PROT_MARK not in tgt_txt:
            continue
        merged, conflicted = _simulate_merge(repo, base, tgt, src, p)
        if merged is None:
            continue
        tr, mr = protected_regions(tgt_txt), protected_regions(merged)
        for name, lines in tr.items():
            cur = mr.get(name)
            if conflicted and not cur:
                cur = []                  # 整段被冲突吞掉 = 等价于丢失
            if cur is None:
                continue
            lost = len(lines) - len(cur)
            if lost > 0:
                missing = [x for x in lines if x not in cur] or lines
                shrunk.append({"path": p, "region": name, "lost_lines": lost,
                               "sample": missing[0][:120]})
    return shrunk


def _facts_touched(repo: str, base: str, src: str, changed=None) -> list:
    changed = set(changed) if changed is not None else set(_names(repo, "diff", "--name-only", base, src))
    hit = [p for p in _FACTS_SOURCES if p in changed]
    if any(p.startswith("references/") and p.endswith(".md") for p in changed):
        hit.append("references/*.md（文件地图）")
    return hit


def check(repo: str, source: str, target: str = "",
          allow_source_deletions: bool = False) -> dict:
    repo = norm_repo(repo)
    tgt = _target(repo, target)
    out = {"ok": False, "decision": "BLOCK", "mode": "pre-merge", "repo": repo,
           "source": source, "target": tgt, "reasons": [], "deleted_by_source": [],
           "missing_in_merge": [], "ahead": 0, "behind": 0, "protected_shrink": []}

    def block(code, **kw):
        """BLOCK 统一出口：附**可执行** next（合法推进方式，不靠手工拼 git）。"""
        kw["code"] = code
        kw["next"] = _NEXT.get(code, "")
        out["reasons"].append(kw)
        return out

    if not tgt:
        return block("TARGET_NOT_FOUND")
    if not _ref_exists(repo, source):
        return block("SOURCE_NOT_FOUND")
    if not _ref_exists(repo, tgt):
        return block("TARGET_NOT_FOUND")
    base_r = _git(repo, "merge-base", tgt, source)
    base = (base_r.stdout or "").strip()
    if base_r.returncode != 0 or not base:
        return block("NO_MERGE_BASE")
    out["base"] = base
    out["ahead"] = _count(repo, "%s..%s" % (tgt, source))
    out["behind"] = _count(repo, "%s..%s" % (source, tgt))
    if out["ahead"] == 0 and out["behind"] == 0:
        out.update({"ok": True, "decision": "ALREADY_MERGED"})
        out["reasons"].append({"code": "ALREADY_MERGED"})
        return out
    if out["ahead"] == 0 and out["behind"] > 0:
        return block("SOURCE_BEHIND_TARGET",
                     detail="source 无独有提交，严格落后 target")
    # source 的独有提交若全部已在 target 有等价补丁 ⟹ 合并只会产生无内容变更的 merge commit；
    # 建议删除分支而不是 merge（2026-11-13 退役 `6af33090-r408` 的实测形态）。
    equivalent_only = False
    cherry = _git(repo, "cherry", tgt, source)
    if cherry.returncode == 0:
        lines = [x for x in (cherry.stdout or "").splitlines() if x.strip()]
        equivalent_only = bool(lines) and all(x.startswith("-") for x in lines)
        if equivalent_only:
            out["reasons"].append({"code": "SOURCE_EQUIVALENT_ONLY",
                                   "detail": "source 独有提交均已在 target 有等价补丁；建议删除分支而非 merge",
                                   "next": _NEXT["SOURCE_BEHIND_TARGET"]})
    # ② source 相对 base 的删除；target 仍存在的才危险
    deleted = _names(repo, "diff", "--diff-filter=D", "--name-only", base, source)
    # 一次 batch-check 判「target 是否仍有该路径」（原实现每文件一个 cat-file -e ⟹ N×300ms）
    alive = _exists_batch(repo, tgt, deleted)
    dangerous = [p for p in deleted if p in alive]
    changed = _names(repo, "diff", "--name-only", base, source)   # 只算一次，下游复用
    tgt_paths = set(_names(repo, "ls-tree", "-r", "--name-only", tgt))
    # 受保护区候选 = source 改过、且 target 里**存在**的 .sh/.py（不存在的没有"缩水"可言）
    prot_cands = [p for p in changed if p.endswith((".sh", ".py")) and p in tgt_paths]
    out["deleted_by_source"] = deleted
    if dangerous and not allow_source_deletions:
        return block("MERGE_DELETES_TARGET_FILES", files=dangerous)
    if dangerous:
        # 显式声明 = 预期清理（如归档搬运后的旧产物）；仍逐条列出，别让"声明"变成静默
        out["reasons"].append({"code": "SOURCE_DELETIONS_DECLARED",
                               "files": dangerous[:50],
                               "detail": "已显式 --allow-source-deletions（预期清理，不是回退）"})
    # ③ 模拟合并结果（Git >= 2.38 `merge-tree --write-tree`）
    mt = _git(repo, "merge-tree", "--write-tree", tgt, source)
    merged_paths = None
    if mt.returncode == 1:
        return block("MERGE_CONFLICT",
                     detail=(mt.stdout or mt.stderr or "").strip()[:2000])
    if mt.returncode == 0 and (mt.stdout or "").strip():
        tree = (mt.stdout or "").splitlines()[0].strip()
        if tree and len(tree) >= 40:
            tgt_paths = set(_names(repo, "ls-tree", "-r", "--name-only", tgt))
            merged_paths = _names(repo, "ls-tree", "-r", "--name-only", tree)
            missing = sorted(tgt_paths - set(merged_paths))
            out["missing_in_merge"] = missing
            if missing:
                return block("MERGE_TREE_DROPS_TARGET_PATHS", files=missing[:50])
    else:
        # Git < 2.38（本机 2.34）：逐文件 `git merge-file` 模拟。
        #   ⚠ 2026-11-13 修：原实现把旧 `merge-tree` 打印的 "changed in both" 判为冲突 ——
        #   该行对**可干净合并**的同文件双改也会出现 ⟹ 恒 BLOCK（假阳性，会把正常合并挡死）。
        #   冲突判据只认 `<<<<<<<` 标记（merge-file 返回值 >0 即含标记）。
        both = sorted(set(_names(repo, "diff", "--name-only", base, tgt)) & set(changed))
        # 一次批量预取三方 blob —— 只取**确实要读**的（both ∪ 受保护区候选）。
        #   ⚠ 2026-11-13 修：曾按「source 改过的全部文本」预取（本仓 800 文件，多数在 target
        #   不存在）⟹ `cat-file --batch` 对每个 `<rev>:<缺失路径>` 都要走一次树查找，实测 45 s。
        cands = [p for p in dict.fromkeys(list(both) + prot_cands) if p.endswith(_TEXT_EXT)]
        for _rev in (base, tgt, source):
            _prefetch(repo, _rev, cands)
        conflicts = []
        for p in both:
            if _blob(repo, base, p) is None:
                continue                    # add/add 由下方受保护区/路径检查覆盖
            _, conflicted = _simulate_merge(repo, base, tgt, source, p)
            if conflicted:
                conflicts.append(p)
        if conflicts:
            # 2026-11-13 ECC-MERGE-SIM-SYM：**反向复算**。实测：`ours=master` 方向 merge-file
            #   报冲突，而 `git merge` 实际自动合并成功（merge-file 不做整树 rename/上下文归一）
            #   ⟹ 单向不足判死。判据 = **双向都冲突**才 BLOCK；仅单向降 WARN，交 git 裁决。
            hard = [p for p in conflicts
                    if _simulate_merge(repo, base, source, tgt, p)[1]]
            if hard:
                return block("MERGE_CONFLICT",
                             detail="双向 merge-file 冲突: " + ",".join(hard[:20]))
            out["reasons"].append({"code": "MERGE_SIM_ASYMMETRY", "files": conflicts,
                                   "detail": "单向 merge-file 冲突、反向可合 ⟹ 交 git 裁决（不预拦）"})
        out["reasons"].append({"code": "MERGE_TREE_FALLBACK",
                               "detail": "git<2.38：逐文件 merge-file 模拟（无冲突）"})
    # ①6 受保护区缩水（只查合并会触达的文件 ⟹ 成本可控；候选集见上方 `prot_cands`）
    shrink = _protected_shrink(repo, base, tgt, source,
                               files=[p for p in (merged_paths or prot_cands)
                                      if p.endswith((".sh", ".py"))])
    out["protected_shrink"] = shrink
    if shrink:
        return block("PROTECTED_REGION_SHRINK", regions=shrink[:10])
    # ①7 事实块须重算（合并触达事实源 ⟹ GK-FACTS 必然漂移）
    facts = _facts_touched(repo, base, source, changed=changed)
    if facts:
        out["reasons"].append({"code": "FACTS_REBUILD_REQUIRED", "files": facts,
                               "next": _NEXT["FACTS_REBUILD_REQUIRED"]})
    out.update({"ok": True,
                "decision": "WARN" if (equivalent_only or facts or deleted
                                        or any(r["code"] == "MERGE_SIM_ASYMMETRY"
                                               for r in out["reasons"])) else "SAFE"})
    if deleted:
        out["reasons"].append({"code": "SOURCE_DELETIONS_NOT_IN_TARGET",
                               "files": deleted[:50]})
    return out


def check_staged_merge(repo: str, target: str = "HEAD",
                       allow_index_deletions: bool = False) -> dict:
    """闸 ②：merge 进行中（MERGE_HEAD 存在）校验**暂存面**，防 merge 提交误删/回退。

    实测事故形态（2026-11-13 本仓）：工作区有 792 条 `docs/analysis/**` 暂存删除，
    一次 merge 提交会把它们**一起写进历史**（`git commit` 提交整个 index）。
    """
    repo = norm_repo(repo)
    out = {"ok": False, "decision": "BLOCK", "mode": "staged-merge", "repo": repo,
           "target": target, "reasons": [], "staged_deletions": [],
           "dropped_paths": [], "protected_shrink": []}

    def block(code, **kw):
        kw["code"] = code
        kw["next"] = _NEXT.get(code, "")
        out["reasons"].append(kw)
        return out

    if not _ref_exists(repo, target):
        return block("TARGET_NOT_FOUND")
    dels = _names(repo, "diff", "--cached", "--diff-filter=D", "--name-only")
    out["staged_deletions"] = dels
    if dels and not allow_index_deletions:
        return block("STAGED_DELETIONS", files=dels[:50], count=len(dels))
    # 改名不是删除：`git diff` 默认 `diff.renames=true` ⟹ 纯改名不出现在 D 面，
    # 但旧路径会从 index 消失。不扣除 rename 源 ⟹ 闸②把「归档搬运」误判为丢路径
    # （2026-11-13 实测：779 份报告归档为 rename，merge 被 MERGE_TREE_DROPS_TARGET_PATHS 挡死）。
    renames = set()
    for ln in _names(repo, "diff", "--cached", "-M", "--name-status", "--diff-filter=R"):
        parts = ln.split("\t")
        if len(parts) >= 3 and parts[0].startswith("R"):
            renames.add(parts[1])
    out["staged_renames"] = sorted(renames)[:50]
    head_paths = set(_names(repo, "ls-tree", "-r", "--name-only", target))
    idx_paths = {ln.split("\t", 1)[1] for ln in _names(repo, "ls-files", "-s")
                 if "\t" in ln}
    dropped = sorted(head_paths - idx_paths - set(dels) - renames)   # 已声明的删除/改名不算「丢路径」
    out["dropped_paths"] = dropped
    if dropped:
        return block("MERGE_TREE_DROPS_TARGET_PATHS", files=dropped[:50])
    shrink = []
    # 候选集用一次 `git grep` 拿（原实现遍历全仓 .sh/.py 逐文件 `git show` ⟹ 分钟级）
    prot = _protected_files(repo, target)
    _prefetch(repo, target, [p for p in prot if p.endswith(_TEXT_EXT)])
    for p in sorted(prot):
        tgt_txt = _blob(repo, target, p)
        if not tgt_txt or _PROT_MARK not in tgt_txt:
            continue
        try:
            cur = Path(repo, p).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        tr, cr = protected_regions(tgt_txt), protected_regions(cur)
        for name, lines in tr.items():
            got = cr.get(name) or []
            lost = len(lines) - len(got)
            if lost > 0:
                missing = [x for x in lines if x not in got] or lines
                shrink.append({"path": p, "region": name, "lost_lines": lost,
                               "sample": missing[0][:120]})
    out["protected_shrink"] = shrink
    if shrink:
        return block("PROTECTED_REGION_SHRINK", regions=shrink[:10])
    out.update({"ok": True, "decision": "WARN" if dels else "SAFE"})
    if dels:
        out["reasons"].append({"code": "STAGED_DELETIONS_ALLOWED", "count": len(dels),
                               "detail": "已显式 --allow-index-deletions"})
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="合并前置闸（退化/回退/误删；只读）")
    ap.add_argument("--repo", default="", help="git 仓库路径（缺省 = 主仓，单源 gk_main_repo）")
    ap.add_argument("--source", default="", help="待合并分支（pre-merge 模式必填）")
    ap.add_argument("--target", default="", help="目标分支（pre-merge 缺省 master/main）")
    ap.add_argument("--staged-merge", action="store_true",
                    help="merge 进行中模式：校验暂存面（MERGE_HEAD 存在时由 commit 强制执行）")
    ap.add_argument("--allow-index-deletions", action="store_true",
                    help="显式承认暂存面删除（会随 merge 提交写入历史）")
    ap.add_argument("--allow-source-deletions", action="store_true",
                    help="显式承认 source 相对 base 的删除属预期清理（闸①2 降为 WARN）")
    ns = ap.parse_args(argv)
    repo = ns.repo or _default_repo()
    if ns.staged_merge:
        out = check_staged_merge(repo, ns.target or "HEAD",
                                 allow_index_deletions=ns.allow_index_deletions)
    else:
        if not ns.source:
            print(json.dumps({"ok": False, "decision": "BLOCK",
                              "reasons": [{"code": "SOURCE_REQUIRED",
                                           "next": "--source <branch> 或 --staged-merge"}]},
                             ensure_ascii=False))
            return 3
        out = check(repo, ns.source, ns.target, allow_source_deletions=ns.allow_source_deletions)
    print(json.dumps(out, ensure_ascii=False))
    return 0 if out.get("ok") else 3


if __name__ == "__main__":
    sys.exit(main())

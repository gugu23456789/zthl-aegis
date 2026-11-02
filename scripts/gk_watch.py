#!/usr/bin/env python3
"""蓝鳍瞭望（Bluefin Watch，`state --watch`）：双向、只读的跨平台缺陷探针。
（代号取「蓝色大肥鱼」→ 蓝鳍，仅作标识；功能面即全部。）

功能（不含叙事）：在 WSL 或 Windows 任一侧运行，输出同一套规范化快照，供两侧互比。同一份代码在
两套解释器、路径形态、换行与大小写语义下必然分叉；本命令把这些分叉变成可判定的 `issues[]`。

  ``state --watch --save .zthl/watch/<side>.json``     # 本侧快照（显式写盘，默认零写）
  ``state --watch --compare .zthl/watch/win.json``     # 与另一侧快照比对 ⟹ divergences[]

边界（本命令的 "gate"）：读 = 不进 `.trae-cn/`、`AppData/Roaming/Trae CN/`、`.keys/`（约束 M）；
写 = 只允许 `<skill_dir>/.zthl/watch/**` 或 `~/.trae/watch/**`，其余 `SAVE_PATH_NOT_ALLOWED`（exit 2）；
输出 = 身份字面量默认脱敏为 `<user>`，`--reveal` 才全文。

探针（每项都给 `os_ref`，直接对接 zthl-adapter §ZH4 OS-1…OS-8）：
  path_forms           `C:/…` vs `/mnt/c/…` 分布 + 归一后是否同一棵树
  worktree_git_view    每个 worktree 的 `.git` 文件形态 + 本侧能否解析（双环境经典坑）
  state_owner          各 state 顶层 `worktree`（归一比较；与 `gk_state_route` 同源）
  line_endings         CRLF / 混合换行（跨侧编辑高频污染）
  identity_literals    `/mnt/c/Users/…`、`C:\\Users\\…` 字面量（OS-6）
  runtime_artifacts    运行期产物是否在跟踪面（OS-5）
  remote_whitelist     远端 vs `_ALLOWED_REMOTE_PATTERNS`（OS-7）
  case_sensitivity     大小写变体路径是否可解析（Windows 不敏感 / WSL 敏感）
  interpreter          本侧解释器 + pytest 可用性（分档测试腿的真假 SKIP 判据）

用法：`gatekeeper-cli.sh state --watch [--hours <h>] [--commits 10] [--limit 30]
      [--save <json>] [--compare <json>]`

口径（2026-11-02 起）：**缺省 = 实时**——`live` 段给「此刻工作区 + 最近 commit 记录 +
gitnexus 索引基线」，不依赖时间窗；`--hours` 只是可选过滤（给才按 mtime 列 `recent`）。
"""
import argparse
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".pytest_cache", ".venv", "venv",
             ".keys",                       # 密钥面：只读也不列名（防快照泄露 key 文件名）
             # 2026-11-01（实测：本仓 walk 12,993 文件 / docs/analysis/subagent 51MB ⟹ 探针
             #   静默跑 >2min，被误当「探针挂了」）：运行时产物与索引库不进扫描面。
             "subagent", ".gitnexus", ".gitnexus-store", ".graphify", ".pytest-tmp"}
# 读取边界（约束 M）：Trae 内部目录一律不进入（越界读会触发 IDE 报错/崩溃）
BLOCKED_DIR_MARKERS = (".trae-cn", "appdata/roaming/trae cn", "appdata\\roaming\\trae cn")
SCRATCH_GLOBS = (".mk_*.py", ".fix_*.py", ".extract_*.py", ".probe_*.py", ".gen_*.py",
                 ".patch_*.py", ".mk_*.sh", ".fix_*.sh")
ARTIFACT_SUFFIX = (".jsonl", ".json", ".lock", ".tmp", ".bak", ".seal", ".sig")
IDENTITY_RE = re.compile(r"(/mnt/[a-z]/Users/[^\s\"'`)]+|[A-Za-z]:[\\/]+Users[\\/][^\s\"'`)]+)")
TEXT_EXT = (".py", ".sh", ".md", ".json", ".yaml", ".yml", ".toml", ".bat", ".ps1", ".txt")

SIDE = "nt" if os.name == "nt" else ("wsl" if os.path.isdir("/mnt/c") else "posix")


# ── 路径：单一口径（canon ⇄ 本侧形态）────────────────────────────────────────
def _canon(p) -> str:
    """归一：\\→/、小写、去尾斜杠、`/mnt/c/…`→`c:/…`（语义同 `gk_self_check._gx_norm_path`）。"""
    p = str(p or "").strip().replace("\\", "/").lower().rstrip("/")
    if p.startswith("/mnt/") and len(p) > 6:
        p = p[5] + ":" + p[6:]
    return p


def _form(p) -> str:
    p = str(p or "").strip().replace("\\", "/")
    if re.match(r"^[a-z]:/", p, re.I):   # ⚠ 必须忽略大小写：Windows 侧常见 `C:/…`
        return "win"
    if p.startswith("/mnt/"):
        return "wsl"
    return "posix" if p.startswith("/") else "none"


def _local(p) -> str:
    """把任一形态的路径转成**本侧**可解析形态（用于 `isdir/read`；比较一律走 `_canon`）。"""
    p = str(p or "").strip()
    if not p:
        return ""
    if SIDE == "nt":
        c = _canon(p)
        return c.replace("/", "\\") if re.match(r"^[a-z]:", c) else p
    if re.match(r"^[a-z]:", p, re.I) and SIDE == "wsl":
        c = _canon(p)
        return "/mnt/%s/%s" % (c[0], c[2:].lstrip("/"))   # 去重斜杠：`c:/x` ⟹ `/mnt/c/x`
    return p


def _git(args, cwd=None):
    try:
        r = subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True, timeout=20)
        return r.stdout if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── 观测段 ───────────────────────────────────────────────────────────────────
def _worktrees(skill_dir):
    out, cur = [], {}
    for line in _git(["worktree", "list", "--porcelain"], skill_dir).splitlines():
        if not line.strip():
            if cur:
                out.append(cur)
                cur = {}
            continue
        k, _, v = line.partition(" ")
        cur[k] = v
    if cur:
        out.append(cur)
    rows = []
    for w in out:
        p = w.get("worktree", "")
        lp = _local(p)
        dotgit, git_form, gd_resolvable = "", "none", False
        gj = os.path.join(lp, ".git")
        if os.path.isdir(gj):                      # 主树：`.git` 是目录（无需解析 gitdir）
            dotgit, git_form, gd_resolvable = "(dir)", "dir", True
        elif os.path.isfile(gj):                   # worktree：`.git` 是文件，内含 `gitdir: <path>`
            try:
                first = open(gj, encoding="utf-8", errors="replace").readline().strip()
                dotgit = first[:120]
                gd = first.split(":", 1)[1].strip() if ":" in first else ""
                git_form = _form(gd)
                gd_resolvable = bool(gd) and os.path.exists(_local(gd))
            except OSError:
                pass
        st = _git(["status", "--porcelain", "-uno"], lp) if os.path.isdir(lp) else ""
        rows.append({
            "path": p, "canon": _canon(p), "form": _form(p),
            "head": (w.get("HEAD") or "")[:8],
            "branch": w.get("branch") or ("(detached)" if "detached" in w else ""),
            "prunable": "prunable" in w,
            "readable_here": os.path.isdir(lp),
            "dotgit": dotgit, "dotgit_form": git_form, "dotgit_resolvable": gd_resolvable,
            "dirty": len([x for x in st.splitlines() if x.strip()]),
        })
    return rows


def _blocked(path) -> bool:
    low = str(path or "").replace("\\", "/").lower()
    return any(m in low for m in BLOCKED_DIR_MARKERS)


def _mask_identity(match: str) -> str:
    """默认脱敏：保留盘符/形态与 `Users`，用户名段替换为 `<user>`（快照可入日志、可进 finding）。"""
    m = str(match or "")
    m = re.sub(r"(/mnt/[a-z]/Users/)[^/]+", r"\1<user>", m)
    m = re.sub(r"([A-Za-z]:[\\/]+Users[\\/])[^\\/]+", r"\1<user>", m)
    return m


def _walk_files(roots, cutoff, limit, depth=6):
    hits = []
    for root in roots:
        root = _local(root)
        if not root or not os.path.isdir(root) or _blocked(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames
                           if d not in SKIP_DIRS and not d.startswith(".venv")
                           and not _blocked(dirpath + "/" + d)]
            if dirpath.count(os.sep) - root.count(os.sep) > depth:
                dirnames[:] = []
                continue
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                if st.st_mtime >= cutoff:
                    hits.append({"path": os.path.relpath(p, root), "mtime": _iso(st.st_mtime),
                                 "size": st.st_size, "_m": st.st_mtime})
    hits.sort(key=lambda x: -x["_m"])
    for h in hits:
        h.pop("_m", None)
    return hits[:limit]


def _scratch(roots, limit=20):
    hits = []
    for root in roots:
        root = _local(root)
        if not root or not os.path.isdir(root):
            continue
        for name in sorted(os.listdir(root)):
            p = os.path.join(root, name)
            if os.path.isfile(p) and any(fnmatch.fnmatch(name, g) for g in SCRATCH_GLOBS):
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                hits.append({"path": os.path.relpath(p, root), "mtime": _iso(st.st_mtime),
                             "size": st.st_size})
    hits.sort(key=lambda x: x["mtime"], reverse=True)
    return hits[:limit]


def _states(roots, skill_dir):
    rows = []
    for root in roots:
        lroot = _local(root)
        if not lroot or not os.path.isdir(lroot):
            continue
        for name in sorted(os.listdir(lroot)):
            if not name.startswith(".gatekeeper.state"):
                continue
            if name.endswith(ARTIFACT_SUFFIX) or ".jsonl" in name:
                continue
            p = os.path.join(lroot, name)
            if not os.path.isfile(p):
                continue
            try:
                st = os.stat(p)
                d = json.load(open(p, encoding="utf-8"))
                w = str(d.get("worktree") or "")
                ok = bool(w) and _canon(w) == _canon(skill_dir)
                row = {"path": os.path.relpath(p, lroot), "size": st.st_size,
                       "mtime": _iso(st.st_mtime), "worktree": w, "worktree_canon": _canon(w),
                       "form": _form(w), "owner": "ok" if ok else ("missing" if not w else "mismatch")}
            except Exception as e:  # noqa: BLE001 — 边界：坏 state 具名，不中断观测
                row = {"path": os.path.relpath(p, lroot), "owner": "unreadable",
                       "error": type(e).__name__}
            rows.append(row)
    return rows


def _tracked(skill_dir):
    return [x for x in _git(["ls-files"], skill_dir).splitlines() if x.strip()]


def _probe_line_endings(skill_dir, files, cap=400):
    crlf, mixed, sample = 0, 0, []
    for rel in files[:cap]:
        if not rel.lower().endswith(TEXT_EXT):
            continue
        p = os.path.join(skill_dir, rel)
        try:
            b = open(p, "rb").read(262144)
        except OSError:
            continue
        crlf_n, lf_n = b.count(b"\r\n"), b.count(b"\n") - b.count(b"\r\n")
        if crlf_n and lf_n:
            mixed += 1
            sample.append({"file": rel, "crlf": crlf_n, "lf": lf_n})
        elif crlf_n:
            crlf += 1
    return {"crlf_only": crlf, "mixed": mixed, "sample": sample[:10], "scanned": min(cap, len(files))}


def _probe_identity(skill_dir, files, limit=20, reveal=False):
    hits = []
    for rel in files:
        if not rel.lower().endswith(TEXT_EXT) or _blocked(rel) or rel.startswith(".keys/"):
            continue
        p = os.path.join(skill_dir, rel)
        try:
            txt = open(p, encoding="utf-8", errors="ignore").read(262144)
        except OSError:
            continue
        for i, line in enumerate(txt.splitlines(), 1):
            m = IDENTITY_RE.search(line)
            if m:
                lit = m.group(1)
                hits.append({"file": rel, "line": i, "form": _form(lit),
                             "match": lit[:120] if reveal else _mask_identity(lit)[:80]})
                if len(hits) >= limit:
                    return hits
    return hits


def _probe_runtime_artifacts(files, limit=20):
    bad = []
    for rel in files:
        base = os.path.basename(rel)
        if (base.startswith(".gatekeeper.state") or base.endswith(".log")
                or rel.startswith("docs/analysis/subagent/")
                or base in ("gk_dbg.log", ".gatekeeper.scopes.json")):
            bad.append(rel)
            if len(bad) >= limit:
                break
    return bad


def _probe_remotes(skill_dir):
    allowed, remotes = [], []
    try:
        cli = open(os.path.join(skill_dir, "gatekeeper-cli.sh"), encoding="utf-8",
                   errors="ignore").read()
        m = re.search(r"_ALLOWED_REMOTE_PATTERNS=\((.*?)\)", cli, re.S)
        if m:
            allowed = re.findall(r'"(.*?)"', m.group(1))
    except OSError:
        pass
    for line in _git(["remote", "-v"], skill_dir).splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] not in remotes:
            remotes.append(parts[1])
    unmatched = [r for r in remotes if not any(a in r or a in r + "/" for a in allowed)]
    return {"remotes": remotes, "allowed": allowed, "unmatched": unmatched}


def _probe_case_sensitivity(skill_dir):
    base = os.path.basename(skill_dir.rstrip("/\\"))
    if not base:
        return None
    probe = os.path.join(os.path.dirname(skill_dir), base.swapcase())
    return os.path.exists(probe)


def _probe_interpreter():
    try:
        import importlib.util
        has_pt = importlib.util.find_spec("pytest") is not None
    except Exception:  # noqa: BLE001
        has_pt = False
    return {"side": SIDE, "exe": sys.executable, "version": sys.version.split()[0],
            "os_sep": os.sep, "pytest": has_pt}


def _visit_log_path(skill_dir) -> str:
    return os.path.join(skill_dir, ".gatekeeper.state.watch-log.jsonl")


def _append_visit(skill_dir, rec) -> str:
    r"""访客记录：append-only、单行 JSON、O_APPEND 单次写（并发下不交错）。

    落点选择：与 state 同目录的 sidecar（`.gatekeeper.state.watch-log.jsonl`）——
    ① 与 edit-log/budget-log/step-log 同族，`state --map` 的 sidecars 自动可见；
    ② 每 worktree 一份 ⟹ 两侧/各 worktree 的访客天然隔离；
    ③ 命中 `^\.gatekeeper\.state` 导出排除规则 ⟹ 不进开源包、不夹带 host 信息；
    ④ 不进 state 本体（state 有 2.6MB 墙 + 裁剪线，访客日志是高频 append）。
    """
    path = _visit_log_path(skill_dir)
    try:
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
        return path
    except OSError as e:
        return "error:%s" % type(e).__name__


def _identity_fields():
    """身份面：user/host/pid/agent id（不读 .keys、不验签——验签属审计面）。"""
    import getpass
    import platform
    return {
        "user": os.environ.get("USER") or os.environ.get("USERNAME") or
                (getpass.getuser() if hasattr(getpass, "getuser") else ""),
        "host": platform.node(),
        "pid": os.getpid(),
        "ppid": os.getppid() if hasattr(os, "getppid") else 0,
        "agent_id": os.environ.get("GK_AGENT_ID") or "unsigned",
    }


def _buddy(hours, limit=10):
    home = os.path.expanduser("~")
    roots = [c for c in (os.path.join(home, ".codebuddy"), os.path.join(home, ".codex"))
             if os.path.isdir(c)]
    if not roots:
        return {"roots": [], "recent": []}
    return {"roots": roots, "recent": _walk_files(roots, time.time() - hours * 3600, limit)}


def _live(skill_dir, commits=10, dirty_limit=200):
    """实时面：**此刻**的工作区 + 最近 commit 记录 + gitnexus 索引基线（不绑时间窗）。

    与 `recent` 分工：`recent` 回答「N 小时内 mtime 动过哪些文件」（可选过滤）；
    `live` 回答「现在什么状态 / 刚提交了什么 / 索引还跟不跟得上 HEAD」。
    """
    head = _git(["rev-parse", "HEAD"], skill_dir).strip()
    branch = _git(["rev-parse", "--abbrev-ref", "HEAD"], skill_dir).strip()
    upstream = _git(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
                    skill_dir).strip()
    ahead = behind = 0
    if upstream:
        cnt = _git(["rev-list", "--left-right", "--count", "@{u}...HEAD"], skill_dir).split()
        if len(cnt) == 2 and all(x.isdigit() for x in cnt):
            behind, ahead = int(cnt[0]), int(cnt[1])

    dirty = []
    for line in _git(["status", "--porcelain"], skill_dir).splitlines():
        if not line.strip():
            continue
        dirty.append({"status": line[:2].strip() or "?", "path": line[3:].strip()})
        if len(dirty) >= dirty_limit:
            break

    rows = []
    for line in _git(["log", "-n", str(max(int(commits), 1)),
                      "--format=%H%x1f%h%x1f%an%x1f%aI%x1f%s"], skill_dir).splitlines():
        parts = line.split("\x1f")
        if len(parts) == 5:
            rows.append({"sha": parts[0], "short": parts[1], "author": parts[2],
                         "date": parts[3], "subject": parts[4]})

    idx = os.path.join(skill_dir, ".gitnexus", "gitnexus.json")
    gx = {"state": "absent", "index": idx, "last_commit": "", "indexed_at": "", "head": head}
    try:
        d = json.load(open(idx, encoding="utf-8"))
        last = str(d.get("lastCommit") or "")
        gx.update({"last_commit": last, "indexed_at": str(d.get("indexedAt") or "")})
        if not head or not last:
            gx["state"] = "unknown"
        elif last.lower() == head.lower():
            gx["state"] = "fresh"
        else:
            gx["state"] = "stale"
            n = _git(["rev-list", "--count", "%s..HEAD" % last], skill_dir).strip()
            gx["commits_behind"] = int(n) if n.isdigit() else None
    except (OSError, ValueError):
        pass

    return {
        "realtime": True,
        "head": {"sha": head, "short": head[:8], "branch": branch, "upstream": upstream,
                 "ahead": ahead, "behind": behind},
        "dirty": dirty,
        "commits": rows,
        "gitnexus": gx,
    }


def _save_allowed(path, skill_dir) -> bool:
    """写入边界：只允许 `.zthl/watch/**`（技能仓内，导出面已排除）或 `~/.trae/watch/**`。"""
    p = _canon(os.path.abspath(path))
    roots = [_canon(os.path.join(skill_dir, ".zthl", "watch")),
             _canon(os.path.join(os.path.expanduser("~"), ".trae", "watch"))]
    return any(p == r or p.startswith(r + "/") for r in roots)


def _summary_os_refs(probes, states, issues):
    """OS-5 / OS-6 / OS-7 汇总（供 zthl-adapter §ZH4 直接采信；清洁时也给 0 计数）。"""
    return {
        "OS-5": {
            "runtime_artifacts": len(probes["runtime_artifacts"]),
            "mixed_line_endings": probes["line_endings"]["mixed"],
            "crlf_only": probes["line_endings"]["crlf_only"],
        },
        "OS-6": {
            "identity_literals": len(probes["identity_literals"]),
            "state_owner_bad": sum(1 for s in states if s.get("owner") in ("mismatch", "missing")),
            "dotgit_unresolvable": sum(1 for i in issues if i["id"] == "dotgit_unresolvable"),
        },
        "OS-7": {"remote_unmatched": len(probes["remote_whitelist"]["unmatched"])},
    }


def _divergences(mine, other):
    """两侧快照比对：只报**可比面**的差异（路径归一后比较，避免形态噪声）。"""
    out = []
    if mine.get("side") != other.get("side"):
        out.append({"id": "side_differs", "severity": "info",
                    "detail": "%s vs %s" % (mine.get("side"), other.get("side"))})
    wt_a = {w["canon"]: w for w in mine.get("worktrees") or []}
    wt_b = {w["canon"]: w for w in other.get("worktrees") or []}
    for c in sorted(set(wt_a) ^ set(wt_b)):
        out.append({"id": "worktree_set_differs", "severity": "warn", "detail": c})
    st_a = {(s.get("path"), s.get("worktree_canon")) for s in mine.get("states") or []}
    st_b = {(s.get("path"), s.get("worktree_canon")) for s in other.get("states") or []}
    for item in sorted(st_a ^ st_b, key=str):
        out.append({"id": "state_view_differs", "severity": "warn", "detail": str(item)})
    pa, pb = mine.get("probes") or {}, other.get("probes") or {}
    for k in ("line_endings", "identity_literals", "runtime_artifacts", "case_sensitivity"):
        if pa.get(k) != pb.get(k):
            out.append({"id": "probe_%s" % k, "severity": "warn",
                        "detail": "left=%s right=%s" % (
                            json.dumps(pa.get(k), ensure_ascii=False)[:160],
                            json.dumps(pb.get(k), ensure_ascii=False)[:160])})
    return out


def _default_skill_dir() -> str:
    """缺省技能目录：`GK_SKILL_DIR` > **本文件父父目录**。

    不用 `os.getcwd()` —— 裸跑（不经 CLI）时 cwd 是任意项目根，访客记录会写到那儿，
    与 hook 侧（同源解析技能目录）分叉成两个文件。与 `pre_tool_hook._watch_log_path` 同口径。
    """
    return os.environ.get("GK_SKILL_DIR") or os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))


def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--skill-dir", default=_default_skill_dir())
    # 实时为默认：`--hours` 缺省 = None（不启用 mtime 时间窗）；显式给出才退回旧口径。
    ap.add_argument("--hours", type=float, default=None)
    ap.add_argument("--commits", type=int, default=10)   # 实时面：最近 N 条 commit
    ap.add_argument("--limit", type=int, default=30)
    ap.add_argument("--save", default="")
    ap.add_argument("--compare", default="")
    ap.add_argument("--reveal", action="store_true")   # 身份字面量回显全文（默认脱敏）
    ap.add_argument("--cross-side", action="store_true")  # 观测另一侧目录（~/.codebuddy、~/.codex）
    ap.add_argument("--purpose", default="")           # 访问事由（写进访客记录）
    ap.add_argument("--json", action="store_true")
    a, _unknown = ap.parse_known_args()

    if a.save and not _save_allowed(a.save, os.path.abspath(a.skill_dir)):
        print(json.dumps({"ok": False, "error": "SAVE_PATH_NOT_ALLOWED",
                          "hint": "只允许 <skill_dir>/.zthl/watch/** 或 ~/.trae/watch/**",
                          "requested": a.save}, ensure_ascii=False))
        sys.exit(2)

    skill_dir = os.path.abspath(a.skill_dir)
    wts = _worktrees(skill_dir)
    roots = [skill_dir] + [w["path"] for w in wts if w["path"] and _canon(w["path"]) != _canon(skill_dir)]
    states = _states(roots, skill_dir)
    files = _tracked(skill_dir)
    live = _live(skill_dir, commits=a.commits)

    probes = {
        "path_forms": {f: sum(1 for s in states if s.get("form") == f)
                       for f in ("win", "wsl", "posix", "none")},
        "worktree_git_view": [{"path": w["path"], "dotgit_form": w["dotgit_form"],
                               "resolvable_here": w["dotgit_resolvable"],
                               "readable_here": w["readable_here"]} for w in wts],
        "line_endings": _probe_line_endings(skill_dir, files),
        "identity_literals": _probe_identity(skill_dir, files, reveal=a.reveal),
        "runtime_artifacts": _probe_runtime_artifacts(files),
        "remote_whitelist": _probe_remotes(skill_dir),
        "case_sensitivity": _probe_case_sensitivity(skill_dir),
        "interpreter": _probe_interpreter(),
    }
    issues = []
    if any(s.get("owner") in ("mismatch", "missing") for s in states):
        issues.append({"id": "state_owner_mismatch", "severity": "warn",
                       "detail": [s["path"] for s in states if s.get("owner") in ("mismatch", "missing")],
                       "os_ref": "OS-6"})
    if probes["line_endings"]["mixed"]:
        issues.append({"id": "mixed_line_endings", "severity": "warn",
                       "detail": probes["line_endings"]["sample"], "os_ref": "OS-5"})
    if probes["identity_literals"]:
        issues.append({"id": "identity_literals", "severity": "warn",
                       "detail": probes["identity_literals"][:5], "os_ref": "OS-6"})
    if probes["runtime_artifacts"]:
        issues.append({"id": "runtime_artifacts_tracked", "severity": "warn",
                       "detail": probes["runtime_artifacts"][:5], "os_ref": "OS-5"})
    if probes["remote_whitelist"]["unmatched"]:
        issues.append({"id": "remote_not_whitelisted", "severity": "warn",
                       "detail": probes["remote_whitelist"]["unmatched"], "os_ref": "OS-7"})
    for w in wts:
        if w["dotgit"] and not w["dotgit_resolvable"]:
            issues.append({"id": "dotgit_unresolvable", "severity": "warn",
                           "detail": {"path": w["path"], "dotgit": w["dotgit"]}, "os_ref": "OS-6"})
    if live["gitnexus"]["state"] in ("stale", "absent"):
        # 信息级（不拦）：索引落后 ⟹ 依赖图查询会给出旧结论；先 `analyze` 再谈 impact。
        issues.append({"id": "gitnexus_baseline_%s" % live["gitnexus"]["state"],
                       "severity": "info",
                       "detail": {"head": live["head"]["short"],
                                  "indexed": (live["gitnexus"]["last_commit"] or "")[:8],
                                  "commits_behind": live["gitnexus"].get("commits_behind")},
                       "os_ref": "OS-5"})

    out = {
        "ok": True, "read_only": not bool(a.save), "side": SIDE,
        "generated_at": _iso(time.time()), "hours": a.hours,
        "skill_dir": skill_dir, "skill_dir_canon": _canon(skill_dir),
        "roots": roots, "worktrees": wts,
        # `recent` = 可选时间窗（`--hours` 才启用）；`live` = 实时面（缺省）。
        "recent": (_walk_files(roots, time.time() - max(a.hours, 0.1) * 3600, a.limit)
                   if a.hours is not None else []),
        "live": live,
        "scratch": _scratch(roots), "states": states,
        "cross_os": {"forms": probes["path_forms"],
                     "mismatch": [s["path"] for s in states
                                  if s.get("owner") in ("mismatch", "missing")]},
        "probes": probes, "issues": issues,
        "os_refs": _summary_os_refs(probes, states, issues),
        "buddy": (_buddy(max(a.hours or 1, 1)) if a.cross_side else
                  {"roots": [], "recent": [],
                   "gated": "另一侧目录属跨边界观测：需 --cross-side + hook 准入（GK_WATCH_APPROVED=1）"}),
    }
    # 访客记录（每次观测都记；deny 由 hook 侧记）——不含快照明文，只留摘要
    _digest = hashlib.sha256(json.dumps(out, ensure_ascii=False, sort_keys=True).encode()).hexdigest()
    _visit = {"ts": _iso(time.time()), "event": "observe", "side": SIDE,
              "cmd": " ".join(sys.argv[1:])[:300], "purpose": a.purpose[:200],
              "scope": "cross-side" if a.cross_side else "own",
              "reveal": bool(a.reveal), "save": a.save,
              "skill_dir": skill_dir, "cwd": os.getcwd(),
              "counts": {"states": len(states), "worktrees": len(wts),
                         "recent": len(out["recent"]), "issues": len(issues),
                         "dirty": len(live["dirty"]), "commits": len(live["commits"])},
              "snapshot_sha256": _digest}
    _visit.update(_identity_fields())
    out["visit_log"] = _append_visit(skill_dir, _visit)
    if a.compare:
        try:
            other = json.load(open(a.compare, encoding="utf-8"))
            out["compare"] = {"with": a.compare, "divergences": _divergences(out, other)}
        except (OSError, ValueError) as e:
            out["compare"] = {"with": a.compare, "error": type(e).__name__}
    if a.save:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(a.save)), exist_ok=True)
            with open(a.save, "w", encoding="utf-8", newline="\n") as f:
                json.dump(out, f, ensure_ascii=False, indent=2)
            out["saved"] = a.save
        except OSError as e:
            out["saved"] = "error:%s" % type(e).__name__
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

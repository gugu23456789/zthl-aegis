#!/usr/bin/env python3
"""
gk_audit_depth.py — GitNexus dead code automation (batch8 R-T6 Phase 6, 2026-08-20)
====================================================================================
死代码深度检测自动化，覆盖交叉审查盲区 3/4/5:
  - Python 模块级: 未使用 import / 模块级未调用函数（轻量 AST，无需 vulture/pyflakes）
  - 脚本级: scripts/*.py 是否被 gatekeeper-cli.sh / 其他脚本 / 测试引用（孤儿脚本）
  - GitNexus: 可用性检测（符号级三关增强的前提，可用时提示人工/后续接 context）

0 API calls, deterministic.

Contract:
  {"depth_checks":[
     {"check":"python_unused_import","file":..., "unused":[...], "unused_lines":{name:lineno}, "match":bool},
     {"check":"python_unused_function","file":..., "unused":[...], "unused_lines":{name:lineno}, "match":bool},
     {"check":"script_consumer","script":..., "consumers":[...], "match":bool},
     {"check":"gitnexus_available","available":bool, "match":true}],
   "summary":{"total":N,"matches":M,"failures":F}}

失败项附加 git 引入溯源（复用 git log --diff-filter=A 文件级 + -S pickaxe 符号级）:
  {"intro":{"commit":..., "date":..., "msg":...}, "intro_by_symbol":{name:{commit,date,msg}}}
  git 不可用 / 无历史时该字段为空 {}（优雅降级）。

Usage:
  python3 scripts/gk_audit_depth.py [--skill-dir <dir>]
  SKILL_DIR env 亦可指定（CLI 调用时传入）。

Exit codes: 0 = OK (JSON on stdout), 1 = error JSON.
"""

import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from gk_hub_scheduler import adaptive_workers   # s5.5：自适应并发度（中枢单源，禁写死 8）

DEFAULT_SKILL = Path(__file__).resolve().parent.parent
# 不参与模块级扫描的文件（测试/tmp/conftest）
_SKIP_MODULE = ("test_", "tmp_", "conftest.py", "_test_", "__")
# 脚本级消费跳过（测试自身不当作"孤儿"）
_SKIP_SCRIPT = ("test_", "tmp_", "conftest.py")


def _ref_count(src: str, name: str, exclude_line: int = None) -> int:
    """统计 name 在 src 中作为单词出现的次数（可选排除指定行号）。"""
    count = 0
    for i, line in enumerate(src.split("\n"), start=1):
        if exclude_line and i == exclude_line:
            continue
        count += len(re.findall(r"\b" + re.escape(name) + r"\b", line))
    return count


def _read_all(scripts_dir: str) -> dict:
    """一次性读满 `scripts/*.py` → `{文件名: 文本|None}`（None = 读盘失败）。

    ⚡ 性能（finding `ECC-A0EFC250C698`）：旧实现在**每个**外层文件里重读全部 .py
    （97 × 261 ≈ 25,317 次冗余读）⟹ 改为全仓只读一次，索引也只建一次。
    读盘失败记 None（调用方逐字复现旧 `except Exception: return []` 分支）。
    """
    out = {}
    for p in sorted(Path(scripts_dir).glob("*.py")):
        try:
            out[p.name] = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            out[p.name] = None
    return out


def _build_crossref(texts: dict) -> tuple:
    """一次性建「跨模块消费」倒排索引，替代旧 `per-(函数 × 文件)` 全文正则。

    与旧判据**逐字等价**（旧 `_module_checks` 内层循环）：
      ① 某**他文件**同时含 `from <stem> import` 且含 `<name>` ⟹ 消费；
      ② 某**他文件**含 `<stem>.<name>` ⟹ 消费。
    返回 `(from_import_files, dot_pair_files, names_in_text)`：
      - `from_import_files: {stem: frozenset(文件名)}`   —— 命中 ① 的前半
      - `dot_pair_files:    {(stem, name): frozenset}`    —— 命中 ②
      - `names_in_text:     {文件名: frozenset(标识符)}`  —— 命中 ① 的后半

    成本：每文件 3 趟 O(L) 正则（总 O(N·L)）；旧实现是 O(N²·F) 趟（实测 53 万次全文扫描）。
    """
    re_from = re.compile(r"\bfrom\s+([A-Za-z_][\w.]*)\s+import\b")
    re_dot = re.compile(r"\b([A-Za-z_]\w*)\.([A-Za-z_]\w*)\b")
    re_word = re.compile(r"[A-Za-z_]\w*")
    fi, dp, nt = {}, {}, {}
    for fn, text in texts.items():
        if not text:
            nt[fn] = frozenset()
            continue
        nt[fn] = frozenset(re_word.findall(text))
        for m in re_from.finditer(text):
            # 按**完整**模块名登记（不取末段）—— 与旧正则 `\bfrom\s+<stem>\s+import\b`
            # 的「字面 stem 才命中」逐字等价（`from pkg.sub import x` 不命中 stem=sub）。
            fi.setdefault(m.group(1), set()).add(fn)
        for m in re_dot.finditer(text):
            dp.setdefault((m.group(1), m.group(2)), set()).add(fn)
    return ({k: frozenset(v) for k, v in fi.items()},
            {k: frozenset(v) for k, v in dp.items()}, nt)


def _cross(stem: str, name: str, cur_file: str, fi: dict, dp: dict, nt: dict) -> bool:
    """跨模块消费判定（O(查表)；`cur_file` 自身不计 —— 复现旧 `p.name != path.name`）。"""
    for fn in fi.get(stem, ()):
        if fn != cur_file and name in nt.get(fn, ()):
            return True
    for fn in dp.get((stem, name), ()):
        if fn != cur_file:
            return True
    return False


def _module_checks(path: Path, texts: dict, fi: dict, dp: dict, nt: dict) -> list:
    """单个 python 文件的模块级死代码检查（跨模块倒排索引由调用方一次性构建）。

    ⚡ 性能（finding `ECC-A0EFC250C698`）：旧实现对**每个**外层文件重读全部 .py 并对
    **每个**顶层函数扫全部文件文本 ⟹ 97×261 次冗余读 + 1009×261×2 ≈ 53 万次全文正则
    （实测 `check_python_module_deadcode` 单点 246s、全流程 278s，击穿每域 120s 预算）。
    现索引一次建、判定 O(1) 查表；**判定语义逐字不变**（等价性对照臂见
    `scripts/test_gk_audit_depth_index.py`）。
    """
    checks = []
    src = texts.get(path.name)
    if src is None:      # 读盘失败 ⟹ 逐字保持旧行为（旧 `except Exception: return []`）
        return []
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return [{"check": "python_parse_error", "file": path.name,
                 "match": False, "error": "syntax"}]
    except Exception:
        return []

    src_lines = src.split("\n")
    # ⚡ 性能（U3 audit_depth 提速）：旧实现每个候选名各扫全文一次（O(名字数 × 行数)）。
    # 现改为**每文件一次**交替正则全量计数（候选名先取并集），再减去需排除行上的计数。
    # 与 `_ref_count`（`Σ 逐行 \bname\b`）**逐字等价**：`\b\w+\b` 的最大词元 === name 时才命中。
    candidates = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                candidates.add(a.asname or a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.name != "*":
                    candidates.add(a.asname or a.name)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name != "main":
            candidates.add(node.name)
    word_counts = {}
    if candidates:
        _pat = re.compile(r"\b(?:" + "|".join(
            re.escape(n) for n in sorted(candidates)) + r")\b")
        for m in _pat.finditer(src):
            w = m.group(0)
            word_counts[w] = word_counts.get(w, 0) + 1

    def _used(name: str, exclude_lines=()) -> int:
        """`_ref_count(src, name, exclude_line)` 的等价实现（排除行按行号取原文计数）。"""
        n = word_counts.get(name, 0)
        for lineno in exclude_lines:
            if 0 < lineno <= len(src_lines):
                n -= len(re.findall(r"\b" + re.escape(name) + r"\b",
                                    src_lines[lineno - 1]))
        return n

    # --- 未使用 import ---
    unused_imports = []  # (name, lineno)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                name = a.asname or a.name.split(".")[0]
                # 引用计数排除 import 行本身
                if _used(name, (node.lineno,)) <= 0:
                    unused_imports.append((name, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.name == "*":
                    continue
                name = a.asname or a.name
                if _used(name, (node.lineno,)) <= 0:
                    unused_imports.append((name, node.lineno))
    if unused_imports:
        checks.append({"check": "python_unused_import", "file": path.name,
                       "unused": sorted(n for n, _ in unused_imports),
                       "unused_lines": dict(unused_imports), "match": False})
    else:
        checks.append({"check": "python_unused_import", "file": path.name,
                       "unused": [], "unused_lines": {}, "match": True})

    # --- 模块级未调用函数（文件内调用 + 跨模块消费，排除 main）---
    # 2026-08-20 修正: ① 只排除 def 行（原排除 name( 开头的调用行 → 误报）；
    # ② 增加跨模块消费（其他脚本 import <module>.func / from <module> import func）。
    # 2026-10-01 性能（ECC-A0EFC250C698）：跨模块消费改查一次性倒排索引（`_cross`），
    # 与旧「逐文件两趟全文正则」**逐字等价**；`src.split` 亦提到循环外（原每函数重切）。
    # U3 提速：`def <name>` 前缀行先按 `def ` 预筛（原每函数扫全文），排除口径逐字不变。
    def_lines = []
    for i, line in enumerate(src_lines, start=1):
        s = line.lstrip()
        if s.startswith("def "):
            def_lines.append((i, s))
    stem = path.stem
    unused_funcs = []  # (name, lineno)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name != "main":
            if _used(node.name, [i for i, s in def_lines
                                 if s.startswith("def " + node.name)]) <= 0 \
                    and not _cross(stem, node.name, path.name, fi, dp, nt):
                unused_funcs.append((node.name, node.lineno))
    if unused_funcs:
        checks.append({"check": "python_unused_function", "file": path.name,
                       "unused": sorted(n for n, _ in unused_funcs),
                       "unused_lines": dict(unused_funcs), "match": False})
    else:
        checks.append({"check": "python_unused_function", "file": path.name,
                       "unused": [], "unused_lines": {}, "match": True})
    return checks


def check_python_module_deadcode(scripts_dir: str, cli_text: str = "",
                                 texts: dict = None) -> dict:
    """扫描 scripts/*.py 模块级死代码（未使用 import/函数）。cli_text 传入 gatekeeper-cli.sh
    文本以识别 bash heredoc 的 python import 消费（防 update_job 类误报）。

    `texts` 可由调用方预读以复用（`run_all` 里与 `check_script_consumers` 共用**一次**读盘）。
    """
    checks = []
    sd = Path(scripts_dir)
    if not sd.exists():
        return {"depth_checks": checks}
    if texts is None:
        texts = _read_all(scripts_dir)
    # 索引面 = 全部 .py ∪ {gatekeeper-cli.sh: cli_text}。旧实现把 cli_text 单列判据，
    # 但其两条判据与「他文件」逐字同形（见 `_build_crossref`）⟹ 可并入同一倒排。
    idx_texts = dict(texts)
    if cli_text:
        idx_texts["gatekeeper-cli.sh"] = cli_text
    fi, dp, nt = _build_crossref(idx_texts)
    for f in sorted(sd.glob("*.py")):
        if f.name.startswith(_SKIP_MODULE):
            continue
        checks.extend(_module_checks(f, texts, fi, dp, nt))
    return {"depth_checks": checks}


def check_script_consumers(scripts_dir: str, cli_path: str, texts: dict = None) -> dict:
    """核对 scripts/*.py 是否有消费方（CLI / 其他脚本 / 测试）→ 孤儿检测。"""
    checks = []
    sd = Path(scripts_dir)
    if not sd.exists():
        return {"depth_checks": checks}
    cli_text = ""
    try:
        cli_text = Path(cli_path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if texts is None:
        texts = _read_all(scripts_dir)
    all_texts = {k: (v or "") for k, v in texts.items()}

    for f in sorted(sd.glob("*.py")):
        if f.name.startswith(_SKIP_SCRIPT):
            continue
        consumers = []
        # 匹配文件名（scripts/foo.py）或模块名（import foo）
        if f.name in cli_text or f.stem in cli_text:
            consumers.append("gatekeeper-cli.sh")
        for other, text in all_texts.items():
            if other != f.name and (f.name in text or f.stem in text):
                consumers.append(other)
        if consumers:
            checks.append({"check": "script_consumer", "script": f.name,
                           "consumers": sorted(set(consumers)), "match": True})
        else:
            checks.append({"check": "script_consumer", "script": f.name,
                           "consumers": [], "match": False})
    return {"depth_checks": checks}


def check_gitnexus_available() -> dict:
    """GitNexus 可用性检测（符号级死代码三关的前提）。"""
    found = shutil.which("gitnexus") is not None
    return {"depth_checks": [{"check": "gitnexus_available", "available": found,
                              "match": True}]}


_GIT_LOG_FMT = "%h|%ad|%s"
_RE_GIT_HEADER = re.compile(r"^[0-9a-f]{7,}\|\d{4}-\d{2}-\d{2}\|")


# 全史账龄表：CIFS 上 2596 commits 实测 ≈30s（`user+sys` 仅 2.7s ⟹ 成本全在对象读，不是 CPU）。
# 旧 `timeout=30` 恰好卡在边界：一旦超时返回 `{}`，调用方就回退**逐文件** `git log`
# （实测 5.5s/次 × ~20 目标 = 110s+，`test_gk_audit_depth_index` 的 60s 预算因此必红）。
# 现：① 超时放宽到 120s（`GK_GIT_ARTIFACT_TIMEOUT` 可覆盖）；
#     ② **跨进程缓存**（键 = repo realpath + HEAD sha，与 A1 的 gitnexus 缓存同策）⟹ 同 HEAD 下
#        第二次起 0 次 git；③ 批量**真失败**（超时/rc≠0）时不再逐文件回退（那是 100s 级陷阱），
#        只有「批量成功但解析为空」才回退（兼容桩/旧 git，见既有臂）。
_ARTIFACT_CACHE_VERSION = "v1"
_DEF_BULK_TIMEOUT_S = 120
_RE_SHA40 = re.compile(r"^[0-9a-f]{40}$")


def _artifact_cache_dir() -> Path:
    return Path(os.environ.get("GK_ARTIFACT_CACHE_DIR", "")
                or os.path.join(os.path.expanduser("~"), ".gatekeeper", "git-artifact-cache"))


_HEAD_MEMO: dict = {}


def _git_head(repo_dir: str) -> str:
    """目标仓 HEAD sha（40 hex）；解析失败返回空串 ⟹ 关闭缓存（不猜）。

    进程内 memo（2026-10-28）：`enrich_with_git_intro` 会为**每个** pickaxe 目标调一次本函数
    （41 目标 × 4.5s 的 `git rev-parse` 在 CIFS 上是 24s 级白开销）。同一进程内 repo HEAD
    不变 ⟹ 按 realpath 记忆；新进程自然重新解析（不引入陈旧面）。
    """
    key = os.path.realpath(repo_dir)
    if key in _HEAD_MEMO:
        return _HEAD_MEMO[key]
    try:
        r = subprocess.run(["git", "-C", repo_dir, "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=10)
    except Exception:
        _HEAD_MEMO[key] = ""
        return ""
    out = (r.stdout or "").strip()
    val = out if r.returncode == 0 and _RE_SHA40.match(out) else ""
    _HEAD_MEMO[key] = val
    return val


def _artifact_cache_file(repo_dir: str, head: str) -> Path:
    key = hashlib.sha256(("%s|%s|%s" % (_ARTIFACT_CACHE_VERSION,
                                        os.path.realpath(repo_dir), head)).encode("utf-8")).hexdigest()
    return _artifact_cache_dir() / (key[:40] + ".json")


def _artifact_cache_read(p: Path) -> dict | None:
    try:
        with p.open(encoding="utf-8") as f:
            d = json.load(f)
    except Exception:
        return None
    m = d.get("map") if isinstance(d, dict) else None
    return m if isinstance(m, dict) and m else None


def _artifact_cache_write(p: Path, data: dict) -> None:
    """原子写（tmp + os.replace）；失败静默（缓存是加速面，不是正确性面）。"""
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump({"map": data}, f, ensure_ascii=False)
        os.replace(tmp, p)
    except Exception:
        pass


def _git_artifact_map(repo_dir: str, timeout: int = None) -> tuple:
    """**一次** `git log` 建「文件 → 最早引入 commit」全表（替代 per-file spawn）。

    判据与旧 `_git_log_line(repo_dir, rel)` 等价：`--diff-filter=A` 只看新增该文件的 commit；
    `git log` 新→旧输出，覆盖写 ⟹ 最终保留**最早**那个（旧实现取 `lines[-1]`，同义）。
    键 = git 原样输出（相对仓库根的 `scripts/xxx.py`，正斜杠）。

    返回 `(map, ok)`：`ok=True` 表示**批量命令本身成功**（即使解析为空 ⟹ 调用方可安全回退逐文件）；
    `ok=False` 表示超时/rc≠0/无 git ⟹ 调用方**不得**回退（逐文件在 CIFS 上是 100s 级陷阱）。
    """
    if timeout is None:
        try:
            timeout = int(os.environ.get("GK_GIT_ARTIFACT_TIMEOUT", "") or _DEF_BULK_TIMEOUT_S)
        except ValueError:
            timeout = _DEF_BULK_TIMEOUT_S
    head = _git_head(repo_dir)
    cpath = _artifact_cache_file(repo_dir, head) if head else None
    if cpath is not None:
        hit = _artifact_cache_read(cpath)
        if hit is not None:
            return hit, True
    cmd = ["git", "-C", repo_dir, "log", "--format=" + _GIT_LOG_FMT,
           "--date=short", "--diff-filter=A", "--name-only"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
    except Exception:
        return {}, False
    if r.returncode != 0:
        return {}, False
    out, cur = {}, None
    for line in (r.stdout or "").splitlines():
        s = line.strip()
        if not s:
            continue
        if _RE_GIT_HEADER.match(s):
            h, d, msg = s.split("|", 2)
            cur = {"commit": h, "date": d, "msg": msg.strip()[:120]}
        elif cur is not None:
            out[s.replace("\\", "/")] = cur      # 覆盖 ⟹ 最早
    if out and cpath is not None:
        _artifact_cache_write(cpath, out)
    return out, True


def _pickaxe_cache_file(repo_dir: str, head: str, rel_path: str, pickaxe: str) -> Path:
    key = hashlib.sha256(("%s|pickaxe|%s|%s|%s" % (
        _ARTIFACT_CACHE_VERSION, os.path.realpath(repo_dir), head,
        rel_path + "\x00" + pickaxe)).encode("utf-8")).hexdigest()
    return _artifact_cache_dir() / ("p-" + key[:36] + ".json")


def _git_log_line(repo_dir: str, rel_path: str, pickaxe: str = None) -> dict:
    """git 溯源单行：文件引入（--diff-filter=A）或符号 pickaxe（-S）。

    复用既有 git log 机制；无 git / 无历史时返回 {}（优雅降级）。
    多条命中取最后一行 = 最早引入 commit。

    ⚡ 性能（2026-10-28，全量回归 747s 实测）：本仓 41 个 pickaxe 目标 × 4.8s（CIFS 上
    git 全史遍历 + 进程启动）≈ 200s，是 `run_all` 的唯一主项（`adaptive_workers` = 4 ⟹ 50s）。
    现按 (repo, HEAD sha, rel, pickaxe) 做**跨进程缓存**（与 A1/gitnexus 同策）：同 HEAD 下
    第二次起 0 次 spawn。空结果（rc=0 但无命中）同样缓存 —— 那是合法结论，不是失败。
    """
    head = _git_head(repo_dir)
    cpath = _pickaxe_cache_file(repo_dir, head, rel_path, pickaxe or "") if head else None
    if cpath is not None:
        try:
            with cpath.open(encoding="utf-8") as f:
                d = json.load(f)
            if isinstance(d, dict) and d.get("v") == _ARTIFACT_CACHE_VERSION:
                return d.get("intro") if isinstance(d.get("intro"), dict) else {}
        except Exception:
            pass
    base = ["git", "-C", repo_dir, "log", "--format=%h|%ad|%s", "--date=short"]
    cmd = base + ["--diff-filter=A", "--", rel_path] if not pickaxe \
        else base + ["-S", pickaxe, "--", rel_path]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=10)
        if r.returncode != 0:
            return {}
        lines = [l for l in r.stdout.splitlines() if l.strip()]
        if not lines:
            info = {}
        else:
            h, d, msg = lines[-1].split("|", 2)
            info = {"commit": h, "date": d, "msg": msg.strip()[:120]}
    except Exception:
        return {}
    if cpath is not None:
        try:
            cpath.parent.mkdir(parents=True, exist_ok=True)
            tmp = cpath.with_suffix(".tmp")
            with tmp.open("w", encoding="utf-8") as f:
                json.dump({"v": _ARTIFACT_CACHE_VERSION, "intro": info}, f,
                          ensure_ascii=False)
            os.replace(tmp, cpath)
        except Exception:
            pass
    return info


def _line_text(src: str, lineno: int) -> str:
    lines = src.split("\n")
    return lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""


def _fill_file_intro(repo_dir: str, targets: list, rels: dict, bulk_ok: bool = True) -> None:
    """文件级引入溯源：批量表（键为 `scripts/<name>`，正斜杠）优先，未命中回退逐文件。

    `bulk_ok=False` ⟹ 批量命令**本身失败**（超时/rc≠0/无 git）：**禁止**逐文件回退
    （CIFS 实测 5.5s/次；旧行为在批量超时后连开 ~20 个进程 ⟹ 100s+ 卡死）。
    批量成功但键缺失（桩环境/旧 git）仍按旧语义回退 —— 见 `test_文件级批量解析空则回退逐文件`。
    """
    file_map = _git_artifact_map(repo_dir) if bulk_ok else ({}, False)
    file_map, ok = file_map
    for c in targets:
        fname = c.get("file") or c.get("script")
        rel = rels[id(c)]
        info = file_map.get("scripts/" + fname) or file_map.get(rel.replace(os.sep, "/"))
        if info is None and ok:
            info = _git_log_line(repo_dir, rel)      # 回退：批量不可用/桩环境
        if info:
            c["intro"] = info


def enrich_with_git_intro(repo_dir: str, checks: list) -> list:
    """对失败项附加 git 引入溯源（原因=commit msg，时间=commit date）。
    文件级 `--diff-filter=A` 兜底；unused 符号级 `-S` pickaxe 覆盖（更精确）。

    ⚡ 性能（finding `ECC-A0EFC250C698`）：旧实现每失败项各 spawn 一次 `git log`
    （实测 23 文件 + 15 符号 = 38 次 ≈ 30.6s，成本几乎全在**进程启动**）。现：
      ① 文件级 = **一次** `git log --diff-filter=A --name-only` 建全表（解析空 ⟹ 回退逐文件，
         保持旧行为且兼容桩环境）；
      ② 符号级 pickaxe = 线程池并行（subprocess 属 I/O 等待，非 CPU）；
      ③ U3 提速：①与②**同池并发**（两者互不依赖，串行白等一次全史遍历），
         判定口径与产出结构**逐字不变**。
    """
    targets = [c for c in checks
               if not c.get("match") and (c.get("file") or c.get("script"))]
    if not targets:
        return checks

    # 目标相对路径 + 符号级 jobs（纯本地读盘，无 git 调用）
    rels = {}
    jobs = []
    for c in targets:
        fname = c.get("file") or c.get("script")
        rel = os.path.join("scripts", fname)
        rels[id(c)] = rel
        if not c.get("unused_lines"):
            continue
        src = ""
        try:
            src = Path(repo_dir, "scripts", fname).read_text(
                encoding="utf-8", errors="replace")
        except Exception:
            pass
        for name, lineno in c["unused_lines"].items():
            line = _line_text(src, lineno) if src else ""
            if line:
                jobs.append((c, name, rel, line))

    # ③ 文件级与符号级并发：池大小仍走中枢单源 `adaptive_workers`（+1 = 文件级那一支）。
    #    `reserve=0`：本池**全是**外部 `git` 进程的 I/O 等待（`user+sys` 实测仅 0.1-0.3s/次），
    #    不留核 —— 41 个 pickaxe 目标在 4 并发下 ≈50s、5 并发下 ≈41s（冷启动口径）。
    with ThreadPoolExecutor(max_workers=adaptive_workers(len(jobs) + 1, reserve=0)) as ex:
        fut_files = ex.submit(_fill_file_intro, repo_dir, targets, rels)
        futs = {ex.submit(_git_log_line, repo_dir, rel, line): (c, name)
                for (c, name, rel, line) in jobs}
        for fut in as_completed(futs):
            c, name = futs[fut]
            try:
                info = fut.result()
            except Exception:
                info = {}
            if info:
                c.setdefault("intro_by_symbol", {})[name] = info
        try:
            fut_files.result()
        except Exception:
            pass
    return checks


def run_all(scripts_dir: str, cli_path: str) -> dict:
    """聚合全部 depth 检查。"""
    cli_text = ""
    try:
        cli_text = Path(cli_path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        pass
    checks = []
    # ⚡ 读盘单点（finding ECC-A0EFC250C698）：模块级与脚本级两检查共用**同一次** scripts 读。
    texts = _read_all(scripts_dir)
    for r in (check_python_module_deadcode(scripts_dir, cli_text, texts=texts),
              check_script_consumers(scripts_dir, cli_path, texts=texts),
              check_gitnexus_available()):
        checks.extend(r["depth_checks"])
    repo_dir = str(Path(scripts_dir).parent)
    checks = enrich_with_git_intro(repo_dir, checks)
    total = len(checks)
    matches = sum(1 for c in checks if c.get("match"))
    return {"depth_checks": checks,
            "summary": {"total": total, "matches": matches, "failures": total - matches}}


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    skill_dir = os.environ.get("SKILL_DIR", str(DEFAULT_SKILL))
    if "--skill-dir" in args:
        i = args.index("--skill-dir")
        if i + 1 < len(args):
            skill_dir = args[i + 1]
    try:
        scripts_dir = str(Path(skill_dir) / "scripts")
        cli_path = str(Path(skill_dir) / "gatekeeper-cli.sh")
        print(json.dumps(run_all(scripts_dir, cli_path)))
    except Exception as e:
        print(json.dumps({"depth_checks": [],
                          "summary": {"total": 0, "matches": 0, "failures": 1, "error": str(e)}}))
        sys.exit(1)


if __name__ == "__main__":
    main()

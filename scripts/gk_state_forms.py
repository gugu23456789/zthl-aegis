#!/usr/bin/env python3
"""state **命名形态**分类器 + 写门（② 单一权威，单源）。

形态（单源判据；`gk_finding._state_file_domain` / `_is_live_ledger_name` / `gk_state_route._collect_state_files`
的形态判断改调本模块，禁第二份）：
  · base            `.gatekeeper.state`
  · domain          `.gatekeeper.state.<token>`（token 合 `^[A-Za-z0-9][A-Za-z0-9._-]*$`）
  · legacy_plan     `.gatekeeper.state.<plan-basename>`（**只读**；判据 = token 含 4 位年份前缀 `YYYY-MM-DD-`）
  · worktree_local  非技能根下的 `.gatekeeper.state`（**只读**）
  · artifact        旁挂（`.jsonl`/`.lock`/`.tmp`/`.bak`/`.corrupt-*`/`.bak-*`/`.wal`）
"""
import json
import os
import re
from pathlib import Path

BASE_NAME = ".gatekeeper.state"
WRITABLE_FORMS = ("base", "domain")
READONLY_FORMS = ("legacy_plan", "worktree_local")   # 设计 §7：仅这两形态只读（artifact 非 state，放行）
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_ARTIFACT_SUFFIXES = (".tmp", ".bak", ".json", ".jsonl", ".lock", ".orig", ".swp",
                      ".seal", ".wal")
_ARTIFACT_MARKERS = ("bak-", "corrupt-", ".subagent-history", "pre-budget")
_LEGACY_SEG_RE = re.compile(r"^\d{4}-\d{2}-\d{2}-")      # 挑战8：按**段**判（非仅头部）


def _repo_prefixes() -> set:
    """域化形态 `<repo>.<plan>` 的 **repo 前缀集合**（P0-A2，2026-10-04 / ECC-8486E07DBE34）。

    单源 = `gk_route_center._VALID_REPOS()`（+ CLI 别名）∪ **scopes 注册的 `read_repo` 别名**
    （`ECC-32124F358C56`：原**只认硬编码表** ⟹ 非表内仓的 `<repo>.<dated-plan>` 域 token 误判
    `legacy_plan` 只读，`build-state` fail-loud）；**惰性 import**（避免模块加载环）。
    import 失败 ⟹ 仅保留技能别名（保守；含日期段者仍 legacy，**不会误放行**）。
    """
    try:
        from gk_route_center import _VALID_REPOS
        prefixes = set(_VALID_REPOS()) | {"spz-gatekeeper-r-sequence", "spz_gatekeeper"}
    except Exception:
        prefixes = {"spz-gatekeeper-r-sequence", "spz_gatekeeper"}
    return prefixes | _scopes_repo_aliases()


def _scopes_repo_aliases() -> set:
    """scopes 注册的 repo 别名（`governed_projects[].read_repo`）—— 单源 = `.gatekeeper.scopes.json`。

    与 `gk_route_center._scopes_read_repo_root` **同源**（同一文件 / 字段）；使域 token
    `<repo>.<dated-plan>` 的 repo 段不限于硬编码 `_VALID_REPOS()`。文件缺失 / 损坏 ⟹ **空集**
    （保守：退回仅硬编码表）。搜索面：`SKILL_DIR` env 优先（worktree 内 `__file__` 指向 worktree
    ⟹ 无 scopes 旁挂），回退 `__file__` 派生技能根。
    """
    cands = []
    _sd = os.environ.get("SKILL_DIR")
    if _sd:
        cands.append(_sd)
    cands.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for d in cands:
        try:
            data = json.loads(open(os.path.join(d, ".gatekeeper.scopes.json"),
                                   encoding="utf-8").read())
        except Exception:
            continue
        aliases = {str(e.get("read_repo")).strip()
                   for e in (data.get("governed_projects") or [])
                   if isinstance(e, dict) and str(e.get("read_repo") or "").strip()}
        if aliases:
            return aliases
    return set()


def is_artifact_name(name: str) -> bool:
    """**名字形态**是否旁挂件（artifact = 非 state）—— `state_form` 的 artifact 判据**单点**。

    与 `state_form` 的「非 base / 非 domain」两支逐字同源（前缀不符 / artifact 后缀 /
    token 非法 / artifact 标记）。**纯字符串判断、不读任何文件**（不触 `_repo_prefixes()` 的
    scopes 读取）⟹ 供高频**枚举面**直调：`gk_state_route._collect_state_files` 在目录过滤时
    只需「是不是 artifact」，不该为 107 个名字各读一次 scopes（实测 19 次读 = 0.15s/次启动）。
    """
    if name == BASE_NAME:
        return False
    if not name.startswith(BASE_NAME + "."):
        return True
    if name.endswith(_ARTIFACT_SUFFIXES):
        return True
    tok = name[len(BASE_NAME) + 1:]
    return not tok or not _TOKEN_RE.match(tok) or any(m in tok for m in _ARTIFACT_MARKERS)


def state_form(path: str, skill_root: str = "") -> str:
    name = Path(path).name
    if name == BASE_NAME:
        # 挑战7：base 须**父目录语义** —— 技能根外（worktree 自带）= 只读
        if skill_root and os.path.abspath(os.path.dirname(os.path.abspath(path))) \
                != os.path.abspath(skill_root):
            return "worktree_local"
        return "base"
    if is_artifact_name(name):          # 判据单点（禁第二份）
        return "artifact"
    tok = name[len(BASE_NAME) + 1:]
    # 挑战8（P0-A2 精化，2026-10-04 / ECC-8486E07DBE34）：日期段存在**且首段不是 repo 前缀**
    #   ⟹ legacy（= 裸 plan-basename `2026-…-plan`，或 `r7.<date>` 类复合遗留）；
    #   `<repo>.<dated-plan>`（首段 = repo，如 `skill.2026-…`）⟹ **domain（可写域）**。
    segs = tok.split(".")
    if any(_LEGACY_SEG_RE.match(seg) for seg in segs) and segs[0] not in _repo_prefixes():
        return "legacy_plan"
    return "domain"


_WT_STATE_MAX_DEPTH = 3   # 标准布局实测最深 3：worktree 根 = 2，agent/<task>/<run> = 3


def worktree_state_roots(skill_dir: str) -> list:
    """worktree 盘点根（c8 扩面，**加性**）：标准布局 `<parent>/worktrees/<skill_name>/…` 下
    **含 `.gatekeeper.state*`** 的目录。布局不存在 ⟹ `[]`（零回归）。

    2026-10-31（perf）：原无界 `os.walk` 在 /mnt/c（9p）上单次 16–18s（941 目录 / 41k 文件），
    使 `gk_audit_state --all` 逼近 30s 子进程超时。标准布局中 state 只出现在 depth 2/3，故改为
    **有界 BFS + `os.scandir`**（只列目录项，不进入代码子树）：本机实测 1.86s，结果与无界 walk
    **逐项相同**（6 个根）。`GK_WT_STATE_MAX_DEPTH` 可显式放宽（缺失/非法回退 3）。
    """
    base = os.path.join(os.path.dirname(os.path.dirname(skill_dir)),
                        "worktrees", os.path.basename(skill_dir))
    if not os.path.isdir(base):
        return []
    try:
        max_depth = int(os.environ.get("GK_WT_STATE_MAX_DEPTH", str(_WT_STATE_MAX_DEPTH)))
    except (TypeError, ValueError):
        max_depth = _WT_STATE_MAX_DEPTH
    out, stack = [], [(base, 0)]
    while stack:
        dirpath, depth = stack.pop()
        try:
            ents = list(os.scandir(dirpath))
        except OSError:
            continue
        if any(e.name.startswith(BASE_NAME) and e.is_file(follow_symlinks=False) for e in ents):
            out.append(dirpath)
        if depth >= max_depth:
            continue
        for e in ents:
            try:
                if e.is_dir(follow_symlinks=False):
                    stack.append((e.path, depth + 1))
            except OSError:
                continue
    return sorted(out)


def iter_live_states(skill_dir: str, extra_roots=None) -> list:
    """**活体 state 枚举**（只读；单源，挑战6）—— 各根下 `state_form() != "artifact"` 且实存者。

    - 枚举面 = `skill_dir` **+ `extra_roots`（c8：worktree 内域 state 可见）**，各根 `os.listdir`
      中 `.gatekeeper.state*` 前缀项；
    - **加性**：`extra_roots` 缺省 `None` ⟹ 逐字等于原**单根**行为（零回归）；原单根结果为新
      结果**子集**（`worktree_state_roots(skill_dir)` 给出标准布局的 worktree 根）；
    - 边界：排除 artifact（备份/临时/旁挂/锁/journal/archive）；不跟随软链到根外；
    - **无生产者即失败**：调用方（audit 项）需据此 fail-loud，禁 `except→空表` 兜底。
    """
    roots = [skill_dir] + [r for r in (extra_roots or []) if r]
    out, seen = [], set()
    for root in roots:
        try:
            names = os.listdir(root)
        except OSError:
            continue
        for n in names:
            if not n.startswith(BASE_NAME):
                continue
            p = os.path.join(root, n)
            if p in seen:
                continue
            if os.path.isfile(p) and state_form(p, skill_root=root) != "artifact":
                seen.add(p)
                out.append(p)
    return sorted(out)


def assert_writable_form(path: str, plan_declared=None) -> None:
    f = state_form(path)
    if f in READONLY_FORMS:
        raise ValueError(
            "STATE_FORM_NOT_WRITABLE: " + path + " 形态=" + f
            + "（只读形态 = " + "/".join(READONLY_FORMS)
            + "）⟹ legacy/worktree 形态只读；见 state-inventory")
    # D3 opt-in（挑战10）：写 `domain` 形态时须该 state 对应计划**已声明** META.state_domain。
    #   · `plan_declared=None` ⟹ 无计划上下文（调用方拿不到计划）⟹ 只判形态门（零回归；
    #     兼容既有 `--domain` 写）；
    #   · `plan_declared=""`   ⟹ 已判：未声明 ⟹ 拒（未声明只可写 base）。
    if f == "domain" and plan_declared is not None and not plan_declared:
        raise ValueError(
            "STATE_FORM_NOT_OPTED_IN: " + path
            + " 形态=domain 但计划未声明 META.state_domain（D3 opt-in：未声明 ⟹ 只可写 base）")


def domain_state_path(state_file: str, domain: str) -> str:
    """域化 state 落点（与 `gk_finding.resolve_domain_state` **同构**：`<state 同级>/<BASE>.<token>`）。

    token 须匹配 `_TOKEN_RE`（禁路径逃逸）；空/非法 ⟹ raise（fail-loud，不静默）。
    """
    tok = (domain or "").strip()
    if not tok or not _TOKEN_RE.match(tok):
        raise ValueError("build-domain 非法 domain token: %r（须匹配 %s）" % (domain, _TOKEN_RE.pattern))
    return str(Path(state_file).with_name(BASE_NAME + "." + tok))


def build_domain_state_exclusive(state_file: str, domain: str, seed: dict) -> dict:
    """**单建者**：原子首建域 state（§18.2 c2；2026-10-04）。

    纪律（§11 判据改法：**不绑实现**，只要求「恰 1 个建者 + 内容非空 + 无互锁」）：
      · 实现 = **`os.link(tmp, target)`** —— POSIX/NTFS 原子「**不存在才创建**」；命中即胜，
        竞败抛 `FileExistsError` ⟹ 返回 `built=False`（**不覆盖**）。内容先写 tmp 再 link ⟹
        **无空窗**（读者永不见半写/空文件），且不依赖 `fcntl`（Windows 下 `state_lock` 退化为无锁）。
      · 只读形态（`legacy_plan`/`worktree_local`）⟹ `assert_writable_form` fail-loud 拒写。
      · 写 tmp 复用 `gk_json_utils.write_json_file`（单源序列化：`ensure_ascii=False`+`indent=STATE_INDENT`）。
    返回 `{"ok", "built", "path", "reason"}`；`built=True` 者仅 1（并发下）。
    """
    import uuid as _uuid
    from gk_json_utils import write_json_file, STATE_INDENT
    target = domain_state_path(state_file, domain)
    assert_writable_form(target)                      # 只读形态 fail-loud
    if os.path.isfile(target):
        return {"ok": True, "built": False, "path": target, "reason": "exists"}
    tmp = target + "." + _uuid.uuid4().hex + ".tmp"   # 尾 `.tmp` ⟹ 归 artifact（不污染 state 枚举）
    if not write_json_file(tmp, seed, indent=STATE_INDENT):
        raise OSError("build-domain tmp 写入失败: " + tmp)
    try:
        os.link(tmp, target)                          # 原子「不存在才创建」
        return {"ok": True, "built": True, "path": target, "reason": "created"}
    except FileExistsError:
        return {"ok": True, "built": False, "path": target, "reason": "raced"}
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

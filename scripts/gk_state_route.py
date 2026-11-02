#!/usr/bin/env python3
"""
gk_state_route.py — State routing safety net (batch8 R-T6, 2026-08-20)
========================================================================
弹性安全网：检测当前解析到的 state 是否属于当前技能仓库；冲突时自动纠正
到匹配的隔离 state（恰好 1 个候选时），否则仅 WARN 不纠正（防误纠）。

背景: 技能目录默认 .gatekeeper.state 曾被门卫 R7.1 的隔离 state 占用
（worktree=/mnt/c/.../worktrees/spz_gatekeeper_project/...），导致
audit --all / advance 等命令读到错误 state（batch8 L454 摸底待办 +
2026-08-20 实测暴露：audit 结果被持久化进门卫 R7.1 state）。

判定依据: state 内嵌 worktree 字段（discover 时写入）。
  期望归属 = SKILL_DIR（技能仓库）或开发 worktree 树（IDE 受控 worktree 根）：
    - state.worktree 与 SKILL_DIR 精确匹配，或含技能仓库特征路径
    - 或位于开发 worktree 根下（.trae/worktrees/、superpowers/worktrees/）
      —— 隔离 state 随 worktree 隔离（窄任务/节点执行级产物归属执行 worktree，
         2026-09-01 扩展：worktree 隔离 state 指向主仓库 feature worktree 为合法归属）
    - 否则视为归属冲突（可能被门卫/其他项目 state 污染）

优先级（对齐 H4/H5 既有机制）:
  1. plan 指针（.gatekeeper.plan，discover --plan 写入）→ 尊重指针，不纠正
  1b. 域解析（domain= 形参非空 且 GK_STATE_DOMAIN_ROUTE≠0）→ 当前 state 同级
      `.gatekeeper.state.<token>`（委托 gk_finding.resolve_domain_state；缺失/非法/域不符 → error）
  2. 无指针 → 校验默认/当前 state 归属 → 冲突则扫描隔离 state 纠正
  2b. worktree 匹配（state.worktree ↔ 隔离 state 唯一候选 + 相位一致）

输出 JSON:
  {"expected": str|None, "current": str, "conflict": bool, "corrected": bool,
   "candidates": [str], "warning": str|None,
   "source": "plan_pointer|state_domain|worktree_match|current|safety_net",
   "domain": str (仅 source=state_domain), "error": str (仅 fail-closed 出口),
   其中 error ∈ {STATE_DOMAIN_MISSING, STATE_DOMAIN_TOKEN_INVALID,
                  STATE_DOMAIN_MISMATCH, STATE_DOMAIN_DEPENDENCY_UNAVAILABLE}
   （CLI 侧另有第五码 STATE_DOMAIN_UNRESOLVED：解析未报错但未产出 expected 时的兜底，
     见 gatekeeper-cli.sh 的 discover 域块；本模块自身不产该码）
   （CLI 侧另有第六码 STATE_DOMAIN_EXPLICIT_CONFLICT（REV-5）：显式 env STATE_FILE 与计划
     声明的域**不一致**时的 fail-closed —— 原为"仅 WARN 后继续"= 静默降级；本模块不产该码）

Usage:
  python3 scripts/gk_state_route.py [--skill-dir <dir>] [--state-file <f>]
                                    [--plan-pointer <f>] [--domain <repo>.<plan>]
                                    [--extra-root <dir>]...
  SKILL_DIR / STATE_FILE / PLAN_POINTER env 亦可指定（CLI 调用时传入）。

Exit codes: 0 = OK (JSON on stdout), 1 = error JSON,
             2 = 未知选项（`-`/`--` 前缀，fail-closed，不静默忽略；裸位置参数按既有契约容忍跳过）。
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# state 命名形态的**单一权威**（artifact/旁挂件剔除口径，禁第二份；见 `_collect_state_files`）
from gk_state_forms import BASE_NAME, is_artifact_name

DEFAULT_SKILL = Path(__file__).resolve().parent.parent
SKILL_MARKER = "/skills/spz-gatekeeper-r-sequence"

# 开发 worktree 根（2026-09-01 扩展：IDE 受控 worktree 树，worktree 隔离 state 合法归属）
# 规范形式（/ 分隔、无尾斜杠；_norm() 后 startswith 匹配）
DEV_WORKTREE_ROOTS = (
    "<home>/.trae/worktrees/",          # WSL 视角（当前 R7.1 worktree 实际位置）
    "c:/users/hp/.trae/worktrees/",              # Windows 视角
    "/root/.config/superpowers/worktrees/",      # WSL 沙箱 worktree 根（SKILL.md 常量）
)

# Phase 7b (2026-08-23): plan 指针 TTL（对齐 CLI 启动级 TTL 阈值 24h）
POINTER_TTL_SECONDS = 24 * 3600


def _pointer_fresh(pdata: dict) -> bool:
    """Phase 7b: plan 指针 updated 时间戳未过期才视为有效。"""
    u = pdata.get("updated", "")
    if not u:
        return False
    try:
        ts = datetime.fromisoformat(u.replace("Z", "+00:00"))
    except ValueError:
        return False
    age = (datetime.now(timezone.utc) - ts).total_seconds()
    return age <= POINTER_TTL_SECONDS


def _norm(p) -> str:
    return (str(p or "").replace("\\", "/")).rstrip("/")


def _path_forms(p):
    """跨运行时路径候选（`/mnt/c/x` ↔ `C:/x` ↔ `C:\\x`）—— 同一 state 的两种合法写法。

    2026-10-18（跨平台 ①B 修复）：plan 指针的 `state_file` 由**写入侧**决定形态：
      · WSL 侧 CLI 发现的 state ⟹ `str(Path(...))` = `<home>`（POSIX）；
      · Windows 侧 CLI / `python3` 发现的 state ⟹ `str(Path(...))` = `<home>`。
    读侧形态必须与写侧**归一**，否则 `Path(...).exists()` 恒 False。
    本函数返回按「宿主原生形态优先」排序的候选列表，调用方**逐个试 exists**。

    ⚠ 本函数只做**字符串**形态换算，不做任何 FS 访问（保持纯函数可单测）。
    """
    s = str(p or "").replace("\\", "/").rstrip("/")
    if not s:
        return []
    out = [s]
    m = re.match(r"^/mnt/([A-Za-z])/(.*)$", s)
    if m:
        # WSL 形态 → Windows 盘符形态
        out.append(f"{m.group(1).upper()}:{'/' + m.group(2)}")
    elif re.match(r"^[A-Za-z]:/", s):
        # Windows 形态 → WSL 形态
        out.append("/mnt/" + s[0].lower() + s[2:])
    # 去重（保持首个 = 原样）
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def _exists_either(p) -> bool:
    """跨运行时实存校验：任一形态 exists 即真。

    先例：`pre_tool_hook._wsl_to_win`（L3036）、`gk_route_center._as_norm`（L1360）
    都做过单向换算；本函数做**双向**且只关心「这个 state 真的在磁盘上吗」。
    """
    return any(Path(x).exists() for x in _path_forms(p))


def _state_mtime(state_file: str):
    """2026-09-04: state 文件修改时间；读不到返回 None（容错）。"""
    try:
        return Path(state_file).stat().st_mtime
    except OSError:
        return None


def _load_worktree(state_file: str):
    """读取 state 内嵌 worktree 字段；读取失败/缺字段返回 None。"""
    proj = _state_projection(state_file)
    return None if proj is None else proj.get("worktree")


def _state_field(state_file: str, key: str):
    """2026-09-04: 读 state 字段（容错）；失败/缺字段返回 None。"""
    if key in _STATE_PROJ_KEYS:      # 投影三字段走缓存（其余字段仍整份读，语义不变）
        proj = _state_projection(state_file)
        return None if proj is None else proj.get(key)
    try:
        with open(state_file, "r", encoding="utf-8") as f:
            return json.load(f).get(key)
    except Exception:
        return None


# ── state 只读投影缓存（2026-10-29 · 提速①）────────────────────────────────────
# 病象（cProfile 实测）：`resolve-state` 在**归属冲突**分支要 `_candidate_isolated_states`
#   逐个登记候选，每候选 `_load_worktree` 整份 json.load —— 本机 109 个隔离 state（单个
#   最大 420KB）在 CIFS 上 open+read+stat 合计 **1.15s/次**；随后 `_describe_candidates`
#   又把命中的候选**再读一遍**（本机 16 个，+0.18s）。这两刀都在 CLI **每次启动**的固定
#   开销里（实测 guard-edit 3.2s 中占 ~1.3s）。
# 做法：把「state → {worktree, r_phase, stage}」这一**只读投影**跨进程缓存。
#   键 = state 归一化绝对路径（纯字符串运算，**不用 realpath**：/mnt/c 上单个 realpath 实测
#        ~40ms，107 候选 × 2 就是 4s 级白开销，2026-10-29 实测踩过）。
#   失效判据 = `(st_mtime_ns, st_size, st_ctime_ns)` 三元逐位相等 **且** 不在 racy 窗口内。
#   ⚠ **racy 窗口（git 的 racy-timestamp 同一手法，必需而非保险）**：本机实测时间戳粒度
#      **不是 ns** —— `/tmp`(ext) 同一秒内两次改写 `st_mtime_ns/st_ctime_ns/st_size` **完全相同**
#      （1s 粒度），`/mnt/c`(v9fs) 约 ms 级。若只比 stamp，同秒内的第二次改写会被判命中
#      = **陈旧读**（正是「advance 了但门禁没变」那一类病灶）。故 `now - st_mtime_ns < 2s`
#      时判 racy：**不读缓存、也不写缓存**（写下去会被后续非 racy 读当成可信，同秒改写的
#      污染就固化下来了）。窗口外任何新写都必然把 mtime 抬到严格更晚的秒 ⟹ stamp 不等 ⟹ 失效。
#   ⚠ 解析失败（非 JSON 对象 / 不可读）**写负结果**（`proj: null`）：内容未变 ⟹ 结论必不变；
#     若一次坏读不写缓存，那 60 个非 JSON 候选每次都要整份解析到抛异常（旧实现的真实成本）。
_STATE_PROJ_VERSION = "v1"
_STATE_PROJ_KEYS = ("worktree", "r_phase", "stage")
_STATE_PROJ_RACY_NS = 2 * 10 ** 9


def _proj_cache_dir() -> Path:
    return Path(os.environ.get("GK_STATE_PROJ_CACHE_DIR", "")
                or os.path.join(os.path.expanduser("~"), ".gatekeeper", "state-projection"))


def _proj_cache_file(state_file: str) -> Path:
    import hashlib
    # ⚠ **不用** `os.path.realpath`：在 /mnt/c(CIFS) 上单个 realpath 实测 ~40ms（逐段解析），
    #   107 个候选 × 2（cache_file/写）就是 4s 级白开销（2026-10-29 实测踩过）。
    #   `abspath+normpath` 是纯字符串运算（无 syscall）：同一字符串路径 ⟹ 同一键；
    #   不同写法指向同一文件 ⟹ 两条缓存条目（仅多一份小文件，不影响正确性）。
    key = hashlib.sha256(("%s|%s" % (_STATE_PROJ_VERSION,
                                     os.path.normpath(os.path.abspath(state_file))))
                         .encode("utf-8")).hexdigest()
    return _proj_cache_dir() / (key[:40] + ".json")


def _peek_json_object(f) -> bool:
    """文件首个非空白字符是否 `{`。

    `_load_worktree` / `_describe_candidates` / `_state_field` 三处原式都是
    `json.load(f).get(k)`：只要顶层不是 object（jsonl 日志 / `.dispatch` / `.tmp` 拍平文本 /
    JSON 数组 / 空文件 / BOM），`json.load` 必抛或被 `isinstance(dict)` 挡回 ⟹ 结果恒 None。
    故「首字符不是 `{` ⟹ 直接 None」与原式**逐字等价**，但省掉对 MB 级 jsonl 的整份解析
    （本机 60/107 个候选就是这类，占 `_candidate_isolated_states` 1.15s 的绝大部分）。
    """
    while True:
        ch = f.read(1)
        if not ch:
            return False
        if ch.isspace():
            continue
        return ch == "{"


def _state_projection(state_file: str):
    """state 文件的只读投影 `{worktree, r_phase, stage}`；不可读/非 JSON 对象 ⟹ None。"""
    try:
        st = os.stat(state_file)
    except OSError:
        return None
    stamp = [st.st_mtime_ns, st.st_size, st.st_ctime_ns]
    # racy（见上方注释）：时间戳粒度不足，同秒内可能又被改过 ⟹ 既不读也不写缓存。
    racy = (time.time_ns() - st.st_mtime_ns) < _STATE_PROJ_RACY_NS
    cf = _proj_cache_file(state_file)
    if not racy:
        try:
            with cf.open(encoding="utf-8") as f:
                d = json.load(f)
            if (isinstance(d, dict) and d.get("stamp") == stamp and "proj" in d
                    and (d["proj"] is None or isinstance(d["proj"], dict))):
                return d["proj"]
        except Exception:  # noqa: BLE001
            pass
    try:
        with open(state_file, "r", encoding="utf-8") as f:
            if not _peek_json_object(f):
                proj = None
            else:
                f.seek(0)
                raw = json.load(f)
                proj = ({k: raw.get(k) for k in _STATE_PROJ_KEYS}
                        if isinstance(raw, dict) else None)
    except Exception:  # noqa: BLE001
        proj = None
    if not racy:
        try:                            # 原子写；失败静默（缓存是加速面，不是正确性面）
            cf.parent.mkdir(parents=True, exist_ok=True)
            tmp = cf.with_suffix(".%d.tmp" % os.getpid())
            with tmp.open("w", encoding="utf-8") as f:
                json.dump({"v": _STATE_PROJ_VERSION, "stamp": stamp, "proj": proj}, f)
            os.replace(tmp, cf)
        except Exception:  # noqa: BLE001
            pass
    return proj


def _owned_by_skill(worktree, skill_dir: str) -> bool:
    """worktree 是否标识技能仓库归属或开发 worktree 树归属（段级匹配，防子串误判）。"""
    wt = _norm(worktree)
    sd = _norm(skill_dir)
    if not wt:
        return False
    if wt == sd:
        return True
    # SKILL_MARKER 命中 + 末段目录名精确匹配（排除 copy/子目录变体）
    if SKILL_MARKER in wt and Path(wt).name == Path(sd).name == "spz-gatekeeper-r-sequence":
        return True
    # 开发 worktree 树（2026-09-01 扩展）：IDE 受控 worktree 根下 = 合法归属
    # （worktree 隔离 state 的 worktree 字段指向主仓库 feature worktree，如
    #   <home>/.trae/worktrees/.../feature/spz-gatekeeper-2.0.4-r7.1）
    for root in DEV_WORKTREE_ROOTS:
        if wt.lower().startswith(root.lower()):
            return True
    return False


def _collect_state_files(root: str, include_plain: bool = False) -> list:
    """2026-09-04: 收集单个根目录下的 state 候选文件。
    .gatekeeper.state.*（隔离 state）；include_plain=True → 额外含裸
    .gatekeeper.state（同址就近默认 state——跨仓库 worktree 就近存放的形态）。
    .lock 忽略；目录缺失/异常 → 空。

    2026-10-29（提速①配套）：原式 `sorted(d.glob(".gatekeeper.state.*"))` 把**旁挂件**也全收
    —— 本机技能目录 107 项里 60 项是 `.jsonl` journal/ledger/archive、`.dispatch`、`.tmp`，
    既不是 state 也永远读不出 worktree；glob 还要对每项各打一次 stat（CIFS ~2ms ⟹ ~0.28s/次，
    每次 CLI 启动都付）。现：① 按 `gk_state_forms.state_form` 的**权威形态**剔除 `artifact`
    （该模块头即声明「`_collect_state_files` 的形态判断改调本模块，禁第二份」，本轮把这条
    口径真正接上，未新造规则）；② 用 `os.scandir` 按名过滤，不再逐项 stat。
    **候选集逐字不变**：artifact 的 `_load_worktree` 恒 None，本来就会被下游过滤掉。
    """
    d = Path(root)
    try:
        names = [e.name for e in os.scandir(d)]
    except OSError:                     # 目录缺失 / 不是目录 ⟹ 空（原语义）
        return []
    out = []
    for n in sorted(names):
        if not n.startswith(BASE_NAME + "."):   # 隔离态前缀（base 走 include_plain）
            continue
        if n.endswith(".lock"):
            continue
        if is_artifact_name(n):
            continue
        out.append(d / n)
    if include_plain:
        plain = d / ".gatekeeper.state"
        if plain.is_file():
            out.append(plain)
    return out


def _candidate_isolated_states(skill_dir: str, extra_roots=()):
    """扫描默认技能目录 + 额外根（跨仓库就近根）的隔离 state，
    返回归属技能仓库的候选列表。技能目录内不含裸 .gatekeeper.state（= current）。"""
    roots = [skill_dir] + [r for r in extra_roots if _norm(r) != _norm(skill_dir)]
    cands = []
    seen = set()
    for root in roots:
        for f in _collect_state_files(root, include_plain=(_norm(root) != _norm(skill_dir))):
            key = _norm(str(f))
            if key in seen:
                continue
            seen.add(key)
            wt = _load_worktree(str(f))
            if wt is not None and _owned_by_skill(wt, skill_dir):
                cands.append(str(f))
    return sorted(cands)


def _worktree_match_state(skill_dir: str, worktree: str, exclude: str = "",
                          extra_roots=()) -> str:
    """2026-09-01: 扫描默认技能目录 + 额外根的隔离 state，找 worktree 字段与给定
    worktree 精确匹配的唯一候选（worktree 隔离 state：窄任务/节点执行级产物随
    worktree 隔离）。额外根允许跨仓库 worktree 就近 state 被匹配到（2026-09-04）。
    唯一匹配返回路径；无/多匹配返回 ""（不武断路由）。"""
    matches = []
    roots = [skill_dir] + [r for r in extra_roots if _norm(r) != _norm(skill_dir)]
    seen = set()
    for root in roots:
        for f in _collect_state_files(root, include_plain=(_norm(root) != _norm(skill_dir))):
            key = _norm(str(f))
            if key in seen or key == _norm(exclude):
                continue
            seen.add(key)
            wt = _load_worktree(str(f))
            if wt is not None and _norm(wt) == _norm(worktree):
                matches.append(str(f))
    return matches[0] if len(matches) == 1 else ""


def _describe_candidates(cands) -> str:
    """候选描述：文件名(r_phase/stage) 列表，让多候选 WARN 可操作（T3, 2026-08-25）。

    2026-10-29：改走 `_state_projection`（同一份 `(mtime,size,ctime)` 校验的只读投影）——
    原实现把命中的候选**整份再读一遍**，实测 16 候选 +0.18s/次，纯重复 I/O。
    不可读/不可解析仍落到 `(/)`，与修前逐字一致。
    """
    parts = []
    for c in cands:
        proj = _state_projection(c) or {}
        rp = proj.get("r_phase", "")
        stage = proj.get("stage", "")
        parts.append(f"{Path(c).name}({rp}/{stage})")
    return "; ".join(parts)


def _auto_extra_roots(skill_dir: str, current: str) -> list:
    """2026-09-04 跨仓库 worktree 就近扩根（方案 C P1/P2 最小落地）。

    仅两种保守信号自动扩根，其余情况一律不扩（防把无关目录的 state 拉进候选）：
      ① current 显式位于技能目录之外（--state-file / env STATE_FILE 给到某仓库或
         worktree 目录）→ 以 current 所在目录为额外根（同址就近扫描，含裸
         .gatekeeper.state —— 其他仓库/插件就近存放的默认形态）
      ② 进程 cwd 位于开发 worktree 树（DEV_WORKTREE_ROOTS）内 → 从 cwd 向上找
         首个就近携带 .gatekeeper.state*/plan 标记的目录为额外根
         （门卫 R7.1 / spz2glb / zthl 等跨仓库 worktree 隔离 state 可被匹配到；
          单测 cwd（scripts 目录）无标记、不在 worktree 树 → 不扩根，行为不变）
    注意：仅凭 state.worktree 字段指向某 worktree 不扩根——否则真实存在的
    门卫 worktree 目录会以额外候选身份混入单测/普通流程（2026-09-04 设计约束）。"""
    roots = []
    sd = _norm(skill_dir)
    try:
        cur_dir = _norm(str(Path(current).parent))
    except Exception:
        cur_dir = ""
    if cur_dir and cur_dir != sd and Path(cur_dir).is_dir():
        roots.append(cur_dir)
    try:
        cwd = _norm(os.getcwd())
    except Exception:
        cwd = ""
    if cwd and any(cwd.lower().startswith(r.lower()) for r in DEV_WORKTREE_ROOTS):
        node = Path(cwd)
        while True:
            try:
                if node.is_dir() and (list(node.glob(".gatekeeper.state*"))
                                      or (node / ".gatekeeper.plan").is_file()):
                    roots.append(str(node))
                    break
            except Exception:
                pass
            if not node.parent or node.parent == node:
                break
            node = node.parent
    out, seen = [], set()
    for r in roots:
        k = _norm(r)
        if k not in seen and k != sd:
            seen.add(k)
            out.append(r)
    return out


def select_plan_pointer(skill_dir: str, session_id: str = "", cmd_target_plan: str = "",
                        env_pointer: str = "", strict: bool = False, ttl_s: int = 86400,
                        domain_route: str = "", state_file_explicit: bool = False) -> dict:
    """**唯一**的「读哪个 plan 指针 / 本进程可写哪个指针」判定（§4.13.5③ 单源，`ECC-1EC0E0732F0D`）。

    收敛前：该判定**内联在 bash 启动块**（会话分片 / TTL / 命令对账 / 域 kill switch / `/mnt↔C:`
    双形态探测）⟹ 与 python 侧无对应实现 = 「指针语义双源」。现收本函数，bash 只消费其产出。

    优先：① `env_pointer`（显式）→ ② 会话指针 `.gatekeeper.plan.<sid>` → ③ 全局 `.gatekeeper.plan`。
    返回 `{pointer, own, followed, domain, plan, reason}`：
      · `pointer` = **读**目标（无绑定则仍回显本进程的 own 路径）；`own` = 本进程**可写/清**目标
        （显式 `STATE_FILE` ⟹ `""`，对齐既有「不写不删」语义）；
      · `followed` = 是否采纳；`reason` ∈ {`explicit_state_file`, `no_pointer_file`, `stale`,
        `cmd_target_mismatch`, `strict`, `domain_route_off`, `dangling_pointer`, `""`}。
    ⚠ **路径形态归一**（2026-10-18 实补）：`state_file` 的存在性判据走 `_exists_either`
    （`/mnt/c/x` ↔ `C:/x` 双向候选）。此前 docstring 声称做了「双形态探测」但实现里
    `Path(...).exists()` 只探单一形态 ⟹ 跨运行时写的指针被判 `dangling_pointer`
    （**声明与实现脱节 = 假绿**，被 `test_gk_plan_pointer_select` 5 红抓到）。
    语义与既有 bash 启动块**逐字一致**（含「有身份但本会话无指针 ⟹ **不采纳全局**」的 2026-09-28 修复）。
    """
    if state_file_explicit:
        return {"pointer": "", "own": "", "followed": False, "domain": "", "plan": "",
                "reason": "explicit_state_file"}
    sd = str(skill_dir)
    own = (env_pointer
           or (str(Path(sd) / (".gatekeeper.plan." + session_id)) if session_id else "")
           or str(Path(sd) / ".gatekeeper.plan"))
    p = own
    if not Path(p).exists():
        return {"pointer": p, "own": own, "followed": False, "domain": "", "plan": "",
                "reason": "no_pointer_file"}
    try:
        d = json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception:
        d = {}
    plan = str(d.get("plan", "") or "")
    dom = str(d.get("domain", "") or "")
    base = {"pointer": p, "own": own, "domain": dom, "plan": plan}
    if cmd_target_plan and plan and cmd_target_plan != plan:
        base.update({"followed": False, "reason": "cmd_target_mismatch"})
        return base
    if strict and plan:
        base.update({"followed": False, "reason": "strict"})
        return base
    if not _pointer_fresh(d):
        base.update({"followed": False, "reason": "stale"})
        return base
    if dom and (domain_route or os.environ.get("GK_STATE_DOMAIN_ROUTE", "1")) == "0":
        base.update({"followed": False, "reason": "domain_route_off"})
        return base
    if not (d.get("state_file") and _exists_either(str(d["state_file"]))):
        # 2026-10-18（跨平台 ①B 修复）：原判据 `Path(str(d["state_file"])).exists()`
        #   **只探单一形态**——WSL 侧 CLI 写 `<home>` ⟹ Windows Python 下
        #   `Path("/mnt/c/...")` 被读成 `C:\mnt\c\...` ⟹ 恒 False ⟹
        #   **`dangling_pointer`** ⟹ `followed=False` ⟹ CLI 报 `STATE_POINTER_STALE`。
        #   真因是「路径形态跨运行时不归一」，报错却说「指针悬空」（state 明明存在）。
        #   docstring 早已声明做了 `/mnt↔C:` 双形态归一，但实现里 `_norm` **从未被调用**
        #   —— 声明与实现脱节 = 假绿（`scripts/test_gk_plan_pointer_select.py` 5 红抓到）。
        # 修法 = `_exists_either` 双向候选试 exists（与 `pre_tool_hook._wsl_to_win` L3036、
        #   `gk_route_center._sf_exists` L305 同语义，但双向）。
        base.update({"followed": False, "reason": "dangling_pointer"})
        return base
    base.update({"followed": True, "reason": ""})
    return base


def read_point_pointer_error() -> dict:
    """§18.2 判据 c3（2026-10-04）：四读点 **declared-but-unresolved** fail-closed 守卫。

    病象（遗漏①）：plan 指针**已声明但未解析**（`stale` / `dangling_pointer`）时，读点静默
    回落 base state 读数据 —— 写不越界、读分裂的新假绿。**单一事实源**：启动块已算出的
    `pointer_reason` 经 env `GK_PLAN_POINTER_UNRESOLVED` 透出（启动块在 `stale` 时会 `rm`
    失效指针 ⟹ Python 侧事后重算只得 `no_pointer_file`，故**必须**由启动块透出，勿在此重算）。

    边界（拍板 A）：仅 `stale` / `dangling_pointer` 触发；`no_pointer_file`（合法默认，无指针）
    与显式 `STATE_FILE`（启动块不置位）**不触发** ⟹ 零回归。返回 `{}` = 无守卫；否则错误 dict。
    """
    reason = os.environ.get("GK_PLAN_POINTER_UNRESOLVED", "")
    if reason in ("stale", "dangling_pointer"):
        return {"ok": False, "error": "STATE_POINTER_" + reason.upper(), "reason": reason,
                "channel": "state-routing",
                "hint": "计划指针已声明但未解析（stale/dangling）⟹ 禁静默读 base；"
                        "先 discover --plan 重建绑定，或清除失效指针"}
    return {}


def resolve_state(skill_dir: str, state_file: str = "", plan_pointer: str = "",
                  extra_roots=None, domain: str = "", pointer_authoritative: bool = False,
                  state_file_explicit=None) -> dict:
    """state 路由判定：域解析 → plan 指针优先 → 归属校验 → 冲突纠正/WARN。

    extra_roots: 额外扫描根（跨仓库就近 state 目录）。None → 自动保守扩根
    （_auto_extra_roots）；显式传入列表 → 仅扫给定根（跳过自动）。
    domain（2026-09-15 A6-P2 接线）: 计划声明的 META.state_domain / CLI `--domain` 域 token
    → 1b 步解析**当前 state 同级**的 `.gatekeeper.state.<token>`（落点解析委托
    `gk_finding.resolve_domain_state`，两者同源）；空串 = 不触发（行为与既有链逐字一致）。
    pointer_authoritative（§4.13.5③ 单源，`ECC-1EC0E0732F0D`）: 调用方（`gk_route_center` 门面
    = `select_plan_pointer` 的唯一消费点）已**判定**指针 ⟹ `plan_pointer` 即定论，**不再**回落
    env `PLAN_POINTER` / 全局 `.gatekeeper.plan`（原式 `plan_pointer or env or 默认` 会在「显式
    判定不跟随」时把**全局指针**重新拉回 ⟹ 判定被静默推翻：跨会话劫持 / 域 kill switch 失效）。
    默认 False 保持既有调用方（含 `gk_state_route.main`）语义**逐字不变**。"""
    sd = str(skill_dir)
    current = state_file or os.environ.get("STATE_FILE") or str(Path(sd) / ".gatekeeper.state")
    roots = _auto_extra_roots(sd, current) if extra_roots is None else list(extra_roots)
    # 2026-10-10（ECC-7FF904ADF22C · L1 惰性化）：显式态判定 —— 调用方可显式传参；
    # 未传（None）时读 env（既有调用方/CLI 逐字不变）。
    explicit = (os.environ.get("STATE_FILE_EXPLICIT", "0") == "1"
                if state_file_explicit is None else bool(state_file_explicit))

    # 1. plan 指针优先（discover --plan 写入，跨进程联动隔离 state）
    #    pointer_authoritative=True ⟹ 只用传入的 `plan_pointer`（空 = 判定「不跟随任何指针」）；
    #    否则（legacy 调用方）按原式回落 env / 全局指针。
    pp = (plan_pointer if pointer_authoritative
          else (plan_pointer or os.environ.get("PLAN_POINTER")
                or str(Path(sd) / ".gatekeeper.plan")))
    if pp and Path(pp).exists():
        try:
            pdata = json.loads(Path(pp).read_text(encoding="utf-8"))
            # Phase 7b (2026-08-23): TTL 校验 — updated 超 24h 视为失效，
            # fall through 到归属校验（safety_net 不被过期指针绕开）
            if _pointer_fresh(pdata):
                # 指针指向的 state 必须真实存在，悬空指针 fall through 到归属校验
                if pdata.get("state_file") and Path(pdata["state_file"]).exists():
                    return {"expected": pdata["state_file"], "current": current,
                            "conflict": False, "corrected": False, "candidates": [],
                            "warning": None, "source": "plan_pointer"}
        except Exception:
            pass

    # 1b. 域解析（A6-P2「路由执行侧强制」接线，2026-09-15；F-REV-63 / 质询 F1-F4 修订）：
    #     计划声明的 META.state_domain（或 `--domain` 直传）→ `.gatekeeper.state.<token>`。
    #     位置 = plan 指针**之后**（运行时显式绑定优先）、worktree 匹配**之前**（计划侧显式
    #     声明优先于隐式启发式匹配）。
    #     基址 = **当前 state 同级**（与 gk_finding.resolve_domain_state 同源，禁第二套落点；
    #     质询 F4 —— 原实装用 skill_dir，会使 finding 写入点与路由读取点分叉）。
    #     纪律**同构**：直接委托 gk_finding.resolve_domain_state（token 校验/fail-closed
    #     单一事实源），**声明域后不静默回退**（目标不存在 → error 显式上报）。
    #     开关：GK_STATE_DOMAIN_ROUTE=0 ⟹ 跳过本步（完全回原链）；无域声明 ⟹ 不触发（J3 不变）。
    dom = (domain or "").strip()
    if dom and os.environ.get("GK_STATE_DOMAIN_ROUTE", "1") != "0":
        try:
            # 单一事实源：域 token 形态 / state 前缀 / 落点解析全部取自 gk_finding（禁第二份实现）
            from gk_finding import (_DOMAIN_TOKEN_RE as dom_re,
                                    resolve_domain_state as rds)
        except Exception as e:
            # 2026-09-15 REV-4（质询 N6）：依赖不可用时**不得静默跳步**——原 `except: pass`
            # 会让 dom_re/rds 双双为 None ⟹ 后续两个 if 全不命中 ⟹ 1b 静默跳过（fail-open），
            # 且无法与"未声明域"区分。改为显式 error（fail-closed 纪律同构）。
            return {"expected": "", "current": current, "conflict": False,
                    "corrected": False, "candidates": [],
                    "warning": f"gk_finding 不可用（state_domain={dom} 无法解析）: {e}",
                    "source": "state_domain", "domain": dom,
                    "error": "STATE_DOMAIN_DEPENDENCY_UNAVAILABLE"}
        if not dom_re.match(dom):
            return {"expected": "", "current": current, "conflict": False,
                    "corrected": False, "candidates": [],
                    "warning": f"state_domain 非法 token: {dom!r}（须匹配 {dom_re.pattern}）",
                    "source": "state_domain", "domain": dom,
                    "error": "STATE_DOMAIN_TOKEN_INVALID"}
        try:
            target = rds(current, dom)
        except Exception as e:
            msg = str(e)
            code = ("STATE_DOMAIN_MISMATCH" if "FINDING_DOMAIN_MISMATCH" in msg
                    else "STATE_DOMAIN_MISSING")
            return {"expected": "", "current": current, "conflict": False,
                    "corrected": False, "candidates": [], "warning": msg,
                    "source": "state_domain", "domain": dom, "error": code}
        return {"expected": target, "current": current, "conflict": False,
                "corrected": False, "candidates": [target],
                "warning": None, "source": "state_domain", "domain": dom}

    # 2. worktree 匹配路由（2026-09-01）：当前 state 的 worktree 指向开发 worktree
    #    （非技能目录自身）时，路由到 worktree 精确匹配的唯一隔离 state——
    #    窄任务/节点执行级产物随 worktree 隔离（CLI 不再恒定读技能目录 state）。
    wt = _load_worktree(current)
    if wt and _owned_by_skill(wt, sd) and _norm(wt) != _norm(sd):
        match = _worktree_match_state(sd, wt, exclude=current, extra_roots=roots)
        if match:
            # 2026-09-04 守卫: 候选与当前默认 state 的 r_phase 必须一致才路由——
            # 旧阶段隔离 state（如 R7/STAGE_0）可能带同 worktree 字段却 checksum 失配，
            # 唯一命中时会把活跃 campaign（R7.1/STAGE_1）顶替成旧阶段 → guard-edit TAMPERED。
            # 追加新鲜度守卫: 候选比当前默认更旧（如 worktree 内 09-02 副本 vs 默认 09-04）
            # → 不路由（默认更新 = 活跃进展在默认，防回退旧副本）。
            cur_rp = _state_field(current, "r_phase")
            m_rp = _state_field(match, "r_phase")
            cur_t = _state_mtime(current)
            m_t = _state_mtime(match)
            phase_mismatch = bool(cur_rp and m_rp and _norm(cur_rp).lower() != _norm(m_rp).lower())
            stale_match = bool(cur_t is not None and m_t is not None and cur_t > m_t)
            if phase_mismatch or stale_match:
                match = ""  # 不路由，落回归属校验/当前默认
        if match:
            return {"expected": match, "current": current, "conflict": False,
                    "corrected": True, "candidates": [match],
                    "warning": "", "source": "worktree_match"}

    # 3. 归属校验：无 worktree 匹配 → 校验当前 state 归属
    conflict = wt is not None and not _owned_by_skill(wt, sd)
    if not conflict:
        # 2026-09-04: 默认 state 被跨仓库 worktree 占用且未找到唯一隔离 state 时
        # 给可操作提示（不复位、不静默）——对齐方案 C 就近落位前的最小区分信号
        hint = None
        if _norm(current) == _norm(str(Path(sd) / ".gatekeeper.state")) \
                and wt and _owned_by_skill(wt, sd) and _norm(wt) != _norm(sd):
            hint = (f"默认 .gatekeeper.state 的 worktree={wt} 指向开发 worktree "
                    f"（疑似被跨仓库 discover 占用），且未找到唯一匹配的隔离 state；"
                    f"如需复位请用 discover（no --plan），或用 --plan/discover --plan 显式绑定。")
        return {"expected": current, "current": current, "conflict": False,
                "corrected": False, "candidates": [], "warning": hint,
                "source": "current"}

    # 4. 冲突 → 扫描隔离 state 纠正（恰好 1 个匹配时）
    # 2026-10-10（ECC-7FF904ADF22C · L1 惰性化）：**显式 state 下跳过全量候选扫描** ——
    #   `_candidate_isolated_states` 是 glob（× 全 extra_roots）+ **逐候选** `_load_worktree`/
    #   `_owned_by_skill`（含 git 调用）的全量索引，实测 ~1.3s/次（17 候选）且为 CLI **每次启动**
    #   的固定开销主成分。而显式注入态（`STATE_FILE_EXPLICIT=1`，测试/集成/论文仓库等）下，
    #   「自动纠正调用方显式指定的 state」与应用语义相悖（启动块 L307-309 同款口径：显式态
    #   无指针通道、不写不删）⟹ 惰性化 = 不枚举、不纠正，只如实报冲突（candidates 恒空）。
    #   ⚠ 仅在显式态生效；非显式调用方**逐字不变**（既有 20+ 安全网臂零回归，见 test_gk_state_route.py）。
    #   ⟹ 2026-10-29 补充：非显式态（生产默认）的这刀由 `_state_projection` 缓存承接
    #     （逐文件整份 json.load → 1 次 stat + 小文件回放），本分支**不枚举**的语义不变。
    if explicit:
        return {"expected": current, "current": current, "conflict": True,
                "corrected": False, "candidates": [],
                "warning": f"state 归属冲突: {current} 的 worktree={wt} 不属于技能仓库; "
                           f"显式 state（STATE_FILE_EXPLICIT=1）⟹ 跳过候选扫描、不自动纠正",
                "source": "safety_net"}
    cands = _candidate_isolated_states(sd, extra_roots=roots)
    if len(cands) == 1:
        return {"expected": cands[0], "current": current, "conflict": True,
                "corrected": True, "candidates": cands,
                "warning": f"state 归属冲突: {current} 的 worktree={wt} 不属于技能仓库; 已纠正到 {cands[0]}",
                "source": "safety_net"}

    return {"expected": current, "current": current, "conflict": True,
            "corrected": False, "candidates": cands,
            "warning": f"state 归属冲突: {current} 的 worktree={wt} 不属于技能仓库; "
                       f"匹配隔离 state {len(cands)} 个，不自动纠正（防误纠，请用 discover --plan 指定）: "
                       f"{_describe_candidates(cands)}",
            "source": "safety_net"}


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    skill_dir = os.environ.get("SKILL_DIR", "")
    state_file = os.environ.get("STATE_FILE", "")
    plan_pointer = os.environ.get("PLAN_POINTER", "")
    # 2026-09-04: 额外扫描根（跨仓库就近 state）——env GATEKEEPER_STATE_ROOTS 分隔
    # 符按平台取 os.pathsep（nt=';'，posix=':'——Windows 盘符含 ':' 不能作分隔符）。
    # --extra-root 可重复。未提供 → 自动保守扩根。
    extra_roots = [r for r in os.environ.get("GATEKEEPER_STATE_ROOTS", "").split(os.pathsep)
                   if r]
    argv_skill = ""
    domain = ""
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--skill-dir" and i + 1 < len(args):
            argv_skill = args[i + 1]
            skill_dir = argv_skill
            i += 2
        elif a == "--state-file" and i + 1 < len(args):
            state_file = args[i + 1]
            i += 2
        elif a == "--plan-pointer" and i + 1 < len(args):
            plan_pointer = args[i + 1]
            i += 2
        elif a == "--domain" and i + 1 < len(args):
            # 2026-09-15 REV-5（质询 d）：独立入口此前**不解析 --domain**，且未知选项被
            # `else: i += 1` 静默吞掉 ⟹ 1b 步在本入口永不触发（与本计划批判的
            # "1b 静默 no-op" 同类）。现补解析 + 未知选项 fail-closed。
            domain = args[i + 1]
            i += 2
        elif a == "--extra-root" and i + 1 < len(args):
            extra_roots.append(args[i + 1])
            i += 2
        elif a.startswith("-"):
            # 2026-09-15 REV-5（四轮质询 G5）：原判据只覆盖 `--` 前缀 ⟹ 单破折号未知选项
            # （如 `-d`）仍被 `else: i += 1` 静默吞掉，"未知选项不静默忽略"只对一半形态成立。
            # 现覆盖全部 `-` 前缀；**裸位置参数仍容忍跳过**（既有契约：本入口可能收到
            # 上游透传的余参），并如实登记在 docstring（不再宣称"所有未知输入"）。
            print(json.dumps({"expected": None, "current": state_file, "conflict": False,
                              "corrected": False, "candidates": [], "domain": domain,
                              "warning": (f"未知选项 {a!r}（usage: --skill-dir <d> | "
                                          "--state-file <f> | --plan-pointer <f> | "
                                          "--domain <repo>.<plan> | --extra-root <r>）"),
                              "source": "error", "error": "UNKNOWN_OPTION"}))
            sys.exit(2)
        else:
            i += 1
    if not argv_skill and skill_dir:
        # C 层收口（2026-09-02）：L4 state 路由独立入口同样受 env SKILL_DIR 注入面威胁
        # （python3 gk_state_route.py + env SKILL_DIR=/tmp/evil → state 路由指向攻击者目录）。
        # 复用路由中枢信任门（内容特征 + git 锚定）——不可信 → 回退默认技能目录（fail-closed）。
        from gk_route_center import _skill_dir_env_trusted
        if not _skill_dir_env_trusted(skill_dir):
            skill_dir = ""
    skill_dir = skill_dir or str(DEFAULT_SKILL)
    try:
        # ensure_ascii=True（默认）：warning 中文转 \uXXXX，避免 argv 传参跨编码损坏
        print(json.dumps(resolve_state(skill_dir, state_file, plan_pointer,
                                       extra_roots=extra_roots or None, domain=domain)))
    except Exception as e:
        print(json.dumps({"expected": None, "current": state_file, "conflict": False,
                          "corrected": False, "candidates": [], "warning": str(e),
                          "source": "error"}))
        sys.exit(1)


if __name__ == "__main__":
    main()

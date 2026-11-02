#!/usr/bin/env python3
"""
gk_route_center.py — 元数据路由中枢（唯一路由，五层分级延展，2026-09-02）
==========================================================================
用户定案（2026-09-02）：元数据路由不应只是文档，而是唯一可执行路由中枢。
state 解析链 / worktree 匹配 / 窄任务查询 全部作为中枢的分级延展，层层咬合，
不再散落为并行独立机制。CLI 只做参数传递与结果消费，不内嵌路由判定。

五层链（自顶向下分级延展，层层咬合）:
  L1 plan 解析    resolve_plan()     META 块解析 + 5 层金字塔搜索 + standing 常驻检测
                                    （迁自 gatekeeper-cli.sh _read_plan_metadata）
  L1b 绑定计划    resolve_bound_plan() state 绑定计划（计划指针 / 隔离 state 文件名后缀），
                                    F-REV-14：防 advance 的 META 读取脱钩到硬编码 PLAN_FILE
  L2 repo 解析    resolve_repo()     target_repo → 绝对路径（迁自 _resolve_repo_path）
  L3 worktree 检测 resolve_worktree() feature worktree 定位（迁自 cmd_discover）
  L4 state 解析链  resolve_state()    plan 指针 → 域解析 → worktree 匹配 → 归属校验 → 默认
                                    （迁自 gk_state_route.py，本轮扩展 worktree 匹配路由）
  L5 窄任务查询   resolve_narrow()    narrow_tasks[] → tier / poison / schema
                                    （迁自 gk_narrow_route.py）

路由优先级（L4 state 解析链，自上而下，显式优先 + 隐式兜底）:
  1. plan 指针（discover --plan 写入，TTL 24h）→ 显式绑定，尊重不纠正
  1b. 域解析（META.state_domain / `--domain` → 当前 state 同级 `.gatekeeper.state.<token>`）
      —— 排在 plan 指针**之后**（运行时显式绑定优先）、worktree 匹配**之前**（计划侧显式
      声明优先于隐式启发式）；落点解析委托 gk_finding.resolve_domain_state（单一事实源）
  2. worktree 匹配（state.worktree 指向开发 worktree → 隔离 state 精确匹配唯一候选）
     —— discover --plan 的隐式补位：无指针时的自动咬合（2026-09-01 新增）
  3. 归属校验（state.worktree ∈ 技能仓库/开发 worktree 树）
  4. safety_net（冲突 + 恰好 1 候选 → 纠正；多候选 → WARN 不武断）

CLI 契约:
  python3 gk_route_center.py route-all [--skill-dir <d>] [--state-file <f>]
                        [--plan-file <p>] [--plan-override <p>] [--repo <r>] [--task <t>]
                        [--domain <repo>.<plan>]
  python3 gk_route_center.py resolve-plan [--skill-dir <d>] [--plan-file <p>]
  python3 gk_route_center.py resolve-bound-plan [--skill-dir <d>] [--state-file <f>]
                        [--plan-pointer <p>]
  python3 gk_route_center.py resolve-repo <repo> [--skill-dir <d>]
  python3 gk_route_center.py resolve-worktree [--skill-dir <d>] [--branch-lines <b>]
  python3 gk_route_center.py resolve-state [--skill-dir <d>] [--state-file <f>]
                        [--plan-pointer <p>] [--domain <repo>.<plan>]
                        [--plan-file <p> | --plan-override <p>]   # 未传 --domain 时读其 META.state_domain
  python3 gk_route_center.py resolve-narrow --state <f> --task <t>
                        [--check-poison] [--check-schema]
  SKILL_DIR / STATE_FILE / PLAN_POINTER env 亦可指定；
  resolve-worktree 另认 GK_WORKTREE_REPO（仓库名，显式胜）/ GK_WORKTREE_CWD（调用方 cwd 路径
  ⟹ 仓库段由 git 权威视图=该仓**主 worktree** 目录名派生，2026-09-25 ⑤ 落点归一）。

`--domain`（2026-09-15，A6-P2 域解析接线）：域 token → L4 1b 步解析同目录
`.gatekeeper.state.<token>`；缺省回退 L1 计划声明的 META.state_domain；两者皆空 = 不触发。

Exit codes: 0 = OK (JSON on stdout), 1 = error JSON。
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

try:  # 同目录单源推导（用户目录不写死用户名，2026-10-29 去硬编码）
    from gk_host_paths import user_home as _user_home
except ImportError:  # pragma: no cover - 导出面/独立调用兜底
    def _user_home() -> str:
        return os.path.expanduser("~")

_USER_HOME = _user_home().replace("\\", "/")

# 技能默认位置（与 gk_state_route 同源推导）
DEFAULT_SKILL = Path(__file__).resolve().parent.parent
SKILL_MARKER = "/skills/spz-gatekeeper-r-sequence"

# 主仓库常量（2026-10-31 起为运行时解析结果的空串占位）
# 2026-10-31（开源前置）：主仓路径运行时解析（单源 = `gk_main_repo.resolve`）。
#   优先级 GK_MAIN_REPO → state.target_repo → META target_repo → git rev-parse。
#   `MAIN_REPO_WSL/WIN` 空串仅为外部 import 兼容；**权威取数** 走 `_main_repo_wsl()`。
#   多副本一致性判据改为「三处均无字面量 + 均引用单源」（test_main_repo_value_sync.py）。
from gk_main_repo import resolve as _resolve_main_repo  # noqa: E402

MAIN_REPO_WSL = ""
MAIN_REPO_WIN = ""
_MR_CACHE = {}


def _main_repo():
    if "v" not in _MR_CACHE:
        _MR_CACHE["v"] = _resolve_main_repo()
    return _MR_CACHE["v"]


def _main_repo_wsl() -> str:
    return _main_repo().get("wsl", "") if _main_repo().get("ok") else ""


def _main_repo_win() -> str:
    return _main_repo().get("win", "") if _main_repo().get("ok") else ""


# import 期解析（git 兜底）；解析失败保持空串（调用方 fail-closed）
MAIN_REPO_WSL = _main_repo_wsl()
MAIN_REPO_WIN = _main_repo_win()


# 5 层金字塔搜索路径（对齐 gatekeeper-cli.sh _read_plan_metadata；2026-09-02 4→5 层修正）
SEARCH_DIRS = (
    "{main}/docs/plans/",
    "{main}/docs/plan-backup/",
    "{skill}/references/",
    "{skill}/references/docs/plan-backup/",
    "{user}/.codex/docs/plans/",
)

# META 字段（对齐 meta-routing-protocol.md 完整形态 8 字段）
# 2026-09-04: 新增可选 state_domain —— 计划声明的 state 域绑定（worktree↔state 对应声明，
# 域 token 形式 <repo>.<plan>，对齐 T15/A2 域化命名前向接口；未声明 → 路由启发式兜底）
# 2026-09-10: 新增可选 source_docs —— 计划引用的源文档清单（逗号分隔路径），供 advance 自动
# 注入 node_guard --source-docs（P1：自动路径原无该前置的自动源 → 恒 missing；未声明 → info 跳过）
_META_FIELDS = ("phases", "target_repo", "project_type", "worktree_needed",
                "work_dir", "commit_obj", "commit_format", "review", "state_domain",
                "source_docs", "edit_budget_declared")


# ────────────────────────── L1 plan 解析 ──────────────────────────
def _parse_meta(text: str) -> dict:
    """从文档文本解析 META 块（完整/ inline 双格式）。"""
    meta = {}
    bm = re.search(r"<!--\s*META\s*(.*?)-->", text, re.DOTALL)
    if bm:
        for line in bm.group(1).split("\n"):
            m = re.match(r"\s*(\w[\w_]*):\s*(\S.*?)(?:\s*-->)?\s*$", line)
            if m:
                meta[m.group(1)] = m.group(2).strip()
    # inline 格式: <!-- META phases: R1 R2 R3 -->
    for field in _META_FIELDS:
        if field in meta:
            continue
        im = re.search(r"<!--\s*META\s+" + field + r":\s*(\S.*?)\s*-->", text)
        if im:
            meta[field] = im.group(1).strip()
    return meta


# REV-1b / owner 2026-09-28：声明式批额度**独立**上界（节点硬顶 `EDIT_BUDGET_HARD_CAP`=16
# **只夹 `current_lr` 项**，不夹 `declared`）⟹ 反棘轮闸，非默认额度。
DECLARED_HARD_CAP = 24


def declared_from_meta(meta: dict) -> int:
    """**唯一**的 C1 载体解析入口：计划 META `edit_budget_declared` → `int ∈ [0, DECLARED_HARD_CAP]`。

    缺省 / 空 / 非法 / 负值 ⟹ **0**（未声明 ⟹ 调用方退回现状注入 `min(current_lr × PER_LR, HARD_CAP)`）；
    越上界 ⟹ 钳到 `DECLARED_HARD_CAP`（不静默丢弃；越界另由 `plan-lint` 报 medium）。
    """
    raw = (meta or {}).get("edit_budget_declared")
    if raw is None or str(raw).strip() == "":
        return 0
    try:
        v = int(str(raw).strip())
    except (TypeError, ValueError):
        return 0
    if v < 0:
        return 0
    return min(v, DECLARED_HARD_CAP)


def resolve_plan(plan_file: str = "", skill_dir: str = "", main_repo_wsl: str = "",
                 search_dirs=None) -> dict:
    """L1: 解析计划文档 META 块。plan_file 缺失/不存在时做 5 层金字塔搜索
    （mtime 降序；命中后校验 META 完整性——phases 非空才采用，残缺跳过继续搜；
    search_dirs 可注入隔离，默认标准金字塔）。
    返回 {"plan_file", "meta": {...}, "warnings": [...]}；未找到 → 空 meta（不崩）。"""
    sd = skill_dir or str(DEFAULT_SKILL)
    mr = main_repo_wsl or _main_repo_wsl()
    warnings = []
    target = ""
    if plan_file:
        if plan_file.startswith("/"):
            target = plan_file
        elif Path(plan_file).is_file():
            target = plan_file
        elif Path(mr, "docs", "plans", plan_file).is_file():
            target = str(Path(mr, "docs", "plans", plan_file))
        elif Path(sd, plan_file).is_file():
            target = str(Path(sd, plan_file))

    if not target:
        # 5 层金字塔搜索：每层 mtime 降序；命中含 META 字样 → 解析校验 phases 非空才采用
        # （2026-09-02 扩展：残缺 META 不再被首个命中采用——防"搜到空壳计划当路由输入"）
        dirs = search_dirs if search_dirs is not None else SEARCH_DIRS
        for d in dirs:
            dpath = Path(d.format(main=mr, skill=sd, user=_USER_HOME))
            try:
                files = sorted(dpath.glob("*.md"),
                               key=lambda p: p.stat().st_mtime, reverse=True)
            except Exception:
                continue
            for f in files:
                try:
                    head = f.read_text(encoding="utf-8", errors="replace")[:2000]
                except OSError:
                    continue
                if re.search(r"META\s+\w+:", head):
                    m = _parse_meta(head)
                    if m.get("phases"):
                        target = str(f)
                        break
                    warnings.append(f"skip 残缺 META: {f.name} (无 phases)")
            if target:
                break

    if not target:
        # standing 常驻计划自动检测（对齐 cmd_discover standing fallback）
        try:
            sp = sorted(Path(sd, "docs", "plans").glob("*-standing-plan.md"),
                        key=lambda p: p.stat().st_mtime, reverse=True)
            if sp:
                target = str(sp[0])
        except Exception:
            pass

    # 过时路径检测（2026-09-02）：SEARCH_DIRS 硬编码目录不存在 → WARN（防静默失效）
    for d in SEARCH_DIRS:
        dp = Path(d.format(main=mr, skill=sd, user=_USER_HOME))
        if not dp.is_dir():
            warnings.append(f"搜索路径不存在: {dp}")

    if not target or not Path(target).is_file():
        return {"plan_file": "", "meta": {}, "warnings": warnings}
    try:
        text = Path(target).read_text(encoding="utf-8", errors="replace")
        meta = _parse_meta(text)
    except OSError:
        return {"plan_file": "", "meta": {}, "warnings": warnings}
    return {"plan_file": target, "meta": meta, "warnings": warnings}


# ─────────────────────── L1b state 绑定计划解析 ───────────────────────
# F-REV-14 (2026-09-10): 计划来源正本清源——advance 的 META 读取（含 source_docs 接源）
# 此前恒读硬编码 PLAN_FILE（默认 R 对齐计划），与 state 指针绑定的实际计划脱钩 →
# 隔离 state（.gatekeeper.state.<plan>）下 META source_docs 恒空、node_guard 该前置
# 等价 no-op（接了管道但源侧永无数据）。本函数给出 state 绑定的计划名/路径：
#   计划指针 plan 字段（跨进程绑定） → 隔离 state 文件名后缀
# 仅当搜索路径中真实存在同名的 .md 才返回路径（防落 resolve_plan 的"5 层金字塔取最新"
# 误采他计划——那正是本缺陷的形态）。
def resolve_bound_plan(state_file: str = "", plan_pointer: str = "",
                       skill_dir: str = "", main_repo_wsl: str = "") -> dict:
    """解析 state 绑定的计划文档。返回 {"plan": name, "plan_file": path, "source": ...}。
    source ∈ {pointer, state, none}；plan_file 为空 = 未绑定或绑定计划不存在。"""
    sd = skill_dir or str(DEFAULT_SKILL)
    mr = main_repo_wsl or _main_repo_wsl()
    name = ""
    source = "none"
    if plan_pointer and Path(plan_pointer).is_file():
        try:
            name = (json.loads(Path(plan_pointer).read_text(encoding="utf-8")).get("plan") or "").strip()
        except Exception:
            name = ""
        if name:
            source = "pointer"
    if not name and state_file:
        b = Path(state_file).name
        prefix = ".gatekeeper.state."
        if b.startswith(prefix):
            name = b[len(prefix):]
            if name:
                source = "state"
    if name.endswith(".md"):
        name = name[:-3]
    if not name:
        return {"plan": "", "plan_file": "", "source": "none"}
    for cand in (Path(mr, "docs", "plans", name + ".md"),
                 Path(sd, "docs", "plans", name + ".md"),
                 Path(sd, "references", name + ".md")):
        if cand.is_file():
            return {"plan": name, "plan_file": str(cand), "source": source}
    return {"plan": name, "plan_file": "", "source": source}


# ────────────────────────── L2 repo 解析 ──────────────────────────
def _scopes_read_repo_root(alias: str, skill_dir: str) -> str:
    """scopes `read_repo` 别名 → 项目根（`dirname(state_file)`）；**单源** = `.gatekeeper.scopes.json`。

    2026-10-01（L2 修通）：与 `subagent_runner._augment_repo_roots` **同源同语义**，消除
    「中枢硬编码表 ↔ scopes」双事实源 —— 此前 `project-register register … --read-repo X`
    只在 subagent 侧生效（读 REPO_ROOTS），中枢 `resolve_repo` 不认 ⟹ CLI `search --repo X`
    恒 `unknown repo`（同一对象两事实源，本仓明禁）。
    实存校验双形态（`/mnt/c/..` ↔ `C:/..`，与 `_augment_repo_roots._sf_exists` 同语义）；
    别名缺失 / state 不实存 / 文件损坏 ⟹ `""`（fail-soft，回退 unknown，不放行死路径）。
    """
    if not alias or not skill_dir:
        return ""
    try:
        d = json.loads(open(os.path.join(skill_dir, ".gatekeeper.scopes.json"),
                            encoding="utf-8").read())
    except Exception:
        return ""
    for e in d.get("governed_projects", []) or []:
        if not isinstance(e, dict) or str(e.get("read_repo") or "") != alias:
            continue
        sf = str(e.get("state_file") or "")
        if not sf:
            continue
        ok = os.path.isfile(sf)
        if not ok:
            m = re.match(r"^/mnt/([a-zA-Z])/(.*)$", sf)
            if m:
                ok = os.path.isfile(f"{m.group(1).upper()}:\\{m.group(2).replace('/', os.sep)}")
        if ok:
            root = os.path.dirname(sf)
            if root:
                return root
    return ""


def resolve_repo(repo_name: str = "", skill_dir: str = "", main_repo_wsl: str = "") -> dict:
    """L2: target_repo → 绝对路径。unknown → {"error", "valid"}（不静默 fallback）。"""
    sd = skill_dir or str(DEFAULT_SKILL)
    mr = main_repo_wsl or _main_repo_wsl()
    name = (repo_name or "").strip()
    if not name:
        return {"error": "no repo specified", "valid": _VALID_REPOS()}
    table = {
        "gatekeeper": mr,
        "skill": sd,
        "spz2glb": os.environ.get("SPZ2GLB_DIR") or str(Path(mr).parent / "spz_ecosystem_simplified" / "tools" / "spz_to_glb"),
        "bridge": os.environ.get("BRIDGE_DIR") or (_USER_HOME + "/.codex"),
        "bridge-r-phase": os.environ.get("BRIDGE_R_PHASE_DIR") or str(Path(sd).parent / "bridge-r-phase"),
        "supply-chain": os.environ.get("SUPPLY_CHAIN_DIR", ""),
        "research": os.environ.get("RESEARCH_DIR", ""),
    }
    # 别名（对齐 CLI：引导用规范名）
    if name == "spz-gatekeeper-r-sequence":
        return {"path": sd, "alias_of": "skill", "note": "use 'skill'"}
    if name == "spz_gatekeeper":
        return {"path": mr, "alias_of": "gatekeeper", "note": "use 'gatekeeper'"}
    if name in table:
        return {"path": table[name], "repo": name}
    # 2026-10-01（L2 修通）：内建表未命中 → scopes `read_repo` 别名回退（单一事实源），
    #   使 `project-register register … --read-repo X` 后 CLI `search --repo X` 与
    #   subagent `read_repo repo=X` **同源**（此前只有 subagent 侧认得 scopes）。
    _sr = _scopes_read_repo_root(name, sd)
    if _sr:
        return {"path": _sr, "repo": name, "source": "scopes"}
    return {"error": f"unknown repo '{name}'", "valid": _VALID_REPOS()}


def _VALID_REPOS() -> list:
    return ["gatekeeper", "skill", "spz2glb", "bridge", "bridge-r-phase",
            "supply-chain", "research"]


# ────────────────────────── L3 worktree 检测 ──────────────────────────
# 开发 worktree 根（对齐 gk_state_route DEV_WORKTREE_ROOTS 语义，本层统一供给）
DEV_WORKTREE_ROOTS = (
    "<home>/.trae/worktrees/",
    "c:/users/hp/.trae/worktrees/",
    "/root/.config/superpowers/worktrees/",
)

# L3 worktree **route 白名单**（2026-09-28，F7 族 / `ECC-5756951C56C8`）：dirscan 只认这三种
# route 形态 —— 值 = (route 名, 该 route 下 worktree 目录相对 `<root>/<repo>/` 的 glob 段数)。
# 实测仓内实存形态（`git worktree list`）：
#   · `feature/<rN>`              （1 段，分支名含 r<N>）
#   · `standing/<slug>`           （1 段）
#   · `agent/<family>/<sha8>`     （2 段；`apply_worktree` 的布局）与 `agent/session/<sha8>`
#     （2 段；`apply-worktree --session` 的布局）—— 二者合为 `*/agent/*/*`。
# ⚠ `dryrun/` 只容 `*.state` 文件（**非** worktree route）、`audit/` 全仓不存在 ⟹ 均**不列入**
# （列入会把非 worktree 目录误判为可见 worktree）。新增 route 须在此白名单登记（单一事实源）。
WORKTREE_ROUTES = (
    ("feature", "*/feature/*"),
    ("standing", "*/standing/*"),
    ("agent", "*/agent/*/*"),
)


def _norm_path(p) -> str:
    return (str(p or "").replace("\\", "/")).rstrip("/")


def _git_branch_lines(repo_dir: str) -> list:
    """列出 feature/spz-gatekeeper-* 分支（对齐 CLI cmd_discover：在主仓库 cwd 跑；
    WSL git；失败返回空）。"""
    try:
        out = subprocess.run(
            ["git", "branch", "--list", "feature/spz-gatekeeper-*"],
            cwd=repo_dir, capture_output=True, text=True, timeout=15)
        return [l for l in out.stdout.splitlines() if l.strip()]
    except Exception:
        return []


def _skill_dir_trusted(skill_dir: str) -> bool:
    """技能目录可信性校验（2026-09-02 L1-10 交叉审查漏洞 1 + 红队空壳伪装绕过修复）：
    env SKILL_DIR 注入 → 五层路由全部指向攻击者目录。
    原实现仅校验文件存在性——攻击者创建两个空文件（evil/gatekeeper-cli.sh +
    evil/SKILL.md）即可伪装通过（红队实测 trusted=True）。
    现 3 层防线（抬升伪造成本）:
      ① 目录名必须为 spz-gatekeeper-r-sequence（对齐 gk_state_route._owned_by_skill 段级匹配）
      ② 结构特征: scripts/gk_route_center.py（路由中枢）+ gatekeeper-cli.sh + SKILL.md 实存
      ③ 内容标记: gatekeeper-cli.sh 含 SKILL_REPO_HASH 指纹、SKILL.md 含技能名（非空）
    残余风险（登记 §10）: 攻击者完整复制技能仓库内容 + 同名目录仍可通过——
    代码即信任锚点，终极防线在 git 完整性/外部签名（本静态脚本内不可解）。"""
    if not skill_dir:
        return False
    sd = Path(skill_dir)
    # 序④-A / ECC-CB64985A85AD（2026-09-28）：从 feature / agent worktree 调用时目录名 = 分支名 /
    #   sha8（≠ 技能名）⟹ 原「名字必须恰为技能名」一刀切把**同仓合法 worktree** 判不可信
    #   （worktree 内全量验收 +9 假红）。正解 = 名字不符时先按 **git 权威视图**归一到该仓**主
    #   worktree**（复用 `_main_worktree`，禁第二实现）再校验；非 git / 非本仓 worktree ⟹ 归一返回
    #   "" ⟹ 退回**原样** ⟹ 下方名字 + 结构 + 内容三层判据**逐字不变**（空壳伪装防护不放松）。
    #   ⚠ 仅在**名字不符**时才付 git 归一开销 —— 正常路径（主 worktree）零额外子进程
    #   （`_skill_dir_trusted` 在 resolve-state 里每次 CLI 启动都跑，见 `_read_head` 的性能注）。
    if Path(sd).name != "spz-gatekeeper-r-sequence":
        _norm = _main_worktree(str(sd))
        sd = Path(_norm) if _norm else sd
        if Path(sd).name != "spz-gatekeeper-r-sequence":
            return False
    cli = sd / "gatekeeper-cli.sh"
    sk = sd / "SKILL.md"
    rc = sd / "scripts" / "gk_route_center.py"
    try:
        if not (cli.is_file() and sk.is_file() and rc.is_file()):
            return False
        if cli.stat().st_size == 0 or sk.stat().st_size == 0:
            return False
        cli_head = _read_head(cli)
        sk_head = _read_head(sk)
        return "SKILL_REPO_HASH" in cli_head and "spz-gatekeeper-r-sequence" in sk_head
    except OSError:
        return False


_HEAD_BYTES = 4000


def _read_head(p: Path, n: int = _HEAD_BYTES) -> str:
    """只读文件**头部 n 个字符**（判据只看前 4000 字符，勿整份读入再切片）。

    2026-09-23（ECC-13BE3E1A9B04 配套，实测驱动）：原式 `p.read_text()[:4000]` 先
    **整份读入**再切片 —— 而 `gatekeeper-cli.sh` 实测 600KB，且本判据在 `resolve-state`
    里每次都跑（CLI 每次启动都调它），在 `/mnt/c`(CIFS) 上实测整份读 ≈ 0.038s/次
    （strace 实证：该文件被 3 次 openat+read）。改限长读取只读 4000 字符 ⟹ 消除这笔
    跨 fs 往返，**判据逐字不变**（`open().read(n)` 与 `read_text()[:n]` 同为「前 n 个
    字符」，文本模式下按解码后字符计数，多字节字符行为一致）。
    """
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        return f.read(n)


def _skill_dir_env_trusted(skill_dir: str) -> bool:
    """env SKILL_DIR 完整信任判定（2026-09-02 红队 C 层 git 锚定修复，残余风险收窄）：
    env 是继承注入面——只凭内容特征，攻击者完整复制技能仓库 + 同名目录即可通过
    （信任锚点 = 代码自身）。追加 git 锚定层：
      自身路径（== DEFAULT_SKILL，脚本所在仓库）→ 天然可信（CLI 正常流：env 仅确认，
      不能把路由重定向到他处——CLI 本就自推导 SKILL_DIR，见 gatekeeper-cli.sh L58-72）
      其他路径 → 必须 git work tree + tracked 干净 + HEAD == 运行仓库 HEAD（干净同源副本）：
        注入恶意计划/state 需改 tracked 文件 → dirty 拒；或提交 → HEAD 漂移 vs 运行仓库 → 拒。
    返回 False → main() 忽略 env，回退 DEFAULT_SKILL。argv --skill-dir 不受限（调用方显式意图）。"""
    if not skill_dir:
        return False
    sd = Path(skill_dir)
    if not _skill_dir_trusted(skill_dir):  # 首层：内容特征（防低成本伪装）
        return False
    try:
        norm_sd = str(sd.resolve()).lower()
        norm_self = str(DEFAULT_SKILL.resolve()).lower()
    except OSError:
        return False
    if norm_sd == norm_self:
        return True
    try:
        head_self = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(DEFAULT_SKILL),
                                   capture_output=True, text=True, encoding="utf-8",
                                   errors="replace", timeout=10)
        head_cand = subprocess.run(["git", "rev-parse", "HEAD"], cwd=norm_sd,
                                   capture_output=True, text=True, encoding="utf-8",
                                   errors="replace", timeout=10)
        status = subprocess.run(["git", "status", "--porcelain"], cwd=norm_sd,
                                capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=10)
    except Exception:
        return False
    if head_self.returncode != 0 or head_cand.returncode != 0 or status.returncode != 0:
        return False
    if head_self.stdout.strip() != head_cand.stdout.strip():
        return False
    return status.stdout.strip() == ""


def resolve_worktree(skill_dir: str = "", main_repo_wsl: str = "", branch_lines=None) -> dict:
    """L3: 定位 feature worktree（对齐 CLI cmd_discover：git branch 在主仓库 cwd 跑）。
    返回 {"branch", "worktree", "r_phase", "detected"}。
    branch_lines 可注入（测试用）；缺省 → 实跑 git branch --list。"""
    mr = main_repo_wsl or _main_repo_wsl()
    prefix = os.environ.get("GATEKEEPER_WORKTREE_ROOT", "")
    if prefix:
        # 2026-09-02 L1-10 交叉审查漏洞 2 修复：env 前缀必须 ∈ DEV_WORKTREE_ROOTS
        # 白名单（防前缀污染：GATEKEEPER_WORKTREE_ROOT=/tmp/evil 构造假 worktree）。
        # 2026-09-02 红队漏洞 3 修复：字符串前缀白名单可被 `..` 段穿越逃逸
        # （root/../../evil 字符串前缀仍命中白名单，Path 归一化后逃逸出根目录）→ 先拒 `..` 段。
        segs = [s for s in _norm_path(prefix).split("/")]
        if ".." in segs:
            prefix = ""
        elif not any(_norm_path(prefix).lower().startswith(_norm_path(r).lower())
                     for r in DEV_WORKTREE_ROOTS):
            prefix = ""  # 非白名单前缀 → 忽略，回退自动探测
    # 2026-09-04 D3: 目录扫描兜底仅对"真实技能目录上下文"开放（skill_dir==DEFAULT_SKILL）
    # ——tmp/隔离 skill_dir 单测不受本机真实 worktree 树影响（保持 detected=False 语义）
    use_dirscan = (not prefix) and (_norm_path(skill_dir or str(DEFAULT_SKILL)).lower()
                                    == _norm_path(str(DEFAULT_SKILL)).lower())
    eff_prefix = prefix
    if not eff_prefix and not use_dirscan:
        for root in DEV_WORKTREE_ROOTS:
            # 原自动前缀（门卫 feature 根）：保持单仓库语义用于非真实上下文/旧路径
            cand = f"{_norm_path(root)}/spz_gatekeeper_project/feature/"
            if Path(cand).is_dir():
                eff_prefix = cand
                break
    # 2026-10-28（计划建树单一入口）：**计划声明的树优先** —— `apply-worktree --plan` 建
    #   `feature/<plan-stem>`，该名通常**不含** `r[0-9.]+` ⟹ 下方 feature 相位过滤会把它滤掉，
    #   探测只能落到「mtime 最新的别的 feature 树」⟹ 计划的 `state.worktree` 每次 discover
    #   都被改绑（实测：`--plan` 刚钉好，紧接着的 discover 探回 `feature/oss-r2-gkviews`）。
    #   规则：`GK_PLAN_FILE` 的 stem 与目录名**逐字相等** ⟹ 直接胜出（确定性，压过两条探测
    #   分支的 mtime/相位门）。该键只由 `cmd_discover --plan` 注入 ⟹ 未注入时本段 no-op（零回归）。
    _plan_stem = Path(os.environ.get("GK_PLAN_FILE") or "").stem
    if _plan_stem:
        for root in DEV_WORKTREE_ROOTS:
            base = Path(_norm_path(root))
            if not base.is_dir():
                continue
            try:
                cands = sorted(base.glob("*/feature/*"),
                               key=lambda p: p.stat().st_mtime, reverse=True)
            except Exception:
                continue
            for d in cands:
                if not d.is_dir() or d.name != _plan_stem:
                    continue
                try:
                    rel = d.relative_to(base).parts
                except ValueError:
                    continue
                if len(rel) == 3 and ".." not in rel:
                    return {"branch": "/".join(rel[1:]), "worktree": str(d),
                            "r_phase": "", "detected": True, "route": "feature"}
    if eff_prefix:
        # 显式/自动前缀 → 沿分支列表逐个校验 worktree 实存
        lines = branch_lines if branch_lines is not None else _git_branch_lines(mr)
        for line in lines:
            b = re.sub(r"^[* +]*", "", line).strip()
            if not b:
                continue
            # 对齐 CLI cmd_discover: wt="${FEATURE_PREFIX}$(basename "$b")"
            # _norm_path rstrip 尾斜杠 → 拼接补分隔符（防 'featurespz-gatekeeper'）
            name = Path(b).name
            if ".." in name:
                # 真实 git ref 禁 `..`（check-ref-format），仅注入 branch_lines 攻击面
                # 可携带 —— 拒（防 wt 拼接后逃逸 prefix 根）
                continue
            wt = f"{_norm_path(eff_prefix)}/{name}"
            if Path(wt).is_dir():
                m = re.search(r"r[0-9.]+", b)
                r_phase = (m.group(0).upper() if m else "")
                # route 恒 "feature"：显式/自动前缀路径本就是 feature 语义（与 dirscan 的
                # feature route 同义；2026-09-28 F7 窄切片统一返回键，未见形态 → ""）。
                return {"branch": b, "worktree": wt, "r_phase": r_phase,
                        "detected": True, "route": "feature"}
        return {"branch": "", "worktree": "", "r_phase": "", "detected": False, "route": ""}
    if use_dirscan:
        # 无 env 前缀 + 真实技能目录 → 2026-09-04 D3 跨仓库自动探测：
        # DEV_WORKTREE_ROOTS 内扫描全部 <repo>/feature/<branch> 实存目录
        # （门卫/spz2glb/zthl/batch8 等任一仓库 feature worktree），r[0-9.]+ 命中 +
        # mtime 最新优先（替换原硬编码 spz_gatekeeper_project 单仓库前缀——修复
        # "其他仓库 worktree 被漏检"）。`..` 段拒绝（防逃逸根）。
        # 2026-09-04 L3 接线（方案 A）：GK_WORKTREE_REPO env 限定仓库上下文——
        # cmd_discover 以其 cwd 仓库名（gatekeeper/skill/spz2glb 等 basename）注入，
        # 复刻原"只扫 cwd 所在仓库 worktree"语义（防跨仓库误绑：spz2glb-r7 最新时
        # 不应顶替门卫 discover）；无该 env → 保持全跨仓库扫描（route-all 语义）。
        repo_hint = os.environ.get("GK_WORKTREE_REPO", "").strip().lower().lstrip("/")
        # ⑤ worktree 落点归一（2026-09-25）：`GK_WORKTREE_CWD` = **调用方 cwd 路径**（路径，非名字）
        #   ⟹ 仓库段由 **git 权威视图**派生（该仓主 worktree 的目录名）。病象：调用方 cwd 常落在
        #   feature worktree 目录（`.trae/worktrees/<repo>/feature/<branch>`）或技能仓子目录 ⟹
        #   目录名 ≠ 仓库名 ⟹ 段名过滤恒不命中（静默漏检本仓 worktree）。与 `ECC-DEBCB4AC53C3`
        #   （git-workflow 以调用方 cwd 目录名当仓库段）同因同治。
        #   优先序：显式 `GK_WORKTREE_REPO`（名字，既有调用方覆盖语义**不变**）> cwd 派生 > 不设
        #   （全域扫描 = route-all 语义，逐字不变）。非 git / 查询失败 ⟹ 回退目录名（fail-safe）。
        if not repo_hint:
            _cwd_hint = os.environ.get("GK_WORKTREE_CWD", "").strip()
            if _cwd_hint:
                repo_hint = Path(_main_worktree(_cwd_hint) or _cwd_hint).name.lower()
        # 2026-09-28（F7 族，`ECC-5756951C56C8` 视野硬编码侧）：dirscan **认三 route**（白名单
        # = 模块级 `WORKTREE_ROUTES` 单一事实源）—— 原只扫 `*/feature/*` 且分支名须命中
        # `r[0-9.]+` ⟹ `standing/<slug>` 与 `agent/<family|session>/<sha8>` 对 L3 **完全不可见**
        # （detected=False）。r_phase 对非 feature route 取空：CLI 绑定门 `if [ -n "$r_phase" ]`
        # （r_phase 不在 plan phases 时**才**重置）⟹ 空 r_phase 让 standing/agent 被看见并绑定，
        # 而 feature 路由仍受相位门约束（原语义不破）。返回新增 `route` 键（未命中 → ""）。
        best = None
        for root in DEV_WORKTREE_ROOTS:
            base = Path(_norm_path(root))
            if not base.is_dir():
                continue
            for _route, _pat in WORKTREE_ROUTES:
                try:
                    cand_dirs = sorted(base.glob(_pat),
                                       key=lambda p: p.stat().st_mtime, reverse=True)
                except Exception:
                    continue
                for d in cand_dirs:
                    if not d.is_dir():
                        continue
                    # d = <root>/<repo>/<route>/… → 段视图（分隔符随平台，统一用 .parts
                    # 取段——防 Windows `\` 拆错）；branch 取 **repo 之后的全子路径**
                    # （agent route 有两段：`session/<sha8>`）。
                    try:
                        rel = d.relative_to(base).parts
                    except ValueError:
                        continue
                    if len(rel) < 3 or ".." in rel:
                        continue
                    name = rel[-1]
                    if repo_hint and rel[0].lower() != repo_hint:
                        continue
                    if _route == "feature":
                        m = re.search(r"r[0-9.]+", name)
                        if not m:
                            continue
                        r_phase = m.group(0).upper()
                    else:
                        r_phase = ""
                    try:
                        mt = d.stat().st_mtime
                    except OSError:
                        continue
                    if best is None or mt > best[1]:
                        best = ("/".join(rel[1:]), mt, r_phase, str(d), _route)
        if best:
            return {"branch": best[0], "worktree": best[3],
                    "r_phase": best[2], "detected": True, "route": best[4]}
    return {"branch": "", "worktree": "", "r_phase": "", "detected": False, "route": ""}


# ──────────────── L3 worktree「申请—分发」（F7 基座 T3，2026-09-22）────────────────
class RouteError(Exception):
    """L3 路由/申请失败（fail-loud，不静默回退）。"""


_FAMILY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


# ── 主 worktree 解析缓存（2026-10-29 · 提速①）────────────────────────────────
# 病象（实测）：`git -C <linked worktree> worktree list --porcelain` 在本机 25 个 worktree
#   注册下 ≈1.7s/次（CIFS 上要读 25 份 gitdir），而 `_main_worktree` 只用**首行**（该仓主
#   worktree）—— 对同一仓**恒定不变**。它却在 worktree 内每次 CLI 启动都被
#   `_skill_dir_trusted` 调用（目录名≠技能名 ⟹ 名字层不成立 ⟹ 付 git 归一开销）：
#   实测 worktree 内 CLI 1.9s vs 主树 0.6s，差额几乎全在这一刀。
# 缓存键 = `git rev-parse --path-format=absolute --git-common-dir`（0.16s；**同仓所有
#   worktree 同键**，与调用方落在仓内哪个子目录无关）；值 = 主 worktree 绝对路径。
# 失效面 = 值路径 `os.path.isdir` 不成立 ⟹ 重算。主 worktree **不随** worktree 增删而变
#   ⟹ 无需理会 `.git/worktrees/*` 变化；「全表 + 分支」判据仍在 `apply_worktree`（创建/复用
#   路径，低频），**不**进本缓存面（避免把两份权威视图混成一个）。
_MAIN_WT_CACHE_VERSION = "v1"
_MAIN_WT_MEMO: dict = {}


def _main_wt_cache_dir() -> Path:
    return Path(os.environ.get("GK_MAIN_WT_CACHE_DIR", "")
                or os.path.join(os.path.expanduser("~"), ".gatekeeper", "main-worktree-cache"))


def _git_common_dir(path: str) -> str:
    """`path` 所属仓库的 **common git dir**（同仓所有 worktree 同值）；非 git ⟹ `""`。

    用 `--path-format=absolute`（git ≥2.31）：主树裸跑时 git 返回相对 `.git`，绝对化后
    才可直接当缓存键（避免「相对路径随 cwd 漂移」造出多份同仓条目）。
    """
    try:
        p = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--path-format=absolute",
             "--git-common-dir"],
            capture_output=True, text=True, timeout=30)
    except Exception:  # noqa: BLE001
        return ""
    if p.returncode != 0:
        return ""
    out = (p.stdout or "").strip()
    # ⚠ 用 normpath 而非 realpath：realpath 在 /mnt/c(CIFS) 上实测 ~40ms/次（逐段解析）。
    #   此处只为把「主树裸跑时 git 返回的绝对 .git 路径」固定成字符串键 —— 无需解符号链接
    #   （同仓所有 worktree 的 `--git-common-dir` 输出本就逐字相同）。
    return os.path.normpath(out) if out else ""


def _main_wt_cache_file(common_dir: str) -> Path:
    import hashlib
    key = hashlib.sha256(("%s|%s" % (_MAIN_WT_CACHE_VERSION, common_dir))
                         .encode("utf-8")).hexdigest()
    return _main_wt_cache_dir() / (key[:40] + ".json")


def _main_wt_cache_read(p: Path, common_dir: str) -> str:
    """命中且值路径仍存在 ⟹ 返回；否则 `""`（一律回落到 git 权威视图重算）。"""
    try:
        with p.open(encoding="utf-8") as f:
            d = json.load(f)
    except Exception:  # noqa: BLE001
        return ""
    if not isinstance(d, dict) or d.get("common") != common_dir:
        return ""
    main = d.get("main")
    if isinstance(main, str) and main and os.path.isdir(main):
        return main
    return ""


def _main_wt_cache_write(p: Path, common_dir: str, main: str) -> None:
    """原子写（tmp + os.replace）；失败静默（缓存是加速面，不是正确性面）。"""
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".%d.tmp" % os.getpid())
        with tmp.open("w", encoding="utf-8") as f:
            json.dump({"v": _MAIN_WT_CACHE_VERSION, "common": common_dir, "main": main}, f)
        os.replace(tmp, p)
    except Exception:  # noqa: BLE001
        pass


def _main_worktree(path: str = "") -> str:
    """`path` 所属 git 仓的**主 worktree** 绝对路径（git 权威视图，非路径推算）。

    2026-09-23（**ECC-DEBCB4AC53C3** 修复）：从 **feature worktree** 内调用 `apply-worktree`
    时有两处同源误算 ——
      ① `DEFAULT_SKILL.parent` 是 `…/feature/…` 而非部署根 `.trae/skills` ⟹ 兄弟插件
         （git-workflow）解析不到（实测 `git-workflow 入口不可得`）；
      ② git-workflow 以**调用方 cwd 的目录名**当仓库段 ⟹ 落
         `…/worktrees/<当前 worktree 目录名>/agent/session/<sha8>`（实测）。
    两处的正解都是「该仓的**主 worktree**」。`git worktree list --porcelain` 首条即主 worktree
    ⟹ 用**权威视图**，不猜父目录层数。非 git / 查询失败 ⟹ `""`（调用方回退既有行为）。

    ── 现状 / 缺口登记（2026-09-26 只读取证，**不改语义**）──────────────────────────────
    · **已修**：本函数（基址）+ `ECC-DEBCB4AC53C3` 的 feature-worktree 误算两处。
    · **缺口（修）**：`agent/session/<sha8>` 的**基址**仍有第二事实源 —— git-workflow 以**调用方 cwd
      的目录名**当仓库段（见上文 ②），非经本函数时仍可落错形态（C 错形态），并污染 dirscan 候选集。
      锚：`ECC-D15C62FFF34A`（worktree 面 RC2）/ `ECC-A91DC4562198`。
    · **缺口（并发）**：会话 worktree 有，**会话 state 无** —— 未声明 `state_domain` 的计划下，
      并发会话（hook / zthl-adapter / coding+runtime）**共享 base `.gatekeeper.state`** ⟹ 同一
      `<state>.lock` 上串行化至 `LOCK_TIMEOUT`。锚：`ECC-46C22B11AD85`（state 面 RC3）+ §4.13.30。

    ── 缓存（2026-10-29 · 提速①）────────────────────────────────────────────────
    见上方 `_MAIN_WT_*` 段：键 = 本仓 common git dir（0.16s），值 = 首行主 worktree。
    语义**逐字不变**：仍只在「非 git / 查询失败」时返 `""`（调用方 fail-closed），
    仍以 `git worktree list --porcelain` 为**唯一**权威视图（缓存只是它的跨进程记忆，
    值路径消失即失效重算）。调用方看到的返回值与修前完全一致。
    """
    base = str(path or DEFAULT_SKILL)
    common = _git_common_dir(base)
    if not common:                       # 非 git / 失败 ⟹ 原语义（""，不猜）
        return ""
    if common in _MAIN_WT_MEMO:
        return _MAIN_WT_MEMO[common]
    cf = _main_wt_cache_file(common)
    hit = _main_wt_cache_read(cf, common)
    if hit:
        _MAIN_WT_MEMO[common] = hit
        return hit
    try:
        p = subprocess.run(
            ["git", "-C", base, "worktree", "list", "--porcelain"],
            capture_output=True, text=True, timeout=30)
        if p.returncode != 0:
            return ""
        for ln in (p.stdout or "").splitlines():
            if ln.startswith("worktree "):
                main = ln[len("worktree "):].strip()
                _MAIN_WT_MEMO[common] = main
                _main_wt_cache_write(cf, common, main)
                return main
    except Exception:  # noqa: BLE001
        return ""
    return ""


_TRASH_DIRNAME = ".gk-trash"


def trash_dir(skill_dir: str = "") -> str:
    """回收区（隔离区）路径 —— **单一事实源**（finding `ECC-82CC385C121E`）。

    2026-09-24 实测**双源**：
      · `pre_tool_hook` 取 `SKILL_DIR.parent.parent/.gk-trash`（= `.trae/.gk-trash`，
        **也是唯一被实际写入的那个**）；
      · `gk_worktree_reclaim.reclaim` 取 `os.path.dirname(main_repo)/.gk-trash`
        ⟹ 随 `--repo` **漂移**（CLI 接线传的是 SKILL_DIR ⟹ 算成 `.trae/skills/.gk-trash`，
        实测**不存在**；从 worktree 内调用时又算成 `…/feature/.gk-trash`）。
    ⟹ 同一个「回收区」有**多处落点**，同一个东西会被归档到不同地方。

    定于一尊的判据 = **技能仓的祖父目录**（`.trae/skills/<skill>` ⟹ `.trae`）：与 hook
    既有落点**逐字一致**（不改既有归档位置，历史归档仍找得回），且仍在**任何 git 仓之外**。

    调用方须知：`skill_dir` 是**起点**，不是最终判据 —— 它若指向一个 **feature worktree**，
    先经 `_main_worktree` **归一**到该仓的**主 worktree**，再取祖父。故无论从主树还是
    worktree 内调用，落点**唯一**。（实测：worktree 内跑 CLI 会算出
    `.trae/worktrees/spz-gatekeeper-r-sequence/.gk-trash` —— 又一个「第二落点」。）
    """
    base = str(skill_dir or os.environ.get("SKILL_DIR", "") or DEFAULT_SKILL)
    if not base:
        return ""
    # 归一：用 git 权威视图，**不猜父目录层数** —— 与 `_git_workflow_entry` 同一手法
    #   （见 `ECC-DEBCB4AC53C3`）。非 git / 查询失败 ⟹ `_main_worktree` 返回 ""，保持原样。
    base = _main_worktree(base) or base
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(base))), _TRASH_DIRNAME)


def _git_workflow_entry(skill_dir: str = "") -> str:
    """git-workflow 入口路径（**从 manifest 的 builtin url 派生，禁硬编码**）。

    2026-09-23（ECC-A91DC4562198 收编，用户裁定「门禁→git-workflow + 保留校验」）：
    worktree 的**创建**归口 git-workflow（唯一入口）；本层只保留**消费侧校验**
    （白名单 / `..` 段拒绝 / family token 正则）作为**后置条件**，不下放、不废除。
    """
    try:
        # 部署/单测缝合：显式指定入口（单测在 worktree 内导入本模块时 `DEFAULT_SKILL` 是该
        # worktree ⟹ 找不到兄弟 `git-workflow`；生产路径经 CLI 调用，`__file__` 即真 SKILL_DIR）。
        _ov = os.environ.get("GK_GIT_WORKFLOW_ENTRY", "")
        if _ov:
            return _ov if os.path.isfile(_ov) else ""
        sys.path.insert(0, os.path.join(str(DEFAULT_SKILL), "scripts"))
        from gk_plugin_manifest import get_manifest
        url = str((get_manifest("git-workflow") or {}).get("url") or "")
        mark = "${SKILL_DIR}/../"
        if "builtin:" in url and mark in url:
            rel = url.split("builtin:", 1)[1].replace(mark, "", 1)
            # ECC-DEBCB4AC53C3：**基址候选 = 调用方 skill_dir → 该仓主 worktree**。
            # 在 worktree 内时前者的 `.parent` 不是部署根 ⟹ 退到主 worktree（权威视图）。
            base = str(skill_dir or DEFAULT_SKILL)
            for cand in (base, _main_worktree(base)):
                if not cand:
                    continue
                p = Path(cand).parent / rel
                if p.is_file():
                    return str(p)
            return ""
    except Exception:
        return ""
    return ""


def apply_worktree(main_repo_wsl: str, finding_id: str, family: str,
                   root: str = "", plan_stem: str = "") -> dict:
    """按 finding 交付一个专用 feature worktree（用户公理 A2：唯一合法来源 = 本中枢）。

    - `family` 须匹配 `^[A-Za-z0-9][A-Za-z0-9._-]*$`（拒 `/`、`\\`、`..`、前导点 → 防路径逃逸）
    - root 须 ∈ `DEV_WORKTREE_ROOTS`（复用 resolve_worktree 的白名单口径，禁第二份校验）
    - 同 finding 已建 → 复用（幂等）；目录存在但分支不符 → RouteError（不覆盖、不静默）
    - 任一步失败 → RouteError（fail-loud，绝不回退主仓）

    `plan_stem` 非空 ⟹ **计划驱动**：分支 = `feature/<plan_stem>`（对齐 `resolve_worktree` 的
    `<root>/<repo>/feature/<basename(branch)>` 目录约定，discover 方能认回该树）；其余
    白名单 / 复用扫描 / 委托 git-workflow / 后置校验与 finding 驱动**逐字共用**（禁第二实现）。
    """
    import hashlib

    if not _FAMILY_RE.match(family or ""):
        raise RouteError("非法 family token: " + repr(family))
    # ECC-DEBCB4AC53C3 ②：**仓库 = 该仓主 worktree**（git 权威视图，一处归一覆盖下方
    #   复用扫描 `git worktree list` 与创建委托 `cwd=`）。从 worktree 内调用时若沿用调用方
    #   路径，git-workflow 会以**当前 worktree 的目录名**当仓库段 ⟹ 落
    #   `…/worktrees/<worktree 目录名>/…`（实测）。非 git / 查询失败 ⟹ 保持原样。
    main_repo_wsl = _main_worktree(main_repo_wsl) or main_repo_wsl
    base_root = root or os.environ.get("GATEKEEPER_WORKTREE_ROOT", "")
    if not base_root:
        raise RouteError("GATEKEEPER_WORKTREE_ROOT 未设置（须 ∈ DEV_WORKTREE_ROOTS）")
    nb = _norm_path(base_root)
    if ".." in nb.split("/") or not any(
            nb.lower().startswith(_norm_path(r).lower()) for r in DEV_WORKTREE_ROOTS):
        raise RouteError("worktree root 不在白名单内: " + base_root)
    short = hashlib.sha256((finding_id or "").encode()).hexdigest()[:8]
    branch = ("feature/%s" % plan_stem) if plan_stem else ("agent/%s/%s" % (family, short))
    # 复用优先（2026-09-23 实测补）：该分支若**已在某 worktree 检出** ⟹ 直接复用。
    # 必要场景（收编迁移）：收编前创建的旧**平面**路径 `agent_<family>_<short>` 仍占着该分支，
    # 而委托后 git-workflow 算出的**嵌套**路径不同 ⟹ `git worktree add` 会
    # `fatal: '<branch>' is already checked out at '<old path>'`（实测）。
    # 判据源 = `git worktree list --porcelain`（git 自身的权威视图，非第二份路径推算）。
    try:
        _wl = subprocess.run(["git", "-C", main_repo_wsl, "worktree", "list", "--porcelain"],
                             capture_output=True, text=True, timeout=30).stdout or ""
    except Exception:
        _wl = ""
    for _blk in _wl.split("\n\n"):
        _w = _b = ""
        for _ln in _blk.splitlines():
            if _ln.startswith("worktree "):
                _w = _ln[len("worktree "):].strip()
            elif _ln.startswith("branch "):
                _b = _ln[len("branch "):].strip().replace("refs/heads/", "")
        if _w and _b == branch:
            _nw = _norm_path(_w)
            if ".." not in _nw.split("/") and any(
                    _nw.lower().startswith(_norm_path(r).lower()) for r in DEV_WORKTREE_ROOTS):
                return {"ok": True, "worktree": _nw, "branch": branch,
                        "reused": True, "created": False}
            break
    # ── 收编（2026-09-23，ECC-A91DC4562198）：创建**委托** git-workflow，禁第二实现 ──
    # 原实现裸调 `git worktree add` ⟹ 门禁技能内自建**第二套** worktree 机制（用户质询点名）。
    # 现：唯一创建入口 = `git-workflow worktree create --from <ref> --json`；返回单行 JSON 机读。
    # **校验不下放**：family token 正则（上方）/ root 白名单 + `..` 段拒绝（上方）/
    #   返回路径须落在 `DEV_WORKTREE_ROOTS` 内（下方**后置条件**）。
    gw = _git_workflow_entry()
    if not gw:
        raise RouteError("git-workflow 入口不可得（收编后 worktree 创建的唯一入口）")
    env = dict(os.environ)
    # git-workflow 的 root 语义 = **不含 repo 段**的公共根；仅在调用方显式给 `root` 时透传，
    # 否则由 git-workflow 读自身配置（`worktree.base_path`，已对齐门禁白名单根）。
    _gw_env_root = os.environ.get("GIT_WORKFLOW_WORKTREE_ROOT", "")
    if root and not _gw_env_root:
        env["GIT_WORKFLOW_WORKTREE_ROOT"] = _norm_path(root)
    p = subprocess.run(["bash", gw, "worktree", "create", branch,
                        "--from", "HEAD", "--json"],
                       cwd=main_repo_wsl, capture_output=True, text=True,
                       timeout=180, env=env)
    line = ""
    for _ln in (p.stdout or "").splitlines():
        if _ln.strip().startswith("{"):
            line = _ln.strip()
            break
    if p.returncode != 0 or not line:
        raise RouteError("git-workflow worktree create 失败（rc=%s）: %s"
                         % (p.returncode, ((p.stderr or p.stdout or "").strip()[:300])))
    try:
        resp = json.loads(line)
    except ValueError as e:
        raise RouteError("git-workflow --json 输出不可解析: %s" % e)
    wt = str(resp.get("worktree") or "")
    if not wt or not os.path.isdir(wt):
        raise RouteError("git-workflow 未返回有效 worktree: " + line[:200])
    # 后置条件（门禁保留的消费侧校验）：返回路径必须落在 DEV_WORKTREE_ROOTS 白名单内。
    nw = _norm_path(wt)
    if ".." in nw.split("/") or not any(
            nw.lower().startswith(_norm_path(r).lower()) for r in DEV_WORKTREE_ROOTS):
        raise RouteError("git-workflow 返回的 worktree 不在白名单内: " + wt)
    if str(resp.get("branch") or "") != branch:
        raise RouteError("git-workflow 返回分支不符（期望 %s，得 %s）"
                         % (branch, resp.get("branch")))
    return {"ok": True, "worktree": nw, "branch": branch,
            "reused": bool(resp.get("reused")), "created": bool(resp.get("created"))}


def apply_worktree_plan(main_repo_wsl: str, plan_file: str, skill_dir: str = "",
                        root: str = "", dry_run: bool = False) -> dict:
    """**计划驱动建树**（2026-10-28）：`feature/<plan-stem>`。

    缺口（实测）：`discover --plan <p>` 只**探测**已有树（`resolve_worktree`），探不到就回落
    `worktree=$SKILL_DIR`；`apply-worktree` 又只有 finding / code-fix / bind 模式 ⟹ 计划建树
    **没有正路** ⟹ agent 手搓 `git worktree add` + `cp`（owner 斥为「奇怪绕路」）。

    本函数把「计划 → 树」收敛成一条入口：
      · 计划解析 = `resolve_plan`（META 金字塔，单源）；`worktree_needed=false` ⟹ 具名拒建；
      · 目标仓 = `META.target_repo`（外仓一等支持，经 `resolve_repo`）→ 该仓**主 worktree**；
      · 建/复用 = `apply_worktree(..., plan_stem=…)`（白名单 / 复用扫描 / 委托 git-workflow /
        后置校验**全部共用**，禁第二实现）；
      · 域 state / plan 指针 / `state.worktree` 由调用方（CLI）走 `discover --plan --build-state`。
    """
    rp = resolve_plan(plan_file, skill_dir, main_repo_wsl)
    pf = str(rp.get("plan_file") or "")
    if not pf:
        raise RouteError("计划未找到（resolve_plan 金字塔无命中）: " + repr(plan_file))
    meta = rp.get("meta") or {}
    if str(meta.get("worktree_needed") or "").strip().lower() == "false":
        raise RouteError("计划 META 声明 worktree_needed=false ⟹ 不建树: " + pf)
    repo = main_repo_wsl or _main_repo_wsl()
    tgt = str(meta.get("target_repo") or "").strip()
    if tgt:
        r = resolve_repo(tgt, skill_dir, main_repo_wsl)
        if r.get("path") and os.path.isdir(str(r["path"])):
            repo = str(r["path"])
    stem = Path(pf).stem
    out = {"ok": True, "plan_file": pf, "branch": "feature/" + stem,
           "meta": {k: meta.get(k, "") for k in _META_FIELDS}}
    if dry_run:
        out.update({"dry_run": True, "worktree": "", "created": False, "reused": False})
        return out
    made = apply_worktree(repo, "plan:" + stem, "plan", root=root, plan_stem=stem)
    out.update(made)
    return out


def meta_state_domain(plan_file: str = "", skill_dir: str = "") -> str:
    """计划 META 声明的 `state_domain`（无 plan_file / 未声明 → 空串）。

    质询 F1 修订（2026-09-15）：`resolve-state` 子命令此前**不读 META**，故 CLI 侧
    （gatekeeper-cli.sh 启动块）永远拿不到域 token ⟹ 1b 步在 CLI 链上是死代码。
    单一事实源 = L1 `resolve_plan` 的 META 解析（禁第二份 META 读取实现）。

    ── 现状 / 缺口登记（2026-09-26 只读取证，**不改语义**）──────────────────────────────
    · **已修**：本函数（子命令读 META）+ `derive_state_domain`（断点①：`target_repo` ↔ `state_domain`
      的缺失推导）。
    · **缺口（核心）**：推导**刻意不接进路由**（理由见 `derive_state_domain` docstring：推导域 state
      不存在时会 fail-closed 把 20+ 份 `target_repo: skill` 计划的启动块打成 exit 1）⟹ 声明仍是
      **opt-in**：09-13～09-22 十二份计划**仅 1 份**声明 `state_domain`（实测）⟹ 其余全落 base。
    · **后果（实测）**：本计划（`review-runtime-subplan`）名下**并存两套台账** —— base 113 条 vs
      plan-basename 域 138 条，**id 交集仅 21**、6 条同 id 状态相反 ⟹ 「落哪套」**无单点裁决**。
    · 锚：`ECC-F2E2F9E07AC2`（断点①/②）/ `ECC-46C22B11AD85`（RC3）/ §4.13.30 一、五。
    """
    if not plan_file:
        return ""
    try:
        return str((resolve_plan(plan_file, skill_dir).get("meta") or {})
                   .get("state_domain") or "").strip()
    except Exception:
        return ""


def derive_state_domain(meta: dict, plan_file: str = "") -> str:
    """未声明 `state_domain` 时按 `<target_repo>.<plan-basename>` **推导**（声明优先）。

    2026-09-26（ECC-F2E2F9E07AC2 断点①）：`target_repo`(L2) 与 `state_domain`(L4 1b) 此前
    **并列但无推导**（`_META_FIELDS` 仅并排列出）⟹ 「目标仓=X」推不出「state 域=X」。本函数即
    该缺失的**单源推导**；消费方 = `gk_plan_lint.check_meta` / `calibration_from_route`
    （把「可推导域」报给作者以驱动声明），**刻意不接进路由** —— `meta_state_domain` 仍只回已声明值：
    推导域 state 不存在时若强行路由会 `STATE_DOMAIN_MISSING` fail-closed，把 `target_repo: skill`
    类计划（docs/plans 20+ 处）的启动块打成 exit 1 ⟹ CLI 全命令失效。
    token 合法性**复用** `gk_finding._DOMAIN_TOKEN_RE`（单一事实源，禁第二套）⟹ 非法形态一律不产出。
    """
    declared = str((meta or {}).get("state_domain") or "").strip()
    if declared:
        return declared
    repo = str((meta or {}).get("target_repo") or "").strip()
    stem = Path(plan_file).stem if plan_file else ""
    if not repo or not stem:
        return ""
    try:
        from gk_finding import _DOMAIN_TOKEN_RE as _re_dom
    except Exception:
        return ""
    token = repo + "." + stem
    return token if _re_dom.match(token) else ""


def derive_state_seed(plan_file: str = "", skill_dir: str = "", state_file: str = "",
                      main_repo_wsl: str = "") -> dict:
    """从计划 META **派生域 state 初值骨架**（元数据中枢派生；§18.2 c2，2026-10-04）。

    病因：域 state 此前**无创建路径**（`resolve_domain_state` 纯读 fail-closed），且 `discover` 的
    骨架是**硬编码 IDLE** heredoc ⟹ 对有活动相位的计划，裸 IDLE 会被各类门拦。本函数即**中枢派生**：
      · `domain`  = META `state_domain` 声明，缺则 `derive_state_domain`（`<target_repo>.<plan-stem>`）；
      · `r_phase`/`stage` **取计划 META**（`project_type=standard` → `STAGE_0`；其余 → 首相位）；
      · `branch`/`worktree` 取 `resolve_worktree`（缺 → `skill_dir`）；
      · 骨架形状对齐 `cmd_discover` 的**规范骨架**（r_phase/stage/branch/worktree/gate_data/
        monitor_scores/history）—— **非**新造 schema。
    计划无 `phases` / 推不出 `domain` ⟹ 返回 `{"error": ...}`（fail-loud，**不产 IDLE**）。
    单一事实源 = L1 `resolve_plan`（禁第二份 META 解析）。
    """
    rp = resolve_plan(plan_file, skill_dir)
    meta = rp.get("meta") or {}
    phases = str(meta.get("phases") or "").split()
    if not phases:
        return {"error": "SEED_NO_PHASES", "plan_file": rp.get("plan_file", "")}
    domain = meta_state_domain(plan_file, skill_dir) or derive_state_domain(meta, plan_file)
    if not domain:
        return {"error": "SEED_NO_DOMAIN", "plan_file": rp.get("plan_file", "")}
    first_phase = phases[0]
    ptype = str(meta.get("project_type") or "standard")
    stage = "STAGE_0" if ptype == "standard" else first_phase
    wt = resolve_worktree(skill_dir, main_repo_wsl)
    branch = wt.get("branch") or ""
    worktree = wt.get("worktree") or skill_dir or str(DEFAULT_SKILL)
    r_phase = wt.get("r_phase") or first_phase
    seed = {
        "r_phase": r_phase or None,
        "stage": stage,
        "branch": branch or None,
        "worktree": worktree or None,
        "gate_data": {},
        "monitor_scores": {},
        "history": [],
    }
    return {"domain": domain, "seed": seed, "plan_file": rp.get("plan_file", ""),
            "warnings": rp.get("warnings", [])}


def is_foreign_repo(repo_name: str, skill_dir: str = "") -> bool:
    """`target_repo` 是否指向**他仓**（非技能本体）—— 自指判定**复用** `resolve_repo` 单源。

    2026-09-26（ECC-F2E2F9E07AC2 断点②）：门须能区分「计划就是技能自维护（`target_repo: skill`）」
    与「计划指向他仓」（跨仓 finding ⟹ 必须有归属域）。`skill` 及其别名
    `spz-gatekeeper-r-sequence` ⟹ False；其余（含**未知名**，`resolve_repo` 返回 error）⟹ True；
    空 ⟹ False（无 target_repo 声明即无跨仓语义）。
    """
    name = (repo_name or "").strip()
    if not name:
        return False
    r = resolve_repo(name, skill_dir)
    return (r.get("repo") or r.get("alias_of") or "") != "skill"


# ────────────────────────── L4 state 解析链 ──────────────────────────
def resolve_state_cli(skill_dir: str = "", state_file: str = "", plan_pointer: str = "",
                      plan_override: str = "", plan_file: str = "", derive_domain: bool = False,
                      extra_roots=None, domain: str = ""):
    """`resolve-state` 子命令的**唯一实现**（`main()` 分支与 `gk_worker` 的 op 共用）。

    2026-10-29（A7 接线）：原本这段 `_dom_plan` 推导写在 `main()` 的 `elif cmd == "resolve-state"`
    分支里。worker 要提供等价的快路，若把推导再抄一份 ⟹ 两条路径迟早漂移（fast path 静默
    改变域路由）。故抽到模块级函数，双方**同一实现**。

    `derive_domain`：`True` 时把 env `GK_PLAN_FILE` 声明的会话计划也作 domain 来源
    （argv 显式 plan 仍优先）。
    """
    _dom_plan = plan_override or plan_file
    if not _dom_plan and derive_domain:
        _dom_plan = os.environ.get("GK_PLAN_FILE", "")
    return resolve_state(skill_dir, state_file, plan_pointer,
                         extra_roots=extra_roots or None,
                         domain=domain or meta_state_domain(_dom_plan, skill_dir))


def flat_route(d) -> str:
    """`resolve-state` 回包 → 启动块用的**12 字段竖线串**（单源，2026-10-29 A7 接线）。

    这段格式化原先是 `gatekeeper-cli.sh` 里的一段内联 `python3 -c`（`_gkr_parsed`）。A7 让
    worker 直接返回成品串以省掉一次 python 冷启 ⟹ 必须与那段内联**逐字等价**，故集中到本函数，
    并用 `test_gk_worker_fastpath.py::test_flat_route_matches_cli_inline_payload` 对拍。

    ⚠ 与内联版一致：`expected` 等字段若为 `None`，`'|'.join` 会抛 TypeError ⟹ 内联版当年
    会把 `_gkr_parsed` 置空并走 WARN 分支（`warning` 字段本身已由 `or ''` 兜底）。
    本函数**不额外兜底**（保持逐字等价），异常由调用方（worker op / 测试）按失败处理。
    """
    d = d if isinstance(d, dict) else {}
    return "|".join([str(d.get('corrected', False)), d.get('expected', ''),
                     str(d.get('conflict', False)), (d.get('warning') or '').replace('|', '/'),
                     d.get('source', ''), (d.get('error') or ''), str(d.get('own', '')),
                     str(d.get('pointer', '')), str(d.get('pointer_followed', False)),
                     str(d.get('pointer_reason', '')), str(d.get('pointer_plan', '')),
                     str(d.get('pointer_domain', ''))])


def resolve_state(skill_dir: str = "", state_file: str = "",
                  plan_pointer: str = "", extra_roots=None, domain: str = "") -> dict:
    """L4: state 路由判定（域解析 → plan 指针 → worktree 匹配 → 归属校验 → safety_net）。
    实现迁自 gk_state_route.resolve_state（唯一实现点，本层委托）。
    2026-09-02 C 层修复: skill_dir 空 → 兜底 DEFAULT_SKILL（env 被拒后防相对路径落 CWD）。
    2026-09-04: extra_roots（跨仓库就近 state 根）透传；None → 读
    env GATEKEEPER_STATE_ROOTS，仍空 → 交 gk_state_route 自动保守扩根。
    2026-09-15（A6-P2 接线）: `domain` = 计划声明的 META.state_domain（或 CLI `--domain`）
    → 交 L4 1b 步解析 `.gatekeeper.state.<token>`；空 = 不触发（行为不变）。"""
    from gk_state_route import resolve_state as _rs
    sd = skill_dir or str(DEFAULT_SKILL)
    if extra_roots is None:
        # env GATEKEEPER_STATE_ROOTS 分隔符按平台取 os.pathsep
        # （nt=';'，posix=':'——Windows 盘符含 ':' 不能作分隔符，2026-09-04）
        extra_roots = [r for r in os.environ.get("GATEKEEPER_STATE_ROOTS", "").split(os.pathsep)
                       if r]
    # ③ 单源（`ECC-1EC0E0732F0D`，挑战3）：**指针选择**也在此完成 —— 启动块不再自行判定。
    #   顺序：① `select_plan_pointer` 定「读哪个指针 + 是否跟随」（TTL / strict / 命令对账 /
    #   域 kill switch 全在其内部）→ ② `resolve_state` 按**已选定**的指针解析。
    #   未跟随（stale / 对账不符 / strict / 域关）⟹ 传空指针 ⟹ 回落默认 state（与既有 bash 逐字一致）。
    #   `own` 的显式态判据 = env `STATE_FILE_EXPLICIT`（**不是** `bool(state_file)` —— 非显式时启动块
    #   也会把「worktree 归主树后的默认落点」传进来，那不该被当成显式态）。
    # 2026-10-10（ECC-7FF904ADF22C · L1 惰性化）：显式态**单点判定** —— 下方 `_spp` 与
    #   `_rs` 同源消费（避免两处各读一次 env 而漂移）。
    _sfe = os.environ.get("STATE_FILE_EXPLICIT", "0") == "1"
    try:
        from gk_state_route import select_plan_pointer as _spp
        _pp = _spp(
            sd, session_id=os.environ.get("GK_SESSION_ID", ""),
            cmd_target_plan=os.environ.get("GK_CMD_TARGET_PLAN", ""),
            env_pointer=os.environ.get("PLAN_POINTER", ""),
            strict=os.environ.get("GK_PLAN_POINTER_STRICT", "0") == "1",
            domain_route=os.environ.get("GK_STATE_DOMAIN_ROUTE", "1"),
            state_file_explicit=_sfe)
    except Exception:  # noqa: BLE001 — 边界：拿不到指针面时退化为「不跟随」（fail-safe）
        _pp = {"pointer": "", "own": "", "followed": False, "reason": "", "plan": "",
               "domain": ""}
    _eff_pointer = plan_pointer or (_pp.get("pointer", "") if _pp.get("followed") else "")
    # `pointer_authoritative=True`：`_eff_pointer` 是**本门面经 `select_plan_pointer` 的定论**
    # （含「判定不跟随 ⟹ 空」）⟹ 禁止 `gk_state_route.resolve_state` 再回落全局 `.gatekeeper.plan`
    # （否则「有身份但本会话无绑定 ⟹ 不采纳全局」/「域 kill switch=0 ⟹ 不跟随域化指针」等判定
    # 会被 step 1 的 `or 全局指针` 静默推翻 —— ③ 单源必须让**判定**成为唯一事实源）。
    out = _rs(sd, state_file, _eff_pointer, extra_roots=extra_roots or None, domain=domain,
              pointer_authoritative=True, state_file_explicit=_sfe)
    out["own"] = _pp.get("own", "")
    out["pointer"] = _pp.get("pointer", "")
    out["pointer_plan"] = _pp.get("plan", "")
    out["pointer_domain"] = _pp.get("domain", "")
    out["pointer_followed"] = bool(_pp.get("followed"))
    out["pointer_reason"] = _pp.get("reason", "")
    return out


# ────────────────────────── L5 窄任务查询 ──────────────────────────
def resolve_narrow(state_file: str = "", task: str = "",
                   check_poison: bool = False, check_schema: bool = False) -> dict:
    """L5: 窄任务路由（tier）/ 投毒 / schema 三合一。实现迁自 gk_narrow_route（委托）。"""
    from gk_narrow_route import poison_check, route, validate_narrow_tasks
    if check_poison:
        hits = poison_check(state_file)
        return {"poison": bool(hits), "hits": hits, "exit": 3 if hits else 0}
    if check_schema:
        issues = validate_narrow_tasks(state_file)
        return {"schema_valid": not issues, "issues": issues, "exit": 4 if issues else 0}
    return {"tier": route(state_file, task or ""), "matched": bool(route(state_file, task or ""))}


# ────────────────────────── route-all 统一入口 ──────────────────────────
def _phase_norm(p) -> str:
    """r_phase / phases 首段归一（大小写折叠、去空白）。"""
    s = re.sub(r"\s+", " ", (str(p or "")).strip())
    first = s.split(" ")[0] if s else ""
    return first.upper()


def calibration_from_route(r: dict) -> dict:
    """2026-09-04 (B): 对【既有】route_all 结果做五层一致性断言（不重跑路由——重跑会丢
    plan_file 等调用上下文，导致校准评估到另一计划，2026-09-04 实测）。"""
    checks = []
    meta = r.get("L1_plan", {}).get("meta", {}) or {}
    wt = r.get("L3_worktree", {}) or {}
    st = r.get("L4_state", {}) or {}
    stf = r.get("state_file", "") or st.get("expected", "")
    # repo ↔ worktree
    repo_p = (r.get("L2_repo", {}) or {}).get("path", "")
    wt_p = wt.get("worktree", "")
    if repo_p and wt_p and wt.get("detected"):
        repo_name = Path(repo_p).name
        if repo_name and (Path(wt_p).name == repo_name
                          or (f"/{repo_name}/" in _norm_path(wt_p))
                          or (f"\\{repo_name}\\" in str(wt_p))):
            checks.append({"item": "repo_worktree", "status": "PASS",
                           "evidence": f"{repo_name} ↔ {wt_p}"})
        else:
            checks.append({"item": "repo_worktree", "status": "FAIL",
                           "evidence": f"L2 repo={repo_p} 与 L3 worktree={wt_p} 目录归属不一致"})
    elif repo_p and wt_p:
        checks.append({"item": "repo_worktree", "status": "INFO",
                       "evidence": f"repo={repo_p} worktree未检出(或未启用)"})
    # phase 三角链（2026-09-04 B 修正：plan 声明多相位如 "R7 R7.1" 时，worktree/state 处任一
    # 声明相位即一致——校准目标是"运行相位 ∈ 计划声明域"，非机械等于首相位；worktree↔state 仍须相等）
    # ⚠ 2026-09-28（`ECC-F766225799CC`）**试改按「相位族」比较已回退**：既有负臂
    #   `test_phase_chain_mismatch_fail`（state=R7 vs plan=R7.1 须 FAIL）与
    #   `test_phase_chain_outside_declared_set`（R7.5 ∉ {R7,R7.1} 须 FAIL）证明
    #   「plan phases = **枚举集**」是**设计意图**（不是假阳性）⟹ 族比较会放松设计判据。
    #   该 finding 的闭法应在**声明侧**（计划 META.phases 须列出实际会走到的子相位），非放松本判据。
    plan_ph = (str(meta.get("phases") or "")).split()
    plan_set = {_phase_norm(t) for t in plan_ph if _phase_norm(t)}
    ph = _phase_norm(plan_ph[0]) if plan_ph else ""
    wt_ph = _phase_norm(wt.get("r_phase", ""))
    st_ph = _phase_norm(st.get("expected") and _state_phase(st.get("expected")) or "")
    mism = []
    if plan_set:
        for lbl, val in (("worktree", wt_ph), ("state", st_ph)):
            if val and val not in plan_set:
                mism.append(f"{lbl}={val} ∉ plan phases [{', '.join(sorted(plan_set))}]")
    if wt_ph and st_ph and wt_ph != st_ph:
        mism.append(f"worktree={wt_ph} vs state={st_ph}")
    if mism:
        checks.append({"item": "phase_chain", "status": "FAIL", "evidence": "; ".join(mism)})
    elif ph or wt_ph or st_ph:
        checks.append({"item": "phase_chain", "status": "PASS",
                       "evidence": f"plan=[{', '.join(sorted(plan_set))}] worktree={wt_ph} state={st_ph}"})
    else:
        checks.append({"item": "phase_chain", "status": "SKIP",
                       "evidence": "无 r_phase 可校准"})
    # state_domain 声明绑定（2026-09-04 B + A 收敛：worktree 须声明对应 state 域）
    # worktree_needed=true 的计划必须声明 META.state_domain（<repo>.<plan> 域 token，
    # A2/D5 域化命名前向接口）——未声明 = 配置缺口 FAIL（驱动存量计划迁移）；
    # 其余（无需 worktree / 计划未要求）→ 无域契约可断言 → SKIP。
    dom = (meta.get("state_domain") or "").strip()
    if dom:
        # 质询 F8 修订（2026-09-15）：原判据 `dom in Path(stf).name` 为**子串**匹配，
        # 且 1b 步生效后 stf 恒由同一 dom 拼接而来 ⟹ 该检查退化为**同义反复**（等价于
        # 路由本身，非独立证据）。改为三重独立断言：精确文件名 + 文件实存 + r_phase 入计划相位集。
        fname = Path(stf).name if stf else ""
        want = ".gatekeeper.state." + dom
        if not stf:
            checks.append({"item": "state_domain", "status": "FAIL",
                           "evidence": (f"declared={dom} 但路由未解析出 state"
                                        f"（{st.get('error') or '空'}）")})
        elif fname != want:
            checks.append({"item": "state_domain", "status": "FAIL",
                           "evidence": (f"declared={dom} state_file={fname} ≠ 精确期望 {want}"
                                        "（子串匹配已废弃：F8）")})
        elif not Path(stf).exists():
            checks.append({"item": "state_domain", "status": "FAIL",
                           "evidence": f"declared={dom} 域化 state 不存在: {stf}"})
        elif plan_set and st_ph and st_ph not in plan_set:
            checks.append({"item": "state_domain", "status": "FAIL",
                           "evidence": (f"declared={dom} 域 state r_phase={st_ph} ∉ plan phases"
                                        f" [{', '.join(sorted(plan_set))}]")})
        else:
            checks.append({"item": "state_domain", "status": "PASS",
                           "evidence": f"declared={dom} state_file={fname} r_phase={st_ph or '-'}"})
    elif (str(meta.get("worktree_needed") or "").strip().lower() == "true"
          or is_foreign_repo(str(meta.get("target_repo") or ""))):
        # 2026-09-26（ECC-F2E2F9E07AC2 断点②）：门从「只挂 worktree_needed=true」松绑 ——
        #   `worktree_needed=false` 的**跨仓**计划（如 zthl-adapter）原走下方 SKIP ⟹ finding 可
        #   静默错落技能默认 state。自指判定复用 is_foreign_repo（resolve_repo 单源）；断点① 的
        #   可推导域一并报出（derive_state_domain 单源），供作者直接声明。
        _why = ("worktree_needed=true" if str(meta.get("worktree_needed") or "").strip().lower() == "true"
                else "target_repo 指向他仓")
        _der = derive_state_domain(meta)
        checks.append({"item": "state_domain", "status": "FAIL",
                       "evidence": (f"未声明 META.state_domain（{_why} ⟹ finding 归属域须显式，"
                                    f"否则跨仓 finding 静默落技能默认 state）")
                                   + (f"；可推导域 `{_der}`" if _der else "")})
    else:
        checks.append({"item": "state_domain", "status": "SKIP",
                       "evidence": "计划未声明 META.state_domain"})
    bad = [c for c in checks if c["status"] == "FAIL"]
    return {"check": "route_calibration", "checks": checks, "consistent": not bad,
            "state_file": stf}


def calibration(skill_dir: str = "", state_file: str = "", plan_file: str = "") -> dict:
    """route-all 全链路后评估五层一致性（calibrate 子命令入口）。
    plan_file 透传：显式计划上下文下校准（CLI 侧 PLAN_FILE env 注入），
    缺省 → route_all 自身 5 层金字塔搜索（与 discover 同源）。"""
    return calibration_from_route(route_all(skill_dir, state_file, plan_file=plan_file))


def _state_phase(state_file: str) -> str:
    from gk_state_route import _state_field
    return _state_field(state_file, "r_phase") or ""


def route_all(skill_dir: str = "", state_file: str = "", plan_file: str = "",
              plan_override: str = "", repo: str = "", task: str = "",
              extra_roots=None, calibrate: bool = False, domain: str = "") -> dict:
    """五层全链路一次输出（唯一路由入口）。层层咬合：L1 plan → L2 repo →
    L3 worktree → L4 state → L5 narrow。extra_roots: 跨仓库就近 state 根（2026-09-04）。
    domain（2026-09-15 A6-P2）: 显式域 token，优先于 L1 计划声明的 META.state_domain。"""
    sd = skill_dir or str(DEFAULT_SKILL)
    mr = _main_repo_wsl()
    pf = plan_override or plan_file
    plan = resolve_plan(pf, sd)
    meta = plan.get("meta", {})
    repo_name = repo or meta.get("target_repo", "")
    repo_r = resolve_repo(repo_name, sd)
    if "error" in repo_r:
        # 无 target_repo 声明或未知 repo：L2 层返回空（不中断全链路，标注即可）
        repo_r = {"path": "", "repo": repo_name, "note": repo_r.get("error", "")}
    worktree = resolve_worktree(sd, mr)
    state = resolve_state(sd, state_file, extra_roots=extra_roots,
                          domain=domain or str(meta.get("state_domain") or "").strip())
    narrow = resolve_narrow(state.get("expected", ""), task)
    out = {
        "center": "gk_route_center",
        "L1_plan": plan,
        "L2_repo": repo_r,
        "L3_worktree": worktree,
        "L4_state": state,
        "L5_narrow": narrow,
        "state_file": state.get("expected", ""),
    }
    if calibrate:
        # 2026-09-04 (B): 运行时五层校准——对本次路由结果直接评估（不重跑）
        out["calibration"] = calibration_from_route(out)
    return out


# ────────────────────────── CLI ──────────────────────────
def _as_norm(p) -> str:
    """路径归一：`\\`→`/` + Windows 盘符→WSL 形态（`C:\\x` → `/mnt/c/x`）+ rstrip('/')。"""
    s = str(p or "").replace("\\", "/")
    if len(s) >= 2 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s.rstrip("/")


def _session_token() -> str:
    """§17-2 域键 token（**方案 a**）：**只**取 env `GK_SESSION_ID`，**只**经 `_DOMAIN_TOKEN_RE` 单源
    校验（长度 ≤64）。非法 / 缺失 ⟹ `""`（回落 base，**零回归**）。**禁**由 cwd / **被判定路径**派生
    （否则 Gate 3 自证恒真）。
    """
    tok = (os.environ.get("GK_SESSION_ID") or "").strip()
    if not tok or len(tok) > 64:
        return ""
    try:
        from gk_finding import _DOMAIN_TOKEN_RE
    except Exception:  # noqa: BLE001 — 单源缺失 ⟹ 不产 token（fail-closed）
        return ""
    return tok if _DOMAIN_TOKEN_RE.match(tok) else ""


def _domain_roots(state, token) -> list:
    """域桶 `gate_data.wt_domain[<token>][]`（§17-2；fail-soft：非 dict / 非 list / 元素非 str / 空串 ⟹ 忽略）。"""
    if not token or not isinstance(state, dict):
        return []
    gd = state.get("gate_data")
    bucket = gd.get("wt_domain") if isinstance(gd, dict) else None
    if not isinstance(bucket, dict):
        return []
    vals = bucket.get(token)
    if not isinstance(vals, list):
        return []
    return [n for n in (_as_norm(v) if isinstance(v, str) else "" for v in vals) if n]


def active_roots(state) -> list:
    """RC1 活动写面 roots（有序去重）：`worktree`（强制面**主值**）在前 + `worktrees_extra[]` 随后
    + §17-2 域桶 `gate_data.wt_domain[<token>][]`（token 只取 env `GK_SESSION_ID`，方案 a）。

    契约（`docs/plans/2026-09-21-review-runtime-subplan.md` §4.13.30 八 / §8.9-③）：
      · 非法形态（非 list / 元素非 str / 空串）**忽略**（fail-soft，不抛）；
      · **不判存在性**（陈旧值按「忽略 + WARN，不 BLOCK」处置；主值通路独立）；
      · 域桶 token 缺失/非法 ⟹ 不并入任何域 roots（回落 base，**零回归**；见 `_session_token`）。
    """
    if not isinstance(state, dict):
        return []
    out = []
    w = _as_norm(state.get("worktree", ""))
    if w:
        out.append(w)
    extra = state.get("worktrees_extra")
    if isinstance(extra, list):
        for e in extra:
            n = _as_norm(e) if isinstance(e, str) else ""
            if n and n not in out:
                out.append(n)
    # §17-2 域桶并入：token 只取 env `GK_SESSION_ID`（方案 a）；缺失/非法 ⟹ 空 ⟹ 零回归。
    for n in _domain_roots(state, _session_token()):
        if n not in out:
            out.append(n)
    return out


def in_active_surface(path, state) -> bool:
    """`path` 是否落在活动写面内（**目录边界**：`p == root` 或 `p.startswith(root + "/")`）。

    RC1 单一 helper：Gate 3（写）与 Gate 5/6/7（读/搜/LS）**同调**（否则制造「写放开、读没放开」）。
    裸 `startswith(wt)` 会被**同前缀兄弟目录**绕过（`ECC-73ACEA635A78`：`wt=/a/b` 放行 `/a/bc/x`）
    ⟹ 此处加 `/` 边界。roots 空 ⟹ `False`（hook 侧 fail-closed；CLI 侧另有 legacy-skip，见下）。
    """
    p = _as_norm(path)
    if not p:
        return False
    for r in active_roots(state):
        if p == r or p.startswith(r + "/"):
            return True
    return False


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(json.dumps({"error": "usage: gk_route_center.py "
                                   "<route-all|resolve-plan|resolve-bound-plan|resolve-repo|"
                                   "resolve-worktree|resolve-state|resolve-narrow|calibrate|"
                                   "apply-worktree|apply-worktree-plan|active-surface|"
                                   "build-state> [opts]"}))
        return 1
    cmd = args[0]
    rest = args[1:]
    # 2026-09-02 L1-10 交叉审查漏洞 1 修复：env SKILL_DIR 注入 → 五层路由全部指向
    # 攻击者目录。env 值必须含技能仓库特征（gatekeeper-cli.sh + SKILL.md）才信任；
    # argv --skill-dir 显式传参不受限（测试/CLI 合法注入）。
    skill_dir = os.environ.get("SKILL_DIR", "")
    argv_skill = ""
    state_file = os.environ.get("STATE_FILE", "")
    plan_pointer = os.environ.get("PLAN_POINTER", "")
    plan_file = os.environ.get("PLAN_FILE", "")
    plan_override = ""
    repo = ""
    task = ""
    domain = ""
    finding = ""
    family = ""
    main_repo = ""
    check_poison = check_schema = False
    calibrate = False
    derive_domain = False
    extra_roots = []
    surf_path = ""
    roots_only = False
    dry_run = False
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in ("--skill-dir",) and i + 1 < len(rest):
            argv_skill = rest[i + 1]; skill_dir = argv_skill; i += 2
        elif a in ("--state-file", "--state") and i + 1 < len(rest):
            state_file = rest[i + 1]; i += 2
        elif a == "--plan-pointer" and i + 1 < len(rest):
            plan_pointer = rest[i + 1]; i += 2
        elif a == "--plan-file" and i + 1 < len(rest):
            plan_file = rest[i + 1]; i += 2
        elif a == "--plan-override" and i + 1 < len(rest):
            plan_override = rest[i + 1]; i += 2
        elif a == "--repo" and i + 1 < len(rest):
            repo = rest[i + 1]; i += 2
        elif a == "--task" and i + 1 < len(rest):
            task = rest[i + 1]; i += 2
        elif a == "--domain" and i + 1 < len(rest):
            domain = rest[i + 1]; i += 2
        elif a == "--derive-domain":
            derive_domain = True; i += 1
        elif a == "--finding" and i + 1 < len(rest):
            finding = rest[i + 1]; i += 2
        elif a == "--family" and i + 1 < len(rest):
            family = rest[i + 1]; i += 2
        elif a == "--main-repo" and i + 1 < len(rest):
            main_repo = rest[i + 1]; i += 2
        elif a == "--extra-root" and i + 1 < len(rest):
            extra_roots.append(rest[i + 1]); i += 2
        elif a == "--calibrate":
            calibrate = True; i += 1
        elif a == "--check-poison":
            check_poison = True; i += 1
        elif a == "--check-schema":
            check_schema = True; i += 1
        elif a == "--path" and i + 1 < len(rest):
            surf_path = rest[i + 1]; i += 2
        elif a == "--roots":
            roots_only = True; i += 1
        elif a == "--dry-run":
            dry_run = True; i += 1
        else:
            if cmd == "resolve-repo" and not repo:
                repo = a
            i += 1

    if not argv_skill and skill_dir and not _skill_dir_env_trusted(skill_dir):
        # env SKILL_DIR 不可信（内容特征失败 或 非自身路径且无 git 锚定干净同源副本）
        # → 忽略，回退默认技能目录（防注入）。argv --skill-dir 显式传参不受限。
        skill_dir = ""

    try:
        if cmd == "route-all":
            out = route_all(skill_dir, state_file, plan_file, plan_override, repo, task,
                            extra_roots=extra_roots or None, calibrate=calibrate,
                            domain=domain)
        elif cmd == "calibrate":
            out = calibration(skill_dir, state_file, plan_override or plan_file)
        elif cmd == "resolve-plan":
            out = resolve_plan(plan_override or plan_file, skill_dir)
        elif cmd == "resolve-bound-plan":
            out = resolve_bound_plan(state_file, plan_pointer, skill_dir)
        elif cmd == "resolve-repo":
            out = resolve_repo(repo, skill_dir)
        elif cmd == "resolve-worktree":
            out = resolve_worktree(skill_dir)
        elif cmd == "resolve-state":
            # 质询 F1 修订：计划可经 --plan-file/--plan-override 显式提供 → 读其 META.state_domain
            # 作为 domain 兜底（此前该子命令不读 META ⟹ CLI 链上 1b 永不触发）。
            # 2026-09-25（§4.13.5「全序列打通①」）：`--derive-domain` = **会话级计划来源**接线 ——
            #   env `GK_PLAN_FILE` 声明的本会话计划亦作 domain 来源（argv 仍优先）。
            #   修前启动块既不传 plan 也不传 domain ⟹ 1b 在 CLI 链上不可达（源注释自陈「生产不可达」）；
            #   接线后「会话声明计划 → 落到该计划声明的域化 state」，无需全局 `.gatekeeper.plan` 指针。
            #   未设该 env / 计划未声明 state_domain ⟹ 与既有链**逐字一致**（零回归）。
            # 2026-10-29（A7 接线）：本段逻辑抽成 `resolve_state_cli` —— `gk_worker.py` 的
            #   `resolve_state_cli` op 与本分支**共用同一实现**（禁第二实现，防 fast path 语义漂移）。
            out = resolve_state_cli(skill_dir, state_file, plan_pointer,
                                    plan_override=plan_override, plan_file=plan_file,
                                    derive_domain=derive_domain,
                                    extra_roots=extra_roots or None, domain=domain)
        elif cmd == "resolve-narrow":
            out = resolve_narrow(state_file, task, check_poison, check_schema)
        elif cmd == "apply-worktree":
            # F7 基座 T3/T4：worktree 申请—分发（--finding/--family/--main-repo）
            out = apply_worktree(main_repo or _main_repo_wsl(), finding, family)
        elif cmd == "apply-worktree-plan":
            # 2026-10-28：**计划驱动建树**（`feature/<plan-stem>`）—— 与 finding 驱动并列，
            #   共用同一套白名单 / 委托 / 后置校验（`apply_worktree(..., plan_stem=…)`）。
            out = apply_worktree_plan(main_repo or _main_repo_wsl(), plan_override or plan_file,
                                      skill_dir, dry_run=dry_run)
        elif cmd == "active-surface":
            # RC1（2026-09-27）：活动写面判定**单一 helper** 的 CLI 面 —— 供 `gatekeeper-cli.sh`
            # 的 P7 谓词委派（bash 无法 import；一次 spawn 取 rc）。
            # exit 契约（§17-6-P4 订正 2026-10-04）：0 = 在面内；1 = **不在**面内 **或** 无 root
            #   （空值三态一律不得放行，「非 worktree 模式」= 显式 root 集合）；
            #            2 = 错误（state 不可读 / 缺 --path，fail-closed）。
            try:
                _st = json.loads(Path(state_file).read_text(encoding="utf-8"))
            except Exception as e:
                out = {"ok": False, "error": "state_unreadable: %s" % e, "exit": 2}
            else:
                _rts = active_roots(_st)
                if roots_only:
                    out = {"ok": True, "roots": _rts}
                elif not surf_path:
                    out = {"ok": False, "error": "--path required", "exit": 2}
                else:
                    _ins = in_active_surface(surf_path, _st)
                    out = {"ok": True, "in_surface": _ins, "roots": _rts}
                    if not _ins:
                        out["exit"] = 1
        elif cmd == "build-state":
            # 2026-10-04（§18.2 c2）：**显式单建入口** —— 元数据中枢派生种子 + 单建者原子首建域 state。
            # 与 apply-worktree 同为「路由中枢承载的写操作」；`resolve_state` 仍 **fail-closed**（零回归）。
            if not state_file:
                out = {"ok": False, "error": "build-state 需要 --state-file（基址 state）"}
            else:
                d = derive_state_seed(plan_override or plan_file, skill_dir, state_file, main_repo)
                if d.get("error"):
                    out = {"ok": False, "error": d["error"], "plan_file": d.get("plan_file", "")}
                else:
                    from gk_state_forms import build_domain_state_exclusive
                    b = build_domain_state_exclusive(state_file, d["domain"], d["seed"])
                    out = {"ok": True, "domain": d["domain"], "path": b["path"],
                           "built": b["built"], "reason": b.get("reason", ""),
                           "stage": d["seed"]["stage"]}
        else:
            print(json.dumps({"error": f"unknown command: {cmd}",
                              "valid": ["route-all", "resolve-plan", "resolve-bound-plan",
                                        "resolve-repo", "resolve-worktree", "resolve-state",
                                        "resolve-narrow", "calibrate", "apply-worktree",
                                        "active-surface", "build-state"]}))
            return 1
        # ensure_ascii=True：中文 warning 转 \uXXXX，避免 argv 跨编码损坏（对齐 gk_state_route）
        print(json.dumps(out, ensure_ascii=True))
        # narrow check / active-surface 失败 → 返回其 exit（对齐 gk_narrow_route exit 契约）
        if cmd in ("resolve-narrow", "active-surface") and out.get("exit"):
            return out["exit"]
        return 0
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())

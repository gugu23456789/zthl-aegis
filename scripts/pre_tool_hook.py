#!/usr/bin/env python3
"""
pre_tool_hook.py — Trae Hook (stdin-driven, Claude Code / VS Code Copilot compliant)
=====================================================================================
Reads Hook JSON from stdin, validates against gatekeeper state, returns exit code.

Stdin JSON (PreToolUse event):
  {"tool_name":"SearchReplace","tool_input":{"file_path":"...","old_str":"...","new_str":"..."},"cwd":"..."}

Exit codes:
  0 = ALLOW (proceed with tool call)
  2 = BLOCK (stderr shown to agent; do NOT proceed)
  Other = NON-BLOCKING ERROR (tool proceeds)

Gate chain (fail-closed: any gate fails = exit 2):
  Gate 0: Block bare Task tool for gatekeeper subagent launches
  Gate R0: Block dangerous RunCommand patterns (shell redirection)
  Gate 1: Stage must be active (not IDLE/DONE)
  Gate 2: Worktree must exist on disk
  Gate 3: file_path must be inside active worktree (for edit/write tools)
  Gate 4: CLI pre-tool-check must pass
  Gate 5: Read scope — file must be within worktree
  Gate 6: Glob/Grep scope — search path must be within worktree
  Gate 7: LS scope — target directory must be within worktree
  Gate 9: 提问挂起闸 — 无人时段 / 纯确认型 AskUserQuestion → BLOCK（F-REV-96，普适）
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

SKILL_DIR = Path(__file__).parent.parent
CLI_PATH = SKILL_DIR / "gatekeeper-cli.sh"

# 2026-09-21：审查节点判据**单源** —— 本 hook 的 Gate 1b 与 CLI `_review_channel_preflight` C
# 同源消费 `scripts/gk_review_nodes.py`（原为两份各持白名单常量、各写 if 分支的**双源**）。
sys.path.insert(0, str(Path(__file__).resolve().parent))
from gk_review_nodes import review_node_ok as _review_node_ok_src  # noqa: E402
from gk_review_nodes import REVIEW_NODE_STANDARD as _REVIEW_NODE_STANDARD  # noqa: E402
from gk_review_nodes import REVIEW_NODE_STANDING as _REVIEW_NODE_STANDING  # noqa: E402
# R2（2026-09-22）：state 序列化单一事实源 —— 勿再内联 json.dump 直写 state。
from gk_json_utils import dump_state, state_lock  # noqa: E402
# 2026-11-04：威胁模式**单一来源**（`scripts/gk_threat_patterns.py`）—— 编辑载荷闸
# 与 cron prompt 扫描共用一处定义，禁止在各自文件里再写一份模式表。
from gk_threat_patterns import PAYLOAD_MALWARE_PATTERNS as _MALWARE_PATTERNS  # noqa: E402

# 2026-09-04 ② state 单一事实源收敛：CLI（gatekeeper-cli.sh）状态机写入 SKILL_DIR/.gatekeeper.state
# （跨 R 机器单源）。此前 hook 默认/登记映射指 spz_gatekeeper_project 仓库级 .gatekeeper.state
# （Downloads 主检出 + r7.1 worktree 双 legacy 副本，停在 STAGE_1）→ 与 CLI（STAGE_2）分歧。
# 收敛后读源优先级：显式 env STATE_FILE > .gatekeeper.scopes.json governed state_file > SKILL_DIR 默认。
# 2026-10-26（开源可移植性）：移除 `<home>/...` 用户目录硬编码 —— 默认 state 改为
# **相对本文件解析**（`scripts/../.gatekeeper.state`）。WSL 下解析为 `/mnt/c/...`，Windows
# 下解析为 `C:\...`，同一份代码两栖可用；仍可用 `STATE_FILE`（或 `GK_STATE_FILE`）显式覆盖。
_REPO_ROOT = Path(__file__).resolve().parent.parent
_STATE_FILE_DEFAULT = _REPO_ROOT / ".gatekeeper.state"
# 旧符号名保留（外部引用/测试兼容），值统一指向可移植默认。
_STATE_FILE_WSL = _STATE_FILE_DEFAULT
_STATE_FILE_WIN = _STATE_FILE_DEFAULT
# STATE_FILE env var overrides hardcoded paths (used by tests and gatekeeper CLI)
# 2026-09-25（hook-xenv §15.3-Q2 自洽臂抓出）：**空串 = 未设置** —— 原式 `"STATE_FILE" in os.environ`
#   对 `STATE_FILE=`（存在但空，wslsh/部分 CI 环境实测）判为显式覆盖 ⟹ `Path("")` = `Path(".")`
#   ⟹ IsADirectoryError ⟹ RunCommand 全量 fail-closed「State file corrupt」假拦（确定性复现）。
_STATE_FILE_FROM_ENV = bool(str(os.environ.get("STATE_FILE", "")).strip())
STATE_FILE = Path(os.environ["STATE_FILE"]) if _STATE_FILE_FROM_ENV else _STATE_FILE_DEFAULT
# 模块默认 fallback 路径集合：仅当 STATE_FILE 命中这些默认值时，main() 才按 cwd 重新解析
# （env/patch 显式设置的 STATE_FILE 不覆盖 — 保持 CLI 契约与测试兼容，2026-08-03）
_DEFAULT_STATE_PATHS = {str(_STATE_FILE_WSL), str(_STATE_FILE_WIN)}

# ── 治理范围注册表（v2 外置化：.gatekeeper.scopes.json，2026-08-07 升级）──
# 2026-08-05 用户定调：门禁只覆盖 技能目录 + 已登记被治理项目。
# cwd 在范围外（未登记项目）→ 放行，不做治理，替代"回退默认 state 拦所有项目"。
# 技能目录本身恒在治理范围内（下方 _in_governed_scope 内建）。
# v2: governed_projects[]（markers 列表 + state_file），多 marker 覆盖主检出 + worktree 路径；
# v1 兼容：governed_project_markers 列表 → 全部映射默认门卫 state。
# 2026-09-04 ②：默认门卫项目收敛到 SKILL_DIR 单源（同 CLI），不再指仓库级 legacy 副本。
_DEFAULT_GOVERNED_SCOPES = {"spz_gatekeeper_project": str(_STATE_FILE_WIN)}
SCOPES_FILE = SKILL_DIR / ".gatekeeper.scopes.json"


def _resolve_existing(sf: str) -> Optional[Path]:
    """state_file 路径（Windows / C:\\ 或 /mnt 形态）→ 首个实际存在形态（跨 Windows/WSL python 运行）。

    双向探测：原样 + _win_to_wsl（C:\\→/mnt）+ _wsl_to_win（/mnt→C:/），
    覆盖 .gatekeeper.plan 指针与 scopes 里可能由 WSL CLI 写入的 /mnt 形态
    （此前只做 Win→/mnt 单向，/mnt 形态在 Windows python 下解析落空 → 回退默认）。
    """
    seen = set()
    cands = []
    for raw in (sf, _win_to_wsl(sf or ""), _wsl_to_win(sf or "")):
        if raw and raw not in seen:
            seen.add(raw)
            p = Path(raw)
            cands.append(p)
            if p.exists():
                return p
    for p in cands:  # 各形态均不存在 → 返回首个（fail-closed 调用方自判）
        return p
    return None


def _load_governed_scopes() -> dict:
    """从 .gatekeeper.scopes.json 加载 {marker: state_file} 映射；失败回退默认门卫项目。"""
    try:
        if SCOPES_FILE.exists():
            data = json.loads(SCOPES_FILE.read_text())
            scopes = {}
            projects = data.get("governed_projects", [])
            if isinstance(projects, list) and projects:
                for p in projects:
                    markers = p.get("markers") or ([p.get("marker")] if p.get("marker") else [])
                    sf = p.get("state_file", "")
                    if markers and sf:
                        for m in markers:
                            scopes[str(m)] = str(sf)
                if scopes:
                    return scopes
            # v1 兼容
            markers = data.get("governed_project_markers", [])
            if isinstance(markers, list) and markers:
                return {str(m): str(_STATE_FILE_WIN) for m in markers}
    except Exception:
        pass
    return dict(_DEFAULT_GOVERNED_SCOPES)


GOVERNED_SCOPES = _load_governed_scopes()


def _norm_forms(p: str) -> tuple:
    """**比较键**的三形态枚举 —— 宿主形态族（XENV-FORM）的单点归一。

    复用 `_resolve_existing` 既有范式（原样 + `_win_to_wsl` + `_wsl_to_win`），
    **不新建第二套归一 helper**、**不引入 `lower()`**（全局 lower 会同时破
    `GOVERNED_SCOPES` 的大写 marker 子串面、以及大小写敏感 FS 上的 `Path(t)` 走查）。

    纪律：**双侧同步枚举**后两两比较 —— 「只归一单侧」（左过 `_win_to_wsl`、右不过）
    正是本族六条缺陷的共同病根（ECC-DF56818912BD / ECC-49F60E32F1F1 / ECC-24D6EC1112BB）。
    形态完备性：同一位置两侧各得 {`/mnt/c/…`, `C:/…`} 之一，交集恒非空 ⟹ 大写盘符
    `/mnt/C/…` 也被 `_wsl_to_win` 形态（`C:/…`）自然覆盖（ECC-99056BFDBC47 的大小写面，
    无需 lower）。统一去尾斜杠 —— 前缀比较必须带目录边界，否则
    `/…/spz-gatekeeper-r-sequence-x` 会被误判为仓内（99056 的另一半）。
    """
    out = []
    for raw in (p or "", _win_to_wsl(p or ""), _wsl_to_win(p or "")):
        s = (raw or "").replace("\\", "/").rstrip("/")
        if s and s not in out:
            out.append(s)
    return tuple(out)


_IS_WIN_HOST = os.name == "nt"


def _host_form(p: str) -> str:
    """**FS / flavour 谓词**的宿主原生单形态 —— 宿主形态族（XENV-FORM）亚型 B 的单点。

    族规则①（计划 §2 / 族契约 `ECC-1FC673558891`）：`_win_to_wsl` 产物**只可用于比较键**；
    凡 FS 操作（`exists` / `is_dir` / `is_file` / `read_text` / `stat` / `resolve`）与
    **flavour 判据**（`is_absolute`）必须吃**宿主原生形态** —— 否则：

      · Windows 宿主把 `/mnt/c/…` 读成 `C:\\mnt\\c\\…`（`Exists` 恒假 ⟹ fail-open：
        G-6 `_scan_script_content` / step3 就近查找，`ECC-658E1E62B86D` / `ECC-B21BEDC08CE7`）；
      · `Path("/mnt/c/x").is_absolute()` 在 Windows flavour 下为 **False** ⟹ 绝对路径被当相对
        （`resolve_path` / `_scan_script_content` 的 `is_absolute` 面，`ECC-AC4695EFEA21`）。

    与 `_norm_forms` 的**分工（不许互换）**：`_norm_forms` = 比较键的**三形态枚举**（零 FS、tuple）；
    本函数 = FS/谓词的**单形态**（宿主、str）。二者由 `test_gk_xenv_form_fsform.py::TestHostFormContract`
    锁形（str vs tuple ≥2）。
    """
    s = (p or "").strip()
    if not s:
        return s
    return _wsl_to_win(s) if _IS_WIN_HOST else _win_to_wsl(s)


def _in_governed_scope(cwd: str) -> bool:
    """cwd 是否落在治理范围内：技能目录 + 已登记被治理项目（marker 命中）。

    XENV-FORM ②a（2026-09-21 修）：原式 `cwd_wsl` 过 `_win_to_wsl` 而 `skill_wsl` 只
    `replace("\\\\", "/")` ⟹ Windows 宿主形态下 `/mnt/c/…` vs `C:/…` 比较**恒假** ⟹
    判范围外 ⟹ `main()` 早退 ⟹ Gate 1/2/3/4/8 **整链不执行**（fail-open）。
    现改为**双侧三形态**比较（`_norm_forms`）。marker 面沿用原「WSL 归一形态」单键，
    **大小写敏感语义不变**（禁 lower 的战果面）。
    """
    keys = _norm_forms(cwd)
    for s in _norm_forms(str(SKILL_DIR)):
        if any(k == s or k.startswith(s + "/") for k in keys):
            return True
    cwd_wsl = _win_to_wsl(cwd or "").replace("\\", "/")
    return any(m in cwd_wsl for m in GOVERNED_SCOPES)


_PLAN_POINTER_TTL_S = 86400.0  # 对齐 CLI Phase 7b（2026-08-23）：updated 超 24h 视为失效


def _plan_pointer_fresh(pp: dict) -> bool:
    """plan 指针 updated 新鲜度（对齐 CLI Phase 7b TTL，2026-09-05 hook 侧补齐）：
    无 updated / 解析失败 / 超 24h → 不新鲜（hook 忽略不跟随；清理仍归 CLI）。"""
    import datetime
    u = pp.get("updated", "")
    if not u:
        return False
    try:
        ts = datetime.datetime.fromisoformat(u.replace("Z", "+00:00"))
        age = (datetime.datetime.now(datetime.timezone.utc) - ts).total_seconds()
        return 0 <= age <= _PLAN_POINTER_TTL_S
    except Exception:
        return False


def _state_claims(p: Path) -> bool:
    """就近 state **认领判据**（2026-11-06，B2）：只认领**含 `stage` 的完整 state**。

    病象（实测）：`<home>\\.gatekeeper.state` 由 `gk_finding.save_findings` 在
    文件不存在时自动创建 —— 只写 `gate_data` + `_checksum`，**没有 `stage`**。就近上溯把它
    认领成治理 state ⟹ `stage.get("stage", "IDLE")` == IDLE ⟹ home 下任何目标（含兄弟技能
    `git-workflow/**`）被 "Cannot edit without active R-phase" 误拦。
    判据：缺 `stage` / 不可解析 ⟹ **不参与认领**（继续上溯；找不到则按范围外放行/回落默认）。
    """
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(d, dict) and "stage" in d


def _resolve_state_by_cwd(cwd: str) -> Optional[Path]:
    """按实际工作目录归属解析 state 文件（修复 hook 读错 state）。

    治理范围模型（2026-08-05 用户定调 + 2026-08-07 多项目注册）：
      - cwd 在治理范围内（技能目录 + 已登记被治理项目）→ fail-closed 解析 state
      - cwd 在范围外（未登记项目）→ 返回 None，main() 直接放行
    范围内优先级: plan 指针（discover --plan 写入，跨进程联动隔离 state）
           → cwd 归属（技能目录 / 登记项目 marker → 各自 state 文件）
           → 就近查找最近的 .gatekeeper.state
    未命中时回退默认门卫 state（Gate 1 无 state 仍拦截 — 2026-08-04 用户定调）。
    """
    # 0. 治理范围检查：范围外 → None（放行）
    if not _in_governed_scope(cwd):
        return None
    # 1. plan 指针 — 活跃隔离计划优先
    plan_pointer = SKILL_DIR / ".gatekeeper.plan"
    if plan_pointer.exists():
        try:
            pp = json.loads(plan_pointer.read_text())
            sf = pp.get("state_file", "")
            if sf and _plan_pointer_fresh(pp):
                pf = _resolve_existing(sf)
                if pf and pf.exists():
                    return pf
        except Exception:
            pass
    # 2. cwd 归属：技能目录 / 登记项目（marker → 各自 state 文件）
    # XENV-FORM ②b（2026-09-21 修）：原式与 ②a 逐字同形（左过 `_win_to_wsl`、右不过）
    # ⟹ Windows 宿主下技能目录分支不成立 ⟹ 掉 marker 分支 ⟹ 再掉就近查找
    # （ECC-49F60E32F1F1；单修 ②a 而不修本条 = 把「静默放行」换成「hook 挂死」）。
    cwd_keys = _norm_forms(cwd)
    for s in _norm_forms(str(SKILL_DIR)):
        if any(k == s or k.startswith(s + "/") for k in cwd_keys):
            cand = SKILL_DIR / ".gatekeeper.state"
            if cand.exists():
                return cand
            break
    cwd_wsl = _win_to_wsl(cwd or "").replace("\\", "/")
    for marker, sf in GOVERNED_SCOPES.items():
        if marker in cwd_wsl:
            # sf 可为 Windows 或 /mnt 形态 → _resolve_existing 双形态探测（跨运行环境）
            c = _resolve_existing(sf)
            if c and c.exists():
                return c
            break  # 命中登记项目但 state 缺失 → 落入就近/默认（fail-closed）
    # 3. 就近查找最近的 .gatekeeper.state
    # XENV-FORM ③（2026-09-21 修）：原哨兵 `while str(p) not in ("/", "", ".")` 是
    # **POSIX 专属** —— Windows 根锚 `str(Path("C:/")) == "\\"` 不在集合内，且 `Path.parent`
    # 在根处自指（`str(p.parent) == str(p)`）⟹ **死循环**（仓内 `_state_walk_boundary`
    # docstring 自证同类曾在根锚死循环、卡死全量 pytest；本批红先测试在 Windows python
    # 子进程下 25s 未返回实测复现）。改复用既有终止判据 `_state_walk_boundary`（单点），
    # 尾部 `return STATE_FILE` **保持不变**（fail-closed 默认门卫；`None` 是
    # `_resolve_state_by_target_path` 的 kill-switch 语义，不可移植）。
    # XENV-FORM G-7′（2026-09-21 修，ECC-B21BEDC08CE7）：原式 `p = Path(cwd_wsl)` 把**归一产物**
    # 喂给 FS 操作 —— Windows 宿主下 `Path("/mnt/c/…")` 被读成 `C:\mnt\c\…` ⟹ `cand.exists()`
    # 恒假 ⟹ 走查**永远找不到真正存在的就近 state**、只能恒落默认门卫（施加错误的 state：
    # edit_budget / r_phase / worktree 归属全取错源）。该面是 ③ 落刀后**新暴露**的：落刀前同一句
    # 因哨兵 POSIX 专属而自指死循环（响的失败），落刀后循环正常退出、于是由「挂死」变「静默降级」。
    # 改吃 `_host_form`（族规则①）：posix 侧 cwd 本就是 /mnt 形态、`_win_to_wsl` 为恒等 ⟹ 零反转；
    # Windows 侧 `/mnt/c/…` → `C:/…` ⟹ 走查可达真实目录。
    p = Path(_host_form(cwd or ""))
    while True:
        cand = p / ".gatekeeper.state"
        if cand.exists() and _state_claims(cand):
            return cand
        parent = p.parent
        if _state_walk_boundary(p, parent):
            break
        p = parent
    return STATE_FILE


def _resolve_state_by_target_path(target: str) -> Optional[Path]:
    """按**目标路径归属**解析 state（F5 / ECC-05D9F1857601，2026-09-18 用户裁定 ①）。

    现场：scope 原**只**按 `cwd` 判 —— Trae 会话 cwd 常在治理范围外（如 `c:\\Users\\HP`），
    `_resolve_state_by_cwd` 返回 None ⟹ `scope_out=True` ⟹ `main()` 早退（`sys.exit(0)`）⟹
    Gate 3（worktree 包含）/ Gate 4（CLI `pre-tool-check`，含 `edit_budget` 扣减）/
    Gate 8（技能自维护防裸跑）**整链不执行**（`hook.log` 全量聚合实测：所有 `Edit`/`Write`
    事件恒带 `[SCOPE-OUT:allow]`）。本函数改以**目标路径**判定，优先级与
    `_resolve_state_by_cwd` 对齐（技能目录 → 登记项目 marker → 就近 state → None）。

    纪律：**全不中即返回 None**（`scope_out` 保持放行），绝不把治理范围外的项目拉进来。
    kill switch：`GK_SCOPE_TARGET=0` → 调用方跳过本函数，回退纯 cwd 判定。
    """
    t = _win_to_wsl(target or "").replace("\\", "/")
    if not t:
        return None
    # XENV-FORM ④（2026-09-21 修）：原式左侧过 `_win_to_wsl`、右侧只 `replace("\\\\","/")`
    # ⟹ Windows 宿主下「目标在技能仓」这一首判不成立 ⟹ F5 目标通道不认领技能仓目标
    # （ECC-24D6EC1112BB；与 ②a 叠加共同造成「技能仓 cwd 整体落范围外」）。
    # 改**双侧三形态**；目录边界（rstrip + "/"）保留（ECC-99056BFDBC47）。
    t_keys = _norm_forms(t)
    # 方案 A（2026-09-23 用户裁定，ECC-B8974A514E81）：技能仓的 **git worktree** 与主树是
    # **同一治理对象** ⟹ `…/worktrees/<技能名>/…` 的目标归**主树** state。
    # 现场（实测）：hook 进程的 SKILL_DIR = 主树（wrapper 由主树启动），目标却在 worktree 下
    #   ⟹ 首判不命中 ⟹ 落到下方「就近 state」分支 ⟹ 命中该 worktree **自己**的
    #   `.gatekeeper.state`（stage=IDLE）⟹ 编辑被莫名拦下（Cannot edit without active
    #   R-phase）；而在 worktree 里跑任意一条会写 state 的 CLI 命令即可把门禁切到该份
    #   ⟹ 等价于绕过主树治理（与 ECC-05D9F1857601 同族，F5 修法只覆盖「目标在主树技能仓」）。
    # ⚠ 只做**归属归一**：state 落点仍在主树；CLI 侧同批做同样归一 —— 两侧必须一致，
    #   否则 hook 读主树而 CLI 写 worktree ⟹ 读写分裂（会出现「advance 了但门禁没变」）。
    _skill_roots = _norm_forms(str(SKILL_DIR))
    _skill_roots += _norm_forms(str(SKILL_DIR.parent.parent / "worktrees" / SKILL_DIR.name))
    for s in _skill_roots:
        if any(k == s or k.startswith(s + "/") for k in t_keys):
            cand = SKILL_DIR / ".gatekeeper.state"
            return cand if cand.exists() else None
    linked = _skill_linked_worktree_state(t)
    if linked is not None:
        return linked
    for marker, sf in GOVERNED_SCOPES.items():
        if marker in t:
            c = _resolve_existing(sf)
            return c if c and c.exists() else None
    p = Path(t).parent
    while True:
        cand = p / ".gatekeeper.state"
        if cand.exists() and _state_claims(cand):
            return cand
        parent = p.parent
        if _state_walk_boundary(p, parent):
            return None
        p = parent


def _linked_gitdir_matches(gitdir_raw: str, wt_dir: str, skill_dir: str) -> bool:
    """`gitdir:` 是否指向本技能仓的 `.git/worktrees/`（形态/相对/大小写/`..` 全归一）。

    2026-11-09（残余漏洞收口）：原实现只做「原样 + `_win_to_wsl`」字符串前缀比较 ⟹
      ① 相对 `gitdir:`（`git worktree add --relative-paths`）永不命中；
      ② `..` / 双斜杠 / Windows 大小写差异永不命中（`<home>/.TRAE` vs `.trae`）；
      ③ 单侧归一（右不归一）复现 ECC-DF56818912BD 同族。
    修法 = 双侧 `_norm_forms`（原样 + win→wsl + wsl→win）+ `normpath` + 仅对
    `/mnt/` 与盘符形态做大小写折叠（不在大小写敏感 FS 上全局 lower）；前缀比较带
    目录边界（`/…/spz-gatekeeper-r-sequence-x` 不得误命中）。
    """
    gd = str(gitdir_raw or "").strip()
    if not gd:
        return False
    # 相对 gitdir 按 worktree 根解析（git 的 `gitdir:` 相对语义）
    if not re.match(r"^[A-Za-z]:[\\/]", gd) and not gd.startswith("/"):
        gd = os.path.normpath(os.path.join(str(wt_dir), gd.replace("\\", "/")))
    base = os.path.join(str(skill_dir), ".git", "worktrees")

    def _keys(x: str):
        out = []
        for raw in _norm_forms(x):
            n = os.path.normpath(raw).replace("\\", "/").rstrip("/")
            if not n:
                continue
            cand = [n]
            if n.startswith("/mnt/") or re.match(r"^[A-Za-z]:/", n):
                cand.append(n.lower())
            for v in cand:
                if v and v not in out:
                    out.append(v)
        return out

    return any(g == b or g.startswith(b + "/") for g in _keys(gd) for b in _keys(base))


def _skill_linked_worktree_state(t: str) -> Optional[Path]:
    """目标是否在本技能仓的 **linked worktree**（名字无关），是则归主树 state。

    2026-11-09 修（预算/门禁绕过，用户质询「额度银行没在干活」）：原判定只认目录名
    **恰好等于技能名**（`worktrees/<SKILL_DIR.name>`）；`worktrees/spz-gatekeeper-*-json`
    等副本 ⟹ 返回 None ⟹ 回退 cwd 判定（cwd 也在 worktree ⟹ None）⟹ `scope_out` ⟹
    Gate3/Gate4/edit_budget 整链**不执行且不计费**（本次 JSON 改造实测即此路径）。

    判据（确定性，不猜名字）：向上找到含 `.git` **文件** 的目录，读 `gitdir:` 行，归一为
    WSL 形态后必须落在 `<技能仓>/.git/worktrees/` 之下（= 同仓 linked worktree）。
    只认文件形态（`git worktree` 的 `.git` 是文件；主检出是目录 ⟹ 不认领）。
    """
    p = Path(t)
    if not p.is_dir():
        p = p.parent
    for _ in range(10):
        gf = p / ".git"
        try:
            if gf.is_file():
                line = gf.read_text(encoding="utf-8", errors="replace").strip()
                if not line.startswith("gitdir:"):
                    return None
                gd_raw = line.split(":", 1)[1].strip()
                if _linked_gitdir_matches(gd_raw, str(p), str(SKILL_DIR)):
                    cand = SKILL_DIR / ".gatekeeper.state"
                    return cand if cand.exists() else None
                return None        # 别的仓的 linked worktree：不认领（防误伤）
        except OSError:
            return None
        parent = p.parent
        if parent == p:
            return None
        p = parent
    return None


def _state_walk_boundary(p: Path, parent: Path) -> bool:
    """就近 state 的 walk-up **终止判据**（F5 落刀后实测补：越界会把范围外路径全拽进治理）。

    三条任一成立即终止：
      ① `parent == p` —— 根锚自指（Windows 宿主下 `str(Path("C:/")) == "C:\\"` ≠ `"/"` ⟹
         只判 `str(p) in ("/", …)` 会在根上死循环；本轮红先测试实测暴露，致全量 pytest 卡死）
      ② `str(p) in ("/", "", ".")` —— 已站在卷根上（无处可退）
      ③ `str(parent) in ("/", "\\", "")` —— **不跨出卷根**。现场实测（2026-09-18）：WSL 根 `/`
         存在**游离** `.gatekeeper.state`（`stage=STAGE_0 / worktree=''`），越界会把**任何**范围外路径
         （`<home>/AppData/Local/Temp/x.py`、`/tmp/x.py`、`/home/u/proj/x.py` —— 逐一实测）
         认领进该 state ⟹ Gate 2 报 `Worktree '' does not exist` ⟹ 编辑被误拦。
         `/mnt/c/.gatekeeper.state`（卷根**内**）仍照常受认领，语义不变。
    """
    return parent == p or str(p) in ("/", "", ".") or str(parent) in ("/", "\\", "")

# Context file — written by gatekeeper-cli.sh _write_context_file() on state transitions.
# Same resolution logic as STATE_FILE but in SKILL_DIR (where CLI writes it).
_CONTEXT_FILE_WSL = SKILL_DIR / ".gatekeeper.context.json"
_CONTEXT_FILE_WIN = SKILL_DIR / ".gatekeeper.context.json"
CONTEXT_FILE = Path(os.environ["CONTEXT_FILE"]) if "CONTEXT_FILE" in os.environ else _CONTEXT_FILE_WSL
_CONTEXT_SEEN_FILE = CONTEXT_FILE.parent / ".gatekeeper.context.seen"

# 调用日志 — 实证 Trae 是否真的触发了本 hook（2026-08-05 排查"hook 没起作用"）
# 每次被调用追加一行；被 .gitignore 的 *.log 规则忽略，不入库。
HOOK_LOG = SKILL_DIR / ".gatekeeper.hook.log"

def _log_hook(line: str) -> None:
    """Append one line to hook invocation log. Non-fatal on any error."""
    import datetime
    try:
        with open(HOOK_LOG, "a", encoding="utf-8") as f:
            f.write(f"{datetime.datetime.now().strftime('%F %T')} {line}\n")
    except Exception:
        pass


# ── A6 可观测性（论文 A1 的 observability 谓词）· AMP access ───────────────────
# 口径：**每次工具调用**由进程出口写一条 access 记录（allow / block / error），
#   使「判定 ⟺ logged」对**所有退出路径**成立（此前 scope_out 等早退不落 allow 行）。
# 落点：**`zthl/acp/amp.py`（规范层）+ `zthl/acp/amp_bridge.py`（采集层）** ——
#   `zthl-harness-adapter` 计划 §2.7「AMP 兼容层」/ ZH2-H10 · ZH3-H14f；
#   六类日志分文件写 `<技能仓>/.zthl/amp/*.log`（`GK_AMP_DIR` 可覆盖；**不跟 Path.home()**，
#   因 hook 由 wsl bash 以 root 启动，家目录会漂到 /root；2026-10-26 实测踩中），
#   `LogRecord` schema 对齐 ACPs v2.2.0 §5.1.2。本 hook 只负责 **access 一类**。
# 逃生舱：`GK_AMP=0`（全局）或 `GK_ACCESS_LOG=0`（仅 access）关闭；`GK_AMP_DIR` 覆盖落点。
# 纪律：任何异常静默（遥测不得阻断调用）；记录**不含**命令正文/文件内容。
_PROC_T0 = time.time()


def _amp_access_record(tool: str, decision: str, reason: str, code: int) -> None:
    if os.environ.get("GK_ACCESS_LOG", "1") == "0":
        return
    try:
        root = str(Path(__file__).resolve().parent.parent)
        if root not in sys.path:
            sys.path.insert(0, root)
        from zthl.acp import amp, amp_bridge
        amp.emit(**amp_bridge.access(
            tool, decision, code, reason,
            duration_ms=(time.time() - _PROC_T0) * 1000.0,
        ))
    except Exception:
        pass


# ── ② 使能切片（§4.13.5「高并发②」，2026-09-25）：**会话身份出口** ──
# 病象（实测）：`session_id` 只在 PreToolUse **载荷**里（仅本进程可见），唯一出口是 `_run_cli`
#   的 env ⟹ **只达 Gate 4 子进程**；agent 自己跑的 CLI（`discover` / `finding` / `state-patch` …）
#   拿不到任何会话身份 ⟹ 会话平面（hook）与全局平面（agent）**分叉 = 两套账**。
# 出路（关键观察）：PreToolUse **先于**工具执行、且每次调用都触发 ⟹ 在此把「本次调用的 sid」
#   落到固定旁挂，**同一次工具调用内**启动的 CLI（如 RunCommand 里的 gatekeeper-cli.sh）即可
#   自解析到同一 sid（见启动块的 `GK_SESSION_ID` 自解析块）。载荷无 sid（老载荷 / 手工调用）
#   → 不写。原子（tmp + os.replace）⟹ 读者不会见到半行；失败静默（便利通道，不得拦死调用）。
_SESSION_FILE = SKILL_DIR / ".gatekeeper.session"


def _session_alias_path(payload_sid: str) -> Path:
    """载荷 sid → worktree token 的**别名分片**路径（2026-10-23，T6 销账用）。"""
    return _SESSION_FILE.parent / (_SESSION_FILE.name + ".alias." + (payload_sid or "x"))


def _write_session_alias(payload_sid: str, token: str) -> None:
    """把「载荷 sid ↔ worktree token」的同一性落盘（**失败静默**，便利通道）。

    背景（实测）：同一次对话有两个身份 —— 载荷 `session_id`（RunCommand 只能拿到它）与
    worktree token（Edit 计费记的是它，本机 = `budget-probe`）。T6 的 `unverified` 按
    `(session,node)` 分组 ⟹ verify 落到载荷桶、编辑记在 token 桶 ⟹ **永不销账**。
    """
    try:
        if not payload_sid or not token or payload_sid == token:
            return
        p = _session_alias_path(payload_sid)
        tmp = p.parent / (p.name + ".tmp")
        tmp.write_text(str(token).strip() + "\n", encoding="utf-8")
        os.replace(tmp, p)
    except Exception:  # noqa: BLE001 — 别名只是便利通道
        pass


def _read_session_alias(payload_sid: str) -> str:
    """读回 worktree token（无别名/坏文件 ⟹ 空串）。"""
    try:
        return _session_alias_path(payload_sid).read_text(encoding="utf-8").strip()
    except Exception:  # noqa: BLE001
        return ""


def _write_session_marker(sid: str, tool: str, cwd: str) -> None:
    """把本次 PreToolUse 的会话身份写到 `<SKILL_DIR>/.gatekeeper.session`。

    单行 `sid<TAB>epoch<TAB>tool<TAB>cwd`（后两列仅供诊断；制表符/换行在值内消融为空格）。

    2026-10-01（会话隔离 finding，实测复现）：单槽会被**任意并发会话**覆写 ⟹ 本会话 CLI
      自解析拿到**外来 sid**，其 `.gatekeeper.plan.<sid>` 不存在 ⟹ 启动块**静默**回落默认
      state（写错账；实测 6 条入队 1→域 / 5→默认）。故除单槽（兼容面不变）外，另写**本 sid
      分片** `.gatekeeper.session.<sid>`：并发会话互不覆写，给「谁在何时写过 marker」留可诊断面。
      分片只增不改（是否新鲜由读者按 TTL 判，见 `gk_state_route.session_marker_status`）。
    """
    sid = (sid or "").strip()
    if not sid:
        return
    line = "%s\t%d\t%s\t%s\n" % (
        sid, int(time.time()), tool or "",
        (cwd or "").replace("\t", " ").replace("\n", " "))
    try:
        tmp = _SESSION_FILE.parent / (_SESSION_FILE.name + ".tmp")
        tmp.write_text(line, encoding="utf-8")
        os.replace(tmp, _SESSION_FILE)
    except Exception:  # noqa: BLE001
        pass
    # 2026-10-01：分片留痕（失败静默 —— 便利/诊断通道，不得拦死调用）。
    try:
        shard = _SESSION_FILE.parent / (_SESSION_FILE.name + "." + sid)
        tmp2 = shard.parent / (shard.name + ".tmp")
        tmp2.write_text(line, encoding="utf-8")
        os.replace(tmp2, shard)
    except Exception:  # noqa: BLE001
        pass


# ═══════════ 工具失效→提权绕过 三层防线（2026-09-02 用户需求）═══════════
# 场景: Edit/Write 写 X 被 BLOCK → agent 放弃重试，改用 RunCommand `echo > X` 直写同一文件
#       （绕过 Gate3 工作树包含 / Gate8 技能自维护 / CLI pre-tool-check = 权限边界越权）。
# 三层: ① 门控（工具选择前）= 既有 R0-R8 按工具门控；② 检测（行为偏离）= 被禁意图持久化
#       state gate_data.hook_block_log（本文件 _record_block_intent）+ cmd_monitor 快照出
#       「提权链」报告（monitor --local/api + audit --hook 消费 _block_log_snapshot）；
#       ③ 拦截（权限边界）= RunCommand 重定向写命中最近被禁 EDIT 目标 → BLOCK（Gate R0.5）。
_BLOCK_LOG_MAX = 24            # ring 上限
_BLOCK_LOG_TTL_S = 1800        # 意图有效窗口（30min，对齐 plan 指针 TTL 量级）
_CALL_TOOL = ""                # 本次调用上下文（main() 开头设置，block() 记录意图用）
_CALL_TARGET = ""
_CALL_CMD = ""
_CALL_KIND = "block"           # block | escalation（escalation = 行为偏离检测的关键信号）
_CALL_REASON = ""
_CALL_IN_SCOPE = False         # 治理范围内才记录（scope_out 普适 BLOCK 不入技能 state）
# 2026-09-25（编辑预算**按会话隔离**，用户裁定「预算控制应该被隔离开，并发会话也不应该和这边抢」）：
#   Trae 的 PreToolUse 载荷实测带 `session_id`（形态 = 24 位十六进制，本仓此前未读）——
#   它是「会话」这一隔离维度的**唯一可得**键（全仓无其他 session 概念）。取之透传给 CLI
#   （见 `_run_cli` 的 `GK_SESSION_ID`），使 Gate 4 的 edit_budget 按会话分别计数。
_SESSION_ID = ""


def _as_float(v) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _block_log_snapshot(state_path: str = "") -> dict:
    """state gate_data.hook_block_log 快照（TTL 窗口内统计 + 提权链明细）。
    cmd_monitor --local / gk_monitor_api / audit --hook / 测试共用单一事实源；
    读失败/无日志/字段损坏 → 全零（检测层只读，绝不因日志问题阻塞工具）。"""
    out = {"blocks": 0, "escalations": 0, "chains": []}
    try:
        d = json.loads(Path(state_path or str(STATE_FILE)).read_text(encoding="utf-8"))
    except Exception:
        return out
    recs = (d.get("gate_data") or {}).get("hook_block_log")
    if not isinstance(recs, list):
        return out
    now = time.time()
    for r in recs:
        if not isinstance(r, dict) or not _as_float(r.get("ts")):
            continue
        if now - _as_float(r.get("ts")) > _BLOCK_LOG_TTL_S:
            continue
        out["blocks"] += 1
        if r.get("kind") == "escalation":
            out["escalations"] += 1
            out["chains"].append({"tool": r.get("tool", ""), "target": r.get("target", ""),
                                  "reason": (r.get("reason") or "")[:120]})
    out["chains"] = out["chains"][-5:]
    return out


def _record_block_intent() -> None:
    """BLOCK 意图持久化 → state gate_data.hook_block_log（ring + TTL；_checksum 内联重算，
    算法对齐 gk_state._write_state：sha256(json.dumps(gate_data, sort_keys, ensure_ascii))[:16]）。
    仅治理范围内（_CALL_IN_SCOPE）且 _CALL_TOOL 已知且 state 可解析时写入；
    任一步失败静默——BLOCK 语义由 exit 2 保证，不因审计日志拖累。
    Q3（hook-xenv §15.3-Q3）：ring 之外**同步 append 持久 JSONL**（`_record_block_persistent`）——
    ring 24 条/30min TTL 结构上产不出长期率 ⟹ 误报率分母改用持久源。"""
    rec = None
    if not _CALL_IN_SCOPE or not _CALL_TOOL:
        return
    # 2026-09-25（选项 A）：读-改-写整体持 `state_lock` —— 本函数**每次 BLOCK 都触发**，
    #   多会话并发下「先读后写」会互相覆盖 `hook_block_log`（同款丢更新机理）。
    try:
        sp = Path(str(STATE_FILE))
        if not sp.exists():
            return
        with state_lock(sp):
            d = json.loads(sp.read_text(encoding="utf-8"))
            gd = d.setdefault("gate_data", {})
            now = time.time()
            log = [r for r in (gd.get("hook_block_log") or [])
                   if isinstance(r, dict) and (now - _as_float(r.get("ts"))) <= _BLOCK_LOG_TTL_S]
            rec = {"ts": round(now, 3), "tool": _CALL_TOOL, "target": _CALL_TARGET,
                   "cmd": (_CALL_CMD or "")[:160], "kind": _CALL_KIND,
                   "reason": (_CALL_REASON or "")[:160]}
            log.append(rec)
            gd["hook_block_log"] = log[-_BLOCK_LOG_MAX:]
            gate_dump = json.dumps(gd, sort_keys=True, ensure_ascii=True)
            d["_checksum"] = hashlib.sha256(gate_dump.encode()).hexdigest()[:16]
            dump_state(sp, d)
    except Exception as e:
        # ECC-6B5775F09911（2026-09-27）：原先此处是裸 `except Exception: pass` —— 把
        #   **state 锁获取失败**（`state_lock` 抛 TimeoutError）连同一切异常**静默吞**，
        #   且 `rec` 在 `with` 块内赋值 ⟹ 抛错时 `rec is None` ⟹ 下方持久源也不写
        #   ⟹ 「0 命中」**不能**排除静默超时（base lock 争用不可观测）。
        #   修法 = **只加可观测落点**：`rec` 构造/`with` 内逻辑/`_record_block_persistent`
        #   的调用条件一字不动，BLOCK 语义（调用方 exit 2）不变。
        _record_lock_timeout(type(e).__name__, str(e)[:160])
    # Q3-①：持久 JSONL 在 state_lock **之外**追加（O_APPEND 单次 write 自身原子，
    #   不持 state 锁做文件 IO）；即便 state 写失败，持久源也独立成立。
    if rec is not None:
        _record_block_persistent(rec)


def _persistent_block_dir(state_path: str = "") -> Path:
    """持久化块日志目录 = **state 同目录**/hook-block/（域隔离随 state 天然成立）。"""
    return Path(state_path or str(STATE_FILE)).parent / "hook-block"


def _record_lock_timeout(err_type: str, err_msg: str, state_path: str = "") -> None:
    """ECC-6B5775F09911：`state_lock` 获取失败（TimeoutError）等异常的**可观测落点**。

    病象：`_record_block_intent` 尾部 `except Exception: pass` 把 state 锁超时静默吞，
    且 `rec` 在 `with state_lock(sp):` **块内**赋值 ⟹ 抛错时 `rec is None` ⟹
    其后的 `_record_block_persistent(rec)` 亦不写 ⟹ 该路径上 **ring 与持久源双丢**。
    后果：「0 命中」**不能**排除静默超时 ⟹ base lock 争用不可观测。

    本函数只补**可观测**（append 一条 JSONL 到 `<hook-block>/lock-timeout.jsonl`），
    **不改** BLOCK 语义（`exit 2` 由调用方保证）、**不改** `rec` 构造/调用条件。
    **必须 fail-quiet**：可观测落点自身失败不得抛、不得升权（与 `_record_block_persistent`
    同款纪律——取证副产品绝不因日志问题影响工具调用）。
    """
    try:
        d = _persistent_block_dir(state_path)
        d.mkdir(parents=True, exist_ok=True)
        line = json.dumps({"ts": round(time.time(), 3), "err": err_type, "msg": err_msg,
                           "tool": _CALL_TOOL, "target": _CALL_TARGET},
                          ensure_ascii=False, sort_keys=True) + "\n"
        with open(str(d / "lock-timeout.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(line)
    except Exception:
        pass  # 有意 fail-quiet（可观测落点失败不得影响 BLOCK 语义）


def _record_block_persistent(rec: dict, state_path: str = "") -> None:
    """Q3-①：BLOCK 记录 append 到持久 JSONL（按天滚动 `<YYYYMMDD>.jsonl`）。

    用途 = 误报率列的**标注源/分母**（hook-xenv §13.1/§15.3-Q3：ring 24 条/30min TTL
    结构上产不出长期率，判别臂实测 ring 与持久源计数差 > 0）。
    原子性 = `O_APPEND` 单次 `write`（单行 <4KB，POSIX 追加原子）⟹ 并发 hook 进程不撕裂。
    **有意 fail-quiet**：本日志是取证副产品，写失败不升权、不阻断（ring 仍在 state）；
    此处静默是**声明过的设计选择**，非吞错（与 `_record_block_intent` 同款纪律）。
    """
    try:
        import datetime as _dt
        day = _dt.datetime.fromtimestamp(_as_float(rec.get("ts")) or time.time()).strftime("%Y%m%d")
        d = _persistent_block_dir(state_path)
        d.mkdir(parents=True, exist_ok=True)
        line = (json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        fd = os.open(str(d / ("%s.jsonl" % day)), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line)
        finally:
            os.close(fd)
    except Exception:
        pass  # 有意 fail-quiet（见 docstring）


def _persistent_block_count(state_path: str = "", window_s: float | None = None) -> int:
    """持久源计数（Q3 判别臂：同窗内 ring 计数 vs 持久源计数，差 > 0 ⟹ ring 不可作长期分母）。

    单一事实源：读与写同在本文件（禁测试侧第二实现重读文件）。"""
    import datetime as _dt
    base = _persistent_block_dir(state_path)
    if not base.is_dir():
        return 0
    total = 0
    now = time.time()
    for f in sorted(base.glob("*.jsonl")):
        if f.name == "lock-timeout.jsonl":
            continue  # 分账：锁超时**不是 block 样本**（ECC-6B5775F09911），不进误报率分母
        try:
            for ln in f.read_text(encoding="utf-8").splitlines():
                if not ln.strip():
                    continue
                try:
                    r = json.loads(ln)
                except ValueError:
                    continue
                ts = _as_float(r.get("ts"))
                if window_s is not None and ts and (now - ts) > window_s:
                    continue
                total += 1
        except OSError:
            continue
    return total


def _norm_target(p: str, cwd: str) -> str:
    """路径归一化为一致匹配键：win→wsl、\\→/、去尾斜杠、小写。"""
    try:
        if not os.path.isabs(p):
            p = os.path.join(cwd, p)
        return _win_to_wsl(p).replace("\\", "/").rstrip("/").lower()
    except Exception:
        return (p or "").replace("\\", "/").rstrip("/").lower()


def _shell_write_targets(command: str) -> list:
    """RunCommand 重定向/PS 写目标路径提取（>X >>X tee X | Set-Content X | Out-File X 等）。"""
    import re as _re
    hits = []
    for m in _re.finditer(r'(?:>>|>)\s*(?:&\s*)?([^\s;&|<>"\']+)', command):
        t = m.group(1)
        if t in ("/dev/null", "nul", "NUL") or t.startswith(("<", "(")):
            continue
        hits.append(t)
    for m in _re.finditer(r'(?:Set-Content|Out-File|Add-Content)\s+(?:-Path\s+)?["\']?([^\s;"\']+)',
                          command, _re.IGNORECASE):
        hits.append(m.group(1))
    return hits


def _escaped_write_after_block(command: str, cwd: str) -> str | None:
    """③ 权限边界拦截判定：RunCommand 重定向写目标命中「TTL 窗口内被 BLOCK 的 EDIT 写意图
    （state gate_data.hook_block_log，kind=block 且 tool ∈ EDIT_TOOLS）」→ 返回提权绕过 reason。
    即「Edit 写 X 被禁 → 放弃重试 → shell 直写同文件」的越权链。命中由调用方 block() 收口。"""
    try:
        d = json.loads(Path(str(STATE_FILE)).read_text(encoding="utf-8"))
    except Exception:
        return None
    recs = (d.get("gate_data") or {}).get("hook_block_log")
    if not isinstance(recs, list):
        return None
    now = time.time()
    blocked = []
    for r in recs:
        if not isinstance(r, dict) or not _as_float(r.get("ts")):
            continue
        if now - _as_float(r.get("ts")) > _BLOCK_LOG_TTL_S:
            continue
        if r.get("kind") == "block" and r.get("tool") in EDIT_TOOLS and r.get("target"):
            blocked.append((str(r["target"]), str(r.get("reason") or "")))
    if not blocked:
        return None
    for tgt in _shell_write_targets(command):
        tn = _norm_target(tgt, cwd)
        if not tn:
            continue
        for bt, reason in blocked:
            if bt.replace("\\", "/").rstrip("/").lower() == tn:
                return (f"工具失效→提权绕过: {bt} 已被编辑工具 BLOCK（{reason[:60]}），"
                        f"禁止经 RunCommand 重定向直写同文件 — 须修复后重试原工具或走 CLI 正规通道")
    return None

# Tools that need file-path validation
# Must match .trae/settings.json matcher: "SearchReplace|Write|Edit|CreateFile|DeleteFile|RunCommand"
EDIT_TOOLS = {"SearchReplace", "Write", "Edit", "CreateFile", "DeleteFile"}

# Tools that need path-scope validation (read-only exploration)
# 单一数据源：只读工具 → 目标路径字段（按优先级取第一个非空）。
# 新增只读工具只需在此加一行，SCOPE_TOOLS 自动派生，Gate 5/6/7 通用循环自动覆盖；
# check_tool_cfg.py（挂 self-check）守护本派生关系不被手写集合破坏。
SCOPE_PATH_MAP: dict[str, tuple[str, ...]] = {
    "Read": ("file_path",),
    "Glob": ("path", "pattern"),
    "Grep": ("path", "pattern"),
    "LS":   ("path",),
}
SCOPE_TOOLS = frozenset(SCOPE_PATH_MAP)

# ── MCP 写工具身份归一（`ECC-BC63B84B28AB`：MCP 写工具并入写面闸）────────────────
# 动机（实测）：MCP 写工具经 `run_mcp` / `mcp__<server>__<tool>` **两形态**到达 hook
#   （两形态在 `.gatekeeper.hook.log` 均有真实 `event=PreToolUse` 派发记录），而写类判定
#   只认 `EDIT_TOOLS` ⟹ **不归一即落空**（绕过 Gate 3 写面包含 / Gate 4 `edit_budget` /
#   `R0.8` 密钥闸，= A8「无旁路」冲突）。
# 纪律：**只做身份归一**，判定全部下沉给既有 Gate（Gate 3 + Gate 4 → CLI `pre-tool-check`
#   → `gk_edit_gate.py` 单源）；本段**不复制任何判定**，也不新增第二套判据。
# 写动词表：按 `_` 切分工具名，任一 token 命中即判写类。**不用正则** —— 本模块模块级
#   未导入 `re`（既有约定 = 函数内局部 import），用元组 ⟹ 零新增导入。宁少勿多：
#   只收**改写磁盘**的动词；误收只读工具名 = 误拦（摩擦）。
MCP_WRITE_VERBS = frozenset((
    "write", "edit", "create", "delete", "remove", "move", "rename", "mkdir", "rmdir",
    "apply", "patch", "truncate", "chmod", "chown", "copy", "sync", "upload", "put"))


def _mcp_inner_tool(tool_name, tool_input):
    """MCP 调用的 `(内层工具名, 内层参数字典)`；非 MCP 调用 → `(None, None)`。

    **写面 / 命令面共用**（`_write_identity` 与 `_cmd_identity` 同源，禁第二份解析）。
    两形态（均有真实派发记录）：
      · `run_mcp`：内层工具名在 `tool_input["tool_name"]`，参数在 `tool_input["args"]`；
      · `mcp__<server>__<tool>`：`split("__", 2)` 第 3 段为内层工具名，参数即 `tool_input`。
    """
    if tool_name == "run_mcp":
        return str(tool_input.get("tool_name") or ""), (tool_input.get("args") or {})
    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__", 2)
        inner = parts[2] if len(parts) == 3 else parts[-1]
        # 2026-10-02 真机实测（DBG）：直呼形态参数**也在** `tool_input["args"]` 下（`top_keys=['args']`，
        #   与 `run_mcp` 同构）；原假设「参数即 `tool_input` 本体」与真机不符 ⟹ 取不到路径/命令。
        #   本函数**写面/命令面共用** ⟹ 一处修正两面对齐；兼容无 `args` 包裹的顶层形态（测试夹具）。
        _a = tool_input.get("args")
        return inner, (_a if isinstance(_a, dict) else tool_input)
    return None, None


def _mcp_write_path(args):
    """写类 MCP 调用的目标路径（取第一个非空）；**取不到 → 空串**（调用方须 fail-closed）。"""
    v = args.get("path") or args.get("file_path")
    if not v:
        ps = args.get("paths")
        v = ps[0] if isinstance(ps, list) and ps else ""
    return str(v or "")


def _write_identity(tool_name, file_path, tool_input):
    """→ `(规范工具名, 目标路径)`；非 MCP / 非写类 → `(tool_name, file_path)` **恒等**。

    `GK_MCP_WRITE_GATE=0` ⟹ 恒等（回退面 = 变更前行为）。

    2026-10-13（`ECC-317C82A14DE8` G3）：原式**一律**归成 `Write` ⟹ filesystem MCP 的 `edit_file`
    （**局部编辑**语义）被 CLI 当**整文件覆盖**拦（实测 hook BLOCK「禁止整体覆盖已存在文件…
    请改用 Edit/SearchReplace」）⟹ **MCP 写工具对已存在文件实际不可用**（用户 2026-09-28 换写工具的
    初衷落空）。现按**内层语义**细分：局部编辑类（`edit*`）→ `SearchReplace`；整文件写类 → `Write`。
    """
    if tool_name in EDIT_TOOLS or os.environ.get("GK_MCP_WRITE_GATE", "1") == "0":
        return tool_name, file_path
    inner, args = _mcp_inner_tool(tool_name, tool_input)
    if not inner or not (set(inner.lower().split("_")) & MCP_WRITE_VERBS):
        return tool_name, file_path
    _name = "SearchReplace" if "edit" in inner.lower().split("_") else "Write"
    return _name, _mcp_write_path(args or {})


# ── MCP 命令执行器身份归一（`ECC-8F128D27B3E1`：MCP 命令执行器并入 shell 安全面）──────
# 动机（实测）：Gate R0 家族（R0.1 引号陷阱 / R0.2 危险命令 / R0.3 脚本内容 / R0.4 插件裸调用 /
#   R0.6 PS / R0.7 WSL / R0.8 明文密钥 / R0.9 windows-git 写）**全部**挂在
#   `tool_name == "RunCommand"` 分支内（范围外 L2824 / 范围内 L2926），而 MCP 命令执行器
#   （`mcp__windows-cli__execute_command` / `ssh_execute` / `run_mcp` 包裹）从不进该分支
#   ⟹ **shell 面整体旁路**（与 `ECC-BC63B84B28AB` 同族 A8，但覆盖面更宽：不是"写哪个文件"，
#   而是"执行任意命令"）。
# 纪律：**只做身份归一**（→ `("RunCommand", cmd)`），判定全部下沉给既有 R0 家族单源。
# 位点纪律：必须**先于** `scope_out` 判定 —— R0 是"普适 gate，范围外也执行"；若放到写类归一那行
#   （`file_path` 提取后）就太晚，范围外的 MCP 执行器仍漏。
# 白名单 = **精确等值**（描述符实测：windows-cli `execute_command` `{shell,command,workingDir}` /
#   `ssh_execute` `{connectionId,command}`）。**禁用 token 交集** —— 否则只读工具
#   `get_command_history` 会因 token `command` 被误收（误拦）。
# 显式排除：`Exec`（integrated_code_mode：隔离 JS 运行时，非 shell；且其可编程调用工具 ⟹ 另案）
#   / `puppeteer_evaluate`（浏览器内 JS，非 shell）。
MCP_EXEC_TOOLS = frozenset((
    "execute_command", "ssh_execute",                                   # windows-cli（描述符实测）
    "run_command", "runcommand", "shell", "shell_exec", "bash",         # 通用 shell 执行器命名
    "powershell", "pwsh", "cmd", "terminal", "run_cmd", "exec_shell"))

# 命令串候选键（按优先级取第一个非空串）；再退 `args`/`argv` 列表拼接。
MCP_CMD_KEYS = ("command", "cmd", "script", "command_line", "cmdline")


def _mcp_cmd_str(args):
    """执行类 MCP 调用的命令串（取不到 → 空串；调用方须 fail-closed）。"""
    for k in MCP_CMD_KEYS:
        v = args.get(k)
        if isinstance(v, str) and v.strip():
            return v
    for k in ("args", "argv"):
        a = args.get(k)
        if isinstance(a, list) and a:
            return " ".join(str(x) for x in a)
    return ""


# ── Gate R0.15 蓝鳍瞭望观测准入（2026-11-01）────────────────────────────────
# 防非法偷窥：默认只许「本侧 + 脱敏」；`--reveal`（回显身份字面量全文）与 `--cross-side`
# （观测 ~/.codebuddy / ~/.codex）属跨边界观测 ⟹ 需 GK_WATCH_APPROVED=1 显式批准。
# 每次命中都落访客记录（allow/deny 都记）；判定单源 = `_watch_gate`。
WATCH_RE = re.compile(r"(gk_watch\.py|state\s+--watch)")
WATCH_APPROVE_ENV = "GK_WATCH_APPROVED"


def _watch_gate(cmd: str) -> dict:
    cmd = str(cmd or "")
    if not WATCH_RE.search(cmd):
        return {"matched": False}
    approved = str(os.environ.get(WATCH_APPROVE_ENV, "")).strip() in ("1", "true", "yes")
    reveal = "--reveal" in cmd
    cross = "--cross-side" in cmd
    scope = "cross-side" if cross else "own"
    if approved:
        return {"matched": True, "allow": True, "reason": "approved", "scope": scope,
                "reveal": reveal}
    if reveal:
        return {"matched": True, "allow": False, "scope": scope, "reveal": True,
                "reason": ("WATCH_GATE: `--reveal` 会回显身份字面量全文 ⟹ 需 "
                           "GK_WATCH_APPROVED=1 显式批准；默认脱敏已足够 OS-6 判读")}
    if cross:
        return {"matched": True, "allow": False, "scope": scope, "reveal": reveal,
                "reason": ("WATCH_GATE: `--cross-side` 观测另一侧目录（~/.codebuddy / ~/.codex）"
                           " ⟹ 需 GK_WATCH_APPROVED=1；本侧观测直接 `state --watch`")}
    return {"matched": True, "allow": True, "reason": "own-scope masked", "scope": scope,
            "reveal": reveal}


def _watch_log_path() -> str:
    r"""访客记录落点单源：与 state 同目录（与 CLI `state --watch` 同落点）。

    不落 hook 的 cwd —— hook cwd = 调用方工作目录（可能是任意项目根/只读目录），
    会把日志打散到各项目、污染无关仓库，且 OSError 被吞 ⟹ 静默丢记录。
    """
    root = os.environ.get("GK_SKILL_DIR") or str(SKILL_DIR)
    return os.path.join(root, ".gatekeeper.state.watch-log.jsonl")


def _record_watch_visit(gate: dict, cwd: str) -> None:
    import getpass
    import platform
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "event": "observe-hook", "decision": "allow" if gate["allow"] else "deny",
           "reason": gate["reason"], "scope": gate.get("scope"), "reveal": gate.get("reveal"),
           "cmd": str(_CALL_CMD or "")[:300], "cwd": cwd, "tool": "RunCommand",
           "user": os.environ.get("USER") or os.environ.get("USERNAME") or getpass.getuser(),
           "host": platform.node(), "pid": os.getpid(),
           "agent_id": os.environ.get("GK_AGENT_ID") or "unsigned"}
    try:
        with open(_watch_log_path(), "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _cmd_identity(tool_name, tool_input):
    """→ `(规范工具名, 命令串)`；非 MCP / 非执行器 → `(tool_name, "")` **恒等**。

    `GK_MCP_EXEC_GATE=0` ⟹ 恒等（回退面 = 变更前行为）。
    """
    if os.environ.get("GK_MCP_EXEC_GATE", "1") == "0":
        return tool_name, ""
    inner, args = _mcp_inner_tool(tool_name, tool_input)
    if not inner or inner.lower() not in MCP_EXEC_TOOLS:
        return tool_name, ""
    return "RunCommand", _mcp_cmd_str(args or {})


# ── Gate R0.14【蓝色大肥鱼与章鱼浏览器之间不得不说的故事：单出网口闸】
#    （`ECC-6007804DD7BD`，2026-10-10；2026-10-11 扩 octop-browser `browser_*` 前缀名 `ECC-96B2214FA16B`）──
# 契约（**单一事实源 = `scripts/gk_evidence.py` L5**）：**单出网口** —— 一切出网走
#   `subagent_runner._prior_art_fetch`，主 agent 取回后按证据契约构造记录经 `GK_WEB_EVIDENCE`
#   注入（可复算 / 可审计）。
# 病象：浏览器 MCP 工具的**导航/取网**动词既不进写面（`MCP_WRITE_VERBS`）也不进命令面
#   （`MCP_EXEC_TOOLS`，其**精确等值**白名单只收 shell 执行器）⟹ 到达 hook 却**无任何面认领**
#   ⟹ 构成**第二条出网通道**（无 URL 台账、无证据注入、R0 家族整体旁路）= A8「无旁路」冲突。
# 纪律（对齐 `ECC-BC63B84B28AB` / `ECC-8F128D27B3E1`）：**只做身份归一**（→ 哨兵名），
#   判定下沉为本闸单点；**精确等值**（禁 token 交集 —— 否则只读的 `dom_tree`/`screenshot`
#   会因 token 被误收；`click`/`type`/`fill`/`select`/`hover` 是**本地页面操作非出网**，故**不收**）。
# 2026-10-11（**方案 A**，`ECC-BB4E8FF782F0`）：本闸由「整体 BLOCK」扩为**受治出网车道** ——
#   白名单域（`MCP_EGRESS_ALLOWLIST`）**放行 + egress 记账**；域外仍 BLOCK；并显式封
#   `evaluate`/`eval_js`（JS 内 `fetch` 出网残余，`ECC-6E292BFBABEC`）。UI 自动化改走**本地页面
#   操作**动词（`click`/`type`/... 仍不收）。
# 逃生舱：`GK_MCP_EGRESS_GATE=0` ⟹ 恒等（回退面 = 变更前行为）。
MCP_EGRESS_GATE_NAME = "蓝色大肥鱼与章鱼浏览器之间不得不说的故事【单出网口闸：浏览器出网未走 _prior_art_fetch】"
MCP_EGRESS_TOOLS = frozenset((
    "navigate", "navigate_to", "goto", "go_to", "page_goto", "open_url",
    "fetch", "request", "http_get", "get_url", "download",
    # 2026-10-11（`ECC-96B2214FA16B`）：octop-browser（TencentCloud/octop-browser）的 MCP
    #   工具名**带 `browser_` 前缀**（`browser_navigate`/`browser_open`/…），与上面**裸动词**
    #   精确集不匹配（`_mcp_inner_tool` 不做前缀剥离）⟹ 曾**整体漏网** = 第二条未受治出网通道。
    #   此处按**精确名**补入其导航/取网动词（仍禁 token 交集，只收会**加载远端页**的动作）。
    "browser_navigate", "browser_open", "browser_new_tab", "browser_replay_run"))
MCP_EGRESS_URL_KEYS = ("url", "uri", "href", "target", "address")
# 受治车道允许域 —— **单源** = `gk_evidence.PRIOR_ART_HOSTS`（与 `_prior_art_fetch` 同源，禁第二份）。
import gk_evidence as _gk_evidence  # noqa: E402（同目录轻量单源）

MCP_EGRESS_ALLOWLIST = frozenset(_gk_evidence.PRIOR_ART_HOSTS)
MCP_EGRESS_ALLOWED = "McpEgressAllowed"    # 受治车道放行哨兵（调用点据此记账 + 放行）
MCP_EGRESS_SEALED = "McpEgressSealed"      # 封禁哨兵（调用点据此 BLOCK）
MCP_EGRESS_SEALED_TOOLS = frozenset((      # JS 内 fetch = 出网残余 ⟹ 封
    "evaluate", "eval_js", "evaluate_handle", "evaluate_function", "eval",
    "browser_eval_js"))                    # octop-browser 前缀名（`ECC-96B2214FA16B`）


def _egress_url(args):
    """从 MCP 内层参数取目标 URL（按 `MCP_EGRESS_URL_KEYS` 优先序；取不到 → 空串）。

    2026-10-11（`ECC-96B2214FA16B`）：octop-browser 的 `browser_open` 走 **`urls`（列表）**
      ⟹ 取首元素（认领为出网即可；多 URL 的逐域判定仍归调用点 allowlist）。
    """
    for k in MCP_EGRESS_URL_KEYS:
        v = (args or {}).get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    urls = (args or {}).get("urls")
    if isinstance(urls, list):
        for v in urls:
            if isinstance(v, str) and v.strip():
                return v.strip()
    return ""


def _egress_host(url):
    """URL → 小写 host（解析失败 → 空串 ⟹ 调用点 fail-closed）。"""
    try:
        from urllib.parse import urlparse
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001 — 边界：解析失败 ⟹ 空（fail-closed）
        return ""


def _record_mcp_egress(host, url):
    """浏览器受治车道出网记账（单源 `gk_evidence.record_egress`；fail-soft 不阻断放行）。"""
    try:
        _gk_evidence.record_egress(host, url, ok=True, via="mcp-browser")
    except Exception:  # noqa: BLE001 — 记账失败不阻断（对齐 prior-art 留痕 fail-soft）
        pass


def _egress_identity(tool_name, tool_input):
    """→ `(规范工具名, 目标 URL)`；非 MCP / 非出网类 → `(tool_name, "")` **恒等**。

    `GK_MCP_EGRESS_GATE=0` ⟹ 恒等（运维逃生舱）。命中三档（哨兵名 ≠ 原 tool_name）：
      · `McpEgressSealed` —— `evaluate`/`eval_js`（JS 内 fetch 残余）⟹ 调用点 BLOCK；
      · `McpEgressAllowed` —— 目标 host ∈ `MCP_EGRESS_ALLOWLIST` ⟹ 调用点**放行 + 记账**；
      · `McpEgress`       —— 其余出网动词 ⟹ 调用点 BLOCK（域外 / URL 不可解析）。
    URL 取不到 → 空串（调用点标 `<未解析>`；非白名单 ⟹ 仍拒，fail-closed）。
    """
    if os.environ.get("GK_MCP_EGRESS_GATE", "1") == "0":
        return tool_name, ""
    inner, args = _mcp_inner_tool(tool_name, tool_input)
    if not inner:
        return tool_name, ""
    low = inner.lower()
    if low in MCP_EGRESS_SEALED_TOOLS:
        return MCP_EGRESS_SEALED, _egress_url(args)
    if low not in MCP_EGRESS_TOOLS:
        return tool_name, ""
    url = _egress_url(args)
    host = _egress_host(url)
    if host and host in MCP_EGRESS_ALLOWLIST:
        return MCP_EGRESS_ALLOWED, url
    return "McpEgress", url


# ── Gate R0.18【蓝色大肥鱼与章鱼浏览器工具面：install / record 写面闸】（2026-11-03）──
# 真机 25 工具实测：`install_browser` 会下载/安装 Chromium（网络 + 落盘）；
#   `browser_record_start/stop/generate_steps/generate_skill` 会把录像/技能写盘；
#   两者都不在 MCP_WRITE_VERBS / MCP_EXEC_TOOLS / R0.14 精确集里 ⟹ 原样可达。
# 本闸只拦这两类；本地读/UI（dom_tree/screenshot/click/type/fill/press/wait/tab/session）放行。
# 逃生舱：GK_MCP_ALLOW_BROWSER_INSTALL=1 / GK_MCP_ALLOW_BROWSER_RECORD=1（运维显式放行）。
BROWSER_TOOLFACE_GATE_NAME = "蓝色大肥鱼与章鱼浏览器工具面【install/record 写面闸】"
BROWSER_INSTALL_TOOL = "install_browser"
BROWSER_RECORD_WRITE_TOOLS = frozenset((
    "browser_record_start", "browser_record_stop",
    "browser_record_generate_steps", "browser_record_generate_skill"))
BROWSER_RECORD_READ_TOOLS = frozenset((
    "browser_record_doctor", "browser_record_status",
    "browser_record_list", "browser_record_show"))
BROWSER_LOCAL_UI_TOOLS = frozenset((
    "browser_dom_tree", "browser_screenshot", "browser_click", "browser_type",
    "browser_fill", "browser_press", "browser_wait", "browser_switch_tab",
    "browser_close_tab", "browser_list_tabs", "browser_close_session"))


def _browser_toolface_gate(tool_name, tool_input):
    """→ BLOCK 原因字符串；非 MCP / 非这两类 → 空串（恒等）。"""
    inner, _args = _mcp_inner_tool(tool_name, tool_input)
    if not inner:
        return ""
    n = inner.lower()
    if n == BROWSER_INSTALL_TOOL and os.environ.get(
            "GK_MCP_ALLOW_BROWSER_INSTALL", "0") != "1":
        return (BROWSER_TOOLFACE_GATE_NAME + ": `install_browser` 会下载/安装 Chromium"
                "（网络 + 落盘）。请手工执行 `octop-browser install-browser`；"
                "确需 agent 直调时显式设 GK_MCP_ALLOW_BROWSER_INSTALL=1。")
    if n in BROWSER_RECORD_WRITE_TOOLS and os.environ.get(
            "GK_MCP_ALLOW_BROWSER_RECORD", "0") != "1":
        return (BROWSER_TOOLFACE_GATE_NAME + f": `{inner}` 会把录像/技能写盘；"
                "确需 agent 直调时显式设 GK_MCP_ALLOW_BROWSER_RECORD=1。")
    return ""


def _wsl_quoting_trap(command: str) -> str | None:
    """检测 WSL 引号陷阱（PS 宿主展开 + 5.1 native arg mangling 两种机制）。命中返回 block 原因，安全返回 None。
    纯语法检测、无状态依赖 → 普适安全 gate（治理范围外也执行，2026-08-09）。
    对齐 wasm-pre-check.sh 分级拦截：本函数是 P0 层"转义陷阱拦截"。
    命中时的修复：用 wslsh -c '<原文>'（wslsh 自动落临时 .sh，内容不经过 wsl.exe 命令行）。

    ⚠ 机制口径（2026-10-30 校正，本机宿主 PS 7.6.4）：
      - **双引号形态** ⟹ PS **自己**展开 `$`/`$( )`/反引号、并把 `<` 当重定向 —— 这是 PS 的字符串
        语义，**与版本无关**（5.1/7.x 都如此），不是引号 bug；
      - **单引号内含内嵌引号** ⟹ PS 5.1 的 native arg mangling（剥内嵌引号）；**PS 7.3+ 已修**，
        但历史脚本/`wsl.exe` 直调仍需设防，故判据保留。
    """
    import re
    command_lower = command.lower()
    m = re.search(r"wsl(?:\.exe)?\s+(?:bash\s+)?-c\s*([\"'])", command)
    if m and "wslsh" not in command_lower:
        outer = m.group(1)
        inner = command[m.end():]
        if outer == '"':
            return ("double-quote payload is expanded by the PS host before wslsh sees it "
                    "($(), <, inner quotes; PS semantics, version-independent). "
                    "Fix: wslsh -c '<原文>' — wslsh 自动落临时 .sh，内容不经过 wsl.exe 命令行")
        if '"' in inner or '<<' in inner or '$(' in inner:
            return ("PS host strips embedded quotes in wsl bash -c "
                    "(PS 5.1 native-arg mangling; PS 7.3+ fixed the quoting, 判据保留以兼容历史脚本). "
                    "Fix: wslsh -c '<原文>' — wslsh 自动落临时 .sh，内容不经过 wsl.exe 命令行")
    return None


# ── Gate R0.6【蓝色大肥鱼与powershell之间不得不说的故事】(2026-09-14) ──
# 独立一类防线：**PS 宿主对任意 RunCommand 命令串的解析改写**（不限于 wsl 前缀形态）。
# 与 R0.1 `_wsl_quoting_trap` 平行、互不复用正则 —— R0.1 把「PS 吞噬」建模为**一种命令形态**
# （`wsl bash -c`），本闸建模为**宿主解析行为**（$ / << / 反引号 / [ ]）⟹ 覆盖面不同。
# 实证（2026-09-14 第五轮质询全程；三例均静默穿过当时**全部** gate）：
#   ① `bash -lc "...\$P..."` → PS 先展开 $P（该变量只在 bash 里）⟹ 吞掉/置空（--task 未被绑定）；
#   ② `git commit -m "$(cat <<'EOF' …)"` → PS ParserError: Missing file specification after
#      redirection operator（PS 无 heredoc 重定向）；
#   ③ `python -c "…[0-9.]+…"` → PS 按类型字面量解析 ⟹ Missing type name after '['。
BLUE_FAT_FISH_GATE_NAME = "蓝色大肥鱼与powershell之间不得不说的故事"
# [2026-10-06 · ECC-EE9B544B88EA] 原 fix 文案「bash 载荷改**单引号**（PS 不展开单引号内内容）」
#   **被实测证伪** —— 宿主层对单引号载荷内的裸 '$X' **照样展开**（静默置空）⟹ 换成实测可行的
#   三措：转义 '\$' / 避开 '$' / 落 .sh。
_PS_STORY_FIX = ("Fix: ① 需保留 '$' 者**转义**为 '\\$'（实测宿主吞反斜杠、bash 端照常求值）；"
                 "② 无需变量者避开 '$'，用**字面**路径/值；"
                 "③ heredoc / 多行 / 含变量 → 用 Write 落 .sh 后 bash <file>（文件内容不经宿主展开）；"
                 "④ 文件写入 → 用 Write/Edit 工具；⑤ 或 wslsh -c '<原文>'")


def _ps_story_single_quoted_spans(command: str) -> list:
    """PS 层**单引号**区间 [start,end)。PS 单引号内不做任何展开/转义 ⟹ 该区间安全。"""
    spans = []
    i, n = 0, len(command)
    while i < n:
        if command[i] == "'":
            j = command.find("'", i + 1)
            if j < 0:
                spans.append((i, n))
                break
            spans.append((i, j + 1))
            i = j + 1
        else:
            i += 1
    return spans


def _ps_story_in_spans(pos: int, spans: list) -> bool:
    return any(s <= pos < e for s, e in spans)


def _blue_fat_fish_ps_story(command: str) -> Optional[tuple]:
    """Gate R0.6 检测体：返回 (level, reason, hint)；level ∈ {"BLOCK","WARN"}；无命中 → None。

    P1 BLOCK `$`  在 bash/sh/zsh -…c… 的**双引号**载荷内（PS 先展开 ⟹ 目标拿到空/错值）
    P2 BLOCK `<<` 出现在单引号区外（PS 无 heredoc 重定向）
    P3 BLOCK 反引号 出现在单引号区外（PS 以反引号为转义符）
    P4 WARN  `-c`/`-e`/`--eval` 载荷含 `[`…`]`（PS 类型字面量；机理未完全复现 ⟹ 只告警，
             避免误伤 `[ -f x ]` 一类合法测试表达式）
    """
    import re
    if not command:
        return None
    sq = _ps_story_single_quoted_spans(command)

    # P1 —— bash -c/-lc 载荷含 '$'（bash 变量在宿主(PS)层被提前展开）
    #   · **双引号**载荷：任何 '$' 皆危险（含 '\$'：PS 视 '\' 为字面量后仍展开）⟹ BLOCK；
    #   · **单引号**载荷：**未转义** '$' 同样被宿主展开（'\\$' 可存活）⟹ BLOCK。
    # [2026-10-06 · ECC-EE9B544B88EA] 原 P1 **只**匹配双引号载荷，且把单引号当安全区
    #   ⟹ `bash -lc 'echo $X'` 实测被宿主展开成空（**静默置空、无报错**）= 跨宿主流程摩擦主因。
    m1dq = re.search(r"\b(?:bash|sh|zsh)\b[^|&;\n]*?\s(?<!-)-[a-zA-Z]{0,4}c[a-zA-Z]{0,4}\s+\"([^\"]*)\"",
                     command, re.DOTALL)
    if m1dq and "$" in m1dq.group(1):
        return ("BLOCK",
                "bash 双引号载荷含 '$' —— 宿主(PS)会先把 $var 展开再交给 bash（实测吞掉/置空）",
                _PS_STORY_FIX)
    m1sq = re.search(r"\b(?:bash|sh|zsh)\b[^|&;\n]*?\s(?<!-)-[a-zA-Z]{0,4}c[a-zA-Z]{0,4}\s+'([^']*)'",
                     command, re.DOTALL)
    if m1sq and re.search(r"(?<!\\)\$(?:[A-Za-z_{(]|[0-9])", m1sq.group(1)):
        return ("BLOCK",
                "bash 单引号载荷含未转义 '$' —— 宿主(PS)层**照样**展开（实测单引号并不安全："
                "`bash -lc 'echo $X'` 打成空）",
                _PS_STORY_FIX)

    # P2 —— '<<' 单引号区外
    for m2 in re.finditer(r"<<", command):
        if not _ps_story_in_spans(m2.start(), sq):
            return ("BLOCK",
                    "命令含 '<<' 且在单引号区外 —— PowerShell 无 heredoc 重定向"
                    "（实测 ParserError: Missing file specification after redirection operator）",
                    _PS_STORY_FIX)

    # P3 —— 反引号 单引号区外（\x60 避免本文件自匹配）
    for m3 in re.finditer(r"\x60", command):
        if not _ps_story_in_spans(m3.start(), sq):
            return ("BLOCK",
                    "命令含反引号且在单引号区外 —— PowerShell 以反引号为转义符（吞掉后一字符）",
                    _PS_STORY_FIX)

    # P4 —— '-c'/'-e'/--eval 双引号载荷含 '[...]'
    m4 = re.search(r"(?:^|\s)(?:--eval|--expression|-[a-zA-Z]*[ce][a-zA-Z]*)\s+\"((?:[^\"\\]|\\.)*)\"",
                   command)
    if m4 and "[" in m4.group(1) and "]" in m4.group(1):
        return ("WARN",
                "-c/-e 双引号载荷含 '[...]' —— PowerShell 可能按类型字面量解析"
                "（实测 ParserError: Missing type name after '['）",
                _PS_STORY_FIX)

    return None


# ── Gate R0.7【蓝色大肥鱼与wsl之间不得不说的故事】(2026-09-14) ──
# 独立一类防线：**wsl 家族入口**（wsl / wsl.exe / wslsh / WSLENV 注入面）的引号与编码陷阱。
# 与 R0.1（只认 `wsl[.exe] bash -c` 一种形态）互补，覆盖面：
#   W1 BLOCK —— `wslsh -c "…"` 的**双引号**载荷含 `$`/反引号。**关键认知**：wslsh 的
#      「落临时 .sh」只保护 **wsl.exe 命令行层**，**不保护 PowerShell 层** —— PS 在 wslsh
#      拿到参数**之前**就展开 `$var`、并以反引号为转义符（这是 PS 的字符串语义，**与 5.1/7.x
#      版本无关**；wslsh.ps1 自述「彻底绕开 native arg mangling」**仅在单引号下成立**，
#      故 `wslsh -c '<原文>'` 才是安全形态）。
#   W2 BLOCK —— `wsl` 的 `-c` 变体**未被 R0.1 正则覆盖**者（`wsl -e|--exec|-- bash -c "…"`）
#      载荷含内嵌 `"` / `$(` / `${`：与 R0.1 同机制（PS 宿主展开；单引号内嵌引号形态另属
#      PS 5.1 native-arg mangling，PS 7.3+ 已修但判据保留）。
#   W3 WARN  —— `WSLENV` 赋值中**敏感变量条目缺 `/u`**：WSL 对未标 `/u` 的值做**路径翻译**
#      （值含 `:` / `/` 时被改写）⟹ key 被破坏。敏感清单 = wslsh.ps1 注入面（L36 实测）。
#   W4 WARN  —— `wsl … bash <Windows 路径>`：WSL 侧不认 `C:\…`（须 `/mnt/c/…` 或走 wslsh）。
#   W5 WARN  —— `wsl[.exe] [--|-e|--exec] bash|sh` **无脚本参数**：脚本经 **stdin 管道**送入 ⟹
#      PS 在管道末尾补一个**裸 CR**（here-string 无结尾换行），CR 粘在**最后一个 token** 上；
#      末行为裸 `-N` 时参数被污染（实测 `git log --oneline -1` → `fatal: '1?': not a
#      non-negative integer`；`bash -x` 实证末参 `$'-1\r'`）。同命令走**脚本文件**（LF 落盘）
#      或末行补垫行则正常。（finding `ECC-2EB738051C82`，2026-10-01）
BLUE_FAT_FISH_WSL_GATE_NAME = "蓝色大肥鱼与wsl之间不得不说的故事"
_WSL_STORY_FIX = ("Fix: ① 内联 bash 改**单引号**（`wslsh -c '<原文>'`，PS 不展开单引号内内容）；"
                  "② 复杂/多行 → Write 落 .sh 后 `wslsh <file>`；"
                  "③ `WSLENV` 敏感条目一律加 `/u`（原样透传，禁路径翻译）；"
                  "④ Windows 路径写 `/mnt/c/…`（或交给 wslsh 自动转换）")
_WSLENV_SENSITIVE = ("DEEPSEEK_API_KEY", "MIMO_API_KEY", "GATEKEEPER_API_KEY", "STATE_FILE")


def _blue_fat_fish_wsl_story(command: str) -> Optional[tuple]:
    """Gate R0.7 检测体：返回 (level, reason, hint)；level ∈ {"BLOCK","WARN"}；无命中 → None。"""
    import re
    if not command:
        return None
    low = command.lower()

    # W1 —— wslsh -c 的**双引号**载荷含 '$' 或反引号
    m1 = re.search(r"\bwslsh(?:\.ps1|\.cmd)?\b[^|&;\n]*?\s(?:-c|-InlineCommand)\s+\"([^\"]*)\"",
                   command, re.DOTALL)
    if m1 and ("$" in m1.group(1) or "\x60" in m1.group(1)):
        return ("BLOCK",
                "wslsh 的 -c **双引号**载荷含 '$'/反引号 —— PS 在 wslsh 落文件**之前**就展开/转义"
                "（wslsh 的落盘保护只覆盖 wsl.exe 命令行层，不覆盖 PS 层）",
                _WSL_STORY_FIX)

    # W2 —— wsl -e/--exec/-- 形态的 -c 载荷：双引号包裹且含**内嵌引号** / `$(` / `${`
    # （该形态未被 R0.1 正则覆盖；单变量 `$` 场景已由 R0.6-P1 覆盖，故此处不重复）
    # 2026-09-24（ECC-… 修复）：载体正则原写死 `-c\s+` —— 而 `bash -lc '<载荷>'` 的
    #   **组合短选项 `-lc` 不含子串 `-c`**（字符序列 `-`,`l`,`c`）⟹ 正则**跳过外层载体**、
    #   向后锁到载荷**内层**的 `python -c "…"` ⟹ 两向后果：
    #     ① **误伤**（本会话实测被拦 3 次）：外层**单引号**载荷本就无风险（PS 不展开单引号
    #        内内容）却被判 PS mangling ⟹ 正常命令被 fail-closed 拦死；
    #     ② **漏网**：`wsl -e bash -lc "…$(…)"` 的**双引号**载荷是**真风险**（PS 会展开
    #        `$()`/`${}`）却**从不命中**（同一根因的沉默面）。
    #   修法：载体判据认「**以 c 结尾的短选项**」（含 `-lc`/`-ilc` 等组合形态），并用
    #   `(?<!-)` 排除长选项（`--exec` 自身以 c 结尾，不得被当成载荷载体）⟹ 非贪婪首选
    #   **最左**载体 = 真正的 shell `-c`。臂：test_pre_tool_hook.TestWslFamilyStory
    #   的 `single_quoted_inner_python_c_pass`（误伤）/ `double_quoted_payload_blocks`（漏网）。
    m2 = re.search(r"\bwsl(?:\.exe)?\s+(?:-e|--exec|--)\s+[^\n]*?(?<!-)-[A-Za-z]{0,4}c\s+(\S.*)",
                   command)
    if m2:
        _tail = m2.group(1).strip()
        if _tail.startswith('"') and (_tail.count('"') > 2 or "$(" in _tail or "${" in _tail):
            return ("BLOCK",
                    "wsl -e/--exec/-- 形态的 -c **双引号**载荷含内嵌引号或 $()/${} —— 与 R0.1 同机制"
                    "（PS 宿主在 wsl 拿到参数前就展开/剥引号；该形态**未被 R0.1 正则覆盖**）",
                    _WSL_STORY_FIX)

    # W3 —— WSLENV 敏感条目缺 /u
    if "wslenv" in low:
        for m3 in re.finditer(r"WSLENV\s*[=:]\s*['\"]?([^'\";|\n]*)", command):
            for part in re.split(r"[:;]", m3.group(1)):
                p = part.strip()
                if not p:
                    continue
                name = p.split("/", 1)[0].strip()
                if name in _WSLENV_SENSITIVE and "/u" not in p:
                    return ("WARN",
                            f"WSLENV 条目 {name} 缺 /u —— WSL 会对未标 /u 的值做路径翻译"
                            "（值含 : 或 / 时被改写）⟹ key 可能被破坏",
                            _WSL_STORY_FIX)

    # W4 —— wsl … bash <Windows 路径>
    if re.search(r"\bwsl(?:\.exe)?\s+(?:bash|sh)\s+[A-Za-z]:[\\/]", command):
        return ("WARN",
                "`wsl … bash <Windows 路径>` —— WSL 侧不认 `C:\\…`，须写 `/mnt/c/…`"
                "（或走 wslsh 自动转换）",
                _WSL_STORY_FIX)

    # W5 —— wsl … bash|sh **无脚本参数**（脚本走 stdin）：PS 在管道末尾补裸 CR，污染**最后一个
    #   token**。形态判据 = `bash`/`sh` 之后**只有空白**直到句末或裸分隔符；带脚本参数
    #   （`bash /mnt/…/x.sh` 或 `bash -lc '<载荷>'`）**不命中** —— 那是命令行传参，不经 stdin 管道。
    #   实测（2026-10-01，finding ECC-2EB738051C82）：末行裸 `-1` 被读成 `-1 + 裸CR` ⟹
    #   `fatal: '1?': not a non-negative integer`；`bash -x` 实证末参值为 $'-1\r'。
    if re.search(r"\bwsl(?:\.exe)?\s+(?:(?:-e|--exec|--)\s+)?(?:bash|sh)\s*(?:$|[|;&])",
                 command, re.MULTILINE):
        return ("WARN",
                "`wsl … bash|sh` 无脚本参数 —— 脚本经 **stdin 管道**送入，PS 会在末尾补一个**裸 CR**"
                "粘在**最后一个 token** 上（末行裸 `-N` 时参数被污染，实测 git 报 "
                "`fatal: '1?': not a non-negative integer`）",
                "Fix: ① 落 .sh 后 `wsl.exe -e bash /mnt/c/…/x.sh`（文件 LF 落盘，不经 stdin 管道）；"
                "② 或末行补垫行（`:` / `echo`），使裸 CR 落在垫行上")

    return None


# ── Gate R0.12【蓝色大肥鱼与PowerShell别名之间不得不说的故事】(2026-10-10) ──
# 独立一类防线：**PS 会话的别名劫持**。RunCommand 在 PS 上执行，`ls`/`cat`/`rm`/`cp`/`mv`/
#   `echo`/`curl`/`wget`/`ps`/`kill`/`head`/`tail`/`sort`/`mkdir` 等**全是 PS 别名**
#   （→ Get-ChildItem / Get-Content / Remove-Item / Copy-Item / Move-Item / Write-Output /
#   Invoke-WebRequest / Get-Process / Stop-Process / Select-Object / Sort-Object / New-Item），
#   其**参数语义与 POSIX 完全不同**：实测 `ls -d <path>` 被 PS 解析成
#   `Get-ChildItem -Depth <path>`（`-Depth` 只收整数）⟹ 报错 / 静默错值。
#   与 R0.6（PS 解析改写）/ R0.7（wsl 家族）**平行、互不复用正则** —— 本闸认
#   「**命令位别名 + POSIX 专属旗标**」。严格度：BLOCK（可静默错值，对齐 R0.6 P1-P3）。
BLUE_FAT_FISH_ALIAS_GATE_NAME = "蓝色大肥鱼与PowerShell别名之间不得不说的故事"
_PS_ALIAS_FIX = ("Fix: ① 交 `wsl` 执行 POSIX 语义（`wsl ls -la <path>`）；"
                 "② 或改用**原生 cmdlet / 专用工具**（`Get-ChildItem` / LS·Read·Grep 工具 / "
                 "`Remove-Item` / `Invoke-WebRequest -OutFile`）；"
                 "③ 显式 exe（`curl.exe`）虽绕别名，但仍是 Windows 版语义 ⟹ 首选 ①")
# 命令位别名 → 该别名在 POSIX 下常见、而 PS cmdlet **不接受**的旗标字母集（POSIX-only；大小写敏感）。
# finding `ECC-BC9FB99C4C93`（2026-10-13）：`mkdir` **不在**本表 —— 实测 Windows PowerShell 下
#   `mkdir -p <新嵌套路径>` 能建出嵌套目录、`-p` 被 `New-Item` 接受（前缀→`-Path`）⟹ 不满足
#   「PS 不接受」判据（对比真阳性 `ls -d` → `Get-ChildItem -Depth` 只收整数 ⟹ 静默错值）。留在
#   表中会让 **hook 自家建议过不了自家闸**（`mkdir -p` 恰是 R0.2 自动替换 hint 的形态，臂 C）。
#   `rmdir: "p"` **保留**：POSIX `rmdir -p` 删祖先后代 / PS `Remove-Item -Path` 只删叶子 ⟹ 静默语义分叉。
_PS_ALIAS_POSIX_FLAGS = {
    "ls": "ladhRtrS1CFA", "cat": "nbEsvA", "head": "nqcv", "tail": "nqfv",
    "rm": "rfRd", "cp": "rfRa", "mv": "fn", "echo": "ne",
    "curl": "oOLXHdkIsSvK", "wget": "OqcS", "rmdir": "p",
    "sort": "unr", "tee": "a",
}
# 少数「非字母旗标」形态（`ps aux` / `kill -9`）的整 token 判据。
_PS_ALIAS_SPECIAL = {"ps": ("aux", "-ef", "-e", "-f"), "kill": ("-9", "-s", "-kill")}


def _ps_alias_strip_quoted(command: str) -> str:
    """把 PS 引号区间（单/双引号，含 `\\` 转义）替换为**等长空格** —— 只暴露命令位 token。

    R0.12/R0.13 的判据须只看**命令位**（引号内是被传内容，不是命令）⟹ 先置空引号区间，
    再按分隔符切段取首 token。长度保持 ⟹ 可原样复用 `re` 的 `\\b` 边界语义。
    """
    out = list(command)
    i, n = 0, len(command)
    while i < n:
        ch = command[i]
        if ch in ("'", '"'):
            q = ch
            j = i + 1
            while j < n:
                if command[j] == "\\":
                    j += 2
                    continue
                if command[j] == q:
                    break
                j += 1
            for k in range(i, min(j + 1, n)):
                out[k] = " "
            i = j + 1
        else:
            i += 1
    return "".join(out)


def _blue_fat_fish_ps_alias_story(command: str) -> Optional[tuple]:
    """Gate R0.12 检测体：返回 (level, reason, hint)；命中命令位别名 + POSIX 旗标 → BLOCK。

    判据（须同时满足）：
      ① 命令**未被** `wsl`/`wslsh`/`bash`/`sh`/`zsh` 前缀包裹（那是 POSIX 语义，另闸覆盖）；
      ② 某个**命令位** token（段首，段按 `;`/`&`/`|`/换行 切、引号内置空）是 PS 别名；
      ③ 其后旗标 token `-<字母>` 的字母集与该别名的**POSIX 专属旗标**相交，或命中整 token 特判。
    """
    import re
    if not command:
        return None
    if re.match(r"^\s*(?:wsl(?:\.exe)?|wslsh(?:\.ps1|\.cmd)?|bash|sh|zsh)\b", command, re.I):
        return None
    masked = _ps_alias_strip_quoted(command)
    for seg in re.split(r"[;&|\n]+", masked):
        toks = seg.split()
        if not toks:
            continue
        head = toks[0].lower()
        flags = toks[1:]
        special = _PS_ALIAS_SPECIAL.get(head)
        if special and any(f.lower() in special for f in flags):
            return ("BLOCK",
                    f"命令位别名 `{head}` 带非字母旗标 —— PS 别名劫持"
                    f"（PS 会话里 `{head}` 是 cmdlet 别名，参数语义与 POSIX 不同）",
                    _PS_ALIAS_FIX)
        posix_only = _PS_ALIAS_POSIX_FLAGS.get(head)
        if not posix_only:
            continue
        letters = "".join(f[1:] for f in flags if re.match(r"^-[A-Za-z]+$", f))
        if letters and (set(letters) & set(posix_only)):
            return ("BLOCK",
                    f"命令位别名 `{head}` 带 POSIX 专属旗标 `-{letters}` —— PS 别名劫持"
                    f"（PS 会话里 `{head}` 是 cmdlet 别名，参数语义与 POSIX 不同："
                    f"实测 `ls -d` 被解析成 `Get-ChildItem -Depth`）",
                    _PS_ALIAS_FIX)
    return None


# ── Gate R0.13【蓝色大肥鱼与PowerShell解析器之间不得不说的故事】(2026-10-10) ──
# 独立一类防线：在 PS 上直接跑 **POSIX 控制语法**（`for/while/until … do … done`、
#   `if … then … fi`、`case … esac`）⟹ PS ParserError。实测 `for i in a b; do echo hi; done`
#   ⟹ `Missing statement body in do loop`。与 R0.12 共用 `_ps_alias_strip_quoted`（只看命令位）。
#   严格度：BLOCK（对齐 R0.6 P1-P3）。
BLUE_FAT_FISH_POSIX_GATE_NAME = "蓝色大肥鱼与PowerShell解析器之间不得不说的故事"
# Gate R0.15（2026-10-26）：绕过工作树、直接 `git` 改主树的通道 —— 同族命名。
BLUE_FAT_FISH_MAIN_GIT_GATE_NAME = "蓝色大肥鱼与主树之间不得不说的故事"
# Gate R0.16（2026-10-27）：pytest 必须用配好的解释器（`_accept_cli.sh` 的 ACCEPT_PY）—— 同族命名。
BLUE_FAT_FISH_PYTEST_GATE_NAME = "蓝色大肥鱼与配好的解释器之间不得不说的故事"
# 2026-10-31（开源收尾）：解释器**不再写死个人 venv** —— 单源 `gk_accept_py.resolve()`
#   （env `ACCEPT_PY` → `scripts/_accept_py.local`（本机私有，gitignored）→ `python3`）。
#   判据语义不变：与「配好的解释器」不一致的 `-m pytest` 仍 BLOCK。
try:
    from gk_accept_py import resolve as _resolve_accept_py
    _ACCEPT_PY = _resolve_accept_py()
except Exception:  # noqa: BLE001 — 边界：单源不可用 ⟹ env → python3（禁因解析失败拒放行）
    _ACCEPT_PY = (os.environ.get("ACCEPT_PY") or "").strip() or "python3"
_PS_POSIX_FIX = ("Fix: ① 包 `wsl -e bash -lc '<原文>'`（**单引号**载荷，PS 不展开）；"
                 "② 或 Write 落 `.sh` 后 `wsl.exe -e bash /mnt/c/…/x.sh`；"
                 "③ 纯 PS 场景改用原语法 `foreach ($x in …) { }` / `if (…) { }`")


def _blue_fat_fish_ps_posix_story(command: str) -> Optional[tuple]:
    """Gate R0.13 检测体：返回 (level, reason, hint)；命中命令位 POSIX 控制语法 → BLOCK。

    判据（须同时满足）：
      ① 命令**未被** `wsl`/`wslsh`/`bash`/`sh`/`zsh` 前缀包裹；
      ② 引号内置空后，同时出现某组 POSIX 控制语法的**首/中/尾**关键字
         （`for|while|until` + `do` + `done`；`if` + `then` + `fi`；`case` + `esac`）。
    """
    import re
    if not command:
        return None
    if re.match(r"^\s*(?:wsl(?:\.exe)?|wslsh(?:\.ps1|\.cmd)?|bash|sh|zsh)\b", command, re.I):
        return None
    masked = _ps_alias_strip_quoted(command)
    if (re.search(r"\b(?:for|while|until)\b", masked)
            and re.search(r"\bdo\b", masked) and re.search(r"\bdone\b", masked)):
        return ("BLOCK",
                "命令位出现 POSIX 循环语法（`for|while|until … do … done`）—— PS 无此语法，"
                "会 ParserError（实测 `Missing statement body in do loop`）",
                _PS_POSIX_FIX)
    if (re.search(r"\bif\b", masked) and re.search(r"\bthen\b", masked)
            and re.search(r"\bfi\b", masked)):
        return ("BLOCK",
                "命令位出现 POSIX 条件语法（`if … then … fi`）—— PS 无此语法，会 ParserError",
                _PS_POSIX_FIX)
    if re.search(r"\bcase\b", masked) and re.search(r"\besac\b", masked):
        return ("BLOCK",
                "命令位出现 POSIX 分支语法（`case … esac`）—— PS 无此语法，会 ParserError",
                _PS_POSIX_FIX)
    return None


# ── A 方案「惰性字面量豁免」（finding `ECC-8DFC84C5B9E5`，2026-09-24 用户裁定）────────────
# 病灶：写 finding / 文档时正文里出现危险字面量会被自身防线拦下；而「自动替换」在那种场合
#   给不出正确目标（抽出的是散文词）⟹ 摩擦白吃，还回注一条**荒谬**的可执行命令。
#
# **作用域（缺了它就会开错门 —— 用户点名的 `run_e2e.sh` 自删事件）**：
#   豁免**只对「这一条命令」成立**，故按调用路径分栏：
#     ✅ 吃豁免：R0.2 **命令串**（L2255 / L2340）；R0.3 的 **`bash -c` 内联荷载**逐行（L1042）
#        —— 内联荷载仍是「这条命令」的一部分，还没落地。
#     ❌ 不吃豁免：R0.3 的**脚本文件**逐行（L1099）—— 文件会在**别的时刻、被别的调用方**
#        执行（`run_e2e.sh` 里 `rm -rf "$TMP"` 把脚本自己删了就是这个），"当时是不是数据"
#        本层**判不了**；声明是给「这条命令」的，**写进文件就不再属于它**。
#     ⟹ 实现上用**默认关**（`inert=False`）的显式开关：漏改的调用点自动退回保守拦截。
#
# **判据 = 双条件，缺一不可**（结构**可证明**不可执行 + 调用方**显式**声明）：
#   ① **显式**：**段首**出现 `GK_INERT_CMD=1`（声明「这段里的是数据，不是命令」）——
#      不是「正文里出现过这个词」，否则谁都无意中满足；命中即落 hook.log 可审计；
#   ② **结构**：命中的字面量所在的**引号区间**内**无命令替换**（`$(` / 反引号 —— 那两个会
#      **真的执行**），且该段不把数据变代码（`eval` / 解释器 `-c`·`-e` / `xargs` / `su`·`sudo`·`ssh`
#      / `find -exec`）。
#   ⟹ 引号内 + 无替换 + 段内不代码化 = shell 只把它当**数据**，**不存在执行可能**。
#   缺① = 纯启发式（不许）；缺② = `GK_INERT_CMD=1 bash -c "…"` 变成免死金牌（更不许）。
#
# **逐层**：`sh -c '<载荷>'` 的载荷是**另一层 shell**，按**它自己那一层**判（同一条检测链）；
#   且**声明必须落在载荷内**、载荷判干净，才在外层把它抹掉。两处「能…才…」是 fail-safe：
#   ① **能提取才抹**（`_c_payload_spans` 提取不干净就不下钻、不抹 ⟹ 外层照旧看得见 token）；
#   ② **载荷内自己有声明才抹** ⟹ 跨边界形态（如 `sh -c 'curl …' | sh`，解释器在引号**外**）
#      不满足，照拦。
_INERT_DECL = "GK_INERT_CMD=1"
_INERT_MAX_LAYER = 3

# ── Gate R0.8：明文 API key / 私钥字面量拦截（2026-09-24 用户裁定「加个 hook 拦截明文写 api key」）──
# 动因（实测）：本会话一次 `printenv <3 变量> | cut -d= -f1` 因分隔符未生效，把两把真 key
#   明文打进了会话记录 —— 明文 key 的泄漏面（会话记录 / 落盘文件 / git 历史）**事后不可收回**。
# 判据形态：只认**高置信形**（前缀 + 足够长连续字母数字）⟹ `sk-****` / `sk-...` /
#   `sk-<占位>` / `$DEEPSEEK_API_KEY` 这类脱敏或引用写法**天然不命中**（无需白名单）。
# 逃生舱：**段首**显式声明 `GK_SECRET_WRITE=1`（与 `GK_INERT_CMD=1` 同形、同为**这一条**调用有效）。
# 作用域：RunCommand 命令串 + Edit/Write 载荷（范围内外**同判** —— 把 key 写到治理范围外
#   （如 ~/.env）同样是泄漏）；**不**据此扫历史文件内容（那是另一类检测）。
_SECRET_DECL = "GK_SECRET_WRITE=1"
_SECRET_PATTERNS = (
    ("sk- 形（OpenAI/DeepSeek 系）", r"\bsk-[A-Za-z0-9]{20,}\b"),
    ("tp- 形（MiMo 系）", r"\btp-[a-z0-9]{20,}\b"),
    ("ghp_ 形（GitHub PAT）", r"\bghp_[A-Za-z0-9]{20,}\b"),
    ("AKIA 形（AWS AKID）", r"\bAKIA[0-9A-Z]{16}\b"),
    ("PEM 私钥头", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("xox 形（Slack token）", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
)
_SECRET_HINT = ("明文写 key 会落进会话记录 / 文件 / git 历史，事后不可收回。改用："
                "① 环境变量引用（如 $DEEPSEEK_API_KEY）；② 既有密钥通道（.keys/ 或 CLI set-key）；"
                "③ 确需字面写入时，在**段首**显式声明 GK_SECRET_WRITE=1（同 GK_INERT_CMD=1 纪律）")


def _plaintext_secret(text: str) -> tuple[str, str] | None:
    """明文 API key / 私钥字面量检测（Gate R0.8）。命中 → (reason, hint)。"""
    import re
    if not text:
        return None
    # 段首声明豁免：`^` 或 `;`/`&`/`|`/换行 之后，**或引号载荷的段首** ——
    # `wsl -e bash -lc '<载荷>'` 是本仓主调用形态，声明写在载荷段首时不该失效（2026-09-24 实测缺口）
    if re.search(r"(?:^|[;&|\n]|['\"])\s*" + re.escape(_SECRET_DECL) + r"\b", text):
        return None
    for label, pat in _SECRET_PATTERNS:
        if re.search(pat, text):
            return (f"BLOCK: 明文 API key / 私钥字面量（{label}）", _SECRET_HINT)
    return None


def _edit_payload_text(tool_input: dict) -> str:
    """Edit/Write 类工具的待写入文本（SearchReplace 的 old_str/new_str + Write 的 content）。"""
    return "\n".join(str(tool_input.get(k) or "")
                     for k in ("old_str", "new_str", "content"))


def _secret_gate_edit(tool_name: str, tool_input: dict, file_path: str = "") -> None:
    """EDIT_TOOLS 载荷闸（Gate R0.8）：范围内外**同判**（写 key 到范围外同为泄漏）。"""
    if tool_name not in EDIT_TOOLS:
        return
    hit = _plaintext_secret(_edit_payload_text(tool_input))
    if hit:
        reason, hint = hit
        block(f"{reason} Target: {file_path or '(unnamed)'}", hint)


# ── Gate R0.19：恶意代码模式拦截（EDIT 载荷，2026-11-04）──
# 动因（用户裁定「恶意代码检查拦截同样需要扩展技能自身的 hook」）：R0.2 管**命令串**、
#   R0.3 管**脚本文件内容**、R0.8 管**密钥字面量** —— 三者都不管「把反弹 shell /
#   下载即执行 / 凭据外送写进一个新文件」。EDIT 载荷这条路径此前只有 R0.8，等于对恶意
#   代码失明（写进去再执行 = 两道门都过）。
# 判据形态：只认**高置信执行形**（设备文件回连 / 管道进解释器 / 解码后执行 / 凭据+外网同现），
#   不认单关键词 —— 否则「讨论恶意代码的文档」会被自己拦掉。
# 扫描面：只扫**新写入内容**（`new_str` / `content`），**不扫 `old_str`** —— 扫它会让
#   「删除恶意代码」这个正确动作被拦（与 R0.8 的取舍不同，理由在此）。
# 豁免（两类）：
#   ① **惰性文档**（.md/.txt/.rst）：不执行，且文档天然要引用攻击串；
#   ② **检测器 / 测试载体**（按**文件名**：`test_*` 或下方白名单）——其正则会必然包含
#      这些字面量，绑目录会在公开导出树 / worktree 副本上误拦。
# 逃生舱：段首声明 `GK_MALWARE_WRITE=1`（与 `GK_SECRET_WRITE=1` 同形、同「这一条有效」）。
_MALWARE_DECL = "GK_MALWARE_WRITE=1"
_SELF_EXEMPT_NAMES = frozenset((
    "pre_tool_hook.py", "gk_bash_static_scan.py", "gk_sarif.py", "gk_threat_patterns.py",
    "gk_edit_verify.py", "gk_foreign_scan.py", "gk_covert_warden.py",
))
_MALWARE_INERT_SUFFIX = frozenset((".md", ".txt", ".rst"))
_MALWARE_HINT = ("写恶意代码 / 后门形态会被本闸拦下。若确属安全研究或检测器实现："
                 "① 写进 .md/.txt/.rst（惰性文档不拦）；② 或在本段首声明 GK_MALWARE_WRITE=1；"
                 "③ 检测器/测试载体按文件名豁免（test_* 或检测器白名单）")


def _malware_self_exempt(file_path: str) -> bool:
    """检测器 / 测试载体豁免（**文件名级**，不绑定目录）。

    为什么按名字而不是按目录：同一条检测器既存在于技能树，也存在于公开导出树 / 各 worktree
    副本，还会被复制到邻居仓库做测试 —— 绑目录必然在某个副本上误拦（实测：公开仓
    `scripts/` 不在技能目录内）。代价与边界：这是**纵深防御的一层**，主动把后门命名为
    `test_*.py` 可绕过，但「改写/新增检测器载体」本身受 Gate 8（技能自维护）与
    R0.4（插件统一入口）覆盖，不靠本闸兜。
    """
    if not file_path:
        return False
    name = Path(_host_form(file_path)).name
    return name in _SELF_EXEMPT_NAMES or name.startswith("test_")


def _malware_payload(text: str) -> tuple[str, str] | None:
    """恶意代码模式检测（Gate R0.19）。命中 → (reason, hint)。"""
    import re
    if not text:
        return None
    if re.search(r"(?:^|[;&|\n]|['\"])\s*" + re.escape(_MALWARE_DECL) + r"\b", text):
        return None
    for label, pat in _MALWARE_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return (f"BLOCK: 恶意代码模式（{label}）", _MALWARE_HINT)
    return None


def _malware_gate_edit(tool_name: str, tool_input: dict, file_path: str = "") -> None:
    """EDIT_TOOLS 载荷闸（Gate R0.19）：范围内外**同判**。"""
    if tool_name not in EDIT_TOOLS:
        return
    if Path(_host_form(file_path or "")).suffix.lower() in _MALWARE_INERT_SUFFIX:
        return
    if _malware_self_exempt(file_path):
        return
    payload = "\n".join(str(tool_input.get(k) or "") for k in ("new_str", "content"))
    hit = _malware_payload(payload)
    if hit:
        reason, hint = hit
        block(f"{reason} Target: {file_path or '(unnamed)'}", hint)


def _c_payload_spans(cmd: str) -> list:
    """本层 `…sh <-c 形态旗标> '<载荷>'` 的**载荷引号区间** `[(start, end, payload)]`。

    严格：旗标 token 必须含 `c`（`-c` / `-lc`）；载荷内**不得**再出现同类引号
    （出现即提取不可靠 ⟹ 不下钻、不抹 —— 由 `_code_making` 的 `c` 旗标拒豁免兜底）。
    """
    import re
    out = []
    for mm in re.finditer(r"\b(?:ba|z|k|d)?sh\b[^|&;\n]*?\s(-[A-Za-z]{1,7})\s+(['\"])(.*?)\2",
                          cmd, re.DOTALL):
        if "c" not in mm.group(1) or mm.group(2) in mm.group(3):
            continue
        out.append((mm.start(2), mm.end(3) + 1, mm.group(3)))
    return out


def _quote_regions(cmd: str) -> list:
    """引号区间 + 所属段：`[(quote_start, quote_end, seg_start, seg_end)]`。

    **同时**决定分段边界 —— 引号内的 `;` / `&&` / `||` / `|` / 换行**不是**分隔符
    （否则 `register "a; b"` 会被切碎，段首声明判据跟着失真）。
    """
    regions, bounds = [], []
    seg_start, q, q_open = 0, "", -1
    i = 0
    while i < len(cmd):
        c = cmd[i]
        if q == "":
            if c == "\\":
                i += 2
                continue
            if c in "'\"":
                q, q_open = c, i
            elif c in ";&|\n":
                j = i
                if c in "&|":
                    while j + 1 < len(cmd) and cmd[j + 1] == c:
                        j += 1
                bounds.append((seg_start, i))
                seg_start, i = j + 1, j
        else:
            if q == '"' and c == "\\":
                i += 2
                continue
            if c == q:
                regions.append((q_open, i, seg_start))
                q = ""
        i += 1
    bounds.append((seg_start, len(cmd)))
    out = []
    for (a, b, s) in regions:
        e = len(cmd)
        for (x, y) in bounds:
            if x == s:
                e = y
                break
        out.append((a, b, s, e))
    return out


def _code_making(seg: str) -> bool:
    """该段是否把「数据」变「代码」（是 ⟹ 拒豁免）。

    旗标判据走**独立短旗标 token**（`-c` / `-lc`），不是扫字符 —— 后者会把
    `gatekeeper-cli.sh` 里的 `-cli` 误读成 `-c`（实测坑：正则扫字符版首测即误判）。
    """
    import re
    toks = seg.strip().split()
    fw = ""
    for t in toks:
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=\S*", t):
            continue                                  # 跳过 VAR=val 前缀
        fw = t.strip("'\"")
        break
    flags = set()
    for t in toks:
        if 1 < len(t) <= 7 and re.fullmatch(r"-[A-Za-z]+", t):
            flags |= set(t[1:])
    # **只列"把跟在后面的东西当代码"的**：`eval` 与各包装器。
    # ⚠ **不列 sh 家族 / find**：`bash gk.sh finding register "…"` 里的引号参数是**数据**
    #   （正例本体就是它），列进来会把正例自己拒掉；`sh -c` 那种"真当代码"的形态由下面的
    #   **`c` 旗标**判据覆盖，`find` 只认 `-exec`。
    if fw in ("eval", "xargs", "su", "sudo", "ssh", "env", "nohup", "timeout", "nice",
              "setsid", "stdbuf"):
        return True
    if "c" in flags and (fw.startswith("python") or fw in ("bash", "sh", "dash", "zsh", "ksh")
                         or "python" in seg):
        return True
    if "e" in flags and (fw in ("perl", "ruby", "node") or "perl" in seg or "ruby" in seg
                         or "node" in seg):
        return True
    if "find" in toks and re.search(r"(?:^|\s)-exec\b", seg):
        return True
    return False


def _declared(text: str) -> bool:
    """**段首**显式声明？（`^` 或 `;`/`&`/`|`/换行 之后首词 —— 不是正文里出现该词就算）"""
    import re
    return bool(re.search(r"(?:^|[;&|\n])\s*GK_INERT_CMD=1\b", text))


def _neutralize_inert(cmd: str, depth: int) -> str:
    """A 方案落刀：抹掉「已**单独判干净**的声明载荷」与「本层段首声明过的惰性引号区」。"""
    import re
    if depth >= _INERT_MAX_LAYER:
        return cmd
    chars, n = list(cmd), 0
    # ① 下钻：载荷内**自己有声明** + 按它自己那层判干净 ⟹ 外层可安全抹掉（能提取才抹）
    if depth + 1 < _INERT_MAX_LAYER:
        for (a, b, payload) in _c_payload_spans(cmd):
            if not _declared(payload):
                continue
            if _dangerous_command(payload, depth + 1, inert=True) is not None:
                continue                              # 载荷里有真危险 ⟹ 不抹，留给本层链去拦
            for k in range(a, b):
                chars[k] = " "
            n += 1
        cmd = "".join(chars)
        chars = list(cmd)
    # ② 本层：段首声明 + 命中在引号内 + 无命令替换 + 段内不代码化
    for (a, b, s, e) in _quote_regions(cmd):
        seg = cmd[s:e]
        if not re.match(r"\s*GK_INERT_CMD=1\b", seg) or _code_making(seg):
            continue
        if re.search(r"\$\s*\(|`", cmd[a:b + 1]):
            continue
        for k in range(a, b + 1):
            chars[k] = " "
        n += 1
    if n:
        _log_hook("GATE-R0-inert: 惰性字面量豁免 %d 处（段首已声明 GK_INERT_CMD=1，"
                  "结构判定为数据；finding ECC-8DFC84C5B9E5）" % n)
    return "".join(chars)


# ── Gate R0.9：Windows 侧 git 写操作硬拦（2026-09-26，跨 OS 抢锁预防）──
# 病根：同一 .git 被 Windows git.exe 与 WSL git **并发写** ⟹ 跨 OS 锁语义不一致
#   ⟹ index.lock 抢锁 / index·refs 丢失面（SKILL.md Red Flag，2026-08-15 审计实锤）。
# 规范面：所有 git 写统一 `wsl git -C <repo> <sub>`（Windows 侧禁 git.exe 写）。
# 此前防线只有 ①文档约束（靠先读技能）+ ②事后检测（audit --crossr git_concurrency）
#   ⟹ **无预防**；2026-09-26 实测复发（Windows git.exe commit ↔ 并发 WSL 提交抢锁）。
# 逃生舱：**段首**声明 GK_ALLOW_WIN_GIT=1（Windows-only 仓合法写；同 GK_INERT_CMD 形）。
_GIT_WRITE_SUBS = frozenset((
    "add", "am", "apply", "checkout", "cherry-pick", "commit", "fetch",
    "filter-branch", "gc", "merge", "mv", "pull", "push", "rebase", "repack",
    "reset", "restore", "revert", "rm", "switch", "update-index", "update-ref",
    "write-tree",
))
_GIT_DUAL_SUBS = frozenset(("branch", "tag", "remote", "worktree", "submodule", "notes", "config"))
_GIT_READ_SUBCMDS = frozenset(("list", "status", "summary", "show", "view", "get"))
_GIT_OPT_ARGS = frozenset(("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"))
_GIT_READ_FLAGS = ("--contains", "--merged", "--no-merged", "--points-at", "--sort",
                   "--format", "--list", "--show-current")


def _git_windows_write(command: str) -> tuple[str, str] | None:
    """Gate R0.9：命令串里的 git **写子命令**若不经 WSL 通道 ⟹ Windows git.exe 写 ⟹ BLOCK。

    判据 = **通道**（非路径）：命中 git 写子命令，且命令串无 wsl/bash 路由标记。
    读命令（status/log/diff/show/rev-parse/ls-remote/branch 裸列…）放行；引号内字面量不误拦。
    已知边界：`git branch --contains X` 这类「读旗标 + 位置参」可能误判为写 ⟹ 用段首
    GK_ALLOW_WIN_GIT=1 逃生（或补 _GIT_READ_FLAGS）。
    """
    import re
    cmd = command.strip()
    if os.environ.get("GK_WIN_GIT_GATE") == "0":                              # 显式关闭（非 Windows 宿主）
        return None
    # 仅当「agent 宿主是 Windows、而 git 写应走 WSL」时才有意义；纯 Linux/macOS 无此双栈 ⟹ 跳过。
    if not (os.path.isdir("/mnt/c") or sys.platform.startswith("win")):
        return None
    if re.search(r"(?:^|[;&|\n])\s*GK_ALLOW_WIN_GIT=1\b", cmd, re.I):        # 段首声明 ⟹ 逃生
        return None
    if re.search(r"\b(?:wsl|wslsh|wsl\.exe|bash|bash\.exe)\b", cmd, re.I):   # 经 WSL 通道
        return None
    for m in re.finditer(r"\bgit\b", cmd, re.I):
        if _in_quotes(cmd, m.start()):          # 引号内字面量（echo "git commit"）不误拦
            continue
        seg = re.split(r"[|&;\n]", cmd[m.end():], maxsplit=1)[0]
        toks, i = seg.split(), 0
        while i < len(toks):                    # 跳过前导选项及其参数（-C <dir> / -c k=v / --opt=…）
            if toks[i] in _GIT_OPT_ARGS:
                i += 2
            elif toks[i].startswith("-"):
                i += 1
            else:
                break
        sub = toks[i].lower() if i < len(toks) else ""
        rest = toks[i + 1:]
        positional = [t for t in rest if not t.startswith("-")]
        if sub in _GIT_WRITE_SUBS:
            hit = True
        elif sub == "stash":                    # bare stash = save（写）；list/show = 读
            hit = (not positional) or (positional[0].lower() not in _GIT_READ_SUBCMDS)
        elif sub in _GIT_DUAL_SUBS:             # 双重语义：有位置参且非读子命令 ⟹ 写
            if any(t.startswith(_GIT_READ_FLAGS) for t in rest):
                hit = False
            else:
                hit = bool(positional) and positional[0].lower() not in _GIT_READ_SUBCMDS
        else:
            hit = False
        if hit:
            return (f"windows-side git write: `git {sub}` 会调 Windows git.exe ⟹ 与 WSL git "
                    f"并发写同一 .git（跨 OS index.lock 抢锁 / refs 损坏面；SKILL.md Red Flag 2026-08-15）",
                    f"Fix: 改用 `wsl git -C <repo> {sub} …`（所有 git 写统一 WSL 通道）；"
                    f"Windows-only 仓确需本地写时，在**段首**声明 GK_ALLOW_WIN_GIT=1")
    return None


# ── Gate R0.15【蓝色大肥鱼与主树之间不得不说的故事】主树 git 写硬拦（2026-10-26）──
# 病根（实证）：写面门禁只覆盖 `EDIT_TOOLS`（Write/Edit/SearchReplace/…）+ Gate 3 路径归属；
#   `wsl git -C <主树> commit|reset|checkout…` 走的是 **RunCommand** ⟹ 既不认领 worktree、
#   也不扣 edit_budget ⟹ 整条写面门禁被绕过（2026-10-26 即以该形态把 6 文件 + 一次 merge 落进主树）。
# 判据：git **改工作区/branch 的子命令** × 目标仓库 == 主树（技能目录，且不在 worktrees/ 下）⟹ BLOCK。
#   通道无关（Windows git 写已由 R0.9 拦；本门管的是「通道合法但目标错」）。
#   `push` / `fetch` / **`merge`** 不在列：前二者不改工作区；`merge` 是**既有落地仪式**
#   （设计 §11.3-3「单队列 git merge --no-ff」，CLI 不提供 merge 子命令）⟹ 拦了就断正路。
#   本门只拦「**绕过工作树直接改主树内容**」的子命令（commit/reset/checkout/clean…）。
# 逃生舱：段首 `GK_ALLOW_MAIN_GIT_WRITE=1`（同 GK_ALLOW_WIN_GIT 形）。
_MAIN_GIT_MUTATING = frozenset((
    "commit", "rebase", "reset", "checkout", "switch", "restore", "revert",
    "cherry-pick", "clean", "rm", "mv", "apply", "am", "stash",
    "update-ref", "update-index", "write-tree",
))


def _git_main_tree_write(command: str, cwd: str = "") -> tuple[str, str] | None:
    """Gate R0.15：git 写子命令的目标仓库是**主树** ⟹ BLOCK（堵 RunCommand 写面旁路）。"""
    import re
    cmd = (command or "").strip()
    if not cmd:
        return None
    if re.search(r"(?:^|[;&|\n])\s*GK_ALLOW_MAIN_GIT_WRITE=1\b", cmd, re.I):
        return None
    main = _win_to_wsl(str(SKILL_DIR)).rstrip("/")
    if not main:
        return None
    # shell 包裹（`bash -c '…'` / `wslsh -c '…'`）内的命令也是命令 ⟹ 把 `-c '` 归一为分隔符，
    # 使内部 `cd`/`git` 处于命令位；纯 `echo 'git …'`（非 -c 载荷）仍不误拦。
    import re as _re
    scan = _re.sub(r"(?:-c|--command)\s*(['\"])", ";", cmd, flags=_re.I)
    # `cd <dir> && git …` 形态：取**该 git 之前**最近的一次 cd（一条命令可跨仓串写，
    # 用「最后一次 cd」会把前段的 worktree 提交误判成主树写 —— 2026-10-26 实测踩中）。
    _cds = [(c.start(), c.group(2)) for c in
            _re.finditer(r"(?:^|[;&|\n])\s*cd\s+(['\"]?)([^'\"\s;&|]+)\1", scan, _re.I)]
    for m in _re.finditer(r"\bgit\b", scan, _re.I):
        if _in_quotes(scan, m.start()):          # 引号内字面量（echo 'git …'）不误拦
            continue
        eff = cwd or ""
        for pos, d in _cds:
            if pos < m.start():
                eff = d
            else:
                break
        seg = _re.split(r"[|&;\n]", scan[m.end():], maxsplit=1)[0]
        toks, i, target = seg.split(), 0, ""
        while i < len(toks):
            if toks[i] == "-C" and i + 1 < len(toks):
                target = toks[i + 1]
                i += 2
            elif toks[i].startswith("-"):
                i += 1
            else:
                break
        if i >= len(toks):
            continue
        sub = toks[i].lower()
        if sub not in _MAIN_GIT_MUTATING:
            continue
        repo = _win_to_wsl(target or eff).rstrip("/")
        if not repo:
            continue
        if repo == main or (repo.startswith(main + "/") and "/worktrees/" not in repo):
            return (f"main-tree git write: `git {sub}` 直接改主树 ⟹ 绕过写面门禁"
                    f"（worktree 归属 / edit_budget / Gate 3 全不执行）",
                    "Fix: 改动一律在 worktree 内 commit，再按落地仪式 `git merge --no-ff` 回主树；"
                    "确需手工时在**段首**声明 GK_ALLOW_MAIN_GIT_WRITE=1")
    return None


# ── Gate R0.16【蓝色大肥鱼与配好的解释器之间不得不说的故事】pytest 解释器硬拦（2026-10-27）──
# 病根（实证）：本仓测试必须跑在**配好的隔离 venv**（`scripts/_accept_cli.sh` 的 `ACCEPT_PY`；
#   单源解析 = `scripts/py_resolve.sh`，`scripts/_accept_baseline.txt` 头部 `runner:` 同源）。
#   RunCommand 里裸 `python -m pytest` 用的是另一套系统 Python ⟹ 路径语义/依赖面全变
#   （2026-10-27 实测：大量环境性红、`.keys` 无法 stat），而**此前没有任何一道门看解释器**。
# 判据：命令位出现 `python|python3|py -m pytest` 或裸 `pytest`，且
#   ① 未走 `scripts/_accept_cli.sh`；② 未显式用配好的解释器（`_ACCEPT_PY`）；
#   ③ 未走 `_redfirst_cli.sh`（其 REDFIRST_PY 默认同源）。
#   引号内字面量 / heredoc 正文不拦（防写文档、写脚本时误伤）。
# 逃生舱：段首 `GK_ALLOW_ANY_PYTEST=1`，或进程环境 `GK_ALLOW_ANY_PYTEST=1`
#   （后者供 **in-process hook 单测** 用：它们只跑形态识别、不真执行命令，无法在命令串里加前缀）。
def _pytest_wrong_interpreter(command: str) -> tuple[str, str] | None:
    """Gate R0.16：pytest 未使用配好的解释器 ⟹ BLOCK。"""
    import re
    cmd = (command or "").strip()
    if not cmd:
        return None
    if os.environ.get("GK_ALLOW_ANY_PYTEST") == "1":
        return None
    if re.search(r"(?:^|[;&|\n])\s*GK_ALLOW_ANY_PYTEST=1\b", cmd, re.I):
        return None
    if "_accept_cli.sh" in cmd or "_redfirst_cli.sh" in cmd or _ACCEPT_PY in cmd:
        return None
    # heredoc 正文（写文档/写脚本时内嵌命令示例）不扫
    scan = cmd.split("<<", 1)[0]
    # `bash -c '…'` / `wslsh -c '…'` 载荷归一为命令位（同 R0.15）
    scan = re.sub(r"(?:-c|--command)\s*(['\"])", ";", scan, flags=re.I)
    pat = re.compile(r"\b(?:python(?:3(?:\.\d+)?)?(?:\.exe)?|py)\s+(?:-\S+\s+)*-m\s+pytest\b"
                     r"|(?:^|[;&|(\n])\s*pytest(?:\.exe)?\b", re.I)
    m = pat.search(scan)
    if not m:
        return None
    if _in_quotes(scan, m.start()):
        return None
    return ("pytest 未使用配好的解释器（裸 python/pytest）⟹ 结果与基线不同源、不可比",
            "Fix: 用 `bash scripts/_accept_cli.sh <test.py>`（ACCEPT_PY 默认 %s）；"
            "或显式 `%s -m pytest …`；确需其他解释器时在**段首**声明 "
            "GK_ALLOW_ANY_PYTEST=1" % (_ACCEPT_PY, _ACCEPT_PY))


def _dangerous_command(command: str, _depth: int = 0, inert: bool = False) -> tuple[str, str] | None:
    """危险命令检测**入口**（Gate R0.2）：`inert=True` 时先做惰性字面量豁免（A 方案），
    再走原检测链（`_dangerous_chain`）。

    **默认 `inert=False`（不吃豁免）** —— 只在「这一条命令」的路径上显式打开（见顶部作用域表）；
    漏传的调用点自动退回保守拦截（fail-safe）。无声明时零行为变化。
    `_depth` 仅供「逐层下钻 `sh -c` 载荷」内部传递。
    """
    cmd = command.strip()
    if inert and _INERT_DECL in cmd:
        cmd = _neutralize_inert(cmd, _depth)
    return _dangerous_chain(cmd)


def _dangerous_chain(command: str) -> tuple[str, str] | None:
    """检测危险命令（W4 普适 gate，Gate R0.2，2026-08-10 落地）。
    命中返回 (reason, fix_hint)，安全返回 None。
    类2 高危破坏 × 类1 语法检测（p0-analysis.md §1.2）：纯语法、无状态依赖 →
    普适安全 gate（治理范围外也执行，同 W1）。拦截后不自动放行，附 Fix 建议（W5）
    由 agent/人类二次确认后再执行（破坏性操作默认拒绝）。

    2026-09-10 E2 扩展（用户定案）：原覆盖仅 git 三族 + rm -r*。红队探针扫 20 形态，
    原实现漏网 = dd of=/dev/* / mkfs / truncate -s 0 /dev/* / chmod -R … / /
    curl|wget → python/perl/ruby/node|sh / fork bomb / python -c rmtree 等
    （逐条见 test_red_attacks.py TestDangerousCommandE2Families）。新增四族：
      ① 磁盘/设备级覆写：dd of=/dev/*、mkfs[.fs]、wipefs、truncate -s 0 /dev/*、> /dev/sd*
      ② 根级权限/属主破坏：chmod|chown -R … /
      ③ 远程代码执行：curl|wget … | sh|bash|python|perl|ruby|node、bash <(curl …)
      ④ 解释器内联删除：python -c rmtree/os.remove、perl -e unlink、ruby -e rm_rf、node -e rmdirSync
    范围外（用户未选，**仍不拦**，勿误读为已覆盖）：shred、find -delete、umount、
    以及写普通文件而非设备节点的形态（如 dd of=/tmp/img）。
    2026-09-10 E4（用户定案"保持严格，只优化提示"）：命中即 BLOCK 语义不变，
    reason 附命中文本、hint 附惰性字面量规避指引（测试夹具/文档中的危险字面量
    改用字符串拼接写入，避免被自身防线误杀）。"""
    import re
    cmd = command.strip()

    def _hit(mm) -> str:
        try:
            s = re.sub(r"\s+", " ", mm.group(0)).strip()[:60]
        except Exception:
            s = ""
        return f"（命中文本: {s}）" if s else ""

    _INERT = ("；惰性字面量（测试夹具/文档）请改用字符串拼接写法，或在**段首**显式声明 "
              "GK_INERT_CMD=1（结构合格即豁免，见 finding ECC-8DFC84C5B9E5；"
              "**脚本文件内容不吃豁免**）")

    # 2026-11-01（治理台账接线）：state 及其旁挂（history / rejected-edits 归档等 append-only
    #   证据）**禁止直接删**；可逆归档唯一入口 = `state --archive-isolated`（os.replace + manifest）。
    #   原实现只靠通用危险命令族，`.gatekeeper.state*` 这类台账并未被点名保护。
    mm = re.search(r"(?:^|[;&|]\s*)(?:rm|unlink|shred|truncate)\b[^\n]*\.gatekeeper\.state", cmd)
    if not mm:
        mm = re.search(r"\bfind\b(?=[^\n|&;]*\.gatekeeper\.state)[^\n|&;]*-delete\b", cmd)
    if mm:
        return ("dangerous command: 删除治理台账/归档 (.gatekeeper.state*)" + _hit(mm),
                "Fix: 用 `gatekeeper-cli.sh state --archive-isolated`（可逆搬运 + manifest）；"
                "归档是 append-only 审计证据，禁直接删" + _INERT)

    # git 与子命令间允许选项（git -C <dir> push --force 同样拦截，2026-08-15 红队测试发现）
    mm = re.search(r"\bgit\b[^|&;\n]*\bpush\b[^|&;\n]*(?:--force(?!-)\b|-f\b)", cmd, re.IGNORECASE)
    if mm:
        return ("dangerous command: git push --force (不可逆覆盖远端)" + _hit(mm),
                "Fix: git push --force-with-lease（或先 git log origin/main 确认远端状态）" + _INERT)
    mm = re.search(r"\bgit\b[^|&;\n]*\breset\s+--hard\b", cmd, re.IGNORECASE)
    if mm:
        return ("dangerous command: git reset --hard (丢弃工作区+暂存区)" + _hit(mm),
                "Fix: git stash 或先备份；确认无误后再执行 git reset --hard" + _INERT)
    mm = re.search(r"\bgit\b[^|&;\n]*\bclean\s+-(?:f|fd|ffd)\b", cmd, re.IGNORECASE)
    if mm:
        return ("dangerous command: git clean -f (删除未跟踪文件，含 gitignored)" + _hit(mm),
                "Fix: 先 git clean -n 预览将删除的文件，确认目标后再执行" + _INERT)
    m = re.search(r"\brm\s+-r\w*\b(.*)", cmd, re.IGNORECASE)
    if m:
        # 豁免 CLI 内部已知安全调用：rm -rf 指向 $_tmp / $tmp 变量模式的临时目录
        if re.search(r"\$\{?_?tmp", m.group(1)):
            return None
        # 2026-09-23（用户裁定「加个最低权限影响最小的最安全的删除命令引导，自动替换高危命令；
        #   安全网虽然有引导但不是自动注入，这就是硬摩擦也很耗时」）：
        #   原实现只给**泛泛** hint（"明确目标路径并备份"）⟹ 使用者仍要自己想等价命令、再拼一遍。
        #   现按**实际命中文本**算出一条**可直接粘贴执行**的等义安全命令。
        # 选型 = **move-to-trash**（`mv` 进技能外的回收区），三条都指向「最低权限 / 影响最小」：
        #   ① **可逆**：rename 不是 unlink，误删可原样搬回；
        #   ② **最省权限**：同 fs 上是原子 rename，不需要递归遍历 / 不需要删除权限；
        #   ③ **无半删态**：不会像 `rm -rf` 中途失败那样留下部分删除的树。
        # 安全约束（避免把「危险」换成「另一种危险」）：
        #   · 只接受**字面路径**（含 glob `*?[` 或裸 `/`/`~` 一律不注入）—— 带引号的 `mv` 不会
        #     展开 glob，硬注入会搬错东西；
        #   · 注入串**不得含命令替换**（`$(` / 反引号）⟹ 一字可执行、可审阅；
        #   · 回收区在**技能仓之外**（`SKILL_DIR.parent.parent/.gk-trash`）⟹ 不污染任何仓库。
        _tgt = ""
        for _tok in re.split(r"\s+", m.group(1).strip()):
            if _tok and not _tok.startswith("-"):
                _tgt = _tok
                break
        # finding `ECC-4DDED6B7E766`（用户点名「自动替换好像有点蠢」）：原式**只**判「非短横线
        #   开头」⟹ 检测命中**散文**时（如 finding 标题里出现该短语）抽到的是**中文词**，注入
        #   出的 `mv` 指向一个**不存在的怪路径**却仍标称「一字可执行」（实测注入目标 =
        #   「的字面路径自动改写成」）⟹ 该「替换」比不替换**更糟**（用户会被带去搬错东西）。
        #   故补**目标形态判据**：真命令的目标必然**长得像路径**（该路径存在，或 `/` `./` `../`
        #   `~` 起头，或含路径分隔符）；不像 ⟹ **不注入**，退回泛化 hint（**不猜**）。
        import os as _os
        _looks_path = bool(_tgt and (
            _os.path.exists(_tgt) or _tgt.startswith(("/", "./", "../", "~"))
            or "/" in _tgt or "\\" in _tgt))
        if (_looks_path and not re.search(r"[*?\[\]]", _tgt)
                and _tgt not in ("/", "~", "./", "../")):
            import datetime as _dt
            _base = _os.path.basename(_tgt.rstrip("/").rstrip("\\")) or "target"
            _ts = _dt.datetime.now().strftime("%Y%m%dT%H%M%S")
            # finding `ECC-82CC385C121E`：回收区**单源** = `gk_route_center.trash_dir`
            #   （原式 `SKILL_DIR.parent.parent` 与 reclaim 侧 `dirname(main_repo)` 构成双源）。
            #   此处是**罕见分支**（仅命中递归删除时进入），且模块级已把 `scripts` 放进
            #   `sys.path` ⟹ 惰性 import **不进热路径**。拿不到即回退**同式**字面量
            #   （保底不降级：隔离区仍必须落在技能仓之外）。
            try:
                from gk_route_center import trash_dir as _trash_dir_fn
                _trash = (_trash_dir_fn(str(SKILL_DIR))
                          or str(SKILL_DIR.parent.parent / ".gk-trash"))
            except Exception:  # noqa: BLE001 — 拿不到即回退同式字面量（保底不降级）
                _trash = str(SKILL_DIR.parent.parent / ".gk-trash")
            # [ECC-1FAEE0EC9E6E] 宿主边界（同 `_run_cli`）：注入串是 **bash 语法**（`mkdir -p … && mv …`）——
            #   Windows 宿主下 WSL bash **不认** `C:\…`（反斜杠被吃）⟹ 注入的是「可直接执行」是**假的**
            #   （实测 `mv: cannot stat`）。故把 `_trash` / `_tgt` 的 Windows 形态转 `/mnt/…`；
            #   WSL 形（`/` 起头）与非 Windows 宿主**逐字不变**（不改任何判据）。
            def _sh_form(p):
                s = str(p)
                return _win_to_wsl(s) if (_IS_WIN_HOST and len(s) > 1 and s[1] == ":") else s
            _trash_sh, _tgt_sh = _sh_form(_trash), _sh_form(_tgt)
            _repl = 'mkdir -p "%s" && mv -- "%s" "%s/%s.%s"' % (
                _trash_sh, _tgt_sh, _trash_sh, _base, _ts)
            return ("dangerous command: rm -rf (递归强制删除，不可逆)" + _hit(m),
                    "Fix（**自动替换 · 可直接执行** · 最低权限/可逆）: " + _repl + _INERT)
        return ("dangerous command: rm -rf (递归强制删除，不可逆)" + _hit(m),
                "Fix: 明确目标路径并备份；CLI 内部 _tmp_* 白名单豁免" + _INERT)

    # ── E2-1 磁盘/设备级覆写（一次性不可逆）──
    mm = re.search(r"\bdd\b[^|&;\n]*\bof\s*=\s*/dev/", cmd, re.IGNORECASE)
    if mm:
        return ("dangerous command: dd of=/dev/* (覆写块设备，不可逆)" + _hit(mm),
                "Fix: 核对目标设备路径；写镜像请用 loop 设备或普通文件" + _INERT)
    mm = re.search(r"\bmkfs(?:\.[a-z0-9]+)?\b", cmd, re.IGNORECASE)
    if mm:
        return ("dangerous command: mkfs (格式化文件系统，不可逆)" + _hit(mm),
                "Fix: 确认目标设备已备份；容器/测试请用 loop 镜像" + _INERT)
    mm = re.search(r"\bwipefs\b", cmd, re.IGNORECASE)
    if mm:
        return ("dangerous command: wipefs (清除文件系统签名)" + _hit(mm),
                "Fix: 确认设备可销毁；先 wipefs -n 预览" + _INERT)
    mm = re.search(r"\btruncate\b[^|&;\n]*-s\s*0[^|&;\n]*/dev/", cmd, re.IGNORECASE)
    if mm:
        return ("dangerous command: truncate -s 0 /dev/* (清零块设备)" + _hit(mm),
                "Fix: 核对目标；清零普通文件而非设备节点" + _INERT)
    mm = re.search(r">\s*/dev/(?:sd|nvme|hd|vd|mmcblk)", cmd, re.IGNORECASE)
    if mm:
        return ("dangerous command: 重定向覆写块设备 (> /dev/*，不可逆)" + _hit(mm),
                "Fix: 写普通文件而非设备节点；确需写入先核对设备名" + _INERT)

    # ── E2-2 根级权限/属主破坏 ──
    mm = re.search(r"\b(?:chmod|chown)\b[^|&;\n]*-R\b[^|&;\n]*\s/(?:\s|$)", cmd, re.IGNORECASE)
    if mm:
        return ("dangerous command: 根级权限/属主递归变更 (chmod|chown -R ... /)" + _hit(mm),
                "Fix: 指定具体子目录而非根 /；先 dry-run 预览影响面" + _INERT)

    # ── E2-3 远程代码执行 ──
    mm = re.search(r"\b(?:curl|wget)\b[^|&;\n]*\|[^|&;\n]*\b(?:ba|z|k)?sh\b", cmd, re.IGNORECASE)
    if mm:
        return ("dangerous command: 远程内容直管解释器 (curl|wget ... | sh)" + _hit(mm),
                "Fix: 先下载到文件、审阅内容后再执行（勿管道直执行）" + _INERT)
    mm = re.search(r"\b(?:ba|z|k)?sh\b\s*<\(\s*(?:curl|wget)\b", cmd, re.IGNORECASE)
    if mm:
        return ("dangerous command: 远程内容进程替换执行 (bash <(curl ...))" + _hit(mm),
                "Fix: 先下载审阅；进程替换无法预审内容" + _INERT)

    # ── E2-5（2026-09-23 用户裁定「扩展高危命令拦截名单」）──
    # 扩容判据 = **一次性不可逆**（不是「不方便」）。据此分两栏，第二栏是**刻意不拦**，
    # 写出理由以免下次被当成漏网再次「补」：
    #   入列：① 擦除类（shred）；② 批量删除类（find -delete）；
    #         ③ 丢弃未提交工作类 —— 与既有 `git reset --hard` / `git clean -f` **同族**
    #            （同「丢工作区」语义），原文只盖了那两条，`checkout .` / `restore .` /
    #            `stash clear|drop` / `branch -D` 当时漏网，本次补齐。
    #   仍不拦（刻意的）：`umount`（可重新挂载 ⟹ 可逆，拦它只给正常开发加摩擦）、
    #     `dd of=<普通文件>`（写镜像到普通文件是正常操作，原 docstring 已按用户裁定排除）、
    #     `kill`/`pkill`/`killall` 族（进程可重启，且开发中高频正常使用）。
    mm = re.search(r"\bshred\b", cmd, re.IGNORECASE)
    if mm:
        return ("dangerous command: shred (覆写擦除，不可逆；区别于可逆的 move-to-trash)" + _hit(mm),
                "Fix: 改 `mv -- <目标> <回收区>/`（可逆）；确实要擦除请显式二次确认" + _INERT)
    mm = re.search(r"\bfind\b[^|&;\n]*-delete\b", cmd, re.IGNORECASE)
    if mm:
        return ("dangerous command: find -delete (按匹配批量删除，易误伤)" + _hit(mm),
                "Fix: 先同条件 `find ... -print` 预览命中集，确认后再 -delete" + _INERT)
    mm = re.search(r"\bgit\b[^|&;\n]*\b(?:checkout|restore)\b[^|&;\n]*\s\.(?:\s|$)", cmd, re.IGNORECASE)
    if mm:
        return ("dangerous command: git checkout|restore . (丢弃工作区未提交改动)" + _hit(mm),
                "Fix: 先 `git stash -u`（可恢复）或 `git diff` 留证，确认后再丢弃" + _INERT)
    mm = re.search(r"\bgit\b[^|&;\n]*\bstash\s+(?:clear|drop)\b", cmd, re.IGNORECASE)
    if mm:
        return ("dangerous command: git stash clear|drop (丢弃暂存，事后难寻)" + _hit(mm),
                "Fix: 先 `git stash list` 核对；要留的先 `git stash apply`" + _INERT)
    mm = re.search(r"\bgit\b[^|&;\n]*\bbranch\b[^|&;\n]*-[A-Za-z]+\b", cmd, re.IGNORECASE)
    if mm and "-D" in mm.group(0).split():
        # 注意：本函数所有 re.search 都带 IGNORECASE（既有约定），而 `-D`/`-d` **语义相反**
        #   （-D 强删、-d 仅删已合并分支）⟹ **不能**在正则里写 `-D\b`（IGNORECASE 会把 -d
        #   也吃掉，实测：首版如此写法把 `git branch -d merged/x` 误拦）。故先宽松找
        #   `branch ... -<flag>`，再用 `.split()` **按大写 D 逐字比对**（`feat-D` 这类
        #   分支名不会被误判，因为它不是一个独立 token）。
        return ("dangerous command: git branch -D (强删分支，未合并提交可能失联)" + _hit(mm),
                "Fix: 先 `git log <branch> --not <base>` 看有无独有提交；已合并用 -d" + _INERT)
    mm = re.search(r"\b(?:curl|wget)\b[^|&;\n]*\|[^|&;\n]*\b(?:python[0-9.]*|perl|ruby|node)\b",
                   cmd, re.IGNORECASE)
    if mm:
        return ("dangerous command: 远程内容直管解释器 (curl|wget ... | python/perl/ruby/node)" + _hit(mm),
                "Fix: 先下载到文件、审阅内容后再执行" + _INERT)

    # ── E2-4 解释器内联删除 ──
    # 段内字符集用 [^\n|&]（**不排 ; **）：python/perl 一行式普遍用 `;` 分隔语句
    # （python3 -c "import shutil; shutil.rmtree(x)"），若沿用 [^|&;\n] 会整体漏检。
    # 目标模式本身足够特异（shutil.rmtree/os.remove/FileUtils.rm_rf/rmdirSync），误拦面小。
    mm = re.search(r"\bpython[0-9.]*\b[^\n|&]*-c\b[^\n|&]*"
                   r"(?:shutil\.rmtree|os\.(?:remove|unlink|rmdir)|\.unlink\()", cmd, re.IGNORECASE)
    if mm:
        return ("dangerous command: python -c 内联删除 (shutil.rmtree/os.remove/unlink)" + _hit(mm),
                "Fix: 用受管工具或先备份；批量删除请写可审阅脚本" + _INERT)
    mm = re.search(r"\bperl\b[^\n|&]*-e\b[^\n|&]*\bunlink\b", cmd, re.IGNORECASE)
    if mm:
        return ("dangerous command: perl -e unlink (内联删除)" + _hit(mm),
                "Fix: 先备份；批量删除请写可审阅脚本" + _INERT)
    mm = re.search(r"\bruby\b[^\n|&]*-e\b[^\n|&]*(?:FileUtils\.rm_rf|File\.delete)", cmd, re.IGNORECASE)
    if mm:
        return ("dangerous command: ruby -e 内联删除" + _hit(mm),
                "Fix: 先备份；批量删除请写可审阅脚本" + _INERT)
    mm = re.search(r"\bnode\b[^\n|&]*-e\b[^\n|&]*rm(?:Sync|dirSync)", cmd, re.IGNORECASE)
    if mm:
        return ("dangerous command: node -e 内联删除" + _hit(mm),
                "Fix: 先备份；批量删除请写可审阅脚本" + _INERT)

    # ── fork bomb（形态固定，无参数）──
    mm = re.search(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", cmd)
    if mm:
        return ("dangerous command: fork bomb" + _hit(mm),
                "Fix: 拒绝执行；如为文档/测试字符串请用拼接写入" + _INERT)

    return None


def _decode_variants(command: str) -> list[tuple[str, str]]:
    """编码解码变体提取（RED-HOOK-16 实装，2026-08-28）。
    编码混淆绕过面：危险命令经 base64/hex/percent-unquote/rot13 编码后，字符串级
    _dangerous_command 逐字匹配不可见。本函数从命令中提取解码候选（整串 + 引号内
    内容 + echo/printf 参数——管道编码执行形态），逐一尝试解码。
    纯语法、确定性、无状态 → 普适 gate（同 R0.2）。解码失败/结果为空或同原串则跳过。
    返回 [(编码形态名, 解码串), ...]。"""
    import base64
    import codecs
    import re
    import urllib.parse
    out: list[tuple[str, str]] = []
    cands = [command.strip()]
    # echo/printf <enc> | base64 -d | bash 形态：取 echo/printf 后的参数
    # 2026-09-10 E1（用户定案必修）：前导分隔符类原为 [\s|;&]，缺引号 →
    # `bash -c 'echo <b64> | base64 -d | bash'` 内 echo 紧跟单/双引号时提取失败
    # → 编码复扫整体失效（红队探针实证：裸形态拦得住、bash -c 内嵌形态漏网）。
    for m in re.finditer(r"(?:^|[\s|;&'\"])(?:echo|printf)\s+([^\s|;&]+)", command, re.IGNORECASE):
        cands.append(m.group(1))
    # bash -c '...' / 任意引号包裹的编码串形态
    for m in re.finditer(r"['\"]([^'\"\n]{4,})['\"]", command):
        cands.append(m.group(1))
    seen: set[str] = set()
    for s in cands:
        if not s or s in seen:
            continue
        seen.add(s)
        # base64：去空白后严格解码（validate=True 拒绝非 b64 字符集）
        try:
            dec = base64.b64decode(re.sub(r"\s+", "", s), validate=True) \
                .decode("utf-8", errors="replace")
            if dec and dec != s:
                out.append(("base64", dec))
        except Exception:
            pass
        # hex：全 hex 字符且偶数长度（bytes.fromhex 天然抛错）
        if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", s):
            try:
                dec = bytes.fromhex(s).decode("utf-8", errors="replace")
                if dec and dec != s:
                    out.append(("hex", dec))
            except Exception:
                pass
        # percent-unquote：%XX 形式（URL 化命令混淆）
        if "%" in s:
            dec = urllib.parse.unquote(s)
            if dec and dec != s:
                out.append(("percent-unquote", dec))
        # rot13：仅 ASCII 字母位移（英文危险词可被 rot13 掩盖；中文命令不受影响）
        if re.search(r"[A-Za-z]", s):
            dec = codecs.decode(s, "rot_13")
            if dec and dec != s:
                out.append(("rot13", dec))
    return out


def _dangerous_command_decoded(command: str, inert: bool = False) -> tuple[str, str] | None:
    """R0.2 逐字检测 + 编码解码复扫（RED-HOOK-16 实装，2026-08-28）。
    先跑字符串级 _dangerous_command；未命中时对 base64/hex/percent-unquote/rot13
    解码变体复扫（编码混淆可绕过逐字匹配，OWASP LLM06/工业界红队常见）。
    命中返回 (reason, fix_hint)，reason 标注编码形态；任何一层命中即 BLOCK。

    `inert`（finding `ECC-8DFC84C5B9E5`）默认 **False** = 不吃惰性豁免；只有「这一条命令」
    的调用路径才显式传 True（**脚本文件内容一路必须保持 False**，见顶部作用域表）。
    解码变体是**裸串**、不含声明 ⟹ 编码夹带照旧拦得住。
    """
    danger = _dangerous_command(command, inert=inert)
    if danger:
        return danger
    for enc, variant in _decode_variants(command):
        danger = _dangerous_command(variant, inert=inert)
        if danger:
            reason, hint = danger
            return (f"{reason}（经 {enc} 编码解码后命中，R0.2 编码复扫）", hint)
    return None


def _bash_c_payload(command: str) -> str | None:
    """提取 bash/sh/zsh -c '<payload>' 的内联荷载（2026-09-10 E3）。

    形态：`bash -c '...'` / `bash -lc "..."`（-c 可与其他短选项连写）。
    旗标用 `(?<!-)-[a-zA-Z]{0,4}c[a-zA-Z]{0,4}`：负向后顾排除双横杠长旗标——
    否则 `--crossrev` / `--task` 之类会被误判成 `-c`（长旗标含 c 即误命中），
    把普通参数里的引号串当成 bash 荷载扫描。
    返回引号内荷载字符串；非 -c 形态返回 None。"""
    import re
    mm = re.search(r"\b(?:bash|sh|zsh)\b[^|&;\n]*?\s(?<!-)-[a-zA-Z]{0,4}c[a-zA-Z]{0,4}\s+(['\"])(.*?)\1",
                   command, re.DOTALL)
    return mm.group(2) if mm else None


def _warn_unanalyzable_bash_c(command: str) -> str | None:
    """bash -c 荷载不可静态分析形态 → 告警（**不 BLOCK**，2026-09-10 E3 用户定案）。

    荷载含 $(...)/反引号/cat/xargs 时实际执行内容来自运行时 → 静态扫描覆盖不到。
    处置 = 告警 + 引导「落 .sh 脚本后经 bash <file> 调用」以走 R0.3 文件内容扫描，
    不升级为 BLOCK（用户定案：E4 严格面只覆盖静态可判形态）。"""
    import re
    payload = _bash_c_payload(command)
    if payload is None:
        return None
    if re.search(r"\$\(|`|\bcat\s|\bxargs\b", payload):
        return ("bash -c 荷载不可静态分析（含 $(...)/反引号/cat/xargs）—— 危险命令可能藏在"
                "运行时内容里；建议落 .sh 脚本后经 bash <file> 调用以走 R0.3 内容扫描")
    return None


# 信任根脚本（2026-10-22，用户裁定「消除自指死锁」）：这两个文件是**被信任的执行入口**——
#   `gatekeeper-cli.sh` 由本 hook 的 Gate 4 每次用 subprocess 直接执行（`_run_cli`），
#   `pre_tool_hook.py` 由 IDE 侧直接执行。对它们做内容扫描 = 自指：扫到 CLI 内部的
#   `find … -delete`（gatekeeper-cli.sh L2142 的 gitnexus memo 清理）⟹ CLI 起不来 ⟹
#   advance / apply-worktree 不可达 ⟹ 节点额度与写面都无法复位（实测 2026-10-22 死锁）。
#   安全面：二者本来就无扫描即被执行，豁免不新增任何执行面；且它们受 Gate 3/4 写面与
#   主树只读守卫保护（改动必须经 feature worktree 合入）。
_TRUST_ROOT_SCRIPTS = ("gatekeeper-cli.sh", "pre_tool_hook.py")


def _scan_script_content(command: str) -> tuple[str, str] | None:
    """脚本内容级扫描（2026-08-15，Gate R0.3）：堵"危险命令藏在脚本文件内部"向量。

    事件: E2E 测试脚本 run_e2e.sh 内 `rm -rf "$TMP"` 自删（TMP=脚本自身目录）。
    字符串级 _dangerous_command 只查 RunCommand 外层字符串（wslsh -c 'bash x.sh'
    不含 rm），危险命令在脚本内部行 → 漏检。本函数在 bash/sh/source <script>
    或 wslsh -c '...bash <script>...' 形态下，读取脚本内容逐行跑 _dangerous_command。

    2026-08-20 扩展（测试脚本自身问题高频，上次 $0 递归 + 引号 bug）:
      a. bash -n 语法预检 — 引号/heredoc/unexpected EOF 提前暴露（WSL 嵌套引号 bug 源头）
      b. $0 递归检测 — 测试脚本 bash "$0" 递归调用自身（gatekeeper-cli.sh 的 $0 是子命令分派，豁免）

    安全边界: 大小写敏感豁免保持与字符串 gate 一致（$TMP 大写不豁免会被拦，
    $tmp/${tmp}/$_tmp 为 CLI 内部临时目录白名单）。文件 >256KB 跳过（性能，如
    gatekeeper-cli.sh 343KB）。返回 (reason, hint) 或 None。"""
    import re
    cmd = command.strip()
    script_path = None
    # 形态1: bash/sh/source <file>（含 wslsh -c '...bash <file>...' 内层）
    m = re.search(r"\b(?:bash|sh|source)\s+([^\s'\"|&;]+)", cmd)
    if m:
        candidate = m.group(1)
        if candidate.endswith((".sh", ".bash")) or "/" in candidate:
            script_path = candidate
    # 形态2: bash -c '<payload>' 内联荷载（2026-09-10 E3，用户定案"当脚本体逐行扫"）。
    # 原实现形态1 正则捕到的是 "-c"（无 "/"、非 .sh）→ return None → 内联荷载完全不进
    # 内容扫描。现把引号内荷载当脚本体逐行跑 R0.2（含编码复扫），命中即 BLOCK；
    # 不可静态分析形态（$(...)/cat/xargs）由 _warn_unanalyzable_bash_c 另行告警。
    payload = _bash_c_payload(cmd)
    if payload is not None:
        for i, line in enumerate(payload.split("\n"), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # 内联荷载仍是「这一条命令」的一部分（还没落地）⟹ 吃惰性豁免（A 方案作用域表）
            danger = _dangerous_command_decoded(stripped, inert=True)
            if danger:
                return (f"bash -c 内联荷载 L{i} 命中危险命令: {danger[0][:80]}", danger[1])
        return None
    if not script_path:
        return None
    # 解析为绝对路径（宿主原生形态，相对则拼宿主 cwd）
    # XENV-FORM G-6（2026-09-21 修，ECC-658E1E62B86D）：原式两处把**归一产物**喂给 FS/谓词 ——
    # ① `Path(_win_to_wsl(script_path))` 后接 `exists()` / `is_file()` / `read_text()`：
    #    Windows 宿主下 `/mnt/c/…` 被读成 `C:\mnt\c\…` ⟹ 恒不存在 ⟹ **Gate R0.3 整条静默失效**
    #    （危险命令藏脚本内部的向量重新敞开）；
    # ② `p.is_absolute()` 是**宿主 flavour 相关**谓词，对归一产物问必得 False（同 ③ resolve_path
    #    的 `ECC-AC4695EFEA21`）⟹ 绝对脚本被当相对、拼出双份 cwd。
    # 改吃 `_host_form`（族规则①）：posix 侧 `_win_to_wsl` 对 /mnt 形态恒等、行为零变化；
    # Windows 侧给出宿主可 stat 的形态。
    p = Path(_host_form(script_path))
    if not p.is_absolute():
        p = Path(_host_form(os.getcwd())) / p
    if not p.exists() or not p.is_file():
        return None
    try:
        if p.stat().st_size > 2621440:  # 2026-10-14: 256KB→2.5MB（对齐 STATE_SIZE_WALL ×10，防撞墙）
            return None
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return None
    # 2026-08-20: bash -n 语法预检 — 引号/heredoc/unexpected EOF 提前暴露（WSL 嵌套引号 bug 源头）
    # 语法错误是"脚本自身问题"类，直接 BLOCK 附修正建议，避免跑出误导性失败。
    # 2026-08-23 修复: stdin 方式（input=内容）替代 `bash -n <file>` —
    # Windows pytest 下 WSL bash 无法解析 C:\ 路径（/bin/bash: C:Users... No such file），
    # 且 _win_to_wsl 在测试中被 mock 恒等 → read_text 可读但 bash -n 子进程失配。
    # stdin 无路径依赖，Windows/WSL 双环境一致。
    try:
        # 2026-08-23: 5s → 15s（×3）— WSL bash 冷启动可达数秒，批量测试/首次调用下 5s 超时
        # 被 except: pass 静默跳过 → 语法预检漏检（flaky 测试失败根因）
        _sn = subprocess.run(["bash", "-n"], input="\n".join(lines),
                             capture_output=True, text=True, timeout=15)
        if _sn.returncode != 0:
            _err = (_sn.stderr or _sn.stdout).strip().splitlines()
            _first = _err[0] if _err else "syntax error"
            return (f"script content scan [{p}]: bash -n 语法错误 — {_first[:120]}",
                    "Fix: 修正引号/heredoc 语法后再执行；WSL 下建议 wslsh 落 .sh 避免嵌套引号")
    except Exception:
        pass  # bash 不可用或超时 → 跳过语法预检
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # 2026-08-20: $0 递归检测 — 测试脚本 bash "$0" 递归调用自身是常见逻辑 bug
        # （上次 .tmp_dbg_all.sh 因 $0 递归导致 state.json 空、输出误导）。
        # gatekeeper-cli.sh 的 bash "$0" 是子命令分派（audit --all 并行 spawn），豁免。
        if p.name not in _TRUST_ROOT_SCRIPTS:
            # 引号形态 "$0" 后无需边界（引号后是空格）；裸 $0 需 \b 防匹配 $0xxx 变量
            if re.search(r"\b(?:bash|sh|source)\s+(?:\"\$0\"|\$0\b)", stripped):
                return (f"script content scan [{p} L{i}]: $0 递归调用自身（测试脚本常见逻辑 bug）",
                        "Fix: 显式写目标脚本名（bash ./xxx.sh），勿用 bash \"$0\" 递归自身")
        # 2026-08-28: 编码复扫（RED-HOOK-16）— 脚本内行也可经 base64/hex 编码藏危险命令
        # 2026-09-24（ECC-8DFC84C5B9E5 **作用域**）：本路**不吃**惰性豁免（`inert` 保持默认
        #   False）—— 文件会在别的时刻、被别的调用方执行（`run_e2e.sh` 里 rm -rf 自删事件即此
        #   形态），「当时是不是数据」本层判不了；声明是给「这一条命令」的，写进文件就不再属于它。
        # 2026-10-22 信任根自指豁免（见 `_TRUST_ROOT_SCRIPTS`）：这两个文件是 hook 自己的
        #   执行入口，扫描它们只会把 CLI 锁死（advance / apply-worktree 永不可达）。
        if p.name in _TRUST_ROOT_SCRIPTS:
            continue
        danger = _dangerous_command_decoded(stripped)
        if danger:
            reason, hint = danger
            return (f"script content scan [{p} L{i}]: {reason}",
                    f"Fix: {hint} — 脚本内危险命令需人工确认后再执行")
    return None


# ── Gate R0.4: 插件调用强制统一入口（2026-08-27，插件加载安全网硬门禁）──
# bashpy-migrate / zthl_bashpy_migrate 只允许经 cmd_migrate（gatekeeper-cli.sh migrate）调用：
# 该入口执行 manifest cap 白名单（gk_plugin_manifest.check_capability）+ 加载安全网
# （gk_bashpy_loader：发布包 SHA256 pin / dev 回退审计，拦截 漏加载/误加载/错误加载）。
# 裸调用（直接 bashpy-migrate / python3 -m / python3 -c import）绕过安全网 → BLOCK。
# 普适安全 gate（范围外也执行）——插件属技能仓库功能，与项目治理无关（同 R0.2/R0.3）。
# 元组元素 = (pattern, quote_sensitive)：
#   quote_sensitive=True  → 匹配位置在引号内则跳过（引号内文字引用不算调用方式：
#                           commit message / echo "..." 描述插件名不拦截）；
#   quote_sensitive=False → 引号内也抓（bash -c / python3 -m / python3 -c 内嵌执行是真绕过）。
_PLUGIN_BARE_PATTERNS = (
    # CLI 命令形态：bashpy-migrate 前是段首（行首 / ;&&|( / 空白）或路径分隔（/ \ .）
    # → 可执行名形态；引号内文字（commit message / echo）由 quote_sensitive 排除
    (r"(?:^|[;&|(\s./\\])bashpy-migrate(?:\.exe)?\b", True),
    # bash/sh -c/--command 内嵌执行（引号内代码是真绕过，不是文字引用）
    (r"\b(?:bash|sh)\s+(?:-c|--command)\s*[\"'][^\"']*bashpy-migrate", False),
    # eval 内嵌执行（2026-08-27 红队: eval "bashpy-migrate audit" 引号内是执行代码）
    (r"\beval\s+[\"'][^\"']*bashpy-migrate", False),
    # python3 模块入口 / -c 代码执行（同 -c 内 import，引号内也抓）
    (r"\bpython3?\s+-m\s+zthl_bashpy_migrate\b", False),
    (r"\bpython3?\s+-c\s+[\"'][^\"']*zthl_bashpy_migrate", False),
    # 升级/状态脚本裸调用（2026-08-27 统一入口：生命周期子命令也走 cmd_migrate）
    (r"\bpython3?\s+[^\s;|&]*gk_bashpy_upgrade\.py\b", False),
    # 模块名段首引用（兜底；引号内文字不拦截）
    (r"(?:^|[;&|(\s])zthl_bashpy_migrate\b", True),
    # ── swe-rb 平级注册（2026-08-31，与 bashpy-migrate 同型统一安全网）──
    # zthl-swe-rb 引擎只允许经 cmd_swe_rb（gatekeeper-cli.sh swe-rb）调用：
    # manifest cap 白名单 + gk_swe_rb_loader 加载安全网（dev 源回退审计）。
    (r"(?:^|[;&|(\s./\\])swe-rb(?:\.exe)?\b", True),
    (r"\b(?:bash|sh)\s+(?:-c|--command)\s*[\"'][^\"']*swe-rb", False),
    (r"\beval\s+[\"'][^\"']*swe-rb", False),
    (r"\bpython3?\s+-m\s+zthl_swe_rb\b", False),
    (r"\bpython3?\s+-c\s+[\"'][^\"']*zthl_swe_rb", False),
    (r"(?:^|[;&|(\s])zthl_swe_rb\b", True),
    # ── paper-review 平级注册（2026-09-20，ECC-E4A5EB64FD05 / ECC-PLAN ④）──
    # 病灶（读码 + 报告实证）：gk_paper_review.py **不在**本名单 ⟹ hook 不拦其裸调用；而插件内
    # fail-closed 只校验**自声明**的 GK_PAPER_REVIEW_VIA_CLI=1（任何调用方 export 即可通过）⟹ 直连
    # 即跳过唯一真正跑 gk_paper_review_loader 五源分流 + SHA256 pin 的地方（CLI cmd_paper_review）。
    # 仅 `gatekeeper-cli.sh paper-review`（连字符）为合法入口（豁免见 _plugin_bare_call）。
    # 路径分隔符锚定 `(?:[^\s;|&]*[/\\])?`：既是可选（`python3 gk_paper_review.py` 亦命中），
    # 又使 `scripts/test_gk_paper_review.py` 不误伤（`test_` 前无分隔符）——否则自测被自家 hook 拦死。
    (r"\bpython3?\s+(?:[^\s;|&]*[/\\])?gk_paper_review\.py\b", False),
)


def _in_quotes(s: str, pos: int) -> bool:
    """pos 位置是否在未闭合引号对内部（跳过 \\" / \\' 转义）。"""
    quote = None
    i = 0
    while i < pos:
        ch = s[i]
        if ch == "\\":
            i += 2
            continue
        if quote:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        i += 1
    return quote is not None


def _plugin_bare_call(command: str) -> str | None:
    """检测插件裸调用（绕过统一入口）。统一入口（gatekeeper-cli.sh migrate）放行。

    按命令段（`;`/`&&`/`|` 分割）逐段判定：某段是统一入口 → 该段豁免；
    某段是插件裸调用形态（bashpy-migrate / python3 -m / python3 -c import）→ 命中。
    分号后裸调用不再因"命令含 migrate 字样"而绕过（2026-08-27 修正）。
    段首形态要求非引号内（commit message / echo 文字引用不算调用）；bash -c / python3 内嵌照抓。
    """
    import re
    for seg in re.split(r"[;&|]", command):
        seg = seg.strip()
        if re.search(r"gatekeeper-cli\.sh\s+(?:migrate|swe-rb|paper-review)\b", seg):
            continue  # 该段是统一入口（cmd_migrate / cmd_swe_rb：manifest cap + 加载安全网）
        # node_guard guard 的 --pid swe-rb 是节点标识参数（SRB 节点 G/D 验证），非插件调用。
        # 2026-09-01 误伤修复 → 同日红队收紧（向量 A/B/C，high）：
        #   A: $(python3 -m zthl_swe_rb ...) 命令替换走私 → 段内 $()/反引号/换行 → 拒绝豁免
        #   B: guard --pid swe-rb\npython3 -m zthl_swe_rb（换行非切分符跨行走私）→ \n → 拒绝豁免
        #   C: $(bash -c 'bashpy-migrate audit') 跨插件走私 → 脱敏后全段复扫 _PLUGIN_BARE_PATTERNS
        # 豁免仅适用"纯 guard 调用"形态：node ∈ plugin-c SRB 节点集 + --pid swe-rb 结尾（允许尾部 --ctx）。
        if re.search(r"gk_node_guard\.py\s+guard\b[^\n;]*?--pid\s+swe-rb\b", seg):
            _masked = re.sub(r"--pid\s+swe-rb\b", "--pid <pid>", seg)  # 脱敏合法值形态再扫走私
            _smuggle = False
            for _pat, _qs in _PLUGIN_BARE_PATTERNS:
                for _m in re.finditer(_pat, _masked):
                    if _qs and _in_quotes(_masked, _m.start()):
                        continue
                    _smuggle = True
                    break
                if _smuggle:
                    break
            if (not _smuggle and not re.search(r"\$\(|`|\n", seg)
                    and re.search(r"--node\s+(SRB-ANALYZE|SRB-VERIFY|SRB-AUDIT)\b", seg)
                    and re.search(r"--pid\s+swe-rb(?:\s+--ctx\s+[^;|&]+)?\s*$", seg)):
                continue
        for pat, quote_sensitive in _PLUGIN_BARE_PATTERNS:
            for m in re.finditer(pat, seg):
                if quote_sensitive and _in_quotes(seg, m.start()):
                    continue  # 引号内文字引用不算调用方式
                return pat
    return None


def _plugin_load_status_line() -> str:
    """插件加载安全网状态（与 hook BLOCK 接轨）；失败降级空串，不阻塞。"""
    try:
        sys.path.insert(0, str(SKILL_DIR / "scripts"))
        from gk_bashpy_loader import load_status
        st = load_status()
        return (f"plugin 加载安全网: source={st.get('source')} "
                f"version={st.get('version')} hash_verified={st.get('hash_verified')}")
    except Exception:
        return ""


# ── Gate 8: 技能自维护防裸跑（2026-08-20, R-T8.3）──
# 技能仓库（SKILL_DIR 内）的代码/脚本写操作必须登记在案：
#   放行（任一）:
#     a. gate_data.ecc_findings 存在 status=open 项（修复驱动，ECC-FINDING 闭环）
#     b. state.r_phase 非空（活跃计划执行中，计划驱动）
#     c. 目标在 docs/ 或 .trae/ 或 .gatekeeper.*（计划/配置文档豁免——登记过程本身）
#   拦截: 无登记且非豁免 → BLOCK（裸跑）。提示 finding register 登记缺陷。
# 路径判定复用 resolve_path（与 Gate 3/5/6/7 同源，防 WSL/Windows 路径比较绕过）。
def _gate8_skill_self_maintenance(cwd: str, target: str, state: dict) -> tuple[str, str] | None:
    import re
    resolved = resolve_path(target, cwd)
    if not resolved:
        return None
    # 统一正斜杠 + resolve 消解 ..（resolve_path 对绝对路径不消解，防 `..` 前缀匹配绕过）
    resolved = str(Path(resolved).resolve()).replace("\\", "/")
    skill_n = str(Path(_win_to_wsl(str(SKILL_DIR))).resolve()).replace("\\", "/").rstrip("/")
    if not resolved.startswith(skill_n):
        return None  # 目标不在技能仓库 → 不适用
    # 豁免: 计划/配置/运行时文件（登记过程本身，非裸跑）
    if re.search(r"/(docs|\.trae)/|\.gatekeeper\.", resolved):
        return None
    # a. open finding 登记（修复驱动）
    gd = state.get("gate_data", {}) or {}
    for f in gd.get("ecc_findings", []) or []:
        if isinstance(f, dict) and f.get("status") == "open":
            return None
    # b. 活跃计划（r_phase 非空，计划驱动）
    if state.get("r_phase"):
        return None
    return ("技能自维护裸跑: 修改技能代码/脚本未登记 ECC-FINDING 且无活跃 R-phase。"
            "请先 `gatekeeper-cli.sh finding register '<title>' <source>` 登记缺陷，"
            "或建立/推进计划（advance）后再改。",
            "Fix: gatekeeper-cli.sh finding register '修复目标' crossr  → 再执行本工具")


# ─── H-SLSN: 启发式技能加载安全网（2026-08-27，ECC-8570E847C7C1）───
# ZTHL 理论创新：带状态检测的 while 循环（可编程零信任启发式学习）。
# 双条件与：① hook 生效（本函数被 PreToolUse 触发） ② 用户指令含 "Use Skill: spz-gatekeeper-r-sequence"
#   —— ② 的代理检测 = Skill 工具调用本身（tool_name=="Skill" 且输入含技能名）。
# 机制：激活会话 → 后续工具调用若绕过技能内置 cmd（gatekeeper-cli.sh）→ hook 回环拦截 + 引导
#   → 再次触发安全网。attempts 计数超阈值降级（冷却降频 + 留痕，防死循环且保可观测）；TTL 自动过期；
#   learned[] 记录每次拦截模式 = 观测日志（学习回路留待 R-T8 消费）。
# 2026-08-27 修复（质询缺口②）：_hslsn_save → _hslsn_transact（flock 临界区 + SHA256 嵌入 +
#   os.replace 原子替换）——满足数学公理 A1（原子性）/A2（完整性），9-agent 并发不再丢失更新。
# 2026-08-27 全名化改造（投毒点关闭）：Skill 调用精确匹配全名——
#   a) 合法技能白名单 = 动态扫描 ~/.trae/skills/*/SKILL.md；
#   b) 旧名/歧义名（如 plan-refine）→ 拦截 + 引导全名；
#   c) 未注册技能名 → 拦截（未知命令全部拦截原则）。
# 模型五元组 M=(S_g, E₂, δ, s₀, F) 见计划文档 §4.3。
_HSLSN_FILE = SKILL_DIR / ".gatekeeper.hslsn"
_HSLSN_TTL = 1800.0          # 30 分钟无工具活动自动失活
_HSLSN_MAX_ATTEMPTS = 3      # 回环拦截阈值：超过降级（冷却降频 + 留痕，不硬拦）
# 只读哨兵白名单（2026-10-05 `REV-16` §22.3 · owner 裁定「门禁加只读白名单」）：Phase A 观测脚本
#   `gk_bill_observe.py` —— 纯读 state / 零写盘 / 零阻断 / 不夺锁，且 §21.3 砍-list 明禁经
#   `_CMD_REG` 注册 ⟹ 直跑是其**唯一**可行通道（走后门须注册子命令 = 违背裁定）。
#   **逐字命中整个文件名**、只此一条 ⟹ 不放宽同类（其余 `scripts/gk_*.py` 照拦）。
_HSLSN_READONLY_OK = ("gk_bill_observe.py",)
# 旧名 → 全名映射（歧义名拦截引导；2026-08-27 全名化）
_HSLSN_LEGACY_NAMES = {"plan-refine": "plan-refinement"}
# 主技能精确名（H-SLSN 激活条件 ②）
_HSLSN_PRIMARY_SKILL = os.environ.get("GK_PRIMARY_SKILL", "spz-gatekeeper-r-sequence")


def _hslsn_win_skill_roots() -> list:
    """WSL 运行环境下的 Windows 用户技能根（2026-08-28 修复）。

    根因：hooks.json 经 `wsl bash .../pre_tool_hook_wrapper.sh` 调用本脚本（wrapper
    `exec python3`），WSL 下 Path.home() 指向 WSL home（/home/HP），`~/.trae/skills`
    不存在 → 白名单空集 → 任何非主技能名（如 git-workflow）都被判"未注册"误拦。
    补扫 /mnt/c/Users/<user>/.trae/skills 与 .trae-cn/skills（Trae CN 全局根）。
    Windows 原生运行（无 /mnt/c）返回空列表，行为不变。"""
    roots = []
    try:
        if Path("/mnt/c").is_dir():
            for u in Path("/mnt/c/Users").iterdir():
                if u.is_dir():
                    roots.append(u / ".trae" / "skills")
                    roots.append(u / ".trae-cn" / "skills")
    except Exception:
        pass
    return roots


def _hslsn_installed_skills() -> set:
    """动态扫描已安装技能白名单（原生 ~/.trae/skills + WSL 补扫 Windows 用户根）。
    失败 → 空集（保守：不拦截正常调用）。"""
    roots = [Path.home() / ".trae" / "skills"] + _hslsn_win_skill_roots()
    found = set()
    for base in roots:
        try:
            if base.is_dir():
                found |= {p.name for p in base.iterdir()
                          if p.is_dir() and (p / "SKILL.md").exists()}
        except Exception:
            continue
    return found


def _hslsn_skill_name(tool_input: dict) -> str:
    """从 Skill 工具输入提取技能名：优先 name/skill/skill_name 字段；
    回退 JSON 全文精确匹配主技能名（兼容旧格式 tool_input 无 name 字段的调用）。"""
    for key in ("name", "skill", "skill_name", "skillName"):
        v = tool_input.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    # 回退：全文精确提取主技能名（词边界匹配，避免子串误报）
    s = json.dumps(tool_input, ensure_ascii=False)
    import re as _re
    if _re.search(r'"%s"' % _HSLSN_PRIMARY_SKILL, s):
        return _HSLSN_PRIMARY_SKILL
    return ""


def _hslsn_load() -> dict:
    """读状态 + checksum 校验（公理 A2）：篡改/损坏 → 视为 inactive（fail-safe）。"""
    import hashlib as _hl
    import json as _json
    try:
        d = _json.loads(_HSLSN_FILE.read_text(encoding="utf-8"))
        if not isinstance(d, dict):
            return {}
        cs = d.pop("_checksum", "")
        payload = _json.dumps(d, ensure_ascii=False, sort_keys=True)
        if cs and _hl.sha256(payload.encode()).hexdigest()[:16] != cs:
            _log_hook("H-SLSN: checksum mismatch — state treated as inactive (tamper fail-safe)")
            return {}
        return d
    except Exception:
        return {}


def _hslsn_transact(mutator) -> dict:
    """flock 保护下的读-改-写原子事务（公理 A1）。返回新状态。
    mutator: d -> d'（读取已校验状态，返回修改后状态）。任何异常 → 回滚（不落盘）。"""
    import hashlib as _hl
    import json as _json
    try:
        import fcntl
    except ImportError:  # 非 POSIX（理论上 WSL 必有 fcntl，兜底退化非原子写）
        fcntl = None
    try:
        if fcntl is not None:
            lock_fd = open(f"{_HSLSN_FILE}.lock", "w")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)  # 阻塞锁：read-modify-write 原子
        d = _hslsn_load()
        new_d = mutator(d)
        payload = _json.dumps(new_d, ensure_ascii=False, sort_keys=True)
        new_d["_checksum"] = _hl.sha256(payload.encode()).hexdigest()[:16]
        tmp = _HSLSN_FILE.with_suffix(".hslsn.tmp")
        tmp.write_text(_json.dumps(new_d, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, _HSLSN_FILE)  # 原子替换
        return new_d
    except Exception:
        return _hslsn_load()
    finally:
        try:
            if fcntl is not None:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                lock_fd.close()
        except Exception:
            pass


def _hslsn_activate() -> None:
    def _mut(d):
        d["active"] = True
        d["activated_at"] = int(time.time())
        d["attempts"] = 0
        d.setdefault("learned", [])
        d["last_ts"] = d["activated_at"]
        return d
    _hslsn_transact(_mut)
    _log_hook("H-SLSN: session activated (skill loading)")


def _hslsn_active() -> bool:
    d = _hslsn_load()
    if not d.get("active"):
        return False
    ts = d.get("last_ts") or d.get("activated_at") or 0
    try:
        if time.time() - float(ts) > _HSLSN_TTL:
            # TTL 过期 → 失活（公理 A5 时间自愈）
            def _mut(x):
                x["active"] = False
                return x
            _hslsn_transact(_mut)
            return False
    except (TypeError, ValueError):
        pass
    return True


def _hslsn_touch() -> None:
    def _mut(d):
        d["last_ts"] = int(time.time())
        return d
    _hslsn_transact(_mut)


def _hslsn_bypass(tool_name: str, tool_input: dict, command: str, file_path: str, cwd: str) -> str | None:
    """会话激活时检测绕过技能内置 cmd 的调用。合法返回 None，绕过返回引导消息。
    2026-08-27 修复（质询缺口③，公理 A3）：shlex 分词 + 分段（; && |）判定，
    剥离引号/多余空白/解释器变体（python3.12 等）后仍命中 scripts/gk_*.py 与裸 grep/rg。
    2026-09-24（用户裁定「裸 find 拦截加回去」）：裸 `find` 同列 —— 引导指向**高性能替代**
    `fdfind`（sharkdp/fd，Rust 并行；本环境 `/usr/bin/fdfind` v8.3.1）与 `search` CLI 路由。"""
    import re as _re
    import shlex as _sh
    if "gatekeeper-cli.sh" in command:
        return None  # 合法：技能内置 cmd 统一入口
    # 分段（; && |）逐段判定，剥离 shell 包装（wsl bash -c "...") 后取最内层 token
    for seg in _re.split(r"[;&|]", command):
        # 递归剥离 shell 包装层：bash -c '...' / sh -c "..." / wsl bash -c "..."
        inner = seg
        for _ in range(4):
            m = _re.search(r"(?:bash|sh)\s+-c\s+['\"](.+?)['\"]\s*$", inner)
            if not m:
                break
            inner = m.group(1)
        try:
            tokens = _sh.split(inner)
        except ValueError:
            tokens = inner.split()
        if not tokens:
            continue
        exe = os.path.basename(tokens[0]).lower()
        rest = " ".join(tokens[1:])
        # 绕过：直接执行 scripts/gk_*.py（跳过 CLI 门禁/审计留痕/上下文注入）
        if exe in ("python3", "python", "py", "python3.12", "python3.11", "python3.10"):
            m = _re.search(r"scripts/(gk_[\w-]+\.py)", rest)
            # 只读哨兵放行（`_HSLSN_READONLY_OK`，逐字命中）；其余 `scripts/gk_*.py` 照拦。
            if m and m.group(1) not in _HSLSN_READONLY_OK:
                return ("直接执行 scripts/gk_*.py 绕过技能内置 cmd — CLI 统一入口（gatekeeper-cli.sh）"
                        "含门禁+审计留痕+上下文注入。请改用 `gatekeeper-cli.sh <cmd>`（audit/self-check/docgen/…）。")
        # 绕过：裸 grep/rg/find 代替 search CLI（技能路由规定：跨仓库搜索须 gatekeeper-cli.sh search --repo <name>）
        if tool_name == "RunCommand" and exe in ("grep", "rg", "find", "rg.exe", "grep.exe", "find.exe"):
            if exe.startswith("find"):
                return ("裸 find 违反技能路由规定 — 本地文件查找请用 `fdfind`（sharkdp/fd 高性能替代："
                        "Rust 并行、默认忽略 .gitignore、比 `find -iname` 快一个量级）；"
                        "跨仓库搜索仍走 `gatekeeper-cli.sh search <pattern> --repo <name>`。禁裸跑。")
            return ("裸 grep/rg 违反技能路由规定 — 跨仓库搜索须经 `gatekeeper-cli.sh search <pattern> --repo <name>`"
                    "（四层金字塔，禁止裸跑）。")
    # 注：技能代码编辑不在此拦截（Gate 8 已强制登记+guard-edit 流程），避免与自维护流程冲突。
    return None


def _hslsn_record_and_verdict(bypass: str) -> tuple[str, str] | None:
    """记录拦截模式（观测日志）+ 返回回环裁决（公理 A6 可观测性）。
    attempts 超阈值降级：不硬拦截（引导网 fail-open 保可用性，防 DoS），
    冷却降频 + HOOK_LOG 留痕（观测不丢）。"""
    result = {}

    def _mut(d):
        d["attempts"] = d.get("attempts", 0) + 1
        learned = d.setdefault("learned", [])
        if not any(bypass[:40] in l for l in learned):
            learned.append(bypass[:200])
        result["attempts"] = d["attempts"]
        return d

    _hslsn_transact(_mut)
    if result.get("attempts", 0) <= _HSLSN_MAX_ATTEMPTS:
        return (bypass, "Fix: 使用技能内置 cmd — gatekeeper-cli.sh <子命令>（35 命令见 references/cli-protocol.md）")
    # 降级：冷却降频 + 留痕（可观测不丢；阈值内已硬拦截 3 次，继续硬拦 = 拒绝服务）
    _log_hook(f"H-SLSN: attempts={result.get('attempts')} > {_HSLSN_MAX_ATTEMPTS} — degraded, log-only (observable)")
    return None


def _entropy_warn(entropy) -> str:
    """熵高时生成 WARN 提示（2026-08-23 交叉审查 #3: 优化器↔安全网接轨）。
    R4 熵监视器阈值: >0.3 升级 --api, >0.5 硬阻断。hook 主动提示替代被动 context。"""
    try:
        e = float(entropy)
    except (TypeError, ValueError):
        return ""
    if e > 0.5:
        return f"GATEKEEPER-WARN: entropy={e:.2f} > 0.5 — advance 将被 R4 硬阻断, 需 appeal (见 gatekeeper-cli.sh reflect)"
    if e > 0.3:
        return f"GATEKEEPER-WARN: entropy={e:.2f} > 0.3 — advance 将升级 monitor 到 --api (R4 熵监视器)"
    return ""


def _unreconciled_debt_warn(cli_result) -> str:
    """r9-2 ②a「未审债 ⟹ **下一节点门可见**」（`ECC-BCF60C185CBE`，owner 裁定 A，2026-10-01）。

    CLI `pre-tool-check` 放行面**透传** `gk_edit_gate.py` 算好的未审债（复用那次**已付**的子进程
    ⟹ 零边际开销）⟹ 本函数只做**可见性**：回 `GATEKEEPER-WARN:` 文案（既有 stderr 通道，与
    `_entropy_warn` 同型）。**不改判定**（放行照旧、非阻断）。无债 / 无该面（非写类工具或旧 CLI）
    ⟹ 空串（**不误报**）。
    """
    if not isinstance(cli_result, dict):
        return ""
    eg = cli_result.get("edit_gate")
    debt = list(((eg or {}).get("unreconciled_raises") or []) if isinstance(eg, dict) else [])
    if not debt:
        return ""
    _ids = ", ".join(str(x) for x in debt[:5])
    _tail = "" if len(debt) <= 5 else " …(共 %d 笔)" % len(debt)
    return ("GATEKEEPER-WARN: 未审债 %d 笔（credit-ledger 有 raise 无 outcome 回填）: %s%s"
            " — 对账口径见 gk_credit_ledger.reconcile / 计划 §19.2" % (len(debt), _ids, _tail))


def block(reason: str, hint: str = "") -> None:
    """Write goal-like context summary + reason (+ optional fix hint, W5) to stderr and exit 2 (BLOCK)."""
    # 2026-09-02: 被禁意图持久化（工具失效→提权绕过 防线②）——先记录再退出
    global _CALL_REASON
    _CALL_REASON = reason or ""
    _record_block_intent()
    # Read state for context summary (non-fatal if missing)
    ctx_lines = []
    if STATE_FILE.exists():
        try:
            s = json.loads(STATE_FILE.read_text())
            stage = s.get("stage", "?")
            phase = s.get("r_phase", "?")
            wt = s.get("worktree", "?")
            branch = s.get("branch", "?")
            entropy = s.get("gate_data", {}).get("entropy_rate", "?")
            ctx_lines.append(f"GATEKEEPER: stage={stage} phase={phase} branch={branch} entropy={entropy}")
            ctx_lines.append(f"GATEKEEPER: worktree={wt}")
            ew = _entropy_warn(entropy)
            if ew:
                ctx_lines.append(ew)
        except Exception:
            ctx_lines.append("GATEKEEPER: state=corrupt")
    else:
        ctx_lines.append("GATEKEEPER: state=absent (no active R-phase)")
    ctx_lines.append(f"GATEKEEPER-BLOCK: {reason}")
    if hint:
        ctx_lines.append(f"GATEKEEPER-FIX: {hint}")
    sys.stderr.write("\n".join(ctx_lines) + "\n")
    _log_hook(f"BLOCK: {reason}" + (f" | FIX: {hint}" if hint else ""))
    sys.exit(2)


def emit_context_if_changed() -> None:
    """Read context file; print to stderr if checksum differs from last seen.
    
    Outputs a short one-liner on state transitions so the agent passively sees
    the current gatekeeper phase without needing to run CLI commands.
    Only fires when the context checksum changes (not on every tool call).
    """
    if not CONTEXT_FILE.exists():
        return
    try:
        ctx = json.loads(CONTEXT_FILE.read_text())
        cs = ctx.get("_checksum", "")
        if not cs:
            return
        last_cs = ""
        if _CONTEXT_SEEN_FILE.exists():
            last_cs = _CONTEXT_SEEN_FILE.read_text().strip()
        if cs != last_cs:
            # State changed — emit one-liner context
            stage = ctx.get("stage", "?")
            r_phase = ctx.get("r_phase", "?")
            branch = ctx.get("branch", "?")
            entropy = ctx.get("entropy_rate", "?")
            eb = ctx.get("edit_budget", {})
            remaining = eb.get("remaining", "?")
            # r_phase is used as-is: "R7", "ECO-RESEARCH", "ECC-IMPACT" all valid
            sys.stderr.write(
                f"GATEKEEPER: {r_phase} | {stage} | branch={branch} | "
                f"entropy={entropy} | edits_remaining={remaining}\n"
            )
            ew = _entropy_warn(entropy)
            if ew:
                sys.stderr.write(ew + "\n")
            _CONTEXT_SEEN_FILE.write_text(cs)
    except Exception:
        pass  # non-fatal — don't block on context output failure


# ── T6 telemetry（2026-10-08，§25）：验证动作事件（**只采集，不判罚**）─────────────────
# 载体 = `<state>.edit-log.jsonl` 的 `kind=verify` 记录，与 `kind=edit` 同文件、同**单源写者**
#   （`gk_budget_ledger.append_verify`，禁本文件第二实现）。目的：让「编辑之后是否发生验证动作」
#   成为可观测事实（§23.6-3 的信号源），供 T6（跨文件未验证加价，本批**未判罚**）与 T4′
#   的「未验证腿」消费。识别面 = RunCommand 命令串。
# fail-safe 纪律：识别/写入失败**一律不阻断**（遥测不得把正常命令拦停）；`GK_EDIT_LOG=0` 整体关。
_VERIFY_CMD_TOKENS = (
    "pytest", "ctest", "run_verify.sh",
    "npm test", "npm run test", "yarn test", "pnpm test",
    "go test", "cargo test", "mvn test", "gradle test",
    "bash -n",
    "gatekeeper-cli.sh self-check", "gatekeeper-cli.sh audit", "gatekeeper-cli.sh doc-align",
    "gk_self_check.py", "gk_audit_state.py",
)


def _emit_step_event(cmd: str, node: str = "") -> None:
    """落一条 `kind=step`（步数 telemetry，2026-10-23）。**永不抛出**（fail-safe，不阻断调用）。

    为何要步数：本仓计费面只数「唯一改动文件」，`RunCommand` 免费 ⟹ 空转不可观测；而业界
    （Agents SDK 10 / LangGraph 25 / SWE-agent 250 / OpenHands 500）的主计量单位正是步数。
    本批**只采集不判罚**（与 T6 同一纪律），分布由 `gk_budget_ledger.py step-stats` 读出。
    """
    try:
        if os.environ.get("GK_EDIT_LOG", "1") == "0":
            return
        if os.environ.get("GK_STEP_LOG", "1") == "0":
            return
        if not Path(str(STATE_FILE)).exists():
            return
        import gk_budget_ledger as _bl  # noqa: E402（同目录单源；延迟导入防循环）
        _bl.append_step(str(STATE_FILE), session=_SESSION_ID, node=node, cmd=cmd)
    except Exception:
        pass


def _emit_step_event_unscoped(cmd: str) -> None:
    """scope_out 分支的步数采集（2026-10-23）。**永不抛出**。

    ⚠ 必须与范围内分支**两处都接**：只接一处会重演 T6 的「采样点够不着」缺陷（会话 cwd 常为
    `c:\\Users\\HP`，走 scope_out 后直接 `sys.exit(0)`）。session 归位规则同 T6（别名优先）。
    """
    try:
        if os.environ.get("GK_EDIT_LOG", "1") == "0":
            return
        if os.environ.get("GK_STEP_LOG", "1") == "0":
            return
        st = Path(str(STATE_FILE))
        if not st.exists():
            st = SKILL_DIR / ".gatekeeper.state"
        if not st.exists():
            return
        import gk_budget_ledger as _bl  # noqa: E402
        node = ""
        try:
            node = str((json.loads(st.read_text(encoding="utf-8")) or {}).get("stage", "") or "")
        except Exception:
            node = ""
        sess = _read_session_alias(_SESSION_ID) or _SESSION_ID
        _bl.append_step(str(st), session=sess, node=node, cmd=cmd)
    except Exception:
        pass


def _is_verify_command(cmd: str) -> bool:
    """命令串是否属**验证动作**（T6 telemetry 信号源）。纯识别、零副作用。

    宽松子串匹配（**只采集** ⟹ 误报代价低）；判据收紧留待 T6 判罚落刀时（§23.6-2/§25）。
    """
    c = cmd or ""
    return any(t in c for t in _VERIFY_CMD_TOKENS)


def _emit_verify_event(cmd: str, node: str = "") -> None:
    """落一条 `kind=verify` 事件（T6 telemetry）。**永不抛出**（fail-safe；不阻断调用）。"""
    try:
        if os.environ.get("GK_EDIT_LOG", "1") == "0":
            return
        if not Path(str(STATE_FILE)).exists():
            return
        import gk_budget_ledger as _bl  # noqa: E402（同目录单源；此处延迟导入防循环）
        _bl.append_verify(str(STATE_FILE), session=_SESSION_ID, node=node, cmd=cmd)
    except Exception:
        pass


def _emit_verify_event_unscoped(cmd: str) -> None:
    """scope_out 分支的 T6 验证采集（2026-10-23，**销账通道**修复）。**永不抛出**。

    病象（实测）：会话 cwd 常为 `c:\\Users\\HP`（治理范围外）⟹ `scope_out` ⟹ 本分支在跑完
    普适闸后直接 `sys.exit(0)` ⟹ **永不**到达范围内分支尾部的 `_emit_verify_event` ⟹
    全仓 `.gatekeeper.state.edit-log.jsonl` 的 `kind=verify` **恒 0** ⟹ T6 的 `unverified`
    只增不减（实测 `budget-probe/ECO-AUDIT` unverified=10）⟹ 节点每刀 `cost=2`，
    `max=8` 实际只剩 4 刀，且**无法销账**。本函数就是缺的那一半。
    state 归属：优先模块 `STATE_FILE`（若存在），否则技能主 state —— 与 Edit 计费写入的
    state 同一份（实测 edit-log 的 session/node 即落在此）。判据单源 = `_is_verify_command`。
    """
    try:
        if os.environ.get("GK_EDIT_LOG", "1") == "0":
            return
        st = Path(str(STATE_FILE))
        if not st.exists():
            st = SKILL_DIR / ".gatekeeper.state"
        if not st.exists():
            return
        import gk_budget_ledger as _bl  # noqa: E402（同目录单源；延迟导入防循环）
        node = ""
        try:
            node = str((json.loads(st.read_text(encoding="utf-8")) or {}).get("stage", "") or "")
        except Exception:  # noqa: BLE001 — 读不到 node 不阻断采集
            node = ""
        # 2026-10-23：归位到 worktree token（= Edit 计费的桶）；无别名则用载荷 sid。
        sess = _read_session_alias(_SESSION_ID) or _SESSION_ID
        _bl.append_verify(str(st), session=sess, node=node, cmd=cmd)
        _log_hook(f"T6-VERIFY scope-out session={sess} node={node} cmd={cmd[:80]}")
    except Exception:  # noqa: BLE001 — 遥测不得阻断调用
        pass


def allow() -> None:
    """Exit 0 (ALLOW) — output context before exiting."""
    _log_hook("ALLOW")
    emit_context_if_changed()
    sys.exit(0)


def _protected_target_line(tool_name: str, tool_input: dict, resolved: str) -> str:
    """算出本次编辑在目标文件中的**行级**位置集合（1-based，逗号分隔）；不可得 → "0"（文件级）。

    2026-09-22（ECC-BFE933526D0B 修复）：Gate 4 原本只传路径，CLI 侧因此恒以 `target_line=0`
    走「文件级 WARN」分支 ⟹ `_protected_region_check` 的行级 BLOCK 分支在自动化拦截路径上
    **永不可达**（红先实测：改 `_CMD_REG` 所在行得 rc=0 + 仅一行 WARN ⟹ 守区形同虚设）。

    2026-09-23（R25 洞口补漏）：原式只回**单个**行号（首个匹配 / 首个差异）⟹ 整文件重写时
    「首行差异在区外、后续差异在区内」以区外行号进入 CLI ⟹ 仍是 fail-open。现回**全部**命中行：

      - `SearchReplace`/`Edit`：`old_str` 首个匹配起始行 .. 被替换区间末行（取 old/new 较长者）
      - `Write`：新旧内容**全部差异行**（含尾部长度差）
      - 其余（CreateFile / DeleteFile / 读不到文件 / 无载荷 / 内容全同）→ "0"（文件级 WARN 放行）

    只读目标文件、不写任何东西；异常一律退 "0" —— 本函数只**提供线索**，
    判定权仍在 CLI 的 `_protected_region_check`（单一事实源，此处不复制其区间逻辑）。
    """
    try:
        cur = Path(_host_form(resolved)).read_text(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001 — 任一侧不可得即退文件级（不阻断）
        return "0"
    # 2026-10-13（`ECC-317C82A14DE8` ①）：MCP 写形态参数**在 `args` 下**（`_mcp_inner_tool` 自证：
    #   `run_mcp` → `tool_input["args"]`；`mcp__…` → 同构）⟹ 先剥 `args` 再取值（复用单源解析，
    #   禁第二份）。否则 MCP 写恒退 "0" ⟹ 保护区行级判定与 `_pe_record` 留痕不可达。
    _inner, _margs = _mcp_inner_tool(tool_name, tool_input)
    if _inner:
        tool_input = _margs if isinstance(_margs, dict) else {}
    # 逐条跨度：native `old_str`/`new_str` + filesystem MCP `edit_file` 的 `edits[].oldText/newText`。
    _spans: list = []
    _old = tool_input.get("old_str")
    if isinstance(_old, str) and _old:
        _spans.append((_old, tool_input.get("new_str")))
    _edits = tool_input.get("edits")
    if isinstance(_edits, list):
        for _e in _edits:
            if isinstance(_e, dict) and isinstance(_e.get("oldText"), str) and _e["oldText"]:
                _spans.append((_e["oldText"], _e.get("newText")))
    if _spans:
        _hits: list = []
        for _o, _n in _spans:
            _idx = cur.find(_o)
            if _idx < 0:
                continue
            _start = cur[:_idx].count("\n") + 1
            _nspan = (_n.count("\n") + 1) if isinstance(_n, str) else 1
            _span = max(_o.count("\n") + 1, _nspan)
            _hits.extend(range(_start, _start + _span))
        return ",".join(str(_n) for _n in sorted(set(_hits))) if _hits else "0"
    new = tool_input.get("content")
    if isinstance(new, str):
        cur_lines = cur.split("\n")
        new_lines = new.split("\n")
        diff = [i + 1 for i, (a, b) in enumerate(zip(cur_lines, new_lines)) if a != b]
        if len(new_lines) != len(cur_lines):
            diff.extend(range(min(len(cur_lines), len(new_lines)) + 1,
                              max(len(cur_lines), len(new_lines)) + 1))
        return ",".join(str(n) for n in diff) if diff else "0"
    return "0"


def _run_cli(cmd: list) -> dict:
    """Run CLI command and return JSON."""
    try:
        # ECC-3104B66AA4EE（2026-09-23 修）：**透传当前已解析的 `STATE_FILE`**。
        #   原式无 `env=` ⟹ 子进程只继承父进程环境（无 `STATE_FILE`）⟹ CLI 自行回退
        #   「默认 state + plan 指针」⟹ Gate 1-3 用域化/worktree 本地 state、而 Gate 4 的
        #   `pre-tool-check` 用**主 state**。
        #   契约：**覆盖**而非替换（`{**os.environ, ...}`）—— 只钉 `STATE_FILE`，其余照旧，
        #   否则 `PATH` 丢失会让子进程 bash 起不来。`_WSLENV_SENSITIVE`(L631) 早已含
        #   `STATE_FILE` ⟹ 设计上本就要透传，此处只是补上漏掉的接线（零行为面扩展）。
        # 2026-09-25（`ECC-F6C94D444CC6`）：**并行会话共用同一预算计数器**这一 hook 侧根因
        #   已由会话隔离收口 —— 同一处 env 追加 `GK_SESSION_ID`（取自 PreToolUse 载荷
        #   `session_id`）⟹ Gate 4 的 `edit_budget` 按会话分别计数，互不饿死。
        # [ECC-1FAEE0EC9E6E] 宿主边界：Windows 宿主下 `bash` = WSL 的 bash（`C:\windows\system32\
        #   bash.exe`），它**不认** `C:\…` 形态路径 ⟹ 原式把 Windows 形态 `CLI_PATH` / 路径参数 /
        #   `STATE_FILE` 直接喂进去 ⟹ `No such file` ⟹ **stdout 为空** ⟹ 调用方（宿主配置护栏 /
        #   Gate 4）**fail-closed 误拦**（实测 arm1/arm5 exit=2、reason 全空）。修：Windows 宿主把
        #   CLI 路径、**路径形**参数（`X:` 开头）、`STATE_FILE` 一并转 `/mnt/…`；非 Windows 逐字不变。
        def _wsl_form(x):
            s = str(x)
            if not _IS_WIN_HOST:
                return s
            if len(s) > 1 and s[1] == ":":
                return _win_to_wsl(s)
            # WSL 形路径在 Windows 上被 `pathlib.Path` **反斜杠化**（`/mnt/c/x` → `\mnt\c\x`）——
            #   直接喂 WSL bash 会因反斜杠被吃而找不到（`\mnt\c\x`）。故归一为正斜杠；无分隔符的
            #   普通实参（子命令名 / 工具名，如 `pre-tool-check`、`Write`）逐字不变。
            return s.replace("\\", "/")

        _env = {**os.environ, "STATE_FILE": _wsl_form(STATE_FILE),
                # 2026-09-25：会话键透传 —— 缺失（老载荷/手工调用）→ 空串 ⟹ CLI 回退全局计数。
                "GK_SESSION_ID": _SESSION_ID,
                # 2026-09-23（用户裁定「加速 hook 进程」；实测驱动）：Gate 4 是本 hook 的**唯一大额**
                #   开销 —— 一次 `pre-tool-check` 实测 **1.13–1.50 s**（对照纯 python 启动仅 0.032 s），
                #   即每次 Edit/Write 都要付这笔钱；其成本主要是 bash 起 CLI + CLI 内部多次
                #   `python3 -c` 子进程，而每个子进程都会尝试在 `/mnt/c`（CIFS/9p）上写 `.pyc`。
                #   本行禁写字节码 ⟹ 去掉每个子进程一次跨 fs 落盘往返（纯提速，不改任何判据）。
                "PYTHONDONTWRITEBYTECODE": "1"}
        if _IS_WIN_HOST:
            # [ECC-1FAEE0EC9E6E] **宿主 env 不穿透**（与上一处路径修同源；实证见 `bash -c
            #   'echo "[$STATE_FILE]"'` 从 Windows 侧起 proc 打出 `[]`）：Windows 侧 `bash` 是
            #   **WSL 启动器** `C:\windows\system32\bash.exe`，它**只**把 `WSLENV` 白名单内的
            #   Windows 变量带进 WSL（本仓先例：`wslsh.ps1`、`gk_env_inject`、CLI 派发前
            #   WSLENV 并入）⟹ 原式只写 `env=STATE_FILE=…` 在 Windows 宿主上**根本不生效**，
            #   CLI 退回**默认 state**（实测 CLI 内 `STATE_FILE=` 被打成主树 `.gatekeeper.state`）
            #   ⟹ 宿主配置留痕落到**错的账本**（本用例即表现为「零留痕」）。修：并入 WSLENV。
            #   · 只并入**非空**键（空串进白名单会让下游见「存在但空」而不回落默认值）；
            #   · `STATE_FILE` 带 `/u`（本仓 `_WSLENV_SENSITIVE` 契约：敏感项原样透传、禁路径翻译）；
            #   · 值已是 WSL 形（`_wsl_form`）⟹ 无需 `/p`；已有同键不重复。
            _prev = os.environ.get("WSLENV", "")
            _have = {p.split("/", 1)[0] for p in _prev.split(":") if p}
            _add = [k + f for k, f in (("STATE_FILE", "/u"), ("GK_SESSION_ID", ""),
                                       ("PYTHONDONTWRITEBYTECODE", ""))
                    if _env.get(k) and k not in _have]
            if _add:
                _env["WSLENV"] = (_prev + ":" + ":".join(_add)) if _prev else ":".join(_add)
        result = subprocess.run(
            ["bash", _wsl_form(CLI_PATH)] + [_wsl_form(c) for c in cmd],
            capture_output=True,
            text=True,
            timeout=30,
            env=_env,
        )
        lines = [ln.strip() for ln in result.stdout.strip().split("\n") if ln.strip()]
        for line in lines:
            if line.startswith("{"):
                return json.loads(line)
        # f9（ECC-12836BA40C51 / 同族 ECC-4FAF495FFF27，2026-09-22 实测）：CLI 的阻断面是
        # **纯文本**（`BLOCK: …` + `HINT: …`），而旧 fallback 只回 `raw` ⟹ 调用方
        # `cli_result.get("error", "unknown")` 恒得 `unknown` ⟹ 真因（例如
        # `edit_budget exhausted (used=4/max=4, remaining=0)`）对操作者**不可达**。
        # 出口：非 JSON 时把首条 BLOCK/ERROR 行回填 `error`（无则末行），`raw` 原样保留
        # 供 Gate 4 的 `kind=budget` 判别与 hook_block_log 取证。
        err = ""
        for ln in lines:
            if ln.startswith(("BLOCK", "ERROR")):
                err = ln
                break
        if not err and lines:
            err = lines[-1]
        # 2026-09-24（用户裁定「t5 可消解的摩擦全部修掉」）：**回填 `stderr`**。
        #   CLI **boot 失败**（`bash -n` 未过 / 解释器缺失）时 stdout 为**空** ⟹ 上面两条
        #   出口都拿不到文案 ⟹ Gate 4 退到 `unknown`（现场实测：`CLI pre-tool-check failed:
        #   unknown`，而真因 `bash: … syntax error near unexpected token` **只在 stderr**）。
        #   本键纯**可观测性**面：不改任何判据/放行逻辑（Gate 仍 fail-closed）。
        return {"ok": result.returncode == 0, "raw": result.stdout, "error": err,
                "stderr": result.stderr}
    except Exception as e:
        return {"ok": False, "error": str(e), "stderr": ""}


def _win_to_wsl(p: str) -> str:
    """Convert Windows path (C:\\path) to WSL path (/mnt/c/path).
    
    Without this, Gate 3/5/6/7 path comparison silently bypasses:
    WSL Python sees 'C:\\...' as a RELATIVE path (not /-prefixed),
    so Path.resolve() produces garbage like /mnt/c/.../C:\\...,
    and startswith(wt_norm) never matches. See test in .tmp_path_test.py.
    """
    import re
    m = re.match(r'^([A-Za-z]):\\(.*)', p)
    if m:
        drive = m.group(1).lower()
        rest = m.group(2).replace("\\", "/")
        return f'/mnt/{drive}/{rest}'
    m = re.match(r'^([A-Za-z]):/(.*)', p)
    if m:
        drive = m.group(1).lower()
        rest = m.group(2)
        return f'/mnt/{drive}/{rest}'
    return p


def _wsl_to_win(p: str) -> str:
    """Convert WSL path (/mnt/c/path) to Windows path (C:/path).

    Counterpart of _win_to_wsl: .gatekeeper.plan 指针与 scopes 的 state_file
    可能由 WSL 侧 CLI 写成 /mnt 形态；Windows python 跑 hook 时需反转为盘符
    才能 exists()。非 /mnt 形态原样返回。"""
    import re
    m = re.match(r'^/mnt/([a-zA-Z])/(.*)', p)
    if m:
        return f'{m.group(1).upper()}:/{m.group(2)}'
    return p


def resolve_path(path: str, cwd: str) -> str:
    """Resolve a potentially relative path to absolute."""
    if not path:
        return ""
    # XENV-FORM ①（2026-09-24 修，岛内 ECC-E136E7C1389A · 源 ECC-AC4695EFEA21@runtime 域）：
    # 原式把**归一产物** `_win_to_wsl` 喂给 FS 操作与 flavour 谓词 —— Windows 宿主下
    # `Path("/mnt/c/…").is_absolute()` 为 **False**（绝对路径被当相对）且 `Path("/mnt/c/…")`
    # 被读成 `C:\mnt\c\…` ⟹ 与 cwd 再拼一次 = `C:/mnt/c/…`（亚型 B；消费方
    # `_gate8_skill_self_maintenance` 与 `main()` 的 `_CALL_TARGET`）。
    # 改吃 `_host_form`（族规则①，见本文件 `_host_form` docstring）：posix 侧 `_win_to_wsl`
    # 对 /mnt 形态恒等 ⟹ 行为**逐字节不变**；Windows 侧给出宿主可判的 `C:/…` 形态。
    # 返回值仍**包裹回 WSL 比较键形态**（`_win_to_wsl`）—— Gate 3/5/6/7 startswith 消费侧契约。
    path = _host_form(path)
    cwd = _host_form(cwd)
    
    p = Path(path)
    if p.is_absolute():
        return _win_to_wsl(str(p))
    if cwd:
        return _win_to_wsl(str((Path(cwd) / path).resolve()))
    return _win_to_wsl(str(p.resolve()))


# ═══════════ Gate 1b: 交叉审查车道节点绑定（2026-09-06，用户批评点闭环）═══════════
# 背景缺陷（L2-L5/L9/L10 绕过 + IDLE 裸跑）:
#   ① CLI 侧 _review_channel_preflight 的 CROSSREVIEW_NODE_BINDING 只对 channel=crossrev
#     （monitor --subagent --crossrev 显式声明）生效；后R 双独立 audit/红队 subagent 走
#     monitor --subagent（不带 --crossrev）→ 无节点绑定 → 可在任意阶段裸跑。
#   ② 确定性车道（audit --crossr/doc-align/self-check/monitor --local/audit --red）0-API，
#     CLI 设计允许 active 阶段运行 → "全量 L1-L10 交叉审查" 可只跑确定性部分、跳过
#     subagent/LLM 车道（L2/后R 双独立/plan-refinement 质询）→ L2/L3/L4/L5 被绕过。
#   ③ IDLE/DONE 下既有 Gate 1 已全工具拦截，但 review 形态无专门留痕。
# 本 Gate 在 IDE 层补两点: (a) IDLE/DONE review 形态 kind=review 留痕（可审计）;
#   (b) active 但非审查节点 + subagent/LLM 车道 → BLOCK（对齐 CLI CROSSREVIEW_NODE_BINDING
#   语义，GK_DEGRADE_REVIEW=1 显式降级豁免）。确定性车道任意 active 阶段放行（证据收集）。
# deterministic 车道子命令（0-API 证据，任意 active 阶段允许）
_REVIEW_DET_SUBS = ("audit --crossr", "audit --coverage", "doc-align", "self-check", "monitor --local",
                    "monitor --align", "audit --hook", "audit --red", "audit --pdg",
                    "audit --pr", "node-guard", "context --update", "calibrate")


def _review_lane_lookup(command: str):
    """RunCommand 是否命中 gatekeeper 交叉审查车道。命中返回 {lane, form}，否则 None。

    lane ∈ deterministic（0-API 确定性证据车道，任意 active 阶段可跑）/
           subagent（受限 agent 车道：--crossrev/--subagent/plan-refinement，须审查节点）/
           api（monitor --api 完整 LLM 审查循环，须审查节点）。
    仅识别 gatekeeper-cli 调用形态（含 --crossrev 显式通道兜底），避免误伤普通命令。
    """
    c = (command or "").lower()
    if "gatekeeper-cli" not in c and "--crossrev" not in c:
        return None
    # subagent / LLM 车道（优先判定；crossrev 是最强信号，subagent runner 调用在 CLI 内）
    if "--crossrev" in c or " --subagent" in c or "monitor --subagent" in c:
        return {"lane": "subagent", "form": "--crossrev/--subagent"}
    if "monitor --api" in c:
        return {"lane": "api", "form": "monitor --api"}
    if " plan-refinement" in c:
        return {"lane": "subagent", "form": "plan-refinement(质询 subagent)"}
    # 确定性证据车道
    for sub in _REVIEW_DET_SUBS:
        if sub in c:
            return {"lane": "deterministic", "form": sub}
    return None


def _review_node_ok(stage: str, project_type: str, r_phase: str = "") -> bool:
    """审查节点白名单 —— **单源**：`gk_review_nodes.review_node_ok`（CLI preflight C 同源）。

    2026-09-21：判据**键**由活动计划的 `project_type`（= `gk_route_center._META_FIELDS` 之一，
    随活动计划切换而翻转）改为**序列命名空间**（`stage` 命中 `ECO-` 前缀；`stage` 空时以
    `r_phase` 兜底）。判据**政策**不变。本薄包装保留 bool 返回以兼容既有调用/测试。
    """
    return bool(_review_node_ok_src(stage, r_phase, project_type)["ok"])


# ═══════════ Gate 3b【standing 跨技能编辑白名单】(2026-09-23, ECC-A91DC4562198) ═══════════
# 用户裁定：「开白名单吧，这个插件是技能的内部组件，跨技能编辑只允许 standing 用，standard 不行」。
# 触发场景：做「门禁委托 git-workflow 建 worktree」的收编时撞到 Gate 3 —— 它只认**单一**活动
#   worktree（`state.worktree`）⟹ 改同级插件技能 `git-workflow/` 必 BLOCK，跨仓收编无法进行。
# 白名单源 = `gk_plugin_manifest` 中 **url 形如 `builtin:${SKILL_DIR}/../<name>/…`** 的**已登记**
#   插件（`MANIFESTS["git-workflow"].url` 即此形态）⟹ **单一事实源、无硬编码名单**，且自动覆盖
#   将来以同形态登记的内置插件。未登记的兄弟目录（如 `../evil/`）一律拒。
# standard 序列 **永不**放行（用户明示）；manifest 不可得 ⟹ **fail-closed**（不放行）。
# ⑤ worktree 落点归一（2026-09-25）：基址**禁** `__file__.parents[*]`（层数推算）⟹ 改用
#   `_cross_skill_root()`（git 权威视图：本仓**主 worktree** 的父目录，见该函数 docstring）。
# 测试缝：`GK_CROSS_SKILL_ROOT` 覆盖技能根（单测 tmp 布局用）。
# ── ④ 写时 shellcheck 安全网（2026-09-24 用户裁定「病灶白名单注入」）───────────────
# 用户原话（本会话）：「$PY 这种问题总是出现，能不能在写脚本的时候就检查出来然后立刻自动
# 处理」「安全网的引导 fix 是被动而不是主动注入，这也是工程摩擦」。
# 口径（用户裁定）：**只**为本仓踩过的病灶注入可直接照做的修法 —— 不做全量 shellcheck
# 打扰（存量告警一进来就把真警告噪声化）；开销策略 = 结果缓存(mtime+size) + 大小上限跳过
# + `GK_SHELLCHECK=0` 全关。
_SHELLCHECK_MAX_BYTES = 64 * 1024
_SHELLCHECK_CODES = ("SC2154", "SC2086", "SC2046", "SC2164", "SC2181")
_SHELLCHECK_FIX = {
    "SC2154": "变量被引用但未赋值（**注意**：实测 shellcheck 对「可能来自环境」的变量不报此码 ⟹ 本仓 $PY unbound 那类它查不出；此码只覆盖它真正判定的场景）⟹ 先赋值再引用，或 ${VAR:-默认}",
    "SC2086": "变量展开未加引号 ⟹ 被拆词/受 glob 影响，改 \"$VAR\"",
    "SC2046": "命令替换未加引号 ⟹ 改 \"$(...)\"",
    "SC2164": "cd 未判失败 ⟹ 改 `cd ... || exit 1`",
    "SC2181": "用 $? 判上条命令 ⟹ 直接写 if cmd; then",
}


def _shellcheck_cache_path() -> Path:
    """缓存落点**由 SKILL_DIR 派生**（不在模块级固化）—— 测试须能 monkeypatch SKILL_DIR 隔离。"""
    return SKILL_DIR / ".gatekeeper.shellcheck-cache.json"


def _shellcheck_argv(path: str) -> list:
    """shellcheck 调用 argv。优先本机 PATH；Windows 宿主下 shellcheck 常**只在 WSL** ⟹ 退回 WSL。

    [ECC-1FAEE0EC9E6E] 实测：Windows PATH 无 `shellcheck`（它在 WSL `/usr/bin`，0.8.0）⟹ 原式
    `["shellcheck", …]` 抛 `FileNotFoundError` 被吞 ⟹ **写时 shellcheck 安全网在 Windows 侧静默失效**
    （安全网"有机制、无效果"）。修：Windows 宿主经 WSL `bash -c` 调用。

    ⚠ 实证坑（首版修法即踩）：**不得**把路径作为 `-c` 后的**位置参数**（`bash -c 'sc "$1"' x <path>`）
    —— Windows 侧 `bash.exe` 是 WSL 启动器，会把 `-c <script>` 之后的参数**全部丢弃**（实测
    `bash -c 'echo "[$0][$1]"' NAME ARG` 打出 `[/bin/bash][]`，`$1` 为空）⟹ shellcheck 拿到**空文件名**、
    报 `: : openBinaryFile: does not exist`。故把路径**内联**进脚本文本，用 `shlex.quote` 保证含空格
    路径（如宿主 `Trae CN/User`）也安全。
    """
    import shutil
    if shutil.which("shellcheck"):
        return ["shellcheck", "-f", "gcc", path]
    if _IS_WIN_HOST:
        import shlex
        return ["bash", "-c", "shellcheck -f gcc " + shlex.quote(_win_to_wsl(str(path)))]
    return ["shellcheck", "-f", "gcc", path]


def _shellcheck_lint(path: str) -> str:
    """写时 shellcheck（病灶白名单）。返回可直接照做的修法串；无命中返回空串。

    判据边界：只报 `_SHELLCHECK_CODES` 内的码（其余一律静默）；非 `.sh`、不可 stat、空文件、
    超 `_SHELLCHECK_MAX_BYTES`、shellcheck 缺失或超时 ⟹ 一律返回空串。**fail-quiet** 是刻意的：
    这是提示型安全网而非门禁，提示器自身出问题绝不能阻断编辑。
    """
    if os.environ.get("GK_SHELLCHECK") == "0":
        return ""
    if not str(path).endswith(".sh"):
        return ""
    try:
        st = os.stat(path)
    except OSError:
        return ""
    if st.st_size == 0 or st.st_size > _SHELLCHECK_MAX_BYTES:
        return ""
    key = "%s|%d|%d" % (path, int(st.st_mtime), st.st_size)
    try:
        cache = json.loads(_shellcheck_cache_path().read_text(encoding="utf-8"))
        if not isinstance(cache, dict):
            cache = {}
    except Exception:  # noqa: BLE001 — 缓存不可读不是错误，重算即可
        cache = {}
    if key in cache:
        return str(cache.get(key) or "")
    out = ""
    try:
        r = subprocess.run(_shellcheck_argv(path),
                           capture_output=True, text=True, timeout=5)
        text = (r.stdout or "") + (r.stderr or "")
        hits = [f"{c}：{_SHELLCHECK_FIX[c]}" for c in _SHELLCHECK_CODES if c in text]
        if hits:
            out = "写时 shellcheck 命中本仓病灶白名单（建议照改）：" + "；".join(hits)
    except Exception:  # noqa: BLE001 — shellcheck 缺失/超时 ⟹ 静默（提示器不得阻断编辑）
        out = ""
    cache[key] = out
    try:  # 只留最近 200 条，防缓存文件膨胀
        _shellcheck_cache_path().write_text(
            json.dumps(dict(list(cache.items())[-200:]), ensure_ascii=False), encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass
    return out


def _cross_skill_root() -> str:
    """部署根（`…/skills`，即跨技能 `<name>` 的基址）—— **git 权威视图，禁 `__file__.parents[*]`**。

    2026-09-25（**⑤ worktree 落点归一**）：原实现用 `Path(__file__).parents[2]` = **路径层数推算**，
    只在「hook 恰位于 `<部署根>/<skill>/scripts/`」时成立。hook 从 **feature worktree 副本**
    （`.trae/worktrees/<repo>/feature/<branch>/scripts/`）加载时它落到 `…/worktrees/<repo>`
    （非部署根）⟹ 兄弟插件根算错 ⟹ standing 下**合法**的跨技能编辑被判越界（fail-closed 拒）。
    修法与 `ECC-DEBCB4AC53C3`（`_git_workflow_entry` 同因）**同源**：复用
    `gk_route_center._main_worktree`（`git worktree list --porcelain` 首条 = 主 worktree），
    再取其父目录。候选序 = env `GK_CROSS_SKILL_ROOT`（**测试缝**，显式胜）→ git 权威视图；
    非 git / 查询失败 ⟹ `""` ⟹ 调用方 fail-closed（**算不出部署根就不放行，绝不按层数猜**）。
    """
    env = (os.environ.get("GK_CROSS_SKILL_ROOT") or "").strip()
    if env:
        return env
    try:
        sys.path.insert(0, str(SKILL_DIR / "scripts"))
        from gk_route_center import _main_worktree as _mw
        main = _mw(str(SKILL_DIR))
    except Exception:  # noqa: BLE001 — 单源不可得 ⟹ fail-closed（不猜层数、不静默放宽）
        return ""
    return str(Path(main).parent) if main else ""


def _standing_cross_skill_plugin(resolved: str, state: dict):
    """resolved 落在某「已登记 builtin 插件」技能根内 且 当前 standing → 返回该插件名，否则 None。"""
    if ((state.get("gate_data") or {}).get("project_type") or "standard") != "standing":
        return None
    skills_root = _cross_skill_root()          # ⑤：部署根（git 权威视图）
    if not skills_root:                        # fail-closed：判据不可得 ⟹ 不放行
        return None
    try:
        import gk_plugin_manifest as _gpm
        manifests = _gpm.list_manifests() or []
    except Exception:
        return None                     # fail-closed：判据不可得 ⟹ 不放行
    rp = str(resolved).replace("\\", "/")
    mark = "${SKILL_DIR}/../"
    for m in manifests:
        url = str((m or {}).get("url") or "")
        if "builtin:" not in url or mark not in url:
            continue
        name = url.split("builtin:", 1)[1].split(mark, 1)[1].split("/", 1)[0].strip()
        if not name:
            continue
        try:
            proot = str((Path(skills_root) / name).resolve()).replace("\\", "/").rstrip("/")
        except Exception:
            continue
        if rp.startswith(proot + "/"):
            return name
    return None


# ═══════════ Gate 9【提问挂起闸】(F-REV-96, 2026-09-17，用户裁定「其他都同意」) ═══════════
# 事故（§8.17 F-REV-92 备注）：agent 用 AskUserQuestion 请示一个「成本已裁定 / 小成本」分叉，
#   用户已入睡 ⟹ **turn 级阻塞数小时**。⚠ CLI 侧任何看门狗都救不了这一类 —— 实测那次冒烟
#   85s / 87s 均 `exit=0` 正常退出，卡住的是 agent 侧（且 hook 里做"30 分钟计时"同样无效：
#   计时器也得有进程在跑，AskUserQuestion 是 agent 那一轮的**结束**）。唯一**不依赖自觉**的
#   落法 = PreToolUse 层 deny（本闸）。普适 gate：与项目治理无关，范围外也执行
#   （对齐 R0.1 / R0.2 / R0.6 / R0.7 定调）。
# 判据（全部确定性、零 API、零状态依赖）：
#   H1 BLOCK 无人时段 —— `SKILL_DIR/.gatekeeper.no-ask` 存在且未过期（内容
#        `<deadline_epoch>|<note>`；不可解析 → 按 mtime + 默认 TTL 兜底，防半写文件永久锁死）
#        ⟹ 无差别 BLOCK。夜间批次 cron job 落盘此标志（= 用户「dream 机制只在北京时间凌晨生效」
#        诉求的载体；白天不落标志 ⟹ 本档不生效）。
#   H2 BLOCK 纯确认型 —— **每个** question 都有 options 且**全部** label 命中元选项词表
#        （继续/取消/是/否/…，信息量为零、不带任何具体方案名）且全文不含不可逆信号词
#        ⟹ 属「挂起等确认」而非「真需裁定」（真分叉必然至少一个选项带具体方案/目标名）。
#   H3 WARN  小成本自决 —— 问题文本命中低风险特征词（临时文件/缓存/日志/回收站/盘点…）且不含
#        不可逆信号词 ⟹ 提示直接执行 + 留痕（**不 BLOCK**，对齐 R0.6-P4 / R0.3b
#        「严格面只覆盖静态可判形态」定案 —— 中文语义匹配的误判面大于逐字命令匹配）。
# 逃生：`GK_ALLOW_ASK=1` → 全放行（留痕）。
_ASK_NOASK_FLAG_NAME = ".gatekeeper.no-ask"
_ASK_NOASK_DEFAULT_TTL_S = 4 * 3600.0   # 标志不可解析时按 mtime + 4h 兜底（半写文件自愈）
_ASK_META_OPTIONS = frozenset({
    "继续", "不继续", "取消", "是", "否", "确认", "确认执行", "同意", "不同意", "放弃",
    "停止", "开始", "执行", "直接执行", "保持", "保持现状", "维持", "推进", "按计划",
    "按计划执行", "照做", "稍后", "待办", "跳过", "返回", "返回上一步", "先不做", "都可以",
    "yes", "no", "ok", "okay", "cancel", "continue", "proceed", "abort", "skip", "stop",
    "go", "hold", "later", "none",
})
_ASK_IRREVERSIBLE_RE = (
    r"删除|删掉|移除|清除|清空|覆盖|覆写|不可逆|销毁|破坏|格式化|卸载|"
    r"rm\s+-rf|--hard|truncate|drop\s+table|force|push|reset|revert|合并|发布|部署|上线|删库"
)
_ASK_LOWCOST_RE = (
    r"临时文件|临时目录|缓存|日志|回收站|运行时废料|\.tmp|缩进|重命名|命名统一|"
    r"整理目录|清理|清点|盘点|统计表|台账|留痕|只读检查|自检|冒烟|bomb"
)

# ── 提问挂起 kill 闸（2026-09-21 用户裁定）──
# 裁定逐字：「kill 应该是 monitor--local 的拦截，纪律表是摆设」「提问静默期间开始跑睡眠，
# 提问半小时没动静就暂停主进程」。⟹ 分工契约：**本文件只记录，判杀在 `monitor --local`
# 的 `ask_hold_kill` 项**（判据单源 = `_ask_hold_snapshot`，本文件导出，CLI 直接调）。
#   · 放行的提问 → 待答标记 `<ask_epoch>|<note>`（单槽，只留最新一次提问）
#   · 任一**非**提问工具调用到达 ⟹ 上一问已结束 ⟹ 台账 jsonl 追加 elapsed_s 后清标记
#   · 被 Gate 9 BLOCK 的提问（无人时段 H1 / 纯确认型 H2）不落标记 —— 提问没发生
#   · 停留 ≥ `_ASK_HOLD_KILL_S` ⟹ CLI 侧判 FAIL 且计入 total_req ⟹ verdict=BLOCKED
# ⚠ 为何不在本文件判杀：`AskUserQuestion` 是 agent 那一轮的**结束**，本进程随即退出 ⟹
#   计时器在此无效（F-REV-96 原始注记已实测定案：「hook 里做 30 分钟计时同样无效」）。
#   跨度只能在「下一次工具调用」时结算，判杀则归 `monitor --local`（唯一被 advance 消费的门禁面）。
_ASK_HOLD_PENDING_NAME = ".gatekeeper.ask-hold"
_ASK_HOLD_LEDGER_NAME = ".gatekeeper.ask-hold.log"
_ASK_HOLD_KILL_S = 1800.0          # 30 分钟（用户口述阈值）
_ASK_HOLD_LEDGER_TTL_S = 86400.0   # 24h 窗口外的陈旧记录不重复判杀（防永久锁死）
_ASK_HOLD_LEDGER_MAX = 24          # ring 上限（对齐 _BLOCK_LOG_MAX）
_ASK_HOLD_PENDING = SKILL_DIR / _ASK_HOLD_PENDING_NAME
_ASK_HOLD_LEDGER = SKILL_DIR / _ASK_HOLD_LEDGER_NAME


def _ask_meta_label(label: str) -> bool:
    """选项 label 是否「元选项」（不含任何具体方案信息）：去括号注解/空白/标点后逐字比对。"""
    import re
    s = re.sub(r"[（(][^）)]*[）)]", "", label or "")   # 去「（推荐）」类注解
    s = re.sub(r"[\s\u3000·、,，.。!！?？:：;；\-—_/]+", "", s)
    return s.strip().lower() in _ASK_META_OPTIONS


def _ask_noask_window() -> tuple:
    """无人时段标志读取：返回 (active, note)。过期自清；不可解析 → mtime + 默认 TTL 兜底。"""
    try:
        f = SKILL_DIR / _ASK_NOASK_FLAG_NAME
        if not f.exists():
            return False, ""
        raw = f.read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        return False, ""
    head, _, note = raw.partition("|")
    try:
        deadline = float(head.strip())
        if deadline <= 0:
            raise ValueError
    except (TypeError, ValueError):
        try:
            deadline = f.stat().st_mtime + _ASK_NOASK_DEFAULT_TTL_S
        except Exception:
            return True, (note.strip() or "no-ask window (unparseable, fail-closed)")
    if time.time() > deadline:
        try:
            f.unlink()   # 过期自清（半写/残留标志不留死锁）
        except Exception:
            pass
        return False, ""
    return True, (note.strip() or "no-ask window")


def _ask_hold_gate(tool_input: dict) -> Optional[tuple]:
    """Gate 9 检测体：返回 (level, reason, hint)，level ∈ {"BLOCK","WARN"}；无命中 → None。"""
    import re
    if os.environ.get("GK_ALLOW_ASK") == "1":
        _log_hook("GATE9-escape: GK_ALLOW_ASK=1 — 提问挂起闸整体放行")
        return None
    qs = tool_input.get("questions")
    if not isinstance(qs, list) or not qs:
        return None
    blob_parts, per_q_meta = [], []
    for q in qs:
        if not isinstance(q, dict):
            continue
        blob_parts += [str(q.get("question", "")), str(q.get("header", ""))]
        opts = q.get("options")
        labels = []
        if isinstance(opts, list):
            for o in opts:
                if isinstance(o, dict):
                    labels.append(str(o.get("label", "")))
                    blob_parts.append(str(o.get("description", "")))
                elif isinstance(o, str):
                    labels.append(o)
        # 无选项的 question（自由文本问询）**不**计入纯确认型 —— 那种是真要用户开口的
        per_q_meta.append(bool(labels) and all(_ask_meta_label(l) for l in labels))
    blob = " ".join(blob_parts)
    in_win, note = _ask_noask_window()
    if in_win:
        return ("BLOCK",
                f"无人时段禁提问（窗口: {note}）—— AskUserQuestion 会**挂起到用户回来为止**"
                "（§8.17 实测卡数小时；CLI 侧看门狗救不了这一类，只能在此 deny）。",
                "Fix: ① 问题写成待办（计划文档 §8.x / state gate_data.todos）；"
                "② 直接执行**已授权 / 可逆 / 小成本**项；③ 确需用户裁定者留待用户在线再问。"
                "急停: export GK_ALLOW_ASK=1")
    if per_q_meta and all(per_q_meta) and not re.search(_ASK_IRREVERSIBLE_RE, blob, re.IGNORECASE):
        return ("BLOCK",
                "纯确认型提问（全部选项为「继续 / 取消」类元选项，不含任何具体方案）"
                "—— 属**挂起等确认**，非「真需用户裁定」的分叉。",
                "Fix: 直接执行（可逆 / 小成本）或落待办；仅当存在**真分叉**（不同方案或不同代价）"
                "时才提问，且选项须带具体方案名。急停: export GK_ALLOW_ASK=1")
    if re.search(_ASK_LOWCOST_RE, blob, re.IGNORECASE) and not re.search(
            _ASK_IRREVERSIBLE_RE, blob, re.IGNORECASE):
        return ("WARN",
                "小成本 / 可逆操作提问（命中低风险特征词）—— 建议直接执行 + 留痕，勿挂起等确认",
                "Fix: 直接执行并在 monitor / 计划文档留痕；确需说明时用一次性告知而非阻塞式提问。")
    return None


def _ask_blob(tool_input: dict) -> str:
    """提问文本摘要（留痕 + 台账用）：question + header + 选项 label，压缩空白。"""
    parts = []
    for q in (tool_input.get("questions") or []):
        if not isinstance(q, dict):
            continue
        parts += [str(q.get("question", "")), str(q.get("header", ""))]
        for o in (q.get("options") or []):
            parts.append(str(o.get("label", "")) if isinstance(o, dict) else str(o))
    return " ".join(p for p in parts if p)


def _ask_hold_paths(skill_dir: str = ""):
    """(待答标记, 台账)。`skill_dir` 空 → 模块 SKILL_DIR（hook 上下文）；
    CLI 侧显式传 SKILL_DIR（判据单源，避免第二份读实现）。"""
    base = Path(skill_dir) if skill_dir else SKILL_DIR
    return base / _ASK_HOLD_PENDING_NAME, base / _ASK_HOLD_LEDGER_NAME


def _ask_hold_record(blob: str) -> None:
    """放行的提问 → 落待答标记（**只记录，绝不 BLOCK**）。写失败静默：记录层不得拖累工具链。"""
    try:
        note = " ".join(str(blob or "").split())[:160]
        _ASK_HOLD_PENDING.write_text(f"{time.time():.3f}|{note}", encoding="utf-8")
    except Exception:
        pass


def _ask_hold_settle() -> None:
    """任一非提问工具调用到达 ⟹ 上一次提问已结束：台账追加
    `{ask_ts,resume_ts,elapsed_s,note}`，随后清掉待答标记。头部不可解析（半写）→ 按 mtime
    兜底（对齐 `_ask_noask_window` 的半写自愈，不丢弃）。只记录，绝不 BLOCK。"""
    try:
        if not _ASK_HOLD_PENDING.exists():
            return
        raw = _ASK_HOLD_PENDING.read_text(encoding="utf-8", errors="replace").strip()
        head, _, note = raw.partition("|")
        try:
            ask_ts = float(head.strip())
            if ask_ts <= 0:
                raise ValueError
        except (TypeError, ValueError):
            ask_ts = _ASK_HOLD_PENDING.stat().st_mtime
        now = time.time()
        rec = {"ask_ts": round(ask_ts, 3), "resume_ts": round(now, 3),
               "elapsed_s": round(max(0.0, now - ask_ts), 3), "note": note.strip()[:160]}
        try:
            lines = [l for l in _ASK_HOLD_LEDGER.read_text(
                encoding="utf-8", errors="replace").splitlines() if l.strip()]
        except Exception:
            lines = []
        lines.append(json.dumps(rec, ensure_ascii=False))
        _ASK_HOLD_LEDGER.write_text("\n".join(lines[-_ASK_HOLD_LEDGER_MAX:]) + "\n",
                                    encoding="utf-8")
        _ASK_HOLD_PENDING.unlink()
    except Exception:
        pass


def _ask_hold_snapshot(skill_dir: str = "") -> dict:
    """判杀侧**单一事实源**（`monitor --local` 的 `ask_hold_kill` 项消费）。

    返回 `{"pending_s": 当前待答停留秒数, "max_s": 最大停留, "threshold_s": 阈值,
    "violations": [{"ask_ts","resume_ts","elapsed_s","note"}]}`。
    只读、绝不抛（检测层不得因台账问题阻塞门禁）；`violations` 非空 = 应判 FAIL。
    """
    pending_path, ledger_path = _ask_hold_paths(skill_dir)
    out = {"pending_s": 0.0, "max_s": 0.0, "threshold_s": _ASK_HOLD_KILL_S, "violations": []}
    now = time.time()
    try:
        for line in ledger_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            if not isinstance(r, dict):
                continue
            ask_ts = _as_float(r.get("ask_ts"))
            if ask_ts <= 0 or (now - ask_ts) > _ASK_HOLD_LEDGER_TTL_S:
                continue
            el = _as_float(r.get("elapsed_s"))
            if el <= 0:
                el = max(0.0, _as_float(r.get("resume_ts")) - ask_ts)
            if el < _ASK_HOLD_KILL_S:
                continue
            out["violations"].append({"ask_ts": ask_ts,
                                      "resume_ts": _as_float(r.get("resume_ts")),
                                      "elapsed_s": round(el, 1),
                                      "note": str(r.get("note", ""))[:160]})
    except Exception:
        pass
    try:
        if pending_path.exists():
            raw = pending_path.read_text(encoding="utf-8", errors="replace").strip()
            head, _, note = raw.partition("|")
            try:
                ask_ts = float(head.strip())
                if ask_ts <= 0:
                    raise ValueError
            except (TypeError, ValueError):
                ask_ts = pending_path.stat().st_mtime
            pend = max(0.0, now - ask_ts)
            out["pending_s"] = round(pend, 1)
            if pend >= _ASK_HOLD_KILL_S:
                out["violations"].append({"ask_ts": round(ask_ts, 3), "resume_ts": 0.0,
                                          "elapsed_s": round(pend, 1),
                                          "note": note.strip()[:160] or "still pending"})
    except Exception:
        pass
    out["max_s"] = round(max([v["elapsed_s"] for v in out["violations"]] + [out["pending_s"]]), 1)
    return out


def _in_active_surface(path: str, state: dict) -> bool:
    """RC1（2026-09-27，`ECC-089658238011`）：活动写面判定 —— Gate 3 与 Gate 5/6/7 的**同一进口**。

    懒加载路由中枢（避免 hook 启动期 import；`scripts/` 已在 `sys.path`，见文件头）。
    实际实现 = `gk_route_center.in_active_surface`（**单一 helper**）：写面 = `worktree`
    （强制面主值）∪ `worktrees_extra[]`（允许集，缺省 `[]` == 今日逐字），且含**目录边界**
    （修 `ECC-73ACEA635A78`）。导入/调用异常 ⟹ **fail-closed**（False）。
    """
    try:
        from gk_route_center import in_active_surface as _f
        return bool(_f(path, state))
    except Exception:
        return False


# ── Gate R0.10【质询派发并行闸】(N9, 2026-09-30) ──────────────────────────────
# 病象（**复发洞**）：`plan-refinement --adjudicate` 派发被写成 `for`/`while` 串行循环 +
#   消费端 `2>&1` 并流。文档约束已写死（口径源 `docs/plans/2026-09-14-convergence-evaluator-subplan.md`
#   §0.1「并行派发 = `&` + `sleep 3` + `wait`」/ N7「禁消费端并流」）却**仍复发**
#   （owner：「这已经修过一次了」）⟹ 属「**文档有、机检无**」族 ⟹ 本闸补机检。
# 判据（**仅当命令串含 `--adjudicate` 时触发** = 窄面，不误伤无关命令）：
#   V1 串行：命令含 `for`/`while` … `do` 循环构造 ⟹ 应并行（每条后 `&`，末行 `wait`）；
#   V2 并流：含 `--adjudicate` 的**同一行**同时含 `2>&1` ⟹ 破坏「stdout=ECC / stderr=落盘通知」契约（N7）。
#   V3 多臂串行（**2026-10-01 补**，堵 `;` 链式缝）：命令含 **≥2** 个 `--adjudicate` 却**无**并行构造
#      （`&` 背景符与 `wait` 关键字缺任一或全缺）⟹ 实为串行派发（`;` / `&&` 链、逐条 `wsl.exe …` 连写）。
#      理由：V1 只抓 `for`/`while`；把 N 条 `--adjudicate` 直接以 `;` 连写**同样串行**却漏网
#      （2026-10-01 实测复发：6 条 `--adjudicate last …` 以 `;` 连写，owner「又在胡乱串行」）。
#      判据面 = **整条命令串**（跨行/跨 `;`）—— 多臂派发天然跨行，不能只看单行。
# 严重度 = **BLOCK**（「堵上」：纯文档不构成门，只有拦停能止复发）；kill switch = `GK_N9_DISPATCH_GATE=0`。
_N9_LOOP_PAT = r'\b(?:for|while)\b[\s\S]*?\bdo\b'
# 背景符 `&`：排除 `2>&1`（大写 >）、`&&`（逻辑与，仍是串行）、`<&`。
_N9_BG_AMP_PAT = r'(?:^|[^>&])&(?:[^&]|$)'
_N9_WAIT_PAT = r'\bwait\b'


# 已知"本机 helper 未必覆盖"的 host（2026-11-04 实测：atomgit 无凭据 ⟹ 弹登录框）。
_PROMPT_PRONE_HOSTS = ("atomgit.com",)


def _git_push_guard(command: str, cwd: str = "") -> str:
    """返回 BLOCK 文案；空串 = 放行。**纯判定在 `_interactive_git_reason`（可单测）**。

    只拦"会弹登录框"的一种：`git push` + `https://` remote + 无 `credential.helper`
    + 命令未带 `GIT_TERMINAL_PROMPT=0`。SSH remote、已配 helper、显式非交互一律放行。
    `GK_ALLOW_INTERACTIVE_GIT=1` 可整条豁免（人工确认后临时用）。
    """
    if os.environ.get("GK_ALLOW_INTERACTIVE_GIT") == "1":
        return ""
    cmd = command or ""
    # 快路径：非 push / 已显式非交互 ⟹ 不 spawn git（hook 在每个工具调用都会跑）。
    if not _is_git_push(cmd):
        return ""
    if "GIT_TERMINAL_PROMPT=0" in cmd:
        return ""
    url, helper = _git_remote_and_helper(cmd, cwd)
    return _interactive_git_reason(cmd, url, helper)


def _is_git_push(cmd: str) -> bool:
    """判定命令里是否真有 `git … push` 子命令（**不看参数里的 push 字样**）。

    `git log --grep push` / `echo push` 不得命中；`git -C <p> push origin x` 必须命中。
    """
    for part in re.split(r"[;&|\n]", cmd or ""):
        toks = part.split()
        for i, t in enumerate(toks):
            if t.strip("\"'") != "git":
                continue
            j = i + 1
            while j < len(toks):
                tj = toks[j]
                if tj in ("-C", "-c", "--git-dir", "--work-tree", "--namespace"):
                    j += 2
                    continue
                if tj.startswith("-"):
                    j += 1
                    continue
                return tj == "push"
    return False


def _interactive_git_reason(command: str, url: str, helper: str) -> str:
    """纯函数：给定命令/远端 URL/credential.helper，判断是否必然弹登录。"""
    cmd = command or ""
    if not _is_git_push(cmd):
        return ""
    # 只信**命令内**显式声明（`GIT_TERMINAL_PROMPT=0 git push`）。
    # ⚠ 不信进程 env：宿主本身可能已设 `GIT_TERMINAL_PROMPT=0`/`GCM_INTERACTIVE=Never`，
    #   但实际弹窗来自宿主 Git 集成（2026-11-04 实测），env 值不构成"不会弹"的证据。
    if "GIT_TERMINAL_PROMPT=0" in cmd:
        return ""
    if not url.startswith("https://"):
        return ""
    host = url.split("://", 1)[1].split("/", 1)[0].split("@")[-1].lower()
    # 2026-11-04 实测教训：**有 credential.helper 也不代表该 host 有可用凭据**——
    #   本机 helper 配的是 GitHub token，atomgit 无凭据时 git 仍会弹登录框
    #   （被宿主接管成「Trae git 登录」）。故对已知"凭据未必覆盖"的 host 一律默认拦。
    if (helper or "").strip() and not any(h in host for h in _PROMPT_PRONE_HOSTS):
        return ""
    return ("BLOCK: git push 将触发交互式登录（remote=%s，credential.helper=%s），"
            "已拦截以防宿主弹登录框。修法：为该 host 配置 token/credential helper；"
            "或显式 `GIT_TERMINAL_PROMPT=0` 让它在无凭据时立刻失败。" % (url, helper or "none"))


def _git_remote_and_helper(command: str, cwd: str = "") -> tuple:
    """读 `origin` URL 与 `credential.helper`（只读；任何异常 → 空串，不误拦）。"""
    repo = cwd or os.getcwd()
    m = re.search(r"git\s+-C\s+(?:\"([^\"]+)\"|'([^']+)'|(\S+))", command or "")
    if m:
        repo = next(g for g in m.groups() if g)
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="echo")
    try:
        url = subprocess.run(["git", "-C", repo, "remote", "get-url", "origin"],
                             capture_output=True, text=True, timeout=4,
                             env=env).stdout.strip()
    except Exception:  # noqa: BLE001 — 判定失败不误拦
        url = ""
    try:
        helper = subprocess.run(["git", "config", "--get", "credential.helper"],
                                capture_output=True, text=True, timeout=4,
                                env=env, cwd=repo).stdout.strip()
    except Exception:  # noqa: BLE001
        helper = ""
    return url, helper


def _n9_parallel_dispatch(command: str):
    """N9 机检（Gate R0.10 检测体）：派发并行闸。命中 → (reason, hint)；无命中 → None。"""
    import re
    if os.environ.get("GK_N9_DISPATCH_GATE", "") == "0":
        return None
    if "--adjudicate" not in command:
        return None
    for line in command.splitlines():
        if "--adjudicate" in line and "2>&1" in line:
            return ("N9 派发行禁消费端 `2>&1` 并流（N7：stdout=ECC / stderr=落盘通知）",
                    "Fix: 逐臂 stdout 落独立日志（`> arm.out 2> arm.err`）后读 output_file；"
                    "禁消费端并流（会掩盖拼接 JSON、造伪证据）")
    if re.search(_N9_LOOP_PAT, command):
        return ("N9 `--adjudicate` 派发禁 `for`/`while` 串行",
                "Fix: 并行派发 = 每条 `... --adjudicate <id> --decision approve &`，各条间 `sleep 3`，"
                "末行 `wait`（口径源 docs/plans/2026-09-14-convergence-evaluator-subplan.md §0.1）")
    # V3：多臂必须以并行构造（`&` + `wait`）派发；否则（`;`/`&&` 链）= 串行。
    _n_adj = command.count("--adjudicate")
    if _n_adj >= 2 and not (re.search(_N9_BG_AMP_PAT, command) and re.search(_N9_WAIT_PAT, command)):
        return ("N9 多臂 `--adjudicate` 派发须并行（`&` + `wait`）；"
                "本命令含 %d 条 `--adjudicate` 却无并行构造 ⟹ 实为串行" % _n_adj,
                "Fix: 每条 `... --adjudicate <**显式 id**> --decision approve > arm.out 2> arm.err &`，"
                "各条间 `sleep 3`，末行 `wait`（禁 `last` —— 并行下必争同一队尾；"
                "口径源 docs/plans/2026-09-14-convergence-evaluator-subplan.md §0.1）")
    return None


# ── Gate R0.11【merge 前孤儿锁闸】(2026-09-30) ───────────────────────────────
# 病象（实测）：主树 `git merge` 撞 **0 字节孤儿 `index.lock`** ⟹ `error: Unable to write index`；
#   `cmd_commit` 段有 `_gk_commit_lock_preflight`，而 **`git merge` 路径不跑它** ⟹ 合并被卡死。
# 处置：孤儿（年龄 ≥ grace 且无活 git 进程）→ **归档（非删除）** 到回收站 + WARN；**活锁 → BLOCK**（不抢）。
# 目标仓解析：命令内 `git -C <dir>`（**真实目录**）∪ state 的 `worktree`/`main_repo`（真实目录）；
#   解析不到任何真实目录 ⟹ **不拦**（窄面，避免误伤 `git -C $VAR` 这类静态不可解形态）。
_GIT_MERGE_PAT = r'\bgit\b[^\n;]*\bmerge\b'
_GIT_C_PAT = r"\bgit\b[^\n;]*?-C\s+(\"[^\"]+\"|'[^']+'|\S+)"


def _merge_lock_preflight(command: str):
    """Gate R0.11 检测体：`git merge` 前孤儿锁预检。命中阻断 → (reason, detail)；否则 None。"""
    import re
    if not re.search(_GIT_MERGE_PAT, command):
        return None
    cands = []
    for m in re.finditer(_GIT_C_PAT, command):
        p = m.group(1).strip().strip('"').strip("'")
        if p and os.path.isdir(p):
            cands.append(p)
    try:
        d = json.loads(Path(str(STATE_FILE)).read_text(encoding="utf-8"))
        for k in ("worktree", "main_repo"):
            v = str(d.get(k) or "")
            if v and os.path.isdir(v):
                cands.append(v)
    except Exception:
        pass
    if not cands:
        return None
    try:
        sys.path.insert(0, str(SKILL_DIR / "scripts"))
        import gk_git_lease as _gl
    except Exception:
        return None
    for r in dict.fromkeys(cands):
        try:
            rc, out, err = _gl.preflight(r)
        except Exception:
            continue
        if err:
            _log_hook(f"WARN R0.11 merge-preflight 归档孤儿锁: {err.strip()[:200]}")
            print(f"GATEKEEPER-WARN: R0.11 merge 前孤儿锁已归档（非删除）: {err.strip()[:200]}",
                  file=sys.stderr)
        if rc != 0:
            return (f"merge 前锁预检未通过（repo={r}）", out or "COMMIT_LOCK_HELD")
    return None


# ── Gate R0.17【worktree 建树单一入口闸】(2026-10-28) ─────────────────────────
# 病象（本会话实测）：绕过 `apply-worktree` 手搓 `git worktree add -b feature/… <path>` 建树 ⟹
#   该目录**不在** `state.worktree` / `worktrees_extra[]` ⟹ 首次 Edit 被 Gate 3 拦
#   （"NOT in active write surface"）⟹ 再用 `cp` 把文件搬进去、手写 `.gatekeeper.state`
#   ⟹ 变成「门禁看得见但管不着」的野树（owner 斥为「奇怪绕路」）。
# 判据（命令串静态可判；引号内字面量与 heredoc 正文**不扫**，避免写文档/写脚本时误伤）：
#   W1 命令位 `git … worktree add` ⟹ 建树归口不是裸 git（创建已委托 git-workflow）；
#   W2 `cp|mv|rsync|install|ln` 的**目标**落在 `**/.trae/worktrees/**` ⟹ 搬树 / 搬 state；
#   W3 `mkdir` 目标落在 `**/.trae/worktrees/**` ⟹ 手搓树目录（同一野树起点）。
# 严重度 = BLOCK（只有拦停能止复发）；逃生舱 `GK_WT_ROUTE_GATE=0`（进程级）/
#   段首 `GK_ALLOW_WT_ADD=1`（单条命令，同 R0.15 形）。
_WT_ROOT_PAT = r"\.trae[\\/]+worktrees(?:[\\/]|$)"
_WT_ADD_PAT = r"\bgit\b[^\n;&|]*?\bworktree\s+add\b"
# 2026-11-08（owner：拦截裸 git 生命周期通道）：创建已有 R0.17；本批补**回收侧**——
#   实测漏网 = `git worktree remove|prune` + `git branch -d`（`-D` 已由 E2-5 拦）。
#   apply-worktree 早有回收链（`--reclaim [--branches] [--path] [--apply]` →
#   `gk_worktree_reclaim.py`：归档前置 + merged/clean 判据 + 解绑 worktrees_extra），
#   故裸 git 回收一律视为绕过单一入口。
_WT_RECLAIM_PAT = r"\bgit\b[^\n;&|]*?\bworktree\s+(?:remove|prune)\b"
_WT_BRANCH_DEL_PAT = r"\bgit\b[^\n;&|]*?\bbranch\b[^\n;&|]*?\s-(?:d|D)(?=\s|$)"
_WT_WRITE_VERBS = ("cp", "mv", "rsync", "install", "ln", "mkdir")

_WT_ROUTE_HINT = (
    "Fix: 建树走**单一入口** —— 计划类：`bash gatekeeper-cli.sh apply-worktree --plan <plan.md>`"
    "（建/复用 `feature/<plan-stem>` + 建域 state + 写 plan 指针 + 钉 `state.worktree`，一条命令）；"
    "finding 类：`apply-worktree <finding-id> --family <F>`。"
    "手搓树/搬树一律拒：写面不会登记 ⟹ 之后的 Edit 必被 Gate 3 拦（这就是绕路的代价）。"
)
_WT_RECLAIM_HINT = (
    "Fix: worktree/分支回收走**单一入口** —— "
    "`bash gatekeeper-cli.sh apply-worktree --reclaim --path <dir> --branches`（缺省 dry-run），"
    "确认后加 `--apply`；它内置归档前置与 merged/clean 判据，并会解绑 `worktrees_extra[]`。"
    "禁裸 `git worktree remove|prune` / `git branch -d|-D`。"
)


def _wt_route_gate(command: str):
    """Gate R0.17 检测体：手搓 worktree 建树 / 搬树 ⟹ (reason, hint)；无命中 → None。"""
    import re
    if os.environ.get("GK_WT_ROUTE_GATE", "") == "0":
        return None
    cmd = (command or "").strip()
    if not cmd:
        return None
    # heredoc 正文（写文档/脚本时内嵌命令示例）不扫
    scan = cmd.split("<<", 1)[0]
    if re.search(r"(?:^|[;&|\n])\s*GK_ALLOW_WT_ADD=1\b", scan):
        return None
    # shell 包裹（`bash -c '…'` / `wslsh -c '…'`）内的命令也是命令 ⟹ 归一为命令位（同 R0.15）
    scan = re.sub(r"(?:-c|--command)\s*(['\"])", ";", scan)
    m = re.search(_WT_RECLAIM_PAT, scan, re.I)
    if m and not _in_quotes(scan, m.start()):
        return ("裸 `git worktree remove|prune` 回收（绕过 apply-worktree 回收链）",
                _WT_RECLAIM_HINT)
    # `-d` / `-D` 语义相反 ⟹ 本模式**不加 IGNORECASE**；两者都拦（回收走 apply-worktree）。
    m = re.search(_WT_BRANCH_DEL_PAT, scan)
    if m and not _in_quotes(scan, m.start()):
        return ("裸 `git branch -d|-D` 删分支（绕过 apply-worktree --reclaim --branches）",
                _WT_RECLAIM_HINT)
    m = re.search(_WT_ADD_PAT, scan, re.I)
    if m and not _in_quotes(scan, m.start()):
        return ("手搓 `git worktree add` 建树（绕过 apply-worktree 单一入口）", _WT_ROUTE_HINT)
    for seg in re.split(r"[;&|\n]+", scan):
        toks = seg.strip().split()
        if not toks:
            continue
        i = 0
        while i < len(toks) and (toks[i].lower() == "sudo" or re.match(r"^\w+=", toks[i])):
            i += 1
        if i >= len(toks):
            continue
        verb = os.path.basename(toks[i].lower())
        if verb not in _WT_WRITE_VERBS:
            continue
        args = [t.strip("\"'") for t in toks[i + 1:] if not t.startswith("-")]
        if not args:
            continue
        dst = args[-1].replace("\\", "/")
        if re.search(_WT_ROOT_PAT, dst, re.I):
            return (f"`{verb}` 目标落在开发 worktree 根（{dst[:80]}）⟹ 搬树/搬 state 绕开路由",
                    _WT_ROUTE_HINT)
    return None


def _task_dispatch_gate(tool_name: str, tool_input: dict, session: str = "") -> str:
    """Gate 0（方案 B，2026-10-27）：Task **默认拒绝** + 单次票据校验。

    返回拒绝原因串（非空 ⟹ 调用方 `block()`）；空串 ⟹ 放行。

    与旧实现（关键词黑名单）的差别：黑名单**只作告警**（`dispatch_keyword_hit` 留痕），
    放行依据改为 `gk_dispatch_ticket.verify` 的可验证凭据（HMAC + 查询哈希 + 过期 + 单次）。
    关键词表**保留**：① 它仍是「本该走 CLI 正规流程」的强信号（告警可用于事后对账）；
    ② `scripts/test_eco_integration.py` 钉住该表存在；③ 删除它只会让绕过更隐蔽。
    """
    if tool_name != "Task":
        return ""
    query = str((tool_input or {}).get("query", "") or "")
    # 关键词命中：只告警、不再作为拦截判据（拦截面 = 票据）
    gatekeep_keywords = ["gk_", "gatekeeper", "Phase 2", "Phase 3", "batch8",
                        "alignment", "adjudicate", "monitor_api", "appeal",
                        "escalate", "reflect", "eco", "audit", "plan-refinement",
                        "质询", "交叉审查", "cross-ref", "双循环", "standing", "标准序列",
                        "monitor --subagent", "advance", "entropy"]
    query_lower = query.lower()
    hits = [kw for kw in gatekeep_keywords if kw.lower() in query_lower]
    if hits:
        _log_hook("dispatch_keyword_hit: " + ",".join(hits[:6])
                  + f" (task will still require a ticket, session={session or '-'})")
    # 无 state ⟹ 本项目未纳入治理（与 Gate 2 的 fail-closed 不同：票据必须落在某个 state 上，
    #   没有 state 就无从签发；此时不制造「永远无票可签」的死锁）
    try:
        state_exists = Path(str(STATE_FILE)).exists()
    except Exception:
        state_exists = False
    if not state_exists:
        _log_hook("dispatch_ticket_skip: no state file (out of governance)")
        return ""
    ticket = str((tool_input or {}).get("__ticket", "") or "")
    try:
        sys.path.insert(0, str(SKILL_DIR / "scripts"))
        import gk_dispatch_ticket as _dt  # noqa: E402
        verdict = _dt.verify(str(STATE_FILE), ticket, query, session=session)
    except Exception as e:  # noqa: BLE001 — 校验器本身异常 ⟹ fail-closed
        return (f"Task dispatch ticket verification error (fail-closed): "
                f"{type(e).__name__}: {e}")
    if verdict.get("ok"):
        _log_hook(f"dispatch_ticket_ok: nonce={verdict.get('nonce', '')[:16]} "
                  f"session={session or '-'}")
        return ""
    reason = verdict.get("reason", "denied")
    hint = ("签发：`bash gatekeeper-cli.sh state-patch --dispatch-issue @<query-file> --ttl 300`"
            "；把输出里的 `ticket` 作为查询**最后一行** `GK-TICKET:<ticket>`（或用 tool_input.__ticket）。"
            "票据单次有效且绑定查询正文哈希 ⟹ 改一个字都要重签。")
    return (f"Task dispatch denied (default-deny, 方案 B): reason={reason}. {hint}")


def _main_checkout_root() -> Optional[Path]:
    """主检出根 = `git-common-dir` 的父目录（worktree 共享同一 common dir）。

    取不到（非 git / git 缺失）⟹ None（不拦；与既有 fail-soft 纪律一致）。
    """
    try:
        p = subprocess.run(["git", "-C", str(SKILL_DIR), "rev-parse", "--git-common-dir"],
                           capture_output=True, text=True, timeout=10)
        if p.returncode != 0 or not p.stdout.strip():
            return None
        common = Path(p.stdout.strip())
        if not common.is_absolute():
            common = (SKILL_DIR / common).resolve()
        return common.parent.resolve()
    except Exception:
        return None


def main():
    # Read Hook JSON from stdin
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            # No stdin — called manually or non-Trae context; let tool proceed
            print(json.dumps({"ok": True, "proceed": True, "mode": "manual_no_stdin"}))
            sys.exit(0)
        hook_data = json.loads(raw)
    except json.JSONDecodeError:
        # Unparseable stdin — don't block (non-Trae context)
        print(json.dumps({"ok": True, "proceed": True, "mode": "stdin_unparseable"}))
        sys.exit(0)

    tool_name = hook_data.get("tool_name", "")
    tool_input = hook_data.get("tool_input", {})
    cwd = hook_data.get("cwd", os.getcwd())

    # ── 工具失效→提权绕过 防线② 前提：本次调用上下文（block() 持久化被禁意图）──
    global _CALL_TOOL, _CALL_TARGET, _CALL_CMD, _CALL_KIND, _SESSION_ID
    _CALL_TOOL = tool_name
    _CALL_CMD = tool_input.get("command", "") if tool_name == "RunCommand" else ""
    _CALL_KIND = "block"
    _fp_ctx = tool_input.get("file_path", "") or tool_input.get("path", "")
    try:
        _CALL_TARGET = resolve_path(_fp_ctx, cwd) if _fp_ctx else ""
    except Exception:
        _CALL_TARGET = _fp_ctx or ""
    # ── 主树只读（2026-11-06，owner 裁定）：编辑目标落在**主检出根** ⟹ 直接 block ──
    #   现状缺口：Gate 3 只校验「在**活动** worktree 内」；无活动 worktree 时活动面=主树
    #   ⟹ 直接改主树被放行（本轮实测）。本闸先于 state 解析执行，确保「主树只读」有机检。
    if tool_name in EDIT_TOOLS and _CALL_TARGET:
        _main_root = _main_checkout_root()
        if _main_root is not None:
            _t = _win_to_wsl(_CALL_TARGET).replace("\\", "/")
            _r = _win_to_wsl(str(_main_root)).replace("\\", "/").rstrip("/")
            if _t == _r or _t.startswith(_r + "/"):
                print(json.dumps({"ok": False, "proceed": False, "mode": "main_tree_readonly",
                                  "error": "MAIN_TREE_READONLY",
                                  "hint": "主检出只读：请先 git worktree add，在 worktree 内编辑后合并"}))
                # 2026-11-08 修（ECC：主树只读形同虚设）：原先 `sys.exit(0)` ⟹ 宿主只看退出码
                #   ⟹ 把 proceed:false 当「成功」继续落盘（实测：Edit/Write 直写主树成功）。
                #   与 `block()` 对齐 = exit 2，宿主才真正拦截。
                sys.exit(2)

    # ── 会话身份链（Q2a，2026-10-02 · 平台无关兜底；finding ECC-AB2FA16E9133）─────────────
    # 与 CLI 启动块**同源**：env `GK_SESSION_ID` > worktree token（由 `_CALL_TARGET` 所在
    #   git worktree 派生）> 宿主 payload `session_id`。目标路径落在开发 worktree ⟹ token =
    #   该 worktree 标识（`agent/session/<leaf>` 等）⟹ hook 与 agent（CLI 侧由 `$PWD` 派生
    #   同一 token）两侧不再「两套账」。无 worktree 锚（主树编辑 / 无目标路径）⟹ 回落 payload
    #   既有行为。解析单源 = `gk_session_identity`（禁第二实现）；失败静默（便利通道不拦调用）。
    _env_sid = str(os.environ.get("GK_SESSION_ID") or "")
    _pay_sid = str(hook_data.get("session_id") or "")
    _wt_tok = ""
    if _CALL_TARGET:
        try:
            sys.path.insert(0, str(SKILL_DIR / "scripts"))
            import gk_session_identity as _gsi  # noqa: E402
            _cand = _gsi.derive(_CALL_TARGET).get("token", "") or ""
            _wt_tok = _cand if _gsi.is_valid_token(_cand) else ""
        except Exception:
            _wt_tok = ""
    _SESSION_ID = _env_sid or _wt_tok or _pay_sid
    # 2026-10-23（T6 销账）：把「载荷 sid ↔ worktree token」同一性落盘 —— 见
    #   `_write_session_alias` 的实测背景（否则 verify 与编辑落到两个桶，T6 永不销账）。
    if _pay_sid and _wt_tok:
        _write_session_alias(_pay_sid, _wt_tok)
    # 2026-09-25：**会话身份出口**（见 `_write_session_marker`）—— 必须在任何早退/拦截之前落盘，
    #   否则被拦的那次调用不留标记，agent 侧同一工具调用内的命令就取不到身份。
    _write_session_marker(_SESSION_ID, tool_name, cwd)

    # ── MCP 命令执行器身份归一（`ECC-8F128D27B3E1`）──
    # 位点：**先于** `scope_out` 判定 —— R0 是"普适 gate，范围外也执行"。归一后
    #   `tool_name == "RunCommand"` ⟹ 下方 `scope_out` 分支与范围内分支、`_hslsn_bypass`
    #   全部按 RunCommand 取 `tool_input["command"]`（判定仍单源，本段不复制任何判据）。
    _ctool, _ccmd = _cmd_identity(tool_name, tool_input)
    if _ctool != tool_name:
        _log_hook(f"CMD-IDENTITY-NORM: {tool_name} -> {_ctool} cmd={(_ccmd or '<none>')[:120]}")
        if not _ccmd:
            # fail-closed：执行器但取不到命令串 ⟹ 无法扫 ⟹ 拒（对齐写类归一无路径的处置）
            block("MCP command executor without a resolvable command (fail-closed): "
                  f"tool={tool_name}; 请在调用参数中给 command/cmd/script，或改用原生 RunCommand。")
        tool_name = _ctool
        tool_input = dict(tool_input)
        tool_input["command"] = _ccmd
        _CALL_TOOL = tool_name      # 归一后同步（提权防线② / 审计口径）
        _CALL_CMD = _ccmd           # R0 家族读它

    # ── Gate R0.14【单出网口闸】：浏览器 MCP 出网归一 + 普适 BLOCK（`ECC-6007804DD7BD`）──
    # 位点同 `_cmd_identity`：**先于** `scope_out` —— 出网是"普适"面，治理范围外同样拦。
    # 判定单源 = `_egress_identity`（哨兵名 ≠ 原 tool_name 即命中）；本段不复制任何判据。
    _eg_tool, _eg_url = _egress_identity(tool_name, tool_input)
    if _eg_tool == MCP_EGRESS_ALLOWED:
        # 受治车道放行：白名单域 → 记账后放行（不 BLOCK）。
        _eg_host = _egress_host(_eg_url)
        _record_mcp_egress(_eg_host, _eg_url)
        _log_hook(f"MCP-EGRESS-ALLOW: {tool_name} host={_eg_host or '<none>'}")
    elif _eg_tool != tool_name:
        _log_hook(f"MCP-EGRESS-BLOCK: {tool_name} target={(_eg_url or '<none>')[:160]}")
        block(MCP_EGRESS_GATE_NAME + ": "
              f"浏览器出网工具 `{tool_name}` 被拦截（目标={_eg_url or '<未解析>'}）。"
              "契约：**一切出网走 `subagent_runner._prior_art_fetch`**（或**受治车道**的**白名单域**）；"
              "浏览器 MCP 导航/取网/`evaluate` = 无台账的第二出网通道 ⟹ 拒。"
              "逃生舱（仅运维显式放行）：GK_MCP_EGRESS_GATE=0。")

    # ── Gate R0.18【octop 浏览器工具面】：install / record 写面（普适面，先于 scope_out）──
    _bt_block = _browser_toolface_gate(tool_name, tool_input)
    if _bt_block:
        _log_hook(f"MCP-BROWSER-TOOLFACE-BLOCK: {tool_name}")
        block(_bt_block)

    # ── H-SLSN 激活检测（2026-08-27，ECC-8570E847C7C1）──
    # 双条件与：① hook 生效（PreToolUse 被触发 = 本函数在跑） ② 用户指令含 Use Skill: spz-gatekeeper-r-sequence
    #   —— ② 的代理检测 = Skill 工具调用本身（tool_name=="Skill" 且输入含技能名）。
    # ── Gate R0.15【蓝鳍瞭望观测准入】(2026-11-01)：防非法偷窥 ─────────────────
    #   默认只许「本侧 + 脱敏」；`--reveal` / `--cross-side` 需 GK_WATCH_APPROVED=1。
    #   allow/deny 都落访客记录（与 state 同目录的 watch-log sidecar）。
    if tool_name == "RunCommand":
        # ── Gate R0.20【非交互凭据闸】(2026-11-04)：禁止触发交互式 git 登录 ──────────
        #   病象：`git push` 到无凭据的 https remote（如 atomgit）会弹登录框，
        #   被宿主 IDE 接管成"Trae git 登录"（用户明确要求无限拦截该机制）。
        #   判据：https remote + 无 credential.helper + 命令未声明 GIT_TERMINAL_PROMPT=0。
        _git_blk = _git_push_guard(tool_input.get("command", ""), cwd)
        if _git_blk:
            block(_git_blk)
        _wg = _watch_gate(tool_input.get("command", ""))
        if _wg.get("matched"):
            _record_watch_visit(_wg, cwd)
            if not _wg["allow"]:
                block(_wg["reason"])

    # 必须在 scope_out 判定之前执行（Skill 工具可在任意 cwd 触发）。
    # 2026-08-27 全名化改造：精确匹配全名（投毒点关闭）——
    #   激活：name == spz-gatekeeper-r-sequence（精确，非子串）
    #   拦截：旧名 plan-refine / 未注册技能名（未知命令全部拦截原则）
    if tool_name == "Skill":
        _sname = _hslsn_skill_name(tool_input)
        if _sname == _HSLSN_PRIMARY_SKILL:
            _hslsn_activate()
        elif _sname in _HSLSN_LEGACY_NAMES:
            # 旧名/歧义名 → 拦截 + 引导全名（投毒点：错误名不再放行）
            _verdict = _hslsn_record_and_verdict(
                f"Skill 名称歧义: '{_sname}' 是旧名 — 统一使用 'Use Skill: {_HSLSN_LEGACY_NAMES[_sname]}' 全名")
            if _verdict:
                block(_verdict[0], _verdict[1])
        elif _sname and _sname not in _hslsn_installed_skills():
            # 未注册技能名 → 拦截（未知命令全部拦截原则）
            _verdict = _hslsn_record_and_verdict(
                f"未知技能名: '{_sname}' 未在 ~/.trae/skills/ 注册 — 使用精确技能名（如 Use Skill: plan-refinement）")
            if _verdict:
                block(_verdict[0], _verdict[1])
    elif _hslsn_active():
        # 回环拦截：会话激活期间，绕过技能内置 cmd 的工具调用 → 引导 + 记录（带状态 while 循环）
        _hslsn_touch()
        _cmd = tool_input.get("command", "") if tool_name == "RunCommand" else ""
        _fp = tool_input.get("file_path", "") or tool_input.get("path", "")
        _bypass = _hslsn_bypass(tool_name, tool_input, _cmd, _fp, cwd)
        if _bypass:
            _verdict = _hslsn_record_and_verdict(_bypass)
            if _verdict:
                block(_verdict[0], _verdict[1])

    # ── Gate 9 配套：提问挂起结算（记录侧，2026-09-21）──
    # 任一工具调用到达（**含** AskUserQuestion 本身，覆盖连续提问）⟹ 上一次提问已结束
    # ⟹ 跨度入台账 `.gatekeeper.ask-hold.log`。**只记录，不在此判杀**（判杀在
    # `monitor --local` 的 `ask_hold_kill` 项；分工见上方常量段注释）。
    _ask_hold_settle()

    # ── Gate 9【提问挂起闸】(F-REV-96, 2026-09-17) ──
    # 普适 gate（治理范围外也执行）：AskUserQuestion 命中「无人时段 / 纯确认型」→ deny。
    # 「agent 用提问挂起等已入睡的用户」是 CLI 侧任何看门狗都覆盖不到的失败面（§8.17 F-REV-92）——
    # AskUserQuestion 是 agent 那一轮的**结束**，没有进程在跑，故只能在此层 deny。
    if tool_name == "AskUserQuestion":
        _ask = _ask_hold_gate(tool_input)
        if _ask:
            _lvl, _arsn, _ahint = _ask
            if _lvl == "BLOCK":
                _CALL_KIND = "ask"
                block(f"提问挂起闸: {_arsn}", _ahint)
            else:
                # WARN = 放行，提问真发生 ⟹ 落待答标记（判杀侧的唯一起飞点）
                _ask_hold_record(_ask_blob(tool_input))
                _log_hook(f"WARN GATE9 提问挂起闸: {_arsn}")
                print(f"GATEKEEPER-WARN: 提问挂起闸: {_arsn} {_ahint}", file=sys.stderr)
        else:
            _ask_hold_record(_ask_blob(tool_input))

    # Hook state 归属（2026-08-03 + 2026-08-05 治理范围模型）：
    # 仅当 STATE_FILE 仍是模块默认 fallback 时按 cwd 解析（env/patch 显式设置不覆盖，
    # 保持 CLI 契约与测试兼容）；解析结果为 None = 治理范围外 → 放行。
    global STATE_FILE
    scope_out = False
    # F5（ECC-05D9F1857601，2026-09-18 用户裁定 ①）：**目标路径优先**判定。
    # 原逻辑只按 cwd 判 ⟹ Trae 会话 cwd 常在治理范围外（`c:\Users\HP`）⟹ scope_out ⟹ 早退
    # ⟹ Gate 3/4/8 整链不执行（实测 hook.log 全部 Edit/Write 带 [SCOPE-OUT:allow]）。
    # 目标与治理范围**无关**时 `_resolve_state_by_target_path` 返回 None ⟹ 落回原 cwd 逻辑
    # （不把范围外项目拉进来 = 不误伤）。kill switch：`GK_SCOPE_TARGET=0` → 纯 cwd 判定。
    _target_hint = tool_input.get("file_path") or tool_input.get("path") or ""
    # ── MCP 写形态扩展（2026-10-02，堵「MCP 写 × scope-out」旁路）──────────────────
    # 现场（实证）：MCP 写路径在 `tool_input["args"]["path"]`（`run_mcp`）/ `tool_input` 本体
    #   （`mcp__…`），**不在** `file_path`/`path`；且原条件 `tool_name in EDIT_TOOLS` 不含 MCP 名
    #   ⟹ MCP 写**漏判** ⟹ 落回 cwd 判定 ⟹ 会话 cwd 常在治理范围外（`c:\Users\HP`）⟹ `scope_out`
    #   早退 ⟹ 写面整链不执行 = **旁路**（而同一目标用原生写会被 F5 认领 ⟹ 不对称）。
    # 复用既有归一（`_mcp_inner_tool`/`_mcp_write_path`/`MCP_WRITE_VERBS`，禁第二份解析）。
    _m_inner, _m_args = _mcp_inner_tool(tool_name, tool_input)
    _is_mcp_write = bool(_m_inner) and bool(set(_m_inner.lower().split("_")) & MCP_WRITE_VERBS)
    if _is_mcp_write:
        _target_hint = _mcp_write_path(_m_args or {})
    _target_state = None
    if (_is_mcp_write or tool_name in EDIT_TOOLS) and _target_hint \
            and os.environ.get("GK_SCOPE_TARGET", "") != "0":
        _target_state = _resolve_state_by_target_path(_target_hint)
    if _target_state is not None:
        STATE_FILE = _target_state
    elif str(STATE_FILE) in _DEFAULT_STATE_PATHS:
        resolved = _resolve_state_by_cwd(cwd)
        if resolved is None:
            scope_out = True
        else:
            STATE_FILE = resolved

    # 调用日志 — 每次被 Trae 触发都留痕（2026-08-05）；F5：增记「目标路径判定进入」标记
    _log_hook(f"INVOKE event={hook_data.get('hook_event_name', '?')} tool={tool_name} cwd={cwd} state={STATE_FILE}"
              + (" [SCOPE-OUT:allow]" if scope_out else "")
              + (f" [SCOPE-TARGET:{_target_hint}]" if _target_state is not None else ""))

    # ── 宿主配置**独立面**（`R-HOSTCFG` 收尾，2026-10-02）──────────────────────────
    # 宿主配置（Trae `hooks.json` / `mcp.json` / `settings.json`）在治理仓**之外**，且会话 cwd 常为
    # `c:\Users\HP` ⟹ 上方 scope 判定落 `SCOPE-OUT` ⟹ Gate 3/4 整链**不执行**（实测：宿主
    # `mcp.json` 写被放行且**零留痕**）；反之若把宿主目录当写面 bind 进 `worktrees_extra`，该键会被
    # 并发会话**整体替换** ⟹ 绑定必丢（本会话实测两次）。
    # 故此处**先于** scope 分支接手，判定**单源**复用既有 `guard-edit`（`_protected_region_check`）：
    # WARN 档放行 + 强制留痕、BLOCK 档拦（门禁本体 `hooks.json` 不可被治理者自拆）。
    # ⟹ **零 state 依赖**（并发重写 state 不影响）、**与 cwd 无关**、且不复制任何判定。
    # 边界：宿主配置**不吃**项目级 Gate 3/4（写面 / 预算 / stage）—— 它本就存明文 token（如 mcp.json
    # 里的 PAT），密钥闸/预算闸对它属**错配**；但「过/拦 + 留痕」仍**单源**于 `_protected_region_check`，
    # 且每次写都进审计账本 `${STATE_FILE}.protected-edits.jsonl`（region=HOST-CONFIG）。
    # 回退面：`GK_HOST_PROTECT=0` ⟹ 整段跳过（= 变更前行为：被 scope-out 静默放行）。
    if (tool_name in EDIT_TOOLS and _target_hint
            and os.environ.get("GK_HOST_PROTECT", "1") != "0"):
        from gk_host_paths import is_host_config_path  # 惰性导入：仅本分支路径需要
        if is_host_config_path(_target_hint):
            _hc = _run_cli(["guard-edit", _target_hint])
            _hc_ok = bool(_hc.get("allowed")) if "allowed" in _hc else bool(_hc.get("ok"))
            if not _hc_ok:
                block(f"宿主配置（独立面）被拒: {_target_hint} :: "
                      f"{str(_hc.get('reason') or _hc.get('error') or _hc.get('raw') or '')[:300]}")
            _log_hook(f"HOST-CONFIG 独立面放行（guard-edit 判定 + 已留痕）: {_target_hint}")
            sys.exit(0)

    if scope_out:
        # 普适安全 gate（与项目治理无关，范围外也执行）：WSL 引号陷阱拦截（2026-08-09）。
        # 治理范围内的项目由 Gate R0.1 执行；范围外项目（如当前 cwd 不在 governed_projects）
        # 此前完全放行 → 转义错误反复发生。对齐 wasm-pre-check.sh P0 层：拦截 + 附修复命令。
        if tool_name == "RunCommand":
            command = tool_input.get("command", "")
            trap = _wsl_quoting_trap(command)
            if trap:
                block(f"WSL quoting trap [universal]: {command[:100]}... {trap}")
            # 2026-08-15: 普适危险命令 gate 范围外也执行（对齐 _dangerous_command 文档承诺，
            # 此前 scope_out 分支只跑引号陷阱 → 范围外命令直接 rm -rf 可绕过）。
            # 2026-08-28: 升级为编码复扫（RED-HOOK-16，base64/hex/rot13 解码后再检测）
            # 2026-09-24（ECC-8DFC84C5B9E5）：本路是 **RunCommand 命令串**（=「这一条命令」）
            #   ⟹ 吃惰性豁免（`inert=True`）。
            danger = _dangerous_command_decoded(command, inert=True)
            if danger:
                reason, hint = danger
                block(f"{reason} Command: {command[:120]}...", hint)
            # ── Gate R0.9: Windows 侧 git 写操作硬拦（普适，范围外也执行）──
            win_git = _git_windows_write(command)
            if win_git:
                block(f"{win_git[0]} Command: {command[:120]}...", win_git[1])
            # ── Gate R0.15: 蓝色大肥鱼与主树之间不得不说的故事（主树 git 写；普适，范围外也执行）──
            main_git = _git_main_tree_write(command, cwd)
            if main_git:
                block(f"{BLUE_FAT_FISH_MAIN_GIT_GATE_NAME}: {main_git[0]} Command: {command[:120]}...",
                      main_git[1])
            # ── Gate R0.16: 蓝色大肥鱼与配好的解释器之间不得不说的故事（pytest 解释器；普适）──
            py_gate = _pytest_wrong_interpreter(command)
            if py_gate:
                block(f"{BLUE_FAT_FISH_PYTEST_GATE_NAME}: {py_gate[0]} Command: {command[:120]}...",
                      py_gate[1])
            # ── Gate R0.8: 明文 API key / 私钥字面量（普适，范围外也执行）──
            _sec = _plaintext_secret(command)
            if _sec:
                block(f"{_sec[0]} Command: {command[:120]}...", _sec[1])
            script_danger = _scan_script_content(command)
            if script_danger:
                reason, hint = script_danger
                block(f"{reason} Command: {command[:120]}...", hint)
            # 2026-09-14: Gate R0.6【蓝色大肥鱼与powershell之间不得不说的故事】普适拦截
            # （范围外也执行，与 R0.1 同层）：PS 宿主解析改写（$ / << / 反引号 / [ ]）。
            ps_story = _blue_fat_fish_ps_story(command)
            if ps_story:
                _lvl, _rsn, _hint = ps_story
                if _lvl == "BLOCK":
                    block(f"{BLUE_FAT_FISH_GATE_NAME} [universal]: {command[:120]}... {_rsn}", _hint)
                else:
                    _log_hook(f"WARN R0.6 {BLUE_FAT_FISH_GATE_NAME}: {command[:160]}")
                    print(f"GATEKEEPER-WARN: {BLUE_FAT_FISH_GATE_NAME}: {_rsn} {_hint}", file=sys.stderr)
            # 2026-09-14: Gate R0.7【蓝色大肥鱼与wsl之间不得不说的故事】普适拦截（范围外也执行）
            # —— wsl 家族入口（wslsh / WSLENV / wsl -e|--|--exec）的引号与编码陷阱。
            wsl_story = _blue_fat_fish_wsl_story(command)
            if wsl_story:
                _wl, _wr, _wh = wsl_story
                if _wl == "BLOCK":
                    block(f"{BLUE_FAT_FISH_WSL_GATE_NAME} [universal]: {command[:120]}... {_wr}", _wh)
                else:
                    _log_hook(f"WARN R0.7 {BLUE_FAT_FISH_WSL_GATE_NAME}: {command[:160]}")
                    print(f"GATEKEEPER-WARN: {BLUE_FAT_FISH_WSL_GATE_NAME}: {_wr} {_wh}", file=sys.stderr)
            # 2026-10-10: Gate R0.12【蓝色大肥鱼与PowerShell别名之间不得不说的故事】普适拦截
            # （范围外也执行）—— PS 会话里 `ls -d`/`curl -o`/`ps aux` 等命令位别名 + POSIX 旗标。
            alias_story = _blue_fat_fish_ps_alias_story(command)
            if alias_story:
                block(f"{BLUE_FAT_FISH_ALIAS_GATE_NAME} [universal]: "
                      f"{command[:120]}... {alias_story[1]}", alias_story[2])
            # 2026-10-10: Gate R0.13【蓝色大肥鱼与PowerShell解析器之间不得不说的故事】普适拦截
            # （范围外也执行）—— PS 上直接跑 POSIX 控制语法 `for…do…done` / `if…then…fi`。
            posix_story = _blue_fat_fish_ps_posix_story(command)
            if posix_story:
                block(f"{BLUE_FAT_FISH_POSIX_GATE_NAME} [universal]: "
                      f"{command[:120]}... {posix_story[1]}", posix_story[2])
            # 2026-08-27: 插件裸调用普适拦截（范围外也执行）——强制统一入口 cmd_migrate
            plugin_bare = _plugin_bare_call(command)
            if plugin_bare:
                block(f"插件裸调用绕过统一入口: {command[:120]}... (命中 {plugin_bare})。{_plugin_load_status_line()}",
                      "Fix: bash gatekeeper-cli.sh migrate analyze|verify|audit ... "
                      "（统一入口执行 gk_plugin_manifest.check_capability + gk_bashpy_loader 哈希对账硬门禁）")
            # ── Gate R0.10【质询派发并行闸】(N9) / Gate R0.11【merge 前孤儿锁闸】──
            # 普适（范围外也执行）。**2026-09-30 实测缺陷**：两闸若只挂「范围内」分支，则
            #   `git merge`（无治理目标 ⟹ scope_out）走本分支后 `sys.exit(0)` 早退 ⟹ **恒不触达**
            #   （「门禁有、实际不生效」族）。故**两分支同挂**（对齐 R0.9 的挂法）。
            n9 = _n9_parallel_dispatch(command)
            if n9:
                _log_hook(f"BLOCK R0.10 N9 质询派发并行闸: {command[:160]}")
                block(f"N9 {n9[0]}. Command: {command[:120]}...", n9[1])
            mlp = _merge_lock_preflight(command)
            if mlp:
                _log_hook(f"BLOCK R0.11 merge-preflight: {command[:160]}")
                block(f"N10 {mlp[0]}. Command: {command[:120]}...", mlp[1])
            # ── Gate R0.17【worktree 建树单一入口闸】(2026-10-28) ──
            # 「门禁看得见但管不着」族的补洞：手搓树 ⟹ 写面未登记 ⟹ Edit 必被 Gate 3 拦
            # ⟹ agent 转而用 `cp` 搬文件 = 绕路。此处**在起手处**拦掉整条绕路链。
            wt_route = _wt_route_gate(command)
            if wt_route:
                _log_hook(f"BLOCK R0.17 worktree-route: {command[:160]}")
                block(f"WT-ROUTE {wt_route[0]}. Command: {command[:120]}...", wt_route[1])
            # ── T6 销账通道（2026-10-23）：范围外**也**采集验证动作 ──
            #   范围内分支尾部有 `_emit_verify_event`；本分支原直接 `sys.exit(0)` ⟹ 会话 cwd
            #   在范围外时**永不采集** ⟹ `kind=verify` 恒 0 ⟹ T6 欠债无法清偿（实测见
            #   `_emit_verify_event_unscoped` 文档）。此处只补采集，不改任何闸的放行语义。
            # 步数 telemetry（2026-10-23）：**无条件**先记一条（验证动作也算一步）。
            _emit_step_event_unscoped(command)
            if _is_verify_command(command):
                _emit_verify_event_unscoped(command)
        # Gate R0.8（EDIT 载荷）：范围内外同判 —— 写 key 到治理范围外（如 ~/.env）同为泄漏
        _secret_gate_edit(tool_name, tool_input,
                          tool_input.get("file_path") or tool_input.get("path") or "")
        # Gate R0.19（EDIT 载荷）：恶意代码同判 —— 把后门写到治理范围外同样是后门
        _malware_gate_edit(tool_name, tool_input,
                           tool_input.get("file_path") or tool_input.get("path") or "")
        sys.exit(0)

    # 治理范围内 → 允许记录被禁意图（scope_out 的普适 BLOCK 不入技能 state）
    global _CALL_IN_SCOPE
    _CALL_IN_SCOPE = True

    # 2026-10-13（`ECC-317C82A14DE8` ①）：留**归一前**原名，供 `_protected_target_line` 用 ——
    #   下方 `_write_identity` 会把 MCP 写身份改写成 `Write`/`SearchReplace`，届时 `_mcp_inner_tool`
    #   认不出 `run_mcp`/`mcp__…` ⟹ 剥不到 `args` ⟹ 行级仍不可得。
    _ORIG_TOOL_NAME = tool_name

    # Extract file path from tool input
    file_path = tool_input.get("file_path", "")
    if not file_path:
        # Some tools use 'path' instead
        file_path = tool_input.get("path", "")

    # ── 工具身份归一（`ECC-BC63B84B28AB`）：MCP 写工具并入写类判定 ──
    # 位点在此（`file_path` 提取后、`_secret_gate_edit` 前）⟹ 一处归一同时覆盖
    #   R0.8 密钥闸 + Gate 3（写面包含）+ Gate 8（技能自维护）+ Gate 4（`pre-tool-check`）。
    #   ⚠ 若放到 `_secret_gate_edit` 之后，密钥闸仍以 MCP 原名落空（其首行即
    #   `if tool_name not in EDIT_TOOLS: return`）。
    _wtool, _wpath = _write_identity(tool_name, file_path, tool_input)
    if _wtool != tool_name:                      # 仅 MCP 写类命中
        _log_hook(f"WRITE-IDENTITY-NORM: {tool_name} -> {_wtool} path={_wpath or '<none>'}")
        if not _wpath:
            # fail-closed：写类但取不到路径 ⟹ 无法判写面包含 ⟹ 拒（block() 内 sys.exit(2)）
            _CALL_TOOL = _wtool                  # 归一身份先同步（该条 BLOCK 也须按写面身份留痕）
            block(f"MCP write tool without a resolvable target path (fail-closed): tool={tool_name}; "
                  "请在调用参数中给 path/paths，或改用原生写工具。")
        tool_name, file_path = _wtool, _wpath
        # ── 调用上下文同步（`ECC-164BC163D0A5`）──────────────────────────────────────
        # 与命令面归一同型（见上方 `_cmd_identity` 的「归一后同步（提权防线② / 审计口径）」）：
        #   写面归一后**必须回写** `_CALL_TOOL`/`_CALL_TARGET`，否则 `_record_block_intent`
        #   落盘的 `tool` = MCP 原始名（`run_mcp`/`mcp__…` ∉ `EDIT_TOOLS`）、`target` = 空串
        #   ⟹ 防线②「工具失效→提权绕过」对 MCP 写**整条失明**（原生 Edit 同链可拦 = 不对称旁路）。
        #   `_CALL_TARGET` 同 scope 段口径（`resolve_path`）重算；异常回落归一后路径。
        _CALL_TOOL = tool_name
        try:
            _CALL_TARGET = resolve_path(file_path, cwd) if file_path else ""
        except Exception:
            _CALL_TARGET = file_path or ""

    # ── Gate R0.8: 明文 API key / 私钥字面量（Edit/Write 载荷）──
    _secret_gate_edit(tool_name, tool_input, file_path)

    # ── Gate R0.19: 恶意代码模式（Edit/Write 载荷）──
    _malware_gate_edit(tool_name, tool_input, file_path)

    # ── Gate 0: Task 默认拒绝 + 单次票据（方案 B，2026-10-27）──
    # 2026-08-26：治理范围内禁止裸 Task 跑任何 gatekeeper 流程，引导回 CLI 正规流程
    #   （monitor --subagent / plan-refinement：受限工具 + 预算 + 审计留痕）。
    # 2026-10-27（用户裁定「按方案 B 执行完整闭包」）：**判据从关键词黑名单换成票据**——
    #   关键词只告警留痕（`dispatch_keyword_hit`），放行须凭 `state-patch --dispatch-issue`
    #   签发的单次票据（HMAC + 查询哈希 + 过期 + 单次消费）。关键词表**保留**，理由见
    #   `_task_dispatch_gate` docstring（黑名单非完备集、生态测试钉住、删了只会更隐蔽）。
    if tool_name == "Task":
        _deny = _task_dispatch_gate(tool_name, tool_input, _SESSION_ID)
        if _deny:
            block(_deny)

    # ── Gate R0: Block dangerous RunCommand patterns ──
    if tool_name == "RunCommand":
        command = tool_input.get("command", "")
        command_lower = command.lower()
        # Detect direct filesystem writes via shell redirection
        write_patterns = ["> ", ">> ", "tee ", "cat >", "cat <<", "echo >", "printf >"]
        if any(p in command_lower for p in write_patterns):
            # Check if writing to a path inside the worktree
            has_state_file = "gatekeeper.state" in command_lower or ".gatekeeper" in command_lower
            if not STATE_FILE.exists() or has_state_file:
                block(f"RunCommand writes filesystem via shell redirection. Use IDE Write/Edit tools instead so pre-tool-check can validate. Command: {command[:120]}...")

        # ── Gate R0.1: WSL quoting trap (PS host expands / strips quotes before wsl sees argv) ──
        # 复用普适检测函数 _wsl_quoting_trap（与 scope_out 普适 gate 同一逻辑）
        trap = _wsl_quoting_trap(command)
        if trap:
            block(f"WSL quoting trap: {command[:100]}... {trap}")

        # ── Gate R0.2: W4 危险命令普适拦截（p0-analysis §1.2，类2 高危破坏）──
        # 纯语法检测 → 普适（范围外也执行）；BLOCK + Fix 建议（W5）二次确认
        # 2026-08-28: 编码解码复扫（RED-HOOK-16）— base64/hex/percent-unquote/rot13
        # 编码的危险命令逐字匹配不可见，解码变体复扫后命中同样 BLOCK
        # 2026-09-24（ECC-8DFC84C5B9E5）：本路是 **RunCommand 命令串**（=「这一条命令」）
        #   ⟹ 吃惰性豁免（`inert=True`）。
        danger = _dangerous_command_decoded(command, inert=True)
        if danger:
            reason, hint = danger
            block(f"{reason} Command: {command[:120]}...", hint)

        # ── Gate R0.9: Windows 侧 git 写操作硬拦（2026-09-26，跨 OS 抢锁预防）──
        win_git = _git_windows_write(command)
        if win_git:
            block(f"{win_git[0]} Command: {command[:120]}...", win_git[1])

        # ── Gate R0.15【蓝色大肥鱼与主树之间不得不说的故事】主树 git 写（2026-10-26，堵 RunCommand 旁路）──
        main_git = _git_main_tree_write(command, cwd)
        if main_git:
            block(f"{BLUE_FAT_FISH_MAIN_GIT_GATE_NAME}: {main_git[0]} Command: {command[:120]}...",
                  main_git[1])

        # ── Gate R0.16【蓝色大肥鱼与配好的解释器之间不得不说的故事】pytest 解释器（2026-10-27）──
        py_gate = _pytest_wrong_interpreter(command)
        if py_gate:
            block(f"{BLUE_FAT_FISH_PYTEST_GATE_NAME}: {py_gate[0]} Command: {command[:120]}...",
                  py_gate[1])

        # ── Gate R0.8: 明文 API key / 私钥字面量（命令串）──
        _sec = _plaintext_secret(command)
        if _sec:
            block(f"{_sec[0]} Command: {command[:120]}...", _sec[1])

        # ── Gate R0.3: 脚本内容级扫描（2026-08-15，堵"危险命令藏脚本内部"向量）──
        # 字符串级 R0.2 看不到 bash <script> 内部行（E2E rm -rf $TMP 自删事件）；
        # 读取脚本内容逐行跑 _dangerous_command，命中即 BLOCK
        script_danger = _scan_script_content(command)
        if script_danger:
            reason, hint = script_danger
            block(f"{reason} Command: {command[:120]}...", hint)

        # ── Gate R0.3b: bash -c 不可静态分析荷载告警（2026-09-10 E3，不 BLOCK）──
        # 荷载含 $(...)/反引号/cat/xargs → 运行时内容静态不可判 → 告警 + 引导落脚本
        # 走 R0.3 文件扫描；不升级为 BLOCK（用户定案：严格面只覆盖静态可判形态）。
        _unanalyzable = _warn_unanalyzable_bash_c(command)
        if _unanalyzable:
            _log_hook(f"WARN R0.3b bash -c 荷载不可静态分析: {command[:160]}")
            print(f"GATEKEEPER-WARN: {_unanalyzable}", file=sys.stderr)

        # ── Gate R0.4: 插件调用强制统一入口（2026-08-27，插件加载安全网硬门禁）──
        # 插件（bashpy-migrate）裸调用绕过 manifest cap 白名单 + 加载安全网哈希对账 → BLOCK。
        # 统一入口 = cmd_migrate（gatekeeper-cli.sh migrate），探测链统一 + 安全网硬门禁。
        plugin_bare = _plugin_bare_call(command)
        if plugin_bare:
            block(f"插件裸调用绕过统一入口: {command[:120]}... (命中 {plugin_bare})。{_plugin_load_status_line()}",
                  "Fix: bash gatekeeper-cli.sh migrate analyze|verify|audit ... "
                  "（统一入口执行 gk_plugin_manifest.check_capability + gk_bashpy_loader 哈希对账硬门禁）")

        # ── Gate R0.5: 工具失效→提权绕过拦截（2026-09-02，防线③ 权限边界）──
        # Edit/Write 写 X 被 BLOCK 后，RunCommand 重定向直写同文件 = 越权通道（绕过编辑门控）。
        # 命中 → kind=escalation 记录（monitor/audit 的「行为偏离」信号源）+ BLOCK。
        esc = _escaped_write_after_block(command, cwd)
        if esc:
            _CALL_KIND = "escalation"
            block(esc, "Fix: 用受管 Write/Edit 重试（先满足 Gate3/8 前置）或经 CLI 正规命令；"
                       "禁止 shell 直写绕过编辑门控")

        # ── Gate R0.6【蓝色大肥鱼与powershell之间不得不说的故事】(2026-09-14) ──
        # 独立一类：PS 宿主解析改写（$ / << / 反引号 / [ ]）。与 R0.1 平行但**覆盖面不同**
        # —— R0.1 只认 `wsl bash -c` 形态；本闸认「宿主会改写任意命令串」。P1-P3 = BLOCK，
        # P4 = WARN（对齐 R0.3b 的"严格面只覆盖静态可判形态"定案）。
        ps_story = _blue_fat_fish_ps_story(command)
        if ps_story:
            _lvl, _rsn, _hint = ps_story
            if _lvl == "BLOCK":
                block(f"{BLUE_FAT_FISH_GATE_NAME}: {command[:120]}... {_rsn}", _hint)
            else:
                _log_hook(f"WARN R0.6 {BLUE_FAT_FISH_GATE_NAME}: {command[:160]}")
                print(f"GATEKEEPER-WARN: {BLUE_FAT_FISH_GATE_NAME}: {_rsn} {_hint}", file=sys.stderr)

        # ── Gate R0.7【蓝色大肥鱼与wsl之间不得不说的故事】(2026-09-14) ──
        # wsl 家族入口（wslsh / WSLENV / wsl -e|--|--exec）的引号与编码陷阱。
        # W1/W2 = BLOCK（引号层 mangling），W3/W4 = WARN（WSLENV 缺 /u / Windows 路径）。
        wsl_story = _blue_fat_fish_wsl_story(command)
        if wsl_story:
            _wl, _wr, _wh = wsl_story
            if _wl == "BLOCK":
                block(f"{BLUE_FAT_FISH_WSL_GATE_NAME}: {command[:120]}... {_wr}", _wh)
            else:
                _log_hook(f"WARN R0.7 {BLUE_FAT_FISH_WSL_GATE_NAME}: {command[:160]}")
                print(f"GATEKEEPER-WARN: {BLUE_FAT_FISH_WSL_GATE_NAME}: {_wr} {_wh}", file=sys.stderr)

        # ── Gate R0.12【蓝色大肥鱼与PowerShell别名之间不得不说的故事】(2026-10-10) ──
        # PS 会话别名劫持：命令位 `ls`/`curl`/`ps`/… + POSIX 专属旗标。
        alias_story = _blue_fat_fish_ps_alias_story(command)
        if alias_story:
            block(f"{BLUE_FAT_FISH_ALIAS_GATE_NAME}: "
                  f"{command[:120]}... {alias_story[1]}", alias_story[2])

        # ── Gate R0.13【蓝色大肥鱼与PowerShell解析器之间不得不说的故事】(2026-10-10) ──
        # PS 上直接跑 POSIX 控制语法 `for…do…done` / `if…then…fi` / `case…esac` ⟹ ParserError。
        posix_story = _blue_fat_fish_ps_posix_story(command)
        if posix_story:
            block(f"{BLUE_FAT_FISH_POSIX_GATE_NAME}: "
                  f"{command[:120]}... {posix_story[1]}", posix_story[2])

        # ── Gate R0.10【质询派发并行闸】(N9, 2026-09-30) ──
        # 「文档有、机检无」族：§0.1 并行派发令 + N7 已写死却复发（owner：已修过一次）⟹ 补机检。
        n9 = _n9_parallel_dispatch(command)
        if n9:
            _log_hook(f"BLOCK R0.10 N9 质询派发并行闸: {command[:160]}")
            block(f"N9 {n9[0]}. Command: {command[:120]}...", n9[1])

        # ── Gate R0.11【merge 前孤儿锁闸】(2026-09-30) ──
        # `git merge` 路径不跑 `cmd_commit` 的 lock preflight ⟹ 孤儿 `index.lock` 卡死合并（实测）。
        mlp = _merge_lock_preflight(command)
        if mlp:
            _log_hook(f"BLOCK R0.11 merge-preflight: {command[:160]}")
            block(f"N10 {mlp[0]}. Command: {command[:120]}...", mlp[1])

        # ── Gate R0.17【worktree 建树单一入口闸】(2026-10-28) ──
        # 与 scope_out 分支**同挂**（对齐 N9/N10 的挂法）：建树命令常从会话 cwd（治理范围外）
        # 发出，只挂范围内分支会造成「门禁有、实际不生效」。
        wt_route = _wt_route_gate(command)
        if wt_route:
            _log_hook(f"BLOCK R0.17 worktree-route: {command[:160]}")
            block(f"WT-ROUTE {wt_route[0]}. Command: {command[:120]}...", wt_route[1])

    # ── Gate 1: Stage must be active ──
    if not STATE_FILE.exists():
        block("Stage is 'no_state_file'. Cannot edit without active R-phase. Run 'gatekeeper-cli.sh state'.")

    try:
        state = json.loads(STATE_FILE.read_text())
    except Exception:
        block("State file corrupt. Run 'gatekeeper-cli.sh state' to repair.")

    stage = state.get("stage", "IDLE")
    if stage in ("IDLE", "DONE"):
        # 2026-09-06: IDLE/DONE 裸跑交叉审查（review 形态）kind=review 留痕 —— hook_block_log
        # 可审计（monitor/audit --hook 的提权链快照含 kind=review 明细），不改变既有拦截语义。
        if tool_name == "RunCommand" and _review_lane_lookup(tool_input.get("command", "")):
            _CALL_KIND = "review"
        block(f"Stage is '{stage}'. Cannot edit without active R-phase. Start with 'spz-gatekeeper-r-sequence' skill.")

    # ── Gate 1b: 交叉审查车道节点绑定（2026-09-06，用户批评点闭环）──
    # active 但非审查节点 + subagent/LLM 车道裸跑 → BLOCK（确定性证据车道放行）。
    # 语义对齐 CLI CROSSREVIEW_NODE_BINDING（2026-09-04）；GK_DEGRADE_REVIEW=1 显式降级豁免。
    if tool_name == "RunCommand":
        _rv = _review_lane_lookup(tool_input.get("command", ""))
        if _rv and _rv["lane"] in ("subagent", "api"):
            _pt = (state.get("gate_data") or {}).get("project_type", "standard")
            _rn = _review_node_ok_src(stage, state.get("r_phase", ""), _pt)
            if not _rn["ok"]:
                if os.environ.get("GK_DEGRADE_REVIEW") == "1":
                    _log_hook(f"GATE1B-degrade: {_rv['form']} at {stage}/{_pt} (GK_DEGRADE_REVIEW=1)")
                else:
                    _CALL_KIND = "review"
                    block(
                        f"交叉审查车道节点绑定: {_rv['form']} 属 subagent/LLM 车道，必须在审查节点运行"
                        f"（当前 stage={stage} project_type={_pt}；允许 "
                        f"{_rn['expected']}）"
                        "——裸跑会绕过 L2/后R 双独立互斥调度（全量 L1-L10 只跑确定性部分=车道绕过）。",
                        "Fix: 用 spz-gatekeeper-r-sequence 推进到审查节点再跑"
                        "（standard STAGE_3|AUDIT-CROSSR / standing ECO-RESEARCH|ECO-VERIFY）；"
                        "或显式 export GK_DEGRADE_REVIEW=1 降级（非默认路径）")

    # ── Gate 2: Worktree must exist ──
    worktree = state.get("worktree", "")
    # §17-3（2026-10-04）：空值三态归一（键缺失 → "" / `null` → "" / "" → ""）—— 原先 `null`
    #   直喂下方 `_win_to_wsl(None)` 抛 `TypeError` ⟹ hook **崩溃退出（rc=1）**、Gate 3/4/5/6/7/8
    #   整链不执行（非确定性「既非放行亦非 BLOCK」）。归一后 `not worktree` 确定性 BLOCK。
    # Normalize worktree to WSL format before any comparison
    worktree = _win_to_wsl(worktree or "")
    # XENV-FORM ②（2026-09-24 修，岛内 ECC-4976A13CFD81，承 runtime 假 close 更正链）：
    # `exists()` 是 **FS 操作** ⟹ 必须吃宿主原生形态（族规则①）。原式把归一产物 `/mnt/c/…`
    # 直接喂 `Path.exists()`，Windows 宿主下被读成 `C:\mnt\c\…` ⟹ **恒假** ⟹ 对真实存在的
    # worktree 恒报 `does not exist`（runtime §4.12.3 记的 close 语义与站点原式矛盾，本落刀为
    # 真实收口）。`worktree` 变量本体**保持 WSL 归一形态**（下方 Gate 3 的 `wt_norm` 比较键
    # 消费侧契约不变），仅 FS 探测这一句换 `_host_form`；posix 侧恒等 ⟹ 零行为变化。
    if not worktree or not Path(_host_form(worktree)).exists():
        block(f"Worktree '{worktree}' does not exist. Create feature worktree first: git worktree add <path> <branch>")

    # ── Gate 3: Path must be in the **active write surface** (edit/write tools only) ──
    # RC1（2026-09-27，ECC-089658238011）：写面 = `worktree`（强制面主值）∪ `worktrees_extra[]`
    #   （允许集，缺省 [] == 今日**逐字**）。判定收敛到**单一 helper** `_in_active_surface`
    #   （= gk_route_center.in_active_surface，L5 路由中枢）—— 与 Gate 5/6/7 **同调**，
    #   且含**目录边界**（修 ECC-73ACEA635A78：裸 startswith(wt) 会放行同前缀兄弟目录）。
    if tool_name in EDIT_TOOLS and file_path:
        resolved = resolve_path(file_path, cwd)
        if not _in_active_surface(resolved, state):
            # Gate 3b（2026-09-23）：standing 序列放行**已登记 builtin 插件**技能（跨技能编辑专供
            # standing；standard 永不放行）—— 判据/白名单源见 `_standing_cross_skill_plugin`。
            _csp = _standing_cross_skill_plugin(resolved, state)
            if _csp:
                _log_hook(f"GATE3-crossskill: standing 白名单放行 plugin={_csp} path={resolved}")
            else:
                block(f"Path '{file_path}' resolves to '{resolved}' which is NOT in active write surface (worktree '{worktree}' + worktrees_extra). Edit files only in the active write surface.")

        # ── Gate 8: 技能自维护防裸跑（2026-08-20, R-T8.3）──
        # 技能仓库（SKILL_DIR 内）写操作须有 open finding 或活跃 R-phase，否则 BLOCK。
        # 与 Gate 3 同层（EDIT_TOOLS 且 file_path 非空），复用同一 resolve。
        g8 = _gate8_skill_self_maintenance(cwd, file_path, state)
        if g8:
            block(g8[0], g8[1])

        # ── ④ 写时 shellcheck 安全网（2026-09-24 用户裁定「病灶白名单注入」）──
        # 放行式**主动注入**（不拦截）：命中白名单病灶即把可照做的修法推给 agent，
        # 而不是等他自己发现（用户点名「引导 fix 是被动而不是主动注入，这也是工程摩擦」）。
        _sc = _shellcheck_lint(resolved)
        if _sc:
            print(f"GATEKEEPER-FIX: {_sc}", file=sys.stderr)
            _log_hook(f"SHELLCHECK-FIX {resolved}: {_sc[:160]}")

        # ── Gate 4: CLI pre-tool-check ──
        # 2026-09-22（ECC-BFE933526D0B 修复）：把**行号**补进自动拦截路径。原式只传路径 ⟹
        # CLI 侧 `target_line=0` ⟹ `_protected_region_check` 恒走「文件级 WARN」分支 ⟹
        # 行级 BLOCK 永不可达。行号不可得时保持 0（文件级 WARN 放行 = F-REV-45 语义不回退）。
        _tline = _protected_target_line(_ORIG_TOOL_NAME, tool_input, resolved)
        cli_result = _run_cli(["pre-tool-check", tool_name, resolved, str(_tline)])
        if not cli_result.get("ok", False):
            # 2026-09-07 P2 (ECC-E75A3C2E8FE6): standing edit_budget 耗尽 BLOCK →
            # kind=budget 留痕（_block_log_snapshot/audit --hook 可按 kind 区分 budget 拦截，
            # 区别于路径/保护区/裸跑等 kind=block 语义）。
            if "edit_budget" in str(cli_result.get("raw", "")) or "edit_budget" in str(cli_result.get("error", "")):
                _CALL_KIND = "budget"
            # f9 配套：`error` 已由 `_run_cli` 回填纯文本 BLOCK 行，但 stdout 为空时它可能是空串 ⟹
            # 依次退到 raw / 'unknown'，保证文案**永不为空**（原式为 `get("error","unknown")`，
            # 键存在但为空时同样渲染成空文案）。
            # 2026-09-24：在 raw 之前**插入 stderr 尾 3 行** —— CLI boot 失败时 `raw` 也是空，
            #   真因只在 stderr；不插则该路径恒渲染 `unknown`（摩擦：真因不可达，见 `_run_cli`）。
            _why = (cli_result.get("error") or "").strip()
            if not _why:
                _st = [ln.strip() for ln in (cli_result.get("stderr") or "").splitlines() if ln.strip()]
                _why = " | ".join(_st[-3:])
            block("CLI pre-tool-check failed: "
                  + (_why or cli_result.get("raw") or "unknown"))
        else:
            # r9-2 ②a（`ECC-BCF60C185CBE`，2026-10-01）：**放行面可见性** —— CLI 已把
            #   `gk_edit_gate.py` 算好的未审债透传上来 ⟹ 有债即 WARN（门可见）；**不改判定**。
            _debt_warn = _unreconciled_debt_warn(cli_result)
            if _debt_warn:
                print(_debt_warn, file=sys.stderr)
                _log_hook("UNRECONCILED-DEBT: " + _debt_warn[:180])

    # ── Gate 5/6/7: SCOPE_TOOLS scope — 目标路径必须落在 worktree 内 ──
    # 由 SCOPE_PATH_MAP 单一数据源驱动：按字段优先级取第一个非空作目标路径。
    # 新增只读工具只需在 SCOPE_PATH_MAP 加一行，此处无需改动（2026-08-09）。
    if tool_name in SCOPE_TOOLS:
        scope_path = next((tool_input[f] for f in SCOPE_PATH_MAP[tool_name] if tool_input.get(f)), "")
        if scope_path:
            resolved = resolve_path(scope_path, cwd)
            if resolved:
                # RC1（2026-09-27，ECC-089658238011）：与 Gate 3 **同调**同一 helper
                # （含目录边界 + 允许集），否则制造「写放开、读没放开」的新分裂（质询 F3）。
                if not _in_active_surface(resolved, state):
                    block(f"{tool_name} scope violation: '{scope_path}' resolves outside active write surface")

    # ── T6 telemetry（2026-10-08，§25）：验证动作事件（只采集，不判罚）──
    # 仅在**放行**面触发（上方任一 Gate BLOCK 即已 sys.exit，不会到达此处）；识别/写入 fail-safe。
    if tool_name == "RunCommand":
        _vcmd = tool_input.get("command", "") or ""
        # 步数 telemetry（2026-10-23，只采集）：每个 RunCommand 一条，含验证动作本身。
        _emit_step_event(_vcmd, node=str((state or {}).get("stage", "") or ""))
        if _is_verify_command(_vcmd):
            _emit_verify_event(_vcmd, node=str((state or {}).get("stage", "") or ""))

    # All gates passed
    allow()


if __name__ == "__main__":
    # A6：进程出口统一落 access 记录（覆盖 allow / block / 早退 / 异常）。
    _access_decision = "allow"
    _access_code = 0
    try:
        main()
    except SystemExit as _e:
        _access_code = _e.code if isinstance(_e.code, int) else (0 if _e.code is None else 2)
        _access_decision = "allow" if _access_code == 0 else "block"
        raise
    except BaseException:
        _access_decision = "error"
        raise
    finally:
        _amp_access_record(
            str(globals().get("_CALL_TOOL", "") or ""),
            _access_decision,
            str(globals().get("_CALL_REASON", "") or ""),
            _access_code,
        )

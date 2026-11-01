"""编码代理 edit 落刀：四道闸 + 原子写（设计 §3）。

闸序：① guard-edit（PROTECTED_REGION）② 窄任务白名单 ③ pre-tool-check（stage 守卫）
      ④ per-agent 配额
原子写：mkstemp + fsync + os.replace（同 gk_json_utils.write_json_file 语义）。
本模块**不写 state**（零落盘派生量：配额来源见 Task 6 的 diff 判据）。
"""
import json
import os
import subprocess
import tempfile

import gk_host_paths as _host_paths

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class EditDenied(Exception):
    """edit 被拒（fail-loud）。"""


def _cli_gate_ok(subcmd: str, path: str, extra: tuple = ()) -> tuple:
    """跑 CLI 门禁（guard-edit / pre-tool-check）；返回 (ok, detail)。

    单一事实源：保护区与 stage 守卫**不在本模块重实现**，一律委托既有 CLI 判据。

    `extra`：`pre-tool-check` 的真实调用形态是 `pre-tool-check <tool> <path>`（hook Gate 4
    同款）。**2026-09-23 实测（`ECC-ABD2BF0E5655` 重定因）**：原实现只传 `<path>` ⟹ `$1` 被
    当工具名、`$2` 未绑定 ⟹ **edit 专属分支根本不匹配**，该次「stage 守卫」实际**空转**
    （门禁比自述更弱）。故须补工具名 —— 但补上后 edit 分支会**同时**触发 Gate 4 的
    `edit_budget` 扣减，见 `apply_edit` ③ 的 `GK_BUDGET_OVERRIDE=1` 说明。
    """
    env = dict(os.environ)
    env["SKILL_DIR"] = SKILL_DIR
    # **2026-09-23（`ECC-ABD2BF0E5655` 修复）**：`GK_BUDGET_OVERRIDE=1` —— 它在 `pre_tool_check`
    #   里**只**跳过 `edit_budget` 的扣减与耗尽阻断（stage 守卫照常执行）⟹ 精确表达「本调用是
    #   **门禁探测**，不是一次用户编辑」。**负载实测**：接线 `<tool> <path>` 后，若不带本变量，
    #   coder 每落一刀都会把主 agent 的节点 `edit_budget` 扣 1（沙箱实测 `remaining 4→3`）
    #   —— 而 coder 的量早已由**族 `edit_quota`（闸④）+ worktree diff 派生量（`agent_used`）**
    #   独立封顶 ⟹ 对节点配额再计一次是**重复计费**，且会饿死主 agent（第三族并发实测：
    #   节点配额被吃光后主 agent 所有 Edit/Write 被 BLOCK）。
    env["GK_BUDGET_OVERRIDE"] = "1"
    # **2026-09-26（`ECC-6C0742C3BC90` 复现实证）**：argv 形态亦走**单一事实源**
    #   `gk_host_paths.bash_script_argv`。原实现自建 `["bash", os.path.join(SKILL_DIR,
    #   "gatekeeper-cli.sh"), …]` ⟹ Windows py311 宿主（subagent 默认环境）下脚本路径是
    #   `C:\…` 形态，被 `bash.exe`（WSL 启动器）吞掉反斜杠 ⟹
    #   `/bin/bash: C:UsersHP…gatekeeper-cli.sh: No such file or directory`、**rc=127**
    #   ⟹ 闸① `guard-edit` **恒拒**（coder 唯一落刀闸静默失效），而工具层
    #   `subagent_runner._bash_script_argv` 同路径却正常 ⟹ 「**第二份实现漏转换**」。
    argv = _host_paths.bash_script_argv(
        os.path.join(SKILL_DIR, "gatekeeper-cli.sh"), subcmd, *extra, path)
    p = subprocess.run(argv, capture_output=True, text=True, env=env)
    if p.returncode == 0:
        return True, ""
    msg = (p.stdout or p.stderr or "").strip()
    if not msg:
        # 空输出 + 非零退出 = **无诊断可用**（原实现直接回空串 ⟹ `detail` 空，操作者只能手工对照
        # 才发现真因 = 流程摩擦源）。fail-loud：交出可判别的三要素（rc / argv 形态 / 宿主形态）。
        msg = ("CLI 无输出即失败 rc=%d —— 疑 CLI 未启动或宿主路径形态错配；"
               "argv[0]=%r argv[1]=%r host_form=%s"
               % (p.returncode, argv[0], argv[1], "win" if os.name == "nt" else "posix"))
    return False, msg[:300]


def _within(path: str, prefixes) -> bool:
    return any(path == p or path.startswith(p) for p in (prefixes or []))


def apply_edit(worktree: str, rel_path: str, old_str: str, new_str: str,
               family: dict, used: int, allowed: int) -> dict:
    """四道闸 → 原子替换。返回 {"ok", "blocked_by"?, "detail"?}。
ECC-32C6F93A9FFB：old_str 为空且目标**不存在** = 建新文件（仍过闸 ⓪-④：路径逃逸/
guard-edit/allowed_paths/pre-tool-check/配额）；空串对**已存在**文件显式拒绝
（空串对任何内容恒命中，防误前插）。"""
    # ⓪ worktree 必须真实存在（**先于**路径预检）—— 2026-09-23（**ECC-D398E70B7E72 修复**）：
    #   原实现对空/不存在 worktree 走 `os.path.realpath("")` = **cwd 静默兜底** ⟹ 落刀打到
    #   调用方 cwd（实测 = **主树**），且**任何闸都不拦**（target 仍落在 `wt_abs` 前缀内）。
    #   产空 worktree 的来源 = 派发链 `--dry-run`（它在建 worktree **之前** compile 窄任务）。
    if not worktree or not os.path.isdir(worktree):
        # ECC-128772BC3F1D：本支无 target ⟹ 无重定向可判，`redirected` 恒 False、
        #   `resolved` 退回 worktree 自身的 realpath（**仅诊断字段**，不影响拦阻判据）。
        return {"ok": False, "blocked_by": "no_worktree",
                "detail": "worktree 为空或不是目录（%r）—— 禁 cwd 兜底" % (worktree,),
                "resolved": os.path.realpath(worktree) if worktree else "",
                "redirected": False}
    # ⓪′ 路径逃逸预检（先于任何闸，防止门禁自身被路径形态绕过）
    wt_abs = os.path.realpath(worktree)
    target = os.path.realpath(os.path.join(wt_abs, rel_path))
    # ⓪″ 诊断锚（ECC-128772BC3F1D）——**只加可观测字段，不动任何放行/拦阻判据**：
    #   本函数先 `realpath` 再调 `guard-edit` ⟹ guard 看到的已是解析后真实路径 ⟹
    #   它**永不**报 `JUNCTION_REDIRECT`；coder 只剩 `old_str_not_found`（detail 仅相对
    #   `norm`）⟹ **junction 真因不可辨**（回 `old_str_not_found` 与「文件真的没有该片段」
    #   不可区分）。故此处前置算出 `raw`（**未解析**请求路径）与 `resolved`（真实落点），
    #   `raw != resolved` ⟺ 该请求路径经 junction/软链重定向，并把二者随每个 return 回给调用方。
    raw = os.path.normpath(os.path.join(wt_abs, rel_path))
    diag = {"resolved": target, "redirected": (raw != target)}
    if not target.startswith(wt_abs + os.sep):
        return {"ok": False, "blocked_by": "path_escape", "detail": rel_path, **diag}
    norm = os.path.relpath(target, wt_abs)
    # ① 保护区（走既有 CLI guard-edit，单一事实源）
    ok, det = _cli_gate_ok("guard-edit", target)
    if not ok:
        return {"ok": False, "blocked_by": "guard-edit", "detail": det, **diag}
    # ② 窄任务白名单（forbidden 先于 allowed 判：禁改优先）
    if _within(norm, family.get("forbidden_paths")):
        return {"ok": False, "blocked_by": "forbidden_paths", "detail": norm, **diag}
    if not _within(norm, family.get("allowed_paths")):
        return {"ok": False, "blocked_by": "allowed_paths", "detail": norm, **diag}
    # ③ stage 守卫（补 `<tool> <path>` 真形态；见 `_cli_gate_ok` 实测注）
    ok, det = _cli_gate_ok("pre-tool-check", target, ("edit",))
    if not ok:
        return {"ok": False, "blocked_by": "pre-tool-check", "detail": det, **diag}
    # ④ 配额
    if used >= allowed:
        return {"ok": False, "blocked_by": "edit_quota",
                "detail": "used=%d allowed=%d" % (used, allowed), **diag}
    # 原子替换（ECC-32C6F93A9FFB：补建新文件语义 —— old_str 为空且目标不存在 = create；
    # 空串对已存在文件恒命中 ⟹ 显式拒绝防误前插。闸 ⓪-④ 对 create 全部先于本段生效。）
    if old_str == "" and not os.path.exists(target):
        new_content = new_str
    else:
        try:
            with open(target, encoding="utf-8") as f:
                cur = f.read()
        except OSError as e:
            return {"ok": False, "blocked_by": "read_failed", "detail": str(e), **diag}
        if old_str == "":
            return {"ok": False, "blocked_by": "old_str_empty_existing",
                    "detail": "old_str 为空但目标已存在（空串恒命中，禁误前插）—— ECC-32C6F93A9FFB",
                    **diag}
        if old_str not in cur:
            # ECC-128772BC3F1D：detail 补 `size`（目标实际体量）—— 助判「读到的是**另一份副本**」
            #   （junction 重定向后真实落点与请求路径是两份文件）而**非**「片段真的不存在」。
            #   `blocked_by` 取值与闸序**逐字不变**（既有臂 `test_old_str_not_found_fails_loud`
            #   只断言 ok/allowed ⟹ 扩 detail 与加 diag 均不破它）。
            return {"ok": False, "blocked_by": "old_str_not_found",
                    "detail": "%s (size=%d)" % (norm, len(cur)), **diag}
        new_content = cur.replace(old_str, new_str, 1)
    d = os.path.dirname(target)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".gk_edit_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(new_content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
    except Exception as e:  # noqa: BLE001
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return {"ok": False, "blocked_by": "write_failed", "detail": str(e), **diag}
    return {"ok": True, **diag}


# ─── T6：per-agent 配额（口径乙 + 零落盘派生量）───────────────────────────
LINES_PER_EDIT = 40     # 配额单位换算：1 刀 ≡ 40 变更行（设计 §4 派生量口径）
AGENTS_CAP = 8          # edit_budget.agents[] FIFO 上限（设计 §4）


def agent_used(worktree: str, base_commit: str) -> int:
    """该 agent 已消耗的变更行数 = worktree 相对分叉点的 tracked diff 行数（现算，零落盘）。

    单位换算：`allowed_lines = allowed_edits × LINES_PER_EDIT`。
    以 git 工作树本身当计数器 ⟹ **不新增 state 写入者** ⟹ Ember 快照零增长、无需翻倍任何 cap。
    """
    p = subprocess.run(["git", "-C", worktree, "diff", "--numstat", base_commit],
                       capture_output=True, text=True)
    if p.returncode != 0:
        raise EditDenied("git diff 失败: " + (p.stderr or "").strip()[:200])
    total = 0
    for ln in p.stdout.splitlines():
        cols = ln.split("\t")
        if len(cols) >= 3 and cols[0].isdigit():
            total += int(cols[0]) + int(cols[1])
    return total


def _state_patch(fragment: str) -> dict:
    """经 CLI `state-patch` 写入（唯一可行的人工 patch 通道；自动记 `overrides` 留痕）。

    2026-09-26（`ECC-6C0742C3BC90` **同一根因的第二处站点** —— 由单源守护臂
    `test_host_paths_is_single_source_for_edit_gate` 揪出）：原为自建
    `["bash", os.path.join(SKILL_DIR, "gatekeeper-cli.sh"), …]` ⟹ Windows py311 宿主下脚本路径
    是 `C:\\…` 形态、被 WSL 启动器吞掉反斜杠（rc≠0）⟹ 本通道**静默失败**（空 stdout 被
    `json.loads(p.stdout or "{}")` 当空 dict）。现走 `gk_host_paths.bash_script_argv`（单一事实源），
    且「空输出 + 非零退出」改为 fail-loud 诊断（不再回空 dict）。
    """
    p = subprocess.run(
        _host_paths.bash_script_argv(os.path.join(SKILL_DIR, "gatekeeper-cli.sh"),
                                     "state-patch", fragment),
        capture_output=True, text=True, env={**os.environ, "SKILL_DIR": SKILL_DIR})
    out = (p.stdout or "").strip()
    if not out and p.returncode != 0:
        return {"ok": False, "rc": p.returncode,
                "raw": (p.stderr or "").strip()[:200] or ("CLI 无输出即失败 rc=%d" % p.returncode)}
    try:
        return json.loads(out or "{}")
    except ValueError:
        return {"ok": False, "raw": out[:200]}


def record_agent_finish(agent_id: str, worktree: str, allowed: int, used: int,
                        status: str) -> dict:
    """终态留痕：`edit_budget.agents[]` 追加**一行**（FIFO cap=`AGENTS_CAP`）；无 per-edit 明细。

    ⚠ `state-patch` 对 `gate_data` 顶层键是**整体替换** ⟹ 生产路径下须读-改-写（追加），
    负臂 `test_record_agent_finish_appends_not_replaces` 钉住该语义。
    """
    row = {"agent_id": agent_id, "worktree": worktree, "allowed": allowed,
           "used": used, "status": status}
    frag = '"edit_budget.agents":%s' % json.dumps([row], ensure_ascii=False)
    return _state_patch(frag)


# ─── ledger 缝（Plan-3「额度银行」预留；零语义变更）─────────────────────
# 本金来源 / 计价单位 / 记账落点三件事全部经此缝；银行实现（Plan-3）只替换 _LEDGER，
# 调用方（edit_gk / apply-worktree --code-fix）不感知。
# 当前实现 = 直读节点作业池（口径乙：节点 max 与 agent 池分离、随节点重置）。
# Plan-3 待裁定前置：本金单位（刀/行）、跨节点边界、利息方向与上限。
class _StateLedger:
    name = "state"

    def allowed(self, family: dict, finding: dict, declared: int = 0) -> int:
        """该 finding 的配额：**声明式批额度优先**，缺省退回族 `edit_quota`。

        REV-3（owner 2026-09-28 裁定 A）：`declared` 由调用方（`subagent_runner.edit_gk`，
        经 env `GK_EDIT_BUDGET_DECLARED`）**注入** —— 本模块不写 state、不调 CLI
        （保 §3 T1″ 自举：declared 读取路径不得经 `gatekeeper-cli.sh`）。
        """
        if int(declared or 0) > 0:
            return int(declared)
        return int(family.get("edit_quota") or 0)

    def used(self, worktree: str, base_commit: str) -> int:
        """已消耗（当前 = tracked diff 行数，现算零落盘）。"""
        return agent_used(worktree, base_commit)

    def finish(self, agent_id: str, worktree: str, allowed: int, used: int,
               status: str) -> dict:
        """终态记账（当前 = state 一行；银行实现可改记独立账本文件）。"""
        return record_agent_finish(agent_id, worktree, allowed, used, status)


_LEDGER = _StateLedger()   # Plan-3: 仅替换此行 → _BankLedger()

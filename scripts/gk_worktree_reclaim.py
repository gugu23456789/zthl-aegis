"""worktree 回收链：**归档前置 + 回收**（finding `ECC-35AC08DA96F0`）。

动机（2026-09-24 实测，非推测）：本仓 worktree **创建侧已自动化**（`apply-worktree` →
git-workflow `worktree create`），但**回收侧无调用点**（`git-workflow worktree cleanup`
从未接入）+ `git worktree prune` 被判「删除动作须用户裁定」⟹ **只产不消**（实测 15 个堆积，
最老 2026-09-04）。更危险的是**无归档前置**：未提交内容会随目录静默消失 —— 本轮实证：
`standing/mimo-v26-output-probe` 的 subplan 更新 + `m1_ladder.jsonl`、
`standing/xenv-form-fix` 的 9 项，均已**脱离任何分支**（git 注册失效后 `status` 还静默
返回空 ⟹ **假 0**，差点漏掉）。

**本模块的三条硬约束**：
1. **归档前置不可跳过**：某 worktree 有未提交内容且**归档失败** ⟹ **拒删**（fail-loud）；
2. **git 注册失效 ≠ 干净**：`rev-parse` 失败时**不得**信 `status` 的空输出（假 0），
   必须走**文件级 diff** 兜底（实测 `standing/mimo-v26-output-probe` 即此形态）；
3. **默认 dry-run**：`--apply` 才落刀（对齐本仓 `audit --apply` 惯例）。

**不做**：不重复实现孤儿判定（那在 `gk_git_workflow_check.check_worktree_status`，audit 面只读
检测）；本模块只做「**归档 + 回收**」这一段可写动作。
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timezone

# 噪声过滤：环境缓存（gitignore 覆盖得了 git，覆盖不了文件级 diff）
_NOISE = ("pyc", "__pycache__", "ruff_cache", "pytest_cache", "gitnexus", ".gatekeeper.state",
          ".gatekeeper.context", ".gatekeeper.hook.log", ".gatekeeper.scopes", ".gatekeeper.ask-hold",
          ".gatekeeper.no-ask", ".gatekeeper.hslsn", ".gatekeeper.ember", ".gatekeeper.plan")

# WSL 形态盘符路径（`/mnt/<d>/…`）—— `_sh_exists` 宿主感知存在性判据用（见 dangling_extras）。
_MNT_RE = re.compile(r"^/mnt/([a-zA-Z])/(.*)$")


def _is_noise(path: str) -> bool:
    return any(n in path for n in _NOISE)


def _git(repo: str, *args: str):
    """返回 `(rc, stdout, stderr)` —— 调用方统一解包（**不**返回 `CompletedProcess`，防误用）。"""
    p = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def list_worktrees(repo: str) -> list:
    """`git worktree list --porcelain` → `[{path, branch, alive}]`（alive=注册是否可用）。

    解析口径与 `gk_git_workflow_check.check_worktree_status` 保持一致（`branch ` 行给的是
    **全 ref**，须剥 `refs/heads/`）—— **不另立第二套解析**。

    ── 现状 / 缺口登记（2026-09-26）+ **RC6 落点**（`ECC-35AC08DA96F0`/`ECC-D03CE3E6CBC9`）
    · 本函数 = **worktree 候选集的全部来源**：`git worktree list` ⟹ **只覆盖 git 注册面**。
    · **缺口（实测三处）**：
      ① **未登记空壳目录**不在候选集 —— 如技能仓 worktree 根下 `agent/<family>` 空目录（既非有效
         worktree 亦无内容；用户 2026-09-26 授权手工清理 7 个，但**无人守**，会再生）；
      ② **非 worktree 残留**不在任何面 —— `dryrun/crossfull-*.state`（`audit --crossfull --isolate`
         的独立 state，实测 4 组 `.state`+`.lock`，2026-09-13×3 + 09-25×1）从未被回收；
      ③ `_NOISE` 把 `.gatekeeper.state*` 一律当噪声 ⟹ 连「未回收内容」都不报（见 `worktree_state`）。
    · **已修（RC6，2026-09-26）**：① ② 由 `scan_residue()` 收口 —— 本函数仍只管 **git 注册面**
      （权威视图，勿在此追加目录猜测），**目录层**残留改由 `reclaim` 末尾的 residue 段枚举
      （dry-run 只报，`--apply` 才清；孤儿 state 先归档再删）。③ 仍**未修**（`.gatekeeper.state*`
      在 worktree 内一律当噪声 ⟹ **worktree 内**的 state 残留仍不报；本切片只覆盖 root 下的孤儿
      state，不含工作树内的）。
    · 锚：`ECC-D03CE3E6CBC9`（空壳残留）/ `ECC-35AC08DA96F0`（回收链未闭合）/ `ECC-092235960526`；
      正本方案 §4.13.30 二（洞 7）+ 四（序①）；红先臂 `test_gk_worktree_reclaim.py::test_rc6_*`。
    """
    rc, out, _ = _git(repo, "worktree", "list", "--porcelain")
    if rc != 0:
        return []
    items, cur = [], {}
    for ln in out.splitlines():
        if ln.startswith("worktree "):
            if cur:
                items.append(cur)
            cur = {"path": ln[len("worktree "):], "branch": ""}
        elif ln.startswith("branch ") and cur:
            br = ln[len("branch "):]
            cur["branch"] = br[len("refs/heads/"):] if br.startswith("refs/heads/") else br
    if cur:
        items.append(cur)
    for it in items:
        # 注册存活判据：`rev-parse HEAD` 能过 ⟹ git 可用（失效注册会静默返回空 status）
        it["alive"] = _git(it["path"], "rev-parse", "HEAD")[0] == 0
    return items


def _files_equal(x: str, y: str) -> bool:
    """两文件内容相等（大小先短路；读失败 ⟹ 视为**不等**，倾向报「有差异」而非静默）。"""
    try:
        if os.path.getsize(x) != os.path.getsize(y):
            return False
        with open(x, "rb") as fx, open(y, "rb") as fy:
            return fx.read() == fy.read()
    except OSError:
        return False


def _diff_budget_s() -> float:
    """失效注册 diff 的**墙钟预算**（秒）；`GK_RECLAIM_DIFF_TIMEOUT=0` ⟹ 无预算（旧语义）。

    2026-11-03 实测（`gk-bare-guard`，git 注册已失效）：与主树逐字节比对 **1810** 个共有文件
    （79 MB，WSL `/mnt/c`）耗时 **70 s/棵** ⟹ 4 棵残留即把 `apply-worktree --reclaim` 的
    dry-run 顶过 2 min 超时。预算默认 45 s：超时**不猜**，交调用方 `truncated` ⟹ 拒删。
    """
    try:
        return max(float(os.environ.get("GK_RECLAIM_DIFF_TIMEOUT", "45") or 45), 0.0)
    except (TypeError, ValueError):
        return 45.0


def _dir_diff_rq_bounded(a: str, b: str, deadline: float = None) -> tuple:
    """`_dir_diff_rq` 的**有界**实现 → `(lines, truncated)`（判据不变，只加边界）。

    三条提速/兜底（**都不放宽判据**）：
      ① **目录剪枝**：名字命中 `_is_noise` 的目录不下钻 —— 其输出行本就会被 `worktree_state`
         的 `_is_noise` 过滤 ⟹ 结果**逐字等价**（缓存/state 目录实测占大头）；
      ② **并行比对**：文件内容比对是 I/O 延迟主导（drvfs 单文件 ~38 ms），线程池并发后
         结果**排序**再返回 ⟹ 输出顺序与串行实现一致；
      ③ **墙钟预算**：`deadline` 到点即停，返回 `truncated=True`；**不**把「没比完」当「没差异」。
    """
    def _names(d):
        try:
            return sorted(os.listdir(d))
        except OSError:
            return []

    only, pairs = [], []
    stack = [(a, b)]
    truncated = False
    while stack:
        if deadline is not None and time.monotonic() > deadline:
            truncated = True
            break
        x, y = stack.pop()
        na, nb = _names(x), _names(y)
        sa, sb = set(na), set(nb)
        for n in nb:
            if n not in sa:
                only.append("Only in %s: %s" % (y, n))
        for n in na:
            if n not in sb:
                only.append("Only in %s: %s" % (x, n))
        for n in na:
            if n == ".git" or n not in sb:
                continue
            px, py = os.path.join(x, n), os.path.join(y, n)
            if os.path.isdir(px) and os.path.isdir(py):
                if _is_noise(n):
                    continue          # ①：与输出侧过滤同判据 ⟹ 剪枝不改变结果
                stack.append((px, py))
            elif os.path.isfile(px) and os.path.isfile(py):
                pairs.append((px, py))

    differ = []
    if pairs and not truncated:
        left = None if deadline is None else deadline - time.monotonic()
        if left is not None and left <= 0:
            truncated = True
        else:
            pool = ThreadPoolExecutor(max_workers=min(8, max(1, len(pairs))))
            try:
                futs = [pool.submit(_files_equal, px, py) for px, py in pairs]
                for fu, (px, py) in zip(futs, pairs):
                    if deadline is not None and time.monotonic() > deadline:
                        truncated = True
                        break
                    try:
                        same = fu.result(timeout=max(deadline - time.monotonic(), 0.001)
                                         if deadline is not None else None)
                    except FuturesTimeout:
                        truncated = True
                        break
                    if not same:
                        differ.append("Files %s and %s differ" % (px, py))
            finally:
                pool.shutdown(wait=False)
    return sorted(only + differ), truncated


def _dir_diff_rq(a: str, b: str) -> list:
    """`diff -rq a b` 的**可移植**等价（输出**同形**行，供 `_copy_entry` 解析）。

    [ECC-8B68A4DF6D68] 原式直接调外部 `diff` 二进制 —— **Windows 宿主无此命令** ⟹
    `FileNotFoundError` ⟹ 「失效 git 注册走 diff 兜底」在 Windows 上**直接崩**（而非兜底）⟹
    未回收内容被静默漏掉（正是本模块要防的病）。自实现（零外部依赖）：
      · 单侧存在的条目 ⟹ `Only in <父目录>: <名字>`（与 GNU `diff -rq` 同形）；
      · 双侧存在但内容不同 ⟹ `Files <a> and <b> differ`；
      · 两侧同为目录 ⟹ 递归（跳过 `.git`：其内部条目在 `worktree_state` 的**顶层**口径下本就被丢，
        且两侧 `.git` 形态不同时 GNU 只报一行「is a directory」，不进 `entries`）。
    2026-11-03：实现下沉到 `_dir_diff_rq_bounded`（剪枝 + 并行 + 预算）；本函数保留无预算语义。
    """
    return _dir_diff_rq_bounded(a, b, None)[0]


def worktree_state(wt: str, main_repo: str) -> dict:
    """单个 worktree 的未回收内容。**失效注册走 diff 兜底**（否则假 0）。

    `alive=False` ⟹ `git status` 恒空（stderr 被吞）⟹ 必须用 `diff -rq` 找
    「只在 wt 的文件」与「内容不同的文件」；噪声（缓存/state）一律滤掉。
    """
    st = {"path": wt, "exists": bool(wt) and os.path.isdir(wt), "entries": [], "noise_only": False}
    if not st["exists"]:
        st["note"] = "目录不存在"
        return st
    if _git(wt, "rev-parse", "HEAD")[0] == 0:
        rc, out, _ = _git(wt, "status", "--short")
        if rc == 0:
            st["entries"] = [l for l in out.splitlines() if not _is_noise(l)]
            st["noise_only"] = (not st["entries"]) and bool(out.strip())
            return st
    # ── 兜底：文件级 diff（git 注册失效，或 status 不可用） ──
    # [ECC-8B68A4DF6D68] 自实现（`_dir_diff_rq`）取代外部 `diff -rq` —— 后者在 Windows 宿主不存在
    #   ⟹ FileNotFoundError 直接崩（不是兜底）。输出行格式**逐字对齐** GNU `diff -rq` ⟹ 下方解析不变。
    # 2026-11-03：改走**有界**实现（剪枝 + 并行 + 墙钟预算）。预算到点 ⟹ `truncated=True`，
    #   此时 entries **不完整**，调用方必须拒删（`reclaim` / `_is_merged_clean` 均已 gate）。
    budget = _diff_budget_s()
    deadline = (time.monotonic() + budget) if budget > 0 else None
    lines, truncated = _dir_diff_rq_bounded(main_repo, wt, deadline)
    only_wt, differ = [], []
    for ln in lines:
        if _is_noise(ln):
            continue
        if ln.startswith("Only in " + wt + ":") or ln.startswith("Only in " + wt + os.sep):
            only_wt.append(ln)
        elif ln.startswith("Files ") and ln.endswith(" differ"):
            differ.append(ln)
    st["entries"] = only_wt + differ
    st["fallback"] = "diff"
    if truncated:
        st["truncated"] = True
    return st


def _copy_entry(main_repo: str, wt: str, entry: str, dest: str) -> bool:
    """把条目对应的 wt 侧文件复制进归档目录。返回是否成功。

    **两种条目形态都要支持**（各自来源不同，格式不同）：
      ① `git status --short`（`XY <rel>`，rel 相对 repo 根）—— git 存活路径产物；
      ② `diff -rq`（`Only in <wt>…` / `Files A and B differ`）—— 失效注册的兜底产物。
    只支持 ② 会让 ① 路径（git 存活的常态）归档**恒失败** ⟹ 全线 HELD（正是本模块要防的
    「静默丢工作」反向）。
    """
    cand = ""
    if entry.startswith("Only in ") or entry.startswith("Files "):
        if entry.startswith("Files ") and entry.endswith(" differ"):
            mid = entry[len("Files "):-len(" differ")]
            for part in mid.split(" and "):
                if part.strip().startswith(wt):
                    cand = part.strip()
        else:
            # `diff -rq` **目录**形态 = `Only in <dir>: <name>`（分隔符是**冒号**，不是 `/`）
            # —— 2026-09-24 红先臂实测：原式找 `wt + os.sep` 恒不命中 ⟹ `entries` 恒空，
            #   失效注册的未回收内容被**静默漏掉**（正是本模块要防的那个病）。
            i = entry.find(wt + ":")
            if i >= 0:
                cand = os.path.join(wt, entry[i + len(wt) + 1:].strip())
            else:
                j = entry.find(wt + os.sep)
                cand = entry[j:].strip() if j >= 0 else ""
    else:
        rel = entry[3:].strip()              # `XY <rel>`
        if " -> " in rel:                    # 重命名条目：取新名
            rel = rel.split(" -> ", 1)[1].strip()
        cand = os.path.join(wt, rel)
    if not cand:
        return False          # 路径**未解析出来** = 真失败（格式未识别，须 fail-loud）
    if not os.path.isfile(cand):
        # 路径解析成功但文件不在 ⟹ ` D` 类**删除**条目：**无内容可丢** ⟹ 不算失败。
        # 2026-09-24 `--apply` 实测：`xenv-form-fix` / `moa-chain` 因这类条目被误判「归档失败」
        # ⟹ 整棵 worktree 被拒删、`ok` 恒 false（fail-loud 过度触发）。
        return True
    rel = os.path.relpath(cand, wt)
    dst = os.path.join(dest, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(cand, dst)
    return True


# ══════════ /tmp 回收（共享区，**只清本仓可归因**的残留）══════════
# 2026-09-24 用户裁定「3 是不是更好」= 做成 CLI 通道（胜过手工 `mv`/`rm`：能过门禁、
#   能加红先臂、能复用本模块已有骨架、且从此对「谁清、清什么、怎么清」有确定答案）。
# **边界（下面这套判据存在的全部理由）**：`/tmp` 是**全局共享**区，别的工具与项目也在用
#   ⟹ 本仓**无权**大扫除。故判据是**双条件，缺一不可**：
#     ① **可归因**：名字命中本仓产物**命名约定**（`gk-` / `gk_` 起头）或**实测例外**短表；
#     ② **超龄**：mtime 早于 `days` 天。
#   只按前缀 ⟹ 会误删**正在跑**的（`gk-tamper-*` 正是并发测试的活目录）；
#   只按龄期 ⟹ 会删**别人的**东西。**在用白名单**（`TMP_NEVER`）优先级最高，永不进报告。
# 实测背景（2026-09-24）：`/tmp` **非 tmpfs**（在 `/dev/sdd` ext4 上）⟹ 重启不清、
#   全 worktree 共享 ⟹ 堆积 9013 条目 / 1.4G，其中 **8008 个超 30 天**；`gk-tamper-*`
#   **58 个**（`test_gk_tamper_detect.py` 的 `teardown_class` 只在**正常结束**时清 ⟹ 残留
#   来自**异常中断**，非设计泄漏）。
# 纪律与 worktree 回收**完全一致**：默认 dry-run · **归档前置** · 归档不完整即**拒删**。
# 2026-09-24（finding `ECC-070771766647`）**改判据形态**：初版是 11 项**手列清单**，实测
#   **漏掉本仓自己的** `gk_worker_*`（CLI `mktemp /tmp/gk_worker_XXXXXX.pid`）、`gk_commit_*`
#   （commit 消息临时文件）、`gk_subagent_dbg.log`、`gk_r03_*` —— 手列清单本身成了「覆盖面
#   的天花板」，漏一项就永远扫不到。本仓产物的**命名约定是一律 `gk` 起头**（`gk-` / `gk_`）
#   ⟹ 归因判据改为**前缀规则**，手列只留「不满足约定但**实测**属本仓」的少数例外。
TMP_OWN_RULE = ("gk-", "gk_")
TMP_OWN_PREFIXES = ("gkfat_", "_rotate_test_", "_adj_err_")
# **刻意不收**（共享区里「不可归因」的名字 —— 宁漏不误删；理由写下来，免得下次被当漏网再「补」）：
#   · `ci_logs`：本仓 `ci-diagnose fetch` 写 `/tmp/ci_logs/<run_id>`，但名字**太泛**
#     （任何 CI 工具都可能用同名目录）⟹ 在共享区**无法归因**；
#   · `plan_backup`：只出现在已废弃的 `SKILL.md.bak`；
#   · `wt` / `x` / `r` / `a.txt` / `img` / `evil`：文档与测试夹具里的**举例**路径，非真实产物。
TMP_NEVER = ("gk-redfirst-cache", "gk-gitnexus-identity", "gk-gx-memo", "gk-mirror")


def scan_tmp(tmp_dir: str = "/tmp", days: int = 7) -> list:
    """枚举**本仓可归因**且**超龄**的 `/tmp` 残留，按体积降序。"""
    import time
    out = []
    now = time.time()
    try:
        names = os.listdir(tmp_dir)
    except OSError:
        return out
    for n in names:
        if any(n == x or n.startswith(x) for x in TMP_NEVER):
            continue                                  # 在用白名单：最高优先
        if not (n.startswith(TMP_OWN_RULE)
                or any(n == p or n.startswith(p) for p in TMP_OWN_PREFIXES)):
            continue                                  # 非本仓可归因 ⟹ 不碰（共享区纪律）
        p = os.path.join(tmp_dir, n)
        try:
            age = (now - os.path.getmtime(p)) / 86400.0
        except OSError:
            continue
        if age < days:
            continue                                  # 未超龄 ⟹ 可能是活目录
        size = 0
        if os.path.isfile(p):
            size = os.path.getsize(p)
        else:
            for d, _s, fs in os.walk(p):
                for f in fs:
                    try:
                        size += os.path.getsize(os.path.join(d, f))
                    except OSError:
                        pass
        out.append({"name": n, "path": p, "age_days": round(age, 1), "size": size,
                    "kind": "file" if os.path.isfile(p) else "dir"})
    return sorted(out, key=lambda x: -x["size"])


def reclaim_tmp(tmp_dir: str = "/tmp", days: int = 7, apply: bool = False,
                trash: str = "") -> dict:
    """`/tmp` 回收链：**先归档 → 归档确认 → 才删**。默认 dry-run。

    **先 copy 后删**（不用 `shutil.move`）：跨设备时 `move` 会先删源，中途失败即**丢数据**；
    分两步则失败停在「已复制」⟹ 可重试、可回溯。
    """
    items = scan_tmp(tmp_dir, days)
    report = {"ok": True, "dry_run": not apply, "days": days, "total": len(items),
              "freed_bytes": 0, "items": items, "archived": [], "held": [], "removed": []}
    if not apply:
        for it in items:
            it["action"] = "WOULD-ARCHIVE-THEN-REMOVE"
        report["freed_bytes"] = sum(i["size"] for i in items)
        return report
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    # ⚠ **归档落点绝不能在 `/tmp` 内**（2026-09-24 `--apply` 实测踩坑，dry-run **查不出**）：
    #   首版默认 `tmp_dir/.gk-tmp-trash` ⟹ 「copy 到 trash + 删源」后 `/tmp` 总占用
    #   **纹丝不动**（实测 1334 MB → 1334 MB）⟹ 用户要的「腾空间」**完全没达成**，而且
    #   还多了一层目录。默认改到 `~/.gk-tmp-trash`（**同设备** ⟹ 复制快；**不在 /tmp** ⟹ 真腾出）。
    dest = os.path.join(trash or os.path.join(os.path.expanduser("~"), ".gk-tmp-trash"),
                        "tmp-%s" % ts)
    for it in items:
        p = it["path"]
        try:
            os.makedirs(dest, exist_ok=True)
            tgt = os.path.join(dest, it["name"])
            if os.path.isdir(p):
                shutil.copytree(p, tgt)
                shutil.rmtree(p)
            else:
                shutil.copy2(p, tgt)
                os.remove(p)
            it["action"] = "ARCHIVED-THEN-REMOVED"
            report["removed"].append(p)
            report["archived"].append(tgt)
            report["freed_bytes"] += it["size"]
        except OSError:
            it["action"] = "HELD"
            it["reason"] = "归档失败 ⟹ 拒删（fail-loud）"
            report["held"].append(p)
            report["ok"] = False
    return report


# ══════════ 隔离区回收（`.gk-trash`，**单向门的另一半**）══════════
# 2026-09-24（用户裁定「2」，finding `ECC-AAB70D5DCF11`）：回收区此前**只进不出** ——
#   `pre_tool_hook` 把每条递归删除改写成「搬进 `.gk-trash`」，而**没有任何清空通路**
#   （全仓无 purge 子命令；批量删除与解释器内联删除也一并被拦）⟹ 隔离区**单调增长**
#   （实测 321M），并发会话的「删除」永远无法完成 —— 它只会再增殖一层。
# 本子命令补上缺的那一半。三条纪律与 worktree / `/tmp` 两条**完全一致**，另加两条：
#   · **龄期门**（`days`）：只收 mtime 早于 `days` 天的条目 —— 回收区可能正被**并发会话**写入
#     （hook 的搬移是瞬时动作，但整批搬移可能跨秒），龄期门即并发保护；
#   · **RESTORE-MAP 自洽校验**：批次目录若含 `RESTORE-MAP.tsv`，其左列每个名字**必须**
#     在目录内存在；缺项 ⟹ 搬移**未完成**（半搬态）⟹ **拒删**（fail-loud）——
#     否则「可逆」这个承诺是假的。
# **不归档**（与另两条不同）：回收区**本身就是归档**，再归档一次只是把同一个东西挪个位置、
#   空间纹丝不动（`/tmp` 那次 `--apply` 实测的教训）。故这里只有「校验 → 删」两步。
def _dir_size(p: str) -> int:
    """目录/文件占用（字节）；不可读项按 0 计（不因个别权限问题整体失败）。"""
    if os.path.isfile(p):
        try:
            return os.path.getsize(p)
        except OSError:
            return 0
    total = 0
    for d, _s, fs in os.walk(p):
        for f in fs:
            try:
                total += os.path.getsize(os.path.join(d, f))
            except OSError:
                pass
    return total


def _restore_map_gaps(entry: str) -> list:
    """批次目录的 `RESTORE-MAP.tsv` 自洽校验：返回**缺失**的名字（空列表 = 自洽）。

    形态（实测 `spz-toolchain-20260924T093735/RESTORE-MAP.tsv`）：`<目录内名>\\t<原路径>`。
    左列名在目录内**必须存在**；否则说明搬移中途停了（源已动、目标未落）⟹ 不能当已完成品删。
    """
    mp = os.path.join(entry, "RESTORE-MAP.tsv")
    if not os.path.isdir(entry) or not os.path.isfile(mp):
        return []
    gaps = []
    try:
        with open(mp, encoding="utf-8") as fh:
            for ln in fh:
                name = ln.rstrip("\n").split("\t", 1)[0].strip()
                if name and not os.path.exists(os.path.join(entry, name)):
                    gaps.append(name)
    except OSError:
        return ["<RESTORE-MAP.tsv 不可读>"]
    return gaps


def scan_trash(trash_dir: str, days: int = 3) -> list:
    """枚举回收区中**超龄**的条目，按体积降序（附 `restore_gaps` = 自洽校验结果）。"""
    import time
    out = []
    now = time.time()
    try:
        names = sorted(os.listdir(trash_dir))
    except OSError:
        return out
    for n in names:
        p = os.path.join(trash_dir, n)
        try:
            age = (now - os.path.getmtime(p)) / 86400.0
        except OSError:
            continue
        if age < days:
            continue                                  # 未超龄 ⟹ 可能正被并发会话写入
        out.append({"name": n, "path": p, "age_days": round(age, 1), "size": _dir_size(p),
                    "kind": "file" if os.path.isfile(p) else "dir",
                    "restore_gaps": _restore_map_gaps(p)})
    return sorted(out, key=lambda x: -x["size"])


def reclaim_trash(trash_dir: str, days: int = 3, apply: bool = False) -> dict:
    """隔离区回收链（`trash` 子命令）。**默认 dry-run**（只报告），`--apply` 才落刀。"""
    items = scan_trash(trash_dir, days)
    report = {"ok": True, "dry_run": not apply, "trash": trash_dir, "days": days,
              "total": len(items), "freed_bytes": 0, "items": items,
              "purged": [], "held": []}
    for it in items:
        if it["restore_gaps"]:
            it["action"] = "HELD"
            it["reason"] = ("RESTORE-MAP 不自洽 ⟹ 搬移未完成，拒删（fail-loud）：缺 "
                            + ", ".join(it["restore_gaps"][:5]))
            report["held"].append(it["path"])
            report["ok"] = False
            continue
        it["action"] = "PURGED" if apply else "WOULD-PURGE"
        report["freed_bytes"] += it["size"]
    if not apply:
        return report
    for it in items:
        if it["action"] != "PURGED":
            continue
        p = it["path"]
        try:
            if os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p)
            else:
                os.remove(p)
            report["purged"].append(p)
        except OSError as e:  # noqa: BLE001 — 边界：删失败进 held 并 fail-loud，不吞
            it["action"] = "HELD"
            it["reason"] = "删除失败：%s" % e
            report["held"].append(p)
            report["ok"] = False
    report["freed_bytes"] = sum(it["size"] for it in items if it["action"] == "PURGED")
    return report


def _trash_dir(repo: str) -> str:
    """回收区路径。**复用** `gk_route_center.trash_dir` —— 不另抄 `dirname(dirname(…))`
    （否则就是「同一路径的第二份定义」，正是 finding `ECC-82CC385C121E` 的病灶）。"""
    sys.path.insert(0, os.path.join(repo, "scripts"))
    try:
        import gk_route_center as rc
        d = rc.trash_dir(repo)
        if d:
            return d
    except Exception:  # noqa: BLE001 — 边界：拿不到走同式兜底（保底不降级：仍在技能仓之外）
        pass
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(repo))), ".gk-trash")


def _git_workflow_entry(repo: str) -> str:
    """派生 git-workflow 入口。**复用** `gk_route_center` 的推导 —— 不另抄字面量（否则就是
    第四处「同一路径的第二份定义」，正是本模块要消的双源）。"""
    sys.path.insert(0, os.path.join(repo, "scripts"))
    try:
        import gk_route_center as rc
        return rc._git_workflow_entry(repo) or ""
    except Exception:  # noqa: BLE001 — 拿不到入口 ⟹ 走兜底（见 reclaim）
        return ""


# ══════════ 目录层残留扫描（RC6，findings `ECC-D03CE3E6CBC9` / `ECC-35AC08DA96F0`）══════════
# 动机（2026-09-26 实测）：`reclaim` 的候选集此前**只**来自 `git worktree list` ⟹ 目录层残留
#   （未登记空壳目录 / `dryrun/crossfull-*.state`）**不在任何面** —— 实测 `--reclaim` dry-run 报
#   `total:1, items:[]`（只认主树），而 worktree 根下仍有空壳目录 + 4 组孤儿 state。
# 判据**保守**（宁漏不误删；`root` 是**跨仓库共享**的 worktree parent，本仓无权在此大扫除）：
#   ① **先收窄**到自有子树 `<root>/<repo 名>`（`repo_worktree_scope`）—— 否则会把他仓目录
#      当残留（实测 `spz2glb`/`spz_gatekeeper_project`/`spz-gatekeeper-agent-worktree-consolidation`
#      三者齐被误报，`--apply` 即越权删他仓）；② 只收**两种已知形态**；③ 一律排除已登记 worktree
#      子树、回收区与 `.git`（`.gk-trash` 内容算「非空」但永不报 —— 见 `_residue_never`）。
_RESIDUE_STATE_SUFFIX = (".state", ".state.lock")
_RESIDUE_NEVER = {".gk-trash"}     # 归档区：其内容算「非空」（别让父目录看起来是空的），但**永不报**


def _residue_never(p: str) -> bool:
    """路径是否落在**永不报**的目录内（`.gk-trash`）。

    **只按路径段判，绝不做子树剪枝** —— 剪枝会让「只装归档的父目录」看起来是空的
    （2026-09-26 实测：首版剪 `.gk-trash` ⟹ `feature/`（其唯一内容 = `feature/.gk-trash/`）
    被误报为 `empty_dir`）。故：`.gk-trash` 的文件照算「内容」，只是不把它自己/其内容列进报告。
    """
    return any(seg in _RESIDUE_NEVER for seg in os.path.abspath(p).split(os.sep))


def repo_worktree_scope(root: str, main_repo: str) -> str:
    """本仓在**共享** worktree 根下的**自有**子树 `<root>/<repo 名>`（不存在 → `""`）。

    `root`（`GATEKEEPER_WORKTREE_ROOT`）= **跨仓库共享** parent（`…/.trae/worktrees/`）⟹ 目录层
    扫描**必须先收窄到自有子树**，否则会把他仓目录当残留。2026-09-26 实测（收窄前）：`spz2glb` /
    `spz_gatekeeper_project` / `spz-gatekeeper-agent-worktree-consolidation` 三者**都被误报**为
    `empty_dir` ⟹ 一旦 `--apply` 即**越权删他仓**。本仓 owner 名 = `basename(main_repo)`
    （与 `resolve_worktree` 的 `<root>/<repo>/<branch>` 布局同源）。
    """
    if not root or not os.path.isdir(root):
        return ""
    cand = os.path.join(root, os.path.basename(os.path.abspath(main_repo)))
    return cand if os.path.isdir(cand) else ""


def _dead_gitdir(wt: str) -> bool:
    """`<wt>/.git`（文件）里的 `gitdir:` 是否指向**不存在**的路径。

    True = 该树已被 `git worktree prune`（或手工删元数据）摘掉注册 —— git 三面（list /
    status / remove）都不再认识它，只剩工作目录与一个断链指针。
    """
    p = os.path.join(wt, ".git")
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            head = f.readline().strip()
    except OSError:
        return False
    if not head.startswith("gitdir:"):
        return False
    tgt = head[len("gitdir:"):].strip()
    if tgt and not os.path.isabs(tgt):
        tgt = os.path.normpath(os.path.join(wt, tgt))
    return bool(tgt) and not os.path.exists(tgt)


def _age_days(p: str) -> float:
    """目录年龄（天）—— 取目录与 `.git` 指针 mtime 的**较新者**（判「正在创建」侧）。"""
    try:
        t = os.path.getmtime(p)
        g = os.path.join(p, ".git")
        if os.path.exists(g):
            t = max(t, os.path.getmtime(g))
        return (time.time() - t) / 86400.0
    except OSError:
        return 0.0


def _route_prefixes() -> set:
    """`<root>/<repo>/<prefix>/…` 形态的 route 前缀（**单源** `gk_route_center.WORKTREE_ROUTES`）。

    2026-10-31（实测 31 个断链 worktree，root cause）：原孤儿扫描限深 1，假设布局 =
    `<root>/<repo>/<branch>`；而权威布局含两段/三段形态 —— `feature/<name>`、`standing/<name>`、
    `agent/<family>` / `agent/<family>/<sha8>` —— 全在**深度 2/3** ⟹ 元数据被 prune 后三面全盲。
    本函数只回答「第一段是不是 route 前缀」；导入失败 ⟹ 空集（fail-closed：少扫不多删）。
    """
    try:
        from gk_route_center import WORKTREE_ROUTES
    except Exception:  # noqa: BLE001 — 边界：缺模块 ⟹ 只关深度 2/3 扫描面
        return set()
    out = set()
    for _name, pat in WORKTREE_ROUTES:
        segs = [s for s in str(pat).split("/") if s]
        if len(segs) >= 3 and segs[0] == "*":
            out.add(segs[1])
    return out


def scan_residue(scope: str, known_paths, trash: str = "") -> list:
    """枚举 `scope`（**本仓自有** worktree 子树）下的目录层残留 → `[{path, kind, size}]`。

    两种已知形态（其余一律不收 —— 见上方 rationale 的「保守」）：
      · `empty_dir` —— **递归不含任何文件**的目录（未登记空壳目录；含只装空目录的父级），
        且不等于 `scope`、不在已登记子树 / 回收区 / `.git` / `.gk-trash` 内；
      · `orphan_state` —— `*.state` / `*.state.lock` 文件（如 `dryrun/crossfull-*.state`），
        且不在已登记 worktree 子树内。

    **只报主形态**：父子同为空壳时只收**最上层**那个（否则 `--apply` 会对同一棵树重复落刀）。
    """
    out = []
    if not scope or not os.path.isdir(scope):
        return out
    scope_abs = os.path.abspath(scope)
    skips = [os.path.abspath(p) for p in known_paths if p]
    if trash:
        skips.append(os.path.abspath(trash))

    def _skipped(p: str) -> bool:
        ap = os.path.abspath(p)
        return any(ap == s or ap.startswith(s + os.sep) for s in skips)

    dirs, all_files = [], []
    for dirpath, dnames, fnames in os.walk(scope_abs):
        if _skipped(dirpath):
            dnames[:] = []                       # 已登记子树 / 回收区 ⟹ 整棵不碰
            continue
        dnames[:] = [d for d in dnames if d != ".git"]
        if os.path.abspath(dirpath) != scope_abs:
            dirs.append(dirpath)
        all_files.extend(os.path.join(dirpath, f) for f in fnames)
    for p in all_files:
        if (p.endswith(_RESIDUE_STATE_SUFFIX) and not _residue_never(p)
                and os.path.isfile(p)):
            out.append({"path": p, "kind": "orphan_state", "size": os.path.getsize(p)})
    shells = [d for d in dirs if not _residue_never(d)
              and not any(f.startswith(os.path.abspath(d) + os.sep) for f in all_files)]
    shells = [d for d in shells                       # 只留最上层（父子同为空壳 ⟹ 收父）
              if not any(o != d and os.path.abspath(d).startswith(os.path.abspath(o) + os.sep)
                         for o in shells)]
    for d in shells:
        out.append({"path": d, "kind": "empty_dir", "size": 0})
    return out


# ══════════ 悬空允许集清理（RC1-S4，finding `ECC-D15C62FFF34A`）══════════
# 2026-09-27：`state.worktrees_extra[]`（活动写面允许集）只增不减 —— 目录被本模块回收后，
#   允许集里仍留着「指向不存在目录」的条目（= 永不命中的放行项，活动写面的**陈旧尾巴**）。
#   本段把它并入**同一次 reclaim**：dry-run 只报（`dangling_extras`），`--apply` 才解绑；
#   解绑走**单一写通路** `gk_state_patch.cmd_worktrees_extra`（禁第二实现）。
def _sh_exists(p) -> bool:
    """**宿主感知的存在性判据**：`/mnt/<d>/…` 形态在 Windows 宿主折成 `<D>:/…` 再判。

    [ECC-WINHOST-DANGLING] `worktrees-extra bind` 经 `gk_route_center._as_norm` 把路径**无条件**
    归一为 WSL 形态（`C:\\x` → `/mnt/c/x`，跨宿主单源，见 gk_write_claims 同族）；而 **Windows
    宿主上 `os.path.isdir("/mnt/c/…")` 恒假**（被当盘符相对路径解释）⟹ 目录**仍存在**的允许集项
    被误判「悬空」并在 `--apply` 时**解绑**（arm20b/20c：存在项被误清）。POSIX 宿主行为 no-op。
    """
    s = str(p)
    if os.path.isdir(s):
        return True
    m = _MNT_RE.match(s.replace("\\", "/"))
    if m and os.name == "nt":
        return os.path.isdir(m.group(1).upper() + ":\\" + m.group(2).replace("/", os.sep))
    return False


def dangling_extras(state_path: str) -> list:
    """`worktrees_extra[]` 中**目录已不存在**的条目（悬空允许集）。只读。"""
    if not state_path:
        return []
    try:
        with open(state_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return []
    v = data.get("worktrees_extra") if isinstance(data, dict) else None
    if not isinstance(v, list):
        return []
    return [p for p in v if isinstance(p, str) and p and not _sh_exists(p)]


def _unbind_extras(state_path: str, paths) -> tuple:
    """经**单一写通路**解绑悬空项 → `(done, failed)`（`failed` 元素含原因，供 fail-loud）。"""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import gk_state_patch as sp
    except Exception as e:  # noqa: BLE001 — 边界：拿不到写通路 ⟹ 全部 fail-loud（不静默）
        return [], ["%s（写通路不可用: %s）" % (p, e) for p in paths]
    done, failed = [], []
    for p in paths:
        r = sp.cmd_worktrees_extra(state_path, "unbind", p)
        if r.get("ok"):
            done.append(p)
        else:
            failed.append("%s（%s）" % (p, r.get("error", "?")))
    return done, failed


def _sweep_dangling_extras(state: str, report: dict, apply: bool) -> None:
    """RC1-S4 段：**只报**（dry-run）或**只解绑悬空项**（apply）。零目录写、只减不增。

    与「全量回收须显式授权」闸（`ECC-2B04C5B10464`）**正交**：该闸保护的是**删目录/归档**，
    而本段只改 state 的允许集（去掉指向不存在目录的放行项）⟹ 闸拒绝全量删档时仍须照常清理。
    `da50f56` 的提前 `return` 曾把本段一并挡掉（`test_worktrees_extra::arm20b` 存量失败）。
    """
    if not state:
        return
    report["dangling_extras"] = dangling_extras(state)
    if report["dangling_extras"] and apply:
        done, failed = _unbind_extras(state, report["dangling_extras"])
        report["unbound_extras"] = done
        for f in failed:
            report["held"].append("extras:" + f)
            report["ok"] = False


def _is_merged_clean(baseline: str, wt: str, branch: str) -> bool:
    """predicate：worktree 分支**已并入** `baseline` 的 HEAD **且** 工作树**干净**（无未回收内容）。

    仅用于「`--all` 授权下的全量回收」（finding `ECC-6056478D1353` · 摩擦③）：把「已并入且干净」
    当作**会话已终结**的确定性判据，以免旧 claim（含已过期）把已终结的 worktree 永久卡住
    （原须逐条 `--path` 枚举 = 流程摩擦）。**fail-closed**：无 branch / git 失败 / 有残留 / 未并入
    任一不满足 ⟹ False（仍走既有 claim 闸拒删）。
    """
    if not (baseline and wt and branch):
        return False
    if _git(baseline, "merge-base", "--is-ancestor", branch, "HEAD")[0] != 0:
        return False
    st = worktree_state(wt, baseline)
    # 2026-11-03：`truncated`（diff 预算到点）**不**等于「干净」—— 未比完的内容可能仍有残留
    #   ⟹ fail-closed，绝不当成可删。
    return (not st.get("entries")) and not st.get("truncated")


def _local_branches(repo: str) -> list:
    """本地分支短名（`refs/heads`）。git 失败 ⟹ 空（调用方据此零动作）。"""
    rc, out, _ = _git(repo, "for-each-ref", "--format=%(refname:short)", "refs/heads")
    return [ln.strip() for ln in out.splitlines() if ln.strip()] if rc == 0 else []


def _checked_out_branches(repo: str) -> set:
    """任一 worktree（含主树）当前检出的分支 —— 删除面必须排除（在用面 + git 亦拒删）。"""
    rc, out, _ = _git(repo, "worktree", "list", "--porcelain")
    res = set()
    if rc == 0:
        for ln in out.splitlines():
            if ln.startswith("branch refs/heads/"):
                res.add(ln[len("branch refs/heads/"):].strip())
    return res


def _patch_equivalent(baseline: str, branch: str) -> bool:
    """`git cherry` 全 `-` ⟹ 该分支**每个提交的改动**都已以等价补丁进入 baseline。

    用途（`backup/b9b-pre-rebase-*` 类）：历史因 rebase 不同源、tip 不是 HEAD 祖先，
    但内容确已入主线。空输出 = 无独有提交（本身即祖先）⟹ 同样安全。
    fail-closed：git 失败 / 有任一 `+` ⟹ False。
    """
    rc, out, _ = _git(baseline, "cherry", "HEAD", branch)
    if rc != 0:
        return False
    lines = [ln for ln in out.splitlines() if ln.strip()]
    return all(ln.startswith("-") for ln in lines)


def sweep_loose_branches(main_repo: str, baseline: str, apply: bool = False,
                         exclude=None) -> dict:
    """**游离分支**回收（不属于任何 worktree 的本地分支）。

    判据（fail-closed）：已并入 baseline HEAD（`merge-base --is-ancestor`）**或**全部提交
    patch 等价（`git cherry`）。任一不满足 ⟹ `guarded`（保留并留痕，绝不误删）。
    检出中的分支（主树 / 任一 worktree）与 `exclude`（如 `master`/`main`）永不删。
    `apply=False` = 只报告（零写）。删分支不丢提交对象（reflog/对象库仍在），故无归档步。
    """
    exclude_set = set(exclude or []) | {"master", "main"}
    checked = _checked_out_branches(main_repo)
    result = {"would_remove": [], "removed": [], "guarded": [], "checked_out": []}
    for br in _local_branches(main_repo):
        if br in exclude_set:
            result["checked_out"].append(br)
            continue
        if br in checked:
            result["checked_out"].append(br)
            continue
        merged = _git(baseline, "merge-base", "--is-ancestor", br, "HEAD")[0] == 0
        if not merged and not _patch_equivalent(baseline, br):
            result["guarded"].append(br)
            continue
        if not apply:
            result["would_remove"].append(br)
            continue
        if _git(baseline, "branch", "-D", br)[0] == 0:
            result["removed"].append(br)
        else:
            result["guarded"].append(br)
    return result


def reclaim(main_repo: str, root: str, apply: bool = False, trash: str = "",
            state: str = "", only=None, branch_reclaim: bool = False,
            all_branches: bool = False) -> dict:
    """回收链主流程：**先归档 → 归档确认 → 才删**。返回报告 dict。

    `apply=False`（默认）= dry-run：只扫描与报告，**零写操作**。
    `state` 非空时，末尾并入**悬空允许集**清理（`worktrees_extra[]`；RC1-S4）。
    `only` = **路径白名单**（2026-10-01；并发多会话现场）：非空时**只**回收其中路径，
    其余一律进 `skipped`（**不动别人正在用的 worktree**），且**跳过目录层残留清理**
    （`residue` 非路径特异，一并收窄）。**opt-in**：不传 = 原全量语义，零回归。
    """
    # finding `ECC-82CC385C121E`：落点走**单源**（`gk_route_center.trash_dir`）—— 原式
    #   `os.path.dirname(main_repo)` 随 `--repo` **漂移**：CLI 接线传的是 SKILL_DIR ⟹ 算成
    #   `.trae/skills/.gk-trash`（实测**不存在**），从 worktree 内调用又算成 `…/feature/.gk-trash`
    #   ⟹ 与 hook 的 `.trae/.gk-trash` 构成**双源**。
    trash = trash or _trash_dir(main_repo)
    only_abs = {os.path.abspath(p) for p in (only or []) if p}
    wts = list_worktrees(main_repo)
    # ⚠ **主 worktree 永不删**（2026-09-24 实测缺陷，首版即踩）：`worktree list` 的**首条**才是
    #   权威主树；**不能**拿 `--repo` 当唯一锚 —— 从 worktree 内调用时 `--repo` 就是那个
    #   worktree，而**主树不在排除集** ⟹ 首版 dry-run 把主树列为 `WOULD-REMOVE`，
    #   `--apply` 会**删掉主树**。故：① 双锚（`--repo` ∪ `list` 首条）；② 命中的显式回
    #   `skipped`（防「静默不动」被误读成「已处理」）。
    protected = {os.path.abspath(main_repo)}
    if wts:
        protected.add(os.path.abspath(wts[0]["path"]))
    # diff 兜底的**基准必须是主树**（不是 `--repo`）—— 否则从 worktree 内调用时「wt 独有内容」
    # 的判据会拿**另一个 worktree** 当参照 ⟹ 满屏差异、零判别力。
    baseline = wts[0]["path"] if wts else main_repo
    # 未注册的孤儿目录（git 已不认识，但目录还在）—— 只扫**本仓自有**子树，深度 ≤2。
    # 2026-10-23（实测挂死，单次 >180s）：原实现对**共享** worktree 根做**无界** `os.walk`
    #   （`root` = `GATEKEEPER_WORKTREE_ROOT` / `DEV_WORKTREE_ROOTS[0]` = 跨仓库共享 parent，
    #   实测含 7+ 棵 worktree × node_modules/.git）⟹ 在 /mnt/c 上 `apply-worktree --reclaim`
    #   超时，`test_gk_edit_budget_metering` 的 5 臂因此挂死（换 master CLI 同样复现
    #   ⟹ 与 CLI 版本无关）。faulthandler 栈实测停在本行 `os.walk`。
    #   修法双保险：① 用既有 `repo_worktree_scope()` 收窄到 `<root>/<repo 名>`（同「越界面」纪律，
    #   避免把他仓目录算作本仓残留）；② 显式限深 ≤2（布局 `<root>/<repo>/<branch>`），
    #   到第 2 层不再下钻。沙箱形态（`--repo` 指向临时目录、不在共享根下）⟹ scope="" ⟹
    #   **零 walk**，即刻返回。
    known = {w["path"] for w in wts}
    _scope = repo_worktree_scope(root, main_repo)
    # 2026-10-31（实测 31 个断链 worktree 静默堆积）：原限深 1 假设布局 `<root>/<repo>/<branch>`，
    #   而权威布局（单源 `gk_route_center.WORKTREE_ROUTES`）含更深形态：
    #     `feature/<name>`、`standing/<name>`（深度 2）、`agent/<family>` / `agent/<family>/<sha8>`（2/3）。
    #   `git worktree prune` 清掉元数据后，这些树既不在 `git worktree list`、又不是空壳、也不是
    #   孤儿 state ⟹ **三面全盲**（现场：19 个断链 + 1 个 499M `.orphan-moved`）。
    #   修法：仅对 **route 前缀** 放行深度 2/3，并对未注册项加**龄期门**（`GK_RECLAIM_UNREG_DAYS`，
    #   默认 7 天）—— 防把正在 `git worktree add` 的半成品当残留回收；深度 1 的既有语义**逐字不变**
    #   （零回归），非 route 前缀的深层目录仍不认领。
    _unreg_days = float(os.environ.get("GK_RECLAIM_UNREG_DAYS", "7") or 7)
    _prefixes = _route_prefixes()
    if _scope:
        for dirpath, dirs, files in os.walk(_scope):
            rel = os.path.relpath(dirpath, _scope)
            segs = [] if rel == "." else rel.split(os.sep)
            depth = len(segs)
            if depth in (1, 2, 3) and ".git" in files and dirpath not in known:
                if depth == 1:
                    # 既有面：深度 1 的未注册孤儿（原语义，龄期门不适用 —— 零回归）
                    wts.append({"path": dirpath, "branch": "", "alive": False,
                                "unregistered": True, "broken": _dead_gitdir(dirpath)})
                elif segs[0] in _prefixes and _age_days(dirpath) >= _unreg_days:
                    wts.append({"path": dirpath, "branch": "", "alive": False,
                                "unregistered": True, "broken": _dead_gitdir(dirpath),
                                "age_days": round(_age_days(dirpath), 1)})
            if depth >= 3 or (depth >= 1 and segs[0] not in _prefixes):
                dirs[:] = []                     # 深 3 封底；非 route 前缀不下钻（既有语义）
            else:
                dirs[:] = [d for d in dirs if d != ".git"]
    report = {"ok": True, "dry_run": not apply, "total": len(wts), "items": [],
              "held": [], "removed": [], "archived": [], "skipped": [], "residue": [],
              "dangling_extras": [], "unbound_extras": []}
    # ⓕ 全量回收须**显式授权**（finding `ECC-2B04C5B10464`，2026-10-06 实测）：一次未带 `--path`
    #   的 `--apply` 全量扫，在 claims 过期后把 3 个**在用**会话 worktree 一并删档。触发面 =
    #   白名单是 **opt-in**（不传 `--path` = 全量，零门槛）⟹ 现改为：`apply` 且 `only` 为空且
    #   未显式授权 ⟹ **拒绝（零写）**，并把候选全部如实列入 `skipped`（不静默）。显式授权
    #   = env `GK_RECLAIM_ALLOW_FULL=1`（CLI 侧 `--reclaim --apply --all` 置位，见 gatekeeper-cli.sh）。
    if apply and not only_abs and os.environ.get("GK_RECLAIM_ALLOW_FULL", "0") != "1":
        report["ok"] = False
        report["error"] = "FULL_SWEEP_REFUSED"
        report["total"] = len(wts)
        report["skipped"] = [w["path"] for w in wts if w.get("path")]
        report["hint"] = ("全量回收须显式授权：`apply-worktree --reclaim --apply --all`"
                          "（或 GK_RECLAIM_ALLOW_FULL=1）；或改用 `--path <dir>` 指名单个 worktree。")
        # 悬空允许集**不属于**全量删档面（见 `_sweep_dangling_extras` 注释）⟹ 拒绝时仍照常清。
        _sweep_dangling_extras(state, report, apply)
        return report
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    root_abs = os.path.abspath(root) if root else ""
    # §16 D-a/D-b①：回收链接 claims 台账（判据单源 = gk_write_claims.claims_for_worktree）。
    #   lazy import：台账依赖不可用时只**关闸**，不让 reclaim 既有调用面整体失败。
    try:
        import gk_write_claims as _wc
    except Exception:  # noqa: BLE001 — 边界
        _wc = None
    report["claim_guarded"] = []
    # T13（`ECC-FCB7E9D604F2`）：**窄面**（`--path` 显式指名）自动释放的**留痕面** —— 与
    #   `claim_guarded` **同处初始化**（两个键恒在，消费方无须 `.get` 兜底）。
    report["claim_autoreleased"] = []
    # B-2（2026-10-16，owner 裁定「回收含 worktree→分支」）：**分支回收**留痕面 —— 与 claim 键
    #   **同处初始化**（两键恒在，消费方无须 `.get` 兜底）。HEAD 无此步 ⟹ 红先必红。
    report["branch_removed"] = []
    report["branch_guarded"] = []
    # 游离分支面（`--all-branches`）：与 worktree 面**分键**留痕，消费方无须猜语义。
    report["loose_branch_would_remove"] = []
    report["loose_branch_removed"] = []
    report["loose_branch_guarded"] = []
    report["loose_branch_checked_out"] = []
    for w in wts:
        wt = w["path"]
        # 路径白名单（并发会话保护）：非指定路径 ⟹ 显式 skip（不静默、不报 held）
        if only_abs and os.path.abspath(wt) not in only_abs:
            report["skipped"].append(wt)
            continue
        if os.path.abspath(wt) in protected:
            report["skipped"].append(wt)   # 主树 / 调用方自身 ⟹ 永不回收
            continue
        # **越界面**：`git worktree list` 实测可能含**别的项目**的 worktree（本仓列表里出现过
        # `spz_gatekeeper_project/feature/spz-gatekeeper-2.0.4-r7`）⟹ 本仓**无权**回收，
        # 显式进 `skipped`（**不报 held**，否则 `ok` 恒 false 且徒增误删面）。
        if root_abs and not os.path.abspath(wt).startswith(root_abs + os.sep):
            report["skipped"].append(wt)
            continue
        # §16 D-a 回收前置闸：有 **未 release** 的 claim ⟹ 拒删（护并发会话在用的工作区）。
        #   finding `ECC-2B04C5B10464`（2026-10-06 实测）：判据原用 `claims_for_worktree`
        #   （**live-only**）⟹ 长任务超 `claim_ttl_s`（3600s）后活 claim 静默失活、闸 **fail-open**，
        #   一次未带 `--path` 的全量 `--apply` 删掉 3 个在用 worktree。现判据改
        #   **`unreleased_claims_for_worktree`（含过期）** ⟹ **过期 ≠ 可删**（fail-closed）；
        #   唯一放行 = 显式 `release`（`apply-worktree --release-claim <sid>`）或以 `--path` 指名。
        #   `GK_RECLAIM_CLAIM_GUARD=0` 应急旁路保留。
        if _wc is not None and os.environ.get("GK_RECLAIM_CLAIM_GUARD", "1") != "0":
            # §16 D-a：账本**单源** —— 传 `None` 让 `gk_write_claims._default_repo()` 走
            #   `git worktree list` 首项（主 worktree），不随 `--repo`（可能是会话 worktree）漂移。
            _guard = _wc.unreleased_claims_for_worktree(None, wt)
            if _guard:
                _sids = [c.get("sid") for c in _guard]
                # T13（`ECC-FCB7E9D604F2`，n4 §19.2）**窄面自动释放**：调用方以 `--path`
                #   **显式指名**该 worktree（`only_abs` 非空）= 会话已终结的明确意图 ⟹ 不再让
                #   未 release 的 claim 把回收卡住（原须手敲 `release`，流程摩擦）。
                #   **宽面**（`only_abs` 为空 = 批量/全量扫）⟹ 行为**逐字不变**，仍拒删。
                _auto_ok = False
                if only_abs and apply:
                    _rels = []
                    for _sid in _sids:
                        try:
                            _rels.append(_wc.release(None, sid=_sid, worktree=wt,
                                                     source="reclaim-autorelease"))
                        except Exception as e:  # noqa: BLE001 — 边界：release 抛 ⟹ 视同失败
                            _rels.append({"ok": False, "error": str(e)})
                    report["claim_autoreleased"].append(
                        {"path": wt, "sids": _sids, "released": _rels})
                    # **复检**（禁静默放行）：任一 release 非 ok，或账本仍报该 wt 未 release ⟹ 回退拒删。
                    _auto_ok = (all(bool(r.get("ok")) for r in _rels)
                                and not _wc.unreleased_claims_for_worktree(None, wt))
                elif only_abs:
                    # T13 缺陷修正（`ECC-5406400DA6BD`）：**dry-run 零写** —— 窄面自动释放此前
                    #   **未 gate 在 `apply` 上** ⟹ 默认 dry-run 也真调 `_wc.release` 落台账，
                    #   破 reclaim 自述的「默认 dry-run…**零写操作**」契约：一次预览
                    #   `--reclaim --path X`（不带 `--apply`）即**静默释放** X 的 live claim，
                    #   可误释放并发会话仍在用的工作区。
                    #   ⟹ dry-run 路**只预告、绝不写**（唯一新增是内存里的预告项），并置
                    #   `_auto_ok=True` 放行 —— 继续走既有 dry-run 的 `WOULD-ARCHIVE-THEN-REMOVE`
                    #   报告面，不再进 `claim_guarded`/`skipped`。
                    report["claim_autoreleased"].append(
                        {"path": wt, "sids": _sids, "would_release": True})
                    _auto_ok = True
                elif apply and w.get("alive") and _is_merged_clean(baseline, wt, w.get("branch", "")):
                    # 2026-10-10（finding ECC-6056478D1353 · 摩擦③）：`--all` 授权下的**全量**扫，对
                    #   「已并入主树 HEAD 且干净且 alive」的 worktree 视同窄面显式指名 ⟹ 自动释放其
                    #   （含过期的）claim 后回收。判据 fail-closed（见 `_is_merged_clean`）。
                    _rels = []
                    for _sid in _sids:
                        try:
                            _rels.append(_wc.release(None, sid=_sid, worktree=wt,
                                                     source="reclaim-autorelease-merged"))
                        except Exception as e:  # noqa: BLE001 — 边界：release 抛 ⟹ 视同失败
                            _rels.append({"ok": False, "error": str(e)})
                    report["claim_autoreleased"].append(
                        {"path": wt, "sids": _sids, "released": _rels, "reason": "merged_clean"})
                    _auto_ok = (all(bool(r.get("ok")) for r in _rels)
                                and not _wc.unreleased_claims_for_worktree(None, wt))
                if not _auto_ok:
                    # ECC-B141333BBA20：guard 项须带**可操作** fix —— 实测坑：`--unbind` 只清
                    #   `state.worktrees_extra[]`，**不**释放 claim（claim 在 gk_write_claims 台账）
                    #   ⟹ 用户以为解绑即可回收，实际仍被挡且输出无指引。
                    report["claim_guarded"].append(
                        {"path": wt, "sids": _sids,
                         "reason": "unreleased_claim（含已过期；fail-closed）",
                         "fix": "该工作区有**未 release** 的 claim（护并发会话，拒删）；先释放再回收： "
                                + " ；".join("apply-worktree --release-claim %s" % s
                                            for s in _sids)
                                + "（应急旁路 GK_RECLAIM_CLAIM_GUARD=0 会跳过此闸，慎用）"})
                    report["skipped"].append(wt)
                    continue
        # B-2 前置：分支回收判据 = `_is_merged_clean`（**已并入 baseline HEAD 且工作树干净**）——
        #   须在**目录仍存在**时算（该谓词依赖 `worktree_state(wt)`）；删除后再算必假。
        _br = w.get("branch", "")
        _br_merged = bool(branch_reclaim and _br and _is_merged_clean(baseline, wt, _br))
        st = worktree_state(wt, baseline)
        item = {"path": wt, "branch": w.get("branch", ""), "alive": w.get("alive", False),
                "unregistered": bool(w.get("unregistered")), "pending": len(st["entries"]),
                "broken": bool(w.get("broken")), "age_days": w.get("age_days"),
                "fallback": st.get("fallback", ""), "noise_only": st.get("noise_only", False)}
        # 2026-11-03（回收超时修复）：失效注册的 diff 兜底到墙钟预算仍未比完 ⟹ **无法判定**是否有
        #   未回收内容 ⟹ 拒删（fail-closed）。原状：全树逐字节比对 70 s/棵，4 棵即顶穿 CLI 超时；
        #   若把「没比完」当「没差异」就会误删（本模块最要防的病），故此处**只**允许人工介入。
        if st.get("truncated"):
            item["action"] = "HELD"
            item["reason"] = ("内容比对超出墙钟预算（GK_RECLAIM_DIFF_TIMEOUT=%gs）⟹ 无法判定是否有"
                              "未回收内容 ⟹ 拒删（fail-closed）；调大预算复跑，或人工核对后用 "
                              "--path 指名" % _diff_budget_s())
            report["held"].append(wt)
            report["ok"] = False
            report["items"].append(item)
            continue
        if st["entries"]:
            # **归档前置**：有未回收内容 ⟹ 先归档；归档失败 ⟹ 拒删（fail-loud）
            item["pending_sample"] = st["entries"][:5]
            if apply:
                dest = os.path.join(trash, "reclaim-%s-%s" % (os.path.basename(wt), ts))
                ok_all = True
                for e in st["entries"]:
                    try:
                        if not _copy_entry(main_repo, wt, e, dest):
                            ok_all = False
                    except OSError:
                        ok_all = False
                if not ok_all:
                    item["action"] = "HELD"
                    item["reason"] = "归档不完整 ⟹ 拒删（fail-loud；请人工核对）"
                    report["held"].append(wt)
                    report["ok"] = False
                    report["items"].append(item)
                    continue
                item["archived_to"] = dest
                report["archived"].append(dest)
            else:
                item["action"] = "WOULD-ARCHIVE-THEN-REMOVE"
                report["items"].append(item)
                continue
        if apply:
            # ① **委托 git-workflow**（`git-workflow worktree delete --path <dir> --force`）——
            #    与创建侧 `apply-worktree → git-workflow worktree create` **对称** ⟹ 单源。
            #    2026-09-24 用户裁定「按建议做」取 A；为此给 git-workflow 的 delete 补了
            #    `--path`（按路径，应对无 branch 的孤儿）与 `--force`（脏 wt 强删，归档已过）。
            #    本仓**不再自持**第二套 `git worktree remove`。
            done = False
            gw = _git_workflow_entry(main_repo)
            if gw and os.path.isdir(wt):
                subprocess.run([gw, "worktree", "delete", "--path", wt, "--force"],
                               capture_output=True, text=True)
                done = not os.path.isdir(wt)
            # ② 兜底**仅此一种**：**未注册的孤儿目录** —— git 已不认识该路径，
            #    `git worktree remove` 必报 "not a working tree" ⟹ git-workflow **结构上**
            #    无法处理（不是重复实现，是能力缺口的唯一下沉）。交付面：删目录 + `prune`。
            if not done and os.path.isdir(wt):
                shutil.rmtree(wt, ignore_errors=True)
                _git(main_repo, "worktree", "prune")
            item["action"] = "REMOVED"
            report["removed"].append(wt)
            # §16 D-b①：回收成功后，对本 worktree 的 live claim 自动 release（治僵尸 live）。
            if _wc is not None:
                for _c in _wc.claims_for_worktree(None, wt):
                    try:
                        _wc.release(None, sid=_c.get("sid", ""),
                                    worktree=_c.get("worktree", ""), source="reclaim")
                    except Exception:  # noqa: BLE001 — best-effort，留痕不阻断
                        pass
            # ── B-2（2026-10-16，owner 裁定「回收含 worktree→分支」）：**分支回收**（新增落点）──
            #   仅当 `--branches`（`branch_reclaim`）且判据 `_is_merged_clean` 为真（已并入基线
            #   HEAD 且干净 = 会话已终结的确定性判据）才删；其余 **fail-closed 保留**并进
            #   `branch_guarded`（不静默、不误删未合并分支）。依据现状：`git worktree delete`
            #   只删目录**不删分支**（全仓原无分支回收步）⟹ 本块补刀。
            if branch_reclaim and _br:
                if _br_merged:
                    if apply:
                        if _git(baseline, "branch", "-D", _br)[0] == 0:
                            item["branch_action"] = "DELETED"
                            report["branch_removed"].append(_br)
                        else:
                            item["branch_action"] = "GUARDED"
                            item["branch_reason"] = "git branch -D 失败 ⟹ 保留（fail-closed）"
                            report["branch_guarded"].append(_br)
                    else:
                        item["branch_action"] = "WOULD-DELETE"
                else:
                    item["branch_action"] = "GUARDED"
                    item["branch_reason"] = "未并入基线 HEAD 或工作树有残留 ⟹ 保留（fail-closed）"
                    report["branch_guarded"].append(_br)
        else:
            item["action"] = "WOULD-REMOVE"
        report["items"].append(item)
    # ── 游离分支面（2026-11-08，owner 裁定「合并回收所有工作区分支」）────────────────────
    #   动机：worktree 面只会回收**其挂载分支**，而长期迭代残留的分支（已并入/patch 等价）
    #   无任何回收通路；同时门禁 R0.17 已拦裸 `git branch -d|-D` ⟹ 标准通道必须覆盖此面，
    #   否则「通道存在但干不了活」= 变相把用户逼回裸 git。判据与留痕全在 sweep_loose_branches。
    if all_branches:
        _loose = sweep_loose_branches(main_repo, baseline, apply=apply)
        report["loose_branch_would_remove"] = _loose["would_remove"]
        report["loose_branch_removed"] = _loose["removed"]
        report["loose_branch_guarded"] = _loose["guarded"]
        report["loose_branch_checked_out"] = _loose["checked_out"]
    # ── RC6：目录层残留（`git worktree list` 看不到的那一层）—— dry-run 只报，`--apply` 才清 ──
    #    与 worktree 面**同一纪律**：归档前置（孤儿 state 先归档再删；空壳无内容可归档）·
    #    fail-loud（归档/删除失败进 held 且 `ok=false`）· 默认 dry-run（`--apply` 才落刀）。
    known_abs = {os.path.abspath(w["path"]) for w in wts if w.get("path")}
    known_abs.add(os.path.abspath(main_repo))
    report["residue"] = scan_residue(repo_worktree_scope(root, main_repo), known_abs, trash)
    for it in report["residue"]:
        if only_abs:
            # `--path` 收窄时**不动**残留层（非路径特异；避免波及其他会话的孤儿 state / 空壳）
            it["action"] = "SKIPPED-PATH-FILTER"
            continue
        if not apply:
            it["action"] = ("WOULD-ARCHIVE-THEN-REMOVE" if it["kind"] == "orphan_state"
                            else "WOULD-REMOVE")
            continue
        try:
            if it["kind"] == "orphan_state":
                dest = os.path.join(trash, "residue-%s" % ts)
                os.makedirs(dest, exist_ok=True)
                tgt = os.path.join(dest, os.path.basename(it["path"]))
                shutil.copy2(it["path"], tgt)
                os.remove(it["path"])
                it["action"] = "ARCHIVED-THEN-REMOVED"
                report["archived"].append(tgt)
            else:
                # 空壳目录：无内容可归档 ⟹「归档前置」天然满足；二次确认无文件（防扫描后并发新增）
                if any(fs for _d, _s, fs in os.walk(it["path"])):
                    raise OSError("扫描后目录已非空")
                shutil.rmtree(it["path"])
                it["action"] = "REMOVED"
            report["removed"].append(it["path"])
        except OSError as e:  # noqa: BLE001 — 边界：归档/删除失败进 held 并 fail-loud，不吞
            it["action"] = "HELD"
            it["reason"] = "归档/删除失败 ⟹ 拒删（fail-loud）：%s" % e
            report["held"].append(it["path"])
            report["ok"] = False
    # ── RC1-S4：悬空允许集（`state.worktrees_extra[]`）—— dry-run 只报，`--apply` 才解绑 ──
    #    顺序在**回收之后**：本次删掉的目录此刻已 `isdir=False` ⟹ 自然被识别为悬空。
    _sweep_dangling_extras(state, report, apply)
    # ECC-B141333BBA20 / ECC-2B04C5B10464：顶层 hint —— 被 guard 的项此前只进 `claim_guarded`/`skipped`，无 fix 指引。
    if report.get("claim_guarded"):
        report["hint"] = ("有**未 release** 的 claim 的工作区被 guard 拒删（含已过期 —— 过期 ≠ 可删）："
                          "**解绑（--unbind）不释放 claim**（claim 在 gk_write_claims 台账）⟹ 先 "
                          "`apply-worktree --release-claim <sid>` 释放；或以 `--path <dir>` 指名"
                          "（窄面自动释放）；应急旁路 GK_RECLAIM_CLAIM_GUARD=0（慎用）。")
    return report


def main(argv: list) -> int:
    """`reclaim [--repo R] [--root W] [--state S] [--path P]... [--apply]` | `tmp [--days N] [--apply] [--trash D]`
    | `trash [--dir D | --repo R] [--days N] [--apply]`。

    CLI 侧经 `apply-worktree --reclaim [--tmp|--trash] [--tmp-days N] [--trash-days N] [--apply]`
    调（见 rationale 头注）。
    """
    if argv and argv[0] == "tmp":
        days, apply_, trash = 7, False, ""
        i = 1
        while i < len(argv):
            a = argv[i]
            if a == "--days" and i + 1 < len(argv):
                days = int(argv[i + 1]); i += 2
            elif a == "--trash" and i + 1 < len(argv):
                trash = argv[i + 1]; i += 2
            elif a == "--apply":
                apply_ = True; i += 1
            else:
                print(json.dumps({"ok": False, "error": "unknown arg: " + a,
                                  "usage": "gk_worktree_reclaim.py tmp [--days N] [--apply] [--trash D]"},
                                 ensure_ascii=False))
                return 2
        print(json.dumps(reclaim_tmp(days=days, apply=apply_, trash=trash), ensure_ascii=False))
        return 0
    if argv and argv[0] == "trash":
        days, apply_, tdir, repo_ = 3, False, "", os.environ.get("SKILL_DIR", "")
        i = 1
        while i < len(argv):
            a = argv[i]
            if a == "--days" and i + 1 < len(argv):
                days = int(argv[i + 1]); i += 2
            elif a == "--dir" and i + 1 < len(argv):
                tdir = argv[i + 1]; i += 2
            elif a == "--repo" and i + 1 < len(argv):
                repo_ = argv[i + 1]; i += 2
            elif a == "--apply":
                apply_ = True; i += 1
            else:
                print(json.dumps({"ok": False, "error": "unknown arg: " + a,
                                  "usage": "gk_worktree_reclaim.py trash [--dir D | --repo R] "
                                           "[--days N] [--apply]"}, ensure_ascii=False))
                return 2
        # 落点解析走**单源**（`trash_dir`）；显式 `--dir` 优先 —— 便于对拍 / 异机回收。
        if not tdir:
            if not repo_ or not os.path.isdir(repo_):
                print(json.dumps({"ok": False,
                                  "error": "回收区不可得（需 --dir，或 --repo / env SKILL_DIR "
                                           "指向技能仓）"}, ensure_ascii=False))
                return 2
            tdir = _trash_dir(repo_)
        print(json.dumps(reclaim_trash(tdir, days=days, apply=apply_), ensure_ascii=False))
        return 0
    repo = os.environ.get("SKILL_DIR", "")
    root = os.environ.get("GATEKEEPER_WORKTREE_ROOT", "")
    apply_ = False
    state = ""
    only = []
    branch_rc = False
    all_br = False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--repo" and i + 1 < len(argv):
            repo = argv[i + 1]; i += 2
        elif a == "--root" and i + 1 < len(argv):
            root = argv[i + 1]; i += 2
        elif a == "--state" and i + 1 < len(argv):
            state = argv[i + 1]; i += 2
        elif a == "--path" and i + 1 < len(argv):
            only.append(argv[i + 1]); i += 2      # 可重复；路径白名单（opt-in）
        elif a == "--apply":
            apply_ = True; i += 1
        elif a == "--branches":                    # B-2：回收 worktree 后按其判据回收分支（opt-in）
            branch_rc = True; i += 1
        elif a == "--all-branches":                # 游离分支面：已并入/patch 等价 ⟹ 回收（opt-in）
            all_br = True; i += 1
        else:
            print(json.dumps({"ok": False, "error": "unknown arg: " + a,
                              "usage": "gk_worktree_reclaim.py [--repo R] [--root W] "
                                       "[--state S] [--path P]... [--apply] [--branches] "
                                       "[--all-branches]"},
                             ensure_ascii=False))
            return 2
    if not repo or not os.path.isdir(repo):
        print(json.dumps({"ok": False, "error": "repo 不可用（需 --repo 或 env SKILL_DIR）"},
                         ensure_ascii=False))
        return 2
    if not root:
        # 单源：从 gk_route_center 取首个白名单根（不另抄字面量）
        sys.path.insert(0, os.path.join(repo, "scripts"))
        try:
            import gk_route_center as rc
            root = rc.DEV_WORKTREE_ROOTS[0] if rc.DEV_WORKTREE_ROOTS else ""
        except Exception:  # noqa: BLE001 — 边界：拿不到根就只扫 git 注册面
            root = ""
    print(json.dumps(reclaim(repo, root, apply=apply_, state=state, only=only,
                             branch_reclaim=branch_rc, all_branches=all_br),
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

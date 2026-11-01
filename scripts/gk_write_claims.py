#!/usr/bin/env python3
"""运行时刻 declare —— **区外 append-only write-claims 台账**（R-CONC-GIT 一期 · 设计 D，2026-09-30）。

来源：`docs/plans/2026-09-28-git-concurrency-lease-declare-plan.md` §3（设计 D）/ §7（kill switch）/ §8（反例）。

载体：`<repo>/.gatekeeper.write-claims.jsonl`（与 `.finding-journal.jsonl` / `.session-state-archive.jsonl`
**同族命名**；单源、**只追加**）。**弃用** `state.gate_data.write_claims[]` —— 质询实测三面皆中：
  ① `discover` 归档并清空 `gate_data` ⟹ 台账被静默清空后**一切重叠检测读空账 = 假绿**；
  ② `cmd_apply_worktree` 的 code-fix 路径 `cp` 出 worktree state 副本 ⟹ 单源前提不成立；
  ③ `state-patch` 走 `gate_data` 顶层键整体 update ⟹ last-writer-wins 丢单。

条目字段：`{sid, worktree, family, source, paths[], ts, ttl_s, state}`
  · `state ∈ {live, released, anomaly}`；`released` = **追加**一条同 `sid` 的终态行（**禁原地改写**）。
  · `ttl_s` 单源 = `gk_git_lease.claim_ttl_s()`（治 §9-ASSUMPTION-3「双 TTL 静默失效」）。

判据（对齐 Loom「lease warns, never blocks」）：
  · 新 claim 与 live claims **路径重叠** → **WARN（不阻断）**，输出 `overlap:[{a,b,paths}]`；
  · **写后对账**：提交时把实际变更路径与 live claims 对账，不一致 ⟹ 落 `state:"anomaly"` 行
    （「会话永不登记」**有成本**，治 G1「只换措辞」）。

kill switch：`GK_WRITE_CLAIM_WARN=0` ⟹ 关闭重叠/对账 **WARN**（**登记仍写入**，便于事后核对）；
`GK_WRITE_CLAIMS_PATH` 非空 ⟹ 覆盖台账路径（**登记点①「写哪本账」的裁定开关**；
缺省 = **主 repo 单本账**，理由：跨批/跨 worktree 要能互相看见）。
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from gk_git_lease import claim_ttl_s  # noqa: E402  （TTL **单源**）

CLAIMS_NAME = ".gatekeeper.write-claims.jsonl"
_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"


# ─────────────────────────── 路径 / 开关 ───────────────────────────
def warn_enabled() -> bool:
    return os.environ.get("GK_WRITE_CLAIM_WARN", "1") != "0"


_DEFAULT_REPO_CACHE = []  # 进程内单槽缓存（避免热路径反复起 git）


def _default_repo() -> str:
    """账本单源 = **主 worktree**（`git worktree list` 首项），而非脚本所在树（§16 P2）。

    round-3 质询：从会话 worktree 的**脚本副本**运行 `_SCRIPT_DIR.parent` 会指向该 worktree ⟹
    读到另一本账（对账恒空转）。`git worktree list` 首项恒为主 worktree ⟹ 单源；git 不可用则回退。
    """
    if _DEFAULT_REPO_CACHE:
        return _DEFAULT_REPO_CACHE[0]
    repo = ""
    try:
        out = subprocess.run(
            ["git", "-C", str(_SCRIPT_DIR.parent), "worktree", "list", "--porcelain"],
            capture_output=True, text=True, timeout=5)
        for ln in (out.stdout or "").splitlines():
            if ln.startswith("worktree "):
                repo = ln.split(" ", 1)[1].strip()
                break
    except Exception:  # noqa: BLE001 — 边界：git 缺失/超时 ⟹ 回退脚本树
        repo = ""
    if not repo:
        repo = str(_SCRIPT_DIR.parent)
    _DEFAULT_REPO_CACHE.append(repo)
    return repo


def claims_path(repo: str = None) -> str:
    p = os.environ.get("GK_WRITE_CLAIMS_PATH")
    if p:
        return p
    return os.path.join(repo or _default_repo(), CLAIMS_NAME)


def _norm(p: str) -> str:
    """归一为仓库相对 posix 路径（**存储**用；兼容 `\\` 与 `./`）。"""
    s = str(p).replace("\\", "/").strip()
    while s.startswith("./"):
        s = s[2:]
    return s.rstrip("/")


_DRIVE_RE = re.compile(r"^([a-zA-Z]):/")
_MNT_RE = re.compile(r"^/mnt/([a-zA-Z])(/.*)?$")


def _host_norm(s: str) -> str:
    """**双宿主归一**：`C:/…` ⟹ `/mnt/c/…`（WSL 形态），使 `C:\\` 与 `/mnt/c` 两形态落同一坐标。

    round-3/6 臂质询：`_canon` 原只 realpath+casefold，**不做盘符映射** ⟹ 判据①「两形态必命中」
    实为「恒空转/恒命中」风险（`/mnt/c/…` vs `C:\…` 永不判等）。
    """
    # [ECC-34FE26B7AFD4] **宿主感知**：原式**无条件** `C:/… ⟹ /mnt/c/…`，在 Windows 宿主上适得其反
    #   —— `os.path.realpath("/mnt/c/x")` 是**盘符相对**路径 ⟹ 解析成 `C:\mnt\c\x`（双重 mangling）
    #   ⟹ ① `_canon` 两侧不判等（臂 arm1/arm13/arm19 报 out_of_scope 假警）；② D-c① 僵尸判据
    #   （**存在性**）对**真实存在**的 `C:\…` 目录恒判「不存在」⟹ 误报 zombie（臂 arm15），假 zombie
    #   又占掉 `_dedup_cap` 配额（臂 arm10 只余 19 条 blind_spot）。修：Windows 宿主把 `/mnt/<d>/…`
    #   折成 `<D>:/…`（`C:\…` 原样），POSIX 宿主行为**逐字不变**。
    if os.name == "nt":
        m = _MNT_RE.match(s)
        if m:
            return m.group(1).upper() + ":" + (m.group(2) or "/")
        return s
    m = _DRIVE_RE.match(s)
    if m:
        return "/mnt/" + m.group(1).lower() + s[2:]
    return s


def _resolve_abs(p: str, base: str = "") -> str:
    """**绝对路径解析**（双宿主归一 → 相对补全 → realpath；**不** casefold）。

    `_canon`（比较用，casefold）与 D-c① 僵尸判据（**存在性**用）**共用本单源** ——
    round-4 6 臂质询（`ECC-19DBC52FBF41`）：僵尸分支原用裸 `os.path.isabs`/`os.path.realpath`，
    跨宿主形态（`C:/…` 在 posix 解释器下 `isabs` 为假）被拼成仓库内不存在的路径 ⟹
    **恒真 zombie anomaly**。
    """
    s = _host_norm(str(p).strip().replace("\\", "/"))
    if not s:
        return ""
    if not os.path.isabs(s):
        s = _host_norm(os.path.join(base or _default_repo(), s))
    try:
        return os.path.realpath(s)
    except OSError:
        return os.path.abspath(s)


def _canon(p: str, base: str = "") -> str:
    """**比较**用单一归一：双宿主映射 → 相对路径按 `base` 补全 → realpath → casefold。

    ECC-71EBE521D5A5 / §16 P1：`claim.paths` 存绝对 worktree 目录、`reconcile --changed`
    存仓库相对路径 ⟹ 旧 `_norm` 不归一 ⟹ 已登记会话恒落 out_of_scope（恒真噪声）。
    `base` = 提交所在树（会话 claim 的 worktree 优先，缺则仓库）⟹ 两侧落到同一绝对坐标再比。

    [ECC-34FE26B7AFD4] **分隔符归一**：`_resolve_abs` 走 `os.path.realpath`，Windows 宿主产出
    反斜杠；而 `_overlaps` 前缀判据按 `b + "/"` 拼 ⟹ 子路径 `…\\wt\\scripts\\foo.py` 判不出
    祖先 `…\\wt` ⟹ arm1/arm13/arm19 报 `out_of_scope` 假警。统一折 `/` 后再比（POSIX 上 no-op）。
    """
    return _resolve_abs(p, base).replace("\\", "/").rstrip("/").lower()


def _overlaps(a: str, b: str, base: str = "") -> bool:
    """前缀口径（`_canon` 后）：`a` 是 `b` 的祖先目录 / 同路径 ⟹ 重叠（派发按目录声明）。"""
    a, b = _canon(a, base), _canon(b, base)
    if not a or not b:
        return False
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


# ─────────────────────────── 读 / 写 ───────────────────────────
def _ts_now() -> str:
    return time.strftime(_TS_FMT, time.gmtime())


def _parse_ts(ts) -> float:
    try:
        return time.mktime(time.strptime(str(ts), _TS_FMT)) - time.timezone
    except (TypeError, ValueError):
        return None


def read_all(repo: str = None) -> list:
    """读全部行（坏行跳过，宁漏勿崩）。"""
    p = Path(claims_path(repo))
    if not p.exists():
        return []
    out = []
    try:
        for ln in p.read_text(encoding="utf-8").splitlines():
            if not ln.strip():
                continue
            try:
                out.append(json.loads(ln))
            except ValueError:
                continue
    except OSError:
        return []
    return out


def _append_line(repo: str, rec: dict) -> dict:
    """**唯一写点**（append-only）。best-effort：失败回 `ok:False` + `error`，**不抛**。"""
    p = claims_path(repo)
    try:
        with open(p, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return {"ok": True, "path": p, "record": rec}
    except OSError as e:
        return {"ok": False, "path": p, "error": "登记失败（best-effort，不得阻断主流程）：%s" % e,
                "record": rec}


def append(repo: str = None, sid: str = "", worktree: str = "", family: str = "",
           source: str = "", paths=None, state: str = "live", ttl_s=None, ts=None) -> dict:
    rec = {"sid": sid, "worktree": _norm(worktree), "family": family, "source": source,
           "paths": sorted({_norm(x) for x in (paths or []) if str(x).strip()}),
           "ts": ts or _ts_now(), "ttl_s": int(ttl_s if ttl_s is not None else claim_ttl_s()),
           "state": state}
    return _append_line(repo, rec)


def release(repo: str = None, sid: str = "", **kw) -> dict:
    """终态 = **追加**同 `sid` 的 `released` 行（禁原地改写）。"""
    return append(repo=repo, sid=sid, state="released", ttl_s=0, **kw)


def renew(repo: str = None, sid: str = "", worktree: str = "", family: str = "",
          source: str = "", paths=None) -> dict:
    """**P4 续期**：追加同 `sid` 的 `renewed` 行（刷新 `ts`）⟹ TTL 重新计时（禁原地改写）。

    长任务超 `claim_ttl_s`（默认 3600s）会使该 sid 静默失活 ⟹ D-a 回收闸失效（round-3 质询）。
    调用方在跨 TTL 的长任务中周期性 `renew`。

    ⚠ round-4 6 臂质询（`ECC-F98CB6627785`，CRITICAL）：原实现用默认空 worktree/paths 追加
    renewed 行，而 `live()` 按 sid 取**最后一条** ⟹ 一次续期即**擦空**该会话的 worktree/paths
    ⟹ `claims_for_worktree` 恒空 ⟹ **D-a 回收前置闸 fail-open**（可删在用 worktree）；同因
    `declared` 被擦空 ⟹ 每次提交恒落 `out_of_scope`。修法 = **继承上一有效行**（live/renewed）的
    worktree/family/paths；**无上一有效行 ⟹ no-op**（禁为未登记会话凭空造 claim，否则顶掉
    `unregistered_writer` 对账信号）。
    """
    prev = [r for r in read_all(repo)
            if sid and r.get("sid") == sid and r.get("state") in ("live", "renewed")]
    if not prev:
        return {"ok": True, "noop": True,
                "reason": "no prior live/renewed claim for sid（禁凭空造 claim）",
                "path": claims_path(repo), "record": None}
    p = prev[-1]
    return append(repo=repo, sid=sid, state="renewed", ttl_s=claim_ttl_s(),
                  worktree=worktree or p.get("worktree", ""),
                  family=family or p.get("family", ""),
                  source=source or "renew",
                  paths=paths if paths else (p.get("paths") or []))


_ANOMALY_CAP = 20


def _dedup_cap(items, cap: int = _ANOMALY_CAP) -> list:
    """异常**去重 + 上限**（D-c②：防 append-only 台账被同类误报淹没）。"""
    seen, out = set(), []
    for x in items:
        k = json.dumps(x, sort_keys=True, ensure_ascii=False)
        if k in seen:
            continue
        seen.add(k)
        out.append(x)
        if len(out) >= cap:
            break
    return out


def _anomaly_key(a: dict) -> str:
    """异常行指纹（**跨调用**去重键；`ECC-0E94F2E374BB`）。"""
    return json.dumps({k: a.get(k) for k in ("kind", "sid", "worktree", "b", "paths")},
                      sort_keys=True, ensure_ascii=False)


def rotate(repo: str = None, keep_anomaly: int = 200) -> dict:
    """台账轮转：把**最旧、超出 `keep_anomaly` 的 anomaly 行**移入 `<ledger>.archive.jsonl`；
    台账仅保留非 anomaly 行 + 最近 `keep_anomaly` 条 anomaly 行。

    `ECC-0E94F2E374BB`：`_dedup_cap` 只单次调用内去重 ⟹ 同类 anomaly 跨次重复落行、台账单调
    增长。跨调用去重在 `reconcile` 落行前做；**轮转 = 显式入口**（对齐 `finding archive-closed`），
    禁自动改写。归档先行 + `os.replace` 原子写 ⟹ 零丢失。
    """
    rows = read_all(repo)
    idx = [i for i, r in enumerate(rows) if r.get("state") == "anomaly"]
    keep = set(idx[-keep_anomaly:]) if (keep_anomaly or 0) > 0 else set()
    drop = {i for i in idx if i not in keep}
    if not drop:
        return {"ok": True, "rotated": 0, "kept": len(rows), "path": claims_path(repo)}
    arc = claims_path(repo) + ".archive.jsonl"
    try:
        with open(arc, "a", encoding="utf-8", newline="\n") as f:
            for i in sorted(drop):
                f.write(json.dumps(rows[i], ensure_ascii=False) + "\n")
        tmp = claims_path(repo) + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            for i, r in enumerate(rows):
                if i not in drop:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
        os.replace(tmp, claims_path(repo))
    except OSError as e:
        return {"ok": False, "error": "rotate 失败: %s" % e, "path": claims_path(repo)}
    return {"ok": True, "rotated": len(drop), "kept": len(rows) - len(drop),
            "archive": arc, "path": claims_path(repo)}


def heartbeat(repo: str = None, worktree: str = "", frac: float = None) -> dict:
    """**P4 心跳**：为 `worktree` 上全部 live claim 续期（追加 `renewed` 行）。

    `ECC-70D40BA92943`（原 `ECC-AC9194A68A4C`）：原判活仅 TTL 续期且 `renew` 只挂**提交**路径 ⟹
    长任务 >`claim_ttl_s` 不提交时静默失活 ⟹ D-a 回收闸被 TTL 架空。本入口把判活锚从「提交」改为
    「**活动**」（挂在 hook 的编辑门 `pre_tool_check` 上）。

    **节流**（`frac` 默认 0.5，可 `GK_CLAIM_HEARTBEAT_FRAC` 覆盖）：仅当该 worktree 最新 live ts
    已过 `claim_ttl_s()*frac` 才续期 ⟹ 每编辑一次的调用**不写盘、不涨台账**（对抗 `ECC-0E94F2E374BB`）。
    """
    cur = _canon(worktree, repo) if str(worktree).strip() else ""
    if not cur:
        return {"ok": True, "noop": True, "reason": "no worktree", "renewed": []}
    if frac is None:
        try:
            frac = float(os.environ.get("GK_CLAIM_HEARTBEAT_FRAC", "0.5"))
        except ValueError:
            frac = 0.5
    now = time.time()
    ttl = claim_ttl_s()
    out, seen = [], set()
    for c in live(repo):
        if _canon(c.get("worktree") or "", repo) != cur:
            continue
        sid = c.get("sid")
        if not sid or sid in seen:
            continue
        seen.add(sid)
        t = _parse_ts(c.get("ts"))
        if t is not None and ttl > 0 and now < t + ttl * frac:
            out.append({"sid": sid, "noop": True, "reason": "heartbeat_throttled"})
            continue
        r = renew(repo=repo, sid=sid, source="heartbeat")
        out.append({"sid": sid, "ok": r.get("ok"), "noop": r.get("noop", False)})
    return {"ok": True, "renewed": out, "worktree": worktree}


def live(repo: str = None, now: float = None) -> list:
    """对每个 `sid` 取**最后一条**；其 `state==live` 且 `ts + ttl_s` 未过 ⟹ 计入。"""
    now = time.time() if now is None else now
    last = {}
    for rec in read_all(repo):
        sid = rec.get("sid")
        # ECC-71EBE521D5A5 / §16 P3：anomaly 行与 live 行**同 sid** ⟹ 旧式「按 sid 取最后一条」
        # 会被 anomaly 遮蔽（落一条异常反使占用隐形 = 保护方向反转）⟹ 显式跳过 anomaly。
        if sid and rec.get("state") != "anomaly":
            last[sid] = rec
    out = []
    for rec in last.values():
        # P4：`renewed` 行已刷新 ts ⟹ 视同 live（防长任务超 TTL 静默失活）。
        if rec.get("state") not in ("live", "renewed"):
            continue
        t = _parse_ts(rec.get("ts"))
        ttl = rec.get("ttl_s")
        if t is None or not isinstance(ttl, (int, float)):
            continue
        if now <= t + ttl:
            out.append(rec)
    return out


# ─────────────────────────── 重叠 / 对账 ───────────────────────────
def claims_for_worktree(repo: str = None, worktree: str = "") -> list:
    """该 worktree 上的 **live** claims（D-a 回收前置闸 / D-b① release 的**判据单源**）。

    `base=repo` 使 `claim.worktree`（绝对）与传入 `worktree`（可能相对）落到同一坐标。
    """
    wt = str(worktree).strip()
    if not wt:
        return []
    return [c for c in live(repo) if _overlaps(c.get("worktree") or "", wt, base=repo)]


def unreleased_claims_for_worktree(repo: str = None, worktree: str = "") -> list:
    """该 worktree 上**未 release** 的 claims（**含已过 TTL 的**）。

    finding `ECC-2B04C5B10464`（2026-10-06 实测）：`claims_for_worktree` 只看 **live**
    （`ts+ttl` 未过）⟹ 长任务超 `claim_ttl_s`（默认 3600s）后活 claim **静默失活** ⟹ 回收前置闸
    **fail-open**：一次未带 `--path` 的全量 `--apply` 把 3 个**在用**会话 worktree 一并删档
    （其中 `3af419a2` 的末条 live claim 已过期 12m43s）。

    本函数 = 回收面的 **fail-closed** 判据：只要该 worktree 某 sid 的**末条**非 `released`
    （且非 anomaly），即视为 held —— **过期 ≠ 可删**；唯一放行通路 = 显式 `release`
    （`apply-worktree --release-claim <sid>`）或回收时以 `--path` 指名（窄面自动释放）。

    `base=repo` 同 `claims_for_worktree`（绝对/相对落到同一坐标）。
    """
    wt = str(worktree).strip()
    if not wt:
        return []
    last = {}
    for rec in read_all(repo):
        sid = rec.get("sid")
        if not sid or rec.get("state") == "anomaly":
            continue
        if _overlaps(rec.get("worktree") or "", wt, base=repo):
            last[sid] = rec          # 末条覆盖（同 live() 口径）
    return [r for r in last.values() if r.get("state") != "released"]


def _git_worktree_paths(repo: str = None) -> list:
    """`git -C <repo> worktree list --porcelain` 的 worktree 路径（首项 = **主树**）。"""
    base = repo or _default_repo()
    try:
        out = subprocess.run(["git", "-C", base, "worktree", "list", "--porcelain"],
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return [ln.split(" ", 1)[1].strip() for ln in out.splitlines() if ln.startswith("worktree ")]


def _state_worktrees_extra(state_file: str) -> list:
    """读 `state.worktrees_extra[]`（顶层活动写面允许集；缺/坏 ⟹ 空）。"""
    if not state_file or not os.path.isfile(state_file):
        return []
    try:
        with open(state_file, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return []
    v = d.get("worktrees_extra")
    return [str(x) for x in v] if isinstance(v, list) else []


def expected_worktrees(repo: str = None, state_file: str = "", exclude=None) -> list:
    """**D-c② 期望集派生**（生产单源）：`state.worktrees_extra ∪ git worktree list`
    − **主树**（git list 首项）− `exclude`（调用方给的自身 worktree 等）。

    round-4 6 臂质询（`ECC-2859AAF1A367`）：`blind_spot` 原**无生产调用点** ⟹ 库级绿、
    生产恒静默。本函数 = 生产侧唯一派生；调用方 `reconcile(expected_worktrees=expected_worktrees(...))`。
    """
    wt = _git_worktree_paths(repo)
    excl = set()
    if wt:
        excl.add(_canon(wt[0], repo))          # 主树
    for x in (exclude or []):
        if str(x).strip():
            excl.add(_canon(str(x), repo))
    out, seen = [], set()
    for p in list(_state_worktrees_extra(state_file)) + list(wt):
        c = _canon(p, repo)
        if not c or c in seen or c in excl:
            continue
        seen.add(c)
        out.append(p)
    return out


def overlap(repo: str = None, paths=None, sid: str = "") -> dict:
    """新声明路径 vs **其它** live claims ⟹ `overlap:[{a,b,paths}]`；**恒不阻断**。"""
    want = [_norm(x) for x in (paths or []) if str(x).strip()]
    hits = []
    for c in live(repo):
        if sid and c.get("sid") == sid:
            continue
        pairs = sorted({"%s<>%s" % (w, d) for w in want for d in (c.get("paths") or [])
                        if _overlaps(w, d, base=repo)})
        if pairs:
            hits.append({"a": sid, "b": c.get("sid"), "paths": pairs})
    res = {"ok": True, "blocked": False, "overlap": hits}   # blocked 恒 False = `lease-warns-never-blocks`
    if hits and not warn_enabled():
        res["warn"] = "suppressed(GK_WRITE_CLAIM_WARN=0)"
    return res


def reconcile(repo: str = None, changed_paths=None, sid: str = "",
              record: bool = True, expected_worktrees=None, worktree: str = "") -> dict:
    """**写后对账**：实际变更路径 vs live claims。不一致 ⟹ anomaly（可 `record` 落 jsonl）。

    `ECC-009607B99A77`（原 `ECC-DF1EF27A9B5D`）：登记键（register 用会话标签/finding id）与
    对账键（reconcile 用 `GK_SESSION_ID`）**非同一命名空间** ⟹ 提交时 `mine` 恒空 ⟹
    `unregistered_writer` 恒报、`out_of_scope` 生产零命中。统一 = **按提交所在 worktree 取
    `mine`**（worktree 才是双方真正共享的键，复用 D-a/D-b① 同一判据单源）；`sid` 退为标注。
    缺 `--worktree` 时保留旧 sid 匹配口径（向后兼容）。
    """
    raw = [x for x in (changed_paths or []) if str(x).strip()]
    claims = live(repo)
    _wt = str(worktree).strip()
    _cur = _canon(_wt, repo) if _wt else ""
    if _cur:
        mine = [c for c in claims if _canon(c.get("worktree") or "", repo) == _cur]
    else:
        mine = [c for c in claims if c.get("sid") == sid]
    # 提交所在树：显式 worktree 优先，缺则会话 claim 声明的 worktree，再缺回仓库 ——
    # `--changed` 是**该树**相对路径。
    base = _wt or ((mine[0].get("worktree") or "") if mine else "") or repo
    chg = sorted({_canon(x, base) for x in raw})
    anomalies = []
    if chg and not mine:
        anomalies.append({"kind": "unregistered_writer", "sid": sid,
                          "worktree": _wt, "paths": raw})
    declared = sorted({_canon(d, base) for c in mine for d in (c.get("paths") or [])})
    out_of_scope = [w for w in chg if not any(_overlaps(w, d) for d in declared)]
    if mine and out_of_scope:
        anomalies.append({"kind": "out_of_scope", "sid": sid, "paths": out_of_scope,
                          "declared": declared})
    for c in claims:
        if sid and c.get("sid") == sid:
            continue
        if _cur and _canon(c.get("worktree") or "", repo) == _cur:
            continue   # 同 worktree 的 claim = 本树自有口径，不报 overlap（键同源）
        pairs = sorted({"%s<>%s" % (w, d) for w in chg for d in (c.get("paths") or [])
                        if _overlaps(w, d, base=base)})
        if pairs:
            anomalies.append({"kind": "overlap_with_live", "sid": sid, "b": c.get("sid"),
                              "paths": pairs})
    # D-c① 僵尸：live claim 的 worktree 目录**已不存在**（目录删了但 claim 还 live）
    for c in claims:
        wt = c.get("worktree") or ""
        if not wt:
            continue
        # `ECC-19DBC52FBF41`（round-4）：存在性判据须与 `_canon` **同源**（`_resolve_abs` 过
        # `_host_norm`）—— 原裸 `os.path.isabs`/`realpath` 在 posix 解释器下把 `C:/…` 判为
        # 非绝对 ⟹ 拼成仓库内不存在的路径 ⟹ **恒真 zombie anomaly**（跨宿主形态）。
        _abs = _resolve_abs(wt, repo)
        if not _abs or not Path(_abs).exists():
            anomalies.append({"kind": "zombie", "sid": c.get("sid"), "worktree": str(wt)})
    # D-c② 盲区：**期望集**内却无任何 live claim 的 worktree（期望集由调用方显式给，防恒报）
    if expected_worktrees is not None:
        _decl = [_canon(c.get("worktree") or "", repo) for c in claims if c.get("worktree")]
        for wt in expected_worktrees:
            if not str(wt).strip():
                continue
            cw = _canon(str(wt), repo)
            if not any(cw == d or cw.startswith(d + "/") or d.startswith(cw + "/") for d in _decl):
                anomalies.append({"kind": "blind_spot", "worktree": str(wt)})
    anomalies = _dedup_cap(anomalies)
    res = {"ok": not anomalies, "anomalies": anomalies, "warn": warn_enabled()}
    # D-c②：`GK_CLAIM_ANOMALY=0` ⟹ **不落** anomaly 行（防污染 append-only 台账）；返回仍如实报。
    if anomalies and record and os.environ.get("GK_CLAIM_ANOMALY", "1") != "0":
        # `ECC-0E94F2E374BB`：**跨调用**去重 —— `_dedup_cap` 只单次调用内去重 ⟹ 同类 anomaly
        # 跨次提交重复落行。落行前比对台账既有 anomaly 指纹，命中即跳过。
        _seen = {_anomaly_key(r.get("anomaly") or {}) for r in read_all(repo)
                 if r.get("state") == "anomaly" and r.get("anomaly")}
        for a in anomalies:
            if _anomaly_key(a) in _seen:
                continue
            _append_line(repo, {"sid": sid, "worktree": _norm(_wt), "family": "",
                                "source": "reconcile",
                                "paths": a.get("paths") or [], "ts": _ts_now(), "ttl_s": 0,
                                "state": "anomaly", "anomaly": a})
    return res


# ───────────────── D-b② 谓词对账（§17-4 A 步①：report-only） ─────────────────
def _live_state_files(repo: str = None) -> list:
    """主 repo 的**活跃 state 文件**（`<repo>/.gatekeeper.state*`；排除 journal / archive / 备份）。"""
    base = repo or _default_repo()
    try:
        cand = sorted(Path(base).glob(".gatekeeper.state*"))
    except OSError:
        return []
    out = []
    for p in cand:
        n = p.name
        if n.endswith(".finding-journal.jsonl") or "archive" in n or n.endswith(".bak"):
            continue
        if p.is_file():
            out.append(str(p))
    return out


def _state_worktree(state_file: str) -> str:
    """读 `state.worktree`；**非字符串 / 空 ⟹ ""**（空值三态：键缺失 / null / "" 一律视同无 root）。"""
    if not state_file or not os.path.isfile(state_file):
        return ""
    try:
        with open(state_file, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return ""
    v = d.get("worktree")
    return v.strip() if isinstance(v, str) else ""


def state_claim_gaps(repo: str = None, state_files=None) -> dict:
    """**D-b② 谓词对账**（§17-4 A 步①，**report-only / 零写**）。

    判据：`∀ live state.worktree ≠ '' ⟹ ∃ live claim(worktree)`。空值三态（键缺失 / null /
    `""`）⟹ 无约束。**本函数不写台账、不改任何命令 rc** ⟹ 对在跑并发会话**零影响**（先取证）。
    返回 `{"ok": count==0, "checked": n, "count": n, "gaps": [{state_file, worktree}]}`。
    """
    files = [str(x) for x in state_files] if state_files else _live_state_files(repo)
    base = _canon(repo or _default_repo(), repo)
    gaps, checked = [], 0
    for sf in files:
        wt = _state_worktree(sf)
        if not wt:
            continue
        # §17-4 A 步②：`state.worktree == repo 自身`（主树）⟹ 无约束（对齐 `expected_worktrees`
        #   排除主树惯例；否则主 state 恒报 gap）。
        if _canon(wt, repo) == base:
            continue
        checked += 1
        if not claims_for_worktree(repo, wt):
            gaps.append({"state_file": sf, "worktree": wt})
    return {"ok": not gaps, "checked": checked, "count": len(gaps), "gaps": gaps}


# ───────────────── D-b② 写面写点同步（§17-4 A 步②） ─────────────────
def sync_state_worktree(repo: str = None, worktree: str = "", sid: str = "",
                        source: str = "state-worktree") -> dict:
    """**D-b② 写面写点同步**：写 `state.worktree` 即登记 claim（§17-4 A 步②）。

    接线两处（均 best-effort，**绝不改调用方 rc**）：`discover` 写 `state.worktree` 后、
    `state-patch set-top <state> worktree` 写成功后。

    fail-soft / sid-gated / **主树排除** / 幂等：
      · 空 worktree 或无 `sid` ⟹ no-op（零写台账，防 sid-less 噪声行）；
      · `worktree == repo 自身`（主树）⟹ no-op（对齐 `expected_worktrees` 排除主树惯例）；
      · 该 `sid` 在该 worktree 已有 live/renewed claim ⟹ no-op（防台账膨胀）；
      · 否则 append 一条 `live` claim（`paths` = 该 worktree 目录）。
    """
    wt = str(worktree).strip()
    sid = str(sid).strip()
    if not wt or not sid:
        return {"ok": True, "noop": True, "reason": "no sid/worktree"}
    if _canon(wt, repo) == _canon(repo or _default_repo(), repo):
        return {"ok": True, "noop": True, "reason": "main tree excluded"}
    cw = _canon(wt, repo)
    if any(c.get("sid") == sid and _canon(c.get("worktree") or "", repo) == cw
           for c in live(repo)):
        return {"ok": True, "noop": True, "reason": "already claimed", "sid": sid}
    return append(repo=repo, sid=sid, worktree=wt, family="state-worktree",
                  source=source, paths=[wt], state="live")


# ─────────────────────────── CLI ───────────────────────────
def _csv(v):
    return [x for x in (v or "").split(",") if x.strip()]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_write_claims.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("append", "release", "renew", "overlap", "reconcile", "list",
                 "rotate", "heartbeat", "state-claim-gaps", "sync-state-worktree"):
        sp = sub.add_parser(name)
        sp.add_argument("--repo", default=None)
        sp.add_argument("--sid", default="")
        sp.add_argument("--worktree", default="")
        sp.add_argument("--family", default="")
        sp.add_argument("--source", default="")
        sp.add_argument("--paths", default="")
        sp.add_argument("--changed", default="")
        sp.add_argument("--live", action="store_true")
        sp.add_argument("--expected-worktrees", default="")
        # D-c② 生产单源（`ECC-2859AAF1A367`）：`--expected-auto` ⟹ 由 `expected_worktrees()`
        #   从 `--state` 的 worktrees_extra ∪ `git worktree list` 派生期望集（排除主树）。
        sp.add_argument("--expected-auto", action="store_true")
        sp.add_argument("--state", default="")
        sp.add_argument("--keep-anomaly", type=int, default=200)
    ns = ap.parse_args(argv)

    if ns.cmd == "append":
        out = append(ns.repo, sid=ns.sid, worktree=ns.worktree, family=ns.family,
                     source=ns.source, paths=_csv(ns.paths))
    elif ns.cmd == "release":
        out = release(ns.repo, sid=ns.sid, source=ns.source or "release")
    elif ns.cmd == "overlap":
        out = overlap(ns.repo, paths=_csv(ns.paths), sid=ns.sid)
    elif ns.cmd == "reconcile":
        exp = (expected_worktrees(ns.repo, ns.state) if ns.expected_auto
               else _csv(ns.expected_worktrees))
        out = reconcile(ns.repo, changed_paths=_csv(ns.changed), sid=ns.sid,
                        expected_worktrees=exp, worktree=ns.worktree)
    elif ns.cmd == "renew":
        out = renew(ns.repo, sid=ns.sid, worktree=ns.worktree, source=ns.source or "renew")
    elif ns.cmd == "rotate":
        out = rotate(ns.repo, keep_anomaly=ns.keep_anomaly)
    elif ns.cmd == "heartbeat":
        out = heartbeat(ns.repo, worktree=ns.worktree)
    elif ns.cmd == "state-claim-gaps":
        # §17-4 A 步①：report-only 谓词对账（`--state` 显式给则只查该文件，否则自动枚举）。
        out = state_claim_gaps(ns.repo, state_files=(_csv(ns.state) or None))
    elif ns.cmd == "sync-state-worktree":
        # §17-4 A 步②：写面写点同步（fail-soft / sid-gated / 主树排除 / 幂等）。
        out = sync_state_worktree(ns.repo, worktree=ns.worktree, sid=ns.sid,
                                  source=ns.source or "state-worktree")
    else:
        out = {"ok": True, "claims": live(ns.repo) if ns.live else read_all(ns.repo)}
    print(json.dumps(out, ensure_ascii=False))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())

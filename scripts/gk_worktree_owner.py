#!/usr/bin/env python3
"""gk_worktree_owner.py — worktree **独占归属**（单一事实源，2026-11-10）。

事故（2026-11-10，实证）：并发会话把 `references/comment-template.md` 写进了**本会话的 worktree**，
并被本会话 commit（`99aed8c2`）⟹ 别人的产物混进了我的提交历史。根因不是「谁忘了检查」，而是
**没有归属判据**：`pre_tool_hook` Gate 3 的写面 = `state.worktree ∪ worktrees_extra[]`，这是一份
**共享**列表（并发会话互相追加）⟹ 任何会话只要目标路径在列表里就能写 ⟹ worktree 事实上可共享。

判据（单源，不新增第二套身份规则）：
  **worktree 归属 = 会话身份**（env `GK_SESSION_ID` / 宿主 payload sid / 新鲜认领的 `allocated_sid`）。
  路径 token（`agent/session/<sid>` / `agent/<family>/<leaf>` ⟹ `<leaf>`；池槽 ⟹ `slot-N`；
  其它 dev-worktree 形态 ⟹ `w<sha8>`）只作定位与 legacy 兜底，**不再单独构成 owner 身份**
  （2026-11-12 同树双写事故：路径 token 会让任何目标落在该树的会话都通过归属闸）。

失败姿态（显式，不静默）：
  · 目标不在 dev-worktree 树内 / 主检出根 ⟹ `kind=main|unknown`，**不据此拦截**（主树另有只读闸）；
  · 调用方给不出任何身份（无 env sid、cwd 不在 worktree）⟹ **fail-open**（`reason=caller_identity_unknown`），
    因为手工排障 / 非 Trae 宿主没有会话上下文；一旦**两边都可判定且不等** ⟹ fail-closed。

用法:
  python3 gk_worktree_owner.py locate --path <任意路径>
  python3 gk_worktree_owner.py check  --path <目标> --sid <调用方身份> [--sid ...]
  python3 gk_worktree_owner.py whoami --cwd <目录>
Exit: 0 = 允许 / 无法判定；1 = 越界；2 = 参数错。
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gk_session_identity as gsi  # noqa: E402  （身份派生**单源**，禁第二实现）

_WALK_MAX = 12


def _norm(p) -> str:
    return str(p or "").replace("\\", "/").rstrip("/")


def _roots(roots=None):
    """dev-worktree 根白名单（默认单源 = `gk_session_identity.DEV_WORKTREE_ROOTS`）。

    `GK_WORKTREE_ROOTS`（`os.pathsep` 分隔）仅供**测试注入**；生产不设该 env ⟹ 恒走常量。
    """
    if roots:
        return tuple(roots)
    env = str(os.environ.get("GK_WORKTREE_ROOTS", "")).strip()
    if env:
        return tuple(x for x in env.split(os.pathsep) if x.strip())
    return None


def worktree_root(path) -> str:
    """从任意路径向上找到 `.git`（目录 = 主检出根；文件 = linked worktree）。找不到 ⟹ `""`。"""
    p = Path(_norm(path))
    if p.is_file():
        p = p.parent
    for _ in range(_WALK_MAX):
        dot = p / ".git"
        if dot.exists() or dot.is_symlink():
            return str(p)
        if p.parent == p:
            break
        p = p.parent
    return ""


def _abs(p) -> Path:
    """绝对化（相对路径按**当前** cwd 解析；`locate('.')` 不得退化成 `not_in_tree`）。"""
    q = Path(_norm(p) or ".")
    return q if q.is_absolute() else Path(os.path.abspath(str(q)))


def locate(path, roots=None) -> dict:
    """目标路径的归属：`{worktree, kind, owner, source}`。

    `kind ∈ {worktree, main, unknown}`；`owner` 为空 ⟹ 无法判定（调用方按 fail-open 处理）。
    """
    out = {"ok": True, "path": _norm(_abs(path)), "worktree": "", "kind": "unknown",
           "owner": "", "source": ""}
    wt = worktree_root(str(_abs(path)))
    if not wt:
        out["source"] = "no_git_root"
        return out
    out["worktree"] = _norm(wt)
    if (Path(wt) / ".git").is_dir():
        out["kind"] = "main"
        out["source"] = "main_checkout"
        return out
    out["kind"] = "worktree"
    d = gsi.derive(wt, _roots(roots))
    tok = d.get("token") or ""
    if gsi.is_valid_token(tok):
        out["owner"] = tok
        out["source"] = d.get("source") or ""
    else:
        out["source"] = d.get("reason") or "not_in_dev_worktree_tree"
    return out


def caller_id(cwd, roots=None) -> str:
    """调用方身份 = 其 cwd 所在 worktree 的 token（**仅 name 派生**）。

    `hash` 派生（`w<sha8>`，= 路径哈希）标识的是**路径**不是会话 —— 本机工作区根
    `…/worktrees/<技能名>` 就是这种形态，它会让「同工作区里的任何会话」共享同一个身份
    ⟹ 必须排除（否则归属闸被架空，实测：ids 里混进 `w446c85a1`）。
    """
    d = gsi.derive(str(cwd or ""), _roots(roots))
    tok = d.get("token") or ""
    if d.get("source") != "name" or not gsi.is_valid_token(tok):
        return ""
    return tok


# ─── 认领（claim）：会话 → worktree 的**显式**映射（2026-11-10）─────────────────────
# 为什么需要：hook 的 cwd 常是**工作区根**（本机 = `…/worktrees/<技能名>`，路径哈希 ⟹ 非会话
# token），而载荷 `session_id` 是宿主给的稳定会话号 —— 二者都无法从**目标路径**推出「谁在写」。
# 故用「首写认领」：第一次通过的写者把 `ids`（载荷 sid / token）写进**该 worktree 的 gitdir**
# （`<gitdir>/gk-owner.json`，不污染工作树内容），此后只有认领者（或其别名）能写。
CLAIM_NAME = "gk-owner.json"


def claim_path(worktree) -> Path:
    gd = own_gitdir(worktree)
    return (gd / CLAIM_NAME) if gd else Path()


def own_gitdir(worktree) -> Path:
    """worktree 的 gitdir（`.git` 文件形态解析；与 hot-pool 侧同一规则）。"""
    dot = Path(_norm(worktree)) / ".git"
    if dot.is_dir():
        return dot
    try:
        raw = dot.read_text(encoding="utf-8").strip()
    except OSError:
        return Path()
    if not raw.startswith("gitdir:"):
        return Path()
    p = raw[len("gitdir:"):].strip()
    if not p:
        return Path()
    q = Path(p)
    return q if q.is_absolute() else (Path(_norm(worktree)) / q).resolve()


def read_claim(worktree) -> dict:
    p = claim_path(worktree)
    if not p:
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}


def _claim_ttl_s() -> float:
    """认领 TTL 单源 = `gk_git_lease.claim_ttl_s()`（与既有 claims 同一口径）。"""
    try:
        from gk_git_lease import claim_ttl_s
        return float(claim_ttl_s())
    except Exception:  # noqa: BLE001 — 边界：缺依赖按 3600s
        return 3600.0


def claim_fresh(cl: dict) -> bool:
    if not cl:
        return False
    try:
        return time.time() <= float(cl.get("ts_epoch") or 0) + float(cl.get("ttl_s") or 0)
    except (TypeError, ValueError):
        return False


def allocated_sid(path) -> str:
    """该 worktree **新鲜认领**里的分配 sid（无认领 / 过期 ⟹ 空串）。

    2026-11-12（会话身份隔离）：这是 CLI 侧身份的首选来源 —— 与 hook 的宿主 payload sid
    同源；路径 token（`agent/session/<leaf>` / `slot-N`）只是**兜底**，不再覆盖会话号。
    存量 claim 无 `allocated_sid` ⟹ 从 `ids` 派生首个非路径 id（不落第二事实源）。
    """
    loc = locate(path)
    if loc.get("kind") != "worktree":
        return ""
    cl = read_claim(loc["worktree"])
    if not claim_fresh(cl):
        return ""
    ids = [str(x) for x in (cl.get("ids") or [])]
    return str(cl.get("allocated_sid") or next(
        (x for x in ids if x != str(loc.get("owner") or "")), ""))


def claim(worktree, ids, force: bool = False) -> dict:
    """首写认领（已有**新鲜**认领 ⟹ 不覆盖，除非 `force`）。

    `force` 只给**迁移/排障**用（例：认领先于「载荷 sid 入册」的存量条目 ⟹ 补记会话号，
    否则该会话的后续写会被自己的认领挡住）。正常路径禁 force（防夺权）。
    """
    p = claim_path(worktree)
    if not p:
        return {"ok": False, "error": "NO_GITDIR", "worktree": _norm(worktree)}
    cur = read_claim(worktree)
    if claim_fresh(cur) and not force:
        return {"ok": True, "claimed": False, "existing": cur}
    ttl = _claim_ttl_s()
    clean = [str(x) for x in ids if str(x or "").strip()]
    # 2026-11-12（会话身份隔离）：`allocated_sid` = 首个**非路径 token** 的会话 id。
    #   路径 token（`agent/session/<leaf>` / `slot-N`）是**路径身份**，不是会话身份；
    #   它只用于 locate/诊断，不再作为「谁拥有这棵树」的唯一依据。
    #   存量 claim 无该字段 ⟹ `check()` 从 ids 里派生（保持兼容，不另落第二事实源）。
    path_tok = str(locate(worktree).get("owner") or "")
    allocated_sid = next((x for x in clean if x != path_tok), "")
    data = {"ids": clean, "allocated_sid": allocated_sid,
            "worktree": _norm(worktree), "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ts_epoch": time.time(), "ttl_s": ttl}
    tmp = p.with_name(p.name + ".tmp")
    try:
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, p)
    except OSError as e:
        return {"ok": False, "error": "CLAIM_WRITE_FAILED", "detail": str(e)[:200]}
    return {"ok": True, "claimed": True, "claim": data}


def _pool_owner_ids(worktree) -> list:
    """池槽的合法身份集 = {`slot-N`, 租约 sid}（租约文件在池根，与槽同名前缀）。"""
    p = Path(_norm(worktree))
    out = [p.name]
    try:
        lease = json.loads((p.parent / (p.name + ".lease.json")).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return out
    sid = str((lease or {}).get("sid") or "").strip()
    if sid:
        out.append(sid)
    return out


def _lease_path_of(worktree) -> Path:
    p = Path(_norm(worktree))
    return p.parent / (p.name + ".lease.json")


def renew_pool_lease(worktree, ids) -> dict:
    """**编辑即续期**（2026-11-11，用户裁定）：活跃会话的槽位不得被 TTL 扫走。

    病象：`acquire` 只写一次 `ts_epoch`、之后无人续期 ⟹ 超过 `GK_POOL_TTL_S`（默认 2h）的
    **活跃**会话也会被 `sweep` 判定为「崩溃/遗忘」而清场（`E5` 本来只该收死掉的槽）。
    节流：距上次 `ts_epoch` 未过 `ttl/2` 则不写盘（编辑是热路径，不能每次编辑都落盘）。
    身份：只有「租约 sid / 槽名」在调用方身份集里才续期（防外人续别人的槽）。
    """
    lp = _lease_path_of(worktree)
    try:
        lease = json.loads(lp.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"ok": False, "error": "NO_LEASE"}
    if not isinstance(lease, dict):
        return {"ok": False, "error": "BAD_LEASE"}
    try:
        ttl = float(lease.get("ttl_s") or 0)
        ts = float(lease.get("ts_epoch") or 0)
    except (TypeError, ValueError):
        return {"ok": False, "error": "BAD_LEASE"}
    if ttl <= 0:
        return {"ok": False, "error": "NO_TTL"}
    if lease.get("state") != "leased" or not lease.get("sid"):
        return {"ok": False, "error": "NOT_LEASED"}
    if not ({str(lease.get("sid")), Path(_norm(worktree)).name} & set(ids or [])):
        return {"ok": False, "error": "NOT_OWNER"}
    now = time.time()
    if now - ts < ttl / 2:
        return {"ok": True, "renewed": False, "reason": "throttled"}
    lease["ts_epoch"] = now
    lease["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    tmp = lp.with_name(lp.name + ".tmp")
    try:
        tmp.write_text(json.dumps(lease, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, lp)
    except OSError as e:
        return {"ok": False, "error": "RENEW_FAILED", "detail": str(e)[:200]}
    return {"ok": True, "renewed": True, "ttl_s": ttl}


def check(path, caller_ids, roots=None, autoclaim: bool = True) -> dict:
    """写/提交闸：目标 worktree 的 owner 必须 ∈ `caller_ids`。

    判据顺序（先强后弱）：
      ① 新鲜认领（`gk-owner.json`）存在 ⟹ **只认认领者**（载荷 sid / token），与路径无关；
      ② 无认领 ⟹ 路径 token（`agent/session/<sid>` / 池槽 `slot-N`+租约 sid）；命中即**首写认领**；
      ③ token 不可判定 ⟹ fail-open（`owner_unknown`；显式 reason 可审计）。
    """
    loc = locate(path, roots)
    ids = []
    for x in (caller_ids or []):
        s = str(x or "").strip()
        if s and s not in ids:
            ids.append(s)
    loc["caller_ids"] = ids
    if loc["kind"] != "worktree":
        loc.update({"decision": "allow", "reason": "not_a_dev_worktree"})
        return loc
    cl = read_claim(loc["worktree"])

    def _allow(reason):
        # 池槽：**编辑即续期**（节流 ttl/2）—— E5 只该收「崩溃/遗忘」的槽，不该收活跃会话。
        if "/_pool/" in (loc["worktree"] + "/"):
            r = renew_pool_lease(loc["worktree"], ids)
            if r.get("renewed"):
                loc["lease_renewed"] = r
        loc.update({"decision": "allow", "reason": reason})
        return loc

    if claim_fresh(cl):
        owners = [str(x) for x in (cl.get("ids") or [])]
        # 2026-11-12（会话身份隔离）：**路径 token 不得给外来会话救场**。
        #   病象：claim 里同时有 `payload-sid` 与路径 token ⟹ 外人只要派生出该路径 token
        #   （目标落在该 worktree / 读到别人的别名）就被判 owner_match，两个 chat 同写一棵树。
        #   处置：有会话级 id 时，从 owner 集里剔除路径 token；只有**纯路径 token 的 legacy claim**
        #   （无任何会话 id）才保留原语义（人工排障 / 老账迁移面）。
        path_tok = str(loc.get("owner") or "")
        session_owners = [x for x in owners if x != path_tok]
        if session_owners:
            owners = session_owners
        loc["claim"] = owners
        alloc = str(cl.get("allocated_sid") or (owners[0] if owners else ""))
        loc["allocated_sid"] = alloc
        if any(i in owners for i in ids):
            # 宿主 sid 轮换（分配 sid 不在本次身份集，但新 sid 已在 ids 里）⟹ 放行 + 显式告警。
            sid_ids = [i for i in ids if i != path_tok]
            if alloc and sid_ids and alloc not in sid_ids:
                loc["sid_rotated"] = True
            return _allow("claim_match")
        loc.update({"decision": "block", "ok": False,
                    "error": "WORKTREE_OWNERSHIP_VIOLATION",
                    "reason": "该 worktree 已由会话 %s 认领，本会话身份 %s 无权写入（worktree 不可共享）"
                              % ("/".join(owners) or "-", "/".join(ids) or "-")})
        return loc
    owners = []
    if loc["owner"]:
        owners.append(loc["owner"])
    if "/_pool/" in loc["worktree"] + "/":
        owners += [x for x in _pool_owner_ids(loc["worktree"]) if x not in owners]
    loc["claim"] = owners
    if not owners:
        loc.update({"decision": "allow", "reason": "owner_unknown"})
        return loc
    if not ids:
        loc.update({"decision": "allow", "reason": "caller_identity_unknown"})
        return loc
    if any(i in owners for i in ids):
        if autoclaim:
            claim(loc["worktree"], ids)
        return _allow("owner_match")
    loc.update({"decision": "block", "ok": False,
                "error": "WORKTREE_OWNERSHIP_VIOLATION",
                "reason": "目标 worktree 属于 `%s`，本会话身份 %s 无权写入（worktree 不可共享）"
                          % ("/".join(owners), "/".join(ids))})
    return loc


def caller_identities(cwd, extra=(), roots=None, session_dir=None) -> list:
    """调用方身份候选集（**多身份面是既有事实**，不是放宽判据）：

    `cwd` token ∪ `extra`（env / 载荷 sid）∪ 会话 marker 的载荷 sid 与其别名 token。
    marker 的采纳以「marker 记录的 cwd == 本调用 cwd」为门（对齐 CLI 启动块的既有同源判据）——
    否则单槽会被任意并发会话覆写 ⟹ 采到**外来 sid**（该仓已记过一次同类事故）。
    """
    ids = []

    def _add(x):
        s = str(x or "").strip()
        if s and s not in ids:
            ids.append(s)

    _add(caller_id(cwd, roots))
    env_sid = os.environ.get("GK_SESSION_ID", "")
    _add(env_sid)
    for x in (extra or ()):
        s = str(x or "").strip()
        # 2026-11-13 ECC-SID-HEX：宿主 payload 的 `session_id` 偶发回填成**池槽标签**
        #   （实测同一会话两次调用分别拿到 `slot-0` / `slot-1`）⟹ 身份逐调用翻转，
        #   归属闸把本会话判成外人（WORKTREE_OWNERSHIP_VIOLATION）。判据与 marker 分片
        #   同源：只接受纯 hex 8–64 位；不符合的标签一律不进身份集。
        if s and _SID_RE.match(s):
            _add(s)
    # 2026-11-12（会话身份隔离）：单槽 marker 只有**与本次调用同 sid** 时才可采纳。
    #   病象：`.gatekeeper.session` 被并发会话覆盖 ⟹ 本会话读到**别人的 sid 与其别名 token**
    #   （实测 `alias.6aee8af5 → 396aa76b`），归属闸据此把外人当成本树 owner。
    #   判据：调用方已有会话身份（env / payload）时，marker 的 sid 必须在该集合内；
    #   只有「调用方完全没有会话身份」（老宿主/手工）才保留 legacy 采纳（平台无关兜底）。
    own = {str(x).strip() for x in (env_sid, *(extra or ())) if str(x or "").strip()}
    d = Path(session_dir) if session_dir else Path(__file__).resolve().parent.parent
    if own:
        # 已有会话身份 ⟹ 只读**自己**的别名；完全不碰单槽/别人的分片（单槽覆盖免疫）。
        for s in sorted(own):
            try:
                _add((d / (".gatekeeper.session.alias." + s)).read_text(encoding="utf-8").strip())
            except OSError:
                pass
        return ids
    # 无会话身份（老宿主/手工）⟹ 分片读面：唯一新鲜候选才采纳；多候选 = 不猜。
    mc = marker_candidates(d, cwd)
    if mc.get("sid"):
        _add(mc["sid"])
        try:
            _add((d / (".gatekeeper.session.alias." + mc["sid"])).read_text(encoding="utf-8").strip())
        except OSError:
            pass
    return ids


def _same_path(a, b) -> bool:
    """双宿主形态判等（`C:/x` ↔ `/mnt/c/x`，大小写不敏感；尾部斜杠无关）。"""
    def _f(p):
        s = _norm(p).lower()
        if len(s) > 1 and s[1] == ":":
            s = "/mnt/" + s[0] + s[2:]
        return s
    return bool(a) and bool(b) and _f(a) == _f(b)


# 分片名 `.gatekeeper.session.<sid>`；排除 `.tmp` 与 `.alias.<sid>`（含点，正则不匹配）。
# 2026-11-13 ECC-SID-HEX：形态收紧为**纯十六进制 8–64 位**。原 `[0-9A-Za-z_-]+` 会把
#   `not-a-hex-sid` 这类非法名当 sid 采纳 ⟹ 建出伪造的会话桶（`test_gk_edit_budget_metering
#   ::test_arm22_stale_or_invalid_marker_falls_back_to_global` 实测红）。合法 sid 来源只有
#   宿主 hex id（8/24/32/40）与 worktree leaf（8 hex）⟹ 不接纳连字符。
_SESSION_SHARD_RE = re.compile(r"^\.gatekeeper\.session\.([0-9a-f]{8,64})$")
# 单槽 legacy 读面同样要过这一关：`sid` 只在**纯 hex 8–64 位**时才算数，
# 否则 `not-a-hex-sid` 这类外来名会被当会话键建桶（实测红臂见文件头注释）。
_SID_RE = re.compile(r"^[0-9a-f]{8,64}$")


def marker_candidates(skill_dir, cwd, ttl_s: float = 1800.0, now: float | None = None) -> dict:
    """扫描 per-sid marker 分片，返回**与 `cwd` 同源且未过期**的候选（单槽的替代读面）。

    2026-11-12（单槽并发覆盖修复）：`.gatekeeper.session` 是单文件，任一并发会话的
    PreToolUse 都会覆写它 ⟹ CLI 读到**别人的 sid**（实测 `alias.6aee8af5 → 396aa76b`）。
    分片 `.gatekeeper.session.<sid>` 由 hook 每次调用写入（只增不改，天然不互相覆盖）。

    判据：sid 与文件名一致 / 第 4 列 cwd 同源 / epoch 在 TTL 内。
    **候选 >1 = ambiguous**（调用方必须告警/回落，禁猜）—— 同 cwd 的并发会话在物理上
    无法从 marker 区分，猜一个就会把账写到别人头上。
    无任何新鲜分片时才回落单槽（legacy writer，旧 hook 兼容面）。
    """
    d = Path(skill_dir)
    now = time.time() if now is None else float(now)
    cand: dict[str, float] = {}
    saw_shard = False
    try:
        files = [p for p in d.glob(".gatekeeper.session.*") if p.is_file()]
    except OSError:
        files = []
    for p in files:
        m = _SESSION_SHARD_RE.match(p.name)
        if not m:
            continue
        sid = m.group(1)
        if sid == "tmp":
            continue
        # 只要存在**任何** sid 分片，就说明写侧是新 hook；分片不匹配也不得回落单槽
        # （单槽可能正是被覆盖的那个外来 sid ⟹ 回落等于把旧 bug 放回来）。
        saw_shard = True
        try:
            cols = p.read_text(encoding="utf-8").splitlines()[0].split("\t")
            if len(cols) < 4 or cols[0].strip() != sid:
                continue
            ts = float(cols[1])
            mcwd = cols[3].strip()
        except (OSError, ValueError, IndexError):
            continue
        if not mcwd or not _same_path(mcwd, cwd):
            continue
        age = now - ts
        if age < 0 or age > float(ttl_s):
            continue
        if sid not in cand or ts > cand[sid]:
            cand[sid] = ts
    ordered = sorted(cand.items(), key=lambda kv: (-kv[1], kv[0]))
    if ordered:
        return {"sid": ordered[0][0] if len(ordered) == 1 else "",
                "ambiguous": len(ordered) > 1,
                "candidates": [{"sid": s, "epoch": e} for s, e in ordered],
                "source": "shard"}
    if saw_shard:
        # 写侧已分片：无匹配/全过期 ⟹ 返回空（由调用方告警/回落），**禁读单槽**。
        return {"sid": "", "ambiguous": False, "candidates": [], "source": "shard_no_match"}
    # legacy：无任何分片（旧 writer）⟹ 才读单槽
    try:
        cols = (d / ".gatekeeper.session").read_text(encoding="utf-8").splitlines()[0].split("\t")
        if (len(cols) >= 4 and _SID_RE.match(cols[0].strip() or "")
                and _same_path(cols[3].strip(), cwd)):
            ts = float(cols[1])
            if 0 <= now - ts <= float(ttl_s):
                return {"sid": cols[0].strip(), "ambiguous": False,
                        "candidates": [{"sid": cols[0].strip(), "epoch": ts}],
                        "source": "legacy_global"}
    except (OSError, ValueError, IndexError):
        pass
    return {"sid": "", "ambiguous": False, "candidates": [], "source": ""}


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: locate --path <p> | check --path <p> (--sid <id>|--cwd <d>)... | "
              "claim --path <p> --sid <id> | allocated --path <p> | "
              "marker --dir <skill> --cwd <d> [--ttl N] | "
              "callers --cwd <d> | whoami --cwd <p>")
        return 2
    cmd, path, cwd, sids, force = argv[0], "", "", [], False
    skill_dir, ttl = "", 1800.0
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--force":
            force, i = True, i + 1
        elif a == "--path" and i + 1 < len(argv):
            path = argv[i + 1]
            i += 2
        elif a == "--cwd" and i + 1 < len(argv):
            cwd = argv[i + 1]
            i += 2
        elif a == "--dir" and i + 1 < len(argv):
            skill_dir = argv[i + 1]
            i += 2
        elif a == "--ttl" and i + 1 < len(argv):
            try:
                ttl = float(argv[i + 1])
            except ValueError:
                ttl = 1800.0
            i += 2
        elif a == "--sid" and i + 1 < len(argv):
            sids.append(argv[i + 1])
            i += 2
        else:
            print(json.dumps({"ok": False, "error": "unknown arg: %r" % a}, ensure_ascii=False))
            return 2
    try:
        if cmd == "locate":
            out = locate(path)
        elif cmd == "whoami":
            out = {"ok": True, "sid": caller_id(cwd or os.getcwd())}
        elif cmd == "marker":
            # 裸 sid 出口；**多候选 = rc=3**（调用方必须告警/回落，禁猜）。
            r = marker_candidates(skill_dir or str(Path(__file__).resolve().parent.parent),
                                  cwd or os.getcwd(), ttl_s=ttl)
            if r.get("ambiguous"):
                sys.stderr.write("WARN[session-identity]: marker ambiguous: %s\n"
                                 % ", ".join(x["sid"] for x in r.get("candidates") or []))
                return 3
            if r.get("sid"):
                print(r["sid"])
            return 0
        elif cmd == "callers":
            out = {"ok": True, "ids": caller_identities(cwd or os.getcwd(), sids)}
        elif cmd == "allocated":
            # 裸 token 出口（与 `gk_session_identity.py derive` 同形，供 CLI `$()` 直接消费）；
            # 无认领/过期 ⟹ 空行 + rc=1（调用方回落 legacy 链）。
            tok = allocated_sid(path)
            print(tok)
            return 0 if tok else 1
        elif cmd == "claim":
            loc = locate(path)
            out = claim(loc["worktree"] or path, sids, force=force)
        elif cmd == "check":
            ids = caller_identities(cwd, sids) if cwd else sids
            out = check(path, ids)
        else:
            print(json.dumps({"ok": False, "error": "unknown cmd: %r" % cmd}, ensure_ascii=False))
            return 2
    except Exception as e:  # noqa: BLE001 — CLI 边界 fail-loud，不裸抛
        print(json.dumps({"ok": False, "error": "%s: %s" % (type(e).__name__, e)},
                         ensure_ascii=False))
        return 2
    print(json.dumps(out, ensure_ascii=False))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())

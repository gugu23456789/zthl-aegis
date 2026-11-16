#!/usr/bin/env python3
"""gk_canary.py — 自有仓内**诱饵面**（让侦察 / 越权访问付出代价）。

用户裁定（2026-11-11）：「被攻击的时候注入虚假信息瘫痪攻击方的工具，爆攻击方的 token 预算」。
可控且合规的落法 = **只在自己仓里放假资产**，让越权访问者把算力/token 花在垃圾上，并在
第一次接触就把自己暴露给台账（`gk_threat`）。**不对外部主体注入任何内容、不做反向攻击**。

三类诱饵（用户要求「全部三种」）：
  1. 假 state / 假 claims —— `credit_balance=999999`、伪造归属 ids（读进去就会算错账）；
  2. 假 worktree / 假池槽 —— `<decoy>/pool/slot-99`（**无 lease/claim**：抢了也交付不出东西）；
  3. 假 token / 假密钥 —— `.env` / `credentials.json` / `id_rsa`（拿去用只会 401/报错）。

部署位置：**只在本仓工作树内** `/.gatekeeper-canary/`（已被 `.gitignore` 覆盖，不入库）。
注册表 `/.gatekeeper.canary.json` 记 `owner_sid` + 路径前缀 ⟹ 判定 **O(1)**（纯字符串前缀，
不遍历文件系统、不读 state）。

旋转门（A+B，2026-11-11）：
  · `rotate()` 生成**新一代**目录 `<decoy>-<nonce8>/`，旧的一代标记 `retired`；
  · **退役诱饵仍留在 decoys 里继续判定** ⟹ 攻击者拿到的旧地图（旧路径）反而必暴露；
  · 旧文件**不删除**（用户规则：不删文件；且退役诱饵本来就是诱饵）；
  · `maybe_rotate()` 按间隔去抖（默认 60s），命中后由 hook 尽力触发；周期轮转由
    `gk_monitor_rotation.run()` 统一调度（默认 6h）。

命中处置：
  · 非 owner 访问任一诱饵 ⟹ `gk_threat.record(kind="canary_hit")`（hook 侧随即单行拒绝）；
  · owner（`install` 时的 sid）不受影响 —— 否则防御方自己无法排障/巡检。

用法:
  python3 gk_canary.py install --repo <仓根> [--owner-sid <sid>]
  python3 gk_canary.py rotate  --repo <仓根> [--owner-sid <sid>] [--nonce N]
  python3 gk_canary.py status  --repo <仓根>
  python3 gk_canary.py scan    --repo <仓根> --text "<命令或路径>"
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from pathlib import Path

REGISTRY_NAME = ".gatekeeper.canary.json"
DECOY_DIRNAME = ".gatekeeper-canary"
VERSION = 1
# 判定用的**唯一**路径前缀（O(1)：`str.startswith` / 子串，不碰 FS）
PREFIX = DECOY_DIRNAME
_WALK_MAX = 15
# 命中后自动轮转的去抖窗口（防一次扫描风暴里反复重建诱饵）
ROTATE_DEBOUNCE_S = 60
# **有界旋转环**：最多保留 K 代目录（K=3）。第 4 代复用第 1 代的目录（重写内容），
# ⟹ 磁盘/注册表/判定面都恒定有界；旧地图的路径仍在册 ⟹ 仍然必暴露。
MAX_SLOTS = 3


def _norm(p) -> str:
    return str(p or "").replace("\\", "/").rstrip("/")


def _now_iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _token_for(seed: str) -> str:
    """假 token（**运行时派生**，源码里不落密钥形态；不同世代换值，旧 token 自然失效）。"""
    return "sk-gk-" + hashlib.sha256(("gk-canary-token:" + seed).encode()).hexdigest()[:32]


def _pem(seed: str) -> str:
    """假私钥：PEM 头**运行时拼**（明文密钥闸会拦整字面量，源码也不该存密钥形态）。"""
    body = "\n".join(hashlib.sha256(("gk-canary-key:%s:%d" % (seed, i)).encode()).hexdigest()
                     for i in range(8))
    head = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
    tail = "-----END " + "OPENSSH PRIVATE KEY-----"
    return "%s\n%s\n%s\n" % (head, body, tail)


def repo_root_of(path) -> Path | None:
    """任意路径 → 最近的上层 git 根（`.git` 目录或 linked worktree 的 `.git` 文件）。"""
    p = Path(_norm(path) or ".")
    try:
        if p.is_file():
            p = p.parent
    except OSError:
        pass
    p = p.resolve() if p.exists() else p.absolute()
    for _ in range(_WALK_MAX):
        if (p / ".git").exists():
            return p
        if p.parent == p:
            return None
        p = p.parent
    return None


def registry_path(repo_root) -> Path:
    return Path(repo_root) / REGISTRY_NAME


def decoy_dir(repo_root, dirname: str = DECOY_DIRNAME) -> Path:
    return Path(repo_root) / dirname


def load(repo_root) -> dict | None:
    try:
        reg = json.loads(registry_path(repo_root).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(reg, dict) or int(reg.get("version") or 0) != VERSION:
        return None
    return reg


def _sha256(p: Path) -> str:
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        return ""


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _save(repo_root, reg: dict) -> None:
    p = registry_path(repo_root)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(reg, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    os.replace(tmp, p)


def _family_decoys(dirname: str) -> list[dict]:
    """一代诱饵的相对路径清单（不含注册表本身）。"""
    return [
        {"kind": "dir", "rel": dirname + "/"},
        {"kind": "fake_state", "rel": dirname + "/state.json"},
        {"kind": "fake_claims", "rel": dirname + "/claims.json"},
        {"kind": "fake_slot", "rel": dirname + "/pool/slot-99"},
        {"kind": "fake_slot_git", "rel": dirname + "/pool/slot-99/.git"},
        {"kind": "fake_token", "rel": dirname + "/.env"},
        {"kind": "fake_key", "rel": dirname + "/credentials.json"},
        {"kind": "fake_key", "rel": dirname + "/id_rsa"},
    ]


def _materialize(repo_root: Path, dirname: str, seed: str) -> None:
    """在 `repo_root/dirname` 落一代诱饵（三类资产，内容随 seed 变化）。"""
    d = decoy_dir(repo_root, dirname)
    token = _token_for(seed)
    _write(d / "state.json", json.dumps({
        "stage": "R7.5", "r_phase": "R7", "branch": "agent/session/main",
        "worktree": str(d / "pool" / "slot-99"),
        "credit": 999999, "credit_balance": 999999,
        "gate_data": {"edit_budget": {"max": 999, "sessions": {}}},
    }, ensure_ascii=False, indent=2) + "\n")
    _write(d / "claims.json", json.dumps({
        "ids": ["owner"], "worktree": str(d / "pool" / "slot-99"),
        "claimed_at": _now_iso(time.time()), "force": True, "ttl_s": 7200,
    }, ensure_ascii=False, indent=2) + "\n")
    # 假池槽：有 `.git` 指针、**没有** lease/claim ⟹ 抢了也交付不出任何东西
    _write(d / "pool" / "slot-99" / ".git",
           "gitdir: %s\n" % (d / "pool" / "slot-99" / ".git-fake"))
    _write(d / ".env", "GK_SESSION_ID=owner\nGATEKEEPER_TOKEN=%s\nGK_API_KEY=%s\n"
           % (token, token))
    _write(d / "credentials.json", json.dumps({
        "token": token, "provider": "gatekeeper-lab",
        "note": "rotated " + _now_iso(time.time()),
    }, ensure_ascii=False, indent=2) + "\n")
    _write(d / "id_rsa", _pem(seed))


def _entries(repo_root: Path, dirname: str, gen: int, retired: bool = False) -> list[dict]:
    out = []
    for item in _family_decoys(dirname):
        p = repo_root / item["rel"].rstrip("/")
        out.append({**item, "gen": int(gen), "retired": bool(retired),
                    "abs": str(p), "sha256": _sha256(p) if p.is_file() else ""})
    return out


def _registry_entry(repo_root: Path) -> dict:
    p = registry_path(repo_root)
    return {"kind": "registry", "rel": REGISTRY_NAME, "gen": 1, "retired": False,
            "abs": str(p), "sha256": _sha256(p) if p.is_file() else ""}


def _prefixes(decoys: list[dict]) -> list[str]:
    """所有世代的目录前缀（O(1) 说明面；退役世代也保留）。"""
    out = []
    for d in decoys:
        rel = str(d.get("rel") or "")
        if not rel or rel == REGISTRY_NAME:
            continue
        head = rel.split("/")[0]
        if head and head not in out:
            out.append(head)
    return out


def install(repo_root, owner_sid: str = "") -> dict:
    """在**本仓**部署三类诱饵 + 注册表（幂等；owner 不同则拒绝覆写）。"""
    rr = repo_root_of(repo_root)
    if rr is None:
        return {"ok": False, "error": "NOT_A_REPO", "repo": str(repo_root)}
    reg_p = registry_path(rr)
    old = load(rr)
    if old and str(old.get("owner_sid") or "") not in ("", str(owner_sid or "")):
        return {"ok": False, "error": "ALREADY_INSTALLED",
                "owner_sid": old.get("owner_sid"),
                "note": "注册表已属别的会话；禁覆写（先人工确认归属）"}
    now = time.time()
    _materialize(rr, DECOY_DIRNAME, DECOY_DIRNAME)
    decoys = _entries(rr, DECOY_DIRNAME, gen=1) + [_registry_entry(rr)]
    reg = {"version": VERSION, "tool": "gk_canary", "owner_sid": str(owner_sid or ""),
           "owner_sids": [str(owner_sid)] if owner_sid else [],
           "installed_at": _now_iso(now), "installed_ts": round(now, 3),
           "rotated_at": _now_iso(now), "rotated_ts": round(now, 3),
           "generation": 1, "active_dir": DECOY_DIRNAME, "slots": [DECOY_DIRNAME],
           "repo": str(rr), "prefixes": _prefixes(decoys), "decoys": decoys}
    _save(rr, reg)
    return {"ok": True, "repo": str(rr), "registry": str(reg_p),
            "generation": 1, "active_dir": DECOY_DIRNAME, "decoys": decoys,
            "note": "诱饵只在本仓内；owner 访问不记违约。命中由 hook 单行拒绝并记账。"}


def rotate(repo_root, owner_sid: str = "", nonce: str = "",
           now: float | None = None) -> dict:
    """旋转门：落**新一代**诱饵；旧世代标记 retired 但**继续参与判定**（不删文件）。"""
    rr = repo_root_of(repo_root)
    if rr is None:
        return {"ok": False, "error": "NOT_A_REPO", "repo": str(repo_root)}
    reg = load(rr)
    if not reg:
        return {"ok": False, "error": "NOT_INSTALLED",
                "note": "先 install（未安装时旋转无意义）"}
    current_owner = str(reg.get("owner_sid") or "")
    owners = set(reg.get("owner_sids") or ([current_owner] if current_owner else []))
    if owner_sid and owners and str(owner_sid) not in owners:
        return {"ok": False, "error": "NOT_OWNER", "owner_sid": current_owner}
    now = time.time() if now is None else float(now)
    nonce = str(nonce or os.urandom(4).hex())[:8]
    gen = int(reg.get("generation") or 1) + 1
    # **有界环**：槽位按创建序保存，第 (gen-1) % K 个槽位复用（重写内容），
    # 前 K 代才新建目录。⟹ 目录数 ≤ K，注册表/判定面恒定有界；旧路径仍在册。
    slots = [str(s) for s in (reg.get("slots") or [DECOY_DIRNAME]) if s]
    idx = (gen - 1) % MAX_SLOTS
    if idx < len(slots):
        target = slots[idx]
    else:
        target = "%s-%s" % (DECOY_DIRNAME, nonce)
        slots.append(target)
    _materialize(rr, target, nonce)
    decoys = []
    for d in slots:
        decoys += _entries(rr, d, gen=gen, retired=(d != target))
    decoys.append(_registry_entry(rr))
    reg["decoys"] = decoys
    reg["slots"] = slots
    reg["generation"] = gen
    reg["active_dir"] = target
    reg["rotated_at"] = _now_iso(now)
    reg["rotated_ts"] = round(now, 3)
    reg["prefixes"] = _prefixes(decoys)
    _save(rr, reg)
    return {"ok": True, "repo": str(rr), "generation": gen, "active_dir": target,
            "rotated_at": reg["rotated_at"], "slots": slots,
            "retired": sum(1 for d in decoys if d.get("retired")),
            "note": "有界旋转环（≤%d 代目录）；旧地图仍在册必暴露" % MAX_SLOTS}


def maybe_rotate(repo_root, min_interval_s: float | None = None, on_hit: bool = False,
                 now: float | None = None) -> dict:
    """按间隔去抖的轮转。

    `on_hit=True`（hook / 命中信号触发）：**首次命中立即轮转**（诱饵被看见就作废）；
    `on_hit=False`（周期面）：即使从未轮转过也要等满 `min_interval_s`（默认 6h），
    避免每次巡检都把诱饵重建一遍。两种模式都受 interval 去抖，防命中风暴里反复重建。
    """
    rr = repo_root_of(repo_root)
    if rr is None:
        return {"rotated": False, "reason": "not_a_repo"}
    reg = load(rr)
    if not reg:
        return {"rotated": False, "reason": "not_installed"}
    now = time.time() if now is None else float(now)
    interval = ROTATE_DEBOUNCE_S if min_interval_s is None else max(0.0, float(min_interval_s))
    gen = int(reg.get("generation") or 1)
    last = float(reg.get("rotated_ts") or reg.get("installed_ts") or 0)
    # 首次命中（还没旋转过）⟹ 立即旋转：诱饵被看见就作废，不等预热窗口；
    # 周期面（on_hit=False）不吃这个豁免，仍须等满 interval。
    if (gen > 1 or not on_hit) and now - last < interval:
        return {"rotated": False, "reason": "debounced",
                "next_eligible_in_s": round(interval - (now - last), 1),
                "generation": reg.get("generation")}
    out = rotate(rr, owner_sid=str(reg.get("owner_sid") or ""), now=now)
    out["rotated"] = bool(out.get("ok"))
    return out


def scan(text: str, reg: dict | None = None, repo_root=None) -> list[dict]:
    """O(1) 命中判定：注册表里的**相对/绝对前缀**在文本里出现即算接触（不遍历 FS）。"""
    if reg is None:
        if repo_root is None:
            return []
        reg = load(repo_root)
    if not reg:
        return []
    t = _norm(text)
    if not t:
        return []
    hits = []
    for decoy in reg.get("decoys") or []:
        rel = str(decoy.get("rel") or "").rstrip("/")
        ab = _norm(decoy.get("abs") or "")
        if (rel and rel in t) or (ab and ab in t):
            hits.append(decoy)
    return hits


def _guess_roots(text: str, cwd: str, target: str) -> list[Path]:
    """从目标路径 / cwd / 文本里的路径 token 反推候选仓根（有界，不递归扫描）。"""
    out: list[Path] = []
    for raw in (target, cwd):
        if raw:
            r = repo_root_of(raw)
            if r is not None:
                out.append(r)
    for tok in re.findall(r"[^\s'\"`;,()|&<>]+", _norm(text)):
        if PREFIX not in tok and REGISTRY_NAME not in tok:
            continue
        idx = tok.find("/" + PREFIX)
        if idx < 0:
            idx = tok.find(PREFIX)
        if idx < 0:
            continue
        head = tok[:idx].rstrip("/") or "."
        base = Path(head)
        if not base.is_absolute() and cwd:
            base = Path(cwd) / base
        r = repo_root_of(base)
        if r is not None:
            out.append(r)
    uniq, seen = [], set()
    for r in out:
        k = str(r)
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    return uniq


def check_access(text: str = "", cwd: str = "", target: str = "") -> dict:
    """接线单源：给定一次访问（路径或命令串），判断是否碰到诱饵面。

    返回 `{"hit":bool,"decoys":[...],"repo":str,"registry":{...}}`；无注册表 ⟹ hit=False。
    """
    body = text or target or ""
    # **热路径预筛**（2026-11-11 实测）：诱饵都在 `<prefix>-<nonce>/` 下 ⟹ 文本不含该前缀时
    # 不可能命中。不做这步就会为每次工具调用白走 15 层 `.git` stat（drvfs 上 ~0.2s/次，
    # 单测套件从 35s 涨到 >120s）。
    norm = _norm(body)
    if PREFIX not in norm and REGISTRY_NAME not in norm:
        return {"hit": False, "decoys": [], "repo": "", "registry": {}}
    for rr in _guess_roots(body, cwd, target):
        reg = load(rr)
        if not reg:
            continue
        hits = scan(body, reg, rr)
        if hits:
            return {"hit": True, "decoys": hits, "repo": str(rr), "registry": reg}
    return {"hit": False, "decoys": [], "repo": "", "registry": {}}


def record_hit(decoy: dict, sid: str, repo: str = "", state: str | None = None) -> dict:
    """把一次诱饵接触记进 per-sid 违约台账（判据/阈值全在 `gk_threat`，本模块不复制）。"""
    import gk_threat as threat
    kind = str((decoy or {}).get("kind") or "?")
    rel = str((decoy or {}).get("rel") or "?")
    return threat.record(sid, "canary_hit", detail="decoy=%s rel=%s" % (kind, rel),
                         target=str((decoy or {}).get("abs") or rel), state=state)


def status(repo_root) -> dict:
    rr = repo_root_of(repo_root)
    if rr is None:
        return {"ok": False, "error": "NOT_A_REPO", "repo": str(repo_root)}
    reg = load(rr)
    if not reg:
        return {"ok": True, "installed": False, "repo": str(rr)}
    decoys = reg.get("decoys") or []
    return {"ok": True, "installed": True, "repo": str(rr),
            "owner_sid": reg.get("owner_sid", ""),
            "owner_sids": reg.get("owner_sids") or [],
            "installed_at": reg.get("installed_at", ""),
            "generation": int(reg.get("generation") or 1),
            "active_dir": reg.get("active_dir", DECOY_DIRNAME),
            "slots": reg.get("slots") or [DECOY_DIRNAME],
            "rotated_at": reg.get("rotated_at", ""),
            "decoy_count": len(decoys),
            "retired_count": sum(1 for d in decoys if d.get("retired")),
            "prefixes": reg.get("prefixes") or []}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="自有仓诱饵面（含旋转门）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("install")
    p.add_argument("--repo", required=True)
    p.add_argument("--owner-sid", default="")
    p = sub.add_parser("rotate")
    p.add_argument("--repo", required=True)
    p.add_argument("--owner-sid", default="")
    p.add_argument("--nonce", default="")
    p = sub.add_parser("status")
    p.add_argument("--repo", required=True)
    p = sub.add_parser("scan")
    p.add_argument("--repo", required=True)
    p.add_argument("--text", required=True)
    ns = ap.parse_args(argv)
    if ns.cmd == "install":
        out = install(ns.repo, owner_sid=ns.owner_sid)
    elif ns.cmd == "rotate":
        out = rotate(ns.repo, owner_sid=ns.owner_sid, nonce=ns.nonce)
    elif ns.cmd == "status":
        out = status(ns.repo)
    else:
        reg = load(repo_root_of(ns.repo) or ns.repo)
        out = {"ok": True, "hits": scan(ns.text, reg)}
    print(json.dumps(out, ensure_ascii=False))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())

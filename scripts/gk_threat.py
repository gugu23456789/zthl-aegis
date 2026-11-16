#!/usr/bin/env python3
"""gk_threat.py — 攻防**违约台账**（per-sid，append-only，侧挂主 state）。

定位（用户口径 2026-11-11「让攻击不划算」）：**不对任何外部主体做反制**，只在本仓边界内
做三件事 —— **记账 → 分级 → 隔离**：

  · 诱饵命中（`gk_canary`）/ 越界尝试等违约 ⟹ `record()` 在文件尾追加一行 JSON；
  · 窗口内计数分级：`normal(0)` / `suspicious(>=1)` / `quarantined(>=3)`；
  · `quarantined` ⟹ `pre_tool_hook` 走单行**零信息**拒绝（`SINGLE_LINE`：无 state、无路径、
    无原因），让对方拿不到任何可用于调整策略的信号；
  · 窗口滑动 = decay（读侧过滤，**不重写**文件）；显式 `decay()` 才压缩（先归档再重写）。

存储：`<state>.threat.<sid-sha16>.jsonl`（与 `.gatekeeper.state` 同目录；被仓内
`.gatekeeper.state*` 忽略规则覆盖 ⟹ 不入库、不污染 `git status`）。**append-only**：
只在文件尾追加，`reset()` 也只改名归档（不删文件）。

边界（不可越）：
  · 不对外部主体注入任何内容、不反向攻击、不反洪泛 —— 真实的 DDoS 只做**准入控制**
    （既有 `gk_sandbox` 限额），本模块不产生任何对外流量；
  · 台账是**证据**，不是命令：本模块除本地文件读写外不起子进程、不发网络请求。

用法：
  python3 gk_threat.py record --sid <sid> --kind canary_hit --detail "..." [--state <state>]
  python3 gk_threat.py status --sid <sid> [--state <state>]
  python3 gk_threat.py check  --sid <sid> [--state <state>]      # exit 0=放行 / 3=隔离
  python3 gk_threat.py reset  --sid <sid> [--state <state>]      # 改名归档（不删）
  python3 gk_threat.py decay  --sid <sid> [--state <state>]      # 归档后只留窗口内
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

# 窗口 / 阈值（env 仅给测试与运维逃生，生产走默认）
WINDOW_S_DEFAULT = 3600          # 1h 滑动窗口
SUSPICIOUS_AT_DEFAULT = 1        # 窗口内 1 次违约 ⟹ suspicious
QUARANTINE_AT_DEFAULT = 3        # 窗口内 3 次违约 ⟹ quarantined
# 额度冷却期（只读投影，见 `budget_freeze`）：隔离期间 hook 已 exit 2 ⟹ 真正可观测的
# 限制面是「解除后冷却期」——最近一次违约距今 < 本值 ⟹ advance 注入额度减半。
COOLDOWN_S_DEFAULT = 3600
COOLDOWN_ENV = "GK_THREAT_BUDGET_COOLDOWN_S"
BANK_KEY_MIN = 8                 # 台账 sid ↔ 额度银行会话键的**最短**前缀对齐长度
SKILL_DIR = Path(__file__).resolve().parent.parent
_SESSION_ALIAS_PREFIX = ".gatekeeper.session.alias."
# 台账是 append-only 的：攻击持续时文件会变长。hook 每次工具调用都要查一次 ⟹ 只读尾部
# 固定字节（判级只需最近若干笔；阈值 3 ⟹ 256KB 足够容纳数万笔）。避免"防护自己把 hook 拖慢"。
READ_MAX_BYTES = 256 * 1024
LEVELS = ("normal", "suspicious", "quarantined")
# 被隔离方**唯一**能看到的一行（零信息：不含错误码 / 路径 / 原因 / state）
SINGLE_LINE = "GATEKEEPER: request rejected."
BYPASS_ENV = "GK_THREAT_BYPASS"
_ANON = "__anon__"


def _int_env(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


def window_s() -> int:
    return _int_env("GK_THREAT_WINDOW_S", WINDOW_S_DEFAULT, 1)


def suspicious_at() -> int:
    return _int_env("GK_THREAT_SUSPICIOUS_AT", SUSPICIOUS_AT_DEFAULT, 1)


def quarantine_at() -> int:
    # 隔离阈值恒 >= suspicious 阈值（env 写反时以 suspicious 为准，避免「1 次就隔离」）
    return max(suspicious_at(), _int_env("GK_THREAT_QUARANTINE_AT",
                                         QUARANTINE_AT_DEFAULT, 1))


def cooldown_s() -> int:
    """额度冷却期（秒）。只读投影用，**不改变** `check()` 的 1h 隔离判决。"""
    return _int_env(COOLDOWN_ENV, COOLDOWN_S_DEFAULT, 1)


def state_file(state: str | None = None) -> Path:
    """主 state 路径（env `STATE_FILE` > 显式参数 > 本仓默认），只用来定位同目录台账。"""
    s = str(state or os.environ.get("STATE_FILE") or "").strip()
    if s:
        return Path(s)
    return Path(__file__).resolve().parent.parent / ".gatekeeper.state"


def _slug(sid: str) -> str:
    """sid → 文件名（sha16；禁路径穿越，禁把 sid 明文写进目录名）。"""
    return hashlib.sha256((sid or _ANON).encode("utf-8", "replace")).hexdigest()[:16]


def ledger_path(sid: str, state: str | None = None) -> Path:
    st = state_file(state)
    return st.with_name(st.name + ".threat." + _slug(sid) + ".jsonl")


def level_of(count: int) -> int:
    if count >= quarantine_at():
        return 2
    if count >= suspicious_at():
        return 1
    return 0


def level_name(level: int) -> str:
    return LEVELS[max(0, min(2, int(level)))]


def _clip(v, n: int = 300) -> str:
    s = str(v or "").replace("\n", " ").replace("\r", " ")
    return s[:n]


def record(sid: str, kind: str, detail: str = "", target: str = "",
           state: str | None = None, now: float | None = None) -> dict:
    """追加一条违约（**永不抛**：记账失败也不得把门禁变成崩溃面）。"""
    sid = str(sid or "").strip() or _ANON
    now = time.time() if now is None else float(now)
    rec = {"ts": round(now, 3),
           "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
           "sid": _clip(sid, 120), "kind": _clip(kind, 60),
           "detail": _clip(detail), "target": _clip(target)}
    p = ledger_path(sid, state)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as e:  # 只读盘 / 权限问题：记账失败，但不影响调用方继续判级
        return {"ok": False, "error": "RECORD_FAILED", "detail": "%s: %s" % (type(e).__name__, e),
                "sid": sid, "kind": rec["kind"]}
    st = status(sid, state=state, now=now)
    return {"ok": True, "recorded": rec, "sid": sid,
            "level": st["level"], "name": st["name"],
            "count": st["count"], "window_s": st["window_s"]}


def _read_tail(p: Path, max_bytes: int = READ_MAX_BYTES) -> str:
    """读文件尾部（最多 `max_bytes`）；超过时从**首个完整行**起返回。

    台账按时间追加 ⟹ 尾部即最新；判级只看最近窗口，不需要全文件（见 `READ_MAX_BYTES` 注释）。
    """
    try:
        with open(p, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            start = max(0, size - max(1, int(max_bytes)))
            f.seek(start)
            data = f.read()
    except OSError:
        return ""
    text = data.decode("utf-8", "replace")
    if start > 0:
        nl = text.find("\n")
        text = text[nl + 1:] if nl >= 0 else ""     # 丢掉被截断的首行
    return text


def events(sid: str, state: str | None = None, window: int | None = None,
           now: float | None = None) -> list[dict]:
    """窗口内事件（decay = 读侧过滤；文件本身只增不改；只读尾部有界字节）。"""
    sid = str(sid or "").strip() or _ANON
    now = time.time() if now is None else float(now)
    win = window_s() if window is None else int(window)
    lo = now - max(1, win)
    out = []
    text = _read_tail(ledger_path(sid, state))
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            rec = json.loads(ln)
            ts = float(rec.get("ts"))
        except (ValueError, TypeError, AttributeError):
            continue
        # `ts` 落盘时 round(…,3) 会**上取整**（实测：刚写的记录因 ts > now 被自己漏数），
        # 故上界放宽 1e-3：保证「刚 record 完立刻 check」计数正确（下界保持严格）。
        if lo <= ts <= now + 1e-3:
            out.append(rec)
    return out


def events_all(state: str | None = None, window: int | None = None,
               now: float | None = None) -> list[dict]:
    """**跨 sid** 的窗口内事件（monitor 事件驱动消费面；只读，不改任何台账）。

    只扫 `<state>.threat.*.jsonl`（per-sid 文件名由 `ledger_path` 单源派生），
    按 `ts` 升序返回，每条形如 `{ts, iso, sid, kind, detail, target}`。
    """
    now = time.time() if now is None else float(now)
    win = window_s() if window is None else int(window)
    lo = now - max(1, win)
    st = state_file(state)
    d, prefix = st.parent, st.name + ".threat."
    out = []
    try:
        # 只认 per-sid 台账（`<state>.threat.<sid-sha16>.jsonl`）；
        # 同前缀还有 `.threat.monitor.jsonl` 等**派生审计面**，混进来会被当成新违约（实测踩中）。
        files = sorted(p for p in d.glob(prefix + "*.jsonl")
                       if re.match(r"^[0-9a-f]{16}\.jsonl$", p.name[len(prefix):]))
    except OSError:
        return out
    for p in files:
        text = _read_tail(p)          # 跨 sid 聚合也只读各文件尾部（有界）
        for ln in text.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                rec = json.loads(ln)
                ts = float(rec.get("ts"))
            except (ValueError, TypeError, AttributeError):
                continue
            if lo <= ts <= now + 1e-3:
                out.append(rec)
    out.sort(key=lambda r: float(r.get("ts") or 0))
    return out


def status(sid: str, state: str | None = None, window: int | None = None,
           now: float | None = None) -> dict:
    evs = events(sid, state=state, window=window, now=now)
    by_kind: dict[str, int] = {}
    for e in evs:
        k = str(e.get("kind") or "?")
        by_kind[k] = by_kind.get(k, 0) + 1
    lvl = level_of(len(evs))
    return {"ok": True, "sid": str(sid or "").strip() or _ANON,
            "level": lvl, "name": level_name(lvl), "count": len(evs),
            "window_s": window_s() if window is None else int(window),
            "suspicious_at": suspicious_at(), "quarantine_at": quarantine_at(),
            "by_kind": by_kind}


def _sid_match(row_sid: str, sid: str) -> bool:
    """台账**行内明文 sid** ↔ 调用方 sid：精确相等，或单向前缀对齐（短者 ≥ `BANK_KEY_MIN`）。

    为什么不能只比文件名：文件名是 `sha256(sid)[:16]`，而两侧 sid 命名空间并不天然一致 ——
    台账用 hook 的 `_env_sid or _pay_sid`（常见 24 hex），额度银行用 CLI 的 `GK_SESSION_ID`
    （常见 worktree 8 hex）。同一会话两种写法 ⟹ 只认精确相等会**静默失联**（fail-open）。
    前缀对齐只在短串已足够长时成立，避免 `a` / `ab` 这类短串互相误配。
    """
    a, b = str(row_sid or "").strip(), str(sid or "").strip()
    if not a or not b:
        return False
    if a == b:
        return True
    short, long_ = (a, b) if len(a) <= len(b) else (b, a)
    return len(short) >= BANK_KEY_MIN and long_.startswith(short)


def session_alias(sid: str, state: str | None = None) -> str:
    """载荷 sid → worktree token（`pre_tool_hook._write_session_alias` 落盘的别名分片）。

    同一次对话有**两个身份**：hook 台账记载荷 sid（24 hex），额度银行用 worktree token
    （8 hex，CLI 侧由 `$PWD` 派生）。两者**不是**同一哈希的截断 ⟹ 只能靠别名文件对齐；
    无别名 / 坏文件 ⟹ 空串（调用方仍可退回前缀对齐）。

    查找面（顺序）：state 文件同目录 → 本模块所在技能根。hook 的别名写在**部署侧**技能根，
    而开发工作树里的模块副本读不到它 ⟹ 必须同时认 state 同目录（隔离 state 也满足）。
    """
    s = str(sid or "").strip()
    if not s:
        return ""
    name = _SESSION_ALIAS_PREFIX + s
    dirs = []
    st = str(state or os.environ.get("STATE_FILE") or "").strip()
    if st:
        dirs.append(Path(st).parent)
    dirs.append(SKILL_DIR)
    for d in dirs:
        try:
            v = (d / name).read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if v:
            return v
    return ""


def last_event(sid: str, state: str | None = None, window: int | None = None,
               now: float | None = None) -> dict:
    """窗口内**最近一次**违约（只读）。

    先查本 sid 的台账（快路径），再扫全部 per-sid 台账按**行内明文 sid** 对齐
    （精确 / 前缀 / **别名分片**双向解析）。不写任何文件。
    """
    sid = str(sid or "").strip()
    now = time.time() if now is None else float(now)
    win = cooldown_s() if window is None else int(window)
    cands = [c for c in (sid, session_alias(sid, state=state)) if c]
    _alias_cache: dict[str, str] = {}

    def _hit(row_sid: str) -> bool:
        if any(_sid_match(row_sid, c) for c in cands):
            return True
        if row_sid not in _alias_cache:   # 洪泛时同一 sid 多行 ⟹ 别名只读一次
            _alias_cache[row_sid] = session_alias(row_sid, state=state)
        tok = _alias_cache[row_sid]       # 反向：行内 sid 的 token 是否等于我方 sid
        return bool(tok) and any(_sid_match(tok, c) for c in cands)

    matched = list(events(sid, state=state, window=win, now=now)) if sid else []
    if sid:
        matched += [r for r in events_all(state=state, window=win, now=now)
                    if _hit(str(r.get("sid") or ""))]
    # 两份来源可能重叠（本 sid 的台账也在 `events_all` 里）⟹ 按内容去重，防 count 虚高
    uniq = {(str(r.get("ts")), str(r.get("sid")), str(r.get("kind")),
             str(r.get("target")), str(r.get("detail"))): r for r in matched}
    best = None
    for rec in uniq.values():
        try:
            ts = float(rec.get("ts") or 0)
        except (TypeError, ValueError):
            continue
        if best is None or ts > best:
            best = ts
    return {"found": best is not None, "count": len(uniq), "sid": sid or _ANON,
            "last_ts": best, "age_s": (max(0.0, now - best) if best is not None else None)}


def budget_freeze(sid: str, state: str | None = None, now: float | None = None,
                  cooldown: int | None = None) -> dict:
    """冷却期判据（**只读投影**）：最近一次违约距今 < 冷却期 ⟹ `active=True`。

    消费面约定（见 `references/violation-charter.md` §4.1）：
      · 调用方**只**允许据此**封顶注入额度**（advance 注入点）；
      · **禁止**扣款、禁止写入熵 / 违约分、禁止据此阻断 advance（阻断面是 hook，不是这里）。
    """
    sid = str(sid or "").strip()
    now = time.time() if now is None else float(now)
    cd = cooldown_s() if cooldown is None else max(1, int(cooldown))
    le = last_event(sid, state=state, window=cd, now=now)
    cnt = int(le.get("count") or 0)
    lvl = level_of(cnt)
    return {"ok": True, "sid": sid or _ANON, "active": bool(le.get("found")),
            "cooldown_s": cd, "age_s": le.get("age_s"), "last_ts": le.get("last_ts"),
            "count": cnt, "level": lvl, "name": level_name(lvl)}


def check(sid: str, state: str | None = None, now: float | None = None) -> dict:
    """隔离判据（hook 唯一入口）。`denied=True` ⟹ 调用方回 `SINGLE_LINE` 并 exit 2。"""
    if os.environ.get(BYPASS_ENV) == "1":
        return {"ok": True, "sid": str(sid or ""), "level": 0, "name": "normal",
                "count": 0, "denied": False, "bypass": True, "line": ""}
    st = status(sid, state=state, now=now)
    denied = st["level"] >= 2
    st["denied"] = denied
    st["line"] = SINGLE_LINE if denied else ""
    return st


def reset(sid: str, state: str | None = None) -> dict:
    """解除隔离：**改名归档**（不删文件，保留证据链）。"""
    p = ledger_path(sid, state)
    if not p.exists():
        return {"ok": True, "sid": sid, "removed": False, "path": str(p)}
    dst = p.with_name(p.name + "." + str(int(time.time())) + ".archive")
    try:
        os.replace(p, dst)
    except OSError as e:
        return {"ok": False, "error": "RESET_FAILED", "detail": str(e), "path": str(p)}
    return {"ok": True, "sid": sid, "removed": True, "archived": str(dst)}


def decay(sid: str, state: str | None = None) -> dict:
    """压缩台账：先整份归档，再只保留窗口内事件（append-only 的唯一显式例外）。"""
    p = ledger_path(sid, state)
    evs = events(sid, state=state)
    if not p.exists():
        return {"ok": True, "sid": sid, "kept": 0, "dropped": 0}
    try:
        total = len([ln for ln in p.read_text(encoding="utf-8", errors="replace").splitlines()
                     if ln.strip()])
    except OSError as e:
        return {"ok": False, "error": "DECAY_FAILED", "detail": str(e)}
    arch = p.with_name(p.name + "." + str(int(time.time())) + ".archive")
    try:
        os.replace(p, arch)
    except OSError as e:
        return {"ok": False, "error": "DECAY_FAILED", "detail": str(e)}
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            for rec in evs:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as e:
        # 写失败：把归档挪回原位（宁可保留旧文件，也不留空台账）
        try:
            os.replace(arch, p)
        except OSError:
            pass
        return {"ok": False, "error": "DECAY_FAILED", "detail": str(e)}
    return {"ok": True, "sid": sid, "kept": len(evs), "dropped": max(0, total - len(evs)),
            "archived": str(arch)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="per-sid 违约台账（append-only）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def _common(p):
        p.add_argument("--sid", required=True)
        p.add_argument("--state", default="")

    p = sub.add_parser("record")
    _common(p)
    p.add_argument("--kind", required=True)
    p.add_argument("--detail", default="")
    p.add_argument("--target", default="")
    for name in ("status", "check", "reset", "decay"):
        _common(sub.add_parser(name))

    ns = ap.parse_args(argv)
    state = ns.state or None
    if ns.cmd == "record":
        out = record(ns.sid, ns.kind, ns.detail, ns.target, state=state)
    elif ns.cmd == "status":
        out = status(ns.sid, state=state)
    elif ns.cmd == "check":
        out = check(ns.sid, state=state)
    elif ns.cmd == "reset":
        out = reset(ns.sid, state=state)
    else:
        out = decay(ns.sid, state=state)
    print(json.dumps(out, ensure_ascii=False))
    if ns.cmd == "check" and out.get("denied"):
        return 3
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())

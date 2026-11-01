#!/usr/bin/env python3
"""gk_dispatch_ticket.py — Task 派发**单次票据**（方案 B，2026-10-27）。

背景（用户裁定「按方案 B 执行完整闭包，先部署票据签发和校验」）：
  「默认拒绝 Task」若无签发/校验面，等于把关键词黑名单换成一句口号 —— 关键词永远
  不是完备集（实测被「质询」类自然语言绕过）。本模块把放行依据从**文本猜测**换成
  **可验证凭据**：

    ① 默认拒绝：任何 `Task` 调用都必须带票据（判据在 hook 的 Gate 0）；
    ② 单次票据：票据 = `<nonce>.<HMAC-SHA256(nonce, sha, exp)>`，
       绑定**查询正文的规范化哈希**（`query_sha`）⟹ 票据 A 不能拿去放行查询 B；
    ③ 事后对账：（后续）比对 `docs/analysis/subagent/*.md` 与 `subagent_history`。

⚠ `session` **不参与签名**（只落库供归属/审计）：签发侧 = CLI 的 `GK_SESSION_ID`
（worktree token，如 `state-trim-lines`），校验侧 = hook 的载荷 `session_id`（24-hex）
—— 实测两者**不同源**（`gk_session_identity.derive` 实测返回 `state-trim-lines`，
而 Task 调用无 file_path ⟹ hook 回落载荷 sid）。若把 session 放进 HMAC 或做相等校验，
**所有**合法票据都会被判 `session_mismatch` ⟹ 门禁恒 BLOCK。单次 + sha 绑定已足够约束
「同一授权只能用一次」；跨会话同查询重放仍需先拿到该票据（且已被消费）。

存储：`gate_data.dispatch_tickets[]`（state 内，受 `_checksum` 保护）。条目：
  `{nonce, sha, exp, session, node, issued_at, used_at, used_by, sig}`。
  · `used_at` 非空 ⟹ 已消费（重放必拒）；
  · `exp`（epoch 秒）过期 ⟹ 拒；
  · `sha` 与本次查询不符 ⟹ 拒；
  · 签名用 `_key()`（`GK_JOURNAL_KEY` → `GATEKEEPER_HMAC_KEY` → `.keys/subagent-hmac.key`，
    与 `gk_finding` 的 journal 签名**同源**，不新建密钥文件）。**无钥即拒**（fail-closed，
    不降级为「无签名放行」—— 与 journal 的 `sig=""` 显式降级不同：这里是门禁判据）。

CLI：`state-patch --dispatch-issue <query|@file> [--ttl N]` /
     `state-patch --dispatch-verify <ticket> <query|@file>`（参数编排在 gatekeeper-cli.sh，
     本模块为唯一实现）。
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import gk_state  # noqa: E402
from gk_json_utils import state_lock  # noqa: E402

DEFAULT_TTL = 300            # 秒；单次票据的默认寿命
MAX_TTL = 3600               # 上限：禁发「长效票」（否则单次语义被稀释）
MAX_KEEP = 256               # state 内保留的票据条数上限（绑定报告的记录要留给对账）
USED_RETENTION = 7 * 86400   # 已消费票据的保留期（对账窗口；过期即剪）
TICKET_PREFIX = "GK-TICKET:"
KEY_FILE = Path(__file__).resolve().parent.parent / ".keys" / "subagent-hmac.key"

# 票据行（可内嵌在 query 内；hook 先剥离再算哈希，故剥离规则必须与本模块一致）
_TICKET_LINE_RE = re.compile(r"(?m)^[ \t]*GK-TICKET:[ \t]*(\S+)[ \t]*$")


# ── 密钥（与 gk_finding._journal_key 同优先级；文件通道供 hook 进程直读）──────────
def _key() -> bytes:
    """HMAC 密钥：`GK_JOURNAL_KEY` → `GATEKEEPER_HMAC_KEY` → `.keys/subagent-hmac.key`。

    缺失 ⟹ `b""`（调用方据此 fail-closed 拒绝签发/校验，不降级放行）。
    """
    for _name in ("GK_JOURNAL_KEY", "GATEKEEPER_HMAC_KEY"):
        v = os.environ.get(_name, "")
        if v:
            try:
                return bytes.fromhex(v) if len(v) == 64 else v.encode()
            except ValueError:
                return v.encode()
    try:
        v = KEY_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return b""
    if not v:
        return b""
    try:
        return bytes.fromhex(v) if len(v) == 64 else v.encode()
    except ValueError:
        return v.encode()


# ── 查询规范化（签发/校验必须同算法）────────────────────────────────────────
def canon_query(text: str) -> str:
    """规范化：CRLF/CR → LF，去首尾空白。"""
    return (text or "").replace("\r\n", "\n").replace("\r", "\n").strip()


def query_sha(text: str) -> str:
    """查询正文的规范化 sha256（hex）。"""
    return hashlib.sha256(canon_query(text).encode("utf-8")).hexdigest()


def extract_ticket(text: str) -> tuple:
    """从查询正文剥离票据行：返回 `(clean_text, ticket)`。

    仅剥离**首条**形如 `GK-TICKET:<token>` 的整行；其余原样保留（哈希口径 = 剥离后正文）。
    """
    m = _TICKET_LINE_RE.search(text or "")
    if not m:
        return (text or "", "")
    clean = (text or "")[:m.start()] + (text or "")[m.end():]
    return (clean, m.group(1).strip())


def _sign(key: bytes, nonce: str, sha: str, exp: int) -> str:
    """票据签名（session 不入签名，理由见模块 docstring：两侧身份链不同源）。"""
    msg = f"{nonce}\n{sha}\n{int(exp)}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _now() -> int:
    return int(time.time())


def _prune(raw, now: int) -> list:
    """票据表剪枝：未过期未消费的保留；已消费的保留 `USED_RETENTION`（供报告对账）。"""
    out = []
    for r in (raw if isinstance(raw, list) else []):
        if not isinstance(r, dict):
            continue
        if r.get("used_at"):
            if now - int(r["used_at"]) <= USED_RETENTION:
                out.append(r)
        elif int(r.get("exp") or 0) >= now:
            out.append(r)
    return out


def _resolve_query(arg: str) -> str:
    """`@file` → 文件正文；64 位 hex → 视为已算好的 sha（`sha:` 前缀同义）；否则原样。"""
    a = arg or ""
    if a.startswith("@"):
        try:
            return Path(a[1:]).read_text(encoding="utf-8")
        except OSError:
            return a
    return a


def _sha_arg(arg: str) -> str:
    """从 CLI 参数得 sha256：`@file` / 64-hex / 裸文本。"""
    a = (arg or "").strip()
    if a.startswith("@"):
        return query_sha(_resolve_query(a))
    if len(a) == 64 and all(c in "0123456789abcdefABCDEF" for c in a):
        return a.lower()
    return query_sha(_resolve_query(a))


def issue(state_path: str, query: str, ttl: int = DEFAULT_TTL, session: str = "",
          node: str = "", sha: str = "") -> dict:
    """签发单次票据：写 `gate_data.dispatch_tickets[]` 并返回票据串。"""
    key = _key()
    if not key:
        return {"ok": False, "error": "no_hmac_key",
                "hint": "无 HMAC 密钥（GK_JOURNAL_KEY/GATEKEEPER_HMAC_KEY/.keys/subagent-hmac.key）"
                        "⟹ 拒绝签发（fail-closed，不降级放行）"}
    try:
        ttl = int(ttl)
    except (TypeError, ValueError):
        return {"ok": False, "error": f"ttl 非法：{ttl!r}"}
    if ttl <= 0 or ttl > MAX_TTL:
        return {"ok": False, "error": f"ttl 越界：{ttl}（有效域 1..{MAX_TTL} 秒）"}
    qsha = (sha or "").lower() or query_sha(query or "")
    nonce = secrets.token_hex(16)
    now = _now()
    exp = now + ttl
    sig = _sign(key, nonce, qsha, exp)
    rec = {"nonce": nonce, "sha": qsha, "exp": exp, "session": session, "node": node,
           "issued_at": now, "used_at": None, "used_by": "", "sig": sig,
           "origin": "issue", "report_file": None}
    with state_lock(state_path):
        d = gk_state._read_state(state_path)
        if "error" in d:
            return {"ok": False, "error": d["error"], "path": d.get("path", state_path)}
        # 直写 state 文件（绕过唯一的 python 写通路）会把 `_checksum` 打歪 ⟹ 拒绝签发，
        # 防「先手改票据表再签发」把篡改洗成合法基线。
        if d.get("_checksum_warning"):
            return {"ok": False, "error": "state_tampered",
                    "detail": d["_checksum_warning"]}
        gd = d.setdefault("gate_data", {})
        lst = _prune(gd.get("dispatch_tickets"), now)
        lst.append(rec)
        gd["dispatch_tickets"] = lst[-MAX_KEEP:]
        w = gk_state._write_state(d, state_path)
    if "error" in w:
        return {"ok": False, "error": w["error"], "path": w.get("path", state_path)}
    return {"ok": True, "ticket": f"{nonce}.{sig}", "sha": qsha, "exp": exp,
            "nonce": nonce, "session": session, "ttl": ttl,
            "checksum": w.get("checksum")}


def verify(state_path: str, ticket: str, query: str, session: str = "", sha: str = "") -> dict:
    """校验并**消费**票据（原子置 `used_at`）。返回 `{"ok": bool, "reason": ...}`。"""
    key = _key()
    if not key:
        return {"ok": False, "reason": "no_hmac_key"}
    clean, embedded = extract_ticket(query or "")
    tk = (ticket or "").strip() or embedded
    if not tk:
        return {"ok": False, "reason": "no_ticket"}
    qsha = (sha or "").lower() or query_sha(clean)
    parts = tk.split(".")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return {"ok": False, "reason": "bad_format"}
    nonce, sig = parts[0].strip(), parts[1].strip()
    now = _now()
    with state_lock(state_path):
        d = gk_state._read_state(state_path)
        if "error" in d:
            return {"ok": False, "reason": "state_unreadable", "error": d["error"]}
        # 篡改面（直写 state 后 `_checksum` 不匹配）⟹ fail-closed：否则被审方可把
        # `used_at` 抹回 null 再走正常校验（单次语义被绕过），而篡改只留一条 warning。
        if d.get("_checksum_warning"):
            return {"ok": False, "reason": "state_tampered",
                    "detail": d["_checksum_warning"]}
        lst = (d.get("gate_data") or {}).get("dispatch_tickets")
        if not isinstance(lst, list):
            return {"ok": False, "reason": "unknown_ticket", "nonce": nonce}
        rec = next((r for r in lst if isinstance(r, dict) and r.get("nonce") == nonce), None)
        if rec is None:
            return {"ok": False, "reason": "unknown_ticket", "nonce": nonce}
        rec_sig = _sign(key, nonce, str(rec.get("sha") or ""), int(rec.get("exp") or 0))
        if not hmac.compare_digest(rec_sig, sig):
            return {"ok": False, "reason": "bad_sig", "nonce": nonce}
        if int(rec.get("exp") or 0) < now:
            return {"ok": False, "reason": "expired", "nonce": nonce,
                    "exp": rec.get("exp"), "now": now}
        if rec.get("used_at"):
            return {"ok": False, "reason": "used", "nonce": nonce,
                    "used_at": rec.get("used_at")}
        if str(rec.get("sha") or "").lower() != qsha:
            return {"ok": False, "reason": "sha_mismatch", "nonce": nonce}
        rec["used_at"] = now
        rec["used_by"] = session or ""
        w = gk_state._write_state(d, state_path)
        if "error" in w:
            return {"ok": False, "reason": "write_failed", "error": w["error"]}
    return {"ok": True, "reason": "ok", "nonce": nonce, "sha": qsha,
            "exp": rec.get("exp"), "checksum": w.get("checksum")}


def record_report(state_path: str, report_file: str, session: str = "",
                  origin: str = "cli", window: int = 1800) -> dict:
    """B（授权 → 产物）：把 subagent 报告与一次派发记录绑定。

    优先绑定「已消费、未绑定、且在 `window` 秒内」的最近一张票据；没有则**自记账**
    一条已消费记录（`origin=report`）—— CLI 直调 `monitor --subagent` 不经 Task 票据，
    若不自记账，它产出的报告会永远显示为「孤儿」，对账失去判别力。

    幂等：同一 `report_file` 重复调用只返回既有 nonce。
    残余风险：本函数可被显式调用（与 `state-patch` 同级信任面），故它是**归属登记**
    而非**授权**；授权仍由 `issue/verify` 的单次票据承载。
    """
    key = _key()
    if not key:
        return {"ok": False, "error": "no_hmac_key"}
    rf = str(report_file or "").strip()
    if not rf:
        return {"ok": False, "error": "report_file 为空"}
    now = _now()
    with state_lock(state_path):
        d = gk_state._read_state(state_path)
        if "error" in d:
            return {"ok": False, "error": d["error"], "path": d.get("path", state_path)}
        if d.get("_checksum_warning"):
            return {"ok": False, "error": "state_tampered", "detail": d["_checksum_warning"]}
        gd = d.setdefault("gate_data", {})
        lst = _prune(gd.get("dispatch_tickets"), now)
        for r in lst:
            if r.get("report_file") == rf:
                gd["dispatch_tickets"] = lst
                return {"ok": True, "bound": False, "nonce": r.get("nonce", ""),
                        "note": "already-recorded"}
        cand = [r for r in lst
                if r.get("used_at") and not r.get("report_file")
                and now - int(r["used_at"]) <= window]
        if cand:
            rec = max(cand, key=lambda r: int(r["used_at"]))
            rec["report_file"] = rf
            rec["report_origin"] = origin
            bound, nonce = True, rec.get("nonce", "")
        else:
            nonce = secrets.token_hex(16)
            exp = now + MAX_TTL
            rec = {"nonce": nonce, "sha": "", "exp": exp, "session": session, "node": "",
                   "issued_at": now, "used_at": now, "used_by": session,
                   "sig": _sign(key, nonce, "", exp), "origin": "report",
                   "report_file": rf, "report_origin": origin}
            lst.append(rec)
            bound = False
        gd["dispatch_tickets"] = lst[-MAX_KEEP:]
        w = gk_state._write_state(d, state_path)
    if "error" in w:
        return {"ok": False, "error": w["error"], "path": w.get("path", state_path)}
    return {"ok": True, "bound": bound, "nonce": nonce, "report_file": rf,
            "checksum": w.get("checksum")}


def _main(argv) -> int:
    if len(argv) < 4 or argv[1] not in ("issue", "verify", "record"):
        print(json.dumps({"ok": False,
                          "error": "usage: gk_dispatch_ticket.py issue|verify|record <state> … "
                                   "（issue <query|@file> [--ttl N] [--session S] [--node N] / "
                                   "verify <ticket> <query|@file> [--session S] / "
                                   "record <report_file> [--session S] [--origin X]）"},
                         ensure_ascii=False))
        return 1
    cmd, state_path = argv[1], argv[2]
    if cmd == "record":
        report_file, rest = argv[3], argv[4:]
        session, origin = "", "cli"
        i = 0
        while i < len(rest):
            k = rest[i]
            v = rest[i + 1] if i + 1 < len(rest) else ""
            if k == "--session":
                session = v
            elif k == "--origin":
                origin = v
            else:
                print(json.dumps({"ok": False, "error": f"unknown arg: {k}（record）"},
                                 ensure_ascii=False))
                return 1
            i += 2
        out = record_report(state_path, report_file, session=session, origin=origin)
        print(json.dumps(out, ensure_ascii=False))
        return 0 if out.get("ok") else 1
    # 位置参数：issue = <state> <query|@file>；verify = <state> <ticket> <query|@file>
    if cmd == "verify":
        if len(argv) < 5:
            print(json.dumps({"ok": False, "error": "verify 需要 <ticket> <query|@file>"},
                             ensure_ascii=False))
            return 1
        ticket, query_arg, rest = argv[3], argv[4], argv[5:]
        allowed = ("--session", "--sha")
    else:
        ticket, query_arg, rest = "", argv[3], argv[4:]
        allowed = ("--ttl", "--session", "--node", "--sha")
    ttl, session, node, sha = DEFAULT_TTL, "", "", ""
    i = 0
    while i < len(rest):
        k = rest[i]
        v = rest[i + 1] if i + 1 < len(rest) else ""
        if k not in allowed:
            print(json.dumps({"ok": False, "error": f"unknown arg: {k}（{cmd}）"},
                             ensure_ascii=False))
            return 1
        if k == "--ttl":
            ttl = v
        elif k == "--session":
            session = v
        elif k == "--node":
            node = v
        else:                                # --sha
            sha = v
        i += 2
    if cmd == "verify":
        out = verify(state_path, ticket, _resolve_query(query_arg), session=session, sha=sha)
    else:
        out = issue(state_path, _resolve_query(query_arg), ttl=ttl, session=session,
                    node=node, sha=sha)
    print(json.dumps(out, ensure_ascii=False))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv))

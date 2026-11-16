#!/usr/bin/env python3
"""gk_red_guard.py — 红队本地确定性护栏（2026-11-09，用户裁定「红队只自维护」）。

原则（与「联网判定合法性」相反）：
  · 闸门**本地、确定性、fail-closed**；不依赖联网/LLM 判断合法性。
  · 公开只读检索源（`PRIOR_ART_HOSTS` / `GOVERNED_SEARCH_HOSTS`）放行；
  · 其余目标必须命中**自维护授权范围** `references/red-scope.json`（sha256 + 窗口 +
    动作面 + `self_maintained=true`），否则 deny。
  · `enforce()` 在 deny 时抛 `RedGuardDenied`（调用点不进入 socket），并写审计 JSONL。
  · 在线法律检索只能作为 advisory 证据，**不参与 allow/deny**（断网也必须能判定）。

scope schema（`python gk_red_guard.py seal --scope <f>` 写 sha256）：
{
  "authorization_id": "...", "owner": "...", "self_maintained": true,
  "window": {"from": "ISO8601", "to": "ISO8601"},
  "assets": [{"host": "self.example", "path_prefix": "/", "actions": ["read"]}],
  "legal_basis": "...", "sha256": "..."
}

CLI:
  python3 scripts/gk_red_guard.py status
  python3 scripts/gk_red_guard.py check --url https://... [--action read]
  python3 scripts/gk_red_guard.py seal --scope references/red-scope.json
"""
import argparse
import datetime
import hashlib
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCOPE = ROOT / "references" / "red-scope.json"
LOG_ENV = "GK_RED_GUARD_LOG"
LOG_DEFAULT = ".gatekeeper.red-guard.jsonl"
ALLOWED_ACTIONS = ("read", "search")


class RedGuardDenied(RuntimeError):
    """红队出网被本地护栏拒绝（调用方不得捕获后继续出网）。"""

    exit_code = 126


def _public_hosts():
    try:
        from gk_evidence import GOVERNED_SEARCH_HOSTS, PRIOR_ART_HOSTS
        return set(PRIOR_ART_HOSTS) | set(GOVERNED_SEARCH_HOSTS)
    except Exception:  # noqa: BLE001 — 单源不可用 ⟹ 不放行任何“公开”宿主
        return set()


def _scope_path():
    return os.environ.get("GK_RED_SCOPE") or str(DEFAULT_SCOPE)


def _canon(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def seal_scope(path):
    """对 scope 的**其余字段**做 sha256 并写回（防手改/漂移）。"""
    p = Path(path)
    d = json.loads(p.read_text(encoding="utf-8"))
    d.pop("sha256", None)
    d["sha256"] = hashlib.sha256(_canon(d)).hexdigest()
    p.write_text(json.dumps(d, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return d["sha256"]


def _load_scope():
    p = Path(_scope_path())
    if not p.is_file():
        return None, "no_scope（未配置 %s）" % _scope_path()
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        return None, "scope_unreadable: %s" % e
    got = d.get("sha256")
    body = {k: v for k, v in d.items() if k != "sha256"}
    want = hashlib.sha256(_canon(body)).hexdigest()
    if not got or got != want:
        return None, "scope_tampered（sha256 不匹配）"
    return d, ""


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _in_window(w):
    try:
        a = datetime.datetime.fromisoformat(str(w["from"]).replace("Z", "+00:00"))
        b = datetime.datetime.fromisoformat(str(w["to"]).replace("Z", "+00:00"))
    except Exception:  # noqa: BLE001
        return False
    if a.tzinfo is None:
        a = a.replace(tzinfo=datetime.timezone.utc)
    if b.tzinfo is None:
        b = b.replace(tzinfo=datetime.timezone.utc)
    return a <= _now() <= b


def check(url, action="read"):
    """→ {ok, url, host, action, reason, authorization_id}；fail-closed，不联网。"""
    u = str(url or "").strip()
    p = urlparse(u)
    host = (p.hostname or "").lower()
    out = {"ok": False, "url": u, "host": host, "action": action,
           "reason": "", "authorization_id": ""}
    if action not in ALLOWED_ACTIONS:
        out["reason"] = "action_not_allowed: %s（仅 %s）" % (action, "/".join(ALLOWED_ACTIONS))
        return out
    if p.scheme != "https" or not host:
        out["reason"] = "only_https"
        return out
    if host in _public_hosts():
        out.update(ok=True, reason="public_read_only")
        return out
    sc, why = _load_scope()
    if sc is None:
        out["reason"] = why
        return out
    if sc.get("self_maintained") is not True:
        out["reason"] = "not_self_maintained"
        return out
    if not _in_window(sc.get("window") or {}):
        out["reason"] = "outside_window"
        return out
    path = p.path or "/"
    for a in sc.get("assets") or []:
        if str(a.get("host") or "").lower() != host:
            continue
        if not path.startswith(str(a.get("path_prefix") or "/")):
            continue
        if action not in (a.get("actions") or ALLOWED_ACTIONS):
            continue
        out.update(ok=True, reason="scope_allow",
                   authorization_id=str(sc.get("authorization_id") or ""))
        return out
    out["reason"] = "external_target（不在自维护授权范围）"
    return out


def _log(result):
    p = Path(os.environ.get(LOG_ENV) or LOG_DEFAULT)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        rec = {"ts": _now().isoformat(), **result, "pid": os.getpid()}
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def enforce(url, action="read"):
    """deny ⟹ 写审计 + 抛 `RedGuardDenied`（调用点不得继续出网）。"""
    r = check(url, action)
    if not r["ok"]:
        _log(r)
        raise RedGuardDenied("RED_GUARD_DENIED: %s（host=%s action=%s）"
                             % (r["reason"], r["host"], action))
    return r


def main(argv=None):
    ap = argparse.ArgumentParser(description="红队本地确定性护栏")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--url", required=True)
    c.add_argument("--action", default="read")
    s = sub.add_parser("seal")
    s.add_argument("--scope", required=True)
    sub.add_parser("status")
    a = ap.parse_args(argv)
    if a.cmd == "check":
        r = check(a.url, a.action)
        print(json.dumps(r, ensure_ascii=False))
        return 0 if r["ok"] else 126
    if a.cmd == "seal":
        print(json.dumps({"ok": True, "sha256": seal_scope(a.scope)}, ensure_ascii=False))
        return 0
    sc, why = _load_scope()
    print(json.dumps({"ok": sc is not None, "scope": _scope_path(), "reason": why,
                      "authorization_id": (sc or {}).get("authorization_id", "")},
                     ensure_ascii=False))
    return 0 if sc is not None else 126


if __name__ == "__main__":
    sys.exit(main())

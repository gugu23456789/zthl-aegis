#!/usr/bin/env python3
"""
gk_project_register.py — 治理范围注册表自动化入库门禁（2026-08-28，域 5）
=======================================================================
把 `.gatekeeper.scopes.json`（governed_projects[]）的手动编辑改为受控 CLI 命令：
输入合规检测 → 原子登记（flock + checksum）→ REPO_ROOTS 联动声明 → 审计留痕。

契约（评估文档 2026-08-28-security-hardening-assessment.md §5.2）:
  登记输入 = 不可变标识（marker 白名单）+ 最小权限声明（--type / --read-repo）
           + 不可抵赖审计（audit_log[] 随注册表原子落盘）+ 周期复核（list/remove）。

用法:
  python3 gk_project_register.py register <marker> --state <path> \
          [--type main|worktree|plugin] [--note <text>] [--read-repo <alias>] [--scopes <file>]
  python3 gk_project_register.py list [--scopes <file>]
  python3 gk_project_register.py remove <marker> [--scopes <file>]

退出码: 0 成功 / 1 输入不合规 / 2 文件读写错误 / 3 其他
"""
import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SCOPES = os.path.join(SKILL_DIR, ".gatekeeper.scopes.json")

# ── 输入合规约束（零信任：输入不可信，逐项校验）────────────────────────────
_MARKER_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")   # marker 白名单（≤64 字符，无空格/控制符）
_VALID_TYPES = {"main", "worktree", "plugin"}
# 密码/机密目录黑名单片段 — 登记路径不得指向机密区（防 scopes 被投毒到不可信根）
_SECRET_DIR_PARTS = (".keys", "secrets", "credentials", ".ssh", "token", "keyring")
# state 文件名要求：以 .gatekeeper.state 结尾（治理注册表的唯一合法目标）
_STATE_SUFFIX = ".gatekeeper.state"


def _err(msg: str, code: int = 1) -> dict:
    return {"ok": False, "error": msg, "exit_code": code}


def _load_scopes(path: str) -> tuple[dict | None, str]:
    """读取注册表；失败返回 (None, error)。"""
    p = Path(path)
    if not p.is_file():
        # 首次登记：允许创建（模板 v2 结构）
        return {"version": 2, "governed_projects": [], "audit_log": [], "_note": ""}, ""
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return None, f"scopes 读取失败: {e}"
    if not isinstance(d, dict) or "governed_projects" not in d:
        return None, "scopes 结构非法：缺少 governed_projects[]"
    return d, ""


def _write_scopes_atomic(path: str, d: dict) -> str | None:
    """原子写：flock 临界区 + SHA256 checksum 内嵌 + os.replace。失败返回错误串。
    flock 仅 POSIX（WSL 必有）；Windows 测试侧退化非原子写（tempfile+os.replace 兜底）。"""
    try:
        import fcntl
    except ImportError:  # 非 POSIX（Windows 测试环境）— 退化：tmp+replace 仍保证不写坏原文件
        fcntl = None
    lock_fd = None
    tmp_path = None
    try:
        if fcntl is not None:
            lock_fd = open(f"{path}.lock", "w")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        payload = json.dumps({k: v for k, v in d.items() if k != "_checksum"},
                             ensure_ascii=False, sort_keys=True)
        d["_checksum"] = hashlib.sha256(payload.encode()).hexdigest()[:16]
        fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(path) or ".", suffix=".scopes.tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
            f.write("\n")
        os.replace(tmp_path, path)
        tmp_path = None
        return None
    except Exception as e:
        return f"原子写失败: {e}"
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        if fcntl is not None and lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                lock_fd.close()
            except Exception:
                pass


def _append_audit(d: dict, action: str, marker: str, detail: dict) -> None:
    """审计留痕：随注册表原子落盘（不可抵赖 — 记录与数据同批写入）。"""
    import datetime
    log = d.setdefault("audit_log", [])
    if not isinstance(log, list):
        log = []
        d["audit_log"] = log
    rec = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "action": action,
        "marker": marker,
        "actor": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        **detail,
    }
    log.append(rec)
    log[:] = log[-200:]  # 有界：最多保留 200 条


def _validate_input(marker: str, state: str, ptype: str) -> str | None:
    """输入合规检测。返回错误串（None = 通过）。"""
    if not _MARKER_RE.match(marker or ""):
        return (f"marker 不合规: {marker!r} — 须匹配 {_MARKER_RE.pattern} "
                "（字母数字开头，≤64 字符，仅含字母/数字/._-）")
    if ptype not in _VALID_TYPES:
        return f"type 非法: {ptype!r} — 合法域 {sorted(_VALID_TYPES)}"
    p = Path(state)
    if not os.path.isabs(state):
        return f"state 路径须为绝对路径: {state!r}"
    if not p.name.endswith(_STATE_SUFFIX):
        return f"state 文件名须以 {_STATE_SUFFIX} 结尾: {state!r}"
    if not p.parent.is_dir():
        return f"state 父目录不存在: {p.parent}"
    if not p.is_file():
        return f"state 文件不存在（先 discover/初始化再登记）: {state!r}"
    low = state.lower().replace("\\", "/")
    if any(s in low for s in _SECRET_DIR_PARTS):
        return f"state 路径指向机密目录（拒绝登记）: {state!r}"
    return None


def _find_project(d: dict, marker: str) -> tuple[int | None, dict | None]:
    """按 marker 精确匹配（markers 列表内任一命中）。"""
    projects = d.get("governed_projects", [])
    if not isinstance(projects, list):
        return None, None
    for i, p in enumerate(projects):
        if not isinstance(p, dict):
            continue
        ms = p.get("markers") or ([p.get("marker")] if p.get("marker") else [])
        if marker in ms:
            return i, p
    return None, None


def _action_register(args) -> dict:
    err = _validate_input(args.marker, args.state, args.type)
    if err:
        return _err(err)
    d, load_err = _load_scopes(args.scopes)
    if load_err:
        return _err(load_err, 2)
    i, existing = _find_project(d, args.marker)
    if existing is not None:
        return _err(f"marker {args.marker!r} 已登记（项目 {existing.get('state_file')}）— 不覆盖")
    projects = d.setdefault("governed_projects", [])
    if not isinstance(projects, list):
        return _err("governed_projects 非数组 — 注册表损坏", 2)
    # 同 state 重复登记（防同一项目挂多条目）
    state_norm = os.path.normpath(args.state).lower()
    for p in projects:
        if isinstance(p, dict) and os.path.normpath(str(p.get("state_file", ""))).lower() == state_norm:
            return _err(f"state {args.state!r} 已被项目 {p.get('markers', [])} 登记 — 不重复")
    entry = {
        "markers": [args.marker],
        "state_file": os.path.normpath(args.state).replace("\\", "/"),
        "note": args.note or "",
    }
    if args.type != "main":  # main 为默认语义，仅非默认显式落盘
        entry["type"] = args.type
    if args.read_repo:
        if not _MARKER_RE.match(args.read_repo):
            return _err(f"read_repo 别名不合规: {args.read_repo!r} — 同 marker 白名单")
        entry["read_repo"] = args.read_repo
    projects.append(entry)
    _append_audit(d, "register", args.marker,
                  {"state": entry["state_file"], "type": args.type,
                   "read_repo": args.read_repo or ""})
    werr = _write_scopes_atomic(args.scopes, d)
    if werr:
        return _err(werr, 3)
    return {"ok": True, "action": "register", "marker": args.marker,
            "entry": entry, "projects": len(d.get("governed_projects", []))}


def _action_list(args) -> dict:
    d, load_err = _load_scopes(args.scopes)
    if load_err:
        return _err(load_err, 2)
    projects = d.get("governed_projects", [])
    return {"ok": True, "action": "list", "projects": projects,
            "count": len(projects) if isinstance(projects, list) else 0}


def _action_remove(args) -> dict:
    d, load_err = _load_scopes(args.scopes)
    if load_err:
        return _err(load_err, 2)
    i, existing = _find_project(d, args.marker)
    if existing is None:
        return _err(f"marker {args.marker!r} 未登记")
    projects = d.get("governed_projects", [])
    removed = projects.pop(i)
    _append_audit(d, "remove", args.marker,
                  {"state": str(removed.get("state_file", "")), "type": str(removed.get("type", "main"))})
    werr = _write_scopes_atomic(args.scopes, d)
    if werr:
        return _err(werr, 3)
    return {"ok": True, "action": "remove", "marker": args.marker, "removed": removed}


def _action_seal(args) -> dict:
    """密封存量注册表：不动 governed_projects，仅补 _checksum + audit_log（升级路径 —
    2026-08-28 前手动编辑的 scopes 无完整性校验，red_registry 会报 RED-REGISTRY-01/08）。"""
    d, load_err = _load_scopes(args.scopes)
    if load_err:
        return _err(load_err, 2)
    _append_audit(d, "seal", "*", {"count": len(d.get("governed_projects", []) or [])})
    werr = _write_scopes_atomic(args.scopes, d)
    if werr:
        return _err(werr, 3)
    return {"ok": True, "action": "seal", "marker": "*", "projects": len(d.get("governed_projects", []) or [])}


def main() -> int:
    ap = argparse.ArgumentParser(description="治理范围注册表自动化入库门禁")
    sub = ap.add_subparsers(dest="action", required=True)
    p_reg = sub.add_parser("register")
    p_reg.add_argument("marker")
    p_reg.add_argument("--state", required=True)
    p_reg.add_argument("--type", choices=sorted(_VALID_TYPES), default="main")
    p_reg.add_argument("--note", default="")
    p_reg.add_argument("--read-repo")
    p_reg.add_argument("--scopes", default=DEFAULT_SCOPES)
    p_list = sub.add_parser("list")
    p_list.add_argument("--scopes", default=DEFAULT_SCOPES)
    p_rm = sub.add_parser("remove")
    p_rm.add_argument("marker")
    p_rm.add_argument("--scopes", default=DEFAULT_SCOPES)
    p_seal = sub.add_parser("seal")
    p_seal.add_argument("--scopes", default=DEFAULT_SCOPES)
    args = ap.parse_args()

    if args.action == "register":
        out = _action_register(args)
    elif args.action == "list":
        out = _action_list(args)
    elif args.action == "seal":
        out = _action_seal(args)
    else:
        out = _action_remove(args)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out.get("ok") else out.get("exit_code", 1)


if __name__ == "__main__":
    sys.exit(main())

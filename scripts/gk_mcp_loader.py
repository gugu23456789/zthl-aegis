#!/usr/bin/env python3
"""gk_mcp_loader.py — MCP 加载安全网（最小验证逻辑，DRAFT-1）

背景（finding `ECC-CB50D6939258`，计划 `docs/plans/2026-09-29-mcp-loading-safety-net-plan.md`）：
  技能仓此前只有 MCP **写面/命令面/出网**闸，**没有加载面**安全网——server 声明不校验、
  未接线工具默认放行、加载失败可能退化成裸放行。本模块只做三件**可机检**的事：

  1. 声明面（`verify`）：`mcp_manifest.json` 的每个 server 必须钉版本、
     带 `sha512-` integrity、scope 在白名单、cap 在能力白名单、条目唯一。
  2. 接线面（`connect`）：server 暴露的**每个**工具都必须落到读/写/命令三类之一；
     未登记 ⟹ 非零退出（**默认拒**，不猜）。
  3. 降级面（`plan_load`）：任一环节失败 ⟹ `health-only` + `proceed=false`；
     **不得**输出“不可用即放行”。`GK_MCP_LOAD_GUARD=0` 为显式回退（恒等直通）。

确定性：0 API、0 第三方依赖。动词集与 `pre_tool_hook` **同源**（直接 import，禁第二份解析）。
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# 写/命令/出网动词集：与 pre_tool_hook 同源（禁第二份解析）
from pre_tool_hook import (  # noqa: E402
    BROWSER_INSTALL_TOOL,
    BROWSER_LOCAL_UI_TOOLS,
    BROWSER_RECORD_READ_TOOLS,
    BROWSER_RECORD_WRITE_TOOLS,
    MCP_EGRESS_SEALED_TOOLS,
    MCP_EGRESS_TOOLS,
    MCP_EXEC_TOOLS,
    MCP_WRITE_VERBS,
)

MANIFEST_NAME = "mcp_manifest.json"
SCOPE_WHITELIST = frozenset(("official", "verified", "local"))
CAP_WHITELIST = frozenset(("read", "write", "exec", "network"))
_UNPINNED = frozenset(("", "latest", "*", "any", "unversioned"))

# 只读工具：**显式名单**（未列入 ⟹ 默认拒；不按前缀猜）。
READ_TOOLS = frozenset((
    "read_file", "read_text_file", "read_multiple_files", "read_media_file",
    "get_file_contents", "list_directory", "list_directory_with_sizes",
    "directory_tree", "search_files", "get_file_info", "list_allowed_directories",
    "search_repositories", "search_code", "search_issues", "search_users",
    "list_commits", "list_issues", "list_pull_requests", "list_branches",
    "list_tags", "get_issue", "get_pull_request", "get_pull_request_comments",
    "get_pull_request_files", "get_pull_request_reviews", "get_pull_request_status",
    "get_commit", "get_repository", "puppeteer_screenshot", "puppeteer_dom_tree",
))

_EXIT_OK = 0
_EXIT_VERIFY = 2
_EXIT_CONNECT = 3
_EXIT_MANIFEST = 4


def _inner_name(name: str) -> str:
    """`mcp__<server>__<tool>` → `<tool>`；其余原样（与 `_mcp_inner_tool` 同形态）。"""
    s = str(name or "")
    if s.startswith("mcp__"):
        parts = s.split("__", 2)
        s = parts[2] if len(parts) == 3 else parts[-1]
    return s.strip().lower()


def classify_tool(name: str):
    """→ `sealed` / `egress` / `read` / `write` / `command` / `None`。

    `sealed` = R0.14 直接封（如 `browser_eval_js` 内的 fetch 残余）；
    `egress` = R0.14 受治出网车道；`None` = 未登记，调用方默认拒。
    """
    inner = _inner_name(name)
    if not inner:
        return None
    if inner in MCP_EGRESS_SEALED_TOOLS:
        return "sealed"
    if inner in MCP_EGRESS_TOOLS:
        return "egress"
    if inner == BROWSER_INSTALL_TOOL or inner in BROWSER_RECORD_WRITE_TOOLS:
        return "gated"
    if inner in BROWSER_LOCAL_UI_TOOLS:
        return "ui"
    if inner in BROWSER_RECORD_READ_TOOLS or inner in READ_TOOLS:
        return "read"
    if inner in MCP_EXEC_TOOLS:
        return "command"
    tokens = set(re.split(r"[_\-]+", inner))
    if tokens & MCP_WRITE_VERBS:
        return "write"
    return None


def load_manifest(path):
    """→ `(data, error)`；缺失/不可解析均 fail-closed（data=None）。"""
    if not path:
        return None, "manifest_missing"
    p = Path(path)
    if not p.exists():
        return None, "manifest_missing: %s" % p
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        return None, "unparseable: %s: %s" % (p, e)
    if not isinstance(data, dict):
        return None, "bad_shape: top-level must be object"
    return data, ""


def verify_manifest(data: dict) -> dict:
    """声明面校验：钉版本 / integrity / scope / cap / 条目唯一。"""
    errors = []
    servers = data.get("servers") if isinstance(data, dict) else None
    if not isinstance(servers, list) or not servers:
        errors.append("servers: 必须为非空列表")
        return {"ok": False, "servers": 0, "errors": errors}
    seen = set()
    for i, s in enumerate(servers):
        tag = "servers[%d]" % i
        if not isinstance(s, dict):
            errors.append("%s: 非对象" % tag)
            continue
        name = str(s.get("server") or "").strip()
        if not name:
            errors.append("%s: 缺 server" % tag)
        elif name in seen:
            errors.append("%s: duplicate server %r" % (tag, name))
        else:
            seen.add(name)
        ver = str(s.get("version") or "").strip()
        if ver.lower() in _UNPINNED:
            errors.append("%s(%s): version 未钉（%r）" % (tag, name or "?", ver))
        integ = str(s.get("integrity") or "").strip()
        if not integ.startswith("sha512-") or len(integ) < 32:
            errors.append("%s(%s): integrity 必须是 sha512-<hex>" % (tag, name or "?"))
        scope = str(s.get("scope") or "").strip()
        if scope not in SCOPE_WHITELIST:
            errors.append("%s(%s): scope 未知 %r" % (tag, name or "?", scope))
        cap = s.get("cap")
        if not isinstance(cap, list) or not cap:
            errors.append("%s(%s): cap 必须为非空列表" % (tag, name or "?"))
        else:
            bad = [c for c in cap if c not in CAP_WHITELIST]
            if bad:
                errors.append("%s(%s): cap 越界 %r" % (tag, name or "?", bad))
        tools = s.get("tools")
        if not isinstance(tools, list) or not tools:
            errors.append("%s(%s): tools 必须为非空列表" % (tag, name or "?"))
    return {"ok": not errors, "servers": len(servers), "errors": errors}


def connect_manifest(data: dict) -> dict:
    """接线面核对：每个工具必须落在 read/write/command；未登记 ⟹ ok=False。"""
    out = {"ok": True, "servers": [], "unwired": []}
    for s in (data.get("servers") or []):
        if not isinstance(s, dict):
            continue
        name = str(s.get("server") or "")
        wired = {}
        for t in (s.get("tools") or []):
            kind = classify_tool(t)
            if kind is None:
                out["unwired"].append("%s:%s" % (name, t))
            else:
                wired[str(t)] = kind
        out["servers"].append({"server": name, "tools": len(s.get("tools") or []),
                               "wired": wired})
    out["ok"] = not out["unwired"]
    return out


def plan_load(path=None, manifest=None) -> dict:
    """加载决策：`load`（proceed=True）或 `health-only`（proceed=False，永不裸放行）。"""
    if os.environ.get("GK_MCP_LOAD_GUARD", "1") == "0":
        return {"action": "passthrough", "proceed": True, "guard": "off"}
    if manifest is None:
        data, err = load_manifest(path)
        if err:
            return {"action": "health-only", "proceed": False,
                    "errors": [err], "servers": []}
    else:
        data = manifest
    v = verify_manifest(data)
    if not v["ok"]:
        return {"action": "health-only", "proceed": False,
                "errors": v["errors"], "servers": []}
    c = connect_manifest(data)
    if not c["ok"]:
        return {"action": "health-only", "proceed": False,
                "errors": ["unwired: " + ", ".join(c["unwired"])],
                "servers": c["servers"]}
    return {"action": "load", "proceed": True, "servers": c["servers"]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="MCP 加载安全网（最小验证逻辑）")
    ap.add_argument("command", choices=("verify", "connect", "check"))
    ap.add_argument("--manifest", default=MANIFEST_NAME)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    data, err = load_manifest(a.manifest)
    if err:
        out = {"ok": False, "action": "health-only", "errors": [err]}
        print(json.dumps(out, ensure_ascii=False) if a.json else out)
        return _EXIT_MANIFEST
    if a.command == "verify":
        out = verify_manifest(data)
        rc = _EXIT_OK if out["ok"] else _EXIT_VERIFY
    elif a.command == "connect":
        out = connect_manifest(data)
        rc = _EXIT_OK if out["ok"] else _EXIT_CONNECT
    else:
        out = plan_load(a.manifest, manifest=data)
        rc = _EXIT_OK if out.get("proceed") else _EXIT_MANIFEST
    print(json.dumps(out, ensure_ascii=False) if a.json else out)
    return rc


if __name__ == "__main__":
    sys.exit(main())

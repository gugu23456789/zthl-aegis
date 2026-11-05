#!/usr/bin/env python3
"""gk_mcp_loader.py — MCP 加载安全网（声明面 / 接线面 / 加载决策）

背景（finding `ECC-CB50D6939258`，计划 `docs/plans/2026-09-29-mcp-loading-safety-net-plan.md`）：
  技能仓此前只有 MCP **写面/命令面/出网**闸，**没有加载面**安全网——server 声明不校验、
  未接线工具默认放行、加载失败可能退化成裸放行。本模块只做三件**可机检**的事：

  1. 声明面（`verify`）：`mcp_manifest.json` 的每个 server 必须钉版本、带 `sha512-`
     integrity、scope / cap 在白名单、条目唯一。
  2. 接线面（`connect`）：server 暴露的**每个**工具都必须落到读/写/命令三类之一；
     未登记 ⟹ 非零退出（**默认拒**，不猜）。
  3. 决策面（`check` / `health-only`）：任一环节失败 ⟹ `health-only` + `proceed=false`；
     **不得**输出“不可用即放行”。`GK_MCP_LOAD_GUARD=0` 为显式回退（恒等直通）。

2026-11-05 升级（SDK 版本适配）：
  MCP SDK 跨版本的工具清单形态不同（`list[Tool]` / `list[dict]` / `{"tools": [...]}`
  / 分页 `nextCursor`），且类路径有迁移（`mcp.ClientSession` ↔ `mcp.client.session.ClientSession`，
  `mcp.server.fastmcp` 1.x 与 2.x 的导出面差异）。本模块**不按版本号分支猜**，而是：
    · `sdk_info()` 探测**实际可用的符号面**并归类 major（1/2/unknown）；
    · `normalize_tools()` 对四类载荷形态统一归一；
    · 任何探测失败 ⟹ `health-only` + 明确 reason（**fail-closed，不退化成裸放行**）。
  仍保持 0 必需依赖：未装 SDK 时 `sdk-info` 报 `installed=false`，其余子命令照常工作（静态面）。

确定性：0 API；动词集与 `pre_tool_hook` **同源**（直接 import，禁第二份解析）。
接线说明：`_CMD_REG` 位于 `PROTECTED_REGION::gate`（禁新增命令）⟹ 本模块是**独立脚本**，
          由 `python3 scripts/gk_mcp_loader.py <cmd>` 调用；hook 消费点属后续工作。
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

# 写/命令/出网动词集：与 pre_tool_hook 同源（禁第二份解析）。
# 2026-11-05：`BROWSER_*` 四组常量已从主线移除（octop-browser 工具改按 `browser_*` 精确名
#   并入 `MCP_EGRESS_TOOLS` / `MCP_EGRESS_SEALED_TOOLS`）⟹ 此处只导现存单源，避免 ImportError。
from pre_tool_hook import (  # noqa: E402
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
_EXIT_SDK = 5


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
    （原 `gated` / `ui` 两档已随 `BROWSER_*` 常量下线一并移除。）
    """
    inner = _inner_name(name)
    if not inner:
        return None
    if inner in MCP_EGRESS_SEALED_TOOLS:
        return "sealed"
    if inner in MCP_EGRESS_TOOLS:
        return "egress"
    if inner in READ_TOOLS:
        return "read"
    if inner in MCP_EXEC_TOOLS:
        return "command"
    tokens = set(re.split(r"[_\-]+", inner))
    if tokens & MCP_WRITE_VERBS:
        return "write"
    return None


# ── SDK 版本适配层（2026-11-05）────────────────────────────────────────────────
# 设计原则：**探测符号面，不猜版本号**。SDK 迁移时类路径会变，但"能拿到名字"这件事不变。
_SDK_SURFACES = (
    ("ClientSession", ("mcp", "ClientSession")),
    ("ClientSession", ("mcp.client.session", "ClientSession")),
    ("stdio_client", ("mcp", "stdio_client")),
    ("stdio_client", ("mcp.client.stdio", "stdio_client")),
    ("sse_client", ("mcp.client.sse", "sse_client")),
    ("FastMCP", ("mcp.server.fastmcp", "FastMCP")),
    ("Tool", ("mcp.types", "Tool")),
)


def _probe(dotted: tuple):
    """返回 `(ok, symbol|None, error)`；不抛异常（探测失败本身是结论）。"""
    mod_name, attr = dotted
    try:
        mod = __import__(mod_name, fromlist=[attr])
    except Exception as e:                      # ImportError / 运行时初始化错误
        return False, None, "%s: %s" % (type(e).__name__, e)
    try:
        return True, getattr(mod, attr), ""
    except AttributeError:
        return False, None, "%s.%s 不存在" % (mod_name, attr)


def sdk_info() -> dict:
    """探测 MCP SDK 是否可用及其符号面（跨版本）。

    → `{"installed","version","major","surfaces","tools_api","notes"}`。
    `major` 只用于**报告**，判定仍按 surfaces（避免版本号撒谎）。
    """
    version = ""
    try:
        from importlib import metadata as _md
        version = _md.version("mcp")
    except Exception:
        version = ""
    surfaces, notes = {}, []
    for label, dotted in _SDK_SURFACES:
        ok, sym, err = _probe(dotted)
        if ok:
            surfaces.setdefault(label, []).append("%s.%s" % dotted)
        elif version:
            notes.append(err)
    installed = bool(surfaces)
    # major：仅当包元数据可读时给出；否则 unknown（不猜）
    major = "unknown"
    if version:
        head = version.split(".", 1)[0]
        major = head if head.isdigit() else "unknown"
    tools_api = ""
    if "Tool" in surfaces:
        tools_api = "mcp.types.Tool"
    return {"installed": installed, "version": version, "major": major,
            "surfaces": surfaces, "tools_api": tools_api, "notes": notes[:6]}


def normalize_tools(payload) -> list:
    """把任意版本的 `list_tools()` 结果归一为 `[{"name","description"}]`。

    兼容五类形态（实测/文档跨 SDK 版本）：
      ① `[Tool, ...]`（对象，取 `.name`）
      ② `[{"name": ...}, ...]`（字典）
      ③ `{"tools": [...]}`（包装一层）
      ④ 带分页 `{"tools": [...], "nextCursor": "..."}`（本函数只取当前页）
      ⑤ `ListToolsResult` 之类的**模型对象**（`.tools` 属性，pydantic）
    其他形态 ⟹ 抛 `ValueError`（调用方转 health-only，**不猜**）。
    """
    if isinstance(payload, dict) and "tools" in payload:
        payload = payload.get("tools")
    if not isinstance(payload, (list, tuple)):
        _attr = getattr(payload, "tools", None)     # pydantic `ListToolsResult`
        if isinstance(_attr, (list, tuple)):
            payload = _attr
    if not isinstance(payload, (list, tuple)):
        raise ValueError("unsupported tools payload: %s" % type(payload).__name__)
    out = []
    for item in payload:
        if isinstance(item, dict):
            name = item.get("name") or item.get("tool") or ""
            desc = item.get("description") or ""
        else:
            name = getattr(item, "name", "") or ""
            desc = getattr(item, "description", "") or ""
        name = str(name).strip()
        if not name:
            raise ValueError("tool entry without name: %r" % (item,))
        out.append({"name": name, "description": str(desc)[:120]})
    return out


def tools_file_manifest(tools: list, server: str = "") -> dict:
    """离线接线：把一份工具清单包装成 manifest 片段（供 `connect --tools` 用）。"""
    names = [t.get("name") if isinstance(t, dict) else str(t) for t in tools]
    return {"servers": [{"server": server or "probe", "tools": [n for n in names if n]}]}


# ── 声明面 ────────────────────────────────────────────────────────────────────
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
    ap = argparse.ArgumentParser(description="MCP 加载安全网（声明/接线/决策 + SDK 版本适配）")
    ap.add_argument("command",
                    choices=("verify", "connect", "check", "health-only", "sdk-info"))
    ap.add_argument("--manifest", default=MANIFEST_NAME)
    ap.add_argument("--tools", default="",
                    help="离线工具清单 JSON（任意受支持形态）；**仅 connect** 可用，优先于 manifest 的 tools")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    if a.command == "sdk-info":
        out = sdk_info()
        print(json.dumps(out, ensure_ascii=False, indent=2) if a.json else out)
        return _EXIT_OK if out["installed"] else _EXIT_SDK

    if a.command == "health-only":
        info = sdk_info()
        print(json.dumps({"action": "health-only", "proceed": False, "sdk": info},
                         ensure_ascii=False, indent=2) if a.json else
              {"action": "health-only", "proceed": False, "sdk": info})
        return _EXIT_OK

    data, err = load_manifest(a.manifest)
    if a.tools and a.command != "connect":
        # `--tools` 只是**工具清单**，不含 version/integrity/scope/cap ⟹ 不能拿去跑声明面
        # 或加载决策（否则恒假红）。只允许 connect。
        out = {"ok": False, "action": "health-only",
               "errors": ["--tools 仅适用于 connect（声明面/决策面需要完整 manifest）"]}
        print(json.dumps(out, ensure_ascii=False, indent=2) if a.json else out)
        return _EXIT_MANIFEST
    if err and not a.tools:
        out = {"ok": False, "action": "health-only", "errors": [err]}
        print(json.dumps(out, ensure_ascii=False, indent=2) if a.json else out)
        return _EXIT_MANIFEST

    if a.tools:
        # 离线接线：把 SDK 读到的工具清单（任意版本形态）归一后做接线核对
        try:
            raw = json.loads(Path(a.tools).read_text(encoding="utf-8"))
            tools = normalize_tools(raw)
        except (OSError, json.JSONDecodeError, ValueError) as e:
            out = {"ok": False, "action": "health-only",
                   "errors": ["tools_unreadable: %s" % e]}
            print(json.dumps(out, ensure_ascii=False, indent=2) if a.json else out)
            return _EXIT_MANIFEST
        data = tools_file_manifest(tools, server=os.path.basename(a.tools))

    if a.command == "verify":
        out = verify_manifest(data)
        rc = _EXIT_OK if out["ok"] else _EXIT_VERIFY
    elif a.command == "connect":
        out = connect_manifest(data)
        if a.tools:
            out["normalized"] = len(data["servers"][0]["tools"])
            out["sdk"] = sdk_info()
        rc = _EXIT_OK if out["ok"] else _EXIT_CONNECT
    else:
        out = plan_load(a.manifest, manifest=data)
        rc = _EXIT_OK if out.get("proceed") else _EXIT_MANIFEST
    print(json.dumps(out, ensure_ascii=False, indent=2) if a.json else out)
    return rc


if __name__ == "__main__":
    sys.exit(main())

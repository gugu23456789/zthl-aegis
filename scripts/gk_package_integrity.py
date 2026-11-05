#!/usr/bin/env python3
"""gk_package_integrity.py — 包 / 钩子完整性静态检查（2026-11-02）。

问题：发布包「注册了什么」必须「有对应载体」。缺件不会让 Python 当场炸，
但会让门禁/钩子/插件在用户机器上静默降级 —— 典型如：命令注册了却没函数、
插件登记了却没内置源、安装器注册钩子却没 wrapper。

检查项（只读、零网络、标准库 + 可选 oss_scrub）：
  H1  `scripts/pre_tool_hook_wrapper.sh` 存在；`gk_hook_manage.WRAPPER_NAME` 与文件同名；
      缺可执行位只 WARN（安装后的调用形态是 `bash <path>`）。
  H2  `install.sh` / `uninstall.sh` 都接 `gk_hook_manage.py`（装卸对称）。
  C1  `_CMD_REG[<cmd>]` 映射的函数在 `gatekeeper-cli.sh` 中有定义。
  P1  `gk_plugin_manifest.MANIFESTS` 自洽：`id == key`、`intercept` 非空、`write`/`undo` 配对。
  P2  `builtin:` 源的载体存在；载体若在导出排除面（私仓独有）⟹ WARN（公开包不提供，非缺件）。
  P3  外部源（`..` / 独立技能）⟹ WARN（不属本包缺件）。

用法：
  python3 scripts/gk_package_integrity.py            # 摘要
  python3 scripts/gk_package_integrity.py --json     # 机器可读
退出码：0 无 error；1 有 error。
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent or Path(".")
WRAPPER_REL = os.path.join("scripts", "pre_tool_hook_wrapper.sh")


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _issue(level: str, check: str, detail: str, **extra) -> dict:
    row = {"level": level, "check": check, "detail": detail}
    row.update(extra)
    return row


def cmd_registry_issues(text: str) -> list:
    """`_CMD_REG[name]="fn|..."` 的 fn 必须在同一文件中有定义。"""
    reg = re.findall(r'^_CMD_REG\[([^\]]+)\]="([^"|]+)\|', text, re.M)
    defined = set(re.findall(r'^(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{', text, re.M))
    out = []
    for name, fn in reg:
        if fn not in defined:
            out.append(_issue("error", "cli_cmd_registry",
                              "命令已注册但函数未定义", command=name, function=fn))
    return out


def hook_local_imports(text: str) -> list:
    """钩子脚本里 `import gk_*` / `from gk_* import` 的本地模块名（去重）。"""
    mods = re.findall(r'^(?:from|import)\s+(gk_[A-Za-z0-9_]+)', text, re.M)
    seen, out = set(), []
    for m in mods:
        if m not in seen:
            seen.add(m)
            out.append(m)
    return out


def hook_issues(root: Path) -> list:
    out = []
    wrapper = root / WRAPPER_REL
    if not wrapper.is_file():
        out.append(_issue("error", "hook_wrapper", "钩子 wrapper 缺失", path=WRAPPER_REL))
    elif not os.access(str(wrapper), os.X_OK):
        out.append(_issue("warn", "hook_wrapper", "钩子 wrapper 缺可执行位（调用形态为 bash <path>）",
                          path=WRAPPER_REL))
    is_excluded = None
    try:
        import oss_scrub as S  # noqa: E402 — 私仓独有；公开包降级为仅存在性检查
        is_excluded = S.is_excluded
    except Exception:  # noqa: BLE001
        pass
    # 钩子依赖闭包：wrapper 的 source/exec 目标 + pre_tool_hook.py 的本地 import 都必须在包内。
    if wrapper.is_file():
        wtext = _read(wrapper)
        for rel in re.findall(r'"\$\(dirname "\$0"\)/([A-Za-z0-9_.-]+)"', wtext):
            if not (root / "scripts" / rel).is_file():
                out.append(_issue("error", "hook_dependency", "wrapper 引用的脚本缺失", path="scripts/" + rel))
    hook_py = root / "scripts" / "pre_tool_hook.py"
    if hook_py.is_file():
        for mod in hook_local_imports(_read(hook_py)):
            rel = "scripts/%s.py" % mod
            if not (root / rel).is_file():
                out.append(_issue("error", "hook_dependency", "钩子 import 的本地模块缺失", path=rel))
            elif is_excluded and is_excluded(rel):
                out.append(_issue("warn", "hook_dependency",
                                  "钩子依赖在导出排除面 ⟹ 公开包缺件", path=rel))
    try:
        sys.path.insert(0, str(root / "scripts"))
        import gk_hook_manage as HM  # noqa: E402
        if HM.WRAPPER_NAME != os.path.basename(WRAPPER_REL):
            out.append(_issue("error", "hook_wrapper",
                              "gk_hook_manage.WRAPPER_NAME 与载体不同名",
                              expected=os.path.basename(WRAPPER_REL), actual=HM.WRAPPER_NAME))
    except Exception as exc:  # noqa: BLE001 — 检查器自身不能静默
        out.append(_issue("warn", "hook_wrapper", "无法导入 gk_hook_manage", error=type(exc).__name__))
    for name in ("install.sh", "uninstall.sh"):
        if "gk_hook_manage.py" not in _read(root / name):
            out.append(_issue("error", "hook_lifecycle",
                              "%s 未接 gk_hook_manage.py（装卸不对称）" % name))
    return out


def plugin_manifest_issues(manifests: dict, root: Path, is_excluded=None) -> list:
    """纯函数：manifest 自洽 + builtin 载体存在性（便于测试注入）。"""
    out = []
    for key, m in (manifests or {}).items():
        if m.get("id") != key:
            out.append(_issue("error", "plugin_manifest", "id 与注册键不一致", plugin=key, id=m.get("id")))
        if not m.get("intercept"):
            out.append(_issue("error", "plugin_manifest", "intercept 能力白名单为空", plugin=key))
        if m.get("write") and not m.get("undo"):
            out.append(_issue("error", "plugin_manifest", "write=True 但缺 undo", plugin=key))
        if not m.get("write") and m.get("undo"):
            out.append(_issue("warn", "plugin_manifest", "write=False 却声明 undo", plugin=key))
        # 包内 vendor（2026-11-05，本体随包）：声明了就必须在；存在则外部源告警不再成立。
        vendor = str(m.get("vendor") or "")
        if vendor:
            vrel = vendor.replace("${SKILL_DIR}/", "", 1)
            if not (root / vrel).is_file():
                out.append(_issue("error", "plugin_manifest", "vendor 源缺失",
                                  plugin=key, path=vrel))
                continue
        url = str(m.get("url") or "")
        if not url.startswith("builtin:"):
            if vendor:
                continue          # 包内载体已在上面核过 ⟹ 不是「本包缺件」
            if ".." in url or url.startswith("pip:") or url.startswith("npm:"):
                out.append(_issue("warn", "plugin_manifest", "外部源（不属本包缺件）",
                                  plugin=key, url=url))
            continue
        rel = url[len("builtin:"):].replace("${SKILL_DIR}/", "", 1)
        if rel.startswith("../") or rel.startswith("..\\"):
            out.append(_issue("warn", "plugin_manifest", "外部技能源（不属本包缺件）",
                              plugin=key, path=rel))
            continue
        if not (root / rel).is_file():
            out.append(_issue("error", "plugin_manifest", "builtin 源缺失", plugin=key, path=rel))
            continue
        if is_excluded and is_excluded(rel.replace(os.sep, "/")):
            out.append(_issue("warn", "plugin_manifest",
                              "builtin 源在导出排除面 ⟹ 仅私仓提供（公开包条件登记后自动摘除）",
                              plugin=key, path=rel))
    return out


def plugin_issues(root: Path) -> list:
    try:
        sys.path.insert(0, str(root / "scripts"))
        import gk_plugin_manifest as PM  # noqa: E402
    except Exception as exc:  # noqa: BLE001
        return [_issue("error", "plugin_manifest", "无法导入 gk_plugin_manifest", error=type(exc).__name__)]
    is_excluded = None
    try:
        import oss_scrub as S  # noqa: E402 — 私仓独有；公开包降级为仅存在性检查
        is_excluded = S.is_excluded
    except Exception:  # noqa: BLE001
        pass
    return plugin_manifest_issues(PM.MANIFESTS, root, is_excluded)


# 需要 monitor schema 的核心序列路线（plugin-* / zthl / w2a-p2 由各自插件自检；
# DONE 是终止伪节点，不跑 monitor）。
MONITOR_ROUTES = ("standing", "standard", "audit", "red")


def monitor_schema_missing(nodes_by_route: dict, schema_dir: Path) -> list:
    """纯函数：route → nodes 映射里，缺 `<NODE>.json` 的节点清单。"""
    out = []
    for route, meta in (nodes_by_route or {}).items():
        for node in (meta or {}).get("nodes", []):
            if node == "DONE":
                continue
            if not (schema_dir / f"{node}.json").is_file():
                out.append((route, node))
    return out


def monitor_schema_issues(root: Path) -> list:
    """每个序列节点必须有 monitor schema（防红队/审计站静默 0.5 拦停）。

    2026-11-02：红队 16 站曾只有 6 个 schema ⟹ RED-HOOK 起 `no schema for RED-HINT`
    ⟹ 银行 monitor 判 0.5 拦停。本检查把「节点注册 → schema 载体」纳入包完整性硬门。
    """
    try:
        sys.path.insert(0, str(root / "scripts"))
        import gk_node_guard as NG  # noqa: E402
        rm = NG.route_map()
    except Exception as exc:  # noqa: BLE001
        return [_issue("error", "monitor_schema", "route_map 不可读", error=type(exc).__name__)]
    if not rm.get("ok"):
        return [_issue("error", "monitor_schema", "route_map 失败", error=rm.get("error", ""))]
    routes = {r: m for r, m in (rm.get("routes") or {}).items() if r in MONITOR_ROUTES}
    missing = monitor_schema_missing(routes, root / "monitor-schemas")
    return [_issue("error", "monitor_schema", "节点缺 monitor schema", route=r, node=n)
            for r, n in missing]


def collect(root: Path = None) -> dict:
    root = Path(root or ROOT)
    issues = hook_issues(root)
    issues += cmd_registry_issues(_read(root / "gatekeeper-cli.sh"))
    issues += plugin_issues(root)
    issues += monitor_schema_issues(root)
    errors = [i for i in issues if i["level"] == "error"]
    warns = [i for i in issues if i["level"] == "warn"]
    return {"ok": not errors, "errors": len(errors), "warnings": len(warns), "issues": issues}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="gk_package_integrity.py")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--root", default="", help="待检查树（默认 = 本仓根）")
    ns = ap.parse_args(argv)
    r = collect(ns.root or None)
    if ns.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print("package-integrity: ok=%s errors=%d warnings=%d"
              % (r["ok"], r["errors"], r["warnings"]))
        for i in r["issues"]:
            print("  [%s] %-16s %s %s" % (i["level"], i["check"], i["detail"],
                                          {k: v for k, v in i.items()
                                           if k not in ("level", "check", "detail")} or ""))
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())

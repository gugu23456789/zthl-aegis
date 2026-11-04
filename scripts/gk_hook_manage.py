#!/usr/bin/env python3
"""gk_hook_manage.py — PreToolUse 钩子的安装/卸载（按加载安全网重写，2026-10-28）
============================================================================

为什么重写：旧 `gk_hook_install.sh` 只拼 JSON 直写盘，三种失败模式全静默 ——
  - **漏加载**：写失败 / 路径失效（换机后 `/mnt/...` 不再是本仓）无人知；
  - **误加载**：整文件覆盖，用户已有 hooks 条目被抹掉；
  - **错加载**：目标 JSON 已坏仍照写。
本模块按 `references/plugin-loading-test-framework.md` §1 落地：

| 协议条款 | 本模块实现 |
|:--|:--|
| 双函数契约 | `load_status()` 只读探测（零副作用）+ `install()/uninstall()` 返回 `{ok, status}` |
| 三失败模式显式报告 | `source = registered / absent / foreign / unparseable / bad_shape / error`，`command_ok` 独立报 |
| 供应链 pin 的同位纪律 | 注册命令**只能指向本仓 wrapper**（`pre_tool_hook_wrapper.sh` 绝对路径）；卸载同时识别旧版 `pre_tool_hook.py` 形态 |
| 可逆效应（write=true 必须有 undo） | `uninstall()` 只摘本仓条目，用户条目逐字保留；每次写前留 `.bak-<UTC>` |
| 校验先于写入 | `hooks.json` 不可解析 ⟹ 拒写（exit 3），备份与校验都在落盘前后 |
| 原子写 | 同目录临时文件 + `os.replace` |

用法：
  python3 scripts/gk_hook_manage.py status  [--hooks PATH] [--skill-dir DIR] [--profile safe|full|off] [--json]
  python3 scripts/gk_hook_manage.py install [--hooks PATH] [--skill-dir DIR] [--profile safe|full|off] [--dry-run]
  python3 scripts/gk_hook_manage.py sync    [--hooks PATH] [--skill-dir DIR] [--profile safe|full|off] [--dry-run]
  python3 scripts/gk_hook_manage.py uninstall [--hooks PATH] [--skill-dir DIR] [--dry-run]

`sync`（2026-11-04，用户：「插件的安装钩子需要自动化更新扩展」）= **幂等自动更新**：
先 `status` 判漂移（覆盖面不足 / 命令漂移 / 超时漂移 / 重复登记 / 未登记），
有漂移才走 `install`/`uninstall`（备份 + 原子写 + 回读校验），无漂移零写入。
升级/换机/改动 profile 后只需跑一次 `sync`，不再依赖人工比对 hooks.json。

退出码：0 成功 / 2 参数错 / 3 目标不可解析（fail-closed，零写入）/ 4 写入后校验失败。
"""

import argparse
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

WRAPPER_NAME = "pre_tool_hook_wrapper.sh"
HOOK_TIMEOUT = 10
# 2026-11-04（用户：「插件的安装钩子需要自动化更新扩展」）：safe 面补齐覆盖面 ——
# 旧值 `Edit|Write|SearchReplace|RunCommand` **漏** `CreateFile`/`DeleteFile`（原生写）
# 与 MCP 两形态（`run_mcp` / `mcp__<server>__<tool>`）⟹ 内核里已实现的
# `_mcp_write_path` / MCP 写归一在默认安装下**根本收不到事件**（= 静默绕过）。
# 现按 `pre_tool_hook.EDIT_TOOLS` + MCP 写身份归一同步覆盖面；`mcp__.*` 覆盖任意 MCP 工具名
# （写类判定仍在 hook 内按写动词表做，matcher 只决定"是否送进来"，不承担判定）。
PROFILES = {
    "safe": "SearchReplace|Write|Edit|CreateFile|DeleteFile|RunCommand|run_mcp|mcp__.*",
    "full": "*",
    "off": None,
}
# 覆盖面基准（缺失任一 = 漂移）。MCP 名取代表性形态：`mcp__<server>__<tool>`。
COVERAGE_TOOLS = ("SearchReplace", "Write", "Edit", "CreateFile", "DeleteFile",
                  "RunCommand", "run_mcp", "mcp__fs__write_file")
# 目标文件不可安全使用（不可解析 / 结构不对）⟹ exit 3 + 零写入
BAD_TARGET_ERRORS = ("HOOKS_UNPARSEABLE", "HOOKS_BAD_SHAPE")


def default_hooks_path() -> Path:
    """用户级 hooks.json 位置（TRAE_ENV=cn ⟹ .trae-cn，其余 .trae）。"""
    trae_dir = ".trae-cn" if os.environ.get("TRAE_ENV") == "cn" else ".trae"
    return Path.home() / trae_dir / "hooks.json"


def resolve_hooks_path(explicit: str = "") -> Path:
    if explicit:
        return Path(explicit).expanduser()
    env = os.environ.get("GK_HOOKS_JSON", "")
    if env:
        return Path(env).expanduser()
    return default_hooks_path()


def wrapper_path(skill_dir: str) -> Path:
    return Path(skill_dir).resolve() / "scripts" / WRAPPER_NAME


def hook_command(skill_dir: str) -> str:
    """WSL 形态（/mnt/<drive>/...）须 `wsl bash`；其余 POSIX 直接 bash。"""
    p = str(wrapper_path(skill_dir))
    return ("wsl bash %s" % p) if p.startswith("/mnt/") else ("bash %s" % p)


def _load(hooks_path: Path) -> tuple:
    """→ (data, error)。文件不存在 ⟹ (None, "")；解析失败 ⟹ (None, 原因)。"""
    if not hooks_path.exists():
        return None, ""
    try:
        raw = hooks_path.read_text(encoding="utf-8")
    except OSError as e:
        return None, "read failed: %s" % e
    if not raw.strip():
        # 空文件很常见（工具初始化即建空文件）⟹ 按「无条目」处理，不当作损坏拒装
        return None, ""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        return None, "invalid JSON: %s" % e
    if not isinstance(data, dict):
        return None, "top-level is not an object"
    return data, ""


def _hooks_shape(data) -> str:
    """`hooks` 容器形状检查；返回错误文案（空 = 正常）。

    2026-11-01：非 dict（例如被别的工具写成数组）原先会 AttributeError traceback，
    现在统一走 fail-closed（零写入 + 可读错误）。
    """
    if data is None:
        return ""
    h = data.get("hooks")
    if h is None or isinstance(h, dict):
        return ""
    return "hooks is %s, expected object" % type(h).__name__


def _entries(data: dict) -> list:
    if _hooks_shape(data):
        return []
    hooks = (data or {}).get("hooks") or {}
    pre = hooks.get("PreToolUse")
    return pre if isinstance(pre, list) else []


_PATH_TOKEN_RE = re.compile(r"[^\s\"']*pre_tool_hook[^\s\"']*")


def _canon_path(p: str) -> str:
    """路径规范化比较形态：`\\`→`/`，`/mnt/c/…`→`c:/…`，统一小写。

    2026-11-04（Windows 实测）：原判定把 `json.dumps(entry)` 与原始路径比较 —— Windows 下
    反斜杠被 JSON 转义成 `\\\\`，`re.escape(str(wrapper))` 永远匹配不到，导致
    "刚装完却判 ours=0 ⟹ VERIFY_FAILED"。同一原因也让 `wsl bash /mnt/c/...` 与
    `bash C:\\...` 被当成两条不同命令（每次 status 都报漂移）。两者都必须归一后比较。
    """
    s = (p or "").replace("\\", "/")
    m = re.match(r"^/mnt/([A-Za-z])/(.*)$", s)
    if m:
        s = "%s:/%s" % (m.group(1).upper(), m.group(2))
    return s.lower().rstrip("/")


def _canon_refs(entry) -> set:
    """条目里所有 `pre_tool_hook*` 路径 token 的规范形态（去重）。"""
    refs = set()

    def walk(v):
        if isinstance(v, str):
            for tok in _PATH_TOKEN_RE.findall(v):
                refs.add(_canon_path(tok))
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    walk(entry)
    return refs


def _our_targets(wrapper: Path) -> set:
    """本仓条目判定目标（**边界安全**）：现行 wrapper + 旧版 pre_tool_hook.py。

    目录边界由"整 token 相等"保证 —— `...-r-sequence-2/scripts/...` 是另一个 token，
    不会因为前缀相同被认领。
    """
    root = wrapper.parent.parent
    return {_canon_path(str(wrapper)),
            _canon_path(str(root / "scripts" / "pre_tool_hook.py"))}


def _is_ours(entry: dict, wrapper: Path) -> bool:
    """条目是否指向本仓（wrapper 或旧版 pre_tool_hook.py），按规范化路径 token 匹配。"""
    if not isinstance(entry, dict):
        return False
    targets = _our_targets(wrapper)
    return any(r in targets for r in _canon_refs(entry))


def _coverage_missing(matcher) -> list:
    """matcher 未覆盖的工具名（空 = 全覆盖）。`*` 视为全覆盖；非法正则按"不覆盖"处理。"""
    if matcher is None:
        return list(COVERAGE_TOOLS)
    m = str(matcher).strip()
    if m in ("*", "", ".*"):
        return []
    missing = []
    for tool in COVERAGE_TOOLS:
        try:
            if not re.fullmatch(m, tool):
                missing.append(tool)
        except re.error:
            missing.append(tool)
    return missing


def _same_command(got: str, expected: str) -> bool:
    """命令等价判定（规范化路径比较）：`wsl bash /mnt/c/...` ≡ `bash C:\\...`。"""
    a = _canon_refs({"c": got or ""})
    b = _canon_refs({"c": expected or ""})
    return bool(b) and a == b


def _drift(entries: list, wrapper: Path, skill_dir: str, profile: str,
           strict: bool = False) -> list:
    """把"注册态 vs 期望态"的差异逐条列出（只读，不写）。

    kind ∈ {not_registered, duplicate, wrapper_missing, matcher_mismatch,
            command_mismatch, timeout_mismatch, unexpected_entry}

    `strict=False`（status 默认）：只在**覆盖面不足**时报 matcher_mismatch —— 装得比期望宽
    （如 profile=full 的 `*`）算健康，不制造假红。
    `strict=True`（sync 用）：matcher 与目标 profile 不逐字相等即报 —— 换 profile 时需要
    真正收敛到目标覆盖面（否则 `full → safe` 的降级永远不会发生）。
    """
    ours = [e for e in entries if _is_ours(e, wrapper)]
    if profile == "off":
        return ([{"kind": "unexpected_entry", "count": len(ours)}] if ours else [])
    drift = []
    if not wrapper.is_file():
        drift.append({"kind": "wrapper_missing", "path": str(wrapper)})
    if not ours:
        drift.append({"kind": "not_registered"})
        return drift
    if len(ours) > 1:
        drift.append({"kind": "duplicate", "count": len(ours)})
    exp_cmd = hook_command(skill_dir)
    exp_matcher = PROFILES[profile]
    for e in ours:
        got_matcher = e.get("matcher")
        if got_matcher != exp_matcher:
            miss = _coverage_missing(got_matcher)
            if miss or strict:
                drift.append({"kind": "matcher_mismatch", "matcher": got_matcher,
                              "expected": exp_matcher,
                              "coverage_missing": miss,
                              "covers_expected": not miss})
        for h in (e.get("hooks") or []):
            if not isinstance(h, dict):
                continue
            if not _same_command(h.get("command") or "", exp_cmd):
                drift.append({"kind": "command_mismatch", "command": h.get("command"),
                              "expected": exp_cmd})
            if h.get("timeout") != HOOK_TIMEOUT:
                drift.append({"kind": "timeout_mismatch", "timeout": h.get("timeout"),
                              "expected": HOOK_TIMEOUT})
    return drift


def load_status(hooks_path=None, skill_dir="", profile="safe", strict=False) -> dict:
    """只读探测（无副作用）：注册态 + 命令可达性 + 漂移清单。"""
    hp = Path(hooks_path) if hooks_path else resolve_hooks_path()
    wrapper = wrapper_path(skill_dir or str(Path(__file__).resolve().parent.parent))
    st = {
        "hooks_path": str(hp),
        "skill_dir": str(wrapper.parent.parent),
        "wrapper": str(wrapper),
        "command": hook_command(str(wrapper.parent.parent)),
        "exists": hp.exists(),
        "source": "absent",
        "ours": 0,
        "foreign": 0,
        "command_ok": wrapper.is_file(),
        "profile": profile,
        "drift": [],
        "detail": "",
    }
    data, err = _load(hp)
    if err:
        st["source"] = "unparseable" if hp.exists() else "error"
        st["detail"] = err
        st["drift"] = [{"kind": "unparseable", "detail": err}]
        return st
    if data is None:
        st["drift"] = _drift([], wrapper, str(wrapper.parent.parent), profile, strict)
        return st
    shape = _hooks_shape(data)
    if shape:
        st["source"] = "bad_shape"
        st["detail"] = shape
        st["drift"] = [{"kind": "bad_shape", "detail": shape}]
        return st
    entries = _entries(data)
    st["ours"] = sum(1 for e in entries if _is_ours(e, wrapper))
    st["foreign"] = len(entries) - st["ours"]
    st["source"] = "registered" if st["ours"] else ("foreign" if entries else "absent")
    st["drift"] = _drift(entries, wrapper, str(wrapper.parent.parent), profile, strict)
    # 命令可达性：注册了但 wrapper 不在 ⟹ 漏加载（换机/卸载不净的典型病象）
    if st["ours"] and not st["command_ok"]:
        st["detail"] = "registered command points to a missing wrapper"
    return st


def _backup(hp: Path) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    bak = hp.with_name(hp.name + ".bak-" + ts)
    shutil.copy2(hp, bak)
    return str(bak)


def _atomic_write(hp: Path, data: dict) -> None:
    hp.parent.mkdir(parents=True, exist_ok=True)
    tmp = hp.with_name(hp.name + ".tmp-%d" % os.getpid())
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, hp)


def _entry_for(skill_dir: str, profile: str) -> dict:
    matcher = PROFILES[profile]
    return {
        "matcher": matcher,
        "hooks": [{"type": "command", "command": hook_command(skill_dir),
                   "timeout": HOOK_TIMEOUT}],
    }


def install(hooks_path=None, skill_dir="", profile="safe", dry_run=False) -> dict:
    """非破坏合并：摘掉旧的本仓条目 → 按 profile 追加 → 原子写 → 回读校验。"""
    if profile not in PROFILES:
        return {"ok": False, "error": "BAD_PROFILE", "detail": "profile must be safe|full|off"}
    hp = Path(hooks_path) if hooks_path else resolve_hooks_path()
    sd = skill_dir or str(Path(__file__).resolve().parent.parent)
    wrapper = wrapper_path(sd)
    if profile != "off" and not wrapper.is_file():
        # 漏加载拦在写前：注册一条恒失败的钩子 = 后续每次工具调用都被拦
        return {"ok": False, "error": "WRAPPER_MISSING", "detail": str(wrapper)}

    data, err = _load(hp)
    if err:
        return {"ok": False, "error": "HOOKS_UNPARSEABLE", "detail": err,
                "hint": "修好或移走 %s 后重试（fail-closed，零写入）" % hp}
    if data is None:
        data = {"version": 1, "hooks": {"PreToolUse": []}}

    shape = _hooks_shape(data)
    if shape:
        return {"ok": False, "error": "HOOKS_BAD_SHAPE", "detail": shape,
                "hint": "hooks 必须是对象；修好或移走 %s 后重试（fail-closed，零写入）" % hp}

    data.setdefault("hooks", {})
    pre = data["hooks"].get("PreToolUse")
    if not isinstance(pre, list):
        pre = []
    kept = [e for e in pre if not _is_ours(e, wrapper)]
    removed = len(pre) - len(kept)
    out = list(kept)
    if PROFILES[profile] is not None:
        out.append(_entry_for(sd, profile))
    data["hooks"]["PreToolUse"] = out

    changed = (out != pre)
    result = {"ok": True, "hooks_path": str(hp), "profile": profile,
              "removed_stale": removed, "changed": changed, "dry_run": bool(dry_run),
              "command": hook_command(sd)}
    if dry_run or not changed:
        return result

    result["backup"] = _backup(hp) if hp.exists() else ""
    _atomic_write(hp, data)
    st = load_status(hp, sd)
    expect = 0 if PROFILES[profile] is None else 1
    if st["source"] == "unparseable" or st["ours"] != expect:
        result.update({"ok": False, "error": "VERIFY_FAILED", "status": st})
        return result
    result["status"] = st
    return result


def uninstall(hooks_path=None, skill_dir="", dry_run=False) -> dict:
    """只摘本仓条目（可逆效应）；用户条目逐字保留。"""
    hp = Path(hooks_path) if hooks_path else resolve_hooks_path()
    sd = skill_dir or str(Path(__file__).resolve().parent.parent)
    wrapper = wrapper_path(sd)

    data, err = _load(hp)
    if err:
        return {"ok": False, "error": "HOOKS_UNPARSEABLE", "detail": err,
                "hint": "fail-closed，零写入；请人工检查 %s" % hp}
    if data is None:
        return {"ok": True, "hooks_path": str(hp), "removed": 0, "changed": False,
                "detail": "hooks.json 不存在，无需卸载"}

    shape = _hooks_shape(data)
    if shape:
        return {"ok": False, "error": "HOOKS_BAD_SHAPE", "detail": shape,
                "hint": "hooks 必须是对象；fail-closed，零写入；请人工检查 %s" % hp}

    pre = _entries(data)
    kept = [e for e in pre if not _is_ours(e, wrapper)]
    removed = len(pre) - len(kept)
    out = {"ok": True, "hooks_path": str(hp), "removed": removed,
           "changed": removed > 0, "dry_run": bool(dry_run)}
    if removed == 0 or dry_run:
        return out
    data.setdefault("hooks", {})["PreToolUse"] = kept
    out["backup"] = _backup(hp)
    _atomic_write(hp, data)
    st = load_status(hp, sd)
    if st["ours"] != 0:
        out.update({"ok": False, "error": "VERIFY_FAILED", "status": st})
        return out
    out["status"] = st
    return out


def sync(hooks_path=None, skill_dir="", profile="safe", dry_run=False) -> dict:
    """幂等自动更新：有漂移才写，无漂移零写入（2026-11-04，用户「安装钩子自动化更新」）。

    `install` 本身已是"摘旧 + 按 profile 追加"，但**没人自动调用它** —— 升级、换机、
    改 profile 之后注册项会一直停在旧形态（matcher 覆盖面不足 / 命令仍指旧路径），
    症状是"钩子看着装着，实际收不到某些工具事件"。`sync` 把"判漂移 → 修 → 回读校验"
    收成一条命令，供 install.sh / 升级脚本 / self-check 复用（单一事实源，不复制判定）。
    """
    if profile not in PROFILES:
        return {"ok": False, "error": "BAD_PROFILE", "detail": "profile must be safe|full|off"}
    hp = Path(hooks_path) if hooks_path else resolve_hooks_path()
    sd = skill_dir or str(Path(__file__).resolve().parent.parent)
    before = load_status(hp, sd, profile, strict=True)
    # 目标不可用 ⟹ fail-closed（零写入），绝不用 install 去"顺手修好"别人的坏文件
    if before["source"] in ("unparseable", "bad_shape"):
        return {"ok": False,
                "error": "HOOKS_UNPARSEABLE" if before["source"] == "unparseable" else "HOOKS_BAD_SHAPE",
                "detail": before.get("detail", ""),
                "hint": "修好或移走 %s 后重试（fail-closed，零写入）" % hp,
                "drift_before": before.get("drift") or []}
    drift_before = before.get("drift") or []
    if not drift_before:
        return {"ok": True, "action": "none", "hooks_path": str(hp), "profile": profile,
                "drift_before": [], "drift_after": [], "status": before,
                "dry_run": bool(dry_run)}
    if dry_run:
        return {"ok": True, "action": "dry_run", "hooks_path": str(hp), "profile": profile,
                "drift_before": drift_before, "drift_after": [],
                "status": before, "dry_run": True}
    res = uninstall(hp, sd) if profile == "off" else install(hp, sd, profile)
    if not res.get("ok"):
        return {"ok": False, "action": "update_failed",
                "error": res.get("error"), "detail": res.get("detail", ""),
                "hint": res.get("hint", ""), "drift_before": drift_before, "result": res}
    after = load_status(hp, sd, profile, strict=True)
    drift_after = after.get("drift") or []
    return {"ok": not drift_after, "action": "updated", "hooks_path": str(hp),
            "profile": profile, "changed": res.get("changed"),
            "backup": res.get("backup", ""), "drift_before": drift_before,
            "drift_after": drift_after, "status": after,
            **({"error": "VERIFY_FAILED"} if drift_after else {})}


def _render(res: dict) -> str:
    if "source" in res:  # status
        lines = ["hooks: %s" % res["hooks_path"],
                 "state: %s (ours=%d foreign=%d)" % (res["source"], res["ours"], res["foreign"]),
                 "command: %s [%s]" % (res["command"], "ok" if res["command_ok"] else "MISSING")]
        drift = res.get("drift") or []
        lines.append("drift: %s" % ("none" if not drift else json.dumps(drift, ensure_ascii=False)))
        if res["detail"]:
            lines.append("detail: %s" % res["detail"])
        return "\n".join(lines)
    if res.get("action"):
        if res["action"] in ("none", "dry_run"):
            return "sync: action=%s drift=%d%s" % (
                res["action"], len(res.get("drift_before") or []),
                " (dry-run)" if res.get("dry_run") else "")
        if not res.get("ok"):
            return "FAIL sync: %s %s" % (res.get("error", "?"), res.get("detail", ""))
        return "sync: updated changed=%s backup=%s drift_after=%d" % (
            res.get("changed"), res.get("backup", "") or "-",
            len(res.get("drift_after") or []))
    if not res.get("ok"):
        return "FAIL %s: %s" % (res.get("error", "?"), res.get("detail", ""))
    if "removed" in res:
        return "uninstall: removed=%d%s" % (res["removed"], " (dry-run)" if res.get("dry_run") else "")
    return "install: profile=%s changed=%s removed_stale=%d%s" % (
        res.get("profile"), res.get("changed"), res.get("removed_stale", 0),
        " (dry-run)" if res.get("dry_run") else "")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="PreToolUse 钩子安装/更新/卸载（加载安全网）")
    ap.add_argument("cmd", choices=["status", "install", "sync", "uninstall"])
    ap.add_argument("--hooks", default="")
    ap.add_argument("--skill-dir", default="")
    ap.add_argument("--profile", default="safe", choices=sorted(PROFILES))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    if a.cmd == "status":
        res = load_status(a.hooks, a.skill_dir, a.profile)
        rc = 0 if res["source"] not in ("unparseable", "bad_shape") else 3
    elif a.cmd == "install":
        res = install(a.hooks, a.skill_dir, a.profile, a.dry_run)
        rc = 0 if res.get("ok") else (3 if res.get("error") in BAD_TARGET_ERRORS else 4)
    elif a.cmd == "sync":
        res = sync(a.hooks, a.skill_dir, a.profile, a.dry_run)
        rc = 0 if res.get("ok") else (3 if res.get("error") in BAD_TARGET_ERRORS else 4)
    else:
        res = uninstall(a.hooks, a.skill_dir, a.dry_run)
        rc = 0 if res.get("ok") else (3 if res.get("error") in BAD_TARGET_ERRORS else 4)

    print(json.dumps(res, ensure_ascii=False) if a.json else _render(res))
    return rc


if __name__ == "__main__":
    sys.exit(main())

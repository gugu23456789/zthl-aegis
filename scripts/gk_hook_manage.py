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
  python3 scripts/gk_hook_manage.py status  [--hooks PATH] [--skill-dir DIR] [--json]
  python3 scripts/gk_hook_manage.py install [--hooks PATH] [--skill-dir DIR] [--profile safe|full|off] [--dry-run]
  python3 scripts/gk_hook_manage.py uninstall [--hooks PATH] [--skill-dir DIR] [--dry-run]

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
PROFILES = {"safe": "Edit|Write|SearchReplace|RunCommand", "full": "*", "off": None}
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


def _ours_matchers(wrapper: Path) -> list:
    """本仓条目判定器（**边界安全**）。

    两种形态都要认：
      1. 现行：`<skill>/scripts/pre_tool_hook_wrapper.sh`
      2. 旧版：`<skill>/scripts/pre_tool_hook.py`（历史安装器注册形态）
    目录前缀后必须紧跟 `/`，避免 `...-r-sequence` 误匹配 `...-r-sequence-2`。
    """
    root = wrapper.parent.parent
    sep = r"[/\\]"
    return [
        re.compile(re.escape(str(wrapper))),
        re.compile(re.escape(str(root)) + sep + r"scripts" + sep + r"pre_tool_hook\.py"),
    ]


def _is_ours(entry: dict, wrapper: Path) -> bool:
    """条目是否指向本仓（wrapper 或旧版 pre_tool_hook.py），按路径边界匹配。"""
    if not isinstance(entry, dict):
        return False
    blob = json.dumps(entry, ensure_ascii=False)
    return any(p.search(blob) for p in _ours_matchers(wrapper))


def load_status(hooks_path=None, skill_dir="") -> dict:
    """只读探测（无副作用）：注册态 + 命令可达性。"""
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
        "detail": "",
    }
    data, err = _load(hp)
    if err:
        st["source"] = "unparseable" if hp.exists() else "error"
        st["detail"] = err
        return st
    if data is None:
        return st
    shape = _hooks_shape(data)
    if shape:
        st["source"] = "bad_shape"
        st["detail"] = shape
        return st
    entries = _entries(data)
    st["ours"] = sum(1 for e in entries if _is_ours(e, wrapper))
    st["foreign"] = len(entries) - st["ours"]
    st["source"] = "registered" if st["ours"] else ("foreign" if entries else "absent")
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
        "hooks": [{"type": "command", "command": hook_command(skill_dir), "timeout": 10}],
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


def _render(res: dict) -> str:
    if "source" in res:  # status
        lines = ["hooks: %s" % res["hooks_path"],
                 "state: %s (ours=%d foreign=%d)" % (res["source"], res["ours"], res["foreign"]),
                 "command: %s [%s]" % (res["command"], "ok" if res["command_ok"] else "MISSING")]
        if res["detail"]:
            lines.append("detail: %s" % res["detail"])
        return "\n".join(lines)
    if not res.get("ok"):
        return "FAIL %s: %s" % (res.get("error", "?"), res.get("detail", ""))
    if "removed" in res:
        return "uninstall: removed=%d%s" % (res["removed"], " (dry-run)" if res.get("dry_run") else "")
    return "install: profile=%s changed=%s removed_stale=%d%s" % (
        res.get("profile"), res.get("changed"), res.get("removed_stale", 0),
        " (dry-run)" if res.get("dry_run") else "")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="PreToolUse 钩子安装/卸载（加载安全网）")
    ap.add_argument("cmd", choices=["status", "install", "uninstall"])
    ap.add_argument("--hooks", default="")
    ap.add_argument("--skill-dir", default="")
    ap.add_argument("--profile", default="safe", choices=sorted(PROFILES))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    if a.cmd == "status":
        res = load_status(a.hooks, a.skill_dir)
        rc = 0 if res["source"] not in ("unparseable", "bad_shape") else 3
    elif a.cmd == "install":
        res = install(a.hooks, a.skill_dir, a.profile, a.dry_run)
        rc = 0 if res.get("ok") else (3 if res.get("error") in BAD_TARGET_ERRORS else 4)
    else:
        res = uninstall(a.hooks, a.skill_dir, a.dry_run)
        rc = 0 if res.get("ok") else (3 if res.get("error") in BAD_TARGET_ERRORS else 4)

    print(json.dumps(res, ensure_ascii=False) if a.json else _render(res))
    return rc


if __name__ == "__main__":
    sys.exit(main())

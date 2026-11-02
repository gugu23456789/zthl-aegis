#!/usr/bin/env python3
"""gk_apply_worktree_cli.py — `apply-worktree` 的内联载荷**单源出口**（2026-10-29）

## 为什么有它

`cmd_apply_worktree`（`gatekeeper-cli.sh` L8206 起）里原有 14 处 `python3 -c "..."`：
取 JSON 字段、拼回包、判收口 verdict 等。内联载荷**不可单测**、引号层数多、且
`test_agent_cli_wiring._code_fix_seg()` 以「列 0 的 `}`」取函数边界 ⟹ 载荷本体
不得出现列 0 花括号。本模块把这些载荷收敛为**可测子命令**，bash 侧只做参数编排。

## 子命令（全部单行输出；失败面显式）

| 子命令 | 输入 | 输出 |
|:--|:--|:--|
| `json-field <key>` | stdin JSON | 该键的字符串值（缺失/非 dict/坏 JSON ⟹ 空串） |
| `json-field-raw <key> [default-json]` | stdin JSON | 该键的 JSON 字面量（缺失 ⟹ `default-json`，缺省 `null`） |
| `json-list-join <key>` | stdin JSON | 该键数组的逗号拼接（缺失/坏 JSON ⟹ 空串） |
| `codefix-dry` | stdin 族判定 JSON | 加 `dispatchable=false` + 不可派发原因（dry-run 语义） |
| `route-root` | — | `gk_route_center.DEV_WORKTREE_ROOTS[0]`（缺 ⟹ 空串） |
| `spillover` | env `STATE_FILE` / `GK_SP_DRY` | `gk_finding.spillover_open` 的 JSON |
| `plan-merge` | env `PJ` / `PSTATE` / `PDET` | 计划建树回包（加 mode/state_file/discover_worktree） |
| `closeout-verdict` | env `ACCEPT_JSON` | `accept.global.verdict`（缺 ⟹ `unknown`） |
| `closeout-next` | env `ACCEPT_JSON` / `FIDS` / `CLOSE_JSON` | 收口摘要（verdict/findings/auto_closed/closeable/next） |
| `closeout-aggregate` | env `ACCEPT_JSON` / `CLOSEOUT_JSON` / `RECLAIM_JSON` / `GX_STATUS` | 收口总回包 |
| `precheck-tail` | stdin JSON | `<error_class>: <error>`（含 `precheck.error`） |
| `json-escape` | stdin 原文 | JSON 字符串字面量 |

## 约定

- 一律**不**做业务判定（判定留在既有单源：`gk_finding` / `gk_route_center`）；
- 解析失败**不崩**：给空串 / `unknown` / `_raw`，由 bash 侧按既有 fail-loud 分支处理；
- 所有输出为**单行**（可直接拼进 bash 回包）。
"""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


def _load_env_json(key: str) -> dict:
    """env 里的 JSON 对象；坏 JSON / 非 dict ⟹ `{}`（调用方按缺省分支处理）。"""
    try:
        v = json.loads(os.environ.get(key) or "{}")
    except (ValueError, TypeError):
        return {}
    return v if isinstance(v, dict) else {}


def _read_stdin() -> str:
    try:
        return sys.stdin.read()
    except (OSError, UnicodeDecodeError):
        return ""


def cmd_json_field(key: str) -> int:
    """stdin JSON 的字符串字段（`null` / 缺失 / 非 dict / 坏 JSON ⟹ 空串）。"""
    raw = _read_stdin()
    try:
        obj = json.loads(raw) if raw.strip() else {}
    except (ValueError, TypeError):
        obj = {}
    if not isinstance(obj, dict):
        obj = {}
    val = obj.get(key, "")
    print("" if val is None else str(val))
    return 0


def cmd_json_field_raw(key: str, default_json: str = "null") -> int:
    """stdin JSON 的某键 → **JSON 字面量**（供 bash 直接拼进回包，如 `allowed_paths`）。"""
    raw = _read_stdin()
    try:
        obj = json.loads(raw) if raw.strip() else {}
    except (ValueError, TypeError):
        obj = {}
    if not isinstance(obj, dict):
        obj = {}
    try:
        default = json.loads(default_json)
    except (ValueError, TypeError):
        default = None
    print(json.dumps(obj.get(key, default), ensure_ascii=False))
    return 0


def cmd_json_list_join(key: str) -> int:
    """stdin JSON 的数组键 → 逗号拼接（`allowed_paths` 记账用）。"""
    raw = _read_stdin()
    try:
        obj = json.loads(raw) if raw.strip() else {}
    except (ValueError, TypeError):
        obj = {}
    if not isinstance(obj, dict):
        obj = {}
    val = obj.get(key)
    print(",".join(str(x) for x in val) if isinstance(val, list) else "")
    return 0


_DRY_REASON = ("dry-run：worktree 未建 ⟹ narrow_task 的 worktree: 行为空；直接派发会把落刀打回调用方 cwd"
               "（主树）。请去掉 --dry-run 真派发，改用返回的 next 串（它带 --task-file，可直接执行）。")


def cmd_codefix_dry() -> int:
    """族判定回包 + `dispatchable=false`（dry-run 不得被当成可派发串）。"""
    raw = _read_stdin()
    try:
        obj = json.loads(raw) if raw.strip() else {}
    except (ValueError, TypeError):
        obj = {}
    if not isinstance(obj, dict):
        obj = {}
    obj["dispatchable"] = False
    obj["not_dispatchable_reason"] = _DRY_REASON
    print(json.dumps(obj, ensure_ascii=False))
    return 0


def cmd_route_root() -> int:
    try:
        import gk_route_center as rc
        roots = getattr(rc, "DEV_WORKTREE_ROOTS", []) or []
        print(roots[0] if roots else "")
    except Exception as e:  # noqa: BLE001 — 边界：缺依赖只影响本行，不崩 CLI
        sys.stderr.write("route-root: %s: %s\n" % (type(e).__name__, e))
        print("")
    return 0


def cmd_spillover() -> int:
    import gk_finding as F
    out = F.spillover_open(os.environ.get("STATE_FILE", ""),
                           dry_run=(os.environ.get("GK_SP_DRY") == "1"))
    print(json.dumps(out, ensure_ascii=False))
    return 0


def cmd_plan_merge() -> int:
    out = _load_env_json("PJ")
    out["mode"] = "plan"
    out["state_file"] = os.environ.get("PSTATE", "")
    out["discover_worktree"] = os.environ.get("PDET", "")
    print(json.dumps(out, ensure_ascii=False))
    return 0


def _accept_verdict(acc: dict) -> str:
    return (((acc.get("accept") or {}).get("global") or {}).get("verdict") or "unknown")


def cmd_closeout_verdict() -> int:
    print(_accept_verdict(_load_env_json("ACCEPT_JSON")))
    return 0


def cmd_closeout_next() -> int:
    acc = _load_env_json("ACCEPT_JSON")
    cl = _load_env_json("CLOSE_JSON")
    fids = [x for x in (os.environ.get("FIDS") or "").split(",") if x.strip()]
    verdict = _accept_verdict(acc)
    auto = bool(cl.get("auto_closed"))
    nxt = ""
    if not auto and verdict == "pass" and fids:
        nxt = " ".join(
            "bash gatekeeper-cli.sh finding close %s --verify-source tests:accept-pass" % f
            for f in fids)
    print(json.dumps({"verdict": verdict, "findings": fids, "auto_closed": auto,
                      "closeable": bool(verdict == "pass" and fids), "next": nxt},
                     ensure_ascii=False))
    return 0


def _parse_or_raw(key: str) -> dict:
    raw = os.environ.get(key) or "{}"
    try:
        obj = json.loads(raw)
    except Exception:  # noqa: BLE001 — 边界：保留原文片段供诊断
        return {"_raw": raw[:2000]}
    return obj if isinstance(obj, dict) else {"_raw": raw[:2000]}


def cmd_closeout_aggregate() -> int:
    print(json.dumps({
        "ok": True,
        "mode": "close_out",
        "accept": _parse_or_raw("ACCEPT_JSON"),
        "closeout": _parse_or_raw("CLOSEOUT_JSON"),
        "reclaim": _parse_or_raw("RECLAIM_JSON"),
        "gitnexus": {"status": os.environ.get("GX_STATUS") or "unknown"},
    }, ensure_ascii=False))
    return 0


def cmd_precheck_tail() -> int:
    """从 precheck 回包拼真因（`<类名>: <文案>`）；无内容 ⟹ 空行。"""
    raw = _read_stdin()
    try:
        o = json.loads(raw) if raw.strip() else {}
    except (ValueError, TypeError):
        o = {}
    if not isinstance(o, dict):
        o = {}
    cls = str(o.get("error_class") or "")
    err = str(o.get("error") or "")
    pre = o.get("precheck") if isinstance(o.get("precheck"), dict) else {}
    perr = str(pre.get("error") or "")
    msg = "; ".join(x for x in (err, perr) if x)
    print((cls + ": " if cls else "") + msg)
    return 0


def cmd_json_escape() -> int:
    print(json.dumps(_read_stdin(), ensure_ascii=False))
    return 0


_COMMANDS = {
    "json-field": lambda argv: cmd_json_field(argv[0]) if argv else 2,
    "json-field-raw": lambda argv: cmd_json_field_raw(argv[0], argv[1] if len(argv) > 1 else "null") if argv else 2,
    "json-list-join": lambda argv: cmd_json_list_join(argv[0]) if argv else 2,
    "codefix-dry": lambda argv: cmd_codefix_dry(),
    "route-root": lambda argv: cmd_route_root(),
    "spillover": lambda argv: cmd_spillover(),
    "plan-merge": lambda argv: cmd_plan_merge(),
    "closeout-verdict": lambda argv: cmd_closeout_verdict(),
    "closeout-next": lambda argv: cmd_closeout_next(),
    "closeout-aggregate": lambda argv: cmd_closeout_aggregate(),
    "precheck-tail": lambda argv: cmd_precheck_tail(),
    "json-escape": lambda argv: cmd_json_escape(),
}


def main(argv: list) -> int:
    if not argv or argv[0] not in _COMMANDS:
        sys.stderr.write("usage: gk_apply_worktree_cli.py <%s> [args]\n"
                         % "|".join(sorted(_COMMANDS)))
        return 2
    return _COMMANDS[argv[0]](argv[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

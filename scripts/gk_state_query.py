#!/usr/bin/env python3
"""
gk_state_query.py -- 确定性 state 字段查询（batch8 R-T6 收尾批次 0）
=====================================================================
替代 gatekeeper-cli.sh 内嵌 `python3 -c "import json;d=json.load(open('$STATE_FILE'));print(...)"`
的纯查询类内联。输出语义与 python print() 完全一致（str 原样 / 其余 repr），
保证 bash 侧输出契约不变。

Usage:
  STATE_FILE=<path> python3 gk_state_query.py --get <a.b.c> [--default <raw>]
  STATE_FILE=<path> python3 gk_state_query.py --dump <a.b.c> [--indent 2] [--default <raw>]
  STATE_FILE=<path> python3 gk_state_query.py --len <a.b.c> [--default 0]
  STATE_FILE=<path> python3 gk_state_query.py --gt <a.b.c> <threshold>      # 输出 yes/no：数值 > threshold
  STATE_FILE=<path> python3 gk_state_query.py --contains <a.b.c> <value>    # 输出 yes/no：list 含 value / dict 含 key
  STATE_FILE=<path> python3 gk_state_query.py --tail <a.b.c> <N> [--indent K] # 输出 json.dumps(list[-N:])（默认紧凑；--indent K ⟹ 缩进，非 list 失败 rc=1）
  STATE_FILE=<path> python3 gk_state_query.py --history-len                # 输出 union 条数（主 state ⊕ 卫星 history 片）
  STATE_FILE=<path> python3 gk_state_query.py --history-last-task [--max N] # 输出 union 末条 task（默认截 120）

Exit codes:
  0 = found（--dump 路径缺失时也输出 {} 并返回 0，对齐 `d.get(path, {})` + `print(json.dumps(...))`）
  1 = state 不可读 / 未找到（--get/--len 输出 --default；--dump 输出空，对齐旧 `2>/dev/null` 静默失败）
  2 = usage error

注意：--get/--len 已输出 --default 即返回 1，调用处勿再加 `|| echo default`
（会双重输出）；--dump 的 `|| echo "{}"` 可保留（仅 state 不可读时触发，对齐原 `|| echo "{}"`）。
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gk_state import _read_state, _resolve_default_state  # noqa: E402


def _get_path(d: dict, path: str):
    """沿 'a.b.c' 路径取值；任一级缺失返回 None（等价原 .get() 链）。"""
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _pyprint(v) -> str:
    """与 python print() 输出一致：str 原样，其余 repr（True/False、数字、单引号 dict/list）。"""
    if isinstance(v, str):
        return v
    return repr(v)


def _history_mode(args: list) -> int:
    """`--history-len` / `--history-last-task`：**union 读面**（主 state ⊕ 卫星 history 片）。

    单源 = `gk_moa_aggregate.history_union`（禁第二实现）。缺片（索引声明有而片不在）
    fail-loud：stderr JSON + exit 1，**不**回落到 live 计数（防静默部分历史 = 读分裂）。
    """
    from gk_state_route import read_point_pointer_error
    _rp_err = read_point_pointer_error()
    if _rp_err:
        sys.stderr.write(json.dumps(_rp_err, ensure_ascii=False) + "\n")
        return 1
    state_file = os.environ.get("STATE_FILE", "") or _resolve_default_state()
    data = _read_state(state_file)
    if "error" in data:
        sys.stderr.write(json.dumps({"error": data.get("error"), "state": state_file},
                                    ensure_ascii=False) + "\n")
        return 1
    try:
        import gk_moa_aggregate as MA
        hist, _info = MA.history_union(state_file, data)
    except Exception as e:  # noqa: BLE001 — 缺片/读失败 fail-loud（值通道走 stderr）
        sys.stderr.write(json.dumps({"error": "%s: %s" % (type(e).__name__, e)},
                                    ensure_ascii=False) + "\n")
        return 1
    if args[0] == "--history-len":
        print(len(hist))
        return 0
    maxlen = 120
    i = 1
    while i < len(args):
        if args[i] == "--max" and i + 1 < len(args):
            try:
                maxlen = int(args[i + 1])
            except ValueError:
                pass
            i += 2
        else:
            i += 1
    last = hist[-1] if hist else {}
    print(str(last.get("task", "") or "")[:maxlen])
    return 0


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    two_arg_modes = ("--gt", "--contains", "--tail")
    if args and args[0] in ("--history-len", "--history-last-task"):
        return _history_mode(args)
    if len(args) < 2 or args[0] not in ("--get", "--dump", "--len") + two_arg_modes:
        print('{"error":"usage: --get <path> [--default v] | --dump <path> [--indent N] | --len <path> [--default n] | --gt <path> <t> | --contains <path> <v> | --tail <path> <N>"}')
        return 2

    mode, path = args[0], args[1]
    extra = args[2] if args[0] in two_arg_modes else ""
    default = ""
    has_default = False
    indent = 2
    indent_given = False
    i = 3 if args[0] in two_arg_modes else 2
    while i < len(args):
        if args[i] == "--default" and i + 1 < len(args):
            default = args[i + 1]
            has_default = True
            i += 2
        elif args[i] == "--indent" and i + 1 < len(args):
            try:
                indent = int(args[i + 1])
            except ValueError:
                pass
            indent_given = True
            i += 2
        else:
            i += 1

    # §18.2 判据 c3（2026-10-04）：declared-but-unresolved（指针 stale/dangling）⟹ 禁静默读 base。
    #   本命令 stdout 是**值通道**（调用方按值消费）⟹ 错误走 stderr + 非零退出，不污染值面。
    from gk_state_route import read_point_pointer_error
    _rp_err = read_point_pointer_error()
    if _rp_err:
        sys.stderr.write(json.dumps(_rp_err, ensure_ascii=False) + "\n")
        return 1
    state_file = os.environ.get("STATE_FILE", "") or _resolve_default_state()
    data = _read_state(state_file)
    if "error" in data:
        # state 不可读（缺文件/坏 JSON）→ 对齐旧 python 崩溃：--gt/--contains 输出 no（exit 1，
        # bash `|| echo no` 若保留会兜底 no）；--tail 输出空（`|| echo '[]'` 兜底）；--dump 输出空
        if mode == "--dump":
            return 1
        if mode == "--tail":
            print("")
            return 1
        if mode in two_arg_modes:
            print("no")
            return 1
        print(default)
        return 1

    val = _get_path(data, path)
    if val is None:
        if mode == "--dump":
            # 路径缺失 → 对齐 `d.get(path, 默认)`：有 --default 输出它，否则输出 {}
            print(default if has_default else "{}")
            return 0
        if mode in two_arg_modes:
            # 路径缺失 → d.get(path, 默认) 成功输出默认（exit 0）：--gt/--contains → no；--tail → []
            print("no" if mode != "--tail" else "[]")
            return 0
        print(default)
        return 1

    if mode == "--get":
        print(_pyprint(val))
    elif mode == "--dump":
        print(json.dumps(val, indent=indent, ensure_ascii=False))
    elif mode == "--len":
        if isinstance(val, (list, dict, str)):
            print(len(val))
        else:
            print(default)
    elif mode == "--gt":
        try:
            print("yes" if float(val) > float(extra) else "no")
        except (TypeError, ValueError):
            print("no")
    elif mode == "--contains":
        if isinstance(val, (list, dict)):
            print("yes" if extra in val else "no")
        else:
            print("no")
    elif mode == "--tail":
        try:
            n = int(extra)
        except ValueError:
            n = 3
        if indent_given:
            # 对齐旧 `rej[-N:] if len(rej)>N else rej` + `json.dumps(recent, indent=N)`：
            # 非 list 在旧式里是 TypeError（rc≠0）⟹ 此处同样 fail-loud，禁静默输出 items。
            if not isinstance(val, list):
                return 1
            print(json.dumps(val[-n:], indent=indent))
            return 0
        if isinstance(val, list):
            print(json.dumps(val[-n:]))
        elif isinstance(val, dict):
            print(json.dumps(list(val.items())[-n:]))
        else:
            print("[]")
    return 0


if __name__ == "__main__":
    sys.exit(main())

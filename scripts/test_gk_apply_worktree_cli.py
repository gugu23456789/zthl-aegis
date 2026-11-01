#!/usr/bin/env python3
"""`gk_apply_worktree_cli.py` 红先臂（2026-10-29）

## 为什么有本文件

`cmd_apply_worktree` 原有 **25 处** `python3 -c "..."` 内联载荷：取 JSON 字段、拼 dry-run
回包、逃逸窄任务串、拼 `allowed_paths`。问题不是「难看」，而是三条**实测**故障面：

  ① 载荷埋在巨型 bash 函数里 ⟹ 无法单测（只能靠整条 CLI 端到端，故障面被层层 shell 吞掉）；
  ② 引号层数随载荷增长（`'...'` 内嵌 `"..."` 内嵌 JSON），改一处即可能截断整段；
  ③ `test_agent_cli_wiring._code_fix_seg()` 以「列 0 的 `}`」取函数边界 ⟹ 载荷本体一旦
     出现列 0 花括号，切片即提前结束、**整组接线臂静默变成「函数只有一半」**。

修法 = 载荷外移到本模块（子命令化、单行输出、失败面显式），bash 侧只做参数编排。
本文件锁两件事：**子命令语义**与**函数体内 `python3 -c` 计数归零**（后者是本轮主判据）。
"""
import io
import json
import re
import sys
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI_SRC = SKILL_DIR / "gatekeeper-cli.sh"

sys.path.insert(0, str(SCRIPT_DIR))

import gk_apply_worktree_cli as A  # noqa: E402


def _stdin(monkeypatch, text: str) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(text))


def _capture(fn, *args) -> str:
    """跑子命令函数并取 stdout（子命令契约 = 单行输出）。"""
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(*args)
    assert rc == 0, f"{fn.__name__} 非零退出：{rc}"
    return buf.getvalue()


# ── json-field ────────────────────────────────────────────────────────────────
def test_json_field_str(monkeypatch):
    _stdin(monkeypatch, '{"family": "F-ECC-PLAND"}')
    assert _capture(A.cmd_json_field, "family").rstrip("\n") == "F-ECC-PLAND"


def test_json_field_missing_is_empty(monkeypatch):
    _stdin(monkeypatch, '{"a": 1}')
    assert _capture(A.cmd_json_field, "family") == "\n"


def test_json_field_null_is_empty_not_none(monkeypatch):
    """`null` 值不得回 `None`（会写进 bash 变量变成字面量 `None`）。"""
    _stdin(monkeypatch, '{"family": null}')
    assert _capture(A.cmd_json_field, "family") == "\n"


def test_json_field_bad_json_and_non_dict_degrade_to_empty(monkeypatch):
    _stdin(monkeypatch, 'not-json')
    assert _capture(A.cmd_json_field, "family") == "\n"
    _stdin(monkeypatch, '[1,2]')
    assert _capture(A.cmd_json_field, "family") == "\n"
    _stdin(monkeypatch, "")
    assert _capture(A.cmd_json_field, "family") == "\n"


# ── json-field-raw / json-list-join ───────────────────────────────────────────
def test_json_field_raw_keeps_json_literal(monkeypatch):
    _stdin(monkeypatch, '{"allowed_paths": ["scripts/a.py", "scripts/b.py"]}')
    out = _capture(A.cmd_json_field_raw, "allowed_paths", "[]")
    assert json.loads(out) == ["scripts/a.py", "scripts/b.py"]


def test_json_field_raw_default_when_missing(monkeypatch):
    _stdin(monkeypatch, '{"x": 1}')
    assert json.loads(_capture(A.cmd_json_field_raw, "allowed_paths", "[]")) == []


def test_json_field_raw_bad_input_uses_default(monkeypatch):
    _stdin(monkeypatch, '<<<garbage>>>')
    assert json.loads(_capture(A.cmd_json_field_raw, "allowed_paths", "[]")) == []


def test_json_list_join_comma(monkeypatch):
    _stdin(monkeypatch, '{"allowed_paths": ["a.py", "b.py"]}')
    assert _capture(A.cmd_json_list_join, "allowed_paths").rstrip("\n") == "a.py,b.py"


def test_json_list_join_non_list_is_empty(monkeypatch):
    """非数组（含 `null`）⟹ 空串（禁把 dict 迭代成 `key1,key2`）。"""
    _stdin(monkeypatch, '{"allowed_paths": null}')
    assert _capture(A.cmd_json_list_join, "allowed_paths") == "\n"
    _stdin(monkeypatch, '{"allowed_paths": {"a": 1}}')
    assert _capture(A.cmd_json_list_join, "allowed_paths") == "\n"


# ── codefix-dry ───────────────────────────────────────────────────────────────
def test_codefix_dry_marks_not_dispatchable(monkeypatch):
    _stdin(monkeypatch, '{"family": "F-A", "tier": 3}')
    o = json.loads(_capture(A.cmd_codefix_dry))
    assert o["family"] == "F-A" and o["tier"] == 3
    assert o["dispatchable"] is False
    assert "worktree 未建" in o["not_dispatchable_reason"]


def test_codefix_dry_bad_json_still_returns_valid_object(monkeypatch):
    """坏输入不得崩（否则 bash 侧 `$(...)` 拿到空串 ⟹ 回包 JSON 结构被破坏）。"""
    _stdin(monkeypatch, 'not-json')
    o = json.loads(_capture(A.cmd_codefix_dry))
    assert o["dispatchable"] is False and o["not_dispatchable_reason"]


# ── plan-merge / closeout-* / precheck-tail / json-escape ─────────────────────
def test_plan_merge_reads_env(monkeypatch):
    monkeypatch.setenv("PJ", '{"ok": true, "worktree": "/w"}')
    monkeypatch.setenv("PSTATE", "/s/.gatekeeper.state")
    monkeypatch.setenv("PDET", "/w/det")
    o = json.loads(_capture(A.cmd_plan_merge))
    assert o["ok"] is True and o["worktree"] == "/w"
    assert o["mode"] == "plan"
    assert o["state_file"] == "/s/.gatekeeper.state"
    assert o["discover_worktree"] == "/w/det"


def test_closeout_verdict_pass_and_unknown(monkeypatch):
    monkeypatch.setenv("ACCEPT_JSON", '{"accept": {"global": {"verdict": "pass"}}}')
    assert _capture(A.cmd_closeout_verdict).rstrip("\n") == "pass"
    monkeypatch.setenv("ACCEPT_JSON", '{"accept": {}}')
    assert _capture(A.cmd_closeout_verdict).rstrip("\n") == "unknown"
    monkeypatch.setenv("ACCEPT_JSON", "broken")
    assert _capture(A.cmd_closeout_verdict).rstrip("\n") == "unknown"


def test_closeout_next_emits_close_commands_on_pass(monkeypatch):
    monkeypatch.setenv("ACCEPT_JSON", '{"accept": {"global": {"verdict": "pass"}}}')
    monkeypatch.setenv("CLOSE_JSON", '{"auto_closed": false}')
    monkeypatch.setenv("FIDS", "ECC-1,ECC-2")
    o = json.loads(_capture(A.cmd_closeout_next))
    assert o["verdict"] == "pass" and o["findings"] == ["ECC-1", "ECC-2"]
    assert o["closeable"] is True
    assert o["next"].count("finding close") == 2


def test_closeout_next_silent_when_already_auto_closed(monkeypatch):
    """已自动收口 ⟹ 不得再下发关闭命令（重复关闭会污染 verify-source 取证）。"""
    monkeypatch.setenv("ACCEPT_JSON", '{"accept": {"global": {"verdict": "pass"}}}')
    monkeypatch.setenv("CLOSE_JSON", '{"auto_closed": true}')
    monkeypatch.setenv("FIDS", "ECC-1")
    o = json.loads(_capture(A.cmd_closeout_next))
    assert o["next"] == "" and o["auto_closed"] is True


def test_closeout_next_not_closeable_on_non_pass(monkeypatch):
    monkeypatch.setenv("ACCEPT_JSON", '{"accept": {"global": {"verdict": "fail"}}}')
    monkeypatch.setenv("CLOSE_JSON", '{}')
    monkeypatch.setenv("FIDS", "ECC-1")
    o = json.loads(_capture(A.cmd_closeout_next))
    assert o["closeable"] is False and o["next"] == ""


def test_closeout_aggregate_keeps_raw_on_broken_env(monkeypatch):
    """坏 JSON 不得吞掉整段（诊断面须保留原文片段）。"""
    monkeypatch.setenv("ACCEPT_JSON", '{"ok": true}')
    monkeypatch.setenv("CLOSEOUT_JSON", "{broken")
    monkeypatch.setenv("RECLAIM_JSON", '{"n": 2}')
    monkeypatch.setenv("GX_STATUS", "ok")
    o = json.loads(_capture(A.cmd_closeout_aggregate))
    assert o["ok"] is True and o["mode"] == "close_out"
    assert o["accept"] == {"ok": True}
    assert o["closeout"]["_raw"] == "{broken"
    assert o["reclaim"] == {"n": 2}
    assert o["gitnexus"] == {"status": "ok"}


def test_precheck_tail_joins_class_and_errors(monkeypatch):
    _stdin(monkeypatch, '{"error_class": "FamilyError", "error": "boom", '
                        '"precheck": {"error": "deep"}}')
    assert _capture(A.cmd_precheck_tail).rstrip("\n") == "FamilyError: boom; deep"


def test_precheck_tail_empty_input_is_blank(monkeypatch):
    _stdin(monkeypatch, "{}")
    assert _capture(A.cmd_precheck_tail) == "\n"


def test_json_escape_round_trip(monkeypatch):
    raw = '窄任务 "引号" \n 换行 \\ 反斜杠'
    _stdin(monkeypatch, raw)
    assert json.loads(_capture(A.cmd_json_escape)) == raw


# ── main() 派发契约 ───────────────────────────────────────────────────────────
def test_main_unknown_command_is_usage_error():
    assert A.main([]) == 2
    assert A.main(["nope"]) == 2


def test_main_known_command_dispatches(monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"family": "F-A"}'))
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        assert A.main(["json-field", "family"]) == 0
    assert buf.getvalue().rstrip("\n") == "F-A"


def test_every_documented_subcommand_is_registered():
    """docstring 表里的子命令必须全部在 `_COMMANDS`（防「补了函数忘注册」= 本轮实际踩过的坑）。"""
    doc = A.__doc__ or ""
    documented = set(re.findall(r"^\| `([a-z][a-z-]+)(?: <[^`]*>)?", doc, re.M))
    assert documented, "docstring 子命令表未解析到（表格式已变，判据须重校）"
    missing = documented - set(A._COMMANDS)
    assert not missing, f"docstring 声明但未注册：{sorted(missing)}"


# ── ★ 主判据：函数体内 `python3 -c` 归零 ─────────────────────────────────────
def _cmd_apply_worktree_seg() -> str:
    """`cmd_apply_worktree` 整个函数体（切到下一个列 0 的 `}`）。"""
    txt = CLI_SRC.read_text(encoding="utf-8", errors="replace")
    rest = txt[txt.index("cmd_apply_worktree()"):]
    m = re.search(r"(?m)^\}\s*$", rest)
    return rest[: m.end()] if m else rest


def test_no_inline_python_c_payload_in_cmd_apply_worktree():
    """红线（红先）：`cmd_apply_worktree` 体内 `python3 -c` 计数须为 **0**。

    修前实测 25 处（14 处取字段/拼回包 + 11 处 `--code-fix` 分支）。留在体内则
    ①不可单测；②引号层数爆炸；③载荷里的列 0 花括号会截断 `_code_fix_seg()`。
    """
    seg = _cmd_apply_worktree_seg()
    hits = re.findall(r"python3\s+-c\b", seg)
    assert hits == [], (
        f"cmd_apply_worktree 仍有 {len(hits)} 处内联 `python3 -c` 载荷 ⟹ 须外移到 "
        f"scripts/gk_apply_worktree_cli.py（子命令已在同目录测试覆盖）")


def test_inline_payload_replacements_are_referenced():
    """反向臂：外移后的子命令须**真被** bash 侧调用（防空壳脚本 + 载荷被删成空）。"""
    seg = _cmd_apply_worktree_seg()
    used = set(re.findall(r"gk_apply_worktree_cli\.py\"?\s+([a-z][a-z-]+)", seg))
    required = {"json-field", "json-field-raw", "json-list-join", "codefix-dry", "json-escape"}
    assert required <= used, f"未被 cmd_apply_worktree 使用的子命令：{sorted(required - used)}"


@pytest.mark.parametrize("sub,args", [
    ("json-field", ["family"]),
    ("json-field-raw", ["allowed_paths", "[]"]),
    ("json-list-join", ["allowed_paths"]),
    ("codefix-dry", []),
    ("json-escape", []),
])
def test_subcommands_run_via_real_process(monkeypatch, sub, args):
    """进程级：真跑 `python3 <脚本> <sub>`（验 `sys.exit(main(...))` 与编码面）。"""
    import subprocess
    r = subprocess.run([sys.executable, str(SCRIPT_DIR / "gk_apply_worktree_cli.py"), sub, *args],
                       input='{"family": "F-A", "allowed_paths": ["a.py"]}',
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-400:]
    assert r.stdout.strip(), f"{sub} 无输出"
    assert len(r.stdout.strip().splitlines()) == 1, f"{sub} 输出非单行（禁多行拼回包）"

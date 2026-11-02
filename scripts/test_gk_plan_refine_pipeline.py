#!/usr/bin/env python3
"""审查管道 **ctx 漂移族** 红先臂（`ECC-<pipe-ctx>`，2026-09-27 实测）。

背景（实测，非推断）：组1 六臂审查首跑时，`plan-refinement --adjudicate` 返回
`{"ok":false,"error":"adjudicate_failed","detail":"gk_task_gate adjudicate rc=1（记录未落地）"}`
—— 而 `gk_task_gate adjudicate` 其实**已产出富错误**（`phase_mismatch` + record/current
context + 可操作 hint），只是被 CLI 丢弃。真因 = **会话指针**（某次 `discover` 写入）
指向 isolate state `…hook-xenv-form-fix-plan`（`project_type=analysis`）⟹ 治理 state
语义被换（`standing→analysis`）⟹ 入队 ctx 与裁决 ctx 不符。三处同族：

  · F-1 `cmd_plan_refinement --adjudicate`：rc≠0 时丢弃富错误只回「记录未落地」。
  · F-2 同函数 commit 段：`>/dev/null` 丢弃 `gk_task_gate commit` 真因。
  · F-3 plan-pointer 跟随：非 discover 命令静默跟随 discover 写下的指针。

判据面（静态；本仓既有同类「静态臂」先例）：三处新形态在场 ∧ 三处旧式**静默形态**缺席。
⚠ 形态臂不单独作落刀前判据（本仓纪律）—— 行为臂（真跑 CLI 复现 `phase_mismatch` 透传）
另立（须真 state + 真 CLI，重；本切片先落形态面 + 负臂）。
"""
from pathlib import Path

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def _src() -> str:
    return CLI.read_text(encoding="utf-8")


def test_p1_adjudicate_passthrough():
    """F-1：rc≠0 时须**透传** `_adj_out`（富错误），不得只回兜底文案。"""
    s = _src()
    assert '[ "$_adj_rc" != "0" ] || [ -z "$_adj_out" ]' not in s, \
        "F-1: 旧式（rc≠0 时丢弃富错误）仍在"
    assert '"$_adj_rc" != "0"' in s, "F-1: 未见 rc≠0 独立分支"
    assert "printf '%s\\n' \"$_adj_out\"" in s, "F-1: rc≠0 未透传 _adj_out"


def test_p2_commit_reason_surfaced():
    """F-2：commit 真因不得被 `>/dev/null` 丢弃。"""
    s = _src()
    assert '"$GK_DBG_LOG" >/dev/null || _cmt_rc=$?' not in s, \
        "F-2: 旧式（吞 commit 真因）仍在"
    assert "commit_out" in s, "F-2: 未回传 commit_out 字段"


def test_p3_strict_pointer_killswitch():
    """F-3：会话/全局指针须有显式解绑通道（零回归 opt-in）。

    ③ 单源（`ECC-1EC0E0732F0D`）后重定位：解绑判定体在 `gk_state_route.select_plan_pointer`
    （`strict` / `domain_route_off`），bash 启动块零判定、仅消费返回 `reason`。原「`${cmd:-}` 守卫
    （set -u unbound）」判据的前提（该块引用裸 `cmd`）已被 ③ 一并移除 ⟹ 本臂改钉「单源判定 ∧
    bash 消费」，并保留「裸 `$cmd` 形态缺席」负断言（set -u 隐患仍须不复现）。
    """
    s = _src()
    assert "GK_PLAN_POINTER_STRICT" in s, "F-3: 未见 STRICT 解绑开关"
    assert '"strict"' in (CLI.parent / "scripts" / "gk_state_route.py").read_text(
        encoding="utf-8"), "F-3: 单源判定未实现 strict 解绑"
    assert "strict)" in s, "F-3: bash 未消费 STRICT 解绑判定"
    assert '[ "$cmd" != "discover" ] && [ -n "$_pp_plan" ]' not in s, \
        "F-3: 本块仍用裸 $cmd（set -u 崩）"


def test_neg_old_silent_forms_absent():
    """负臂：三处旧式静默形态须全部消失（防「只加新、不删旧」）。"""
    s = _src()
    assert '[ "$_adj_rc" != "0" ] || [ -z "$_adj_out" ]' not in s, "负臂: F-1 旧式仍在"
    assert '> /dev/null || _cmt_rc=$?' not in s, "负臂: F-2 旧式仍在"

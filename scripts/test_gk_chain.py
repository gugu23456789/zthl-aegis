#!/usr/bin/env python3
"""
`scripts/gk_chain.py` 回归臂（2026-10-30）。

背景（用户裁定）：
  · standing 是**可组合、可拆分**调用的一键链；audit / red 同样需要，否则「审计署」与
    「审计序列」两套口径各说各话。
  · 链执行器**只驱动** `gatekeeper-cli.sh advance <node>`（证据注入在 cmd_advance 内），
    禁在本文件复刻证据采集；节点名唯一真源 = `gk_node_guard.route_map()`。

红先：本文件 import `gk_chain` 时若模块不存在即 ImportError（实现前必红）。
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_chain as C  # noqa: E402
from gk_node_guard import route_map  # noqa: E402


# ─── 链注册：三路线 + 节点单源交叉校验 ──────────────────────────────────────
def test_three_chains_registered():
    assert {"standing", "audit", "red"} <= set(C.CHAINS)


@pytest.mark.parametrize("name", ["standing", "audit", "red"])
def test_chain_nodes_are_registered_in_node_guard(name):
    """链不得另立节点事实源：每一步的节点必须出现在 gk_node_guard 对应路线里。"""
    chain = C.CHAINS[name]
    rm = route_map(chain.route)
    assert rm["ok"] is True, rm
    for step in chain.steps:
        assert step.node in rm["nodes"], f"{name}: {step.node} 不在 route {chain.route}"


@pytest.mark.parametrize("name", ["standing", "audit", "red"])
def test_step_nodes_unique(name):
    nodes = [s.node for s in C.CHAINS[name].steps]
    assert len(nodes) == len(set(nodes))


def test_standing_audit_red_cover_all_route_nodes():
    """三条链必须覆盖各自路线的全部节点（审计序列/红队序列不得漏站）。"""
    for name in ("standing", "audit", "red"):
        expected = route_map(C.CHAINS[name].route)["nodes"]
        assert [s.node for s in C.CHAINS[name].steps] == list(expected)


# ─── 选择：--only / --from / --to ────────────────────────────────────────────
def test_select_default_returns_all_in_order():
    steps = C.select_steps("audit")
    assert [s.node for s in steps] == ["AUDIT-STATE", "AUDIT-MEMORY",
                                       "AUDIT-CROSSR", "AUDIT-REPORT"]


def test_select_only_preserves_requested_order_and_subsets():
    """--only 是显式组合：按用户给的顺序执行，不偷偷改序。"""
    steps = C.select_steps("audit", only=["AUDIT-REPORT", "AUDIT-STATE"])
    assert [s.node for s in steps] == ["AUDIT-REPORT", "AUDIT-STATE"]


def test_select_only_accepts_comma_and_lowercase():
    steps = C.select_steps("audit", only=["audit-memory,audit-report"])
    assert [s.node for s in steps] == ["AUDIT-MEMORY", "AUDIT-REPORT"]


def test_select_from_to_inclusive():
    steps = C.select_steps("audit", start="AUDIT-MEMORY", end="AUDIT-REPORT")
    assert [s.node for s in steps] == ["AUDIT-MEMORY", "AUDIT-CROSSR", "AUDIT-REPORT"]


def test_select_from_after_to_is_usage_error():
    with pytest.raises(C.UsageError):
        C.select_steps("audit", start="AUDIT-REPORT", end="AUDIT-STATE")


def test_select_unknown_step_is_usage_error():
    with pytest.raises(C.UsageError):
        C.select_steps("audit", only=["AUDIT-NOPE"])


def test_only_and_range_are_mutually_exclusive():
    with pytest.raises(C.UsageError):
        C.select_steps("audit", only=["AUDIT-STATE"], start="AUDIT-STATE")


def test_unknown_chain_is_usage_error():
    with pytest.raises(C.UsageError):
        C.select_steps("standard")


# ─── argv：单步必须可独立调用 ────────────────────────────────────────────────
def test_build_argv_advances_the_node():
    step = C.CHAINS["audit"].steps[0]
    argv = C.build_argv(step)
    assert argv[-3:] == ["gatekeeper-cli.sh", "advance", "AUDIT-STATE"]
    assert argv[0].endswith("bash")


def test_build_argv_dry_run_does_not_add_check():
    """演练不执行 ⟹ argv 不注入 `--check`（否则线性链会撞 sequential 假失败）。"""
    step = C.CHAINS["audit"].steps[0]
    argv = C.build_argv(step, dry_run=True)
    assert "--check" not in argv
    assert argv[-1] == "AUDIT-STATE"


# ─── 执行：失败即停 / 状态传递 / 非 JSON 判红 ───────────────────────────────
class _Runner:
    """假执行器：按节点返回预设结果，并记录调用序。"""

    def __init__(self, verdicts):
        self.verdicts = verdicts
        self.calls = []

    def __call__(self, argv, env, cwd):
        node = argv[-1] if argv[-1] != "--check" else argv[-2]
        self.calls.append({"node": node, "argv": argv, "env": dict(env), "cwd": cwd})
        ok = self.verdicts[node]
        if ok is None:
            return 0, "not-json", ""
        return 0, '{"ok":%s,"node":"%s"}' % ("true" if ok else "false", node), ""


def test_run_all_ok():
    r = _Runner({n: True for n in ("AUDIT-STATE", "AUDIT-MEMORY")})
    res = C.run_chain("audit", C.select_steps("audit", only=["AUDIT-STATE", "AUDIT-MEMORY"]),
                      runner=r)
    assert res["ok"] is True and res["executed"] == 2 and res["failed_step"] is None


def test_run_stops_on_first_failure():
    r = _Runner({"AUDIT-STATE": True, "AUDIT-MEMORY": False, "AUDIT-CROSSR": True})
    res = C.run_chain("audit", C.select_steps("audit"), runner=r)
    assert res["ok"] is False
    assert res["failed_step"] == "AUDIT-MEMORY"
    assert [c["node"] for c in r.calls] == ["AUDIT-STATE", "AUDIT-MEMORY"]


def test_run_propagates_state_env():
    r = _Runner({"AUDIT-STATE": True})
    C.run_chain("audit", C.select_steps("audit", only=["AUDIT-STATE"]),
                runner=r, state="/tmp/x.state")
    assert r.calls[0]["env"]["STATE_FILE"] == "/tmp/x.state"


def test_run_non_json_output_is_failure():
    r = _Runner({"AUDIT-STATE": None})
    res = C.run_chain("audit", C.select_steps("audit", only=["AUDIT-STATE"]), runner=r)
    assert res["ok"] is False and res["failed_step"] == "AUDIT-STATE"


def test_run_dry_run_does_not_execute():
    r = _Runner({"AUDIT-STATE": True})
    res = C.run_chain("audit", C.select_steps("audit", only=["AUDIT-STATE"]),
                      runner=r, dry_run=True)
    assert r.calls == [], "dry-run 不得执行任何命令"
    assert res["ok"] is True and res["executed"] == 0
    assert res["plan"][0]["argv"][-1] == "AUDIT-STATE"

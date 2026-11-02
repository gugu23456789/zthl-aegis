"""红先臂：plan-refinement 链的 id/字段捕获 CRLF 污染（Windows python print = \\r\\n）。

实证（2026-11-01，本机 WorkBuddy python 3.13）：`python3 -c 'print("a\\nb")'` 输出
`a\\r\\nb\\r\\n`。CLI 里 `_adj_ids=$(resolve-ids | python3 -c 'print("\\n".join(ids))')` ——
`$()` 只剥尾部 `\\n` 不剥 `\\r`，且 bash IFS 不含 `\\r` ⟹ `for _aid in $_adj_ids` 拆出的
每个 id 尾粘 `\\r` ⟹ `gk_task_gate adjudicate --id "pr-…\\r"` 查无记录 ⟹
`arm_prepare_failed`（逐臂下发半瘫；同 id 手工单跑 RC=0 实证非记录态问题）。

修法 = 各 `$(python3 …)` 捕获链尾加 `| tr -d '\\r'`（id 列表 / tier / batch-plan 目标 /
arm-group 标签 / batch-narrow 并集）+ `_budget_snap` 的 heredoc python 显式
`sys.stdout.reconfigure(newline="\\n")`（账单快照串同根因）。

判据面 = 「gatekeeper-cli.sh 源文本中该捕获链含 `tr -d '\\r'`」（仓内 bash 静态臂同款
口径：HEAD 必红 —— 修复前这些链一个 `tr` 都没有）。
"""
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
SK = os.path.dirname(HERE)
CLI = os.path.join(SK, "gatekeeper-cli.sh")


def _txt():
    with open(CLI, encoding="utf-8") as f:
        return f.read()


def _near(anchor: str, window: int) -> bool:
    """锚点后 window 字符内出现 `tr -d '\\r'`（捕获链尾净化）。"""
    m = re.search(anchor, _txt())
    assert m, "锚点丢失（上游重构？）: %r" % anchor
    return "tr -d '\\r'" in _txt()[m.end(): m.end() + window]


def test_adj_ids_resolve_pipe_strips_crlf():
    """`_adj_ids`（resolve-ids → print join 管道）：id 列表尾粘 \\r ⟹ 逐臂 prepare 必挂。"""
    assert _near(r"resolve-ids", 600), "resolve-ids 捕获链缺 | tr -d '\\r'（id 尾 \\r 污染）"


def test_tier_field_strips_crlf():
    """`_tier`（gk_json_utils field tier）：export SUBAGENT_TIER 带 \\r 污染下游档位路由。"""
    assert _near(r"field tier --env ADJ_OUT", 300), "tier 捕获链缺 | tr -d '\\r'"


def test_bplan_target_strips_crlf():
    """`_bplan`（adjudicate 输出 record.target）：`--batch-plan` 带 \\r ⟹ plan 归属错配。"""
    assert _near(r'get\("target"\) or ""', 300), "batch-plan 捕获链缺 | tr -d '\\r'"


def test_arm_group_label_strips_crlf():
    """`_ag`（group_label_of_full_task）：`--arm-group G1\\r` / 临时文件名带 \\r 污染批语义。"""
    assert _near(r"group_label_of_full_task", 300), "arm-group 捕获链缺 | tr -d '\\r'"


def test_batch_narrow_union_strips_crlf():
    """`_bnarrow`（3 组窄任务并集串）：\\r 混入共享 --batch-narrow ⟹ 批指纹分叉/臂题面污染。"""
    assert _near(r'print\(","\.join\(str\(e\.get\("task"\)', 600), \
        "batch-narrow 捕获链缺 | tr -d '\\r'"


def test_budget_snap_lf_newline():
    """`_budget_snap` heredoc python：Windows print 出 \\r\\n ⟹ 三字段串尾粘 \\r，
    账单差额对账（session/global 域比对）被污染。"""
    m = re.search(r"_budget_snap\(\)\s*\{", _txt())
    assert m, "_budget_snap 函数锚点丢失"
    body = _txt()[m.end(): m.end() + 1600]
    assert "reconfigure(newline=" in body, \
        "_budget_snap heredoc 缺 sys.stdout.reconfigure(newline=…)（CRLF 净化）"

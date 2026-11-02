#!/usr/bin/env python3
"""n4 T1/T9 红先：入队 3×K pending + 批级消解出口（resolve_ids）+ T2 逐臂显式 id。

机理（2026-10-05，n4 `2026-10-04-plan-refine-group-dispatch-plan.md`）：
  · **T1** = `cmd_plan_refinement` 入队段须一次入队 `3×K` 条 pending（record **不含 arm_group**，
    批级见 `batch` 键 + id 唯一加盐），以承载 MoA 的 3 组×K 臂（§2-T1）。
  · **T9** = `gk_task_gate.resolve_ids('last-batch')` 批级消解出口（取整批**显式 id**），
    而 `resolve_id('last')` 旧**单条**语义须零回归（§4-R9；本文件 `r9_*` 臂为非红回归，不入选红先集）。
  · **R7/R10** = 一次批下发后全 3×K pending 被消解，每 id 恰消费一次（无僵尸）。

红先契约（HEAD 必红）：`submit` 无 `count` 参数 / `resolve_ids` 不存在 /
  CLI 无 `--arms-per-group`、无 `last-batch`+`resolve-ids` 接线。

锚形态：符号锚（函数名 / CLI flag 串），非行号。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"


def _state(tmp_path, name=".gatekeeper.state.test"):
    p = Path(tmp_path) / name
    p.write_text(json.dumps({"gate_data": {}}), encoding="utf-8")
    return str(p)


def _rec(rid="pr-1696000000-abcdef12"):
    return {"id": rid, "status": "pending", "task": "t",
            "full_task": "plan-refinement: x — t", "tier": "3"}


def test_t1_submit_count_adds_n_records(tmp_path):
    """T1：`submit(count=N)` 一次入队 N 条 pending（HEAD 无 count ⟹ TypeError ⟹ 红）。"""
    from gk_task_gate import submit, pipeline
    st = _state(tmp_path)
    out = submit(st, _rec(), count=6)
    assert out["ok"] is True
    pend = [r for r in pipeline(st) if r.get("status") == "pending"]
    assert len(pend) == 6, "入队条数 %d != 6（T1 未落）" % len(pend)


def test_t1_records_share_batch_key_and_unique_ids(tmp_path):
    """T1：批内 id 唯一（加盐）+ 共享 `batch` 键（T9 消解键）；单条 count=1 不加 batch（零回归）。"""
    from gk_task_gate import submit, pipeline
    st = _state(tmp_path)
    submit(st, _rec(), count=3)
    pend = [r for r in pipeline(st) if r.get("status") == "pending"]
    ids = [r.get("id") for r in pend]
    assert len(set(ids)) == 3, "批内 id 不唯一 %s" % ids
    bks = {r.get("batch") for r in pend}
    assert len(bks) == 1, "批内 batch 键不一致 %s" % [r.get("batch") for r in pend]
    st2 = _state(tmp_path, ".gatekeeper.state.single")
    submit(st2, _rec(), count=1)
    one = [r for r in pipeline(st2) if r.get("status") == "pending"][0]
    assert not one.get("batch"), "单条不应带 batch 键（零回归）"


def test_t9_resolve_ids_last_batch(tmp_path):
    """T9：`resolve_ids('last-batch')` 返回整批 id（入队序）；HEAD 无该函数 ⟹ 红。"""
    from gk_task_gate import submit, resolve_ids
    st = _state(tmp_path)
    submit(st, _rec(), count=6)
    ids = resolve_ids(st, "last-batch")
    assert len(ids) == 6, "批级消解取到 %d != 6" % len(ids)


def test_r7_batch_fully_consumed(tmp_path):
    """R7/R10：resolve_ids 取整批 → 逐 id（prepare+commit）⟹ 批全消解、无僵尸。"""
    from gk_task_gate import submit, resolve_ids, adjudicate, commit, pipeline
    st = _state(tmp_path)
    submit(st, _rec(), count=6)
    ids = resolve_ids(st, "last-batch")
    for i in ids:
        assert adjudicate(st, i, "approve", persist=False)["ok"] is True
        assert commit(st, i, "approve")["ok"] is True
    pend = [r for r in pipeline(st) if r.get("status") == "pending"]
    assert pend == [], "批未全消解，僵尸 pending=%d" % len(pend)


def test_r9_old_last_still_single(tmp_path):
    """R9 零回归（HEAD 即绿，**不入选红先集**）：队内多条 pending 时 `resolve_id('last')` 仍取**单条**。

    ⚠ 用旧 `submit(rec)`（count=1 缺省）入队多条 ⟹ HEAD 即绿（不引入 T1 新面）；
    加 T9 后 `resolve_id` 本体**不得**被改造成多值（批级走独立的 `resolve_ids`）。
    """
    from gk_task_gate import submit, resolve_id
    st = _state(tmp_path)
    for i in range(6):
        submit(st, _rec("pr-1696000000-%08d" % i))
    one = resolve_id(st, "last")
    assert isinstance(one, str) and one != ""
    assert "\n" not in one and "," not in one, "旧 last 语义被污染成多值"


def test_t1_cli_enqueue_wires_arms_per_group():
    """T1 接线（静态）：`cmd_plan_refinement` 入队段须解析 `--arms-per-group` 且按批入队。"""
    s = CLI.read_text(encoding="utf-8")
    assert "--arms-per-group)" in s, "CLI 未解析 --arms-per-group（T1 入队面未接线）"
    assert "--count" in s, "CLI 未把 3×K 传给 submit --count（T1 入队面未接线）"


def test_t2_cli_dispatch_resolves_last_batch():
    """T9/T2 接线（静态）：裁决下发段须支持 `last-batch` 批级消解（逐臂显式 id）。"""
    s = CLI.read_text(encoding="utf-8")
    assert "last-batch" in s, "CLI 未接线 last-batch 批级消解（T9 出口缺）"
    assert "resolve-ids" in s, "CLI 未调 resolve-ids（T9 单源消解缺）"

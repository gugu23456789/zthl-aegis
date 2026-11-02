"""
test_gk_history_spill.py — 红先臂：臂输出**全量直接落卫星片**，state 只留元数据
================================================================================
finding：`ECC-2E9DA8D90CB2`（`history-inline-full-payload-not-spilled`）

病象（2026-10-17 实测）：`subagent_history` 每条 entry 都内联完整 `conclusion`
（`_ENTRY_KEYS` 含 conclusion），卫星 `history` 片**只在 >96KB 溢出时**才产生 ⟹ state
不满足卫星计划 §0「主 state 只留元数据 + `satellite_index`」。且读侧 union
（`gk_moa_aggregate._satellite_history_union`）的 `seen = {live subagent_id}` **偏好 live**
⟹ 一旦写侧改为元数据占位，`--recent` 会拿到**无 conclusion 的占位**（读分裂的镜像形态）。

修法（方案 a）：
  ① 写侧：每条 entry **先全量落片**（`gk_satellite.append(kind=history)`），成功后才把
     state 内的 `conclusion` 抹成元数据投影（`spilled` / `conclusion_len`）；落片失败
     **保留全量**（fail-safe，禁静默丢结论）；溢出循环跳过已落片条目（防重复行）。
  ② 读侧：union 遇「live 无 conclusion ∧ 片内有」⟹ 用片内**全量原位替换**占位。

红先：HEAD 上 ① 写侧无片（无溢出即不落片）⟹ 行为臂红；② union 偏好占位 ⟹ 读臂红。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from test_gk_history_archive import CLI, _ecc, _hist_pipeline, _run_payload


# ── ① 形态臂：落片先于抹除 + 溢出循环跳过已落片 ──────────────────────────────
def test_history_payload_spills_before_strip():
    src = _hist_pipeline()
    assert "HISTORY_SPILL_FAILED" in src, "落库段未见「每条 entry 全量落片」的失败留痕"
    assert "_sat" in src and "'history'" in src, "未见 history 片落点"
    assert ".get('spilled')" in src or '.get(\"spilled\")' in src, (
        "溢出循环未跳过已落片条目 ⟹ 同一条会写两行")


# ── ② 行为臂（写）：新 entry 落片全量，state 只留元数据 ──────────────────────
def test_new_entry_spills_full_and_state_keeps_metadata(tmp_path):
    state = _run_payload(tmp_path, _ecc("sub-new"), [])
    shard = Path(str(state) + ".history-archive.jsonl")
    assert shard.is_file(), "新 entry 未落 history 片（仍内联全量 ⟹ state 非元数据）"
    rows = [json.loads(ln) for ln in shard.read_text(encoding="utf-8").splitlines() if ln.strip()]
    hit = [r for r in rows if r.get("subagent_id") == "sub-new"]
    assert hit, ("片内无本条", rows)
    assert hit[-1].get("conclusion") == "c", ("片内应保留全量 conclusion", hit[-1])

    d = json.loads(state.read_text(encoding="utf-8"))
    gd = d.get("gate_data") or {}
    last = (gd.get("subagent_history") or [])[-1]
    assert not last.get("conclusion"), ("state 仍内联 conclusion ⟹ 未抹成元数据", last)
    assert last.get("spilled") is True, ("缺 spilled 标记（读侧无法判定占位）", last)
    assert last.get("conclusion_len") == 1, ("缺 conclusion_len（可审计的全量线索）", last)
    assert not (gd.get("subagent_last") or {}).get("conclusion"), (
        "subagent_last 仍内联 conclusion（它是 history[-1] 的副本）")


# ── ③ 行为臂（读）：union 用片内全量替换元数据占位 ──────────────────────────
def test_union_prefers_shard_full_record_over_placeholder(tmp_path):
    M = pytest.importorskip("gk_moa_aggregate")
    state = tmp_path / ".gatekeeper.state"
    placeholder = {"subagent_id": "s1", "task": "t", "spilled": True, "conclusion_len": 9}
    state.write_text(json.dumps({"gate_data": {"subagent_history": [placeholder]}}),
                     encoding="utf-8")
    shard = Path(str(state) + ".history-archive.jsonl")
    full = {"subagent_id": "s1", "task": "t", "conclusion": "FULL-TEXT"}
    shard.write_text(json.dumps(full, ensure_ascii=False) + "\n", encoding="utf-8")

    merged, _info = M._satellite_history_union(str(state), {}, [placeholder])
    assert merged, "union 返回空"
    assert merged[0].get("conclusion") == "FULL-TEXT", (
        "union 偏好元数据占位 ⟹ 聚合拿不到 conclusion（读分裂镜像）", merged)


# ── ④ standard 序列读面对齐（`ECC-2EC7FD463D29` 读侧半场）─────────────────────
#   病象：写侧 history 溢出已落卫星片，但 standard 门禁 / preflight 自检仍只读
#   `gate_data.subagent_history` ⟹ 溢出后 live 变空 = 真前置被误判缺失（写卫星、读 base）。
#   修法：统一走 `gk_moa_aggregate.history_union`（单源），CLI 内联读改为
#   `gk_state_query --history-len/--history-last-task`（去 `2>/dev/null` 静默兜底）。

SCRIPTS_DIR = Path(__file__).resolve().parent
QUERY = SCRIPTS_DIR / "gk_state_query.py"


def _mk_union_state(tmp_path, live=None, shard_rows=None, index_records=None):
    """live history + 卫星 history 片 + per-arm 索引叶子的最小现场。"""
    state = tmp_path / ".gatekeeper.state"
    gd = {"subagent_history": live or []}
    if index_records is not None:
        gd["satellite_index"] = {"b1": {"s1": {
            "kind": "history", "file": ".gatekeeper.state.history-archive.jsonl",
            "arm": "s1", "records": int(index_records)}}}
    state.write_text(json.dumps({"gate_data": gd}, ensure_ascii=False), encoding="utf-8")
    if shard_rows is not None:
        Path(str(state) + ".history-archive.jsonl").write_text(
            "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in shard_rows),
            encoding="utf-8")
    return state


def _query(state, *args):
    env = dict(os.environ, STATE_FILE=str(state))
    return subprocess.run([sys.executable, str(QUERY), *args],
                          capture_output=True, text=True, env=env)


def test_plan_ref_checkpoint_reads_satellite_history(tmp_path):
    """live 空 + 卫星片有 plan-refinement ⟹ 不得判 NONE（写卫星、读 base = 读分裂）。"""
    import gk_advance as A
    state = _mk_union_state(tmp_path, live=[], index_records=1,
                            shard_rows=[{"subagent_id": "s1",
                                         "task": "plan-refinement: x"}])
    d = json.loads(state.read_text(encoding="utf-8"))
    assert A._plan_ref_checkpoint(d, str(state)) == "plan-refinement"


def test_adjudicate_gate_reads_satellite_history(tmp_path):
    """ECO-EDIT→AUDIT 裁决门禁的 plan-refinement 前置同样须见卫星片。"""
    import gk_advance as A
    state = _mk_union_state(tmp_path, live=[], index_records=1,
                            shard_rows=[{"subagent_id": "s1",
                                         "task": "plan-refinement: x"}])
    d = json.loads(state.read_text(encoding="utf-8"))
    assert A._check_adjudicate(d, "standard", str(state)) != "no_plan_refinement_checkpoint"


def test_eco_prereq_heuristic_reads_satellite_history(tmp_path):
    """advance 被拦时的前置提示须见卫星片（否则把已做的审查报成缺失）。"""
    import gk_advance as A
    state = _mk_union_state(tmp_path, live=[], index_records=1,
                            shard_rows=[{"subagent_id": "s1", "task": "read only"}])
    d = json.loads(state.read_text(encoding="utf-8"))
    h = A._eco_prereq_heuristic(d, "ECO-READ", str(state))
    assert "subagent_review" not in {m["item"] for m in h["missing"]}, h


def test_state_query_history_len_uses_union(tmp_path):
    state = _mk_union_state(tmp_path, live=[{"subagent_id": "l1", "task": "x"}],
                            index_records=1,
                            shard_rows=[{"subagent_id": "s1", "task": "y"}])
    p = _query(state, "--history-len")
    assert p.returncode == 0, p.stderr
    assert p.stdout.strip() == "2", (p.stdout, p.stderr)


def test_state_query_history_last_task_uses_union(tmp_path):
    state = _mk_union_state(tmp_path, live=[], index_records=1,
                            shard_rows=[{"subagent_id": "s1",
                                         "task": "plan-refinement: abc"}])
    p = _query(state, "--history-last-task")
    assert p.returncode == 0, p.stderr
    assert p.stdout.strip() == "plan-refinement: abc", (p.stdout, p.stderr)


def test_state_query_history_len_fails_loud_on_missing_shard(tmp_path):
    """索引声明有片而片不在 ⟹ 非零退出 + stderr，**不得**回落 live 计数。"""
    state = _mk_union_state(tmp_path, live=[], index_records=3, shard_rows=None)
    p = _query(state, "--history-len")
    assert p.returncode != 0, p.stdout
    assert "缺失" in p.stderr, p.stderr


def test_standard_sequence_reads_use_query_union():
    """CLI 两个 standard 读点须走查询器 union，且旧内联/静默兜底已移除。"""
    src = CLI.read_text(encoding="utf-8")
    assert "--history-len" in src and "--history-last-task" in src
    assert "print(len(d.get('gate_data',{}).get('subagent_history',[])))" not in src

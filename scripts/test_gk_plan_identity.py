"""计划身份单一真源（plan_identity / plan_match）的不变量与边界测试。

红先背景（2026-10-30，user 裁定「多源多实现漂移」）：
  `chain_head` 把相对入参归一成绝对，聚合端拿绝对去裸子串匹配 history 里的相对 /
  worktree 形态 ⟹ 双处 0 命中 ⟹ `batch_resolved=""` + `refs=0` ⟹ 误判「基础设施缺陷」。
  同文件内 `_pending_for_plan` 有 basename 兜底（故链头 resume 成功），另两处没有 ⟹ 分裂。

本测试钉死两条不变量：
  A. 四种路径形态（主仓绝对 / worktree 绝对 / 仓相对 / task 全文 / Windows 反斜杠）⟹ 同一 key；
  B. identity 双侧可得但**不等** ⟹ 绝不回退子串（防跨计划混批）。
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gk_moa_aggregate as G

PLAN = "2026-10-28-standard-sequence-compression-plan.md"
KEY = "2026-10-28-standard-sequence-compression-plan"
MAIN_ABS = "<home>/.trae/skills/spz-gatekeeper-r-sequence/docs/plans/" + PLAN
WT_ABS = ("<home>/.trae/worktrees/spz-gatekeeper-r-sequence/feature/"
          "bomb-inline-b2/docs/plans/" + PLAN)
REL = "docs/plans/" + PLAN
TASK_REL = "plan-refinement: " + REL + " — 对本文做 SCR 质询，逐条裁决 Q1"
WIN_ABS = "<home>\\.trae\\skills\\spz-gatekeeper-r-sequence\\docs\\plans\\" + PLAN


# ── A. 形态归一不变量 ────────────────────────────────────────────────────────
def test_plan_identity_all_forms_collapse_to_one_key():
    forms = [MAIN_ABS, WT_ABS, REL, TASK_REL, WIN_ABS]
    keys = {G.plan_identity(f) for f in forms}
    assert keys == {KEY}, "计划身份漂移：%r" % (keys,)


def test_plan_identity_empty_inputs():
    assert G.plan_identity("") == ""
    assert G.plan_identity(None) == ""
    assert G.plan_identity("   ") == ""


def test_plan_identity_is_idempotent():
    k = G.plan_identity(MAIN_ABS)
    assert G.plan_identity(k) == k


# ── B. 三层边界 ──────────────────────────────────────────────────────────────
def test_plan_match_identity_hit_across_forms():
    hit, how = G.plan_match("plan-refinement: " + REL + " — x", MAIN_ABS)
    assert hit and how == "identity", (hit, how)


def test_plan_match_worktree_vs_main_repo_is_same_plan():
    """worktree 绝对 vs 主仓绝对 —— 同一计划，必须命中（这是当日 79/47 形态并存的实况）。"""
    hit, how = G.plan_match("plan-refinement: " + WT_ABS + " — x", MAIN_ABS)
    assert hit and how == "identity", (hit, how)


def test_plan_match_never_falls_back_on_identity_mismatch():
    """两个不同计划：identity 均可得但不等 ⟹ 必须拒，方式=identity_mismatch。"""
    hit, how = G.plan_match(
        "plan-refinement: docs/plans/2026-10-29-accept-throughput-forensics-plan.md — x",
        REL,
    )
    assert (not hit) and how == "identity_mismatch", (hit, how)


def test_plan_match_legacy_substring_only_when_identity_missing():
    """无计划语义的通道（preflight 摘要）⟹ identity 不可得 ⟹ 回退子串但留痕、不命中。"""
    task = "【preflight 证据摘要】通道=standing（通用质询） — plan-refinement 质询 preflight 确定性 0-API 预取"
    hit, how = G.plan_match(task, REL)
    assert (not hit) and how == "legacy_substring", (hit, how)


def test_plan_match_legacy_substring_hits_when_both_identity_missing():
    """双侧 identity 均不可得（裸 key、无分隔符无扩展名）⟹ 回退子串，命中且留痕。

    注：若任一侧形似路径（含 `/` 或 `.md`），`plan_identity` 会提出身份走 identity 层，
    不再进 legacy —— 故真正的 legacy 命中只发生在双侧都不可得时。
    """
    entry = "旧格式任务 " + KEY + " 无扩展名"
    hit, how = G.plan_match(entry, KEY)
    assert hit and how == "legacy_substring", (hit, how)


# ── C. 三个消费点回归（当日 0 命中的实况复现） ────────────────────────────────
def _state(tmp_path, hist):
    p = tmp_path / ".gatekeeper.state.test"
    p.write_text(json.dumps({"gate_data": {"subagent_history": hist}}, ensure_ascii=False),
                 encoding="utf-8")
    return str(p)


def _entry(sid, task, bid="6b8569574639"):
    return {"subagent_id": sid, "task": task, "batch_id": bid}


def test_collect_entries_matches_abs_anchor_against_rel_history(tmp_path):
    """当日事故复现：传主仓绝对锚，history 里是相对形态 ⟹ 必须命中（原实现 0 命中）。"""
    rel_task = "plan-refinement: " + REL + " — x"
    other_task = "plan-refinement: docs/plans/2026-10-29-accept-throughput-forensics-plan.md — y"
    sp = _state(tmp_path, [_entry("s1", rel_task), _entry("s2", other_task, "aaaaaaaaaaaa")])

    entries, attr = G.collect_entries(sp, None, None, plan=MAIN_ABS)
    assert len(entries) == 1, "绝对锚未命中相对 history：%r" % (attr,)
    assert entries[0]["subagent_id"] == "s1"
    assert attr["match_ways"].get("identity") == 1
    assert attr["anchor_identity"] == KEY


def test_collect_entries_identity_mismatch_not_fallback(tmp_path):
    """锚与 history 是不同计划 ⟹ 0 命中，且方式记为 identity_mismatch（不静默）。"""
    other_task = "plan-refinement: docs/plans/2026-10-29-accept-throughput-forensics-plan.md — y"
    sp = _state(tmp_path, [_entry("s1", other_task)])
    entries, attr = G.collect_entries(sp, None, None, plan=MAIN_ABS)
    assert entries == []
    assert attr["match_ways"].get("identity_mismatch") == 1


def test_latest_batch_fingerprint_resolves_with_abs_anchor(tmp_path):
    """当日 `batch_resolved=""` 复现：绝对锚 + 相对 history ⟹ 必须解析出 batch_id。"""
    rel_task = "plan-refinement: " + REL + " — x"
    sp = _state(tmp_path, [
        _entry("s0", rel_task, "9e1dab65f53e"),
        _entry("s1", rel_task, "6b8569574639"),
    ])
    assert G.latest_batch_fingerprint(sp, MAIN_ABS) == "6b8569574639"


def test_pending_for_plan_uses_single_source(tmp_path):
    """`_pending_for_plan` 原手写 basename 兜底，现统一到 plan_match；行为不得退化。"""
    p = tmp_path / ".gatekeeper.state.pending"
    p.write_text(json.dumps({"gate_data": {"task_pipeline": [
        {"status": "pending", "target": REL, "id": "t1"},
        {"status": "pending", "target": MAIN_ABS, "id": "t2"},
        {"status": "pending",
         "target": "docs/plans/2026-10-29-accept-throughput-forensics-plan.md", "id": "t3"},
        {"status": "done", "target": REL, "id": "t4"},
    ]}}, ensure_ascii=False), encoding="utf-8")

    out = G._pending_for_plan(str(p), MAIN_ABS)
    ids = sorted(r["id"] for r in out)
    assert ids == ["t1", "t2"], ids

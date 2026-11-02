#!/usr/bin/env python3
"""T1 消费端红先：窄任务分组**承载面**（2026-10-05）。

缺陷（读码 + 实测）：`gk_task_gate.submit(count=N)` 把**同一条 record 复制 N 份**
（只换 id/加 batch）⟹ `plan-refinement --arms-per-group K` 入队的 `3×K` 条 pending
`full_task` **逐字相同**；而 fan-out 段又共用单条 `_ft` ⟹ **3 组只是标签**，
`gate_data.narrow_tasks[]` 成为**悬空产物**（无消费方）。这正是 disp-plan §3
「3 组窄任务文本源 + index→组 显式映射」缺失的现场。

修法：`submit --expand-groups --k K` —— 从 `gate_data.narrow_tasks[]` 取前 `3×K` 条，
按**入队序** index//K 映射 G1/G2/G3，把**各组任务逐臂嵌入 `full_task`**（逐臂逐字不同
⟹ `BARE_PLAN_REFINEMENT` 守卫 `task_in_pipeline` 按逐臂 full_task 命中）。

四臂（HEAD 必红 → 绿）：
  1 展开      expand + narrow_tasks≥3K ⟹ group_tasks=true，6 条 full_task 两两不同，组序 G1/G2/G3
  2 未展开    无 expand ⟹ 6 条 full_task **逐字相同**（旧语义零回归）
  3 不足拒发  expand 但 narrow_tasks<3K ⟹ **fail-closed**（rc≠0 + error=narrow_tasks_insufficient，零写盘）；
              显式逃生 `GK_ALLOW_GROUP_FALLBACK=1` ⟹ 回落旧语义（同名复制）
  4 守卫相容  逐臂 full_task 均命中 task_pipeline（BARE 守卫放行）
"""
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
GATE = HERE / "gk_task_gate.py"
CLI = HERE.parent / "gatekeeper-cli.sh"

BASE = {
    "id": "pr-1700000000-abcdef01",
    "target": "docs/plans/demo.md",
    "plan_path": "docs/plans/demo.md",
    "task": "审查 DRAFT-4 基线",
    "full_task": "plan-refinement: docs/plans/demo.md — 审查 DRAFT-4 基线",
    "source_docs": "",
    "tier": "3",
    "r_phase": "",
    "project_type": "",
    "status": "pending",
}

# 6 条窄任务：入队序 = G1×2 / G2×2 / G3×2（与 narrow_tasks[] 的顺序映射同源）
# 2026-10-28：读侧开始**复算**三组语义（堵「手写 sidecar / 整表替换」绕过）⟹ 夹具必须是
# **合格**清单：G1 两条逐字同题 + pair_id、covers 是 coverage_target 的划分、G3 带污染标记、
# 每条含 verdict/SOURCES 输出契约。用不合格夹具去测「数量门」会被语义门先拦（另设专臂）。
_G1_TASK = "基线 题：给 VERDICT 与 SOURCES: <path:line>"
NT6 = [
    {"id": "nt-g1-1", "name": "g1a", "group": "G1", "pair_id": "p12", "covers": [1, 2],
     "task": _G1_TASK, "tier": 3},
    {"id": "nt-g1-2", "name": "g1b", "group": "G1", "pair_id": "p12", "covers": [1, 2],
     "task": _G1_TASK, "tier": 3},
    {"id": "nt-g2-1", "name": "g2a", "group": "G2", "covers": [3],
     "task": "正交 甲：给 VERDICT 与 SOURCES: <path:line>", "tier": 3},
    {"id": "nt-g2-2", "name": "g2b", "group": "G2", "covers": [4],
     "task": "正交 乙：给 VERDICT 与 SOURCES: <path:line>", "tier": 3},
    {"id": "nt-g3-1", "name": "g3a", "group": "G3", "covers": [1], "polluted": True,
     "poison_claim": "污染 甲", "task": "已知污染 甲：给 VERDICT 与 SOURCES: <path:line>", "tier": 3},
    {"id": "nt-g3-2", "name": "g3b", "group": "G3", "covers": [2], "polluted": True,
     "poison_claim": "污染 乙", "task": "已知污染 乙：给 VERDICT 与 SOURCES: <path:line>", "tier": 3},
]


def _state(tmp_path: Path, nt) -> Path:
    p = tmp_path / "s.json"
    p.write_text(json.dumps(
        {"gate_data": {"narrow_tasks": nt, "task_pipeline": [],
                       "narrow_coverage_target": [1, 2, 3, 4]}}, ensure_ascii=False),
        encoding="utf-8")
    return p


def _submit(state: Path, count: int, extra=None, env=None):
    args = [sys.executable, str(GATE), "submit", "--state", str(state), "--count", str(count)]
    if extra:
        args += extra
    run_env = {**os.environ, **env} if env else None
    r = subprocess.run(args, input=json.dumps(BASE), capture_output=True, text=True, env=run_env)
    out = json.loads(r.stdout) if r.stdout.strip() else {}
    return r.returncode, out, (state and _pipeline(state))


def _pipeline(state: Path) -> list:
    return json.loads(state.read_text(encoding="utf-8"))["gate_data"]["task_pipeline"]


class TestGroupTaskCarrier:
    def test_arm1_expand_embeds_group_tasks(self, tmp_path):
        st = _state(tmp_path, NT6)
        rc, out, pipe = _submit(st, 6, ["--expand-groups", "--k", "2"])
        assert rc == 0, out
        assert out.get("group_tasks") is True, out
        fts = [r["full_task"] for r in pipe]
        assert len(fts) == 6, fts
        assert len(set(fts)) == 6, "6 臂 full_task 必须两两不同（组任务已嵌入）"
        # G1 组（前 2 条）两条互不相同、且都含 G1 组标注
        assert "G1" in fts[0] and "G1" in fts[1]
        assert fts[0] != fts[1]
        assert "G2" in fts[2] and "G2" in fts[3]
        assert "G3" in fts[4] and "G3" in fts[5]
        # 组任务正文确实进了各自臂（G1 为相同对 ⟹ 两条同题、仅 arm 标记不同）
        assert "基线 题" in fts[0] and "基线 题" in fts[1]
        assert "正交 甲" in fts[2] and "污染 乙" in fts[5]

    def test_arm2_legacy_without_expand_identical(self, tmp_path):
        st = _state(tmp_path, NT6)
        rc, out, pipe = _submit(st, 6)
        assert rc == 0, out
        assert out.get("group_tasks") is False, out
        fts = [r["full_task"] for r in pipe]
        assert len(set(fts)) == 1, "未展开 ⟹ 旧语义零回归（同名复制）"
        assert len(pipe) == 6

    def test_arm3_insufficient_failclosed(self, tmp_path):
        """新契约（2026-10-14，用户裁定）：expand 但 narrow_tasks<3K ⟹ **fail-closed**（拒入队，零写盘），
        不再静默回退同名复制（那会把「3 组 MoA」静默降级成 N 个**同题**样本 = 假 MoA）。

        落刀前**必红**：HEAD 版返回 rc=0 + group_tasks=false（静默回退）。
        """
        st = _state(tmp_path, NT6[:5])  # < 3*K=6
        rc, out, pipe = _submit(st, 6, ["--expand-groups", "--k", "2"])
        assert rc != 0, out
        assert out.get("error") == "narrow_tasks_insufficient", out
        assert len(pipe) == 0, "fail-closed ⟹ 零写盘（不得入队）"

    def test_arm3b_explicit_fallback_escape(self, tmp_path):
        """显式逃生 `GK_ALLOW_GROUP_FALLBACK=1` ⟹ 回落旧语义（同名复制），供无清单的合法流程显式自证。"""
        st = _state(tmp_path, NT6[:5])
        rc, out, pipe = _submit(st, 6, ["--expand-groups", "--k", "2"],
                                env={"GK_ALLOW_GROUP_FALLBACK": "1"})
        assert rc == 0, out
        assert out.get("group_tasks") is False, out
        assert len(set(r["full_task"] for r in pipe)) == 1

    def test_arm4_guard_compatible(self, tmp_path):
        st = _state(tmp_path, NT6)
        sys.path.insert(0, str(HERE))
        from gk_task_gate import task_in_pipeline
        rc, out, pipe = _submit(st, 6, ["--expand-groups", "--k", "2"])
        assert rc == 0, out
        for r in pipe:
            assert task_in_pipeline(str(st), r["full_task"]) is True, r["id"]


def test_arm5_cli_fanout_uses_per_arm_full_task():
    """CLI 接线（静态）：fan-out 段须**逐臂取各自 full_task**（`_arm_fts`），不再全批共用单条 `_ft`。

    HEAD 必红：原块仅 `cmd_monitor --subagent "$_ft"`（3×K 次同一条）⟹ `_arm_fts` 零命中。
    """
    src = CLI.read_text(encoding="utf-8")
    i = src.find("cmd_plan_refinement() {")
    assert i != -1, "锚失效：cmd_plan_refinement 未找到"
    j = src.find("\ncmd_", i + 20)
    blk = src[i: j if j != -1 else len(src)]
    assert "_arm_fts" in blk, "fan-out 未按臂取各自 full_task（T1 消费端未接线）"
    assert '--subagent "${_arm_fts[$_i]}"' in blk, "fan-out 仍共用单条 full_task ⟹ 3 组为标签"


def test_arm6_group_label_derived_from_full_task_marker():
    """L0 实跑回归：`_adj_ids` 顺序与入队序不一致 ⟹ index//K 把 n3 标成 G2。

    `full_task` 里的 `【本臂窄任务（G#｜id=…）】` 是入队时写入的**单源**；
    派发端必须从该标记还原组别，禁止再按 id 列表下标推算。
    """
    sys.path.insert(0, str(HERE))
    from gk_task_gate import group_label_of_full_task

    ft = ("plan-refinement: docs/plans/demo.md — 审查\n\n"
          "【本臂窄任务（G2｜id=w2a-web-n2）】\n核查断言 3-4")
    assert group_label_of_full_task(ft) == "G2"
    assert group_label_of_full_task("无标记") == ""
    assert group_label_of_full_task("") == ""


def test_arm7_cli_fanout_uses_marker_not_index():
    """静态接线：fan-out 组别须来自 `group_label_of_full_task`（标记单源），
    回退才用 index//K。"""
    src = CLI.read_text(encoding="utf-8")
    i = src.find("cmd_plan_refinement() {")
    j = src.find("\ncmd_", i + 20)
    blk = src[i: j if j != -1 else len(src)]
    assert "group_label_of_full_task" in blk, \
        "派发端仍按 id 下标推组别 ⟹ arm_group 可与 full_task 内 G# 错位"
    assert "_arm_grps+=(" in blk


# ── 2026-10-21（`ECC-81883BA000AB`）：窄任务来源须绑定本计划 ─────────────────────
# 病象（实跑）：新计划的 `plan-refinement --run` 第一臂执行了**上一份计划**的
# `w2a-web-n3` —— 因为 `submit` 只读 `gate_data.narrow_tasks[]`（跨计划共享面）。
# 契约：sidecar（`<plan>.narrow.json`）优先且必须自足；无 sidecar ⟹ 按 plan 归属过滤；
# 未声明归属的条目一律排除 ⟹ 无 sidecar 的计划 fail-closed（禁静默复用旧清单）。


def _sidecar(tmp_path: Path, nt, coverage_target=None) -> Path:
    """sidecar 两种形态：裸数组（旧）或包裹对象（带 coverage_target —— 读侧复算需要）。"""
    p = tmp_path / "demo.narrow.json"
    if coverage_target is None:
        p.write_text(json.dumps(nt, ensure_ascii=False), encoding="utf-8")
    else:
        p.write_text(json.dumps({"narrow_tasks": nt,
                                 "coverage_target": coverage_target},
                                ensure_ascii=False), encoding="utf-8")
    return p


def _scoped(nt, plan="docs/plans/demo.md"):
    return [dict(e, plan=plan) for e in nt]


class TestNarrowTaskSourceBinding:
    def test_sidecar_overrides_state_global(self, tmp_path):
        old = [{"id": "w2a-web-n%d" % i, "task": "旧计划 %d" % i} for i in range(6)]
        st = _state(tmp_path, old)
        # 新清单须**合格**（读侧复算组语义），否则会被 narrow_groups_invalid 先拦
        new = [dict(e) for e in NT6]
        for e in new:
            e["task"] = "新计划 " + e["task"]
        # G1 相同对：改 task 后仍须逐字相同
        new[0]["task"] = new[1]["task"] = "新计划 " + _G1_TASK
        sc = _sidecar(tmp_path, new, coverage_target=[1, 2, 3, 4])
        rc, out, pipe = _submit(st, 6, ["--expand-groups", "--k", "2",
                                        "--narrow-tasks-file", str(sc)])
        assert rc == 0, out
        assert out.get("narrow_source") == "sidecar", out
        fts = [r["full_task"] for r in pipe]
        assert all("新计划" in f for f in fts), fts
        assert not any("旧计划" in f for f in fts), "sidecar 在场时不得混入 state 全局清单"

    def test_sidecar_insufficient_does_not_fallback(self, tmp_path):
        st = _state(tmp_path, NT6)          # 全局清单够 3×K
        sc = _sidecar(tmp_path, NT6[:2])    # sidecar 不够
        rc, out, pipe = _submit(st, 6, ["--expand-groups", "--k", "2",
                                        "--narrow-tasks-file", str(sc)])
        assert rc != 0, out
        assert out.get("error") == "narrow_tasks_file_insufficient", out
        assert len(pipe) == 0, "sidecar 不足 ⟹ fail-closed，禁止回退全局清单"

    def test_scope_keeps_only_same_plan(self, tmp_path):
        foreign = [{"id": "old-%d" % i, "task": "旧计划 %d" % i,
                    "plan": "docs/plans/other.md"} for i in range(6)]
        st = _state(tmp_path, foreign + _scoped(NT6))
        rc, out, pipe = _submit(st, 6, ["--expand-groups", "--k", "2",
                                        "--narrow-scope", "docs/plans/demo.md"])
        assert rc == 0, out
        assert out.get("narrow_source") == "state_scoped", out
        fts = [r["full_task"] for r in pipe]
        assert all("旧计划" not in f for f in fts), "外计划条目必须被过滤"
        assert any("基线 题" in f for f in fts), fts

    def test_scope_rejects_unattributed_entries(self, tmp_path):
        """未声明 plan 归属的旧条目一律排除 ⟹ 无 sidecar 的计划 fail-closed。"""
        st = _state(tmp_path, NT6)          # NT6 无 plan 字段
        rc, out, pipe = _submit(st, 6, ["--expand-groups", "--k", "2",
                                        "--narrow-scope", "docs/plans/demo.md"])
        assert rc != 0, out
        assert out.get("error") == "narrow_tasks_insufficient", out
        assert out.get("narrow_source") == "state_scoped", out
        assert len(pipe) == 0

    def test_sidecar_explicit_group_wins_at_k1(self, tmp_path):
        """K=1 时按显式 group 取每组首条，而不是清单前 3 条（Q4 不得被挤掉）。

        2026-10-28：K 下限抬到 2，K=1 须显式 `GK_ALLOW_ARMS_PER_GROUP_1=1`（stderr 留痕），
        且只放宽「每组条数下限」—— covers/正交/污染/输出契约一条不减 ⟹ 夹具仍须是合格三组清单。
        """
        base = "给 VERDICT 与 SOURCES: <path:line>"
        nt = [
            {"id": "nt-G1-0", "group": "G1", "pair_id": "p1", "covers": [1, 2],
             "task": "Q1 题：" + base},
            {"id": "nt-G1-1", "group": "G1", "pair_id": "p1", "covers": [1, 2],
             "task": "Q1 题：" + base},
            {"id": "nt-G2-0", "group": "G2", "covers": [3], "task": "Q2 甲：" + base},
            {"id": "nt-G2-1", "group": "G2", "covers": [4], "task": "Q3 乙：" + base},
            {"id": "nt-G3-0", "group": "G3", "covers": [1], "polluted": True,
             "poison_claim": "Q4 甲", "task": "Q4 甲：" + base},
            {"id": "nt-G3-1", "group": "G3", "covers": [2], "polluted": True,
             "poison_claim": "Q4 乙", "task": "Q4 乙：" + base},
        ]
        st = _state(tmp_path, [])
        sc = _sidecar(tmp_path, nt, coverage_target=[1, 2, 3, 4])
        rc, out, pipe = _submit(st, 3, ["--expand-groups", "--k", "1",
                                        "--narrow-tasks-file", str(sc)],
                                env={"GK_ALLOW_ARMS_PER_GROUP_1": "1"})
        assert rc == 0, out
        fts = [r["full_task"] for r in pipe]
        assert "Q1 题" in fts[0] and "Q2 甲" in fts[1] and "Q4 甲" in fts[2], fts
        # 判别臂：按位置取前 3 条会得到 Q1/Q1/Q2（Q4 被挤掉），显式组选取才拿得到 Q4
        assert "Q2 甲" not in fts[0] and "Q4 甲" not in fts[1]

    def test_k1_requires_explicit_escape(self, tmp_path):
        """无 `GK_ALLOW_ARMS_PER_GROUP_1=1` 时 K=1 直接 fail-closed（k_below_min），零写盘。"""
        st = _state(tmp_path, NT6)
        rc, out, pipe = _submit(st, 3, ["--expand-groups", "--k", "1",
                                        "--narrow-tasks-file",
                                        str(_sidecar(tmp_path, NT6))])
        assert rc != 0, out
        assert out.get("error") == "k_below_min", out
        assert out.get("need_min") == 2 and out.get("got") == 1, out
        assert len(pipe) == 0, "K 下限拒绝 ⟹ 零写盘"

    def test_cli_wires_sidecar_to_enqueue_and_fanout(self):
        src = CLI.read_text(encoding="utf-8")
        i = src.find("cmd_plan_refinement() {")
        j = src.find("\ncmd_", i + 20)
        blk = src[i: j if j != -1 else len(src)]
        assert "_narrow_sidecar" in blk, "CLI 未解析 <plan>.narrow.json"
        assert '--narrow-tasks-file "$_narrow_sidecar"' in blk, "入队端未接 sidecar"
        assert "GK_NARROW_SIDECAR" in blk, "fan-out 端未接 sidecar"
        assert "--narrow-scope" in blk, "无 sidecar 时未按 plan 归属过滤"

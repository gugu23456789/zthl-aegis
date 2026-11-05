#!/usr/bin/env python3
"""§18.1 红先臂：批身份（batch identity）—— 界定“批”治跨批 / 单臂批混聚。

正本：`docs/plans/2026-09-28-git-concurrency-lease-declare-plan.md` §18.1（2026-10-03 登记）。
关联：`ECC-5538DD07B709`（MoA 面根因汇总 RC1/N1）· `ECC-489C8AE274E6`（tier 缺失，同类）。

判据（红先，HEAD 必红）：
  1) 派发写入：`subagent_history` 条目带 `batch_id`（12 hex）与 `tier`。HEAD 的 `_ENTRY_KEYS`
     既无 `batch_id` 亦无 `tier` ⟹ 行为臂 + 静态臂全红。
  2) 聚合语义：`moa-aggregate --batch <id>` 精确取批；缺省（同计划多批）报 `mode=all_batches`
     并按批分节（不混票）；跨批仅显式放开（trace 记 `cross_batch_allowed`）。
  3) 可比性：仅同批同规模（`batch_size` 相同）等权；单臂批标 `batch_size:1` 降权/单列；
     批边界与权重恒进 trace（非静默）。
"""
import json
import os
import subprocess
import sys

import pytest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import gk_moa_aggregate as M  # noqa: E402

CLI = SCRIPT_DIR.parent / "gatekeeper-cli.sh"
PLAN = "/p/docs/plans/x-plan.md"


# ── 批身份纯函数（§18.1 判据公式）──────────────────────────────────────────

def test_batch_id_is_12hex_deterministic():
    """同 (plan, narrow, epoch 桶) ⟹ 同 id；形态 = 12 hex。"""
    a = M.compute_batch_id(PLAN, ["a", "b"], epoch=1000)
    b = M.compute_batch_id(PLAN, ["a", "b"], epoch=1000)
    assert a == b, (a, b)
    assert len(a) == 12 and all(c in "0123456789abcdef" for c in a), a


def test_batch_id_order_insensitive():
    """narrow_tasks 规范化为**排序后**入哈希 ⟹ 各臂给序不同也得同 id。"""
    assert M.compute_batch_id(PLAN, ["b", "a"], epoch=1000) == \
        M.compute_batch_id(PLAN, ["a", "b"], epoch=1000)


def test_batch_id_accepts_str_form():
    """narrow 接受换行/逗号分隔 str（派发侧 env 形态）。"""
    assert M.compute_batch_id(PLAN, "b\na\n", epoch=1000) == \
        M.compute_batch_id(PLAN, ["a", "b"], epoch=1000)


def test_batch_id_differs_by_epoch_bucket():
    """跨纪元桶 ⟹ 异 id（同一计划的相邻两批须可分）。"""
    assert M.compute_batch_id(PLAN, ["a"], epoch=1000) != \
        M.compute_batch_id(PLAN, ["a"], epoch=1000 + M.BATCH_BUCKET_S)


def test_plan_key_from_task():
    """从派发 task 提取计划键（batch 作用域）；非 plan-refinement 通道 → 空串。"""
    assert M.plan_key_from_task("plan-refinement: %s — 质询 组1" % PLAN) == PLAN
    assert M.plan_key_from_task("RED-SCOPE: 枚举攻击面") == ""


# ── 聚合语义：--batch 精确取批 ─────────────────────────────────────────────

def _state(tmp_path, rows):
    """rows = [(subagent_id, batch_id)]；task 含 PLAN 以便 plan 锚。"""
    hist = [{"subagent_id": sid, "batch_id": bid,
             "task": "plan-refinement: %s — 质询 %s" % (PLAN, sid),
             "conclusion": "结论" * 200, "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]}
            for sid, bid in rows]
    p = tmp_path / ".gatekeeper.state"
    p.write_text(json.dumps({"gate_data": {"subagent_history": hist}}), encoding="utf-8")
    return str(p)


def test_collect_entries_batch_bound(tmp_path):
    sf = _state(tmp_path, [("s0", "B1"), ("s1", "B1"), ("s2", "B2"), ("s3", "B1")])
    entries, at = M.collect_entries(sf, None, None, batch="B1")
    assert at.get("mode") == "batch_bound", at
    assert at.get("batch_id") == "B1", at
    assert [e["subagent_id"] for e in entries] == ["s0", "s1", "s3"], entries
    assert at.get("excluded_other_batches") == 1, at


def test_aggregate_all_batches_sections(tmp_path):
    """缺省（同计划多批）⟹ trace.batch.mode=all_batches 且按批分节（不混票）。"""
    sf = _state(tmp_path, [("s0", "B1"), ("s1", "B1"), ("s2", "B2")])
    out = M.aggregate(sf, None, None, plan=PLAN)
    b = out["trace"]["batch"]
    assert b.get("mode") == "all_batches", b
    assert b.get("mixed_batches") is True, b
    assert {x["batch_id"] for x in b["batches"]} == {"B1", "B2"}, b


def test_single_arm_batch_downweight(tmp_path):
    """单臂批（size==1）降权并单列；多臂批等权（weight==1.0）。"""
    sf = _state(tmp_path, [("s0", "B1"), ("s1", "B1"), ("s2", "B2")])
    out = M.aggregate(sf, None, None, plan=PLAN)
    b = out["trace"]["batch"]
    w = {x["batch_id"]: x["weight"] for x in b["batches"]}
    assert w.get("B1") == 1.0, w
    assert w.get("B2", 1) < 1.0, w
    assert b.get("single_arm_batches") == ["B2"], b


def test_cross_batch_allowed_in_trace(tmp_path):
    """跨批唯一出口 = 显式放开；trace 恒记 `cross_batch_allowed`（非静默）。"""
    sf = _state(tmp_path, [("s0", "B1"), ("s1", "B2")])
    on = M.aggregate(sf, None, None, plan=PLAN, allow_cross_batch=True)
    off = M.aggregate(sf, None, None, plan=PLAN)
    assert on["trace"]["batch"]["cross_batch_allowed"] is True
    assert off["trace"]["batch"]["cross_batch_allowed"] is False


# ── §18.4（ECC-9BD2FA550A78）：plan_bound 跨批**不静默混票**（分节 + 显式合并门）──
# 病象：`--plan`(plan_bound) 收全 history（`excluded_other_tasks=0`），trace 只记
#   `mixed_batches=True`，但 consensus **仍对全臂混算**，且 `--allow-cross-batch` 在该
#   路径为 **no-op**（加不加结果逐字相同）⟹ 违反 §18.1「缺省按批分节（不混票）；
#   跨批仅显式放开」。

def test_plan_bound_mixed_requires_ack(tmp_path):
    """缺省跨批 ⟹ 不混票 + fail-loud（error=cross_batch_requires_ack）。

    红先：HEAD 的 `plan_bound` 直接对全臂算 consensus（n_refs=全臂数）且无 error ⟹ 红。
    """
    sf = _state(tmp_path, [("s0", "B1"), ("s1", "B1"), ("s2", "B2")])
    out = M.aggregate(sf, None, None, plan=PLAN)
    assert out["trace"]["batch"]["mixed_batches"] is True, out["trace"]["batch"]
    assert out.get("error") == "cross_batch_requires_ack", out.get("error")
    assert int(out["consensus"].get("n_refs", 0) or 0) < 3, out["consensus"]


def test_plan_bound_batch_sections_present(tmp_path):
    """缺省跨批 ⟹ 输出逐批分节的 clusters/consensus（不混票的可核载体）。

    红先：HEAD 无 `batch_sections` 键 ⟹ 红。
    """
    sf = _state(tmp_path, [("s0", "B1"), ("s1", "B1"), ("s2", "B2")])
    out = M.aggregate(sf, None, None, plan=PLAN)
    secs = out.get("batch_sections")
    assert secs, "缺 batch_sections（§18.4 分节未落）"
    got = {s["batch_id"]: s for s in secs}
    assert set(got) == {"B1", "B2"}, got
    assert got["B1"]["n_refs"] == 2 and got["B2"]["n_refs"] == 1, got
    assert got["B1"]["consensus"]["n_refs"] == 2, got["B1"]


def test_plan_bound_ack_merges_with_sections(tmp_path):
    """显式 `--allow-cross-batch` ⟹ 合并（顶层 n_refs=全臂数）**且**仍给分节。

    红先：HEAD 无 `batch_sections` 键 ⟹ 红；本臂兼负臂 —— 防「一刀切拒绝」。
    """
    sf = _state(tmp_path, [("s0", "B1"), ("s1", "B1"), ("s2", "B2")])
    out = M.aggregate(sf, None, None, plan=PLAN, allow_cross_batch=True)
    assert out["trace"]["batch"]["cross_batch_allowed"] is True
    assert "error" not in out, out.get("error")
    assert int(out["consensus"].get("n_refs", 0) or 0) == 3, out["consensus"]
    assert {s["batch_id"] for s in out.get("batch_sections") or []} == {"B1", "B2"}, \
        out.get("batch_sections")


# ── 派发写入（行为臂：真跑 CLI 落库载荷）──────────────────────────────────

def _payload_path():
    """2026-11-04（B2）：落库载荷已下沉为模块文件，判据面随之迁移（单源）。"""
    return CLI.parent / "scripts" / "gk_monitor_payload.py"


def _hist_region() -> str:
    """落库段 = `scripts/gk_monitor_payload.py` 全文（原 CLI 内联区已删）。"""
    return _payload_path().read_text(encoding="utf-8")


def _run_payload(tmp_path, ecc, extra_env=None):
    """真跑落库载荷（模块文件），返回写后的 state。"""
    sd = str(CLI.parent).replace("\\", "/")
    state = tmp_path / ".gatekeeper.state"
    state.write_text('{"gate_data":{}}', encoding="utf-8")
    out = tmp_path / "sub-1.json"
    out.write_text(json.dumps(ecc, ensure_ascii=False), encoding="utf-8")
    env = dict(os.environ, GK_TASK=ecc.get("task", ""), GK_HMAC_VALID="skip",
               GK_OUTPUT_FILE=str(out), GK_REPORT_FILE=str(tmp_path / "sub-1.md"),
               # 真因 D（2026-11-02）：路径经 env 传入（形态锚在解释器，见 `_gk_py_path`）
               GK_PY_SCRIPTS=sd + "/scripts", GK_PY_STATE=str(state).replace("\\", "/"))
    env.update(extra_env or {})
    r = subprocess.run([sys.executable, str(_payload_path())], input=json.dumps(ecc),
                       capture_output=True, text=True, env=env, timeout=90)
    assert r.returncode == 0, (r.returncode, r.stdout[-800:], r.stderr[-800:])
    return json.loads(state.read_text(encoding="utf-8"))


def _ecc(task):
    return {"mode": "subagent", "subagent_id": "sub-1", "nonce": "n1",
            "timestamp": "2026-10-03T00:00:00+00:00", "task": task, "conclusion": "c" * 300,
            "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]}


def test_payload_writes_batch_id_and_tier(tmp_path):
    """派发时写入 `batch_id`（按 §18.1 公式）与 `tier`；同批各臂 id 相同。"""
    ecc = _ecc("plan-refinement: %s — 质询 组1" % PLAN)
    d = _run_payload(tmp_path, ecc, extra_env={
        "GK_BATCH_PLAN": PLAN, "GK_BATCH_NARROW": "n1\nn2",
        "GK_BATCH_EPOCH": "1000", "SUBAGENT_TIER": "3"})
    ent = d["gate_data"]["subagent_history"][-1]
    assert ent.get("batch_id") == M.compute_batch_id(PLAN, ["n1", "n2"], epoch=1000), ent.get("batch_id")
    assert str(ent.get("tier", "")) == "3", ent.get("tier")


def test_payload_derives_plan_from_task(tmp_path):
    """无 GK_BATCH_PLAN 时从 task 提取计划键（各臂 task 均含计划路径）。"""
    ecc = _ecc("plan-refinement: %s — 质询 组2" % PLAN)
    d = _run_payload(tmp_path, ecc, extra_env={"GK_BATCH_EPOCH": "1000"})
    ent = d["gate_data"]["subagent_history"][-1]
    assert ent.get("batch_id") == M.compute_batch_id(PLAN, [], epoch=1000), ent.get("batch_id")


def test_payload_no_scope_means_no_batch(tmp_path):
    """无计划作用域（非 MoA 派发单元）⟹ `batch_id` 为空串（不凭空聚类无关臂）。"""
    ecc = _ecc("RED-SCOPE: 枚举攻击面")
    d = _run_payload(tmp_path, ecc, extra_env={"GK_BATCH_EPOCH": "1000"})
    ent = d["gate_data"]["subagent_history"][-1]
    assert ent.get("batch_id") == "", ent.get("batch_id")


# ── §18.3 组别身份（arm_group）派发写入 ────────────────────────────────────

def test_payload_writes_arm_group(tmp_path):
    """§18.3：派发侧注入 `GK_ARM_GROUP` ⟹ entry 落 `arm_group`（聚合端只读不猜）。

    红先：HEAD 的 `_ENTRY_KEYS` 无 `arm_group` ⟹ 载荷自检 `ENTRY_KEY_UNDECLARED` 或键缺失 ⟹ 红。
    """
    ecc = _ecc("plan-refinement: %s — 质询 组2 正交互补" % PLAN)
    d = _run_payload(tmp_path, ecc, extra_env={"GK_ARM_GROUP": "G2"})
    ent = d["gate_data"]["subagent_history"][-1]
    assert ent.get("arm_group") == "G2", ent.get("arm_group")


def test_payload_arm_group_defaults_empty(tmp_path):
    """未注入组别 ⟹ 空串（UNKNOWN，禁聚合端按指纹反推真组）。"""
    ecc = _ecc("plan-refinement: %s — 质询 组1" % PLAN)
    d = _run_payload(tmp_path, ecc)
    ent = d["gate_data"]["subagent_history"][-1]
    assert ent.get("arm_group") == "", ent.get("arm_group")


def test_entry_keys_include_arm_group():
    seg = _hist_region()
    assert "'arm_group'" in seg, "落库 entry 缺 arm_group（§18.3 派发写入未落）"


def test_cli_monitor_wires_arm_group():
    """§18.3 派发侧接线：monitor 须解析 `--arm-group` 并注入 `GK_ARM_GROUP`。"""
    cli = CLI.read_text(encoding="utf-8")
    assert "--arm-group)" in cli, "monitor 未解析 --arm-group（§18.3 派发侧接线缺）"
    assert "export GK_ARM_GROUP=" in cli, "monitor 未注入 GK_ARM_GROUP（§18.3 未接线）"


# ── 静态：投影键集 + CLI 接线 ─────────────────────────────────────────────

def test_entry_keys_include_batch_and_tier():
    seg = _hist_region()
    assert "'batch_id'" in seg, "落库 entry 缺 batch_id（§18.1 派发写入未落）"
    assert "'tier'" in seg, "落库 entry 缺 tier（ECC-489C8AE274E6 未治）"
    assert "_ENTRY_KEYS" in seg, "缺投影键集单源常量（红先锚失效）"


def test_cli_forwards_batch_flags():
    cli = CLI.read_text(encoding="utf-8")
    assert "--batch) batch=" in cli, "moa-aggregate 未解析 --batch（§18.1 CLI 接线缺）"
    assert "args+=(--batch " in cli, "moa-aggregate 未透传 --batch（§18.1 CLI 接线缺）"
    assert "--allow-cross-batch" in cli, "moa-aggregate 未接 --allow-cross-batch"


def test_cli_monitor_wires_batch_env():
    """G1（2026-10-03）：monitor 须提供批身份 env 注入面。

    病象：§18.1 的 `GK_BATCH_PLAN/GK_BATCH_NARROW/GK_BATCH_EPOCH` 三要素**无任何生产调用者**
    ⟹ batch_id 退化为 `f(plan, 10min 桶)`（同计划两轮误并 / 跨桶误分）。本臂钉住派发侧接线。
    """
    cli = CLI.read_text(encoding="utf-8")
    for flag in ("--batch-plan)", "--batch-narrow)", "--batch-epoch)"):
        assert flag in cli, ("monitor 未解析 %s（G1 派发侧接线缺）" % flag)
    for ev in ("export GK_BATCH_PLAN=", "export GK_BATCH_NARROW=", "export GK_BATCH_EPOCH="):
        assert ev in cli, ("monitor 未注入 %s（G1 批身份未接线）" % ev)


def test_cli_monitor_guards_batch_flags_to_subagent():
    """T3/T12（2026-10-05，n4）：批身份/组别 flag 须**与 `--subagent` 同用**，否则 exit 2。

    病象：`--arm-group`/`--batch-*` 原可在任意 mode（如 `--local`）下被接受并静默注入 env，
    而该 mode 无消费方 ⟹ 编排误用不显形。HEAD 无该守卫（`monitor --local --arm-group G3`
    落 rc=1 `stage required`）⟹ 红。行为对照（手工实测）：落刀后 `monitor --local --arm-group G3`
    = rc 2 + `--arm-group/--batch-* 仅与 --subagent 同用`。
    """
    cli = CLI.read_text(encoding="utf-8")
    assert "--arm-group/--batch-* 仅与 --subagent 同用" in cli, (
        "monitor 缺批 flag↔`--subagent` 模式守卫（T3/T12 未落）")


@pytest.mark.skipif(os.name == "nt", reason="POSIX bash payload test")
def test_history_payload_runs_under_real_bash(tmp_path):
    """结构 + 行为臂：落库载荷必须是**文件调用**，且能在真实 bash 下跑通并落 batch_id。

    2026-11-04（B2）下沉后，原「双引号区早闭合」风险**结构性消失**（不再有内联代码）。
    本臂守两点：① CLI 不再出现该块的内联 `python3 -c "` 形态；② 文件形态在 bash 下真跑成功。
    """
    cli = CLI.read_text(encoding="utf-8")
    assert 'GK_HMAC_VALID="$hmac_valid" python3 -c "' not in cli, "落库载荷仍是内联形态"
    assert "gk_monitor_payload.py" in cli, "CLI 未接线到下沉模块"
    ecc = _ecc("plan-refinement: %s — 质询 组1" % PLAN)
    state = tmp_path / ".gatekeeper.state"
    state.write_text('{"gate_data":{}}', encoding="utf-8")
    out = tmp_path / "sub-1.json"
    out.write_text(json.dumps(ecc, ensure_ascii=False), encoding="utf-8")
    env = dict(os.environ, STATE_FILE=str(state), SKILL_DIR=str(CLI.parent),
               GK_DBG_LOG=str(tmp_path / "dbg.log"), GK_TASK=ecc["task"],
               GK_HMAC_VALID="skip", GK_OUTPUT_FILE=str(out),
               GK_REPORT_FILE=str(tmp_path / "sub-1.md"),
               # 真因 D（2026-11-02）：路径经 env 传入（形态锚在解释器，见 `_gk_py_path`）
               GK_PY_SCRIPTS=str(CLI.parent / "scripts"), GK_PY_STATE=str(state))
    r = subprocess.run(["bash", "-c", 'python3 "$1"', "_", str(_payload_path())],
                       input=json.dumps(ecc), capture_output=True,
                       text=True, env=env, cwd=str(CLI.parent), timeout=90)
    both = (r.stdout or "") + (r.stderr or "")
    assert r.returncode == 0, (r.returncode, both[-500:])
    d = json.loads(state.read_text(encoding="utf-8"))
    assert d["gate_data"]["subagent_history"][-1].get("batch_id") != "", \
        "文件形态下未写入 batch_id ⟹ 落库链断裂"

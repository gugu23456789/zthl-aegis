#!/usr/bin/env python3
"""W2A-P2 红先臂：**消融腿接线**（臂记录带 Δ + 观测量）—— 治 §14.7.1「仪器与结果变量两条通道
从未会合」（探针 `gk_phase_probe` ↔ 六臂 `moa-aggregate` 从不见面）。

正本：`docs/plans/2026-10-12-w2a-p2-phase-experiment-plan.md` §14.7-C/§14.7-D-1（「接线先行，
零 API 可机检：让臂记录带 det_F1 / cache / 逐臂污染标记 —— 由 §2 五件在**臂装配侧**产出，
非事后从 verdicts 推」）。

判据（红先，HEAD 必红）：
  1) `gk_moa_aggregate.arm_observables` —— §2 五件在臂装配侧产出 φ（`gk_evidence.per_arm_phases`
     单源）/ `det_F1`（`gk_moa_judge`）/ cache（`gk_cache_observe`）；缺 S / 缺 gold / 缺 usage
     各**具名拒估**（禁静默 0）。
  2) 派发写入：`subagent_history` 条目带 `arm_delta`（标签层）+ `arm_obs`（观测量）；HEAD 的
     `_ENTRY_KEYS` 两者皆无。
  3) 接线：`monitor` 解析 `--arm-delta` 并注入 `GK_ARM_DELTA`；`plan-refinement` fan-out 逐臂落
     `i·Δ`（`--arm-delta-base` 缺省 0 = 同相控制臂，零回归）。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import gk_moa_aggregate as M  # noqa: E402
import gk_moa_judge  # noqa: E402

CLI = SCRIPT_DIR.parent / "gatekeeper-cli.sh"
PAYLOAD = SCRIPT_DIR / "gk_monitor_payload.py"
PLAN = "/p/docs/plans/x-plan.md"


# ── 1) `arm_observables` 纯函数（§2 五件臂装配侧产出）───────────────────────

def test_arm_observables_named_refusals():
    """缺 S / 缺 gold / 缺 usage ⟹ 三项各**具名拒估**（None / UNKNOWN），禁静默 0。"""
    obs = M.arm_observables({"conclusion": "some critique"}, delta=3, stride=None)
    assert obs["arm_phase"] is None, obs
    assert obs["det_F1"] is None and obs["det_f1_reason"] == "no_gold", obs
    assert obs["cache"]["usage_status"] == "UNKNOWN", obs
    assert obs["cache"]["calls"] == 0, obs


def test_arm_observables_phase_single_source():
    """φ = Δ mod S，经 `gk_evidence.per_arm_phases` 单源；stride=2/delta=3 ⟹ 1。"""
    obs = M.arm_observables({}, delta=3, stride=2)
    assert obs["arm_phase"] == 1, obs


def test_arm_observables_det_f1_with_gold():
    """gold 非空且 conclusion 可读 ⟹ `gk_moa_judge.score` 的 det_F1（同源比对）。"""
    gold = [{"id": "D1", "clause": "范围蔓延须收窄"}]
    concl = "K1 范围蔓延须收窄\nK2 无锚断言"
    obs = M.arm_observables({"conclusion": concl}, gold=gold)
    expect = gk_moa_judge.score(gold, concl)["det_F1"]
    assert obs["det_F1"] == expect, obs


def test_arm_observables_cache_from_usage():
    """逐调用 usage ⟹ `gk_cache_observe.observe` 摘要（usage_status=OBSERVED）。"""
    usage = {"calls": [{"prompt_cache_hit_tokens": 40, "prompt_cache_miss_tokens": 60},
                       {"prompt_cache_hit_tokens": 100, "prompt_cache_miss_tokens": 20}]}
    obs = M.arm_observables({"token_usage": usage}, stride=2, provider="deepseek")
    assert obs["cache"]["usage_status"] == "OBSERVED", obs
    assert obs["cache"]["calls"] == 2, obs
    assert obs["cache"]["cache_hit_ratio"] == round(140 / 220, 4), obs
    # 二条件 (a)：2 次调用 < min_steady(20) ⟹ 稳态状态必须具名 UNKNOWN（禁冒充「极高」）
    assert obs["cache"]["cache_status"] == "UNKNOWN", obs
    assert obs["cache"]["steady_cache_hit_ratio"] is None, obs


# ── 2) 派发写入（真跑 CLI 落库载荷）────────────────────────────────────────

def _hist_region() -> str:
    """落库载荷：2026-11-04 起由 `gatekeeper-cli.sh` 内联块**逐字下沉**到脚本式模块。"""
    return PAYLOAD.read_text(encoding="utf-8")


def _ecc(task):
    return {"mode": "subagent", "subagent_id": "sub-1", "nonce": "n1",
            "timestamp": "2026-10-03T00:00:00+00:00", "task": task, "conclusion": "c" * 300,
            "evidence": [{"file": "f", "lines": "1", "status": "confirmed"}]}


def _run_payload(tmp_path, ecc, extra_env=None):
    """真跑下沉后的落库载荷模块（stdin = ECC JSON），返回写后的 state。"""
    state = tmp_path / ".gatekeeper.state"
    state.write_text('{"gate_data":{}}', encoding="utf-8")
    out = tmp_path / "sub-1.json"
    out.write_text(json.dumps(ecc, ensure_ascii=False), encoding="utf-8")
    env = dict(os.environ, GK_TASK=ecc.get("task", ""), GK_HMAC_VALID="skip",
               GK_OUTPUT_FILE=str(out), GK_REPORT_FILE=str(tmp_path / "sub-1.md"),
               GK_PY_SCRIPTS=str(SCRIPT_DIR), GK_PY_STATE=str(state))
    env.update(extra_env or {})
    r = subprocess.run([sys.executable, str(PAYLOAD)], input=json.dumps(ecc),
                       capture_output=True, text=True, env=env, timeout=90)
    assert r.returncode == 0, (r.returncode, r.stdout[-800:], r.stderr[-800:])
    return json.loads(state.read_text(encoding="utf-8"))


def test_payload_writes_arm_delta_and_obs(tmp_path):
    """派发侧注入 `GK_ARM_DELTA`/`GK_STRIDE` ⟹ entry 落 `arm_delta` + `arm_obs`（φ 可派生）。"""
    ecc = _ecc("plan-refinement: %s — 质询 组1" % PLAN)
    d = _run_payload(tmp_path, ecc, extra_env={"GK_ARM_DELTA": "3", "GK_STRIDE": "2"})
    ent = d["gate_data"]["subagent_history"][-1]
    assert str(ent.get("arm_delta")) == "3", ent.get("arm_delta")
    obs = ent.get("arm_obs") or {}
    assert obs.get("arm_phase") == 1, obs
    assert (obs.get("cache") or {}).get("usage_status") == "UNKNOWN", obs


def test_payload_arm_delta_defaults_empty(tmp_path):
    """未注入 Δ ⟹ 空串（UNKNOWN，禁聚合端按指纹反推相位）。"""
    ecc = _ecc("plan-refinement: %s — 质询 组1" % PLAN)
    d = _run_payload(tmp_path, ecc)
    ent = d["gate_data"]["subagent_history"][-1]
    assert ent.get("arm_delta") == "", ent.get("arm_delta")


# ── 3) 静态：投影键集 + CLI 接线 ───────────────────────────────────────────

def test_entry_keys_include_arm_delta_and_obs():
    seg = _hist_region()
    assert "'arm_delta'" in seg, "落库 entry 缺 arm_delta（消融腿 Δ 未落）"
    assert "'arm_obs'" in seg, "落库 entry 缺 arm_obs（消融腿观测量未落）"


def test_cli_monitor_wires_arm_delta():
    """`monitor` 须解析 `--arm-delta` 并注入 `GK_ARM_DELTA`（对齐 `--arm-group` 惯例）。"""
    cli = CLI.read_text(encoding="utf-8")
    assert "--arm-delta) arm_delta=" in cli, "monitor 未解析 --arm-delta（消融腿接线缺）"
    assert "export GK_ARM_DELTA=" in cli, "monitor 未注入 GK_ARM_DELTA（消融腿未接线）"


def test_plan_refine_fanout_passes_arm_delta():
    """`plan-refinement` fan-out 须逐臂落 `i·Δ`（新旗标 `--arm-delta-base`，缺省 0）。"""
    cli = CLI.read_text(encoding="utf-8")
    assert "--arm-delta-base) arm_delta_base=" in cli, "plan-refinement 未解析 --arm-delta-base"
    assert '--arm-delta "$(( _i * _delta_base ))"' in cli, "fan-out 未逐臂传 Δ"


# ── 4) 消费侧：(组,Δ) 在聚合端可分离 ───────────────────────────────────────

def test_arm_group_label_with_delta():
    """φ/Δ 追加到标签：`G1`+Δ1 ⟹ `相同对·Δ1`；缺 Δ ⟹ 逐字零回归。"""
    assert M.arm_group_label("G1", "1") == "相同对·Δ1", M.arm_group_label("G1", "1")
    assert M.arm_group_label("G1", None) == "相同对", M.arm_group_label("G1", None)
    assert M.arm_group_label("", "") == "", M.arm_group_label("", "")


def test_arm_groups_splits_by_delta():
    """同组异 Δ ⟹ 分节（(组,Δ) 可分离）；同组同 Δ ⟹ 合节；`delta` 键随落。"""
    refs = [{"subagent_id": "a", "arm_group": "G1", "arm_delta": "0"},
            {"subagent_id": "b", "arm_group": "G1", "arm_delta": "1"},
            {"subagent_id": "c", "arm_group": "G1"}]
    gv = M.arm_groups(refs)
    assert [g["group"] for g in gv] == ["相同对", "相同对·Δ0", "相同对·Δ1"], gv
    assert [g["delta"] for g in gv] == ["", "0", "1"], gv


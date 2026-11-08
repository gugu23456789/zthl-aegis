"""`gk_gate_entropy.py` — ECO 分支作用域隔离（B3，2026-11-06）。

病灶（实测）：ECO 分支取 `human_calibration_log[-5:]` 却不按 `stage` 过滤，
`ECC-*`（评审/裁决的增量校准）与 `ECO-*`（阶段校准）共用同一个窗口 ⟹
无关车道数据把熵抬到 0.60、`advance` 被 R4 硬阻断
（本机真实形态：5 条里 4 条属 `ECC-1E37E2BFCC8C`）。

修正语义（本文件锁死）：
  - 只统计 `stage` 以 `ECO-` 开头的记录；
  - `stage == ""` 的旧数据仍计入（`gk_adjudicate` 恒写 stage，空值只出现在引入该字段之前，
    与 `gk_advance.py` 的旧数据口径一致，避免历史状态熵被清零）；
  - `ECC-*` / `RED-*` / 其它前缀完全隔离；
  - 窗口仍是「过滤后最近 5 条」；标准分支（`rejected_edits`）行为不变。
"""
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
from gk_gate_entropy import compute_entropy_from_dict  # noqa: E402


def _entry(stage, pass_n=0, warn_n=0, ts="2026-11-06T00:00:00Z"):
    """构造 human_calibration_log 条目：pass_n 个 PASS + warn_n 个 WARN。"""
    vj = {}
    for i in range(pass_n):
        vj["P%d" % i] = "PASS"
    for i in range(warn_n):
        vj["W%d" % i] = "WARN"
    return {"stage": stage, "verdicts_json": vj, "timestamp": ts}


def _state(log):
    return {"gate_data": {"human_calibration_log": log}}


# ─── B3 核心：ECC 不得污染 ECO 熵 ───

def test_ecc_entries_do_not_pollute_eco_entropy():
    """真实形态：4 条 ECC WARN + 1 条 ECO PASS ⟹ 熵 0.0（修前为 0.8）。"""
    log = [_entry("ECC-1E37E2BFCC8C", warn_n=1) for _ in range(4)]
    log.append(_entry("ECO-EDIT", pass_n=1))
    assert compute_entropy_from_dict(_state(log), "ECO-EDIT") == 0.0


def test_only_ecc_entries_yield_zero():
    """只有 ECC 记录 ⟹ ECO 域无样本 ⟹ 0.0（不得把 ECC 的 FAIL 算进来）。"""
    log = [_entry("ECC-ABC", warn_n=1) for _ in range(5)]
    assert compute_entropy_from_dict(_state(log), "ECO-EDIT") == 0.0


def test_eco_entries_still_counted():
    """ECO 域本身仍按 WARN/FAIL 比例计熵：全 PASS + 1/2 WARN ⟹ 均值 0.25。"""
    log = [_entry("ECO-EDIT", pass_n=1, warn_n=0),
           _entry("ECO-VERIFY", pass_n=1, warn_n=1)]
    assert compute_entropy_from_dict(_state(log), "ECO-EDIT") == 0.25


def test_window_applies_after_domain_filter():
    """窗口必须先过滤再切片：2 条旧 ECO FAIL + 5 条新 ECO PASS，中间夹 10 条 ECC FAIL
    ⟹ 域内最近 5 条全 PASS ⟹ 0.0（修前取全量最近 5 条 = 5 条 ECC FAIL ⟹ 1.0）。"""
    log = [_entry("ECO-EDIT", warn_n=1), _entry("ECO-EDIT", warn_n=1)]
    log += [_entry("ECC-X", warn_n=1) for _ in range(10)]
    log += [_entry("ECO-EDIT", pass_n=1) for _ in range(5)]
    assert compute_entropy_from_dict(_state(log), "ECO-EDIT") == 0.0


def test_non_eco_prefixes_excluded():
    """RED-* 等其它前缀与 ECC 同等隔离。"""
    log = [_entry("RED-PLAN", warn_n=1),
           _entry("ECOX-NOT-ECO", warn_n=1),
           _entry("ECO-DOC", pass_n=1)]
    assert compute_entropy_from_dict(_state(log), "ECO-DOC") == 0.0


def test_stageless_legacy_entry_still_counts():
    """旧数据（无 stage 字段）保持计入，避免历史状态熵被清零。"""
    log = [{"verdicts_json": {"a": "WARN"}, "timestamp": "2026-06-17T10:00:00"}]
    assert compute_entropy_from_dict(_state(log), "ECO-EDIT") == 1.0


# ─── 零回归：标准分支不受影响 ───

def test_standard_branch_ignores_calibration_log():
    d = {"gate_data": {
        "human_calibration_log": [_entry("ECO-EDIT", warn_n=1)],
        "rejected_edits": [{"score": 0.2, "source": "gate"}],
    }}
    assert compute_entropy_from_dict(d, "STAGE_2") == 1.0


def test_eco_branch_ignores_rejected_edits():
    d = {"gate_data": {
        "human_calibration_log": [_entry("ECO-EDIT", pass_n=1)],
        "rejected_edits": [{"score": 0.2, "source": "gate"}],
    }}
    assert compute_entropy_from_dict(d, "ECO-EDIT") == 0.0


def test_empty_and_null_log_no_crash():
    assert compute_entropy_from_dict({"gate_data": {"human_calibration_log": None}}, "ECO-EDIT") == 0.0
    assert compute_entropy_from_dict({"gate_data": {}}, "ECO-EDIT") == 0.0

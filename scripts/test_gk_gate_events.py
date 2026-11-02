#!/usr/bin/env python3
"""T1/T2 红先臂（2026-11-01）：额度银行**事件单写**。

判据（计划 §2.1 / §3 T1-T2）：
  ① 一次 block 只多 **1** 条事件（落 `gate_data.rejected_edits`，`outcome=blocked`），
     且 `bank_actions` **不再增长**（本期改读时投影，见 T3）；
  ② `force` 也写 **1** 条事件（`outcome=forced`），且**熵值不变**（forced 不进熵窗）；
  ③ `dry_run` 零写（既有契约，不许被本次改动破坏）。
"""
import json as _json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import gk_advance as A  # noqa: E402
import gk_gate_entropy as E  # noqa: E402


def _monitor(score=0.0):
    return {"mode": "local", "passed": 0, "total": 4, "score": score}


def _state():
    return {"gate_data": {"rejected_edits": []}}


def test_block_writes_exactly_one_event_and_no_bank_actions(tmp_path):
    d = _state()
    r = A._bank_monitor_gate(d, "STAGE_1", "STAGE_2", _monitor(), False, False,
                             str(tmp_path / "s.state"))
    assert r and r.get("allowed") is False, r
    rej = d["gate_data"]["rejected_edits"]
    assert len(rej) == 1, rej
    ev = rej[0]
    assert ev["source"] == "bank"
    assert ev["outcome"] == "blocked"
    assert ev["stage"] == "STAGE_1" and ev["to_stage"] == "STAGE_2"
    assert not d["gate_data"].get("bank_actions"), "bank_actions 不应再被追加"


def test_force_writes_one_event_and_entropy_unchanged(tmp_path):
    d = _state()
    before = E.compute_entropy_from_dict(d, "STAGE_1")
    r = A._bank_monitor_gate(d, "STAGE_1", "STAGE_2", _monitor(), True, False,
                             str(tmp_path / "s.state"))
    assert r is None, "force 必须放行"
    rej = d["gate_data"]["rejected_edits"]
    assert len(rej) == 1, rej
    assert rej[0]["outcome"] == "forced"
    assert not d["gate_data"].get("bank_actions"), "bank_actions 不应再被追加"
    assert E.compute_entropy_from_dict(d, "STAGE_1") == before, "forced 事件不得抬熵"


def test_dry_run_zero_writes(tmp_path):
    d = _state()
    r = A._bank_monitor_gate(d, "STAGE_1", "STAGE_2", _monitor(), False, True,
                             str(tmp_path / "s.state"))
    assert r and r.get("allowed") is False, r
    assert d["gate_data"]["rejected_edits"] == []
    assert not d["gate_data"].get("bank_actions")


def test_bank_actions_projection_is_single_source(tmp_path):
    """T3：投影 == filter(source=bank)，且不落盘第二份。"""
    from gk_json_utils import view_bank_actions

    d = _state()
    A._bank_monitor_gate(d, "STAGE_1", "STAGE_2", _monitor(), False, False, str(tmp_path / "s.state"))
    A._bank_monitor_gate(d, "STAGE_1", "STAGE_2", _monitor(), True, False, str(tmp_path / "s.state"))
    proj = view_bank_actions(d["gate_data"])
    assert len(proj) == 2, proj
    assert proj[0]["forced"] is False and proj[1]["forced"] is True
    assert proj[0]["transition"] == "STAGE_2"
    assert not d["gate_data"].get("bank_actions"), "投影不得落盘"


def test_journal_name_rotation_and_no_legacy_write(tmp_path, monkeypatch):
    """T5：写新 journal、超硬顶轮转 `-1`、绝不写旧名 `-archive`。"""
    st = str(tmp_path / "s.state")
    monkeypatch.setattr(A, "REJECTED_CAP", 1)
    monkeypatch.setattr(A, "JOURNAL_HARD_BYTES", 300)
    gd = {"rejected_edits": []}
    for i in range(8):
        A._append_rejected(gd, {"i": i, "pad": "x" * 120}, st)
    j = tmp_path / "s.state.rejected-edits-journal.jsonl"
    j1 = tmp_path / "s.state.rejected-edits-journal.jsonl-1"
    assert j.exists() and j1.exists(), "超硬顶必须轮转 -1"
    assert not (tmp_path / "s.state.rejected-edits-archive.jsonl").exists(), "不得再写旧名"
    # 轮转 = `os.replace` 覆盖旧 `-1` ⟹ **不承诺跨轮守恒**（总量 ≤ 2×硬顶才是契约）；
    #   这里只钉「有写入、未交错、且总量有界」。
    lines = [ln for ln in j.read_text(encoding="utf-8").splitlines() if ln.strip()]
    lines1 = [ln for ln in j1.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) + len(lines1) <= 7
    for ln in lines + lines1:
        _json.loads(ln)
    assert j.stat().st_size <= 300 + 200, "当前文件不得无界增长（硬顶 + 单块余量）"


def test_journal_concurrent_append_no_interleave(tmp_path, monkeypatch):
    """T6：8 线程并发写 journal，行不交错（每行仍是完整 JSON）。"""
    import threading

    st = str(tmp_path / "s.state")
    monkeypatch.setattr(A, "REJECTED_CAP", 1)

    def worker(i):
        gd = {"rejected_edits": [{"seed": i}]}
        for k in range(20):
            A._append_rejected(gd, {"t": i, "k": k, "pad": "y" * 40}, st)

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    lines = [ln for ln in (tmp_path / "s.state.rejected-edits-journal.jsonl")
             .read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 160, len(lines)
    for ln in lines:
        _json.loads(ln)      # 交错会直接抛 JSONDecodeError


def test_forced_exits_denominator_not_only_numerator(monkeypatch):
    """质询臂 a 红先臂：119 forced + 1 blocked ⟹ 熵必须是 1.0，不得被 forced 稀释到 0。

    原实现只在 `is_violation` 排除 forced（分子），它仍占 `len(w)` 分母 ⟹ 1/120≈0.008，
    与「1 条阻断 = 全窗违规」的语义相反（与 C3b 洗窗失明同型）。
    """
    monkeypatch.setattr(E, "_rejected_window", lambda: 120)
    gd = {"rejected_edits": [{"source": "bank", "outcome": "forced", "stage": "S"}] * 119
          + [{"source": "bank", "outcome": "blocked", "stage": "S"}]}
    assert E.compute_entropy_from_dict({"gate_data": gd}, "STAGE_1") == 1.0


def test_projection_merges_legacy_bank_actions():
    """质询臂 d 红先臂：存量落盘 `bank_actions` 必须并入投影（`legacy=true`），不得消失。"""
    from gk_json_utils import view_bank_actions

    gd = {"bank_actions": [{"stage": "OLD", "transition": "T-OLD", "score": None,
                            "ts": "2026-10-20T00:00:00Z", "forced": True}],
          "rejected_edits": [{"source": "bank", "outcome": "blocked", "stage": "NEW",
                              "to_stage": "T-NEW", "timestamp": "2026-11-01T00:00:00Z"}]}
    proj = view_bank_actions(gd)
    assert len(proj) == 2, proj
    assert proj[0]["stage"] == "OLD" and proj[0]["legacy"] is True
    assert proj[1]["stage"] == "NEW" and "legacy" not in proj[1]



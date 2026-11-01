#!/usr/bin/env python3
"""红先测试：提问挂起 kill 闸（落点 = `monitor --local` 的拦截）

2026-09-21 用户裁定（逐字）：
  「kill 应该是 monitor--local 的拦截，纪律表是摆设」
  「提问静默期间开始跑睡眠，提问半小时没动静就暂停主进程」

分工契约（不越权）：
  - **记录侧**（`pre_tool_hook.py`，只写不拦）：
      · `AskUserQuestion` 被 Gate 9 放行（None/WARN）→ 落待答标记 `.gatekeeper.ask-hold`
        （内容 `<ask_epoch>|<note>`）。
      · 任一**非** `AskUserQuestion` 工具调用到达 ⟹ 上一次提问已结束（用户已答/已放弃）
        ⟹ 台账 `.gatekeeper.ask-hold.log` 追加 `{ask_ts,resume_ts,elapsed_s,note}`，
        并清掉待答标记。
      · Gate 9 **BLOCK** 的提问（无人时段 H1 / 纯确认型 H2）**不落标记** —— 提问没发生。
  - **判杀侧**（`monitor --local` 的 `ask_hold_kill` 项）：
      · 停留 ≥ `_ASK_HOLD_KILL_S`（1800s）⟹ 判 `FAIL` 且**计入 `total_req`**
        ⟹ `verdict=BLOCKED` ⟹ `advance` 被拦 = 「暂停主进程」的机制化落法。
      · 24h 窗口外的历史记录不重复判杀（防陈旧台账永久锁死）。
      · `GK_ASK_HOLD_KILL=0` 关闭本闸（显式人工放行，与 edit_budget 逃生舱同调）。

红先纪律：实现前本文件**必须全红**（`AttributeError`/`AssertionError`），不得先写实现。
"""
import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import pre_tool_hook  # noqa: E402
from test_gk_edit_budget_metering import _mk_sandbox, _wsl  # noqa: E402

CLI_SRC = SCRIPT_DIR.parent / "gatekeeper-cli.sh"


def _q(question, labels, header="x"):
    return {"questions": [{"question": question, "header": header,
                           "options": [{"label": l} for l in labels]}]}


def _run_hook(stdin_data: dict) -> int:
    old = sys.stdin
    sys.stdin = io.StringIO(json.dumps(stdin_data))
    try:
        pre_tool_hook.main()
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0
    finally:
        sys.stdin = old
    return 0


@pytest.fixture()
def hold_paths(tmp_path, monkeypatch):
    """待答标记 / 台账落 tmp（绝不触碰真 SKILL_DIR 的 .gatekeeper.ask-hold*）。"""
    monkeypatch.setattr(pre_tool_hook, "SKILL_DIR", tmp_path)
    monkeypatch.setattr(pre_tool_hook, "_ASK_HOLD_PENDING", tmp_path / ".gatekeeper.ask-hold")
    monkeypatch.setattr(pre_tool_hook, "_ASK_HOLD_LEDGER", tmp_path / ".gatekeeper.ask-hold.log")
    monkeypatch.delenv("GK_ALLOW_ASK", raising=False)
    return tmp_path / ".gatekeeper.ask-hold", tmp_path / ".gatekeeper.ask-hold.log"


# ───────────────────────── 记录侧 ─────────────────────────

class TestAskHoldRecord:
    def test_record_writes_pending_with_epoch_and_note(self, hold_paths):
        pending, _ = hold_paths
        pre_tool_hook._ask_hold_record("R7 用哪个方案？")
        assert pending.exists(), "放行的提问必须落待答标记（否则判杀侧无判据）"
        head, _, note = pending.read_text(encoding="utf-8").partition("|")
        assert abs(float(head) - time.time()) < 5, "头部必须是提问时刻 epoch"
        assert "R7 用哪个方案" in note

    def test_record_is_single_slot_keeps_latest(self, hold_paths):
        pending, _ = hold_paths
        pre_tool_hook._ask_hold_record("第一个问题")
        first = pending.read_text(encoding="utf-8")
        time.sleep(0.01)
        pre_tool_hook._ask_hold_record("第二个问题")
        assert "第二个问题" in pending.read_text(encoding="utf-8")
        assert first != pending.read_text(encoding="utf-8")

    def test_record_never_raises_without_skill_dir(self, monkeypatch):
        monkeypatch.setattr(pre_tool_hook, "SKILL_DIR", Path("/nonexistent/\x00bad"))
        monkeypatch.setattr(pre_tool_hook, "_ASK_HOLD_PENDING", Path("/nonexistent/\x00bad/p"))
        pre_tool_hook._ask_hold_record("x")   # 只记录层绝不因写失败影响工具链


class TestAskHoldSettle:
    def test_settle_appends_ledger_and_clears_pending(self, hold_paths):
        pending, ledger = hold_paths
        pending.write_text(f"{time.time() - 2400:.3f}|R7 用哪个方案？", encoding="utf-8")
        pre_tool_hook._ask_hold_settle()
        assert not pending.exists(), "结算后必须清掉待答标记（否则每轮重复结算）"
        recs = [json.loads(l) for l in ledger.read_text(encoding="utf-8").splitlines() if l.strip()]
        assert len(recs) == 1
        assert recs[0]["elapsed_s"] >= 2300, "elapsed 必须是「提问→下一次工具调用」的真实跨度"
        assert recs[0]["resume_ts"] >= recs[0]["ask_ts"]

    def test_settle_noop_when_no_pending(self, hold_paths):
        pending, ledger = hold_paths
        pre_tool_hook._ask_hold_settle()
        assert not pending.exists() and not ledger.exists(), "无待答不得凭空空转出台账"

    def test_settle_falls_back_to_mtime_when_head_unparseable(self, hold_paths):
        pending, ledger = hold_paths
        pending.write_text("garbage-no-epoch|note", encoding="utf-8")
        pre_tool_hook._ask_hold_settle()
        recs = [json.loads(l) for l in ledger.read_text(encoding="utf-8").splitlines() if l.strip()]
        assert len(recs) == 1 and recs[0]["elapsed_s"] >= 0, "半写/不可解析须按 mtime 兜底而非丢弃"


# ───────────────────────── 判杀侧（只读快照契约） ─────────────────────────

class TestAskHoldSnapshot:
    def test_threshold_is_1800s(self):
        assert pre_tool_hook._ASK_HOLD_KILL_S == 1800.0, "阈值 = 用户口述的半小时"

    def test_snapshot_flags_elapsed_over_threshold(self, hold_paths):
        _, ledger = hold_paths
        ledger.write_text(json.dumps({"ask_ts": time.time() - 3000, "resume_ts": time.time() - 1200,
                                      "elapsed_s": 1800.0, "note": "R7"}) + "\n", encoding="utf-8")
        snap = pre_tool_hook._ask_hold_snapshot(str(hold_paths[0].parent))
        assert snap["violations"], "≥1800s 的停留必须产出 violation（判杀依据）"
        assert snap["max_s"] >= 1800.0

    def test_snapshot_ignores_under_threshold(self, hold_paths):
        _, ledger = hold_paths
        ledger.write_text(json.dumps({"ask_ts": time.time() - 600, "resume_ts": time.time(),
                                      "elapsed_s": 600.0, "note": "ok"}) + "\n", encoding="utf-8")
        snap = pre_tool_hook._ask_hold_snapshot(str(hold_paths[0].parent))
        assert snap["violations"] == [], "未超阈值的正常提问不得误杀"
        assert snap["max_s"] < 1800.0

    def test_snapshot_flags_still_pending_over_threshold(self, hold_paths):
        pending, _ = hold_paths
        pending.write_text(f"{time.time() - 2400:.3f}|still pending", encoding="utf-8")
        snap = pre_tool_hook._ask_hold_snapshot(str(hold_paths[0].parent))
        assert snap["violations"], "进行中且已超阈值的提问同样要判杀"
        assert snap["pending_s"] >= 2300

    def test_snapshot_ignores_stale_ledger_beyond_ttl(self, hold_paths):
        _, ledger = hold_paths
        ledger.write_text(json.dumps({"ask_ts": time.time() - 200000, "resume_ts": time.time() - 190000,
                                      "elapsed_s": 3600.0, "note": "ancient"}) + "\n", encoding="utf-8")
        snap = pre_tool_hook._ask_hold_snapshot(str(hold_paths[0].parent))
        assert snap["violations"] == [], "24h 窗口外的陈旧记录不得永久锁死流程"

    def test_snapshot_never_raises_on_broken_input(self, hold_paths):
        _, ledger = hold_paths
        ledger.write_text("not-json\n{broken\n", encoding="utf-8")
        snap = pre_tool_hook._ask_hold_snapshot(str(hold_paths[0].parent))
        assert snap["violations"] == []


# ───────────────────────── main() 接线 ─────────────────────────

class TestMainWiring:
    def test_main_settles_pending_on_non_ask_tool(self, hold_paths):
        pending, ledger = hold_paths
        pending.write_text(f"{time.time() - 2400:.3f}|prior ask", encoding="utf-8")
        _run_hook({"tool_name": "RunCommand", "tool_input": {"command": "echo hi"}, "cwd": "/tmp"})
        assert not pending.exists(), "任一非提问工具调用 ⟹ 上一问已结束"
        recs = [json.loads(l) for l in ledger.read_text(encoding="utf-8").splitlines() if l.strip()]
        assert len(recs) == 1 and recs[0]["elapsed_s"] >= 2300

    def test_main_records_pending_on_allowed_ask(self, hold_paths):
        pending, _ = hold_paths
        _run_hook({"tool_name": "AskUserQuestion",
                   "tool_input": _q("R7 用方案甲还是方案乙？", ["方案甲", "方案乙"]),
                   "cwd": "/tmp"})
        assert pending.exists(), "放行的真分叉提问必须落待答标记"

    def test_main_does_not_record_on_blocked_ask(self, hold_paths):
        pending, _ = hold_paths
        _run_hook({"tool_name": "AskUserQuestion",
                   "tool_input": _q("是否继续推进下一批？", ["继续", "取消"]),
                   "cwd": "/tmp"})
        assert not pending.exists(), "被 Gate 9 BLOCK 的提问没发生 ⟹ 不得落标记"

    def test_main_settles_before_adding_new_ask(self, hold_paths):
        pending, ledger = hold_paths
        pending.write_text(f"{time.time() - 2400:.3f}|prior ask", encoding="utf-8")
        _run_hook({"tool_name": "AskUserQuestion",
                   "tool_input": _q("R7 用方案甲还是方案乙？", ["方案甲", "方案乙"]),
                   "cwd": "/tmp"})
        recs = [json.loads(l) for l in ledger.read_text(encoding="utf-8").splitlines() if l.strip()]
        assert len(recs) == 1, "连续提问之间也必须结算上一问（否则跨度丢失）"
        assert pending.exists() and "方案甲" in pending.read_text(encoding="utf-8")


# ───────────────────────── CLI 侧：monitor --local 的拦截 ─────────────────────────

def _sandbox(tmp_path: Path) -> Path:
    """`_mk_sandbox` + `monitor-schemas` 软链（后者是 `monitor` 的 schema 门前置：
    缺它任何 stage 都先撞 `{"error":"no schema for <stage>"}`，与本闸无关）。"""
    sb = _mk_sandbox(tmp_path, {"max": 9, "used": 0, "remaining": 9}, worktree="")
    link = sb / "monitor-schemas"
    if not link.exists():
        os.symlink(SCRIPT_DIR.parent / "monitor-schemas", link)
    return sb


def _monitor_local(sb: Path, stage: str = "STAGE_0"):
    """沙箱跑 `monitor --local <stage>`；`STAGE_0` 与 `_mk_sandbox` 的 state 对齐。"""
    w = _wsl(sb)
    return subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh monitor --local %s' % (w, stage)],
        capture_output=True, text=True, timeout=300)


def _write_ledger(sb: Path, elapsed_s: float):
    rec = {"ask_ts": time.time() - elapsed_s - 1, "resume_ts": time.time(),
           "elapsed_s": elapsed_s, "note": "ledger arm"}
    (sb / ".gatekeeper.ask-hold.log").write_text(json.dumps(rec) + "\n", encoding="utf-8")


class TestMonitorLocalKill:
    def test_monitor_local_fails_and_blocks_when_over_threshold(self, tmp_path):
        sb = _sandbox(tmp_path)
        _write_ledger(sb, 3600.0)
        r = _monitor_local(sb)
        assert '"item":"ask_hold_kill"' in r.stdout, f"monitor --local 必须产出该检查项：{r.stdout[-400:]}"
        assert '"item":"ask_hold_kill","status":"FAIL"' in r.stdout, "超阈值必须判 FAIL"
        assert '"verdict":"BLOCKED"' in r.stdout, "FAIL 须计入 total_req ⟹ verdict 必须被拉成 BLOCKED"

    def test_monitor_local_passes_under_threshold(self, tmp_path):
        sb = _sandbox(tmp_path)
        _write_ledger(sb, 600.0)
        r = _monitor_local(sb)
        assert '"item":"ask_hold_kill","status":"PASS"' in r.stdout, f"未超阈值必须 PASS：{r.stdout[-400:]}"

    def test_monitor_local_kill_switch_disables_check(self, tmp_path):
        sb = _sandbox(tmp_path)
        _write_ledger(sb, 3600.0)
        w = _wsl(sb)
        r = subprocess.run(
            ["bash", "-lc", 'cd "%s" && GK_ASK_HOLD_KILL=0 bash gatekeeper-cli.sh monitor --local STAGE_0' % w],
            capture_output=True, text=True, timeout=300)
        assert '"item":"ask_hold_kill","status":"PASS"' in r.stdout, "逃生舱必须放行"
        assert '"verdict":"BLOCKED"' not in r.stdout, "逃生舱下不得因本闸判 BLOCKED"

    def test_monitor_local_passes_without_any_ledger(self, tmp_path):
        sb = _sandbox(tmp_path)
        r = _monitor_local(sb)
        assert '"item":"ask_hold_kill","status":"PASS"' in r.stdout, "无台账 = 无提问挂起 ⟹ PASS"

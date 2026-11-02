#!/usr/bin/env python3
"""档 1 红先臂：`calibrate --edit-log` —— edit-log K/N **读面**的 CLI 通路（`ECC-D72764C0D354`）。

病象（2026-10-09）：`gk_budget_ledger.py calibrate|edit-stats`（K/N 标定 + T6 摘要读面）**无 CLI 包装**，
直跑被 `pre_tool_hook` 拦（「绕过技能内置 cmd」）；`audit --all` 只跑 `audit --state` 子域（`gk_audit_state`
mode=state 不含 `edit_log`；含 `edit_log` 的 mode=all 无人调用）⟹ 读面整体不可达 = edit-log 载体
「只写不读」。hook 禁直跑 ⟹ agent **结构性**无法标定 开关 B（`ECC-F66552EC9DA3`）。

修法（落刀面 = **区外** `cmd_calibrate`，不新增命令 —— `_CMD_REG` 在 `PROTECTED_REGION::gate` 内）：
  `calibrate --edit-log [...]` → 委托 `gk_budget_ledger.py calibrate`；
  `calibrate --edit-log --stats` → 委托 `gk_budget_ledger.py edit-stats`。
  无 `--edit-log` ⟹ 既有 route-center 五层校准**逐字不变**。

臂（HEAD 必红：`cmd_calibrate` 无 `--edit-log` 分支，`--edit-log` 会被透传给 route-center 报错）：
  · `test_calibrate_edit_log_reaches_ledger`（行为：真跑 CLI ⟹ K/N 标定 JSON）
  · `test_calibrate_edit_log_stats_reaches_edit_stats`（行为：真跑 CLI ⟹ edit-stats 读面 JSON）
  · `test_calibrate_edit_log_branch_wired`（静态：分支 + 委托单一源）
  · `test_calibrate_default_route_center_preserved`（非红回归守卫：route-center 通路须仍在）
"""
import json
import os
import subprocess
from pathlib import Path

SD = Path(__file__).resolve().parent.parent
CLI = SD / "gatekeeper-cli.sh"


def _mk(tmp_path, events):
    st = tmp_path / ".gatekeeper.state"
    st.write_text(json.dumps({"stage": "ECO-EDIT", "r_phase": "R1", "gate_data": {}},
                             ensure_ascii=False), encoding="utf-8", newline="\n")
    p = Path(str(st) + ".edit-log.jsonl")
    p.write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events),
                 encoding="utf-8", newline="\n")
    return st


def _run(st, *args):
    return subprocess.run(["bash", str(CLI), *args],
                          env={**os.environ, "STATE_FILE": str(st)},
                          capture_output=True, text=True, timeout=180)


def _json(r):
    """取 stdout 里最后一行 JSON（CLI 可能混入非 JSON 提示行）。"""
    for ln in reversed([x for x in r.stdout.splitlines() if x.strip()]):
        try:
            return json.loads(ln)
        except ValueError:
            continue
    raise AssertionError("stdout 无 JSON：rc=%s\n%s\n---stderr---\n%s"
                         % (r.returncode, r.stdout[:400], r.stderr[:400]))


def _edits(n_sessions):
    return [{"ts": "2026-10-09T00:00:%02dZ" % i, "kind": "edit", "source": "edit",
             "session": "s%d" % i, "node": "ECO-EDIT", "path": "/x/a.py", "result": "allow"}
            for i in range(n_sessions)]


def _calibrate_src():
    src = CLI.read_text(encoding="utf-8")
    i = src.index("cmd_calibrate() {")
    j = src.index("\n}\n", i)
    return src[i:j]


def test_calibrate_edit_log_reaches_ledger(tmp_path):
    """行为臂：`calibrate --edit-log` 真跑到 `gk_budget_ledger calibrate`（K/N 标定 JSON）。"""
    st = _mk(tmp_path, _edits(3))
    r = _run(st, "calibrate", "--edit-log")
    out = _json(r)
    assert "sample" in out and "insufficient_data" in out, out
    assert out["sample"]["nodes"] == 3, out
    assert out["insufficient_data"] is True, out   # 3 < EDIT_CALIB_MIN_NODES=20


def test_calibrate_edit_log_stats_reaches_edit_stats(tmp_path):
    """行为臂：`calibrate --edit-log --stats` 真跑到 `gk_budget_ledger edit-stats`（T6 读面）。"""
    st = _mk(tmp_path, _edits(2))
    r = _run(st, "calibrate", "--edit-log", "--stats")
    out = _json(r)
    assert "t6" in out and "edits" in out, out
    assert out["edits"] == 2, out


def test_calibrate_edit_log_branch_wired(tmp_path):
    """静态臂：`cmd_calibrate` 须含 `--edit-log` 分支且委托**单一源** `gk_budget_ledger.py`。"""
    seg = _calibrate_src()
    assert "--edit-log" in seg, "cmd_calibrate 未解析 --edit-log"
    assert "gk_budget_ledger.py" in seg, "未委托读面单源 gk_budget_ledger.py"


def test_calibrate_default_route_center_preserved(tmp_path):
    """非红回归守卫：无 `--edit-log` 时 route-center 五层校准通路**须仍在**（防顺手删）。"""
    assert "gk_route_center.py" in _calibrate_src(), "route-center calibrate 通路被误删"

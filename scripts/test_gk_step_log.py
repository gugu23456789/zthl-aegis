"""步数 telemetry 载体（`<state>.step-log.jsonl`）红先臂 —— 2026-10-23。

为什么需要（owner：「限制整体动刀额度而不管步数……业界管步数应该是经过长期探索的产物」）：
  现计费面只数「唯一改动文件」，`RunCommand` **完全免费** ⟹ 空转 200 次 bash 的额度代价为零。
  步数是业界主计量单位（Agents SDK 10 / LangGraph 25 / SWE-agent 250 / OpenHands 500），
  而本仓**无历史步数数据** ⟹ 先采集（`kind=step`）、由 `step_stats` 出分布，再谈阈值。

载体纪律（本套件锁死）：步事件走**独立**文件，**绝不**混入 edit-log ——
  ① T4′ 的 `EDIT_SPAM_WINDOW` 按**记录数**切窗口 ⟹ 步事件会稀释判罚；
  ② `EDIT_MAX_LINES` 轮转按行数 ⟹ 步事件会把 T6 尚需累积的编辑事件挤进 archive。

落刀前红：`gk_budget_ledger` 无 `append_step` / `read_steps` / `step_stats`（AttributeError）。
"""
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import gk_budget_ledger as B  # noqa: E402


def _mkstate(tmp_path):
    st = str(tmp_path / ".gkstate")
    Path(st).write_text(json.dumps({"gate_data": {"edit_budget": {"max": 24, "used": 0,
                                                                  "remaining": 24}}}),
                        encoding="utf-8")
    return st


def test_append_step_goes_to_own_carrier(tmp_path):
    """载体臂：step 落 `<state>.step-log.jsonl`，**不**落 edit-log、不碰 budget-log。"""
    st = _mkstate(tmp_path)
    r = B.append_step(st, session="s1", node="ECO-EDIT", cmd="echo hi")
    assert r["ok"] is True, r
    assert Path(st + B.STEP_SUFFIX).exists(), "step-log 未产生"
    for suffix in (B.EDIT_SUFFIX, B.SUFFIX):
        assert not Path(st + suffix).exists(), "步事件污染了 %s" % (suffix,)
    rec = B.read_steps(st)[0]
    assert rec["kind"] == B.KIND_STEP and rec["session"] == "s1", rec
    assert rec["node"] == "ECO-EDIT" and rec["cmd"] == "echo hi", rec
    assert rec.get("ts"), "缺 ts（分位/窗口分析需要时间序）"


def test_append_step_requires_state(tmp_path):
    assert B.append_step("", session="s")["ok"] is False


def test_read_steps_skips_bad_and_foreign_lines(tmp_path):
    """读侧容错：坏行 / 异 kind 跳过（纯 telemetry，不做 ED4 计数告警）。"""
    st = _mkstate(tmp_path)
    B.append_step(st, session="s", node="N", cmd="a")
    with open(st + B.STEP_SUFFIX, "a", encoding="utf-8") as f:
        f.write("{not json\n")
        f.write(json.dumps({"kind": "edit", "path": "/x"}) + "\n")
    assert [r["cmd"] for r in B.read_steps(st)] == ["a"]


def test_step_stats_distribution_and_warn(tmp_path, monkeypatch):
    """分布面：`p50/p90/max/over_warn` —— 供人工定阈值（本批只标注、不判罚）。"""
    st = _mkstate(tmp_path)
    for i in range(4):
        B.append_step(st, session="s", node="A", cmd="c%d" % i)
    for _ in range(2):
        B.append_step(st, session="s", node="B", cmd="c")
    monkeypatch.setattr(B, "STEP_WARN_PER_NODE", 3)
    s = B.step_stats(st)
    assert s["total"] == 6 and s["nodes"] == 2, s
    assert s["by_node"] == {"s/A": 4, "s/B": 2}, s
    assert s["max"] == 4 and s["p50"] == 2 and s["p90"] == 4, s
    assert s["warn_at"] == 3 and s["over_warn"] == {"s/A": 4}, s


def test_step_stats_empty_is_zero(tmp_path):
    s = B.step_stats(_mkstate(tmp_path))
    assert s["total"] == 0 and s["nodes"] == 0 and s["max"] == 0 and s["over_warn"] == {}, s


def test_steps_do_not_dilute_t4_window(tmp_path):
    """**结构性回归臂**：100 条 step 不得把 T4′ 的 50 条窗口挤空。

    若 step 与 edit 同载体，3 次同文件编辑会被后续 step 推出 `EDIT_SPAM_WINDOW` ⟹ T4′ 静默失效。
    """
    st = _mkstate(tmp_path)
    for _ in range(3):
        B.append_edit(st, session="s", node="N", path="/x/a.py")
    for i in range(100):
        B.append_step(st, session="s", node="N", cmd="bash %d" % i)
    assert B.edit_spam_flag(st, "/x/a.py", session="s", window=50, k=3)["flagged"] is True, (
        "步事件稀释了 T4′ 窗口（载体混用回归）：%r" % (B.edit_spam_flag(st, "/x/a.py",
                                                                      session="s"),))
    assert B.node_unverified_flag(st, "s", "N", k=3)["unverified"] == 3, "步事件混入 T6 分组"


def test_edit_log_stats_unaffected_by_steps(tmp_path):
    """读数面隔离：`edit_log_stats` 只数 edit/verify（`by_kind` 不得冒出 step）。"""
    st = _mkstate(tmp_path)
    B.append_edit(st, session="s", node="N", path="/x/a.py")
    B.append_verify(st, session="s", node="N", cmd="pytest")
    for _ in range(5):
        B.append_step(st, session="s", node="N", cmd="echo")
    s = B.edit_log_stats(st)
    assert s["edits"] == 1 and s["verifies"] == 1, s
    assert s["by_kind"] == {"edit": 1, "verify": 1}, s["by_kind"]
    assert s["lines"] == 2, "edit-log 行数被步事件污染：%r" % (s["lines"],)


def test_cli_step_append_and_stats(tmp_path):
    """CLI 面：`step-append` 写入、`step-stats` 读出（供人工标定）。"""
    import subprocess
    st = _mkstate(tmp_path)
    p = subprocess.run([sys.executable, str(SCRIPTS / "gk_budget_ledger.py"), "step-append",
                        "--state", st, "--session", "s", "--node", "N", "--cmd", "echo hi"],
                       capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    p = subprocess.run([sys.executable, str(SCRIPTS / "gk_budget_ledger.py"), "step-stats",
                        "--state", st], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["by_node"] == {"s/N": 1}, p.stdout

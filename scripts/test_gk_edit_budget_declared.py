#!/usr/bin/env python3
"""声明式批额度（P5 §3 T1″ / REV-3，2026-09-28）红先回归。

载体 = **C1 计划 META** `edit_budget_declared:`（owner 2026-09-28 裁定）；权威式子（§12.4）：

    max = max(declared, min(current_lr × EDIT_BUDGET_PER_LR, EDIT_BUDGET_HARD_CAP))

其中 `16` **只夹 `current_lr` 项**，`declared` 独立封顶 **24**（owner 同批裁定）。

本文件锁 REV-3 §12.10 反例表与 §4 判据：
  · J1（红先）  `declared=24` ⟹ 跨 `current_lr` 1..4 `remaining` 恒 24（现状 = `min(lr×4,16)` ≤ 16 ⟹ 必红）；
  · J2（零回归）缺省无 `declared` ⟹ `remaining == min(lr×4,16)` **逐字**同现状（**不作红先**）；
  · J8（红先）  新增 `used_total` 跨节点累计、单调不减（现状无该字段）；
  · 自举静态臂  `declared` 读取路径**不得**含 `gatekeeper-cli.sh`（§3 T1″ 自举要求）；
  · 幻影落刀点臂 7 个落刀点文件**实存**、`gk_plan_meta.py`（幻影）不存在；
  · 熵第三支臂  旁挂 `<state>.budget-log.jsonl` 的提额条数须入熵（现状零信号）；
  · audit 臂    `check_state_file` 须产出提额频次项；
  · kill switch `GK_EDIT_BUDGET_DECL=0` ⟹ `declared` 归零（关闭态逐字退回现状）；
  · 银行接线臂  `_StateLedger.allowed(fam, finding, declared)` 本金来源优先取 `declared`；
               `edit_gk` 经 env `GK_EDIT_BUDGET_DECLARED` 取 declared（承 owner 裁定 A）。

harness 复用：state 写入 / standing 推进取自 `test_gk_advance.py`（`_write_state` / `_standing_run`），
沙箱契约对齐 `test_gk_edit_budget_metering.py`。
"""
import inspect
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import gk_advance  # noqa: E402
import gk_gate_entropy as gk_entropy  # noqa: E402
import gk_audit_state as gk_audit  # noqa: E402
from test_gk_advance import _standing_run, _write_state  # noqa: E402
from test_gk_edit_budget_metering import _mk_sandbox, _wsl  # noqa: E402

_LANDING = ("gk_route_center.py", "gk_plan_lint.py", "gk_advance.py", "gk_agent_edit.py",
            "subagent_runner.py", "gk_gate_entropy.py", "gk_audit_state.py")
_SIDE_SUFFIX = ".budget-log.jsonl"


def _sandbox(tmp_path, lr=4, budget=None):
    """最小 standing 沙箱：`.gatekeeper.state`（+ 可选既有 edit_budget）。"""
    sb = (tmp_path / "sb").resolve()
    sb.mkdir(parents=True, exist_ok=True)
    gd = {"project_type": "standing",
          "scheduler": {"mode": "cosine", "max_lr": 4, "min_lr": 1,
                        "total_steps": 6, "current_step": 0, "current_lr": lr}}
    if budget:
        gd["edit_budget"] = budget
    sf = _write_state(sb / ".gatekeeper.state", "ECO-SCAN", gate_data=gd)
    return sb, sf


def _write_plan(sb, declared):
    p = sb / "plan.md"
    p.write_text(
        "<!-- META\nphases: ECO-SCAN\ntarget_repo: skill\nproject_type: standing\n"
        "worktree_needed: false\nedit_budget_declared: %s\n-->\n# p\n" % declared,
        encoding="utf-8", newline="\n")
    return p


def _bind_pointer(sb, plan_path, sf):
    (sb / ".gatekeeper.plan").write_text(json.dumps({
        "plan": str(plan_path), "state_file": str(sf),
        "updated": datetime.now(timezone.utc).isoformat()}), encoding="utf-8", newline="\n")


def _declared_fn():
    return getattr(gk_advance, "_resolve_declared_budget", None)


def _budget_of(sf):
    return json.load(open(sf, encoding="utf-8"))["gate_data"]["edit_budget"]


# ─── J1 声明式额度生效（红先）────────────────────────────────────────────

def test_j1_declared_dominates_across_lr(tmp_path, monkeypatch):
    """J1（红先）：`declared=24` ⟹ 跨 `current_lr` 1..4 `remaining` 恒 **24**。"""
    monkeypatch.setattr(gk_advance, "_resolve_declared_budget",
                        lambda sd, env: 24, raising=False)
    for lr in (1, 2, 3, 4):
        sb, sf = _sandbox(tmp_path / ("lr%d" % lr), lr=lr)
        r = _standing_run(sf, "ECO-SCAN", "ECO-READ")
        assert r.get("ok") is True, f"advance 未放行：{r}"
        eb = _budget_of(sf)
        assert eb["max"] == 24 and eb["remaining"] == 24, (
            f"declared 未主导 lr={lr} ⟹ 现状 = min(lr×PER_LR, HARD_CAP) ≤ 16：{eb}")


def test_j1_resolver_reads_plan_meta(tmp_path):
    """J1 解析端到端：`.gatekeeper.plan` → 计划 META `edit_budget_declared` 取值。"""
    sb, sf = _sandbox(tmp_path)
    _bind_pointer(sb, _write_plan(sb, 24), sf)
    fn = _declared_fn()
    assert callable(fn), "未落刀：gk_advance._resolve_declared_budget 不存在"
    assert fn(str(sb), {}) == 24, "declared 未从计划 META 读出"


def test_declared_over_cap_is_clamped(tmp_path):
    """守护臂（2026-10-07）：`declared` **越上界**（999）⟹ 经 `gk_route_center.declared_from_meta`
    钳到 `DECLARED_HARD_CAP=24`，**不得穿透**到 `max`。

    动机：coder 报告曾据 `gk_advance._resolve_declared_budget` 本文件判定「`declared` 旁路无上界
    （999 ⟹ max=999）」，**误报** —— 钳位在被调方 `gk_route_center::declared_from_meta` 末行
    `return min(v, DECLARED_HARD_CAP)`。本臂钉死「declared 有界」防回退。
    现状即满足 ⟹ **绿臂（非红先）**；`J1` 只覆盖 `declared=24`（正好等于上界，不含越界）。
    """
    sb, sf = _sandbox(tmp_path)
    _bind_pointer(sb, _write_plan(sb, 999), sf)
    fn = _declared_fn()
    assert callable(fn), "未落刀：gk_advance._resolve_declared_budget 不存在"
    assert fn(str(sb), {}) == 24, "declared 越上界未被钳到 DECLARED_HARD_CAP=24"
    r = _standing_run(sf, "ECO-SCAN", "ECO-READ")
    assert r.get("ok") is True, f"advance 未放行：{r}"
    eb = _budget_of(sf)
    assert eb["max"] == 24 and eb["remaining"] == 24, f"declared=999 穿透外生上限：{eb}"


# ─── J2 零回归（不作红先）──────────────────────────────────────────────

def test_j2_zero_regression_without_declared(tmp_path):
    """J2：缺省无 `declared` ⟹ `remaining == min(current_lr × PER_LR, HARD_CAP)`。"""
    sb, sf = _sandbox(tmp_path, lr=4)
    fn = _declared_fn()
    assert (fn(str(sb), {}) if callable(fn) else 0) == 0, "无计划却读出非零 declared"
    r = _standing_run(sf, "ECO-SCAN", "ECO-READ")
    assert r.get("ok") is True, f"advance 未放行：{r}"
    want = min(4 * gk_advance.EDIT_BUDGET_PER_LR, gk_advance.EDIT_BUDGET_HARD_CAP)
    eb = _budget_of(sf)
    assert eb["max"] == want and eb["remaining"] == want, f"零回归被破坏：{eb}"


def test_kill_switch_zeroes_declared(tmp_path):
    """kill switch：`GK_EDIT_BUDGET_DECL=0` ⟹ 载有 declared 也归零（回退忠实）。"""
    sb, sf = _sandbox(tmp_path)
    _bind_pointer(sb, _write_plan(sb, 24), sf)
    fn = _declared_fn()
    assert callable(fn), "未落刀：gk_advance._resolve_declared_budget 不存在"
    assert fn(str(sb), {}) == 24, "前置：开关缺省应读 24"
    assert fn(str(sb), {"GK_EDIT_BUDGET_DECL": "0"}) == 0, "kill switch 未生效"


# ─── J8 双计数器（红先）────────────────────────────────────────────────

def test_j8_used_total_accumulates_and_is_monotonic(tmp_path):
    """J8：`used_total` 跨节点累计 = 前值 + 本节点已用；单调不减（现状无该字段）。"""
    sb, sf = _sandbox(tmp_path, budget={"max": 8, "used": 2, "remaining": 6,
                                        "used_total": 10})
    r = _standing_run(sf, "ECO-SCAN", "ECO-READ")
    assert r.get("ok") is True, f"advance 未放行：{r}"
    eb = _budget_of(sf)
    assert eb.get("used_total") == 12, f"used_total 未累计（现状字段缺失）：{eb}"


# ─── 自举 / 幻影 / 熵 / audit ──────────────────────────────────────────

def test_bootstrap_declared_read_path_excludes_cli():
    """自举（§3 T1″）：declared 读取路径**不得**经 `gatekeeper-cli.sh`（查函数体，去 docstring）。"""
    fn = _declared_fn()
    assert callable(fn), "未落刀：gk_advance._resolve_declared_budget 不存在"
    src = inspect.getsource(fn)
    body = src.split('"""', 2)[-1] if '"""' in src else src
    assert "gatekeeper-cli.sh" not in body, "declared 读取路径含 CLI ⟹ 自举失败"
    assert "subprocess" not in body and "bash" not in body, "declared 读取路径含子进程 ⟹ 自举失败"


def test_landing_files_exist_and_no_phantom():
    """幻影落刀点臂：7 个落刀点实存；`gk_plan_meta.py` 不得出现。"""
    for f in _LANDING:
        assert (SCRIPT_DIR / f).exists(), "落刀点文件不存在：%s" % f
    assert not (SCRIPT_DIR / "gk_plan_meta.py").exists(), "幻影文件混入落刀点表"


def test_entropy_third_branch_counts_raises(tmp_path):
    """熵第三支：旁挂账本提额条数须入熵（现状两支皆不看它 ⟹ 提额零信号）。"""
    sb, sf = _sandbox(tmp_path)
    Path(str(sf) + _SIDE_SUFFIX).write_text(
        "".join(json.dumps({"source": "state_patch"}) + "\n" for _ in range(3)),
        encoding="utf-8", newline="\n")
    import gk_budget_ledger as _BL
    _BL.seal_now(str(sf))     # 2026-10-31：有账本必须有封印（否则读侧 fail-loud）
    try:
        v = gk_entropy.compute_entropy_from_dict({"gate_data": {}}, "STAGE_1", str(sf))
    except TypeError:
        v = gk_entropy.compute_entropy_from_dict({"gate_data": {}}, "STAGE_1")
    assert v > 0.0, "提额条数未入熵（第三支缺失）"


def test_audit_reports_edit_budget_raises(tmp_path):
    """audit：`check_state_file` 须产出「提额频次」项（现状 19 项无此面）。"""
    sb, sf = _sandbox(tmp_path)
    Path(str(sf) + _SIDE_SUFFIX).write_text(
        json.dumps({"source": "state_patch"}) + "\n", encoding="utf-8", newline="\n")
    out = gk_audit.check_state_file(str(sf), str(sb))
    fields = [str(c.get("field", "")) for c in out.get("state_checks", [])]
    assert any("edit_budget" in f for f in fields), f"audit 缺提额频次项：{fields}"


# ─── 银行接线（owner 裁定 A：env 注入）─────────────────────────────────

def test_state_ledger_allowed_prefers_declared():
    """`_StateLedger.allowed` 本金来源优先取 `declared`，缺省退回族 `edit_quota`。"""
    from gk_agent_edit import _StateLedger
    fam = {"family": "F-x", "edit_quota": 3}
    try:
        got_hi = _StateLedger().allowed(fam, None, 9)
        got_lo = _StateLedger().allowed(fam, None, 0)
    except TypeError as e:
        raise AssertionError("未接线：allowed 无 declared 形参（%s）" % e)
    assert got_hi == 9, f"declared 未优先：{got_hi}"
    assert got_lo == 3, f"缺省未退回族 edit_quota：{got_lo}"


def test_edit_gk_reads_declared_env():
    """接线臂（静态）：`edit_gk` 须经 env `GK_EDIT_BUDGET_DECLARED` 取 declared。"""
    txt = (SCRIPT_DIR / "subagent_runner.py").read_text(encoding="utf-8")
    assert "GK_EDIT_BUDGET_DECLARED" in txt, "edit_gk 未接线 declared（env 注入缺失）"


def test_p8_declared_is_upper_bound():
    """P8 穿透臂（**红先**，2026-09-30）：`declared` 须为**上界** —— 传极大 `allowed` 实参不得穿透。

    第二轮 3×2 质询**全 6 臂收敛**：原 `allowed = max(调用方实参, 银行值)` ⟹ 实参可**自抬本金**。
    """
    import subagent_runner as sr
    fam = {"family": "F-x", "edit_quota": 3}
    got = sr._resolve_edit_allowed(10 ** 6, fam, 24)
    assert got == 24, f"**P8 穿透**：declared=24 被实参穿透，实际 allowed={got}"


def test_p8_legacy_semantics_when_declared_unset():
    """守卫（零回归）：`declared = 0`（未配置）⟹ 逐字退回既有语义（实参仍可抬）。"""
    import subagent_runner as sr
    fam = {"family": "F-x", "edit_quota": 3}
    got = sr._resolve_edit_allowed(10 ** 6, fam, 0)
    assert got == 10 ** 6, f"零回归失守：declared 未设时实参未按既有语义透传（allowed={got}）"


# ─── 写侧：旁挂提额账本（REV-3 §12.7，4 源）────────────────────────────────

def _ledger_lines(sf):
    p = Path(str(sf) + _SIDE_SUFFIX)
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def _state_patch(sb, fragment):
    w = _wsl(sb)
    return subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh state-patch %s' % (w, repr(fragment))],
        capture_output=True, text=True, timeout=120)


def test_ledger_written_on_state_patch(tmp_path):
    """写侧①：`state-patch` 触及 `edit_budget` ⟹ 旁挂账本追加一条 `source=state_patch`。"""
    sb = _mk_sandbox(tmp_path, {"max": 4, "used": 0, "remaining": 4})
    r = _state_patch(sb, '"edit_budget":{"max":9,"remaining":9}')
    assert '"ok": true' in (r.stdout + r.stderr) or '"ok":true' in (r.stdout + r.stderr), \
        f"state-patch 未成功：{(r.stdout + r.stderr)[:300]}"
    lines = _ledger_lines(sb / ".gatekeeper.state")
    assert lines, "提额旁挂账本**未写入**（熵第三支/audit 将恒读空账）"
    assert lines[-1].get("source") == "state_patch", f"source 口径错：{lines[-1]}"


def test_ledger_append_only_across_raises(tmp_path):
    """写侧②（不变量）：账本 **append-only** —— 两次提额 ⟹ 两行（无 FIFO 截断、不被覆盖）。"""
    sb = _mk_sandbox(tmp_path, {"max": 4, "used": 0, "remaining": 4})
    _state_patch(sb, '"edit_budget":{"max":9,"remaining":9}')
    _state_patch(sb, '"edit_budget":{"max":11,"remaining":11}')
    lines = _ledger_lines(sb / ".gatekeeper.state")
    assert len(lines) == 2, f"账本被截断/覆盖（应 2 行）：{lines}"


def test_ledger_not_written_on_plain_patch(tmp_path):
    """写侧负臂：`state-patch` 未触及 `edit_budget` ⟹ 不留痕（防「凡 patch 必记」噪声）。"""
    sb = _mk_sandbox(tmp_path, {"max": 4, "used": 0, "remaining": 4})
    _state_patch(sb, '"ci_status":"green"')
    assert not _ledger_lines(sb / ".gatekeeper.state"), "非额度 patch 被误记入账本"


def test_ledger_written_on_advance_env(tmp_path, monkeypatch):
    """写侧③：`GATEKEEPER_EDIT_BUDGET` 注入提额 ⟹ 账本追加一条 `source=advance_env`。"""
    monkeypatch.setenv("GATEKEEPER_EDIT_BUDGET", "6")
    sb, sf = _sandbox(tmp_path, budget={"max": 4, "used": 0, "remaining": 4})
    r = _standing_run(sf, "ECO-SCAN", "ECO-READ")
    assert r.get("ok") is True, f"advance 未放行：{r}"
    lines = _ledger_lines(sf)
    assert lines and lines[-1].get("source") == "advance_env", f"注入侧提额未入账：{lines}"

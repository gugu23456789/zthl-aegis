#!/usr/bin/env python3
"""红先臂：G4-d **按通道计价**（治「内容嗅探免密」，REV-5 §13.2）。

计划：`docs/plans/2026-09-18-edit-budget-dual-track-plan.md` §13.1（实测）/ §13.2（G4-d）/ §13.6（判据）。

缺陷（2026-09-30 实测，§13.1 第 2 行）：计费 gating 的豁免判据是**内容嗅探**
    `state-patch) case "$*" in *edit_budget*) : ;; *)
⟹ fragment = `{"note":"edit_budget"}`（对额度**毫无作用**）也能**免计费**，且**顺带多写一条**提额留痕
⟹ 免密提款 + 噪声留痕（双重失灵）。
同时 `finding`（**记账/治理动作**）落在 `state_write` 计费面 ⟹ **每次调用扣额度**（用户裁定：不该扣）。

**⚠ 2026-09-30 G4-e（REV-5 §13.3）**：留痕的**观察面**由 `edit_budget.overrides[]`（已降**只读遗留**、
本仓不再写）改为**旁挂 append-only 账本** `<state>.budget-log.jsonl` ⟹ arm3/arm4 的判据面随之换（判据不变：
文本巧合**不**留痕 / 真改额度**必**留痕）。

修法（本臂钉住）：
  · 计费豁免**按通道**（命令白名单 `_BILL_EXEMPT_CMDS`），**不按内容**；
  · 「是否留痕」是**另一个**判据（fragment 的**解析后键**是否真的触及 `edit_budget`），不得用子串巧合触发。

HEAD 上 `_BILL_EXEMPT_CMDS` 不存在、豁免仍是子串嗅探 ⟹ arm1/arm3/arm5 **红**；
arm2/arm4 是**负臂/守卫**，落刀前后都必须**绿**（防「删嗅探顺手把真计费/真留痕也删了」）。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

SD = Path(__file__).resolve().parent.parent
# red-first 对照臂（同 `test_gk_edit_budget_metering.py` 的既有约定）：指向**旧版 CLI** 即可复现红。
CLI = Path(os.environ.get("GK_CLI_UNDER_TEST") or (SD / "gatekeeper-cli.sh"))
BUDGET_LOG_SUFFIX = ".budget-log.jsonl"


def _mk_state(tmp: Path, remaining: int = 3, used: int = 0) -> Path:
    """**合成** state（不用真 state：worktree 内无 `.gatekeeper.state`；`_read_state` 接受缺 checksum）。"""
    st = tmp / ".gatekeeper.state"
    d = {"stage": "ECO-EDIT", "r_phase": "R1",
         "gate_data": {"edit_budget": {"max": remaining, "used": used,
                                       "remaining": remaining, "overrides": []}}}
    st.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8", newline="\n")
    return st


def _run(st: Path, *args, extra_env: dict = None):
    env = {**os.environ, "STATE_FILE": str(st)}
    env.update(extra_env or {})
    return subprocess.run(["bash", str(CLI), *args],
                          env=env,
                          capture_output=True, text=True, timeout=180)


def _eb(st: Path) -> dict:
    d = json.loads(st.read_text(encoding="utf-8"))
    return (d.get("gate_data") or {}).get("edit_budget") or {}


def _ledger_n(st: Path) -> int:
    """旁挂 append-only 账本行数（2026-09-30 G4-e：提额留痕的判据面，`overrides[]` 已降只读遗留）。"""
    p = Path(str(st) + BUDGET_LOG_SUFFIX)
    if not p.exists():
        return 0
    return len([ln for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()])


# ── arm1（正臂，红先）：`finding` 是记账动作 ⟹ 不得扣额度 ──────────────────────
def test_arm1_finding_is_not_billed(tmp_path):
    st = _mk_state(tmp_path, remaining=3, used=0)
    p = _run(st, "finding", "register", "G4-d 红先臂：finding 不应计费",
             "--family", "META-STATE",
             "--root-key", "bill.channel.exempt",
             "--anchor", "gatekeeper-cli.sh::_bill_edit")
    eb_after = _eb(st)
    assert p.returncode == 0, f"finding register 应成功：rc={p.returncode} {p.stdout[:300]}"
    assert int(eb_after.get("used", -1)) == 0, \
        f"**finding 被计费**（used=0 → {eb_after.get('used')}）—— 记账动作不应扣额度（G4-d）"
    assert int(eb_after.get("remaining", -1)) == 3, \
        f"remaining 被扣（3 → {eb_after.get('remaining')}）"


# ── arm2（负臂，必须保持绿）：工程动作仍须计费 ───────────────────────────────
def test_arm2_engineering_command_is_still_billed(tmp_path):
    st = _mk_state(tmp_path, remaining=3, used=0)
    wt = tmp_path / "wt"; wt.mkdir()
    p = _run(st, "apply-worktree", "--bind", "--path", str(wt))
    assert p.returncode == 0, f"apply-worktree --bind 应成功：{p.stdout[:300]}"
    assert int(_eb(st).get("used", 0)) == 1, \
        "**负臂失效**：工程动作（apply-worktree）竟未被计费 ⟹ 豁免名单过宽 = 无限额度"


# ── arm3（红先）：文本巧合**不得**触发留痕 ───────────────────────────────────
def test_arm3_textual_coincidence_does_not_log(tmp_path):
    st = _mk_state(tmp_path, remaining=3, used=0)
    before = _ledger_n(st)
    _run(st, "state-patch", json.dumps({"note": "edit_budget"}))
    after = _ledger_n(st)
    assert after == before, \
        f"**子串巧合触发留痕**（账本 {before} → {after}）：`{{\"note\":\"edit_budget\"}}` " \
        "对额度无任何作用，却写了一条提额留痕 ⟹ 仍是内容嗅探（G4-d）"


# ── arm4（守卫，必须保持绿）：**真**改额度仍须留痕 ───────────────────────────
def test_arm4_real_budget_change_is_still_logged(tmp_path):
    st = _mk_state(tmp_path, remaining=3, used=0)
    before = _ledger_n(st)
    _run(st, "state-patch", json.dumps({"edit_budget": {"max": 9, "used": 0, "remaining": 9}}))
    after = _ledger_n(st)
    assert after > before, \
        f"**守卫失效**：真改额度（fragment 顶层键含 `edit_budget`）竟未留痕（{before} → {after}）"


# ── arm5（静态，红先）：按通道的豁免名单存在且覆盖治理动作 ────────────────────
def test_arm5_channel_allowlist_exists():
    src = CLI.read_text(encoding="utf-8")
    marker = '_BILL_EXEMPT_CMDS="'
    assert marker in src, "缺 `_BILL_EXEMPT_CMDS` **赋值**（按通道计价的白名单，G4-d）"
    i = src.index(marker)          # 从**赋值处**取窗口（防命中注释里的首次提及）
    block = src[i:i + 200]
    for cmd in ("finding", "state-patch", "self-check", "audit", "plan-lint", "doc-align"):
        assert cmd in block, f"豁免名单未含治理通道 `{cmd}`"
    for eng in ("commit", "push", "apply-worktree", "advance"):
        assert eng not in block, \
            f"工程通道 `{eng}` **不得**进入豁免名单（否则 = 无限额度）"


# ── arm6（红先）：`plan-refinement --check-only` 零副作用 ⟹ 不计费（F-PROC-2 形态级豁免）──
# 计划 §16.3（owner 2026-09-30 授权）：形态级豁免扩至 `--check-only`（只跑 preflight，纯只读）。
def test_arm6_plan_refinement_check_only_not_billed(tmp_path):
    st = _mk_state(tmp_path, remaining=3, used=0)
    plan = SD / "docs/plans/2026-09-18-edit-budget-dual-track-plan.md"
    _run(st, "plan-refinement", str(plan), "--check-only")
    assert int(_eb(st).get("used", -1)) == 0, \
        f"**假计费**：`plan-refinement --check-only`（纯只读 preflight）被计费（used={_eb(st).get('used')}）"


# ── arm7（红先）：`plan-refinement --list-pending` 零副作用 ⟹ 不计费 ──────────
def test_arm7_plan_refinement_list_pending_not_billed(tmp_path):
    st = _mk_state(tmp_path, remaining=3, used=0)
    plan = SD / "docs/plans/2026-09-18-edit-budget-dual-track-plan.md"
    _run(st, "plan-refinement", str(plan), "--list-pending")
    assert int(_eb(st).get("used", -1)) == 0, \
        f"**假计费**：`plan-refinement --list-pending`（纯只读队列视图）被计费（used={_eb(st).get('used')}）"


# ── arm8（守卫，必须保持绿）：`--task` 真写 task_pipeline ⟹ 仍计费 ────────────
def test_arm8_plan_refinement_task_still_billed(tmp_path):
    st = _mk_state(tmp_path, remaining=3, used=0)
    plan = SD / "docs/plans/2026-09-18-edit-budget-dual-track-plan.md"
    _run(st, "plan-refinement", str(plan), "--task", "额度 阈值 早警 反例", "--tier", "3")
    assert int(_eb(st).get("used", 0)) >= 1, \
        "**守卫失效**：`--task`（真写 `task_pipeline`）竟未计费 ⟹ 形态豁免过宽（P9）"


# ── arm9（守卫，必须保持绿）：`--adjudicate` 下发 ⟹ 仍计费 ──────────────────
def test_arm9_plan_refinement_adjudicate_still_billed(tmp_path):
    st = _mk_state(tmp_path, remaining=3, used=0)
    plan = SD / "docs/plans/2026-09-18-edit-budget-dual-track-plan.md"
    _run(st, "plan-refinement", str(plan), "--adjudicate", "pr-nope", "--decision", "drop")
    assert int(_eb(st).get("used", 0)) >= 1, \
        "**守卫失效**：`--adjudicate`（下发 subagent）竟未计费 ⟹ 形态豁免过宽（P9）"


# ── arm10（红先）：**扣了额度必须开票** —— `kind=charge` 交易凭证（2026-10-23）──
# 病象（读码 + 实测）：Gate 4 / `_bill_edit` 只改 `used`/`remaining`，**不留任何交易记录**
#   ⟹ 审计只能看到「余额变了」，看不到「谁、为什么、扣了几刀」；`budget-log` 里只有提额行，
#   「花掉多少」只能靠撞墙次数反推。修法 = 区外整次调用前后快照差额 → 一条 `kind=charge`。
def _ledger_rows(st: Path) -> list:
    p = Path(str(st) + BUDGET_LOG_SUFFIX)
    if not p.exists():
        return []
    return [json.loads(ln) for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]


def test_arm10_billed_command_emits_charge_voucher(tmp_path):
    st = _mk_state(tmp_path, remaining=3, used=0)
    wt = tmp_path / "wt"; wt.mkdir()
    before = len(_ledger_rows(st))
    p = _run(st, "apply-worktree", "--bind", "--path", str(wt))
    assert p.returncode == 0, f"apply-worktree --bind 应成功：{p.stdout[:300]}"
    rows = _ledger_rows(st)
    assert len(rows) == before + 1, \
        f"**扣了额度却没开票**（账本 {before} → {len(rows)} 行）：审计拿不到交易流"
    rec = rows[-1]
    assert rec.get("kind") == "charge", f"kind 口径错（会被计成提额）：{rec}"
    assert int(rec.get("cost", 0)) == 1, f"cost 与实扣不符：{rec}"
    assert "apply-worktree" in str(rec.get("reason", "")), f"凭证未记命令名：{rec}"
    assert "used=0->1" in str(rec.get("reason", "")), f"凭证未记前后余额：{rec}"


# ── arm10b（红先）：**新会话首刀也要开票** —— 会话域预演口径 ──────────────────
# 坑（实测）：会话条目是**首笔扣款时**才被 `setdefault` 创建的 ⟹ 若快照只看「条目在不在」，
#   b0 读全局、b1 读新会话域 = 跨域伪差值 ⟹ 每个会话的**第一刀永远无票**（且不报错）。
def test_arm10b_first_charge_of_new_session_still_emits_voucher(tmp_path):
    st = _mk_state(tmp_path, remaining=3, used=0)
    wt = tmp_path / "wt"; wt.mkdir()
    _run(st, "apply-worktree", "--bind", "--path", str(wt),
         extra_env={"GK_SESSION_ID": "sid-fresh"})
    assert "sessions" not in _eb(st) or "sid-fresh" in (_eb(st).get("sessions") or {}), \
        f"会话域未建立（前提失效）：{_eb(st)}"
    rows = _ledger_rows(st)
    assert rows and rows[-1].get("kind") == "charge", \
        f"**新会话首刀无票**（跨域伪差值被丢掉）：{rows}"
    rec = rows[-1]
    assert rec.get("scope") == "session" and rec.get("session") == "sid-fresh", \
        f"未标会话域（多会话不可分账）：{rec}"
    assert int(rec.get("session_max", -1)) == 3, f"缺本会话 `max`：{rec}"
    assert int(rec.get("session_used", -1)) == 1, f"缺本会话 `used`：{rec}"
    # 余额字段必须跟 `scope` 走：扣的是会话域，却报全局余额 = 自相矛盾（实测 global remaining=0）
    assert (rec.get("used"), rec.get("remaining")) == (1, 2), f"余额口径与 scope 不符：{rec}"


# ── arm11（负臂）：**不动额度的调用不得开票** ────────────────────────────────
def test_arm11_readonly_command_emits_no_charge(tmp_path):
    st = _mk_state(tmp_path, remaining=3, used=0)
    before = len(_ledger_rows(st))
    _run(st, "state")
    assert len(_ledger_rows(st)) == before, \
        f"**假开票**：只读命令 `state` 也写了 charge 行：{_ledger_rows(st)[before:]}"


# ── arm12（守卫）：`charge` **不得**被读成「提额」 ───────────────────────────
# `count_raises` 原判据是 `kind != degrade` ⟹ 新增 `charge` 后会把扣款读成提额，
# `audit` 的 `raises_today > RAISES_TODAY_MAX` 每天必红（假红）。
def test_arm12_charge_not_counted_as_raise(tmp_path):
    st = _mk_state(tmp_path, remaining=3, used=0)
    wt = tmp_path / "wt"; wt.mkdir()
    assert _run(st, "apply-worktree", "--bind", "--path", str(wt)).returncode == 0
    sys.path.insert(0, str(SD / "scripts"))
    import gk_budget_ledger as BL
    total, today = BL.count_raises(str(st))
    assert (total, today) == (0, 0), f"`charge` 被记成提额（total={total} today={today}）"
    _recs, stat = BL.read_records(str(st))
    assert stat.get("charges", 0) == 1, f"`charges` 计数缺失：{stat}"
    assert stat.get("raises", 0) == 0, f"`raises` 把 charge 计进去了：{stat}"

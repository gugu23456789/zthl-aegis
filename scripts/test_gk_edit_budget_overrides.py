#!/usr/bin/env python3
"""edit_budget 提额留痕回归（P5 §3 T5′ / 计划次序 S1-b，2026-09-19；**2026-09-30 G4-e 改判据面**）。

背景（读码 + 实测）：`edit_budget` 有三条**逃生舱**路径，能把额度抬过机制天花板
（`scheduler.max_lr=4`）或直接放行已耗尽节点，而三条**全是静默的**：

  ① 注入侧 `GATEKEEPER_EDIT_BUDGET`（`gk_advance.py` standing 注入分支）
  ② 消费侧 `GK_BUDGET_OVERRIDE=1`（`gatekeeper-cli.sh::pre_tool_check` edit 分支）
  ③ 人工   `state-patch '"edit_budget":{...}'`（`cmd_state_patch`）

实证：本会话 `state` 读到 `{max:8, used:1, remaining:5}` —— `max:8` **超出**
`max_lr=4` 的天花板 ⟹ 必由 ③ 抬出，而当时**零留痕**，只能靠撞墙次数反推。

**⚠ 2026-09-30 口径变更（REV-5 §13.3 / G4-e「分账收口」）**：留痕的**判据面**由
内嵌 `gate_data.edit_budget.overrides[]` 改为**旁挂 append-only 账本**
`<state>.budget-log.jsonl`。理由（实测）：`state-patch` 对 `gate_data` 顶层键是**整体替换**
⟹ 留痕寄居 `edit_budget` 会被**写一次砸一次**（实测 `overrides` 7→1）；旁挂账本只追加、
不受整体替换影响。`overrides[]` 由此**降级为只读遗留**（本仓不再写它）。
同批补规格漂移：旁挂记录补 `from_max` / `to_max`（「提额幅度」可复算）与 `expires_at`
（提额有效期，绑会话 TTL `GK_SESSION_TTL` 默认 1800s）。

本文件锁 P5 §4 **J7**（口径已升级）：三条路径各走一次 ⟹ 旁挂账本各留一条；外加两条本实现自带的语义：

  - **负臂**：`GK_BUDGET_OVERRIDE=1` 在 `remaining > 0` 时**不得**留痕 —— 该情形下 override
    只跳过扣减（计量缺口，另由 finding 追踪），并未改变**门禁结果**，按次刷屏会让账本被噪声挤满。
  - **只读遗留**：`overrides[]` 不再是写入面 —— 一次抬额后它**逐字不变**（既不增长、也不由本仓抹除）。

⚠ 范围声明（如实登记，不代为落刀）：`remaining == max - used`（P5 §4 **J8** 双计数器自洽）
**不在 T5′ 范围内** —— 属 T1″ 落刀，仍被 D1/D2/D3 阻塞。本文件**不断言 J8**，故
`{max:12, used:1, remaining:12}` 这类不自洽态在本门内是**合法**的。不假装 J8 已修。

⚠ `reason` 属**自报字段** ⟹ 仅作审计叙述，**不得作为任何门禁判据**
（P5 §5 纪律）。本文件只断言「留痕有无 + `source` 取值 + 关键字段」，不断言 `reason` 内容。

harness 复用：沙箱 / 预算读取取自 `test_gk_edit_budget_metering.py`（同子系统、同沙箱契约，
避免两份漂移）；advance 调用取自 `test_gk_advance.py`（既有 `_standing_run` 契约）。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from test_gk_advance import _standing_run, _write_state  # noqa: E402
from test_gk_edit_budget_metering import _budget, _mk_sandbox, _wsl  # noqa: E402

LEDGER_SUFFIX = ".budget-log.jsonl"


def _consume(sb: Path, override: bool):
    """走一次 `pre-tool-check edit <file>`；`override=True` 时带 `GK_BUDGET_OVERRIDE=1`。"""
    w = _wsl(sb)
    pre = "export GK_BUDGET_OVERRIDE=1; " if override else ""
    return subprocess.run(
        ["bash", "-lc",
         '%scd "%s" && bash gatekeeper-cli.sh pre-tool-check edit "%s/note.md"' % (pre, w, w)],
        capture_output=True, text=True, timeout=120)


def _state_patch(sb: Path, fragment: str):
    """走一次 `state-patch <fragment>`（③ 人工抬额度路径）。"""
    w = _wsl(sb)
    return subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh state-patch %s' % (w, repr(fragment))],
        capture_output=True, text=True, timeout=120)


def _ledger_of(state_path) -> list:
    """读旁挂账本（append-only）全部记录；缺文件 ⟹ `[]`。"""
    p = Path(str(state_path) + LEDGER_SUFFIX)
    if not p.exists():
        return []
    recs = []
    for ln in p.read_text(encoding="utf-8").splitlines():
        if ln.strip():
            recs.append(json.loads(ln))
    return recs


def _ledger(sb: Path) -> list:
    return _ledger_of(sb / ".gatekeeper.state")


def _overrides(sb: Path):
    return _budget(sb).get("overrides")


# ─── ③ 人工 state-patch ───

def test_state_patch_records_override(tmp_path):
    """判据 J7-③：`state-patch` 触及 `edit_budget` ⟹ 旁挂账本留一条 `state_patch`。

    G4-e：判据面 = 旁挂账本（不再断言 `overrides[]` 增长），且须含 `to_max`。
    """
    sb = _mk_sandbox(tmp_path, {"max": 4, "used": 0, "remaining": 4})
    r = _state_patch(sb, '"edit_budget":{"max":9,"remaining":9}')
    out = r.stdout + r.stderr
    assert '"ok": true' in out or '"ok":true' in out, f"state-patch 未成功：{out[:400]}"
    led = _ledger(sb)
    assert led, f"人工 state-patch 抬额度**无留痕**（本会话 max:8 即此路径）：{led}"
    assert led[-1].get("source") == "state_patch", f"source 口径错：{led[-1]}"
    assert led[-1].get("to_max") == 9, f"未记下抬升后的额度：{led[-1]}"
    assert "from_max" in led[-1], f"缺 `from_max`（提额幅度不可复算）：{led[-1]}"
    assert led[-1].get("expires_at"), f"缺 `expires_at`（无有效期）：{led[-1]}"


def test_state_patch_without_edit_budget_records_nothing(tmp_path):
    """负臂：`state-patch` 未触及 `edit_budget` ⟹ 不留痕（防「凡 patch 必记」的噪声口径）。"""
    sb = _mk_sandbox(tmp_path, {"max": 4, "used": 0, "remaining": 4})
    r = _state_patch(sb, '"ci_status":"green"')
    out = r.stdout + r.stderr
    assert '"ok": true' in out or '"ok":true' in out, f"state-patch 未成功：{out[:400]}"
    assert not _ledger(sb), f"非 edit_budget 的 patch 被误记：{_ledger(sb)}"


def test_ledger_from_to_max_chain_across_two_raises(tmp_path):
    """G4-e 新臂：连抬两次 ⟹ 第二条的 `from_max` == 第一条的 `to_max`（提额幅度可复算）。

    首条无前项 ⟹ `from_max` 为 `None`（显式登记「起点未知」，不得伪造成 0）。
    """
    sb = _mk_sandbox(tmp_path, {"max": 4, "used": 0, "remaining": 4})
    assert _state_patch(sb, '"edit_budget":{"max":6,"remaining":6}').returncode == 0
    assert _state_patch(sb, '"edit_budget":{"max":9,"remaining":9}').returncode == 0
    led = _ledger(sb)
    assert len(led) == 2, f"两次抬额应留两条：{led}"
    assert led[0].get("from_max") is None and led[0].get("to_max") == 6, f"首条口径错：{led[0]}"
    assert led[1].get("from_max") == 6 and led[1].get("to_max") == 9, (
        f"链式 from_max≠上一条 to_max ⟹ 幅度不可复算：{led[1]}")
    assert "budget-log" not in json.dumps((_budget(sb) or {}), ensure_ascii=False), (
        f"账本不得内嵌 `edit_budget` 对象（G4-e「不含账本」）：{_budget(sb)}")


# ─── ② 消费侧 GK_BUDGET_OVERRIDE ───

def test_budget_override_records_when_it_prevents_block(tmp_path):
    """判据 J7-②：`remaining=0` + `GK_BUDGET_OVERRIDE=1` 放行 ⟹ 旁挂留一条 `budget_override`。

    同时守**只读遗留**：本路径走 `_state_write`（非整体替换）⟹ 既有 `overrides[]` 须**逐字不变**。
    """
    prior = {"ts": "2026-09-19T00:00:00Z", "source": "legacy", "max": 4,
             "used": 0, "remaining": 4, "reason": "prior"}
    sb = _mk_sandbox(tmp_path, {"max": 4, "used": 4, "remaining": 0, "overrides": [prior]})
    r = _consume(sb, override=True)
    out = r.stdout + r.stderr
    assert "OK" in out, f"override 未放行：{out[:400]}"
    led = _ledger(sb)
    assert led, f"override 放行已耗尽节点**无留痕**：{led}"
    assert led[-1].get("source") == "budget_override", f"source 口径错：{led[-1]}"
    assert led[-1].get("remaining") == 0, f"事件现场未记下：{led[-1]}"
    assert _overrides(sb) == [prior], (
        f"`overrides[]` 已降只读遗留，不得再被写入：{_overrides(sb)}")


def test_budget_override_not_recorded_when_budget_remains(tmp_path):
    """负臂：`remaining>0` + `GK_BUDGET_OVERRIDE=1` ⟹ **不**留痕（未改变门禁结果）。"""
    sb = _mk_sandbox(tmp_path, {"max": 4, "used": 0, "remaining": 4})
    r = _consume(sb, override=True)
    out = r.stdout + r.stderr
    assert "OK" in out, f"override 未放行：{out[:400]}"
    assert not _ledger(sb), f"未耗尽也留痕（会挤满账本）：{_ledger(sb)}"


# ─── ① 注入侧 GATEKEEPER_EDIT_BUDGET + 跨节点台账不变量 ───

def _advance_state(tmp_path, prior, seed_ledger=None):
    gd = {
        "project_type": "standing",
        "edit_budget": {"max": 4, "used": 0, "remaining": 4, "overrides": [prior]},
        "scheduler": {"mode": "cosine", "max_lr": 4, "min_lr": 1,
                      "total_steps": 6, "current_step": 0, "current_lr": 4},
    }
    sf = _write_state(tmp_path / "s.json", "ECO-SCAN", gate_data=gd)
    if seed_ledger is not None:
        (tmp_path / "s.json.budget-log.jsonl").write_text(
            json.dumps(seed_ledger, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
        import gk_budget_ledger as _BL
        _BL.seal_now(str(sf))     # 2026-10-31：有账本必须有封印（否则读侧 fail-loud）
    return sf


def test_advance_env_records_override_and_preserves_ledger(tmp_path, monkeypatch):
    """判据 J7-① + 不变量：advance 注入记一条 `advance_env`，且**不得抹掉**既有 `overrides[]` 遗留。

    本臂账本为空 ⟹ 首条无前项，`from_max` 须为 `None`（链式口径，不得伪造成 0）。
    """
    monkeypatch.setenv("GATEKEEPER_EDIT_BUDGET", "6")
    prior = {"ts": "2026-09-19T00:00:00Z", "source": "state_patch",
             "max": 4, "used": 0, "remaining": 4, "reason": "prior"}
    sf = _advance_state(tmp_path, prior)
    r = _standing_run(sf, "ECO-SCAN", "ECO-READ")
    assert r.get("ok") is True, f"advance 未放行：{r}"
    eb = json.load(open(sf, encoding="utf-8"))["gate_data"]["edit_budget"]
    assert eb["max"] == 6 and eb["remaining"] == 6, f"注入侧覆盖未生效：{eb}"
    assert eb.get("overrides") == [prior], f"advance 重置把跨节点台账抹掉了（且已降只读）：{eb}"
    led = _ledger_of(sf)
    assert len(led) == 1, f"注入侧覆盖应留一条：{led}"
    assert led[-1].get("source") == "advance_env", f"注入侧覆盖无留痕：{led}"
    assert led[-1].get("to_max") == 6, f"未记下覆盖额度：{led[-1]}"
    assert led[-1].get("from_max") is None, f"首条无前项 ⟹ from_max 须为 None：{led[-1]}"
    assert led[-1].get("expires_at"), f"缺 `expires_at`（无有效期）：{led[-1]}"


def test_advance_env_ledger_chains_from_prior_record(tmp_path, monkeypatch):
    """G4-e 新臂（py 产出器）：账本已有前项 ⟹ advance 侧 `from_max` == 上一条 `to_max`。"""
    monkeypatch.setenv("GATEKEEPER_EDIT_BUDGET", "6")
    prior = {"ts": "2026-09-19T00:00:00Z", "source": "state_patch",
             "max": 4, "used": 0, "remaining": 4, "reason": "prior"}
    sf = _advance_state(tmp_path, prior, seed_ledger={
        "ts": "2026-09-19T00:00:01Z", "source": "seed", "from_max": None,
        "to_max": 4, "max": 4, "used": 0, "remaining": 4, "reason": "seed"})
    r = _standing_run(sf, "ECO-SCAN", "ECO-READ")
    assert r.get("ok") is True, f"advance 未放行：{r}"
    led = _ledger_of(sf)
    assert len(led) == 2, f"应在前项之后追加一条：{led}"
    assert led[-1].get("to_max") == 6, f"未记下覆盖额度：{led[-1]}"
    assert led[-1].get("from_max") == 4, (
        f"链式 from_max≠上一条 to_max ⟹ 幅度不可复算：{led[-1]}")


def test_advance_without_env_records_nothing(tmp_path, monkeypatch):
    """负臂：未设 `GATEKEEPER_EDIT_BUDGET` ⟹ 非覆盖事件，不留痕（但仍须保住既有台账）。"""
    monkeypatch.delenv("GATEKEEPER_EDIT_BUDGET", raising=False)
    prior = {"ts": "2026-09-19T00:00:00Z", "source": "state_patch",
             "max": 4, "used": 0, "remaining": 4, "reason": "prior"}
    sf = _advance_state(tmp_path, prior)
    r = _standing_run(sf, "ECO-SCAN", "ECO-READ")
    assert r.get("ok") is True, f"advance 未放行：{r}"
    eb = json.load(open(sf, encoding="utf-8"))["gate_data"]["edit_budget"]
    assert eb.get("overrides") == [prior], f"未设 env 却动/丢了台账：{eb}"
    assert not _ledger_of(sf), f"未设 env 却留痕：{_ledger_of(sf)}"


# ─── §17.2 外生安全上限（owner 裁定 2026-10-07：①②③夹取 + ④豁免留痕）───
# 红先臂：env 逃生舱（advance_env，路①）不得突破外生上限 CEILING。
# HEAD 现状 = env「逐字采用、无上界」⟹ 本臂 RED；落刀后应绿（ECC-E87222420E1F / ECC-C8BD812FE19E）。

def test_edit_budget_env_override_is_clamped_by_ceiling(tmp_path, monkeypatch):
    """§17.2 路①：`GATEKEEPER_EDIT_BUDGET` 注入超上限 ⟹ `max` 须被 CEILING 夹取（不得逐字采用）。"""
    monkeypatch.setenv("GATEKEEPER_EDIT_BUDGET", "999")
    prior = {"ts": "2026-09-19T00:00:00Z", "source": "state_patch",
             "max": 4, "used": 0, "remaining": 4, "reason": "prior"}
    sf = _advance_state(tmp_path, prior)
    r = _standing_run(sf, "ECO-SCAN", "ECO-READ")
    assert r.get("ok") is True, f"advance 未放行：{r}"
    eb = json.load(open(sf, encoding="utf-8"))["gate_data"]["edit_budget"]
    # 上界**取自常量**（2026-10-23 CEILING 24→32：原字面量 24 使本臂随常量漂移而假红）
    from gk_advance import EDIT_BUDGET_CEILING as _CEIL
    assert eb["max"] <= _CEIL, (
        "env 覆盖未被外生上限夹取（CEILING=%s）：%r" % (_CEIL, eb))

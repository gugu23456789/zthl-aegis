#!/usr/bin/env python3
"""③ state 解析链**三维回归**（设计 §8 交付物，`ECC-1EC0E0732F0D`）。

三维 = `STATE_FILE ∈ {∅, base, 域化, 显式异路径}` × `domain ∈ {∅, 声明域}` ×
`worktree ∈ {无, 匹配, 不匹配}`。被测 = `gk_state_route.resolve_state`（**唯一实现体**）+
`gk_route_center.resolve_state`（门面：`select_plan_pointer` 定论**权威**、禁回落全局指针）。

**期望值独立性**：每条期望按契约（`resolve_state` docstring 的优先级 1 → 1b → 2 → 3）
**推导**，不跑实现反填 —— 否则本文件退化为「实现即真理」的自证（假绿）。

与 ③ 前基线的关系：③ 只**新增** `select_plan_pointer` 并让门面消费它；`gk_state_route.resolve_state`
既有分支语义与 `pointer_authoritative` 默认 False 下的行为**逐字不变** ⟹ 本矩阵即行为回归基线。
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gk_route_center as grc  # noqa: E402
import gk_state_route as gsr  # noqa: E402

# 本仓「开发 worktree 树」根下的合法归属路径（`_owned_by_skill` 段级字符串匹配，无需实存）。
DEV_WT = "<home>/.trae/worktrees/feature/spz-gatekeeper-r7.1"
OTHER = "/tmp/other-project"          # 非本仓目录（既不等于 sd，也不在 dev worktree 树）


def _state(p: Path, worktree: str = "") -> Path:
    """写最小 state（`r_phase` 固定 R1；`worktree` 决定归属维）。"""
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"r_phase": "R1", "stage": "STAGE_0", "worktree": worktree,
                             "gate_data": {}}), encoding="utf-8", newline="\n")
    return p


def _ptr(p: Path, state_file, plan: str = "p", domain: str = "") -> Path:
    """写 fresh（默认 TTL 内）plan 指针；`domain` 非空 ⟹ 域化绑定标记。"""
    d = {"state_file": str(state_file), "plan": plan, "writer": "discover",
         "updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    if domain:
        d["domain"] = domain
    p.write_text(json.dumps(d), encoding="utf-8", newline="\n")
    return p


def _state_no_wt(p: Path) -> Path:
    """写最小 state，**不含** `worktree` 字段 ⟹ `_load_worktree` 回 None = 真「无归属声明」。"""
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"r_phase": "R1", "stage": "STAGE_0", "gate_data": {}}),
                 encoding="utf-8", newline="\n")
    return p


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """隔离进程 env：`STATE_FILE` / `PLAN_POINTER` 的 env 通道会短路维度输入。"""
    for k in ("STATE_FILE", "PLAN_POINTER", "GK_SESSION_ID", "GK_STATE_DOMAIN_ROUTE",
              "GK_CMD_TARGET_PLAN", "GK_PLAN_POINTER_STRICT", "STATE_FILE_EXPLICIT"):
        monkeypatch.delenv(k, raising=False)


# ── 维：worktree（无指针、base state）───────────────────────────────────────────

def test_wt_owned_no_pointer_is_current(tmp_path):
    """worktree=sd（本仓）⟹ 无冲突 ⟹ source=current、expected=base。"""
    sd = tmp_path / "skill"
    base = _state(sd / ".gatekeeper.state", worktree=str(sd))
    r = gsr.resolve_state(str(sd), state_file=str(base))
    assert (r["source"], r["expected"], r["conflict"]) == ("current", str(base), False), r


def test_wt_absent_field_is_current(tmp_path):
    """`worktree` 字段**缺席**（None）⟹ conflict=False ⟹ source=current、expected=base。"""
    sd = tmp_path / "skill"
    base = _state_no_wt(sd / ".gatekeeper.state")
    r = gsr.resolve_state(str(sd), state_file=str(base))
    assert (r["source"], r["expected"]) == ("current", str(base)), r


def test_wt_empty_string_is_conflict_safety_net(tmp_path):
    """`worktree: ""`（字段在但为空串）⟹ `_owned_by_skill("")` False ⟹ **归属冲突**（锁既有语义）。

    空串**不等于**「无归属声明」（后者是字段缺席 → None）；③ 未改此语义，故本臂锁定之：
    防把跨仓占位写下的空 worktree 当本仓，且无候选 ⟹ safety_net **不纠正**。
    """
    sd = tmp_path / "skill"
    base = _state(sd / ".gatekeeper.state", worktree="")
    r = gsr.resolve_state(str(sd), state_file=str(base))
    assert (r["source"], r["conflict"], r["corrected"]) == ("safety_net", True, False), r
    assert r["expected"] == str(base), r


def test_wt_foreign_no_candidate_is_safety_net(tmp_path):
    """worktree 非本仓 + 无隔离候选 ⟹ safety_net、不纠正（防误纠）。"""
    sd = tmp_path / "skill"
    base = _state(sd / ".gatekeeper.state", worktree=OTHER)
    r = gsr.resolve_state(str(sd), state_file=str(base))
    assert r["source"] == "safety_net" and r["conflict"] is True, r
    assert r["corrected"] is False and r["expected"] == str(base), r


def test_wt_foreign_single_candidate_corrects(tmp_path):
    """worktree 非本仓 + **恰好 1** 个本仓隔离候选 ⟹ safety_net 纠正到候选。"""
    sd = tmp_path / "skill"
    base = _state(sd / ".gatekeeper.state", worktree=OTHER)
    cand = _state(sd / ".gatekeeper.state.c1", worktree=str(sd))
    r = gsr.resolve_state(str(sd), state_file=str(base))
    assert r["source"] == "safety_net" and r["corrected"] is True, r
    assert r["expected"] == str(cand), r


def test_wt_development_worktree_match_routes(tmp_path):
    """worktree=本仓 dev worktree + 唯一同 worktree 隔离 state ⟹ worktree_match 路由。"""
    sd = tmp_path / "skill"
    base = _state(sd / ".gatekeeper.state", worktree=DEV_WT)
    cand = _state(sd / ".gatekeeper.state.wt1", worktree=DEV_WT)   # 后写 ⟹ 不因更旧被拒
    r = gsr.resolve_state(str(sd), state_file=str(base))
    assert r["source"] == "worktree_match" and r["expected"] == str(cand), r


# ── 维：plan 指针（fresh，覆盖 state/worktree 维）──────────────────────────────

def test_pointer_fresh_wins_over_worktree(tmp_path):
    """fresh 指针指向实存 state ⟹ **优先于**归属/域/worktree（契约步 1）。"""
    sd = tmp_path / "skill"
    base = _state(sd / ".gatekeeper.state", worktree=OTHER)        # 故意冲突
    tgt = _state(sd / ".gatekeeper.state.t1", worktree=OTHER)
    _ptr(sd / ".gatekeeper.plan", tgt)
    r = gsr.resolve_state(str(sd), state_file=str(base))
    assert r["source"] == "plan_pointer" and r["expected"] == str(tgt), r


# ── 维：domain（1b；ROUTE 开关）───────────────────────────────────────────────

def test_domain_declared_routes_to_domain_state(tmp_path, monkeypatch):
    """声明域 + ROUTE≠0 + 域 state 实存 ⟹ source=state_domain（契约步 1b）。"""
    monkeypatch.setenv("GK_STATE_DOMAIN_ROUTE", "1")
    sd = tmp_path / "skill"
    base = _state(sd / ".gatekeeper.state", worktree=str(sd))
    dom = _state(sd / ".gatekeeper.state.gp.r1", worktree=str(sd))
    r = gsr.resolve_state(str(sd), state_file=str(base), domain="gp.r1")
    assert r["source"] == "state_domain" and r["expected"] == str(dom), r


def test_domain_route_off_skips_step_1b(tmp_path, monkeypatch):
    """`GK_STATE_DOMAIN_ROUTE=0` ⟹ 跳过 1b，回落既有链（worktree=sd ⟹ current=base）。"""
    monkeypatch.setenv("GK_STATE_DOMAIN_ROUTE", "0")
    sd = tmp_path / "skill"
    base = _state(sd / ".gatekeeper.state", worktree=str(sd))
    _state(sd / ".gatekeeper.state.gp.r1", worktree=str(sd))
    r = gsr.resolve_state(str(sd), state_file=str(base), domain="gp.r1")
    assert r["source"] == "current" and r["expected"] == str(base), r


def test_domain_declared_but_state_missing_fails_closed(tmp_path, monkeypatch):
    """声明域但域 state 缺失 ⟹ fail-closed（`STATE_DOMAIN_MISSING`，不静默回退）。"""
    monkeypatch.setenv("GK_STATE_DOMAIN_ROUTE", "1")
    sd = tmp_path / "skill"
    base = _state(sd / ".gatekeeper.state", worktree=str(sd))
    r = gsr.resolve_state(str(sd), state_file=str(base), domain="gp.r1")
    assert r["source"] == "state_domain" and r["error"] == "STATE_DOMAIN_MISSING", r
    assert r["expected"] == "", r


# ── 维：STATE_FILE（显式异路径）───────────────────────────────────────────────

def test_explicit_state_file_outside_skill_root_is_current(tmp_path):
    """显式 STATE_FILE 落在技能根外、worktree=sd ⟹ 无冲突 ⟹ expected=该显式路径。"""
    sd = tmp_path / "skill"
    sd.mkdir()
    ext = _state(tmp_path / "other" / ".gatekeeper.state", worktree=str(sd))
    r = gsr.resolve_state(str(sd), state_file=str(ext))
    assert (r["source"], r["expected"]) == ("current", str(ext)), r


# ── 门面（`gk_route_center.resolve_state`）：指针**定论权威**，禁回落全局 ─────────

def test_facade_session_without_own_binding_does_not_adopt_global(tmp_path, monkeypatch):
    """有会话身份但本会话无自身指针 ⟹ **不采纳**全局指针（回落默认 base）。

    ③ 判据：门面把 `select_plan_pointer` 的「不跟随」定论传给 `resolve_state` 且
    `pointer_authoritative=True` ⟹ `gk_state_route` 步 1 **不得**再回落全局 `.gatekeeper.plan`。
    """
    monkeypatch.setenv("GK_SESSION_ID", "0123456789abcdef01234567")
    sd = tmp_path / "skill"
    base = _state(sd / ".gatekeeper.state", worktree=str(sd))
    g = _state(sd / ".gatekeeper.state.g", worktree=str(sd))
    _ptr(sd / ".gatekeeper.plan", g)          # 全局指针存在（会被误采纳 ⟹ 跨会话劫持）
    r = grc.resolve_state(str(sd), state_file=str(base))
    assert r["source"] == "current" and r["expected"] == str(base), r
    assert r["pointer_followed"] is False, r


def test_facade_no_session_follows_global_pointer(tmp_path):
    """**无**会话身份 ⟹ 仍跟全局指针（零回归护栏）。"""
    sd = tmp_path / "skill"
    base = _state(sd / ".gatekeeper.state", worktree=str(sd))
    g = _state(sd / ".gatekeeper.state.g", worktree=str(sd))
    _ptr(sd / ".gatekeeper.plan", g)
    r = grc.resolve_state(str(sd), state_file=str(base))
    assert r["source"] == "plan_pointer" and r["expected"] == str(g), r
    assert r["pointer_followed"] is True, r

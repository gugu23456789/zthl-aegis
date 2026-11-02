#!/usr/bin/env python3
"""§18.2 判据 c3 红先臂：四读点 declared-but-unresolved fail-closed（2026-10-04）。

缺陷（遗漏①）：plan 指针**已声明但未解析**（`stale` / `dangling_pointer`）时，四读点
（`ember replay` / `finding reconcile` / `MoA aggregate` / `gk_state_query`）静默回落 base
state 读数据 —— 「只禁写回退、未禁读回退」= 写不越界、读分裂的新假绿。

修法：CLI 启动块把**已算出**的 `pointer_reason` 经 env `GK_PLAN_POINTER_UNRESOLVED` 透出
（启动块在 `stale` 时会 `rm` 失效指针 ⟹ Python 侧事后重算只得 `no_pointer_file`，故须透出）；
四读点入口经**单点守卫** `gk_state_route.read_point_pointer_error()` 显式报错。
**边界（拍板 A）**：仅 `stale` / `dangling_pointer` 触发；`no_pointer_file`（合法默认）不触发。

臂：
  · 守卫臂（HEAD 必红：`read_point_pointer_error` 不存在）
  · 现实锚（投毒源真实：`select_plan_pointer` 真会产出 stale/dangling）
  · **投毒臂**（HEAD 必红：读点不检查 marker ⟹ 静默读 base；投毒 = 置位 marker + base 放 sentinel）
"""
import datetime
import json
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import gk_state_route as R  # noqa: E402

MARKER = "GK_PLAN_POINTER_UNRESOLVED"


def _base_state(tmp: Path, data: dict) -> Path:
    p = tmp / ".gatekeeper.state"
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8", newline="\n")
    return p


def _write_pointer(sd: Path, state_file: str, updated: str) -> None:
    (sd / ".gatekeeper.plan").write_text(
        json.dumps({"plan": "p", "domain": "", "state_file": state_file, "updated": updated}),
        encoding="utf-8", newline="\n")


# ── 守卫臂（HEAD 必红） ──────────────────────────────────────────────────
def test_guard_flags_stale(monkeypatch):
    monkeypatch.setenv(MARKER, "stale")
    assert R.read_point_pointer_error().get("error") == "STATE_POINTER_STALE"


def test_guard_flags_dangling(monkeypatch):
    monkeypatch.setenv(MARKER, "dangling_pointer")
    assert R.read_point_pointer_error().get("error") == "STATE_POINTER_DANGLING_POINTER"


def test_guard_ok_when_absent(monkeypatch):
    monkeypatch.delenv(MARKER, raising=False)
    assert R.read_point_pointer_error() == {}, "no_pointer_file（合法默认）不触发"


# ── 现实锚（投毒源真实，非杜撰） ────────────────────────────────────────
def test_pointer_reason_dangling_is_real(tmp_path):
    _write_pointer(tmp_path, str(tmp_path / "nope.state"),
                   datetime.datetime.now(datetime.timezone.utc).isoformat())
    r = R.select_plan_pointer(str(tmp_path), session_id="", env_pointer="",
                              state_file_explicit=False)
    assert r["reason"] == "dangling_pointer", r


def test_pointer_reason_stale_is_real(tmp_path):
    _write_pointer(tmp_path, str(tmp_path / ".gatekeeper.state"), "2020-01-01T00:00:00+00:00")
    r = R.select_plan_pointer(str(tmp_path), session_id="", env_pointer="",
                              state_file_explicit=False)
    assert r["reason"] == "stale", r


# ── 生产端（bash 透出）链完整性 ─────────────────────────────────────────
def test_cli_produces_unresolved_marker():
    """c3：启动块须把 stale/dangling reason 经 `GK_PLAN_POINTER_UNRESOLVED` 透出给读侧。"""
    cli = (SCRIPTS.parent / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    assert "GK_PLAN_POINTER_UNRESOLVED" in cli, (
        "c3：启动块须导出 GK_PLAN_POINTER_UNRESOLVED（否则 stale 分支 rm 指针后读侧无从判别）")


# ── 投毒臂（HEAD 必红：读点不检查 marker ⟹ 静默读 base） ────────────────
def test_poison_state_query_no_base_leak(monkeypatch, tmp_path, capsys):
    base = _base_state(tmp_path, {"stage": "POISON_LEAK_XYZ"})
    monkeypatch.setenv("STATE_FILE", str(base))
    monkeypatch.setenv(MARKER, "stale")
    import gk_state_query as SQ
    rc = SQ.main(["--get", "stage"])
    cap = capsys.readouterr()
    assert rc != 0, "投毒后 gk_state_query 须非零退出"
    assert "POISON_LEAK_XYZ" not in cap.out, "投毒后禁把 base 值泄漏到 stdout（禁静默读 base）"
    assert "STATE_POINTER_STALE" in (cap.out + cap.err), "须显式报 STATE_POINTER_STALE"


def test_poison_ember_replay_errors(monkeypatch, tmp_path, capsys):
    base = _base_state(tmp_path, {})
    monkeypatch.setenv(MARKER, "stale")
    import gk_ember_replay as ER
    ER.main(["get", "--state-file", str(base), "--phase", "R6"])
    assert "STATE_POINTER_STALE" in capsys.readouterr().out


def test_poison_moa_aggregate_errors(monkeypatch, tmp_path, capsys):
    base = _base_state(tmp_path, {"gate_data": {"subagent_history": []}})
    monkeypatch.setenv(MARKER, "stale")
    monkeypatch.setattr(sys, "argv", ["gk_moa_aggregate.py", "--state", str(base)])
    import gk_moa_aggregate as MA
    MA.main()
    assert "STATE_POINTER_STALE" in capsys.readouterr().out


def test_poison_finding_reconcile_errors(monkeypatch, tmp_path, capsys):
    base = _base_state(tmp_path, {"gate_data": {"ecc_findings": {}}})
    monkeypatch.setenv(MARKER, "stale")
    import gk_finding as F
    try:
        F.main(["reconcile", str(base)])
    except SystemExit:
        pass
    assert "STATE_POINTER_STALE" in capsys.readouterr().out

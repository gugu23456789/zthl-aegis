"""红先臂：`gk_finding._gate_writable` 在 `GK_PLAN_FILE` 上下文下不得崩（ECC-D652357E13AB）。

病象（2026-10-07 实测）：`_gate_writable` 把 `resolve_plan_state(...)` 的 **dict** 返回值
当对象读 `.declared_domain` ⟹ `AttributeError`。只要进程导出 `GK_PLAN_FILE`，任何
`finding register` 与 `moa-aggregate` 的 `emit_aggregate_finding` 都在写门前崩溃。

三臂：臂1 = 红（修复前 AttributeError）；臂2 = 对照（恒绿，零回归）；臂3 = 负臂
（防"修复后门禁失效"：计划未声明 state_domain 时仍须 fail-loud 拒绝）。
"""
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
import gk_finding  # noqa: E402

_DOMAIN = "skill.demo"


def _domain_state(tmp_path: Path) -> str:
    p = tmp_path / (".gatekeeper.state." + _DOMAIN)
    p.write_text('{"gate_data": {}}', encoding="utf-8")
    return str(p)


def _plan(tmp_path: Path, declare: bool) -> str:
    p = tmp_path / "demo-plan.md"
    if declare:
        meta = "<!-- META\nstate_domain: " + _DOMAIN + "\n-->\n"
    else:
        meta = "<!-- META\nphases: R1\n-->\n"
    p.write_text(meta, encoding="utf-8")
    return str(p)


def test_arm1_domain_state_with_plan_env_no_crash(tmp_path, monkeypatch):
    """臂1（红）：域 state + 计划声明 state_domain + `GK_PLAN_FILE` 在场 ⟹ 写门放行。"""
    state = _domain_state(tmp_path)
    monkeypatch.setenv("GK_PLAN_FILE", _plan(tmp_path, declare=True))
    gk_finding._gate_writable(state)  # 修复前：AttributeError


def test_arm2_no_plan_env_base_state_ok(tmp_path, monkeypatch):
    """臂2（对照，恒绿）：无 `GK_PLAN_FILE` 上下文 ⟹ 仅形态门（零回归）。"""
    monkeypatch.delenv("GK_PLAN_FILE", raising=False)
    state = str(tmp_path / ".gatekeeper.state")
    Path(state).write_text('{"gate_data": {}}', encoding="utf-8")
    gk_finding._gate_writable(state)


def test_arm3_domain_state_plan_undeclared_still_rejected(tmp_path, monkeypatch):
    """臂3（负臂）：域 state + 计划**未**声明 state_domain ⟹ 仍须 fail-loud 拒绝。"""
    state = _domain_state(tmp_path)
    monkeypatch.setenv("GK_PLAN_FILE", _plan(tmp_path, declare=False))
    with pytest.raises(ValueError) as ei:
        gk_finding._gate_writable(state)
    assert "STATE_FORM_NOT_OPTED_IN" in str(ei.value)

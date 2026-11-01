#!/usr/bin/env python3
"""③ 指针选择单源（`select_plan_pointer`）契约测（红先）。

归属：元数据中枢 · 全序列打通 ③（计划 finding `ECC-1EC0E0732F0D`；汇总条 `ECC-46C22B11AD85`）。
被测面：`gk_state_route.select_plan_pointer()` —— 唯一决定「读哪个 plan 指针 / 本进程可写哪个指针」的地方。

两段判据：
  A. **python 单源臂**（直调，覆盖四维：env PLAN_POINTER × sid × cmd_target × (domain×kill switch)）；
  B. **bash 对拍臂**（启动块最终 `STATE_FILE` == python 单源判定；收敛后 bash 零指针判定）。

红先对照臂：`GK_CLI_UNDER_TEST=<旧版 CLI 绝对路径>`（默认 = 仓内 CLI）。
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_gk_edit_budget_metering import (  # noqa: E402
    SKILL_DIR, _mk_sandbox, _ptr, _sess_state, _state_via_cli, _wsl, _write_marker)

import gk_state_route as gsr  # noqa: E402

SID = "0123456789abcdef01234567"


def _sb(tmp_path: Path) -> Path:
    """沙箱 + 三个可辨识 state（`r_phase` 区分解析到了哪一个）。"""
    sb = _mk_sandbox(tmp_path, {"max": 8, "used": 0, "remaining": 8})
    _sess_state(sb, "gatekeeper.state.sS", "SESS")
    _sess_state(sb, "gatekeeper.state.sG", "GLOB")
    _sess_state(sb, "gatekeeper.state.sP", "PTR")
    return sb


# ═══════════════ A. python 单源臂（四维覆盖，≥12 例）═══════════════

def test_python_sess_pointer_priority(tmp_path):
    """会话指针优先于全局（读侧分片）。"""
    sb = _sb(tmp_path)
    _ptr(sb, ".gatekeeper.plan." + SID, sb / ".gatekeeper.state.sS", plan="p1")
    _ptr(sb, ".gatekeeper.plan", sb / ".gatekeeper.state.sG", plan="p1")
    out = gsr.select_plan_pointer(str(sb), session_id=SID)
    assert out["followed"] is True, out
    assert out["pointer"].endswith(".gatekeeper.plan." + SID), out
    assert out["own"].endswith(".gatekeeper.plan." + SID), out


def test_python_no_sid_uses_global_pointer(tmp_path):
    """**无**会话身份 ⟹ 认全局指针（零回归），且 own = 全局。"""
    sb = _sb(tmp_path)
    _ptr(sb, ".gatekeeper.plan", sb / ".gatekeeper.state.sG", plan="p1")
    out = gsr.select_plan_pointer(str(sb), session_id="")
    assert out["followed"] is True, out
    assert out["pointer"].endswith(".gatekeeper.plan"), out
    assert out["own"].endswith(".gatekeeper.plan"), out


def test_python_sid_without_own_pointer_does_not_adopt_global(tmp_path):
    """**有** sid 但本会话无指针 ⟹ 不采纳全局（防跨会话劫持）；own 仍指本会话指针。"""
    sb = _sb(tmp_path)
    _ptr(sb, ".gatekeeper.plan", sb / ".gatekeeper.state.sG", plan="p1")
    out = gsr.select_plan_pointer(str(sb), session_id=SID)
    assert out["followed"] is False, out
    assert out["reason"] == "no_pointer_file", out
    assert out["own"].endswith(".gatekeeper.plan." + SID), out


def test_python_env_pointer_takes_precedence(tmp_path):
    """env `PLAN_POINTER` 显式给出 ⟹ 认它（§4.13.5② 记的缺口闭合）。"""
    sb = _sb(tmp_path)
    _ptr(sb, ".gatekeeper.plan", sb / ".gatekeeper.state.sG", plan="keep")
    _ptr(sb, ".gatekeeper.plan.sP", sb / ".gatekeeper.state.sP", plan="keep")
    out = gsr.select_plan_pointer(str(sb), session_id="",
                                  env_pointer=str(sb / ".gatekeeper.plan.sP"))
    assert out["followed"] is True and out["pointer"].endswith(".plan.sP"), out


def test_python_explicit_state_file_owns_nothing(tmp_path):
    """显式 `STATE_FILE` ⟹ 本进程**不写不删**指针（own 为空；对齐既有 L315 语义）。"""
    sb = _sb(tmp_path)
    out = gsr.select_plan_pointer(str(sb), session_id=SID, state_file_explicit=True)
    assert out["own"] == "", out


def test_python_cmd_target_match_follows(tmp_path):
    """命令计划 == 指针 plan ⟹ 跟随。"""
    sb = _sb(tmp_path)
    _ptr(sb, ".gatekeeper.plan", sb / ".gatekeeper.state.sG", plan="my-plan")
    out = gsr.select_plan_pointer(str(sb), session_id="", cmd_target_plan="my-plan")
    assert out["followed"] is True, out


def test_python_cmd_target_mismatch_skips(tmp_path):
    """命令计划 ≠ 指针 plan ⟹ 不跟随（防跨计划劫持）。"""
    sb = _sb(tmp_path)
    _ptr(sb, ".gatekeeper.plan", sb / ".gatekeeper.state.sG", plan="other-plan")
    out = gsr.select_plan_pointer(str(sb), session_id="", cmd_target_plan="my-plan")
    assert out["followed"] is False and out["reason"] == "cmd_target_mismatch", out


def test_python_strict_skips_plan_pointer(tmp_path):
    """`strict=True` 且指针带 plan ⟹ 不跟随（reason=strict）。"""
    sb = _sb(tmp_path)
    _ptr(sb, ".gatekeeper.plan", sb / ".gatekeeper.state.sG", plan="p1")
    out = gsr.select_plan_pointer(str(sb), session_id="", strict=True)
    assert out["followed"] is False and out["reason"] == "strict", out


def test_python_stale_ttl_not_followed(tmp_path):
    """`updated` 超 TTL ⟹ reason=stale（不跟随）。"""
    sb = _sb(tmp_path)
    p = _ptr(sb, ".gatekeeper.plan", sb / ".gatekeeper.state.sG", plan="p1")
    d = json.loads(p.read_text(encoding="utf-8"))
    d["updated"] = "2020-01-01T00:00:00Z"
    p.write_text(json.dumps(d), encoding="utf-8", newline="\n")
    out = gsr.select_plan_pointer(str(sb), session_id="")
    assert out["followed"] is False and out["reason"] == "stale", out


def test_python_domain_route_off_skips_domain_pointer(tmp_path):
    """`GK_STATE_DOMAIN_ROUTE=0` 且指针带 domain ⟹ reason=domain_route_off（**不删**指针）。"""
    sb = _sb(tmp_path)
    p = _ptr(sb, ".gatekeeper.plan", sb / ".gatekeeper.state.sG", plan="p1")
    d = json.loads(p.read_text(encoding="utf-8"))
    d["domain"] = "d1"
    p.write_text(json.dumps(d), encoding="utf-8", newline="\n")
    out = gsr.select_plan_pointer(str(sb), session_id="", domain_route="0")
    assert out["followed"] is False and out["reason"] == "domain_route_off", out
    assert p.exists(), "kill switch 不得删指针（可逆）"


def test_python_domain_route_on_follows_with_domain(tmp_path):
    """`GK_STATE_DOMAIN_ROUTE=1` + 指针带 domain ⟹ 跟随并回带 domain。"""
    sb = _sb(tmp_path)
    p = _ptr(sb, ".gatekeeper.plan", sb / ".gatekeeper.state.sG", plan="p1")
    d = json.loads(p.read_text(encoding="utf-8"))
    d["domain"] = "d1"
    p.write_text(json.dumps(d), encoding="utf-8", newline="\n")
    out = gsr.select_plan_pointer(str(sb), session_id="", domain_route="1")
    assert out["followed"] is True and out.get("domain") == "d1", out


def test_python_no_pointer_file(tmp_path):
    """无任何指针文件 ⟹ 不跟随（reason=no_pointer_file）。"""
    sb = _sb(tmp_path)
    out = gsr.select_plan_pointer(str(sb), session_id="")
    assert out["followed"] is False and out["reason"] == "no_pointer_file", out


# ═══════════════ B. bash 对拍臂（收敛后应逐例相等）═══════════════

EXPECT_MATRIX = [
    # env_pointer, sid_mode, expect(r_phase)
    ("", "sess",        "SESS"),   # 会话分片优先
    ("", "none",        "GLOB"),   # 无身份 → 全局
    ("", "sess_absent", "R1"),     # 有 sid 但本会话无指针 → 回落**默认** state（不认全局）
    ("", "ptr",         "PTR"),    # env PLAN_POINTER 显式
    ("", "explicit",    "GLOB"),   # 显式 STATE_FILE（own 为空）
]


@pytest.mark.parametrize("env_pointer,sid_mode,expect", EXPECT_MATRIX)
def test_bash_state_matches_python_pick(tmp_path, env_pointer, sid_mode, expect):
    """bash 启动块最终解析到的 state == python 单源判定（逐例对拍）。"""
    sb = _sb(tmp_path)
    if sid_mode == "sess":     # `sess_absent` 刻意**不建**会话指针（判据面 = 有 sid 但本会话无绑定）
        _ptr(sb, ".gatekeeper.plan." + SID, sb / ".gatekeeper.state.sS", plan="my-plan")
    _ptr(sb, ".gatekeeper.plan", sb / ".gatekeeper.state.sG", plan="my-plan")
    _ptr(sb, ".gatekeeper.plan.sP", sb / ".gatekeeper.state.sP", plan="keep")
    if sid_mode in ("sess", "sess_absent"):
        _write_marker(sb, SID)
    env = ""
    if sid_mode in ("sess", "sess_absent"):
        env += "GK_SESSION_ID=%s " % SID
    if sid_mode == "ptr":
        env += "PLAN_POINTER=%s " % _wsl(sb / ".gatekeeper.plan.sP")
    if sid_mode == "explicit":
        env += "STATE_FILE=%s " % _wsl(sb / ".gatekeeper.state.sG")
    got = _state_via_cli(sb, env)
    assert got.get("r_phase") == expect, (got, env)


def test_resolve_default_state_is_thin_delegate():
    """③ 单源不变量：`gk_state._resolve_default_state` 须为**薄壳**（函数体 ≤1 语句）。

    收敛前它自持第二套「env → 全局指针 → 默认」判定（无 TTL / 无会话分片 / 无命令对账 / 无域）
    ⟹ 与 bash 链可得出不同 state。薄壳化后实现体只允许 1 条语句（docstring 不计）。
    """
    import ast
    src = (SKILL_DIR / "scripts" / "gk_state.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "_resolve_default_state")
    body = [s for s in fn.body if not isinstance(s, ast.Expr)]
    assert len(body) == 1, f"非薄壳（{len(body)} 语句）—— 第二实现回流"


def test_bash_startup_has_no_inline_pointer_logic():
    """单源不变量（**语句级**判据）：bash 启动块不再有指针判定语句。

    只判「赋值/拼接」形态并**跳过注释行**（head 内既有注释含 `.gatekeeper.plan.` 文案与 TTL 字面量，
    判全文会假红；判注释外文本才等价于「无判定语句」）。
    """
    src = (SKILL_DIR / "gatekeeper-cli.sh").read_text(encoding="utf-8")
    head = src.split("# ── state 路由弹性安全网", 1)[0]
    code = [ln for ln in head.splitlines() if not ln.lstrip().startswith("#")]
    joined = "\n".join(code)
    assert "_PLAN_POINTER_OWN=" not in joined, "bash 仍在派生 own（应改由 python 给）"
    assert '".gatekeeper.plan."' not in joined, "bash 仍在拼接会话指针路径"
    assert "86400" not in joined, "bash 仍在算指针 TTL"

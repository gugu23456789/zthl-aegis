#!/usr/bin/env python3
"""质询派发锁 + default 前置闸 + 强制击杀/报警 —— 非法启动路径全量压测（2026-11-14 owner 令）。

本轮事故：手工拼 `monitor --subagent "<质询文本>" --arm-group G1 --batch-*`，既不过统一入口
`plan-refinement <plan> --run` 的 L2 入站门，也不带 `--role plan-refinement` ⟹ 落 `default`
角色径直派发（实测 6s 内 STUB_CALLED，报告 sub-1794632361-72-30684）；事后同一手法被用来
冒充「3 臂模式」。owner 判据：

  ① 计划质询只允许标准入口派发；其他一切携带**批身份/臂组别**的派发 = 非法 ⟹
     **强制击杀当前进程**（SIGKILL）+ **立刻报警**（stderr 横幅 + append-only 账本）。
  ② `default` 是兜底角色，落点必须有显式理由 `--default-reason`（去空白 ≥8 字符），
     理由随 payload 落 `subagent_history.default_reason`。
  ③ 显式具名通道 `--crossrev` 有自己的 preflight ⟹ 不属兜底，豁免理由闸。

本文件枚举**所有结构性非法启动路径**（flag × role、env 继承 × role、文本 × role），
逐条断言「未派发（STUB 未被调用）+ 已被击杀 + 账本有记录」，并守住标准入口零回归。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

CLI = Path(__file__).resolve().parent.parent / "gatekeeper-cli.sh"

# 批身份五要素（§18.1/§18.3）：出现即必属 MoA 质询臂的结构性身份。
BATCH_FLAGS = [
    ("--batch-plan", "p.md"),
    ("--batch-narrow", "n1,n2"),
    ("--batch-epoch", "1700000000"),
    ("--arm-group", "G1"),
    ("--arm-delta", "3"),
]
BATCH_ENVS = ["GK_BATCH_PLAN", "GK_BATCH_NARROW", "GK_BATCH_EPOCH", "GK_ARM_GROUP", "GK_ARM_DELTA"]
BATCH_CODE = "BATCH_IDENTITY_REQUIRES_PLAN_REFINEMENT"


def _src() -> str:
    return CLI.read_text(encoding="utf-8")


def _helper_body() -> str:
    s = _src()
    i = s.find("_gk_illegal_dispatch_kill() {")
    assert i >= 0, "缺 _gk_illegal_dispatch_kill（强制击杀/报警单一实现）"
    j = s.find("\n}\n", i)
    assert j > i, "_gk_illegal_dispatch_kill 未闭合"
    return s[i:j]


# ── 夹具：最小 state + 桩解释器 + 干净环境 ────────────────────────────────
def _fixture(tmp_path: Path):
    state = tmp_path / "st.json"
    state.write_text(json.dumps({
        "stage": "STAGE_0", "r_phase": "R1", "branch": "master", "worktree": "",
        "gate_data": {"project_type": "standing"},
    }, ensure_ascii=False), encoding="utf-8")
    stub = tmp_path / "stub.sh"
    stub.write_text('#!/bin/sh\necho STUB_CALLED\nread -r _x || true\nexit 0\n', encoding="utf-8")
    stub.chmod(0o755)
    nogx = tmp_path / "no-gitnexus"
    nogx.mkdir(exist_ok=True)
    alarm = tmp_path / "alarm.jsonl"
    return state, stub, nogx, alarm


def _env(tmp_path: Path, kill: str = "1", state_obj=None):
    state, stub, nogx, alarm = _fixture(tmp_path)
    if state_obj is not None:
        state.write_text(json.dumps(state_obj, ensure_ascii=False), encoding="utf-8")
    env = dict(os.environ)
    # 父进程 env 不得把批身份/击杀开关/理由带进判据（否则矩阵互相污染）。
    for k in BATCH_ENVS + ["GK_ILLEGAL_ALARM_LOG", "GK_ILLEGAL_DISPATCH_KILL", "GK_DEFAULT_REASON"]:
        env.pop(k, None)
    env.update({
        "STATE_FILE": str(state), "STATE_FILE_EXPLICIT": "1",
        "GK_STATE_DOMAIN_ROUTE": "0", "GK_ALLOW_STALE_CTX": "1",
        # 标准入口臂会触发质询通道的 L3 基线门；本仓无 gitnexus 索引 ⟹ 显式降级（判据与
        # 本文件的锁无关，避免用环境不可用掩盖锁的判据）。
        "GK_ALLOW_STALE_BASELINE": "1",
        "SUBAGENT_DS_RETRY": "0", "GK_MIMO_DISABLED": "1",
        "GK_SANDBOX_SUBAGENT": "0", "SUAGENT_PYTHON": str(stub),
        "GK_GX_DIR": str(nogx), "GK_GX_TIMEOUT": "2", "GK_GX_STATUS_TIMEOUT": "2",
        "GK_ILLEGAL_ALARM_LOG": str(alarm), "GK_ILLEGAL_DISPATCH_KILL": kill,
    })
    return env, alarm


def _run(tmp_path: Path, args, extra_env=None, kill: str = "1", state_obj=None):
    env, alarm = _env(tmp_path, kill=kill, state_obj=state_obj)
    env.update(extra_env or {})
    r = subprocess.run(["bash", str(CLI), "monitor", "--subagent", *args],
                       cwd=str(CLI.parent), capture_output=True, text=True,
                       env=env, timeout=240)
    return r, alarm


def _alarms(path: Path):
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def _assert_killed(r, alarm_path: Path, code: str):
    assert r.returncode in (-9, 137), (
        "非法质询未被强制击杀（rc=%r；期望 SIGKILL -9 / 137）\nstdout=%s\nstderr=%s"
        % (r.returncode, r.stdout[-800:], r.stderr[-800:]))
    assert code in r.stdout, "击杀前 stdout 须先给出错误码 %s：%r" % (code, r.stdout[-800:])
    assert "STUB_CALLED" not in r.stdout, "非法路径仍派发到了子代理（STUB 被调用）"
    rows = _alarms(alarm_path)
    assert rows, "未写报警账本（立刻报警缺失）"
    assert any(x.get("code") == code and x.get("event") == "ILLEGAL_PLAN_REFINEMENT_DISPATCH"
               for x in rows), rows
    assert "[ALARM]" in r.stderr, "未在 stderr 播报警（禁静默击杀）"


# ── ① 结构面：击杀实现 / 三条守卫均接线 ──────────────────────────────────
def test_kill_helper_alarms_before_kill():
    body = _helper_body()
    i_alarm = body.find("alarm.jsonl")
    assert i_alarm > 0, "击杀 helper 未定义告警账本（立刻报警缺失）"
    assert body.find(">>\"$alarm_log\"") > 0, "击杀 helper 未 append 账本"
    assert body.find("kill -KILL") > body.find(">>\"$alarm_log\""), (
        "账本/横幅必须先落，再击杀（否则取证丢失）")
    assert "ILLEGAL_PLAN_REFINEMENT_DISPATCH" in body


def test_three_plan_refinement_gates_use_kill():
    s = _src()
    for code in (BATCH_CODE, "BARE_PLAN_REFINEMENT", "REVIEW_ROLE_UNSPECIFIED"):
        assert code in s, "缺守卫错误码 %s" % code
    # 三条守卫都必须走同一 helper（禁第二实现）
    assert s.count("_gk_illegal_dispatch_kill \"") >= 3, (
        "三条质询守卫未全部接强制击杀（禁只报错不杀）")


def test_default_reason_gate_present_and_crossrev_exempt():
    s = _src()
    assert "DEFAULT_ROLE_REASON_REQUIRED" in s, "缺 default 前置闸"
    assert '[ "$subagent_role" = "default" ] && ! $crossrev_flag' in s, (
        "default 闸条件须含 crossrev 豁免（--crossrev 是具名通道，不属兜底）")
    assert 'export GK_DEFAULT_REASON="$default_reason"' in s, (
        "理由未 export 到 payload（subagent_history 无审计面）")


def test_sanctioned_fanout_keeps_role_and_batch_identity():
    s = _src()
    assert ('cmd_monitor --subagent "${_arm_fts[$_i]}" --role plan-refinement' in s), (
        "标准 fan-out 必须同时带 --role plan-refinement（否则被新锁击杀）")
    assert "--adjudicate last-batch --decision approve" in s, "统一入口裁决链被破坏"


# ── ② 行为面：flag 矩阵（任一 flag × 任一非 plan-refinement 角色 ⟹ 击杀）──
def test_each_batch_flag_without_role_is_killed(tmp_path):
    for flag, val in BATCH_FLAGS:
        d = tmp_path / flag.lstrip("-").replace("-", "_")
        d.mkdir()
        r, alarm = _run(d, ["质询臂A：审查计划 §2.1", flag, val])
        _assert_killed(r, alarm, BATCH_CODE)
        ident = _alarms(alarm)[-1].get("identity", "")
        assert flag in ident, "账本须记录触发的 flag：%r" % ident
        assert "env:" not in ident, (
            "flag 形态被误记成 env 继承（采样时机错了）：%r" % ident)


def test_each_batch_flag_with_explicit_default_role_is_killed(tmp_path):
    for flag, val in BATCH_FLAGS:
        d = tmp_path / ("d_" + flag.lstrip("-").replace("-", "_"))
        d.mkdir()
        r, alarm = _run(d, ["质询臂A：审查计划 §2.1", "--role", "default", flag, val])
        _assert_killed(r, alarm, BATCH_CODE)


def test_named_role_plus_batch_identity_is_killed(tmp_path):
    r, alarm = _run(tmp_path, ["质询臂A", "--role", "reporter", "--arm-group", "G2"])
    _assert_killed(r, alarm, BATCH_CODE)


# ── ③ 行为面：env 继承矩阵（绕过 flag 解析的入口）────────────────────────
def test_each_batch_env_without_role_is_killed(tmp_path):
    for k in BATCH_ENVS:
        d = tmp_path / ("env_" + k.lower())
        d.mkdir()
        r, alarm = _run(d, ["质询臂A：审查计划 §2.1"], extra_env={k: "X"})
        _assert_killed(r, alarm, BATCH_CODE)
        ident = _alarms(alarm)[-1].get("identity", "")
        assert "env:" in ident and k in ident, (
            "env 继承形态须在账本中标出 env: 与键名：%r" % ident)


# ── ④ 既有两条质询守卫：同样击杀（不再只回错误串）────────────────────────
def test_bare_plan_refinement_role_is_killed(tmp_path):
    """裸 `--role plan-refinement`（task ∉ pipeline）⟹ BARE 守卫击杀。"""
    r, alarm = _run(tmp_path, ["裸窄任务（不在 task_pipeline）", "--role", "plan-refinement"])
    _assert_killed(r, alarm, "BARE_PLAN_REFINEMENT")


def test_plan_refinement_text_without_role_is_killed(tmp_path):
    """改写措辞前的最原始形态：task 含 `plan-refinement` 而**无** --role ⟹ 击杀。"""
    r, alarm = _run(tmp_path, ["plan-refinement: docs/plans/x.md — 质询 X"])
    _assert_killed(r, alarm, "REVIEW_ROLE_UNSPECIFIED")


def test_kill_switch_off_still_alarms_but_returns_137(tmp_path):
    """测试开关 `GK_ILLEGAL_DISPATCH_KILL=0`：只报警不自杀（仍 rc=137 + 账本）。"""
    r, alarm = _run(tmp_path, ["质询臂A", "--arm-group", "G1"], kill="0")
    assert r.returncode == 137, (r.returncode, r.stdout[-800:])
    assert BATCH_CODE in r.stdout and '"killed":false' in r.stdout, r.stdout[-800:]
    assert "STUB_CALLED" not in r.stdout, "关闭自杀开关后仍不得派发"
    assert _alarms(alarm), "关闭自杀开关也必须报警"


# ── ⑤ default 前置闸：缺理由 / 太短 / 有理由 ─────────────────────────────
def test_default_role_without_reason_is_blocked(tmp_path):
    r, alarm = _run(tmp_path, ["通用审计任务：列出五域现状"])
    assert r.returncode == 2, (r.returncode, r.stdout[-800:])
    assert "DEFAULT_ROLE_REASON_REQUIRED" in r.stdout, r.stdout[-800:]
    assert "STUB_CALLED" not in r.stdout, "default 未说明理由仍派发"


def test_default_role_with_too_short_reason_is_blocked(tmp_path):
    r, _ = _run(tmp_path, ["通用审计任务", "--default-reason", "太短"])
    assert r.returncode == 2 and "DEFAULT_ROLE_REASON_REQUIRED" in r.stdout, r.stdout[-800:]


def test_default_role_with_reason_passes_gate(tmp_path):
    r, _ = _run(tmp_path, ["通用审计任务：列出五域现状",
                           "--default-reason", "该任务只需通用 evidence 面，无专用角色协议可用"])
    assert "DEFAULT_ROLE_REASON_REQUIRED" not in r.stdout, r.stdout[-800:]
    assert "STUB_CALLED" in r.stdout, (
        "给出理由后 default 闸不应再阻断（实际未到派发）：%r" % r.stdout[-800:])


def test_default_reason_on_named_role_is_rejected(tmp_path):
    r, _ = _run(tmp_path, ["某任务", "--role", "reporter",
                           "--default-reason", "这个理由不该出现在具名角色上"])
    assert r.returncode == 2 and "DEFAULT_REASON_NOT_APPLICABLE" in r.stdout, r.stdout[-800:]


# ── ⑥ 落库审计：理由随 payload 进 subagent_history ───────────────────────
def _run_payload(tmp_path: Path, ecc: dict, extra_env=None):
    sd = str(CLI.parent).replace("\\", "/")
    state = tmp_path / ".gatekeeper.state"
    state.write_text('{"gate_data":{}}', encoding="utf-8")
    out = tmp_path / "sub-1.json"
    out.write_text(json.dumps(ecc, ensure_ascii=False), encoding="utf-8")
    env = dict(os.environ, GK_TASK=ecc.get("task", ""), GK_HMAC_VALID="skip",
               GK_OUTPUT_FILE=str(out), GK_REPORT_FILE=str(tmp_path / "sub-1.md"),
               GK_PY_SCRIPTS=sd + "/scripts", GK_PY_STATE=str(state).replace("\\", "/"))
    env.update(extra_env or {})
    r = subprocess.run([sys.executable, str(CLI.parent / "scripts" / "gk_monitor_payload.py")],
                       input=json.dumps(ecc), capture_output=True, text=True, env=env, timeout=90)
    assert r.returncode == 0, (r.returncode, r.stdout[-800:], r.stderr[-800:])
    return json.loads(state.read_text(encoding="utf-8"))


def test_payload_records_default_reason(tmp_path):
    d = _run_payload(tmp_path, {"mode": "subagent", "subagent_id": "sub-1", "nonce": "n1",
                                "task": "通用审计任务", "conclusion": "c" * 200},
                     extra_env={"GK_DEFAULT_REASON": "无专用角色协议可用，只用 evidence 面"})
    ent = d["gate_data"]["subagent_history"][-1]
    assert ent.get("default_reason") == "无专用角色协议可用，只用 evidence 面", ent.get("default_reason")


def test_payload_default_reason_empty_for_named_roles(tmp_path):
    d = _run_payload(tmp_path, {"mode": "subagent", "subagent_id": "sub-2", "nonce": "n2",
                                "task": "RED-SCOPE: 枚举攻击面", "conclusion": "c" * 200})
    ent = d["gate_data"]["subagent_history"][-1]
    assert ent.get("default_reason") == "", ent.get("default_reason")


# ── ⑦ 零回归：标准入口形态（--role plan-refinement + 批身份 + full_task ∈ pipeline）──
# 锁必须只杀「非标准来源」，不得误伤统一入口 fan-out 的**逐字形态**。
def _state_with_pipeline(ft: str):
    """构造带 task_pipeline 的最小 state（BARE 守卫按 full_task 精确命中）。"""
    return {
        "stage": "STAGE_0", "r_phase": "R1", "branch": "master", "worktree": "",
        "gate_data": {"project_type": "standing",
                      "task_pipeline": [{"id": "pr-x", "full_task": ft, "status": "pending",
                                         "target": "docs/plans/x.md"}]},
    }


_SANCTIONED_FT = "plan-refinement: docs/plans/x.md — 只质询 §2.1 治理原则"


def test_sanctioned_fanout_shape_is_not_killed(tmp_path):
    """标准 fan-out 逐字形态（role + 五要素 flag）必须放行（锁不得误伤正规链）。"""
    r, alarm = _run(tmp_path, [
        _SANCTIONED_FT, "--role", "plan-refinement",
        "--batch-plan", "docs/plans/x.md", "--batch-narrow", "n1",
        "--batch-epoch", "1700000000", "--arm-group", "G1", "--arm-delta", "0",
    ], state_obj=_state_with_pipeline(_SANCTIONED_FT))
    assert BATCH_CODE not in r.stdout, "标准 fan-out 被批身份锁误杀：%r" % r.stdout[-800:]
    assert "BARE_PLAN_REFINEMENT" not in r.stdout, "标准 full_task 未命中 pipeline：%r" % r.stdout[-800:]
    assert "STUB_CALLED" in r.stdout, "标准链未到达派发（锁/守卫过度拦截）：%r" % r.stdout[-800:]
    assert not _alarms(alarm), "标准链不应触发报警：%r" % _alarms(alarm)


def test_sanctioned_env_inherited_batch_identity_is_not_killed(tmp_path):
    """批身份经 env 继承 + 显式 plan-refinement 角色 ⟹ 同样放行（角色是判据，不是 flag）。"""
    r, alarm = _run(tmp_path, [_SANCTIONED_FT, "--role", "plan-refinement"],
                    extra_env={"GK_ARM_GROUP": "G2", "GK_BATCH_PLAN": "docs/plans/x.md"},
                    state_obj=_state_with_pipeline(_SANCTIONED_FT))
    assert BATCH_CODE not in r.stdout and "STUB_CALLED" in r.stdout, r.stdout[-800:]
    assert not _alarms(alarm), _alarms(alarm)

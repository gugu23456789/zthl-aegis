"""⑥ 跨族共因（`ECC-786B05E46C61`）：`apply-worktree --code-fix` 的诊断面不得被吞。

现场（2026-09-23 实测）：族模板字面花括号触发 `KeyError`，但 CLI 只回
`{"ok":false,"error":"族判定失败","detail":null}` —— `detail` 取的是 **stdout**，而
traceback 只落 **stderr**；操作者看到的「无族命中」是假象，真因仅在 `scripts/gk_dbg.log`。

本臂用**同一类非 `FamilyError` 异常**触发（`ecc_findings` 是字符串 ⟹
`for cand in "boom": cand.get(...)` 抛 `AttributeError`）钉住：回包必须带 `rc` 与非空
`stderr_tail`，否则「故障可观测性」这一面会继续静默。
"""
import json
import os
import subprocess

import pytest

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run_cli(*args, timeout=120):
    # `GK_BUDGET_OVERRIDE=1`（`ECC-1F6514B84334`，2026-09-26 实测）：本文件测的是**诊断面**
    # （回包是否带 rc / stderr_tail），**不是用户编辑** ⟹ 与生产面 `gk_agent_edit._cli_gate_ok`
    # 同一口径。修前三条臂里的「无名/缺值」两条不带 `--state` ⟹ 打到**真** state，每次 pytest
    # 扣主 agent 节点额度 3 次/验收轮（`apply-worktree` 是写类子命令 ⟹ 经 `_bill_edit` 按次计；
    # 计费**先于** `_dispatch` ⟹ 即便命令随即失败也照样扣）。
    return subprocess.run(["bash", os.path.join(SKILL_DIR, "gatekeeper-cli.sh"), *args],
                          capture_output=True, text=True, timeout=timeout, cwd=SKILL_DIR,
                          env={**os.environ, "GK_BUDGET_OVERRIDE": "1"})


def _bad_state(tmp_path):
    """合法 JSON，但 `ecc_findings` 形态非法 ⟹ 抛**非** `FamilyError`（模拟 `KeyError` 类真因）。"""
    p = tmp_path / ".gatekeeper.state.bad"
    p.write_text(json.dumps({"r_phase": "X", "stage": "S",
                             "gate_data": {"ecc_findings": "boom"}}), encoding="utf-8")
    return str(p)


def test_non_familyerror_is_not_swallowed(tmp_path):
    r = _run_cli("apply-worktree", "--code-fix", "--finding", "ECC-NOPE",
                 "--state", _bad_state(tmp_path))
    out = r.stdout.strip()
    obj = json.loads(out)
    assert obj.get("ok") is False, out
    assert "rc" in obj, f"回包缺 rc —— 诊断面仍被吞（真因只在 gk_dbg.log）：{out}"
    assert obj.get("stderr_tail"), f"回包缺非空 stderr_tail —— 真因未暴露给操作者：{out}"
    assert "Error" in obj["stderr_tail"], f"stderr_tail 未含异常类名：{obj['stderr_tail']!r}"


def test_familyerror_detail_still_carried(tmp_path):
    """负臂：真正的 `FamilyError`（finding 不存在）仍须回可读 detail，且 rc=1。"""
    st = tmp_path / ".gatekeeper.state.ok"
    st.write_text(json.dumps({"r_phase": "X", "stage": "S",
                              "gate_data": {"ecc_findings": []}}), encoding="utf-8")
    r = _run_cli("apply-worktree", "--code-fix", "--finding", "ECC-NOPE", "--state", str(st))
    obj = json.loads(r.stdout.strip())
    assert obj.get("ok") is False and obj.get("rc") == 1, r.stdout
    # `FamilyError` 的 JSON 原文由 `gk_agent_family.resolve` 打到 **stdout** ⟹ 仍须被 detail 带出。
    assert isinstance(obj.get("detail"), dict) and obj["detail"].get("ok") is False, r.stdout


def test_valueless_trailing_flag_does_not_hang():
    """flag 缺值族（`ECC-AAD612CC8270`）行为面：尾随缺值旗标不得挂起，须给可读 fail-loud。

    实测（2026-09-24 修前）：`apply-worktree --code-fix --family` 落 `while` 内裸 `shift 2`；
    `$#==1` 时 `shift 2` 返回非零且**不移位** ⟹ 死循环（`timeout 12` → rc=124）。
    修后守卫 `shift 2 2>/dev/null || shift` 令其退化为单步 `shift` ⟹ 约 0.6s 返回可读 fail-loud JSON
    （实测 `{"ok":false,"error":"apply-worktree <finding-id> required"}`），且不泄漏 `unbound variable`。
    """
    try:
        r = _run_cli("apply-worktree", "--code-fix", "--family", timeout=25)
    except subprocess.TimeoutExpired:
        pytest.fail("尾随缺值旗标触发死循环（旗标支 shift 2 未守卫）")
    obj = json.loads(r.stdout.strip())
    assert obj.get("ok") is False and obj.get("error"), r.stdout
    assert "unbound variable" not in (r.stdout + r.stderr), r.stderr


# ── 环境坑加固（2026-10-30）：显式 state 失败必须 fail-loud，禁静默回落默认 state ──────────
# 现场（本会话实测）：外层 shell 吞掉 `$VAR` 时 `--state "$ST"` / `STATE_FILE="$ST"` 退化为**空串**，
#   CLI 把空串当「未显式给出」⟹ **静默回落默认 state** ⟹ finding 查不到 / 写错台账；
#   表面症状是「族判定失败」，真因（state 走错域）完全不可见。
def test_empty_state_flag_fails_loud():
    """`--state ""` = 显式给出但为空 ⟹ STATE_PATH_EMPTY（rc=2），禁回落默认 state。"""
    r = _run_cli("apply-worktree", "--code-fix", "--finding", "ECC-NOPE", "--state", "")
    obj = json.loads(r.stdout.strip())
    assert obj.get("ok") is False, r.stdout
    assert obj.get("error") == "STATE_PATH_EMPTY", (
        "空 --state 未被拦截（静默回落默认 state = 写错台账）: %s" % r.stdout)
    assert r.returncode == 2, r.returncode


def test_empty_state_file_env_fails_loud():
    """`STATE_FILE=`（set-but-empty）同样是注入失败 ⟹ fail-loud，禁当「未设置」静默回落。"""
    env = {**os.environ, "GK_BUDGET_OVERRIDE": "1", "STATE_FILE": ""}
    r = subprocess.run(["bash", os.path.join(SKILL_DIR, "gatekeeper-cli.sh"), "finding", "status"],
                       capture_output=True, text=True, timeout=120, cwd=SKILL_DIR, env=env)
    obj = json.loads(r.stdout.strip())
    assert obj.get("ok") is False, "空 STATE_FILE 被当未设置（静默回落默认 state）: %s" % r.stdout
    assert obj.get("error") == "STATE_FILE_EMPTY", r.stdout
    assert r.returncode == 2, r.returncode

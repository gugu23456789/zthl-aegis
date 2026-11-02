"""A 沙箱接线红先臂（2026-10-16，owner 裁定「沙箱面向所有 subagent」「全接」）。

契约（两接线点，均有逃生舱 ⟹ 零回归）：
  · **A-1** `scripts/gk_hub_scheduler.py` 的 `run` 分支：准入(`admit`)后经 `gk_sandbox.run`
        限额执行（单进程 mem/time/proc 硬上限）；`GK_SANDBOX_OFF=1` 回退裸 subprocess。
  · **A-2** `gatekeeper-cli.sh`：把 `$subagent_python` 包成 `scripts/suagent_sandbox.sh`
        （**单源**覆盖三个 runner 调用点 L4578/4613/4672）；`GK_SANDBOX_SUBAGENT=0` 回退直连。

HEAD 必红：两处接线在 HEAD 均不存在。
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PY = sys.executable


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


# ── A-1 ────────────────────────────────────────────────────────────────────────
def test_arm1_hub_run_branch_imports_and_calls_sandbox():
    """机检：`run` 分支须引入 gk_sandbox 并经其 `run()`，且留 `GK_SANDBOX_OFF` 逃生舱。"""
    src = _read("scripts/gk_hub_scheduler.py")
    assert "import gk_sandbox" in src, "A-1 未接：gk_hub_scheduler 未引入 gk_sandbox"
    assert "_sb.run(" in src, "A-1 未接：run 分支未调 gk_sandbox.run()"
    assert "GK_SANDBOX_OFF" in src, "A-1 缺逃生舱 GK_SANDBOX_OFF"


def test_arm2_hub_run_actually_enforces_memory_limit():
    """真跑：经 hub `run` 申请 1GB，MEM=256 ⟹ 必被限（沙箱真生效）；OFF=1 ⟹ 放行（逃生舱）。"""
    hog = "x=bytearray(1024*1024*1024); print('ALLOC_OK')"
    cmd = [PY, os.path.join(ROOT, "scripts", "gk_hub_scheduler.py"),
           "run", "--", PY, "-c", hog]

    env_on = dict(os.environ, GK_SANDBOX_MEM_MB="256")
    env_on.pop("GK_SANDBOX_OFF", None)
    p_on = subprocess.run(cmd, capture_output=True, text=True, env=env_on, timeout=180)
    assert "ALLOC_OK" not in p_on.stdout, (
        "沙箱未生效（1GB 分配成功）⟹ A-1 未真限值", p_on.returncode,
        p_on.stdout[-300:], p_on.stderr[-300:])

    env_off = dict(env_on, GK_SANDBOX_OFF="1")
    p_off = subprocess.run(cmd, capture_output=True, text=True, env=env_off, timeout=180)
    assert "ALLOC_OK" in p_off.stdout, (
        "逃生舱 GK_SANDBOX_OFF=1 未回退裸执行", p_off.returncode, p_off.stderr[-300:])


# ── A-2 ────────────────────────────────────────────────────────────────────────
def test_arm3_cli_wires_subagent_sandbox_wrapper():
    """机检：CLI 须含 GK_SANDBOX_SUBAGENT 开关 + 指向 suagent_sandbox.sh，且包裹器存在。"""
    cli = _read("gatekeeper-cli.sh")
    assert "GK_SANDBOX_SUBAGENT" in cli, "A-2 未接：缺 GK_SANDBOX_SUBAGENT 开关"
    assert "suagent_sandbox.sh" in cli, "A-2 未接：未引用 suagent_sandbox.sh"
    wrap = os.path.join(ROOT, "scripts", "suagent_sandbox.sh")
    assert os.path.exists(wrap), "A-2 缺包裹器 scripts/suagent_sandbox.sh"


def test_arm4_three_runner_callsites_share_single_source():
    """单源：三个 runner 调用点一律经 `$subagent_python "$subagent_runner"`（无直连第二实现）。"""
    cli = _read("gatekeeper-cli.sh")
    n = cli.count('"$subagent_python" "$subagent_runner"') + \
        cli.count('$subagent_python "$subagent_runner"')
    assert n >= 3, "runner 调用点未全部经 $subagent_python（单源被破）: n=%d" % n


def test_arm5_wrapper_execs_sandbox_on_real_interpreter():
    """包裹器须经 gk_sandbox.py run，并把真实解释器透传（GK_SUBAGENT_PY_REAL）。"""
    src = _read("scripts/suagent_sandbox.sh")
    assert "gk_sandbox.py" in src and " run " in src
    assert "GK_SUBAGENT_PY_REAL" in src

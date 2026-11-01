#!/usr/bin/env python3
"""`pre_tool_check` 元数（arity）契约回归（f8 / ECC-8BA5B8F8EDC2，2026-09-22，**红先**）。

背景（**实测**，非读码推测；探针见会话留痕 `_r23_f8.out`）：`gatekeeper-cli.sh` 顶部为
`set -uo pipefail`，而 `pre_tool_check()` 原首行是

    local cmd_type="$1" path_or_msg="$2"

⟹ 两个形态都在**函数进入处裸崩**（bash `unbound variable`，rc=1）：

  A) **0 参**：`bash gatekeeper-cli.sh pre-tool-check`
       → `line 2507: $1: unbound variable` —— 既不是 usage 报文，也没有 BLOCK 语义；
  B) **1 参**：`_dispatch` 的 full-gate 预检形态 `gate_out=$(pre_tool_check "$cmd" 2>/dev/null || echo "")`
       → `line 2507: $2: unbound variable`。**这一支最隐蔽**：stderr 被 `2>/dev/null` 吞掉、
       stdout 被 `|| echo ""` 用空串顶掉 ⟹ 六个 full-gate 命令
       （guard-edit / advance / appeal / escalate / resolve / push）的 dispatch 预检
       **恒静默跳过**（fail-open，且不报错、无留痕）。

判据：
  ① 0 参 → rc=2 + usage JSON（含 `required`，对齐其它命令的 fail-closed 用法错误形态）；
  ② 1 参 → 输出**不得**含 `unbound variable`（内部路由形态：仅命令名、路径面留空；
     非写类命令名落 `*)` 分支 ⟹ 与既有路由语义一致）；
  ③ 2 参 → 契约不变（既有 BLOCK/OK 语义由 test_main_repo_guard / test_eco_integration 守）。

red-first 对照臂：`GK_CLI_UNDER_TEST=<修复前 CLI 绝对路径>`
（例：`git show HEAD:gatekeeper-cli.sh > /tmp/old-cli.sh`）⟹ 判据①②在修复前均红。

做法：与被测点同形的**最小沙箱**（`scripts` 软链 + CLI 实拷 + 最小 standing state）——
不在技能仓原地跑 CLI，避免测试反过来改动活的 state/密钥。
"""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parent
SKILL_DIR = SCRIPT_DIR.parent
CLI_SRC = Path(os.environ.get("GK_CLI_UNDER_TEST") or (SKILL_DIR / "gatekeeper-cli.sh"))


def _wsl(p) -> str:
    """Windows 路径 → WSL 路径（`C:\\a\\b` → `/mnt/c/a/b`）。"""
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        s = "/mnt/" + s[0].lower() + s[2:]
    return s


def _sandbox(root: Path) -> Path:
    """最小技能根：`scripts` 软链 + CLI 实拷 + 最小 standing state（stage 非 IDLE/DONE）。"""
    sb = (root / "sb").resolve()
    sb.mkdir(parents=True)
    w = _wsl(sb)
    r = subprocess.run(
        ["bash", "-lc", 'ln -s "%s" "%s/scripts" && cp "%s" "%s/gatekeeper-cli.sh"'
         % (_wsl(SCRIPT_DIR), w, _wsl(CLI_SRC), w)],
        capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, f"沙箱搭建失败：{r.stdout}{r.stderr}"
    (sb / ".gatekeeper.state").write_text(json.dumps({
        "stage": "STAGE_0", "r_phase": "R1", "branch": "master", "worktree": "",
        "gate_data": {
            "project_type": "standing",
            "edit_budget": {"max": 4, "used": 0, "remaining": 4, "overrides": []},
            "scheduler": {"mode": "constant", "max_lr": 4, "min_lr": 1,
                          "total_steps": 6, "current_step": 1, "current_lr": 4},
        },
    }, ensure_ascii=False), encoding="utf-8", newline="\n")
    return sb


def _cli_run(sb: Path, *args: str):
    """在沙箱里跑一次 `pre-tool-check <args...>`（不经 `bash -c` 传载荷）。"""
    w = _wsl(sb)
    argv = " ".join('"%s"' % a for a in args)
    return subprocess.run(
        ["bash", "-lc", 'cd "%s" && bash gatekeeper-cli.sh pre-tool-check %s' % (w, argv)],
        capture_output=True, text=True, timeout=120)


@pytest.fixture()
def sandbox():
    if shutil.which("bash") is None:
        pytest.skip("本机无 bash（Windows 语义下 pre_tool_check 无法执行）")
    root = Path(tempfile.mkdtemp(prefix="gk_arity_"))
    try:
        yield _sandbox(root)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _out(r) -> str:
    return (r.stdout or "") + (r.stderr or "")


def test_zero_args_reports_usage_not_crash(sandbox):
    """判据①：0 参必须是 usage（rc=2 + JSON），而不是 `unbound variable` 裸崩。"""
    r = _cli_run(sandbox)
    out = _out(r)
    assert "unbound variable" not in out, f"仍在函数入口裸崩：{out[:300]}"
    assert r.returncode == 2, f"0 参应 rc=2（用法错误），实得 {r.returncode}：{out[:300]}"
    assert '"ok":false' in out and "required" in out, f"未回 usage JSON：{out[:300]}"


def test_single_arg_does_not_crash(sandbox):
    """判据②：1 参（`_dispatch` 内部预检形态）不得裸崩 —— 原为 fail-open 静默跳过。"""
    r = _cli_run(sandbox, "monitor")
    out = _out(r)
    assert "unbound variable" not in out, f"1 参仍在函数入口裸崩（dispatch 预检 fail-open）：{out[:300]}"


def test_two_args_contract_unchanged(sandbox):
    """判据③：2 参（hook 形态）语义不变：非写类命令名 ⟹ 放行 OK。"""
    r = _cli_run(sandbox, "monitor", "/tmp/x.md")
    out = _out(r)
    assert "unbound variable" not in out, out[:300]
    assert "OK" in out, f"2 参放行语义被破坏：{out[:300]}"

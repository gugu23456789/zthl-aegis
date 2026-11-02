#!/usr/bin/env python3
"""n4-L2 红先臂：`discover --build-state` —— 为计划**首建域 state** 的 CLI 包装。

缺口（n4 根因）：`gk_route_center.py build-state`（§18.2 c2）是 sanctioned「元数据中枢派生种子 +
单建者原子首建域 state」入口，但**无 CLI 包装** ⟹ 直调 `scripts/gk_*.py` 被 hook 拦 ⟹
CLI 链路**无路可建域 state**（`discover --plan` 域缺失时 fail-closed 且无解除手段）。

裁法（owner 2026-10-05）：**不新增命令**（`_CMD_REG` 在 `PROTECTED_REGION::gate` 内，SKILL.md T48b；
先例 `cmd_ember burn` / `apply-worktree --code-fix` / `state --inventory` / `pre-check convergence --loop`），
把 `build-state` 挂到既有 `cmd_discover`（区外）的 `--build-state` 模式，**薄转发** route-center。

臂（HEAD 必红：`--build-state` 分支与转发调用均不存在）：
  · `test_discover_parses_build_state_flag`（flag 解析）
  · `test_discover_forwards_build_state_with_required_args`（转发参数契约）
  · `test_no_new_cmd_reg_entry_for_build_state`（路线 A：禁新注册）
  · `test_discover_build_state_fail_closed`（构建失败 ⟹ fail-closed，不静默绑定）
  · `test_domain_token_writable_and_resolvable`（E2E 参数契约：dated 域 token 可写 + 可被 resolve 命中）
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
SK = SCRIPTS.parent
CLI = SK / "gatekeeper-cli.sh"
RC = SCRIPTS / "gk_route_center.py"


def _cli_txt():
    return CLI.read_text(encoding="utf-8")


def _discover_src():
    """`cmd_discover` **整个函数体**（切到下一个列 0 的 `}` 为止）—— 与长度解耦，防假红/假绿。"""
    src = _cli_txt()
    i = src.index("cmd_discover() {")
    j = src.index("\n}\n", i)
    return src[i:j]


def test_discover_parses_build_state_flag():
    """`cmd_discover` 的参数循环须识别 `--build-state`（否则该模式不可达）。"""
    seg = _discover_src()
    assert "--build-state" in seg, "cmd_discover 未解析 --build-state"


def test_discover_forwards_build_state_with_required_args():
    """薄转发契约：调 `gk_route_center.py build-state`，且带 build-state 的必需参数。"""
    seg = _discover_src()
    assert "gk_route_center.py" in seg and "build-state" in seg, "未转发到 route-center build-state"
    for flag in ("--skill-dir", "--state-file", "--main-repo"):
        assert flag in seg, f"build-state 转发缺必需参数 {flag}"
    assert ("--plan-file" in seg) or ("plan_override" in seg), "build-state 转发未提供计划来源"


def test_no_new_cmd_reg_entry_for_build_state():
    """路线 A：**禁**新增 `_CMD_REG[build-state]`（注册表在保护区，T48b）。"""
    assert not re.search(r"^_CMD_REG\[build-state\]", _cli_txt(), re.M), \
        "路线 A 下不得新注册 build-state 命令"


def test_discover_build_state_fail_closed():
    """构建失败（回包 error / 非 ok）⟹ 具名 fail-closed，**禁静默继续绑定**。"""
    seg = _discover_src()
    assert re.search(r"BUILD_STATE|build[_-]state[^\n]*fail|建域[^\n]*失败", seg), \
        "缺少构建失败的具名 fail-closed 分支"


def _run(argv, cwd):
    return subprocess.run(argv, capture_output=True, text=True, cwd=str(cwd))


def test_domain_token_writable_and_resolvable(tmp_path):
    """E2E 参数契约（镜像 wrapper 的转发面）：`<repo>.<dated-plan>` 域 token **可写**（P0 已闭合）
    且建出的域 state 能被 `resolve-state --domain` 命中（= CLI 能拿到信息）。"""
    domain = "skill.2026-01-01-n4-fixture-plan"
    plan = tmp_path / "2026-01-01-n4-fixture-plan.md"
    plan.write_text("<!-- META\nphases: R9\nstate_domain: " + domain + "\n"
                    "target_repo: skill\nproject_type: standing\nworktree_needed: false\n-->\n# t\n",
                    encoding="utf-8")
    base = str(tmp_path / ".gatekeeper.state")
    plan_path = str(plan)
    # ① 首建（与 wrapper 同形参数）
    r = _run([sys.executable, str(RC), "build-state", "--skill-dir", str(tmp_path),
              "--state-file", base, "--plan-file", plan_path, "--main-repo", str(tmp_path)], tmp_path)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out.get("ok"), out
    target = tmp_path / (".gatekeeper.state." + domain)
    assert target.is_file(), "域 state 未建出（dated 域 token 只读？P0 回归）"
    # ② 可被 resolve-state 命中（同域 token）
    r2 = _run([sys.executable, str(RC), "resolve-state", "--skill-dir", str(tmp_path),
               "--state-file", base, "--plan-pointer", "/nonexistent", "--domain", domain], tmp_path)
    assert r2.returncode == 0, r2.stderr
    exp = json.loads(r2.stdout).get("expected", "")
    assert exp and os.path.abspath(exp) == os.path.abspath(str(target)), \
        f"resolve-state 未命中建出的域 state: expected={exp!r} target={str(target)!r}"

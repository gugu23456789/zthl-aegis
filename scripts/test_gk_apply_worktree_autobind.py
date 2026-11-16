#!/usr/bin/env python3
"""ECC-794907FEC0CE 红先臂：apply-worktree **建树即进写面**（自动 bind + 双域写入）。

病象：`--code-fix` / plain 建树后不写 `state.worktrees_extra` ⟹ agent 必须再手工跑
`apply-worktree --bind --path <wt>`，否则主 agent 改 coder 弄坏的地方即被 Gate 3
`Path not in active worktree` 拦（「新建工作区即被 BLOCK」）。且 `--bind` 只写「当前生效
state」（有 plan 指针时 = 域 state），而 hook 按目标路径解析、缺省域是
`<SKILL>/.gatekeeper.state` ⟹ CLI 说绑了、hook 仍 BLOCK。

修法（唯一写通路不变 = `gk_state_patch.py worktrees-extra`，禁第二实现）：
  ① code-fix 建树后**自动 bind**（生效 state + 默认域，幂等、失败不阻断派发）
  ② `--bind` / `--unbind` 同批**双写**默认域（写失败不改主返回值）
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
SKILL = SCRIPTS.parent
CLI = SKILL / "gatekeeper-cli.sh"


def _sandbox(tmp_path):
    """隔离技能根（CLI 实拷 + scripts 实拷 + 两个空 state）—— 真跑 CLI，不碰真 state。"""
    sb = tmp_path / "sb"
    shutil.copytree(SCRIPTS, sb / "scripts")
    shutil.copy2(CLI, sb / "gatekeeper-cli.sh")
    body = '{"gate_data":{},"history":[],"monitor_scores":{}}\n'
    for name in (".gatekeeper.state", "other.state"):
        (sb / name).write_text(body, encoding="utf-8")
    return sb


def _run(sb, *args):
    env = {k: v for k, v in os.environ.items() if k != "STATE_FILE"}
    return subprocess.run(["bash", str(sb / "gatekeeper-cli.sh"), *args],
                          capture_output=True, text=True, env=env, timeout=300)


def test_bind_writes_effective_and_default_domain(tmp_path):
    """行为臂：`--bind` 须**双写**（生效 state + 默认域）——否则 hook 仍读不到。"""
    sb = _sandbox(tmp_path)
    wt = sb / "wtA"
    wt.mkdir()
    r = _run(sb, "apply-worktree", "--bind", "--path", str(wt),
             "--state", str(sb / "other.state"))
    assert r.returncode == 0, r.stdout + r.stderr
    eff = json.loads((sb / "other.state").read_text(encoding="utf-8"))
    dft = json.loads((sb / ".gatekeeper.state").read_text(encoding="utf-8"))
    assert str(wt) in (eff.get("worktrees_extra") or []), eff
    assert str(wt) in (dft.get("worktrees_extra") or []), \
        "默认域未写入 ⟹ hook 按缺省域解析仍 BLOCK"


def test_code_fix_autobinds_created_worktree():
    """静态臂：code-fix 建树段落 bind（生效 state + 默认域）——不再依赖手工第二步。"""
    src = CLI.read_text(encoding="utf-8")
    start = src.index('local _wt_state="$_wt/.gatekeeper.state"')
    seg = src[start:start + 2500]
    assert 'worktrees-extra "$_st" bind "$_wt"' in seg, \
        "code-fix 建树后未自动 bind（仍须手工 --bind 才算进写面）"
    assert '_DEFAULT_STATE_FILE" bind "$_wt"' in seg, "默认域未同步 bind"


def test_bind_segment_uses_single_write_path():
    """静态臂：bind 分支仍走唯一写通路 `gk_state_patch.py worktrees-extra`（禁第二实现）。"""
    src = CLI.read_text(encoding="utf-8")
    i = src.index('if [ -n "$bind_mode" ]; then')
    seg = src[i:i + 2200]
    assert 'gk_state_patch.py" worktrees-extra' in seg, seg[:400]
    assert "_DEFAULT_STATE_FILE" in seg, "--bind 未双写默认域"
